# Live-Lab Handover — 2026-08-14

Written for whoever picks this up next. Read `LiveLabStageStatus_2026-08-14.md` first for the raw
state; this document is the **method and the traps**.

---

## 1. The operating contract for a stage failure

**Never fix a failing stage directly. Always: PLAN → ADVERSARIAL REVIEW → IMPLEMENT → ADVERSARIAL
REVIEW.** This is not ceremony. Every time it was skipped this session it cost a wasted run, and
twice it nearly landed a change that was actively wrong.

1. **Diagnose before planning.** Get the failure from the stage's OWN report artifact
   (`artifacts/live_lab/<run>/<stage>_report.json` and `<stage>.log`), never from a ledger column.
2. **Plan.** Write the causal chain with `file:line` evidence. State what would DISPROVE it.
3. **Review the plan adversarially.** Spawn reviewers whose job is to REFUTE it, defaulting to
   "not established". This caught a proposed fix that would have converted a true positive into a
   fail-open (QH-50), and rejected the obvious industry-standard answer for a codebase-specific
   reason (QH-46, below).
4. **Implement**, with the reasoning written into the code comment — not just the commit.
5. **Review the implementation adversarially.** Then **mutate**: reintroduce the bug and confirm the
   test fails. A test that passes both ways is decoration.

**A prediction that fails is data, not embarrassment.** Record refuted hypotheses in the ledger so
nobody re-runs them. Seven were eliminated on QH-51 this session; each is written down.

### Mutation testing is the acceptance bar

Commit BEFORE mutating (`git checkout --` restores to the last COMMIT, so uncommitted work in the
same file dies with the mutation — this destroyed a patch four times in one earlier session). Then:

* Mutation caught (test fails) → the test is load-bearing. Restore and verify **by reading the file**.
* **Mutation SURVIVED** → the code is redundant or the test is fake. This happened once here: a
  `ct status` stripping pass changed no verdict at all. The correct response was to **delete the
  redundant code**, not invent a test to justify it.

---

## 2. Running the lab

### Launching

Two paths. They are NOT equivalent — this was verified by adversarial review, not assumed.

**Direct CLI (what this session used):**

```bash
<orch-binary> ops vm-lab-orchestrate-live-lab \
  --inventory documents/operations/active/vm_lab_inventory.json \
  --ssh-identity-file ~/.ssh/id_ed25519 \
  --known-hosts-file ~/.ssh/known_hosts_lab \
  --node debian-headless-2:exit --node debian-headless-4:client \
  --node fedora-utm-1:entry --node rocky-utm-1:aux --node ubuntu-utm-1:relay \
  --report-dir /ABSOLUTE/PATH/artifacts/live_lab/<run-id>
```

**MCP (`start_live_lab_run`)** — gives a job record and better tooling, but note the differences,
all confirmed in code:

| | direct | MCP |
| --- | --- | --- |
| engine | `--node` → Rust engine | same, but ONLY via `nodes=["alias:role"]` |
| SSH key | whatever you pass | **hardcoded** `~/.ssh/rustynet_lab_ed25519` (differs from `id_ed25519`) |
| known_hosts | whatever you pass | **hardcoded** `~/.ssh/known_hosts` |
| topology | exactly your nodes | **silently appends `--windows-vm` + `--macos-vm`** unless `auto_topology: false` — this CHANGES the planned stage set |
| build | your prebuilt binary | `cargo run` (recompiles working tree) |
| target dir | workspace `target/` | `CARGO_TARGET_DIR=target-livelab` (avoids lock contention) |

The MCP's `*_platform` selectors DO drive the Rust engine — `start_live_lab_run` auto-synthesizes a
`--node` topology from them (`lab_state.rs:6317-6341`, `synthesize_nodes_from_platform_selectors`
at `:4079`). The tool's own description strings still claim legacy bash and are STALE. Only the raw
CLI `--exit-platform` flags are bash-only, and the MCP never emits them.

### Rebuild the orchestrator before every verification run

The stage code that builds SSH targets and drives the lab compiles **into** the orchestrator binary;
only the inner test binaries are rebuilt by `cargo run`. A stale binary will "verify" a fix it does
not contain — this nearly happened here with a 3-hour-old binary. Always:

```bash
cargo build -p rustynet-cli --features vm-lab --bin rustynet-cli
cp target/debug/rustynet-cli <dest>.new && mv -f <dest>.new <dest>   # atomic; never cp in place
```

### The launch gate

The orchestrator REFUSES to start when a prior stage failed with no recorded remedy. Record one
honestly — including "no code change, measurement run only":

```bash
<orch> ops live-lab-record-stage-patch --ledger documents/operations/live_lab_stage_triage.jsonl \
  --stub-id "<stub>" --patch "what you changed, or: none: <reason>"
```

### The TUI (`rustynet-lab-monitor`)

**If it says IDLE during a live run, suspect the report-dir path first.** `active_job` merges three
sources including a `ps` scan for `vm-lab-orchestrate-live-lab` that reads `--report-dir` from argv
(`job_watcher.rs:348`) — so direct-CLI runs ARE meant to be visible.

The running binary here predates commit `37b9690e` (2026-07-29), which resolves a **relative**
`--report-dir` against the repo root. Pass an **ABSOLUTE** `--report-dir` and the current binary
tracks the run. MCP runs only appear to work because they pass absolute paths.

**`rustynet-lab-monitor` has NO freshness gate** — `check_mcp_binaries_fresh.sh` covers only
`crates/rustynet-mcp`, so the monitor rotted invisibly for three weeks. Rebuild with `cd crates/rustynet-lab-monitor && cargo build` — its own workspace and `Cargo.lock`.
`./scripts/ci/lab_monitor_gates.sh` GATES it (fmt/clippy/check/test, ~270 tests) but runs `cargo
check`, so it never produces a binary. Note `check_mcp_binaries_fresh.sh` is itself a `cargo run`, so it takes the **shared workspace target
lock with or without `--fix`** — do not run it at all during a lab run. (`bin/rustynet-mcp-lab-state`
is currently stale: Aug 13 09:11 vs source Aug 13 10:42. The staleness cannot affect run
correctness — `start_live_lab_run` shells to `cargo run` — only the tool surface.)

---

## 3. Traps that cost real time here

**Read exit codes without a pipe.** `cmd | tail; echo $?` reports `tail`'s status. This produced four
false-green readings in one session despite being a known trap. Use `cmd > /tmp/out 2>&1; echo $?`.

**Never suppress stderr in a capture.** `2>/dev/null` makes a failed command indistinguishable from
an empty result. This destroyed three diagnostic captures. Use `2>&1` and print `<EMPTY>` explicitly.

**Time your captures against the stage, not the clock.** A sample taken 60s in predates a stage whose
readiness phase alone runs ~96s. Trigger on a marker in the STAGE's own log
(`artifacts/live_lab/<run>/<stage>.log`), and gate loop exit on a NEW occurrence — matching text
already present ends the poll after one iteration.

**Cleanup is `always_run`.** The daemon socket and all nft tables are gone once a run ends; nothing
can be sampled retroactively. Mid-stage or never.

**Do not compare counters across runs, or across address families.** An `inet` table counts IPv4 AND
IPv6; an `ip` table is IPv4-only. Comparing them manufactures contradictions — 40+8+30 = 78 bytes is
an IPv6 gossip packet, not evidence about pings.

**Verify a field name before parsing it.** A probe here silently resolved to `<unresolved>` for a
whole run because it parsed `assigned_cidr=` out of `rustynet status`. The field is REAL (an
auto-tunnel-bundle key, `daemon.rs:12671`) but `rustynet status` does not emit it — "exists" and
"emitted here" are different questions.
Copy a discovery method that already works (`mesh_ipv4_discovery_command` in the two-hop stage).

**`--node` role names.** `entry` and `relay` are DISTINCT roles — a `relay` node does NOT satisfy the
two-hop `entry` requirement (`live_two_hop_validation.rs:52`, `role.rs:288-289`). Some stage lookups
accept either via an explicit fallback list (`&["relay", "entry"]`); that is a fallback, not aliasing.
The second client must be `aux` or `extra`, not `client`. Getting this wrong makes `live_two_hop_validation` SKIP with a precise reason — read it.

**Ledger columns lie in both directions.** Confirm the row exists and is attributed to the right
commit, then take pass/fail from the stage's own report artifact. Parse the CSVs quote-aware.

---

## 4. What landed, and the one thing that did not

### Fixed and verified

QH-49/50/51 are mutation-proven. **QH-46 is LIVE-proven, NOT mutation-proven** — and it has a real
gap: its grammar/posture layer is unit-tested (`linux_firewalld_zone.rs`, 9 tests) but the
enforcement point `ensure_host_firewall_admits_forwarding` (`phase10.rs:890`) and its
`allow_tunnel_relay_forward` gate (`:2351`) have **no test**. That violates CLAUDE.md §4
(1 enforcement point + 1 verification test). Close it.

* **QH-46 — firewalld.** Rustynet's forward chain is `hook forward priority 0`; firewalld's is
  `filter + 10` and runs AFTER, ending in `reject`. `NF_ACCEPT` means "continue to the next base
  chain", not a final verdict — but reject/drop IS terminal, so no rule we add later can rescue the
  packet. The runtime-created tunnel is in no zone, so forwarded traffic died between FORWARD and
  POSTROUTING. **Any RHEL-family host could not forward as relay/exit.** Fixed by binding the tunnel
  to firewalld's EFFECTIVE DEFAULT ZONE at runtime over D-Bus.
  * **NOT the `trusted` zone**, though that is what comparable VPNs do: Rustynet installs no
    `hook input` chain and structurally cannot, so firewalld's zone is the ONLY inbound filter on the
    tunnel. Conceding FORWARD is free (our chain is default-drop, drop is terminal); conceding INPUT
    is not.
  * **NOT `firewall-cmd`**: it writes `connection.zone` into NetworkManager's on-disk config, which
    outlives uninstall. The D-Bus method has no such branch.
  * The zone is UNREPRESENTABLE in the helper grammar — always the empty string, resolved server-side.
  * **Result: `live_two_hop_validation` passed for the first time in the RECORDED `--node` history**
    (the per-stage ledger only starts 2026-07-10). `two_hop_reply_ttl=63`, `per_hop_ttl_decrement=1`
    on a Fedora entry — matching the pre-registered expected value in
    `NodeEngineFlipDispositions_2026-07-24.md:223`. No June artifact exists on disk; do not claim one.
    The attribution proof is the adjacent-commit pair: `qh49-verify-20260814b` @ `1d271015` FAILED,
    `qh46-firewalld-20260814c` @ `dda439a2` (the firewalld fix) PASSED. Quote-aware parse of
    `live_lab_node_stage_results.csv`: 291 skip / 121 fail / 50 pass, all 50 on 2026-08-14. Do NOT
    cite `linux_stage_two_hop` in the run matrix — 35 of its pass rows are the `traffic_test_matrix`
    alias contamination (CLAUDE.md §12.3).
* **QH-49** — LAN-toggle hardcoded the SSH username, so any non-Debian guest was dialled as `debian@`.
* **QH-50** — blind-exit NAT scan read `ct status dnat` (a conntrack MATCH) as NAT, and missed a
  leading-token `dnat to`. Wrong in both directions. Fixed the MATCHER, deliberately keeping the scan
  host-wide: narrowing it would have made the control blind to foreign NAT.
* **QH-51 partials** — dormant keepalive now populated; userspace engine now applies it to `Tunn`
  (it passed a hardcoded `None`); session no longer rebuilt on an unchanged reconcile; endpoint-only
  change now roams in place instead of destroying the session.

### Still failing: `live_network_flap_validation`

3 of 4 checks pass. `recovery_arrived=false`. **Eight hypotheses, seven eliminated** — all listed in
`LiveLabStageStatus_2026-08-14.md`; do not re-run them.

**Current hypothesis (8): the stage's premise is wrong.** A WireGuard session rekeys at ~120s; the
stage blocks egress for 35s. So when the block lifts the session is still valid, traffic resumes on
it, and boringtun emits keepalives rather than a handshake — there is no new handshake to observe.
The stage demanded one as proof of recovery.

**HYPOTHESIS 8 IS NOW WEAKENED — read this before building on it.** Run
`qh51-datapath2-20260814n` added a recovery proof based on DATA crossing the tunnel (ping the exit's
mesh IP from the client) instead of a handshake timestamp. The probe RESOLVED its target this time
(`exit mesh ipv4 for data probe: 100.80.169.183`, versus `<unresolved>` in the inert previous
attempt) and **still reported `recovery_arrived=false`**. So data does not cross the tunnel within
the 180s poll either — the original handshake assertion was not merely blind, and "the test's premise
is wrong" is NOT established.

**Crucial caveat on that probe, which must be resolved before concluding anything.** The stage's
`--exit-host` resolves to the `exit` ROLE (`live_network_flap_validation.rs:30`) =
`debian-headless-2`, but the client's actual WireGuard peer is the ENTRY (`fedora-utm-1`). So the
probe crosses TWO hops and can fail for entry-forwarding reasons entirely unrelated to the client's
session recovering — i.e. the QH-46 failure class. **Before trusting a negative result, re-target the
probe at the client's OWN peer (the entry's mesh IP) to separate "client session did not recover"
from "entry stopped forwarding".** That single change is the highest-value next experiment.

**Do NOT widen the recovery assertion to make the suite green.** It is the only check proving the
tunnel comes back.

---

## 5. Next work, in order

1. **Finish QH-51** — read run `qh51-datapath2-20260814n`'s stage artifact; confirm the probe
   resolved a target this time (the previous attempt was inert).
2. **Rebuild `rustynet-lab-monitor`** so the TUI stops lying, and consider adding it to a freshness
   gate — nothing covers it today.
3. **Cross-platform parity — the larger release blocker.** Linux is only the reference.
   * `windows-utm-1` (192.168.64.25) is powered on and on the SAME network as the Linux guests, but
     **port 22 is closed** — the only `.64` host that does not answer SSH. Fixing that unblocks the
     Windows **client/admin/relay** cells ONLY: this guest has no WinNAT/HNS and no nested virt
     (`CrossPlatformRoleParityPlan_2026-06-21.md:67,176`), so the Windows **exit** cell needs
     `windows-x86-1` (192.168.121.108 on `ubuntu-kvm-1`) — a different network, so it also needs the
     cross-network path.
   * `macos-utm-1` (192.168.65.101) is up and reachable but on a **different vmnet** (`.65` vs `.64`)
     because macOS UTM uses the Apple backend. A mixed mesh needs the cross-network path; no
     network-mode change fixes it.
   * **`userspace_shared_macos` needs NO mirroring — CHECKED.** It imports the same `UserspaceEngine`
     (`userspace_shared_macos/runtime.rs:18-22`), so the `Tunn::new` keepalive pass-through,
     `Unchanged` and `EndpointMoved` are inherited by construction, and its `configure_peer` already
     clears telemetry only on `Replaced` (`:584`). QH-51a is in `daemon.rs`, platform-independent.
   * **QH-46's Windows analogue is unexamined** — the defect CLASS (a foreign filter at the same hook
     silently discarding traffic we authorised) has an obvious counterpart in WFP filter weights.
4. **QH-47** — nothing flushes conntrack when NAT rules change.
5. **QH-48** — the suite is a linear dependency chain; one failure blocks ~19 stages, so a
   ~24-minute run (18.7-29.1 min measured across the eleven 2026-08-14 runs) surfaces at most one
   defect.


---

## 6. Operational facts a successor needs

**HEAD this document describes:** `e73a0d7e`. Run→commit anchors for the QH-46 attribution:
`qh49-verify-20260814b` @ `1d271015` (two_hop FAILED) → `qh46-firewalld-20260814c` @ `dda439a2`
(two_hop PASSED, firewalld fix present).

**Find an in-flight run:**
```bash
ps -eo pid=,args= -ww | grep '[v]m-lab-orchestrate-live-lab'   # argv carries --report-dir
```

**Where the verdicts live.** `<report-dir>/state/stages.tsv` is the AUTHORITATIVE per-run verdict
list (59 rows on this topology) — the headline pass/fail/skip counts come from there, not from the
orchestrator's stdout. Also in `state/`: `live_lab_node_stage_results.csv`, `nodes.tsv`,
`orchestration_context.json`. Per-stage detail is `<report-dir>/<stage>_report.json` +
`logs/<stage>.log`.

**Pending triage stubs (the launch gate reads these):**
```bash
jq -r 'select(.patch == null) | "\(.ts_utc)  \(.stub_id)"' \
  documents/operations/live_lab_stage_triage.jsonl | sort
```

**The orchestrator binary.** This session built it to a session-scoped scratchpad
(`.../scratchpad/orch<N>`, incrementing per rebuild) — a path a successor CANNOT reconstruct. Build
your own and keep it somewhere stable; `target/debug/rustynet-cli` is fine if you accept that any
`cargo build` overwrites it.

**`--source-mode` defaults to `working-tree`** (`vm_lab/mod.rs:28945`), and the direct CLI emits **no
untracked-file warning** (the MCP does, via `untracked_crate_files`). A fix in a NEW file under
`crates/` silently does not deploy — `git add` it first, or check with the MCP's `what_will_deploy`.

**Four launch paths, not two.** Direct CLI; MCP `start_live_lab_run`; MCP
`launch_live_lab_on_host` (remote host — and it DOES accept `host_known_hosts`); and
`ai_lab_run` (deterministic worker + auto-triage, CLAUDE.md §12.5). The latter three share
singleton/reconcile machinery the direct path bypasses entirely.

**Gates (CLAUDE.md §7) — not covered elsewhere in this document.** Before landing:
`cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace --all-targets --all-features`, plus `cargo audit` / `cargo deny`. Note
`--workspace` SKIPS `crates/rustynet-lab-monitor`, `fuzz/` and `gui/` (separate workspaces); CI adds
`--locked`; and `cargo run -p rustynet-xtask -- gates` dirties the tracked
`documents/operations/gate_timings.csv`.

**Dirty-tree hazard.** A running lab auto-appends to tracked files (`live_lab_node_run_matrix.csv`,
`live_lab_node_stage_results.csv`, `live_lab_stage_triage.jsonl`). NEVER `git add -A`; add explicit
paths. Check `git rev-list --count HEAD..origin/main` is 0 before committing, and do not take a
"dirty state" evidence reading mid-run.

**The cross-network substrate is UNTESTED, not confirmed.** All 11 `cross_network_*` stages are in
the cascade behind the single failure, so nothing has established whether the `.65`/`.64` vmnet split
is actually workable for a mac cell — only that it is the route that would have to work.


---

## 7. HANDOVER STATE — read this first

**Commit handed over on: `9ac63abd`** ("Probe the client's own peer for flap recovery, not the final
exit"). Push it if `git rev-list --count origin/main..HEAD` is non-zero — it was 1 at handover.

### A run is IN FLIGHT right now

| | |
| --- | --- |
| run id | `qh51-peerprobe-20260814p` |
| report dir | `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/qh51-peerprobe-20260814p` |
| stdout log | session scratchpad `liverun39.log` (session-scoped; use the report dir instead) |
| orchestrator | built from `9ac63abd`, holds locks on all 5 Linux guests |
| find it | `ps -eo pid=,args= -ww \| grep '[v]m-lab-orchestrate-live-lab'` |

**Do not start another run until it exits** — it holds all five guest locks.

**What it is testing (the discriminating experiment).** The flap stage's data-path recovery probe was
re-targeted from the final exit to the client's OWN peer (`entry` role). Probing the exit crossed TWO
hops, so a failure could not distinguish "this client's session did not recover" from "the entry
stopped forwarding" — the QH-46 failure class. Read:

```bash
grep -E 'peer mesh ipv4|recovery_arrived|recovery proven' \
  artifacts/live_lab/qh51-peerprobe-20260814p/live_network_flap_validation.log
```

* **`recovery_arrived=true`** → the client's session DOES recover; the earlier two-hop failure was
  forwarding, and hypothesis 8 (the stage demanded a handshake that correct WireGuard behaviour never
  produces after a 35s block) stands. The stage should then pass.
* **`recovery_arrived=false` with a resolved peer IP** → the session genuinely does not recover. That
  is a REAL daemon defect and the original assertion was right. Do NOT weaken it; diagnose.
* **`<unresolved>`** → the probe was inert again; the discovery command failed on the entry host.
  Fix that before reading anything else into the result.

Whatever it returns, **append the outcome to `LiveLabStageStatus_2026-08-14.md`** and record a triage
patch for the stage before the next run, or the launch gate will refuse.

### Uncommitted at handover — deliberate, do not commit blindly

`git status` shows three modified TRACKED files:
`live_lab_node_run_matrix.csv`, `live_lab_node_stage_results.csv`, `live_lab_stage_triage.jsonl`.
These are auto-appended by the RUNNING lab. Let the run finish, then commit them as evidence with
explicit paths. **Never `git add -A`** — other sessions share this working tree.

### Immediate next actions, in order

1. **Read run 39's verdict** (above) and act on whichever of the three branches it lands in.
2. **Rebuild the TUI** so it stops reporting IDLE:
   `cd crates/rustynet-lab-monitor && cargo build` (own workspace; the gate script only checks, it
   does not build). Do it between runs — it takes the target lock.
3. **Close the QH-46 test gap.** `ensure_host_firewall_admits_forwarding` (`phase10.rs:890`) and its
   `allow_tunnel_relay_forward` gate (`:2351`) have NO test, which violates CLAUDE.md §4. The fix is
   live-proven but not unit-proven.
4. **Run the full §7 gates.** The ~30 commits landed today were gated per-crate (fmt/clippy/targeted
   tests), NOT with a full `cargo test --workspace --all-targets --all-features`. Do that before
   treating today's work as release-ready, and remember `--workspace` skips
   `crates/rustynet-lab-monitor`, `fuzz/` and `gui/`.
5. **Cross-platform parity** — the larger release blocker, untouched (§5).

### Do not repeat these

* Do not widen the flap stage's recovery assertion to make the suite green. It is the only check
  proving the tunnel comes back.
* Do not re-run the seven eliminated QH-51 hypotheses (listed in the status doc).
* Do not trust `linux_stage_two_hop` in the run matrix — 35 of its pass rows are alias contamination.
* Do not parse a field name you have not seen emitted. That wasted a full run today.
