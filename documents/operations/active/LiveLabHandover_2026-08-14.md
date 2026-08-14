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

The `*_platform` selectors (`exit_platform` etc.) route to the **legacy bash orchestrator**, not the
Rust engine. Use `nodes` if you are verifying `--node`.

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
`crates/rustynet-mcp`, so the monitor rotted invisibly for three weeks. Rebuild it between runs
(`./scripts/ci/lab_monitor_gates.sh`; the crate is workspace-EXCLUDED, 269 tests). Note `--fix` on the
MCP freshness script takes the **shared workspace target lock**, so do not run it during a lab run.

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
whole run because it parsed `assigned_cidr=` out of `rustynet status`, a field that does not exist.
Copy a discovery method that already works (`mesh_ipv4_discovery_command` in the two-hop stage).

**`--node` role names.** `entry` is an ALIAS for `relay`; the second client must be `aux` or `extra`,
not `client`. Getting this wrong makes `live_two_hop_validation` SKIP with a precise reason — read it.

**Ledger columns lie in both directions.** Confirm the row exists and is attributed to the right
commit, then take pass/fail from the stage's own report artifact. Parse the CSVs quote-aware.

---

## 4. What landed, and the one thing that did not

### Fixed and verified (all mutation-proven)

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
  * **Result: `live_two_hop_validation` passed for the first time in the `--node` engine's history.**
    `two_hop_reply_ttl=63` on a Fedora entry — the same value Debian entries produced in June.
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

**In flight at handover:** run `qh51-datapath2-20260814n` tests a recovery proof based on DATA
crossing the tunnel (ping the exit's mesh IP from the client) rather than a handshake timestamp. That
is STRICTER — a reply cannot be produced without a live session, whereas a stale-but-present
timestamp proves nothing about whether packets move.

**Unverified, and it must be checked before trusting hypothesis 8:** what cleared the handshake
record during the block (nothing in `configure_peer` should, after the fixes above — look at
`remove_peer`), and whether a handshake genuinely never occurs post-unblock. "The test is wrong" is
the most self-flattering possible conclusion after seven failures; treat it with suspicion.

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
     **port 22 is closed** — it is the only `.64` host that does not answer SSH. Fix that and it can
     join the existing topology directly.
   * `macos-utm-1` (192.168.65.101) is up and reachable but on a **different vmnet** (`.65` vs `.64`)
     because macOS UTM uses the Apple backend. A mixed mesh needs the cross-network path; no
     network-mode change fixes it.
   * **`userspace_shared_macos` may need the QH-51 session/roaming fixes mirrored** — they landed in
     `userspace_shared` only. NOT checked. Do this before assuming macOS benefits.
   * **QH-46's Windows analogue is unexamined** — the defect CLASS (a foreign filter at the same hook
     silently discarding traffic we authorised) has an obvious counterpart in WFP filter weights.
4. **QH-47** — nothing flushes conntrack when NAT rules change.
5. **QH-48** — the suite is a linear dependency chain; one failure blocks ~19 stages, so a
   17-minute run surfaces at most one defect.
