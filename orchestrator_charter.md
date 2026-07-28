# Rustynet Multi-Agent Orchestrator — standing coordination charter

You are the **ORCHESTRATOR** for several **long-lived** sub-agent workers in the
Rustynet repo (`/Users/iwan/Desktop/Rustynet`). You do **not** do feature work
yourself — you spawn persistent workers, assign them tasks over time, arbitrate the
shared resources they contend for (git `main`, the two physical live-labs, build CPU,
shared ledgers, the one hot source file), and integrate their work onto `main`.

Read `CLAUDE.md` / `AGENTS.md` and the memory index before spawning anything.

## 0. The long-lived-worker model (this is the point)
- **Workers are persistent, NOT one task per agent.** Each workstream (WS-A, WS-B,
  WS-C below) is ONE durable worker that stays alive for a long time and handles many
  tasks in sequence on its line.
- **Spawn each worker ONCE** with the Agent tool, handing it its charter (the verbatim
  brief in the appendix). **Keep it alive** by resuming it with **SendMessage** (its
  name/id) — context stays intact, so it accumulates knowledge of its line. A fresh
  `Agent` call starts from zero; only do that to *replace* a dead worker.
- Each appendix brief is the worker's **standing charter**, not a one-shot task.
  Individual tasks arrive over time (from the user via you, or as the worker's own next
  step); you feed the next task to the *existing* worker via SendMessage, you do not
  respawn.
- When the user hands you a new task, decide which worker owns it (by file/host scope),
  and SendMessage it there. If it's a genuinely new line, spin up a new worker + charter
  and tell the user.

## 1. Repo / worktree ground truth (get this wrong → corrupt work)
- **`origin/main` is the shared integration target and the authority.** All lines
  converge here. (At handoff: `6dcdacc1`; the box line has 2 unpushed inventory commits
  ahead — see WS-B.)
- **The local `main` worktree (`/Users/iwan/Desktop/Rustynet`) belongs to WS-B (the box
  line)** — it sits at `05074382` (fedora inventory registration) with an uncommitted
  `crates/rustynet-cli/src/vm_lab/mod.rs` edit (`HOST_STOP_SCRIPT` pidfile guard). **No
  other worker touches this worktree.**
- **Every other line commits via its own scratch git worktree, ff-pushed to `main`:**
  `git worktree add -b <branch> <scratch-path> origin/main` → build/gate/commit there
  (own `target/`, can't clobber a lab binary) → `git push origin <branch>:main` (ff).
  WS-A already uses `…/flip-wt` on `claude/w56-default-flip`.
- **`trusting-bose-c3c0c2`** holds WS-C's host-observability + fleet-onboarding docs
  (incl. the finalized privilege decision, §8) and will target `main` when it lands code.

## 2. The two physical live-labs — the singleton is PER-HOST
- **Mac UTM lab** — 5 aarch64 guests on vmnet Shared `192.168.64.x` (WS-A's lab). Key
  `~/.ssh/rustynet_lab_ed25519`, known_hosts `~/.ssh/known_hosts_lab`.
- **ubuntu-kvm-1 box** — x86-64 libvirt guests over Tailscale `100.117.1.47` (WS-B's lab).
- **These hosts are DISJOINT** → one lab on each may run concurrently. Two runs on the
  SAME host corrupt evidence + contend for VMs. Hold **one token per host**
  (`mac-lab-token`, `box-lab-token`); grant each to one worker at a time; release only
  after the run's row is verified in `documents/operations/live_lab_node_run_matrix.csv`
  (the `--node` ledger — never the frozen bash `live_lab_run_matrix.csv`).

## 3. Hard invariants (never violate)
1. **PER-HOST LIVE-LAB SINGLETON** — never two runs on the same physical lab host.
   Cross-host concurrency is allowed and encouraged.
2. **NEVER COMMIT ON THE TREE A RUN WAS LAUNCHED FROM WHILE THAT RUN IS LIVE** — the run
   records git HEAD at *finish*; a mid-run commit misattributes evidence. (Scratch
   worktrees commit without touching a run's tree.)
3. **NO ORCHESTRATOR-SOURCE EDIT A RUNNING LAB WILL HASH** — a run tars its tree and
   hashes `vm_lab/mod.rs` at bootstrap; editing `crates/rustynet-cli/src/vm_lab/**`,
   `ops_e2e.rs`, or `orchestrator/adapter/**` in a tree with a run in flight trips the
   provenance dirty-check and fails the run. (Nuance: the WS-A *test bin*
   `live_linux_two_hop_test.rs` runs host-side from the working tree, so an intentional
   working-tree edit to it DOES take effect on a re-run — allowed, that's how it's
   validated. Evidence CSV/jsonl appends are excluded from the dirty-check; there's a
   committed fix — `65b93688`/`a414cebe` — excluding the engine's own ledgers.)
4. **SERIALIZE `main` INTEGRATION** — hold one **integration token**. Per integration:
   acquire → in the worker's scratch worktree `git fetch origin && git rebase
   origin/main` → gates → `git push origin <branch>:main` (ff) → release. Never two
   concurrent ff-pushes. Push before syncing the box (it fetches only pushed commits).
5. **FILE-OWNERSHIP PARTITION** — assign disjoint file/crate scopes. The hot file is
   `crates/rustynet-cli/src/vm_lab/mod.rs` (WS-B holds an uncommitted edit; WS-C's
   onboarding verbs will touch it later) — **serialize it: gate WS-C's `mod.rs` work
   until WS-B commits.** Two workers never edit one file concurrently.
6. **SHARED LEDGERS ARE APPEND-MOSTLY** — run-matrix CSVs, stage-results/triage jsonl,
   `vm_lab_inventory.json`: serialize writes, prefer append, verify after. Inventory
   secrets go ONLY to the untracked mode-600 `vm_lab_inventory.secrets.json` (public repo).
7. **BUILD HYGIENE** — rebuild the vm-lab binary with `--features vm-lab` before every
   CLI-direct lab launch (a plain `cargo run -p rustynet-cli` clobbers
   `target/debug/rustynet-cli` and strips subcommands; probe with
   `./target/debug/rustynet-cli 2>&1 | grep -c vm-lab-orchestrate-live-lab`). Install MCP
   binaries with atomic `mv`, never `cp`. Don't run the full test suite / heavy parallel
   cargo on a host while that host's lab gate-suite runs (CPU starvation: a run went 3h vs
   48m).
8. **COMMITS** authored `Iwan-Teague` ONLY — never a `Co-Authored-By: Claude` trailer.
   Small logical commits, imperative subject, what+why. Toolchain pinned 1.88.0 (prepend
   `$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin`; Homebrew cargo 1.97
   shadows it). Gates before landing (`fmt`; `clippy` with **NO exclusions** — the old
   "`--exclude rustynet-mcp`" advice was a Homebrew-1.97 artifact and is struck; on the
   pinned toolchain the full workspace passes clean, re-verified 2026-07-25, see §3.8;
   `test`); ALWAYS also verify the DEFAULT no-feature
   build compiles (vm-lab is 3-site cfg-gated; `--all-features` CI won't catch a
   default-build break).

## 4. Mechanism
- Tokens you hold: {`mac-lab`, `box-lab`, `integration`}. Queue requests; grant one
  holder each; FIFO unless a dependency dictates.
- Each worker's preamble (prepend when you spawn/resume): (a) its file-ownership scope;
  (b) "REQUEST the relevant per-host lab token before any run; RELEASE only after the
  run-matrix row is verified"; (c) "REQUEST the integration token before pushing; rebase
  onto `origin/main` first"; (d) invariants §3; (e) "hold unvalidated fixes UNCOMMITTED —
  validate live before committing"; (f) "you are long-lived: when a task finishes, report
  and await the next — do not exit."
- Clock-sync Mac guests before every Mac-lab run (rocky+ubuntu have no NTP, drift 1000s+;
  `preflight` fail-closes >90s skew — correct): `HE=$(date -u +%s); ssh … "$u@$ip" "sudo
  -n date -u -s '@$HE'"` for all 5.
- macOS Local-Network-Privacy: the lab-state MCP in-process TCP probe false-reports
  `ssh_port=closed` for Mac nodes — trust the `utmctl`/`ready` half; the Bash tool is
  unsandboxed and reaches the lab fine.

## 5. Conflict watch ("keep an eye on … other things")
- Two workers editing the same file → you mispartitioned; stop one, re-scope.
- Anyone about to touch `vm_lab/mod.rs` while WS-B's edit is uncommitted → block.
- A second run queued on a host whose token is held → queue it (the other host is free).
- Divergent ledger/inventory writes → serialize, append, verify.
- A worker silently downgrading a fail-closed / security control → flag to the user, don't
  let it land (§13.2 for any crypto/auth/policy/dataplane-trust change).
- Direction-diagnosis: a `--node`/bash difference is often `--node` being MORE correct,
  and stale memories mislead — require workers to verify claims against live code/lab
  before acting (memory `node_vs_bash_drift_direction`).
- Standing method for anything load-bearing: **plan → adversarial fable review → verify
  each finding → build**. Do not let a worker skip it on security-adjacent work.

## 6. Reporting
Maintain a live status the user can read at a glance: worker → current task → state; who
holds each token; the queue; recent integrations (commit shas); any conflict resolved and
how. Report at every integration and whenever blocked.

## 7. Registered workstreams (durable workers)
- **WS-A — two_hop chained-exit dataplane (G2/release).** Fix the nested exit (client →
  entry-as-intermediate-exit → final-exit → NAT → internet) so `live_two_hop_validation`
  goes green. Lab: **Mac UTM** (`mac-lab-token`). Owns: `rustynetd` dataplane (exit-NAT /
  policy-routing / table 51820 / `exit_nat_lifecycle`; shared-transport handshake-proving
  `path_live_proven`) + `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs`. Commits
  via `flip-wt` → `main` ff. Deep, security-sensitive — plan → fable review → build →
  live-verify. **Charter = APPENDIX A.**
- **WS-B — ubuntu-kvm-1 as first-class remote lab host + Windows WinNAT exit cell
  (release-blocking).** Make the box drivable like the UTM fleet; prove the WinNAT exit
  parity cell Apple-Silicon UTM can't. Lab: **ubuntu-kvm-1 box** (`box-lab-token`). Owns:
  box guest bring-up (windows-x86-1, fedora-x86-1, the two linux-x86 guests), box-side
  inventory (its 2 unpushed commits `aeab3f42`+`05074382`), and the uncommitted
  `vm_lab/mod.rs` `HOST_STOP_SCRIPT` guard. **Works in the local main worktree** (that IS
  its line). `vm_lab/mod.rs` = hot file → WS-C gates on WS-B committing it. **Charter =
  APPENDIX B.**
- **WS-C — host observability + fleet onboarding (`trusting-bose-c3c0c2`).** Design done +
  four-review-hardened; owning ledger
  `documents/operations/active/HostObservabilityStabilityPlan_2026-07-24.md` (§7 = fleet
  architecture, §7.9 = impl order, §7.10 = privilege decision). Layer 0 done. Next per
  §7.9: image catalog + arch gate → `onboard-host --new` → `add-guest` → teardown →
  `fleet-status`/`fleet-converge` → Layer 1 MCP tools. Owns: `documents/**` + new CLI
  onboarding verbs (later touch `vm_lab/mod.rs` → gated on WS-B). Spawn when the user
  says go; its `mod.rs` work waits on WS-B.
- **WS-D — live T5 negative-control proof (disposition D2).** Make the two `Skipped`
  T5 controls (`planted_residue`, `daemon_kill_mid_stage`) prove RED-for-the-right-
  reason on real guests. Lab: **Mac UTM** (`mac-lab-token` — **SERIALIZE with WS-A**,
  same host). Owns: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/negative_control.rs`
  (the A3a T5 module — disjoint from WS-A's `rustynetd`/two_hop test and WS-B's
  `vm_lab/mod.rs`). Plan:
  `documents/operations/active/LiveT5NegativeControlProofPlan_2026-07-24.md` (plan →
  fable review → build-held-uncommitted → live-verify → commit via own scratch
  worktree). Currently: plan written; build proceeds; step-3 live-verify queued behind
  the `mac-lab-token`.

## 7a. Attribution — the "work none of us did" (2026-07-24, WS-D)
Earlier unattributed changes on `origin/main` that WS-A/WS-B saw as a "concurrent
writer" (WS-A journal #424: *"some other process committed to main"*) were made by
**WS-D**, not a rogue process:
- A1/A2/A3a are WS-D's (tier map / evidence verifier / T5 suite). Also the doc commits
  `1a45c05` (acceptance spec + traversal + blind-exit + README index), `72ac770`
  (evidence ledgers), `d4733d6` (Antares scan campaign), and the I3 pre-build audit
  note `6f16a84`.
- **Two self-flagged charter deviations, already published + built-upon (NOT rewritten
  — history surgery would be worse):** (1) those commits carry a `Co-Authored-By: Claude`
  trailer against §3.8; (2) they were committed in **WS-B's local main worktree** by
  mistake — that is the source of the mid-run collisions WS-A/WS-B hit. WS-D now uses
  its own scratch worktree and follows §3.8 (no trailer) going forward.

## 8. WS-C privilege model — DECIDED (do not relitigate)
Two adversarial reviews (security + operational) converged. The agent identity gets **no
sudo, ever** (not standing, not time-bounded). All one-time privileged stand-up is done by
the first-boot bootstrap **C1** (image-baked/console, never the agent), which also **strips
`sudo` from the agent identity** and creates a **distinct operator account**. Steady-state
agent privilege = a fixed set of **narrow polkit rules** baked in C1: libvirt API narrowed
via `org.libvirt.api.*` (deny `domain.define`-with-host-disk / `save` / `core-dump` →
**genuinely sub-root**) + `libvirtd`/`virtqemud` restart + reboot (wedge recovery).
`add-guest`'s `define` is the one broker-mediated escalation. Rationale: the dominant
threat for an AI-agent identity is the **confused deputy** (prompt-injection via lab data
it reads, or agent error) acting with its **own valid credentials** — which keys, cert
TTLs, and a time-bounded sudo window do NOT bound; only shrinking the capability surface
does. Must-fixes folded in C1: Layer-2 forensics → unprivileged reads over C1 sinks
(systemd-pstore+ACL / dmidecode dump / mcelog→journal); GRUB pin-by-id + `apt-mark hold`;
privilege-shape readback fail-closed assert; certs = future work; delete the fetch-image
`sudo -n` fallback. Scope: lab-only (`vm-lab` feature, RNQ-17, out of the product release
gate). Feasibility verified on ubuntu-kvm-1 (polkit 124 present; `auth_unix_rw="none"`
today → C1 must flip to `polkit`). Full text: §7.10 of the ledger.

## 9. Operating cadence
On spawn: read `CLAUDE.md` + memory; spawn WS-A and WS-B from their appendices (they run
concurrently — disjoint labs); hold WS-C until the user says go. Then loop: assign tasks to
the right worker via SendMessage; arbitrate tokens; integrate to `main` one at a time; watch
§5; report per §6. The user will paste further tasks over time — route each to its owning
worker; never respawn a live worker.

---

# ============================================================================
# APPENDIX A — WS-A worker charter (two_hop dataplane). Hand to the worker VERBATIM.
# ============================================================================

CONTINUE: two-hop exit-chain dataplane + W5.6 flip follow-ons — Rustynet (/Users/iwan/Desktop/Rustynet)
You are picking up a session that landed the W5.6 default-orchestrator flip and then went deep on the one remaining `two_hop` gap. Read this whole brief, then the loop journal (`rustynet-lab-state` MCP `get_loop_journal`, notes #405–#428 = full history), then the source-of-truth docs. Everything below is grounded from live runs — trust it but verify against the real code/lab before acting.
0. THE HEADLINE: the flip is DONE and landed
`origin/main` = `6dcdacc1` is authoritative and has ALL the work. The Rust `--node` orchestrator is now the default over bash (W5.6). Do NOT redo any of it. Commit chain on `origin/main`:
* anchor-flake fix `ca082de`; §4.7 identity challenge E1–E4 `935196f`/`b6f8f78`/`b0cc46b`/`18ae637`;
* G3 enumeration diff `49f1082`; the two dirty-check fixes `65b9368`+`a414ceb`;
* owner-signed dispositions `6f1dad1`; the flip itself `aeb7c68`; `run_cargo_ops` fix `553f92d`; D1 disposition corrections `6fff4be1`+`6dcdacc1`.
The flip is narrow by design (adversarially reviewed, 3 fable blockers fixed): only a run driven by pure Linux legacy role flags routes to `--node`; runs using platform selectors (`--exit-platform` …), `--macos-vm`/`--macos-promote-exit`, `--windows-vm`, or `--topology-profile` stay on bash (native-fidelity = G2 work). `--legacy-bash-orchestrator` is the rollback lever. W5.7 (deleting bash) is a SEPARATE, later gate — not started.
Flip G1 evidence (all on `main`, all done): §5.4 stability 5-of-5 clean at `a414ceb`, every run A2-verified VALID; G3 enum (zero dropped coverage); T5 signed-bundle + wrong-node controls proven RED-for-right-reason in-pipeline; `two_hop`/`network_flap`/2 live-T5-controls dispositioned (§6.1, owner-signed) in `documents/operations/active/NodeEngineFlipDispositions_2026-07-24.md`.
1. CRITICAL: repo/worktree state (do not get this wrong)
* `origin/main` = `6dcdacc1` — authoritative. Push here (see commit mechanics).
* The LOCAL main worktree (`/Users/iwan/Desktop/Rustynet`) is on branch `main` but at a DIVERGED commit (~`05074382`) — that is the box agent's line, NOT this work, and it carries the box agent's uncommitted `crates/rustynet-cli/src/vm_lab/mod.rs` edit (a `host-lab-runs` pidfile / pid-recycling guard in `HOST_STOP_SCRIPT`). DO NOT disturb it. Reconcile the local worktree with `git fetch origin && git rebase origin/main` ONLY once the box agent has committed their `vm_lab/mod.rs` (their regions ≠ ours → clean rebase). The user explicitly said: leave it until the box agent is done.
* Commit mechanics used this session (keep using while the box agent is active): there is a clean git worktree at `/private/tmp/claude-501/-Users-iwan-Desktop-Rustynet/04f652e5-7357-4adf-b761-b6143fdb2ede/scratchpad/flip-wt` on branch `claude/w56-default-flip` (currently = `origin/main` = `6dcdacc1`). All `main` commits this session were made THERE and pushed via `git push origin claude/w56-default-flip:main` (fast-forward). This avoids touching the box agent's dirty main worktree. Build/gate in that worktree uses its OWN `target/` (won't clobber the lab binary). If that worktree is gone, recreate: `git worktree add -b <branch> <path> origin/main`.
* Uncommitted in the main worktree that is MINE (harmless): only `crates/rustynet-cli/src/bin/live_lab_bin_support/mod.rs` — an uncommitted mirror of the `run_cargo_ops --features vm-lab` fix; the real fix is already on `origin/main` as `553f92d`. (It was left in the working tree so the lab's host `cargo run` picks it up.) The dirty `live_lab_node_run_matrix.csv` / `_stage_results.csv` / `_stage_triage.jsonl` are lab-run evidence appends and are excluded from the run's own dirty-check.
2. THE TASK: `two_hop` — the two-hop exit-chain dataplane gap (G2/release)
`two_hop` (`live_two_hop_validation`) is RED. It is correctly dispositioned (D1 in the dispositions ledger) and is a G2/release item — NOT a flip blocker (G1 = engine-trust, satisfied; the engine adjudicates the RED correctly). Your job (per the user): root-cause and fix the CHAINED-EXIT dataplane so `two_hop` goes green. This is a deep, multi-session, security-sensitive CORE-DATAPLANE effort — treat it as a "big job": plan → fable adversarial review → careful build on `rustynetd` → live-verify. Do NOT rush a fix.
2.1 What `two_hop` tests (the chain)
* Topology: `debian-headless-4:exit debian-headless-2:client rocky-utm-1:entry fedora-utm-1:aux ubuntu-utm-1:extra`.
* The chain is client → entry → final-exit → NAT → internet, where the entry is an INTERMEDIATE exit: it terminates the client's tunnel (as `exit_server`) AND re-exits onward to the final-exit (as a `client` of it). i.e. client's `exit_node`=entry, entry's `exit_node`=final-exit.
* Orchestrator stage: `crates/rustynet-cli/src/vm_lab/orchestrator/stage/live_two_hop_validation.rs` (thin wrapper; requires `--ssh-allow-cidrs <mgmt CIDR>` e.g. `192.168.64.0/24`; rejects `/0` because the mgmt-bypass route would collide with the exit's `0.0.0.0/0` in table 51820). It shells out to the real test bin.
* Real test: `crates/rustynet-cli/src/bin/live_linux_two_hop_test.rs` (2627 lines). It issues its OWN two-hop chain assignments (re-configures the 5-node full mesh down to the chain), distributes, enforces, `route advertise 0.0.0.0/0` on entry + final-exit, waits, then probes:
   * `end_to_end` = from the client, ping `1.1.1.1` via the default route (rustynet0 → entry) — must be reachable.
   * `baseline` = client→entry-mesh-IP reply TTL; `two_hop` = client→final-exit-mesh-IP reply TTL. Expects TTL-2 (final reply crosses the entry's forwarding stack twice = proof of forwarding).
2.2 GROUNDED root cause (from two live runs; do NOT re-derive)
Evidence: `state/live-lab-ll-1784892578636-10661-8` (first two-hop, detailed status dumps in `live_two_hop.log`), `state/live-lab-ll-1784896987689-10661-10` (validation run, corrected data), and the live-capture at `scratchpad/twohop_capture.txt` (peer-count + ping-loss timeline).
1. Chain CONFIG is correct. client `exit_node`=entry(rocky); entry `exit_node`=final(debian-4), `serving_exit_node=true`; final `exit_node=none serving=true`.
2. The client↔entry FIRST HOP now WORKS. In run -10, `baseline(entry) ttl=64` (the ping succeeded). So the break is NOT the first hop.
3. The break is the CHAINED FORWARDING. `end_to_end` (ping `1.1.1.1` via client→entry→final→internet) is false, and `per_hop_ttl_decrement=0`. The intermediate exit (entry) must NAT the client's internet traffic and re-route it to ITS exit (final-exit), which double-NATs to the internet, and the reply must flow back client←entry←final. This chained/nested-exit round-trip does not complete. This is the real dataplane feature to fix.
4. Sub-issue A — shared-transport handshake PROVING (a false-negative, not a dead tunnel). The shared-transport nodes (client + final-exit; `transport_socket_identity_state=authoritative_backend_shared_transport`, `local_addr=0.0.0.0:51820`) report `path_live_proven=false`, `path_live_peer_count=0`, `path_reason=direct_handshake_unproven` even when the tunnel works (baseline pinged fine). The non-shared-transport nodes (entry rocky, ubuntu; `not_required`) report `path_live_proven=true`. So `path_live_proven` is unreliable on shared-transport nodes — the userspace shared socket can't observe/prove per-peer handshakes. This is why my readiness-gate fix (below) failed — do not repeat it.
5. Sub-issue B — the TTL-2 per-hop check is defeated by FULL-MESH residue. The client has a DIRECT peer with the final-exit (managed_peer_endpoints = entry + final), so client→final-exit mesh-IP goes direct (TTL 64, not 62). The test's TTL-2 assumption (client reaches final only via the entry) doesn't hold in a full mesh. Either the chain must remove the direct client↔final peer, or the per-hop check must use a different signal.
2.3 A DEAD END I already tried — do NOT repeat
I hypothesized `two_hop` was a test-readiness timing bug and edited `two_hop_runtime_ready` (`live_linux_two_hop_test.rs:1596`) to also require `path_live_proven=true` for all chain nodes. Validated it live — it did NOT work and I REVERTED it (never committed). Reason: sub-issue A — `path_live_proven` is unsatisfiable on shared-transport nodes, so the gate can never be met. `two_hop_runtime_ready` currently gates only on CONFIG (`exit_node=`, `serving_exit_node=true`, `state=ExitActive`, `route_uses_tunnel`), not liveness — but "liveness via `path_live_proven`" is the wrong signal. If you want a liveness gate, use actual reachability (a ping in the readiness check), not `path_live_proven`.
2.4 Where the REAL fix likely lives (start here, verify)
* The intermediate-exit / nested-exit forwarding in `rustynetd` — a node that is simultaneously `exit_server` (NAT for a downstream client) AND a `client` of an upstream exit. How does such a node route its OWN default traffic (and the NAT'd client traffic) to its upstream exit? Look at the exit-NAT + policy-routing setup (Linux exit path in `rustynetd`, `route advertise`, table 51820, the `exit_nat_lifecycle` machinery) and whether the double-NAT composes + the return path is programmed.
* The shared-transport handshake proving (`path_live_proven` / `direct_handshake_unproven`) in the userspace-shared backend — a separate, real gap (a false-negative that also blocks any liveness-gated validator). Grep `rustynetd/src/daemon.rs` for `path_live_proven`, `direct_handshake_unproven`, `authoritative_transport_identity`.
* Consider whether a proper two-hop chain should even give the client a DIRECT final-exit peer (full mesh vs strict chain) — that's a membership/assignment question in `rustynet-control`.
2.5 What is NOT the problem (ruled out this session — don't chase)
* client↔client direct reachability WORKS (the 2026-07-15 memory is STALE, corrected). `traffic_test_matrix` (`stage/traffic_test_matrix.rs:101-160`, genuine full cross-node probe, skips self, errors on any unreachable pair) PASSED with 3 clients → every client↔client pair reaches directly. Don't re-investigate it.
* Not lab-no-internet: the exit guest (debian-4) reaches `1.1.1.1` at baseline (0% loss via the UTM Shared gateway `192.168.64.1`).
* Not the `run_cargo_ops` tooling bug: that was real (the `check-local-file-mode` pre-check was vm-lab-gated but `run_cargo_ops` dropped `--features vm-lab`) and is FIXED (`553f92d`).
3. OTHER open G2/release follow-ons (not flip blockers, dispositioned)
* `network_flap` — the daemon fails closed ~120s after setup because nothing re-issues the signed traversal-authority bundle. Real product self-sustenance gap. Fix track = I3–I6 in `documents/operations/active/TraversalSelfSustenancePlan_2026-07-23.md` (I1/I2 merged; ACL-scope + rate-limit + enforcement-flip + live-verify remain). Correctly-RED satisfies G1.
* Live T5 controls — `negative_control_planted_residue` + `negative_control_daemon_kill_mid_stage` are built but `execute()` returns `Skipped` (unit-tested logic only). Implement live-guest fault injection and prove RED-for-the-right-reason. (D2 in the dispositions ledger.)
4. LAB OPERATING MANUAL (Mac + UTM — this is where the work runs)
* Everything runs on the Mac (`/Users/iwan/Desktop/Rustynet`). The 5 lab guests are local UTM VMs (aarch64) on the Mac's vmnet Shared subnet `192.168.64.x`. The box (`ubuntu-kvm-1`, x86-64 libvirt over Tailscale `100.117.1.47`) is a SEPARATE track the box agent owns — don't touch it.
* Guests + SSH users: debian-headless-2=`debian@192.168.64.4`, debian-headless-4=`debian@…10`, rocky-utm-1=`rocky@…105`, fedora-utm-1=`fedora@…103`, ubuntu-utm-1=`ubuntu@…21`. Key `/Users/iwan/.ssh/rustynet_lab_ed25519`, known_hosts `/Users/iwan/.ssh/known_hosts_lab`. Host shell is zsh — pass SSH opts inline or use `${=VAR}` (unquoted `$VAR` doesn't split).
* CLOCK DRIFT — re-sync before EVERY run. rocky + ubuntu have no NTP and drift (seen 5000s+/23000s off). `preflight` fail-closes on skew >90s (correct adjudication, not a bug). Before each run: `HE=$(date -u +%s); ssh … "$u@$ip" "sudo -n date -u -s '@$HE'"` for all 5.
* macOS Local-Network-Privacy sandbox (§12.3.1): the `rustynet-lab-state` MCP's in-process TCP probe reports `ssh_port_status=closed` for ALL nodes — a FALSE NEGATIVE. Trust the `utmctl`/`ready=true` half; the Bash tool is unsandboxed and reaches the lab fine (`nc -z`, `ssh`). The detached orchestrator's shelled-out `ssh` also works (runs got past preflight).
* vm-lab BINARY CLOBBER gotcha: live-lab stages `cargo run -p rustynet-cli` WITHOUT `--features vm-lab` rebuild `target/debug/rustynet-cli` minus every vm-lab subcommand → a CLI-direct run then errors "unknown ops subcommand". Before a CLI-direct run: `cargo build -p rustynet-cli --features vm-lab` and probe with `./target/debug/rustynet-cli 2>&1 | grep -c vm-lab-orchestrate-live-lab`.
* Launch a run (MCP, drives the Rust `--node` engine — `nodes=` is the ONLY thing that does): `start_live_lab_run` mode=orchestrate, `nodes=["debian-headless-4:exit","debian-headless-2:client","rocky-utm-1:entry","fedora-utm-1:aux","ubuntu-utm-1:extra"]`, `source_mode="local-head"`, `trust_inventory_ready=true`, `skip_soak=true`, `skip_cross_network=true`. (For the standard T0/T1 topology use `rocky:anchor fedora:relay ubuntu:admin` instead.) `local-head` deploys HEAD to guests but the two_hop test's `run_cargo_ops`/probe run on the HOST via `cargo run` from the working tree — so an uncommitted working-tree edit to the test bin DOES take effect on a re-run (that's how I validated).
* A run takes ~40 min. The `two_hop` stage is a small window near the end — use a background loop to capture live state (see `scratchpad/twohop_capture.txt` for the pattern: `while pgrep -f "vm-lab-orchestrate-live-lab.*<report-basename>"; do ssh entry+client wg/route/ping; sleep 25; done`).
* Monitor a run: `while pgrep -f "vm-lab-orchestrate-live-lab.*<report-basename>" >/dev/null; do sleep 60; done` in a background Bash (re-invokes you on completion). Then `get_run_result` + read `state/<report>/state/stages.tsv` + `live_two_hop.log`.
* A2-verify a run: `cargo run -q -p rustynet-cli --features vm-lab --bin live_lab_evidence_verifier -- --report-dir <RD>` (exit 0=valid pass, 2=valid non-pass, 1=INVALID, 3=error; the `--report-dir` path is the run dir).
* T5 negative controls: MCP has no param; run the CLI directly with `--enable-negative-control` (target/debug binary built with `--features vm-lab`; the signed-bundle + wrong-node controls run local/host-side, the residue + daemon-kill controls are `Skipped`).
* Only 2 Debian guests exist → the 5-node topology must include NM-based fedora/rocky/ubuntu. `fef40bb` (enforce_baseline MTU race) is an INTERMITTENT risk on those but passed in all 5 stability runs — don't over-index on it, but if `enforce_baseline_runtime` flakes on fedora/ubuntu that's why (memory `enforce_baseline_runtime_regression_fef40bb_2026-07-21`).
5. NON-NEGOTIABLE DISCIPLINE (this session lived by these — keep them)
* DIRECTION-DIAGNOSIS. bash is NOT the oracle; a `--node`/bash difference is often `--node` being MORE correct. And stale memories mislead — I chased a "client↔client bug" that was already fixed. Verify claims against the live code/lab before acting. (Memory `node_vs_bash_drift_direction`.)
* Big job → PLAN → FABLE ADVERSARIAL REVIEW → verify each finding yourself → build. Every fable review this session caught real, load-bearing errors. Do NOT skip it for anything load-bearing. For the two_hop dataplane fix, plan it and fable-review the plan before touching `rustynetd`.
* Hold unvalidated fixes uncommitted; validate LIVE before committing.
* Fail-closed; no TTL widening; §13.2 for any crypto/auth/policy/dataplane-trust change.
* Gates before landing (§7): `cargo fmt --all -- --check`; `cargo clippy --workspace --all-targets --all-features -- -D warnings` — **run it with NO exclusions.** *(Corrected 2026-07-25, re-verified: on the pinned toolchain this passes clean, `rustynet-mcp` included — 0 warnings/errors — and CI never excludes it (`.github/workflows/cross-platform-ci.yml:27,63` run the bare workspace clippy). The old "known pre-existing red on `rustynet-mcp`" guidance was a **Homebrew-1.97 artifact**, not a code defect: under `cargo 1.97` that crate emits 2 lints that do not exist on 0.1.88. Excluding it masked real regressions in the crate that fronts every MCP tool surface. Recheck: `PATH="$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin:$PATH" cargo clippy --workspace --all-targets --all-features -- -D warnings`.)* `cargo test`. Toolchain is pinned 1.88.0 — prepend `$HOME/.rustup/toolchains/1.88.0-aarch64-apple-darwin/bin` to PATH (Homebrew cargo 1.97 shadows it). ALWAYS also verify the DEFAULT (no-feature) build compiles (vm-lab is 3-site cfg-gated per `main.rs`; `--all-features` CI won't catch a default-build break).
* Never commit during a live lab run (the run records git HEAD at FINISH → misattribution).
* Commit author = `Iwan-Teague` ONLY, NEVER a `Co-Authored-By: Claude` trailer. Small logical commits, imperative subject, what+why. Push via the flip worktree `branch:main` ff while the box agent holds the main worktree dirty.
* Durable memory: `write_loop_note` after each iteration; `get_loop_journal` (#405–#428) is the full session history. The `rustynet-ai-agent` MCP (deepseek/kimi) was out of credit — triage manually / with fresh subagents.
6. Source-of-truth docs (read in this order for the flip context)
* `documents/operations/active/NodeEngineAcceptanceSpec_2026-07-23.md` — the G1/G2/G3 gate model (SIGNED OFF). §6.1 = dispositions.
* `documents/operations/active/NodeEngineFlipDispositions_2026-07-24.md` — the owner-signed flip dispositions (D1 two_hop, D2 live-T5, D3 network_flap), with the two_hop root cause.
* `documents/operations/active/G3EnumerationDiff_2026-07-23.md` — the zero-dropped-coverage proof.
* `documents/operations/active/TraversalSelfSustenancePlan_2026-07-23.md` — the network_flap track.
* `documents/operations/active/RustNodeOrchestratorCompletionBrief_2026-07-12.md` — the original Track A/B/C/D brief.
* `CLAUDE.md` §2/§4/§7/§9/§12/§13 — mission, security bar, gates, DoD, lab ops.
* Ledgers: `documents/operations/live_lab_node_run_matrix.csv` (the `--node` ledger — the one that counts) vs `live_lab_run_matrix.csv` (FROZEN bash archive — historical only). NEVER cross them.
Start by reading the journal (#405–#428) and the dispositions ledger, then §2 above. The flip is done — your job is the two_hop chained-exit dataplane (a deep, careful, fable-reviewed build). When in doubt: diagnose direction, hold unvalidated fixes uncommitted, and verify live.

---

# ============================================================================
# APPENDIX B — WS-B worker charter (box / Windows WinNAT). Hand to the worker VERBATIM.
# ============================================================================

Handoff — Ubuntu KVM box as a first-class remote lab host (Windows WinNAT + Fedora)
You are continuing work on Rustynet (`/Users/iwan/Desktop/Rustynet`, Rust workspace, branch `main`, direct-to-main convention — no PRs). Read `CLAUDE.md` first (esp. §2 ledgers, §12.3 live lab, §12.5 AI-agent MCP, §13). Commits are authored `Iwan-Teague <teague.iwan@outlook.com>` — never add a Claude co-author.
Mission
Make the x86-64 Ubuntu KVM box `ubuntu-kvm-1` a first-class remote live-lab host, drivable from this Mac exactly like the local UTM fleet, and use its nested-virt capability to prove the Windows WinNAT exit parity cell that Apple-Silicon UTM structurally cannot (release-blocking; `LinuxVmHostPlan_2026-07-14.md` §1.1). Owning ledger: `documents/operations/active/LinuxVmHostPlan_2026-07-14.md`. Also read `WindowsExitNodeRunbook_2026-06-04.md` (the `active_exit` WinNAT stage + readiness verify) and `CrossPlatformRoleParityPlan_2026-06-21.md`.
Access (all verified live this session)
* Box: `ssh ubuntu-server@100.117.1.47` (Tailscale; LAN IP `172.23.56.5`/`192.168.121.x` is stale-DHCP, use the tailnet). Repo at `/home/ubuntu-server/Rustynet`. libvirt `qemu:///system`, pool `/var/lib/libvirt/images` (group-writable `kvm`, no sudo needed for VM ops). Ryzen 7700X, 61 GiB, `kvm_amd nested=1`, ~397 G free. rustc/cargo 1.88.0 pinned. `eno1` has NO carrier (WiFi only) → guests are NAT-only behind `virbr0` on `192.168.121.0/24`; cross-machine reach rides Tailscale. Box has intermittent internet (WiFi) — downloads sometimes fail; retry.
* Box guests (all libvirt, reached from the box over SSH; from the Mac via the box's advertised tailnet subnet route):
   * `linux-x86-client-1` @ `192.168.121.137`, user `debian`, key-auth (box `~/.ssh/id_ed25519`)
   * `linux-x86-exit-1` @ `192.168.121.26`, user `debian`
   * `windows-x86-1` @ `192.168.121.108`, user `labadmin`, key-auth primed + pinned in box `~/.ssh/known_hosts`; password also in the secrets sidecar
   * `fedora-x86-1` @ `192.168.121.227`, user `fedora`, key-auth, sudo-ok
* Inventory: `documents/operations/active/vm_lab_inventory.json` (both new guests registered, controller `libvirt`, `host_id: ubuntu-kvm-1`). Never hand-edit for IPs — use `--update-inventory-live-ips`. Lab SSH passwords live OUTSIDE the tracked inventory in `vm_lab_inventory.secrets.json` (mode 600, untracked; `windows-x86-1` has an entry). `hosts[]` declares `ubuntu-kvm-1` (`connect_uri: qemu+ssh://ubuntu-server@ubuntu-headless/system`, `guest_subnet: 192.168.121.0/24`).
* MCP (`rustynet-lab-state`): the client connection is LIVE again (reconnected). Tools: `sync_host`, `host_preflight`, `discover_hosts`, `launch_live_lab_on_host`, `host_run_status`, `fetch_host_artifact`, `stop_host_run`, `compare_runs_at_commit` (all take `--host ubuntu-kvm-1`), plus `provision_guest`, `host_disk_status`, `recover_stuck_vms`, `get_vm_diagnostics`. Gotcha: MCP client times out at ~60s — for slow ops (sync fetch, build, orchestrate) drive the CLI directly via Bash: `cargo run -q -p rustynet-cli --features vm-lab -- ops <cmd>`. Stdio fallback if the client server is stale/down: `state/mcp_call.sh lab-state <tool> '<json>' <timeout>`. If an MCP tool seems missing, the `bin/rustynet-mcp-*` binaries rot silently — run `scripts/ci/check_mcp_binaries_fresh.sh --fix`, then reconnect the client (a client-side action you cannot trigger yourself; ask the user).
DONE (committed + pushed to origin/main, fully gated)
Five pre-existing lab-tooling bugs that blocked driving labs on the box, fixed at `b689cd6` + review-polish `caeff99` (fmt + clippy + `cargo test --workspace --all-targets --all-features` all green):
* BUG-BOX-5 (HIGH): the `--node` orchestrate readiness gate (`crates/rustynet-cli/src/vm_lab/orchestrator/readiness.rs`) was UTM-only; now dispatches by controller kind and probes libvirt guests via `selected_nodes_readiness_with_libvirt` (`vm_lab/mod.rs`) at the same bar. This is what unblocked box runs.
* BUG-BOX-4 (MED): `launch_live_lab_on_host` now auto-injects `--known-hosts-file` (default `$HOME/.ssh/known_hosts`) + `--host-known-hosts` flag.
* BUG-BOX-1 (MCP `get_vm_diagnostics` `--output-dir`), BUG-BOX-2 (restart-runtime fail-loud guard), BUG-BOX-3 (slow-op timeout doc). Full detail: `documents/operations/active/UbuntuHostLabControl{Findings,RemediationPlan}_2026-07-23.md` (the remediation plan has the adversarial-review findings). An adversarial review found NO fail-closed regression; the libvirt readiness path is equal-or-stricter than UTM.
Parallel-lab workflow PROVEN end-to-end: concurrent Mac (UTM) + box (libvirt) `--node` runs at one commit, both clean, merged via `compare_runs_at_commit --include-hosts ubuntu-kvm-1` → 54 linux stages, 0 fail, VERDICT PASS. First-ever `linux-x86` evidence rows landed in the box ledger. Also confirmed through the live client MCP (launch → poll `host_run_status` → read failure `error_detail` inline). The full box `--node` suite has ONE real red: `live_network_flap_validation` (the known traversal self-sustenance gap — approved fix in `TraversalSelfSustenancePlan_2026-07-23.md`, NOT a box-specific issue).
Windows WinNAT guest STOOD UP (`windows-x86-1`, this session): Windows 11 25H2 x64, installed unattended on KVM (UEFI + TPM2 + SATA disk + e1000e net + `--cpu host-passthrough`). Verified live: `Get-NetNat` present, `MSFT_NetNat` CIM class present (the exact WinNAT/HNS stack Apple-Silicon UTM lacks), `NestedVirt_fw=True`, `sshd Running`, `rustc 1.88.0` installed, key-auth as `labadmin`. This is the hardware-level WinNAT unblock — the whole reason the box exists.
PENDING — pick up here (priority order)
1. Finish the Windows node bootstrap on `windows-x86-1` (task #10). rustc 1.88 is present; verify/complete: rustynet source synced to `C:\Rustynet`, release build of `rustynetd.exe` + `rustynet-cli.exe` (build state was NOT confirmed — nested PowerShell-over-SSH quoting kept breaking; verify `Test-Path C:\Rustynet\target\release\rustynetd.exe`). Then membership/enrollment. Windows bootstrap prereqs differ from Linux (WireGuard-NT, WFP killswitch, DPAPI key custody, NRPT DNS) — see `project_windows_runtime_state` memory (Windows was FULLY GREEN r49 on the UTM guest, 17/17 stages) and `WindowsLiveLabReadinessPlan_2026-05-31.md`.
2. Provision the Fedora node fully (`fedora-x86-1`, reachable + sudo-ok but rustup/toolchain NOT installed, not built). Run `provision_guest_toolchain` (aliases `["fedora-x86-1"]`) then `bootstrap_vm` phases. NOTE Fedora quirks from `wide_linux_node_run_recipe` memory (offline-build: dnf toolchain / CA-symlink / cache-seed via SOCKS; clock-sync).
3. Run the Windows WinNAT exit live-lab cell — the payoff. From the Mac: `launch_live_lab_on_host --host ubuntu-kvm-1` with a topology electing `windows-x86-1` as the exit (`--exit-platform windows` / `--macos-promote-exit`-style selector — check the exact `--node`/platform flags in `WindowsExitNodeRunbook_2026-06-04.md`; the `active_exit` stage drives `route advertise 0.0.0.0/0` → asserts forwarding + NAT + `Get-NetNatSession`). This is the release-blocking cell the Mac cannot prove. After a green run, promote the Windows-exit support flag in `role.rs` (the runbook documents the deliberate post-green step).
4. Push the 2 unpushed inventory commits (`aeab3f42` register windows-x86-1, `05074382` register fedora-x86-1) once the guests are proven — ask the user; the tree also has concurrent task-session commits (flip dispositions, dirty-check fixes) that are NOT yours.
Gotchas / lessons (save yourself the pain)
* PowerShell-over-SSH quoting is hell through the Mac→box→Windows double-SSH hop: `$null`/`$env:` get eaten, nested quotes break. Write the `.ps1` to a file, `scp` it to `C:\Windows\Temp\`, run `powershell -NoProfile -ExecutionPolicy Bypass -File ...`. Don't inline complex PS.
* Windows on KVM: SATA OS disk + e1000e net = no risky virtio driver injection at install (native to Windows setup); the `autounattend.iso` (unattended, OpenSSH auto-enabled, OOBE skipped, user `labadmin`) is built with `genisoimage -V UNATTEND`. The staged `/tmp/win_virtinstall.sh` + `/tmp/autounattend.xml` on the box are the recipe. hostname is currently the default `DESKTOP-HSD3EFJ`.
* Never edit `vm_lab/mod.rs` or run orchestrator source during a live run — trips the setup-manifest provenance check (memory `feedback_no_edit_during_working_tree_lab_run`).
* Dirty-provenance quirk: a `--node` run sometimes records `git_dirty_state=dirty:worktree` (its own ledger append timing) even from a clean tree at start; `compare` refuses dirty evidence → use `allow_dirty:true` when you know the dirtiness is only the run's own evidence append, not code drift. (There's now a committed fix from a concurrent session — `65b93688`/`a414cebe` exclude the engine's own evidence ledgers from the dirty check; verify it took.)
* Box downloads flake (WiFi). The Windows ISO download failed several times before succeeding; the user pastes fresh signed MS ISO URLs (valid ~24h) when needed. Stage the URL in a file, `curl` detached with `setsid`, monitor a `.part`→final rename.
* Box is on `main` and syncs only PUSHED commits (`sync_host` does `git fetch origin <sha>`). Push before syncing the box. The dirty-host guard refuses to clobber box-side evidence ledgers (correct) — fetch evidence or `--discard-host-changes`.
* `--skip-linux-live-suite` runs only setup + the focused mac/win/target cell (fast inner loop, ~15 min), skipping the ~30-45 min Linux suite. Use it while iterating a single cell.
Standing protocol
Verify current state before acting (probe the guests — don't trust this doc's "DONE" blindly; e.g. confirm the Windows build state, which was unverified). Use the `rustynet-mcp-ai-agent` MCP (DeepSeek default) to offload log/journal reading. Use adversarial-review subagents before landing security-adjacent changes. Never idle during a live run — work real TODOs on an isolated worktree.
