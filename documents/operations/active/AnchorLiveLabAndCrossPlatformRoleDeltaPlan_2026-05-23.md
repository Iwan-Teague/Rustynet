# Anchor Live-Lab Coverage + Cross-Platform Role + Adversarial Test Delta Plan
**Generated:** 2026-05-23
**Repository Root:** workspace root
**Scope:** Add live-lab coverage for the anchor role, outline what is missing for Windows and macOS to be exercised as exit_server / relay / anchor / blind_exit in the live lab, and add an adversarial / fault-injection / chaos category that actively tries to break Rustynet under real-world failure modes.

## Execution Scope

```text
You are the implementation agent for the three parallel tracks defined below.
Repository root: workspace root
Output file to keep updated during the work: documents/operations/active/AnchorLiveLabAndCrossPlatformRoleDeltaPlan_2026-05-23.md

Mission:
- Track A: extend the live lab so the anchor role (D11) is exercised end-to-end
  on at least one Linux host with the same rigour we already apply to client +
  exit_server. Anchor unit tests + CI gates exist (scripts/ci/anchor_*.sh) but
  no live-lab stage exercises the bundle-pull listener, gossip priority,
  enrollment endpoint, port-mapping authority, or downgrade revocation under
  the real systemd / launchd / SCM service lifecycle.
- Track B: close the topology-selection and platform-validator gaps that
  currently prevent picking a Windows or macOS host as the active exit_server,
  relay, or anchor in the orchestrator. This is a scoped survey; concrete
  implementation lands in follow-up tracks once the gaps are confirmed.
- Track C: add an adversarial / fault-injection / chaos test category to the
  live lab. The current 60+ stages cover happy-path + a few negative paths,
  but do not actively try to *break* Rustynet under crash, replay, clock
  attack, resource exhaustion, network impairment, membership poisoning, or
  concurrent-transition stress. This track inventories the categories,
  proposes concrete stages, and outlines required tooling (impairment
  harness, signed-bundle forger, chaos coordinator).

Mandatory reading order:
1. AGENTS.md
2. CLAUDE.md
3. documents/Requirements.md
4. documents/SecurityMinimumBar.md
5. documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md (D11 + D12)
6. documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md
7. documents/operations/active/NodeRoleTaxonomy_2026-05-21.md
8. documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md
9. documents/operations/active/HomelabConnectivityParityDeltaPlan_2026-05-21.md
10. This document
11. The code you touch

Hard truth:
- Anchor unit tests prove pieces in isolation; a signed anchor must survive
  daemon restart, role-transition planner, service-manager-driven lifecycle,
  and live peers pulling bundles. Until live-lab evidence exists, anchor is
  not release-gate ready.
- Windows currently has validate_windows_exit_* stages, but they assert
  *readiness* properties on the Windows host while Linux exit-1 is still the
  active mesh exit. None of them flip the mesh exit role onto Windows.
- macOS has zero exit / relay / anchor live-lab validators.

Non-negotiables:
- One hardened execution path per security-sensitive flow. No legacy fallback.
- Fail closed on missing, stale, replayed, or unauthorized state.
- No TODO/FIXME/placeholders in completed deliverables.
- New stages must integrate with the existing report dir / stages.tsv /
  failure_digest plumbing.
```

## Read Order And Source Of Truth

When documents disagree, apply this precedence:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
4. `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`
5. `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
6. This document
7. Supporting design docs
8. `README.md` and operational runbooks

## Track A — Anchor Live-Lab Stages

### A0. Pre-conditions Already In Place

- `RoleCapability::Anchor` and the five sub-capabilities (`AnchorGossipSeed`,
  `AnchorBundlePull`, `AnchorEnrollmentEndpoint`, `AnchorRelayColocation`,
  `AnchorPortMappingAuthoritative`) defined in `crates/rustynet-control/src/roles.rs`.
- Daemon: bundle-pull listener (`crates/rustynetd/src/daemon.rs`,
  loopback-only by default, token-gated), gossip anchor-priority rebroadcast
  (`crates/rustynetd/src/gossip_runtime.rs`), port-mapping multi-anchor
  coordination (`crates/rustynetd/src/port_mapper.rs`).
- CLI: `rustynet anchor init` planner (`crates/rustynet-cli/src/anchor_init.rs`,
  currently `--dry-run` only).
- Unit test gates: `scripts/ci/anchor_role_gates.sh`,
  `scripts/ci/anchor_downgrade_gates.sh`,
  `scripts/ci/anchor_secret_redaction_gates.sh`.

### A1. New Live-Lab Stages

Add five stages between `validate_baseline_runtime` and the existing
`live_exit_handoff` / `live_two_hop` / `live_lan_toggle` block. They run on
the Linux exit node (`exit-1`) because it already carries `Anchor` + `Client`
+ `ExitServer` from genesis (per the D11 work-in-progress + the `start.sh`
6-role wizard).

| # | Stage name | Validates | Fail-closed signal |
|---|---|---|---|
| 1 | `validate_anchor_membership_advertise` | exit-1 membership entry contains all five anchor sub-caps; `rustynet anchor status` JSON matches the signed snapshot; non-anchor peers do not advertise the caps | absent or stale anchor caps in `membership.snapshot` |
| 2 | `validate_anchor_bundle_pull` | loopback bundle-pull listener is up; SSH-tunnelled peer with a valid token receives the signed snapshot byte-for-byte; tokens shorter than 32 printable ASCII or expired tokens fail-closed; LAN bind blocked unless `--anchor-bundle-pull-allow-lan` set | listener missing, accepts invalid token, or returns body that does not match `membership.snapshot` digest |
| 3 | `validate_anchor_gossip_priority` | promote `client-2` (relay-1) to a second anchor; gossip from clients prefers exit-1 (lex-min authority); the second anchor passively rebroadcasts and never claims port-mapping authority while exit-1 is up | both anchors claim authoritative status, or non-anchor peer is preferred over an active anchor |
| 4 | `validate_anchor_enrollment_endpoint` | a fresh node (debian-headless-5 brought online with no signed state) presents an enrollment token to the anchor; anchor returns a sealed bundle; the new node enrols, surfaces in the membership snapshot, and joins mesh on next reconcile | enrollment without token succeeds, or sealed bundle decrypts under any non-issued key, or the new node lacks anchor-signed approver attestation |
| 5 | `validate_anchor_downgrade_revocation` | owner-signed revocation of `anchor.bundle_pull` propagates; running listener stops within the reconcile interval; in-flight pulls (started before revocation) complete; new pull attempts fail-closed; downgrade audit log entry emitted | listener keeps serving after revocation, or no audit entry recorded |

### A2. Files To Add / Touch

- **New Rust integration bin:** `crates/rustynet-cli/src/bin/live_linux_anchor_test.rs`
  - Pattern: mirror `crates/rustynet-cli/src/bin/live_linux_exit_handoff_test.rs` (SSH + tokio runtime, signed-bundle IO, monitor loop).
  - Stage-internal sub-tests for A1.1 → A1.5.
  - Emits JSON report at `--report-path` and human-readable log at `--log-path`.
- **New wrapper script:** `scripts/e2e/live_linux_anchor_test.sh`
  - Single-line `exec cargo run --quiet -p rustynet-cli --bin live_linux_anchor_test -- "$@"` (matches existing wrappers).
- **Orchestrator wiring:** `scripts/e2e/live_linux_lab_orchestrator.sh`
  - Add `stage_run_live_anchor` function calling the wrapper script.
  - Add `run_stage hard live_anchor 'run live anchor role validation' stage_run_live_anchor` after `validate_baseline_runtime`, before `live_role_switch_matrix`.
  - Skip rule when no anchor-capable target is available (mirrors the existing `record_stage_skip` patterns).
- **Stage list:** `crates/rustynet-cli/src/vm_lab/mod.rs`
  - Add `"live_anchor"` to `FULL_RELEASE_GATE_REQUIRED_STAGES`.
  - Add the stage name + log/artifact paths to the orchestration outcome scaffolding.
- **CI gate script:** `scripts/ci/anchor_live_lab_gates.sh`
  - Reuses the existing per-stage runner pattern from `phase9_gates.sh`.
  - Runs unit tests + an offline dry-run of the new live test bin so PR-time CI catches regressions without standing up VMs.

### A3. Definition Of Done

- All five sub-stages PASS on a clean Debian 13 + macOS 26.x + Windows 11 lab
  run (`rustynet ops vm-lab-orchestrate-live-lab --legacy-bash-orchestrator
  --exit-vm debian-headless-1 --client-vm debian-headless-2 --windows-vm
  windows-utm-1 --macos-vm macos-utm-1`).
- Evidence regenerated under `documents/operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md` (or successor) with the new stage outcomes appended.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-targets --all-features` all green.
- `scripts/ci/anchor_live_lab_gates.sh` exits zero.
- No TODO / FIXME / placeholder left in the new bin, script, or orchestrator integration.

### A4. Sequencing (recommended)

1. Land A2 unit-test scaffolding in `live_linux_anchor_test.rs` covering A1.1
   and A1.2 against a single-node mock (the bin should compile and dry-run
   green before live wiring).
2. Wire `live_anchor` into the bash orchestrator behind a skip rule
   (`stage_skip` when no anchor target is present) so PRs without an anchor
   topology do not regress.
3. Implement A1.3 → A1.5 incrementally, gated by individual sub-stage CI
   gates so each lands testable.
4. Refresh `documents/operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md` once all five sub-stages pass on the canonical lab topology.

## Track B — Multi-Platform Role Test Gap Analysis

Goal: make the live lab able to drive a topology where the **active mesh
exit / relay / anchor** is a Windows or macOS host instead of Linux.

### B1. Shared Blockers (apply to both Windows and macOS)

| # | Blocker | Where it lives | Impact |
|---|---|---|---|
| B1.1 | Orchestrator topology hardcodes Linux exit-1 as the mesh exit | `scripts/e2e/live_linux_lab_orchestrator.sh` (`build_onehop_specs`); `crates/rustynet-cli/src/vm_lab/mod.rs` (selected-alias plumbing) | Need a `--exit-platform <linux|windows|macos>`, `--relay-platform`, `--anchor-platform` selector that drives NODES_SPEC, ASSIGNMENTS_SPEC, and per-platform install scripts |
| B1.2 | Membership genesis runs only on the Linux exit-1 node | `crates/rustynet-cli/src/ops_e2e.rs` (`e2e-bootstrap`) | Need a platform-agnostic genesis surface or a per-platform helper (`rustynet ops e2e-bootstrap-windows`, `rustynet ops e2e-bootstrap-macos`) so the bootstrap host can be non-Linux |
| B1.3 | Live tests assume nftables killswitch + iproute2 route advertise | `scripts/e2e/live_linux_*.sh`, daemon enforcement paths | Each test bin needs platform-aware command dispatch (already partially abstracted in the role-switch test); validators must accept the equivalent pf / Windows-firewall artefacts |
| B1.4 | Role-transition planner is Linux-only for `exit`, `relay`, `anchor` deploy/undeploy actions | `crates/rustynet-cli/src/role_cli.rs` `plan_concrete_actions` + adapters | Already started for relay/anchor via `ops_install_macos_relay.rs` (uncommitted) and the Windows installer; needs completion + tests |
| B1.5 | No platform-neutral "lab topology profile" — selection is implicit in the orchestrator script | Inventory + orchestrator | Add an optional `topology.json` describing which platform owns which role for the run; default profile keeps current Linux-exit behaviour |

### B2. Windows-Specific Gaps

| # | Gap | Notes |
|---|---|---|
| W1 | `validate_windows_exit_*` stages validate Windows host readiness, not active mesh exit role | Already in tree: `validate_windows_exit_nat_lifecycle`, `validate_windows_exit_dns_failclosed`, `validate_windows_exit_killswitch_precedence`. Need an actual-exit variant that asserts client mesh traffic egresses via Windows |
| W2 | No Windows relay service install path | macOS launchd has `scripts/launchd/com.rustynet.relay.plist`; Linux has `scripts/systemd/rustynet-relay.service`; Windows SCM equivalent missing |
| W3 | Windows anchor install path absent | Bundle-pull listener integration with Windows DPAPI-protected tokens untested in live lab |
| W4 | Windows SCM role transitions not exercised | `OpsCommand::InstallWindowsService` / `InstallWindowsRelayService` exist but role-switch planner does not currently call them during exit/relay/anchor transitions |
| W5 | UTM guest-file pull failures (`probe.json` "file not found", OSStatus -2700) seen in current runs | Likely needs UTM guest-tools install verification on the Windows VM; documented in `documents/operations/active/HomelabConnectivityParityDeltaPlan_2026-05-21.md` W-track |

### B3. macOS-Specific Gaps

| # | Gap | Notes |
|---|---|---|
| M1 | Zero exit-mode validators | Need `validate_macos_exit_nat_lifecycle` (pf-based), `validate_macos_exit_dns_failclosed`, `validate_macos_exit_killswitch_precedence` parallel to the Windows set |
| M2 | macOS relay live test missing | `ops_install_macos_relay.rs` + `scripts/launchd/com.rustynet.relay.plist` are in tree but no live stage exercises them |
| M3 | macOS anchor live test missing | Bundle-pull listener is Unix-portable; need launchd unit + live stage validating it after `anchor init` on macOS |
| M4 | macOS killswitch invariants not validated under role transitions | `documents/operations/active/HomelabConnectivityParityDeltaPlan_2026-05-21.md` M4 |
| M5 | Daemon role-switch via launchd not wired | Linux has `rustynetd-relay.service`; macOS plist exists for relay but the role transition planner does not drive launchd transitions |
| M6 | macOS bootstrap depends on internet egress for `rustup update` | Current run hit this because the daemon killswitch persisted from a prior run; orchestrator's `cleanup_hosts` removes nftables but the equivalent pf cleanup path on macOS needs verification |

### B4. Suggested Unblock Order

1. **B1.5 + B1.1** — Add `topology.json` profile + `--exit-platform / --relay-platform / --anchor-platform` selectors so the orchestrator can be told who owns each role. Keep the current Linux-exit default unchanged.
2. **M1** — Add the three macOS exit-mode validators (parallel to W1's Windows set). Skip when macOS is not the exit.
3. **B1.4** — Complete the role-transition planner for non-Linux platforms (use the already-started `ops_install_macos_relay.rs` and Windows installers as the seam).
4. **W1** — Promote `validate_windows_exit_*` to active-exit validators when `--exit-platform windows` is set.
5. **M5 + W4** — Wire role-transition into launchd / SCM so the planner can actually flip exit/relay/anchor onto non-Linux hosts at runtime.
6. **W2 / W3 / M2 / M3** — Add live-lab stages exercising relay + anchor on each platform once the install paths are exercised.
7. **B1.2** — Optional final step: enable a fully non-Linux origin run by making the genesis platform-agnostic.

### B5. Out Of Scope For This Document

- Mobile (iOS / Android) role host eligibility — the role taxonomy locks these to `client` for the foreseeable future.
- Cross-network NAT matrix coverage for non-Linux exits — landing this requires B1.4 + B1.5 first; revisit after.
- Live-lab anchor co-deployment with a remote relay (D11.b two-anchor failover) — already covered in `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md` D11.b; this document only covers single-host anchor stages.

## Track C — Adversarial / Fault-Injection / Chaos Live-Lab Stages

### C0. Current Coverage Baseline

Today the live lab has ~60+ unique stage names. Of those, only a handful
exercise *negative* paths:

- `live_linux_endpoint_hijack_test` — adversarial endpoint takeover (signed-bundle replay vectors against a specific peer).
- `live_linux_server_ip_bypass_test` — checks that exit-IP cannot be observed by clients via DNS leaks.
- `live_linux_control_surface_exposure_test` — verifies daemon control surface is not externally reachable.
- `cross_network_traversal_adversarial` — adversarial traversal-bundle inputs.
- `extended_soak` — long-duration run, but no active fault injection.

Everything else is happy-path or expected-config validation. There is no
stage that actively crashes the daemon mid-operation, fills the disk,
forges membership updates, or skews the clock past the max-age window
while live peers depend on the bundle.

### C1. Adversarial Category Inventory

Eight categories. Each entry includes the failure modes it targets and
the new stage(s) it proposes.

#### C1.1 Daemon Process Fault Injection

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_daemon_kill_during_reconcile` | `kill -KILL rustynetd` while `validate_baseline_runtime` traffic is in flight | daemon restarts, killswitch holds until daemon binds socket; no plaintext egress observed in `tcpdump` between kill and bind |
| `chaos_daemon_oom_during_bundle_write` | use `prlimit --as` to clip daemon address space mid-`assignment-refresh` | bundle file either present-and-valid or absent (no partial / corrupt write); recovery on next reconcile |
| `chaos_daemon_sigstop_sigcont` | `SIGSTOP` the daemon for 60s longer than reconcile interval, then `SIGCONT` | peer-side timers expire, peers go fail-closed, daemon resumes and resyncs without leaking plaintext during the stop window |
| `chaos_helper_socket_race` | open many parallel connections to `/run/rustynet/rustynetd-privileged.sock` with malformed argv | helper enforces argv-only exec, no shell construction, no panic, audit log records rejections |

#### C1.2 Clock Attack Suite

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_clock_jump_forward_past_max_age` | `timedatectl set-time` on exit jumps ahead `max_age_secs + 60s` | peers reject newly-signed bundles as future-dated; once clock resyncs (NTP), recovery without manual intervention |
| `chaos_clock_jump_backward_past_replay_window` | jump clock back beyond replay watermark | replay protection rejects; watermark not regressed |
| `chaos_clock_skew_slow_drift` | introduce 5%/sec drift over 10 minutes | reconcile loop tolerates within `max_clock_skew_secs`; out-of-bounds drift triggers fail-closed |

#### C1.3 Signed-State Adversarial Inputs

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_replay_old_membership` | inject an older signed membership update with valid signature but stale watermark | rejected with replay error; daemon stays on current snapshot |
| `chaos_future_dated_assignment` | issue an assignment bundle with `generated_at_unix > now + clock_skew_max` | bundle rejected; existing bundle continues serving |
| `chaos_malformed_bundle_truncation` | truncate signed bundle to 1 byte, half-length, length-prefix corruption | each variant fails-closed; no panic; daemon logs structured rejection reason |
| `chaos_forged_signature_attempt` | submit bundle signed by a different (unauthorised) key | signature verification fails; no state mutation |
| `chaos_quorum_starvation_propose` | submit a propose-add update needing quorum that cannot be reached | record remains pending; daemon does not accept partial-quorum updates |

#### C1.4 Crash Recovery

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_crash_during_membership_apply` | kill daemon between `verify-update` and `apply-update` | snapshot integrity preserved (rollback to prior valid snapshot or atomic apply completes on restart) |
| `chaos_crash_during_tunnel_setup` | kill daemon after WG interface created but before route table installed | next reconcile cleans partial interface; killswitch holds during the gap |
| `chaos_crash_during_bundle_write` | kill daemon mid-`publish_file_with_owner_mode` | atomic rename guarantees pre-write OR post-write state, never partial |

#### C1.5 Resource Exhaustion

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_disk_full_signed_state_write` | fill `/var/lib/rustynet` filesystem during bundle write | write fails with structured `Io` error; existing bundle untouched; daemon stays on prior good state |
| `chaos_readonly_filesystem_state` | remount `/var/lib/rustynet` read-only mid-run | reconcile reports `Io` failure cleanly; no panic |
| `chaos_inotify_watch_exhaustion` | exhaust `fs.inotify.max_user_watches` so daemon cannot register watchers | startup either succeeds with degraded watcher fallback or fails-closed with a clear log; no half-armed state |
| `chaos_file_descriptor_exhaustion` | `ulimit -n 32` for daemon, then load all peers | startup fails-closed with clear error; no partial WG state left behind |

#### C1.6 Network Impairment Matrix

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_heavy_packet_loss` | `tc qdisc add dev <iface> root netem loss 60%` on exit-1's link | mesh stays up via retries; relay path activates if direct loss exceeds threshold |
| `chaos_jitter_with_reorder` | `tc qdisc ... netem delay 200ms 100ms reorder 25%` | handshake completion within budget or controlled failover to relay |
| `chaos_asymmetric_route_break` | block one direction of WG UDP via `iptables` / `pf` | WG handshake fails-closed within keepalive window; recovery on rule remove |
| `chaos_mtu_blackhole` | drop ICMP fragmentation-needed, set MTU mismatch | path-MTU recovery without leaking plaintext; metric event recorded |
| `chaos_dns_poisoning_attempt` | local DNS returns wrong IP for mesh hostnames | signed DNS zone bundle rejects unsigned answers; resolver fail-closed |

#### C1.7 Membership Adversarial Scenarios

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_concurrent_role_transitions` | request `role set exit` on three nodes simultaneously | only one becomes exit; others see conflict and remain client; audit log captures the race resolution |
| `chaos_owner_key_compromise_simulation` | rotate owner key under load; old signed updates submitted with old key | post-rotation updates with old key rejected; in-flight pre-rotation updates complete cleanly |
| `chaos_revoked_node_persistence` | propose-revoke a client; ensure revoked node cannot mesh-rejoin even with old assignment bundle | revoked node fails-closed; existing peers drop the revoked node's traversal target |
| `chaos_membership_log_tamper` | bit-flip a byte in `membership.log` post-write | next read detects digest mismatch; daemon refuses to apply derived state |

#### C1.8 Privileged Boundary Stress

| Stage | What it does | Pass criterion |
|---|---|---|
| `chaos_privileged_helper_malformed_argv` | call helper with arg lists containing shell metacharacters, null bytes, oversize args | rejected; no shell construction; no panic; auditable rejection reason |
| `chaos_privileged_helper_socket_race` | rapid open/close cycles racing daemon socket creation | helper rejects mid-create connections cleanly |
| `chaos_setuid_binary_inspection` | confirm no setuid bit on rustynet binaries; confirm helper drops privileges where applicable | bit set as expected (or absent) per `documents/SecurityMinimumBar.md`; no extra setuid surface |

### C2. Shared Tooling Needed

Most chaos stages need a small amount of new tooling. Build once, reuse
across stages.

- **Impairment harness** (`scripts/e2e/chaos_impair_link.sh`)
  - Wrap `tc` (Linux) / `dnctl` + `pfctl` (macOS) / `netsh interface` (Windows).
  - Inputs: alias, direction (in/out/both), profile (loss/delay/reorder/asym).
  - Output: JSON manifest of applied rules for diagnostic capture; clean teardown on stage exit.
- **Signed-bundle forger** (`crates/rustynet-cli/src/bin/live_signed_bundle_forger.rs`)
  - Generates adversarial inputs: truncated, future-dated, signature-mismatched, replay-watermarked, quorum-starved.
  - **Hermetic and offline only** — never accepted by production daemons; used by chaos stages to feed test inputs.
- **Chaos coordinator** (extension to `scripts/e2e/live_lab_common.sh`)
  - Adds `live_lab_chaos_inject` / `live_lab_chaos_release` helpers.
  - Ties injection to per-stage report dir with timing and recovery deadline.
- **Crash-aware logging gate** (`scripts/ci/chaos_gates.sh`)
  - Asserts that during any chaos-stage window the killswitch holds: no plaintext UDP from mesh IPs to non-mesh CIDRs in `tcpdump` captures.

### C3. Files To Add / Touch

- New Rust bins (one per category, each owning the sub-stages):
  - `crates/rustynet-cli/src/bin/live_chaos_daemon_fault_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_clock_attack_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_signed_state_adversarial_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_crash_recovery_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_resource_exhaustion_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_network_impairment_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_membership_adversarial_test.rs`
  - `crates/rustynet-cli/src/bin/live_chaos_privileged_boundary_test.rs`
- Wrappers for each: `scripts/e2e/live_chaos_*.sh`.
- Orchestrator wiring: append `run_stage hard chaos_<category>` lines in `live_linux_lab_orchestrator.sh` after the existing `live_*` block, gated by a new `--enable-chaos-suite` flag so default runs stay fast.
- New top-level CI gate: `scripts/ci/chaos_gates.sh` running offline subset (forger output + impairment harness arg parsing).
- Documentation: extend `documents/operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md` with a chaos-evidence section once stages land.

### C4. Sequencing

1. **C2 tooling** lands first (impairment harness, forger, chaos coordinator). Without it everything else is bespoke.
2. **C1.1 Daemon Fault Injection** — smallest blast radius, biggest signal-to-noise. Two stages (kill-during-reconcile, crash-during-bundle-write) are the canonical "did we leave broken state behind" canaries.
3. **C1.3 Signed-State Adversarial Inputs** — relies on the forger; covers the largest set of negative-path security checks.
4. **C1.4 Crash Recovery** + **C1.5 Resource Exhaustion** — paired since both need atomic-write invariants validated.
5. **C1.6 Network Impairment Matrix** — needs the impairment harness; can run independently of the others.
6. **C1.2 Clock Attack Suite** — needs the lab to tolerate clock perturbation (VMs should snapshot+restore time at stage exit); land after the simpler stages prove the chaos coordinator works.
7. **C1.7 Membership Adversarial Scenarios** + **C1.8 Privileged Boundary Stress** — last because they touch the most-sensitive code paths and require the forger + chaos coordinator to be battle-tested.

### C5. Definition Of Done (Track C)

- All chaos stages run with `--enable-chaos-suite` and emit per-stage outcomes into the standard `state/stages.tsv`.
- For every chaos stage, the recovery deadline is encoded in the report and verified against measured recovery time.
- `tcpdump` captures across chaos stages prove zero plaintext leakage from mesh IPs to non-mesh CIDRs during fault windows.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo test --workspace --all-targets --all-features` all green.
- `scripts/ci/chaos_gates.sh` exits zero on hermetic subset (forger output + impairment harness arg parsing).
- Evidence captured in `documents/operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md` with one row per chaos stage and a link to the stage log + tcpdump artifact.
- No TODO / FIXME / placeholder left in new bins, scripts, or harness modules.

### C6. Out Of Scope For This Document

- Long-horizon fuzzing of the IPC protocol (libfuzzer / cargo-fuzz integration) — separate testing track.
- Formal model-checking of the membership log (TLA+ / Stateright) — research-level work, not live-lab.
- Cross-tenant tenancy attacks — Rustynet is single-tenant by design today.

## Risk Register

- **R1.** Adding a second anchor in A1.3 risks collision with the lex-min
  authority logic if both anchors race port-mapping claims. Mitigation: the
  test orchestrates the order (exit-1 active first, then second anchor joins
  with passive role) and inspects gossip authority transitions in the daemon
  trace.
- **R2.** Bundle-pull listener token rotation is not yet wired into the
  orchestrator. A1.2 must validate a token issued in the same orchestration
  run, not an inventory-pinned one.
- **R3.** Live anchor enrollment (A1.4) requires a node without prior signed
  state. The existing `debian-headless-5` "extra" VM is the natural target;
  the orchestrator must skip cleanup on that VM so its initial-enrollment
  artefacts are not wiped before the test runs.
- **R4.** Exposing the platform-selection knobs (B1.1) early risks
  surprising operators running the existing single-Linux-exit topology.
  Default behaviour must remain unchanged; the selectors are opt-in.
- **R5.** Chaos stages can leave a VM in a degraded state (corrupted
  filesystem, skewed clock, half-armed pf rules) if a stage aborts before
  cleanup. Mitigation: every chaos stage registers its teardown handler
  with the chaos coordinator before injection; the orchestrator runs all
  registered teardowns on stage exit regardless of pass/fail, and a final
  `chaos_post_run_invariants` stage asserts no residual perturbation.
- **R6.** The signed-bundle forger (C2) must never be reachable from
  production builds. Mitigation: gate the binary behind a build feature
  (`--features chaos-forger`) and assert in CI that release artifacts do
  not include it.
- **R7.** Network impairment via `tc` / `pf` can break orchestrator SSH
  if applied to the wrong interface. Mitigation: impairment harness
  enforces an explicit allow-list of safe interfaces (the WG tunnel
  interface + the VM's bridge-side virtio NIC), never the orchestrator
  control plane NIC, and validates the rule set against an inventory
  manifest before applying.

## Tracking And Cross-References

- Anchor role canonical design: `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`
- Role taxonomy: `documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`
- Dataplane execution ledger (D11 + D12): `documents/operations/active/RustynetDataplaneExecutionPlan_2026-05-18.md`
- Connectivity parity ledger: `documents/operations/active/HomelabConnectivityParityDeltaPlan_2026-05-21.md`
- Windows orchestrator delta plan: `documents/operations/active/OsAgnosticOrchestratorAndWindowsPeerDeltaPlan_2026-04-27.md`
- Live-lab evidence record: `documents/operations/active/HeterogeneousLiveLabEvidence_2026-04-28.md`

## Change Log

- 2026-05-23 — Document created. No code changes landed yet; Track A and
  Track B are planning-only at this point.
- 2026-05-23 — Track C (adversarial / fault-injection / chaos live-lab
  stages) added: eight categories, 30+ proposed chaos stages, shared
  tooling (impairment harness, signed-bundle forger, chaos coordinator,
  chaos CI gate). Risks R5-R7 added covering chaos-specific safety.
- 2026-05-23 — Track A code scaffold added: `live_linux_anchor_test` Rust
  harness, `scripts/e2e/live_linux_anchor_test.sh`, orchestrator
  `live_anchor` hook, and `scripts/ci/anchor_live_lab_gates.sh`. The harness
  is non-destructive today: signed anchor-capability check, loopback
  bundle-pull byte-for-byte check, invalid-token rejection, authority
  capability check, and daemon status availability. Enrollment/downgrade
  destructive sub-stages remain separate follow-up work before `live_anchor`
  can become release-gate required.
- 2026-05-23 — Anchor harness made platform-aware for Linux/macOS dry-run
  coverage and macOS POSIX digest tooling (`shasum -a 256`). Added
  `scripts/e2e/live_macos_anchor_test.sh`; CI now exercises Linux + macOS
  report generation without touching live hosts.
- 2026-05-23 — macOS `validate_macos_anchor_bundle_pull` stage upgraded from
  a pure reserved slot to a non-destructive executable plan check: after macOS
  mesh join it runs `rustynet anchor init --dry-run --node-id <macos-node>`
  over SSH and verifies the output contains anchor advertisement, all five
  anchor sub-capabilities, and the loopback bundle-pull listener plan.
- 2026-05-23 — Track B steps 1-6 landed:
  - **Step 1 (B1.5 + B1.1)** topology selection: new
    `crates/rustynet-cli/src/vm_lab/topology.rs` module with
    `TopologyProfile` JSON schema, `TopologyPlatform` selector,
    `resolve_topology` planner, and
    `apply_topology_overrides_to_orchestrate_config` orchestrator
    wrapper. New CLI flags: `--topology-profile <path>`,
    `--exit-platform <linux|macos|windows>`, `--relay-platform`,
    `--anchor-platform`. Default behaviour preserved byte-for-byte
    (default Linux-exit runs are unchanged). 21 unit tests.
  - **Step 2 (M1)** macOS exit-mode validators: three new orchestrator
    stages (`validate_macos_exit_nat_lifecycle`,
    `validate_macos_exit_dns_failclosed`,
    `validate_macos_exit_killswitch_precedence`) + pure evaluator
    functions parsing pf-anchor lifecycle + pf-block-rules + tampered
    assertion artefacts. Stages skip cleanly when the artefact files
    are absent. 13 new unit tests.
  - **Step 3 (B1.4) + Step 5 (M5 + W4)** platform-aware role
    transition planner: new `ConcreteAction::DeployExitService` /
    `UndeployExitService` planner variants, `admin → exit` emits
    `[AdvertiseDefaultRoute, DeployExitService]` (advertise-then-prep),
    `exit → admin` emits `[UndeployExitService, RetractDefaultRoute]`
    (undeploy-then-revoke). New installer modules
    `ops_install_systemd_exit.rs` (Linux) and
    `ops_install_macos_exit.rs` (macOS) follow the existing
    systemd_relay / macos_relay pattern. New
    `Install-RustyNetWindowsExitService.ps1` /
    `Uninstall-RustyNetWindowsExitService.ps1` cover Windows via
    `Set-NetIPInterface -Forwarding {Enabled,Disabled}`. Per-OS
    dispatch via `execute_platform_exit_service_action` /
    `execute_platform_relay_service_action` in `main.rs`. The relay
    dispatcher now also dispatches to Windows.
  - **Step 4 (W1)** Windows active-exit promotion stage: new
    `promote_windows_exit_active` stage gated on
    `windows_vm == exit_vm`; runs the reviewed
    install-windows-exit-service preflight on the Windows host then
    polls daemon IPC for `node_role=admin serving_exit_node=true`
    (60s cap). Skip-with-reason when topology did not elect Windows.
  - **Step 6 (W2 / W3 / M2 / M3)** macOS + Windows relay/anchor
    live-lab stage slots: substantive
    `validate_macos_relay_service_lifecycle` drives
    `ops install-macos-relay --dry-run` over SSH and parses the
    bootout/bootstrap/kickstart plan. `validate_macos_anchor_bundle_pull`
    runs a non-destructive anchor-init dry-run on macOS, and
    `validate_windows_anchor_bundle_pull` now validates the local Windows
    anchor bundle-pull plan contract without guest mutation. Both still defer
    real listener/token traffic to Track A / Track C.
    `validate_windows_relay_service_lifecycle` is now a non-mutating SCM helper
    contract gate; real Windows SCM install/start/traffic/uninstall remains
    Track C.
  - **Step 7 (B1.2)** non-Linux genesis (was deferred, now landed via
    commit `6ccf153`): new `ops e2e-bootstrap-macos` and
    `ops e2e-bootstrap-windows` CLI verbs in
    `crates/rustynet-cli/src/ops_e2e.rs` mirror the Linux
    `ops e2e-bootstrap-host` membership-init step against the
    platform-canonical state paths. macOS uses
    `/usr/local/var/rustynet/membership/`; Windows uses
    `rustynetd::windows_paths::DEFAULT_WINDOWS_MEMBERSHIP_*` so a
    future path move stays consistent with the daemon. Each verb is
    cfg-gated to its host OS and returns a clear error on
    non-target platforms.
  - New CI gate `scripts/ci/cross_platform_role_gates.sh` covers all
    of the above hermetically (no VM required), including the new
    genesis verbs (`E2eBootstrapMacos` + `E2eBootstrapWindows`
    OpsCommand variants and the per-OS executor functions).
  - Evidence appended to
    [`HeterogeneousLiveLabEvidence_2026-04-28.md`](./HeterogeneousLiveLabEvidence_2026-04-28.md)
    §7.
  - Track-A enrollment / downgrade destructive sub-stages and Track-C
    chaos work remain out of scope for this Track-B run.
  - Track B all seven steps now landed; full commit chain: `4e5a37f`
    (Step 1) → `c664a4f` (Step 2) → `5739385` (Step 3+5) → `3bdc92e`
    (Step 4) → `c2fceeb` (Step 6) → `acf9934` (gates+evidence+ledger)
    → `6ccf153` (Step 7) → `7938750` (Step 2 follow-up: macOS NAT
    lifecycle producer).
- 2026-05-23 — Step 2 (M1) producer-side wiring landed in commit
  `7938750`: the `validate_macos_exit_nat_lifecycle` orchestrator
  stage now has a working artefact source. New
  `crates/rustynetd/src/macos_exit_nat_lifecycle.rs` module +
  `rustynetd macos-exit-nat-lifecycle-snapshot` subcommand emit a
  single-phase pf-anchor + sysctl forwarding snapshot. New
  `scripts/e2e/capture_macos_exit_nat_lifecycle.sh` drives the
  destructive two-phase capture sequence (snapshot during exit
  mode → stop daemon → snapshot → restart → merge) and writes the
  validator's two-phase JSON artefact. 11 producer unit tests + 2
  orchestrator-side round-trip tests (`vm_lab::tests::
  macos_exit_nat_lifecycle_producer_*`) pin the contract. CI gate
  extended to verify the module + subcommand wiring + round-trip
  tests. Track B DOD now achievable on a live macOS-as-exit run
  for the NAT lifecycle artefact; DNS-failclosed + killswitch
  producers remain follow-up work.
- 2026-05-23 — Windows relay lifecycle slot upgraded from a pure reserved
  placeholder to a non-mutating SCM helper contract gate. The
  `validate_windows_relay_service_lifecycle` stage now verifies the reviewed
  install/uninstall PowerShell helpers contain the fail-closed path guards,
  loopback-only health bind gate, Authenticode signing, service SID, ACL
  repair, JSON arg-file handoff, failure actions, hardening check, and
  non-recursive uninstall preservation controls before reporting pass. It
  still does **not** install, start, stop, or delete a Windows service; the
  live SCM mutation + relay traffic exercise remains Track C / operator-opt-in.
  `live_anchor` was added to the full release-gate required stage list so the
  anchor role cannot silently fall out of release completeness once live
  topology evidence is present.
- 2026-05-23 — Windows anchor bundle-pull slot upgraded from a pure reserved
  placeholder to a non-mutating dry-run plan contract gate. The
  `validate_windows_anchor_bundle_pull` stage now fails closed unless the
  selected Windows inventory entry is actually Windows, has a node ID, and the
  `anchor init` planner renders anchor advertisement, all five anchor
  sub-capabilities, relay co-deploy, and loopback bundle-pull listener
  enablement at `127.0.0.1:51822`. It does not bind a socket, consume a token,
  or mutate the Windows guest; live token/listener proof remains Track A / C.
- 2026-05-23 — Anchor live harness dry-run coverage extended to Windows.
  `live_linux_anchor_test --platform windows --dry-run` now accepts reviewed
  Windows absolute paths and emits a Windows-labelled `live_anchor` report.
  `scripts/e2e/live_windows_anchor_test.sh` was added as the Windows wrapper,
  and `scripts/ci/anchor_live_lab_gates.sh` now generates Linux, macOS, and
  Windows dry-run anchor reports. Live Windows execution still fails closed
  until a reviewed PowerShell/SCM-safe runner is added.
- 2026-05-23 — Bash live-lab orchestrator made anchor-platform aware. The
  `live_anchor` stage now records dry-run coverage, resolves the exit node's
  platform explicitly, runs the live traffic validator only for Linux anchors,
  and records an honest skip for macOS/Windows anchors until their live-safe
  runners graduate beyond non-mutating plan gates.
- 2026-05-23 — Track C C2 scaffold landed. Added the shared chaos tooling
  surfaces without enabling destructive live faults by default:
  `scripts/e2e/chaos_impair_link.sh` for allow-listed impairment planning,
  `live_signed_bundle_forger` gated behind the `chaos-forger` Cargo feature,
  chaos coordinator bookkeeping helpers in `live_lab_common.sh`, eight
  category harness bins plus wrappers, `--enable-chaos-suite` opt-in wiring
  in `live_linux_lab_orchestrator.sh`, and `scripts/ci/chaos_gates.sh`.
  The category harnesses emit structured dry-run reports today; live host
  mutation, tcpdump leak proofs, and measured recovery deadlines remain the
  next Track C slices.
- 2026-05-23 — Track C C1.1 daemon-fault live slice started. The
  `chaos_daemon_kill_during_reconcile` sub-stage now has a live-capable Rust
  harness path that requires explicit target/client/identity arguments, verifies
  pinned known_hosts and passwordless sudo, starts client exit-path traffic,
  registers remote teardown before injecting `systemctl kill -s KILL`, captures
  a tcpdump plaintext-leak window on the exit host's default-route interface,
  measures daemon socket recovery against the encoded deadline, and emits a
  structured report. Orchestrator `--enable-chaos-suite` now wires this daemon
  KILL proof; default runs still skip chaos. The OOM, SIGSTOP/SIGCONT, and
  helper-socket daemon-fault sub-stages remain skipped until their live-safe
  implementations land.
- 2026-05-23 — Track C C1.3 signed-state adversarial offline slice landed. The
  `live_signed_bundle_forger` scenario contract moved into shared Rust helper
  code (`live_signed_state_chaos`) and `live_chaos_signed_state_adversarial_test`
  now generates and validates reject-only fixtures for replayed membership,
  future-dated assignment, truncated bundles, forged signature, and
  quorum-starved proposal stages. The report fails if any signed-state stage
  lacks fixture coverage or if the manifest ever claims `production_accepted`.
  `scripts/ci/chaos_gates.sh` now asserts the signed-state report is `pass`,
  `reject_fail_closed`, and `production_accepted=false`. This is hermetic only;
  live daemon ingestion/rejection proof remains a later opt-in live-lab slice.
- 2026-05-23 — Linux orchestration parity L1 landed. Added
  `rustynetd linux-exit-nat-lifecycle-snapshot`, the
  `linux_exit_nat_lifecycle` producer module, destructive two-phase
  `scripts/e2e/capture_linux_exit_nat_lifecycle.sh`, and the
  `validate_linux_exit_nat_lifecycle` orchestrator stage with skip-when-artefact-
  absent behavior. Added hermetic producer→validator round-trip tests and
  `scripts/ci/linux_exit_role_gates.sh`; extended
  `scripts/ci/cross_platform_role_gates.sh` to include the Linux producer. DNS
  fail-closed, killswitch precedence, relay, anchor, genesis, and IPv6 schema-v2
  parity remain follow-up Linux slices.
