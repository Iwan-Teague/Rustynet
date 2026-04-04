# Linux Userspace-Shared Live-Lab Readiness Delta
**Generated:** 2026-04-03  
**Repository Root:** `/Users/iwanteague/Desktop/Rustynet`  
**Status:** Active narrow delta document for the remaining work before an honest reduced Linux live-lab completion attempt  
**Owning Ledger:** [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)  
**Related Supporting Plan:** [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)

## 0. Purpose And Document Relationship
This document narrows the remaining work from the broader production transport-owning backend effort down to the exact delta that still blocks the current Linux five-node live-lab path.

Use this document when the question is:
- what still blocks the next honest reduced Linux live-lab rerun,
- what code must change next,
- what validation must pass before rerunning the lab,
- and what still remains afterward before repo-level pre-live-lab readiness can be claimed.

This document does **not** replace the public ledger or the broader backend plan:
- execution evidence and current truth remain in [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- broader backend phase history remains in [ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md](./ProductionTransportOwningWireGuardBackendPlan_2026-03-31.md)

## 1. Current Audited Truth As Of 2026-04-04
The following repository state is already true and must not be regressed.

### 1.1 What Is Already Working
- The Linux `linux-wireguard-userspace-shared` backend now exists and is explicitly selectable.
- The backend owns the authoritative UDP socket, userspace WireGuard engine state, TUN runtime state, authoritative control operations, and handshake telemetry.
- Shared-transport proof for peer ciphertext, STUN, and relay control already exists in local simulated tests.
- The daemon/helper/start/install surfaces now preserve the explicit userspace-shared backend mode instead of silently rewriting it away.
- `rustynet-cli` now has a narrow typed reduced-live-lab iteration helper:
  - `ops vm-lab-iterate-live-lab`
  - it only accepts typed local validation steps (`fmt`, `check`, `check-bin`, `test`, `test-bin`)
  - it writes the live-lab profile, runs preflight, launches the standard reduced five-node live-lab orchestrator, waits for completion, and prints the first failed stage plus key report/log paths
  - it supports strict provenance guards:
    - `--require-clean-tree`
    - `--require-local-head`
  - it does **not** accept arbitrary shell commands or widen the operator surface beyond the existing `vm-lab-write-live-lab-profile`, `vm-lab-preflight`, and `vm-lab-run-live-lab` flow
- `rustynet-cli` now also has narrow live-lab support helpers:
  - `ops vm-lab-validate-live-lab-profile`
  - `ops vm-lab-diagnose-live-lab-failure`
  - `ops vm-lab-diff-live-lab-runs`
  - these helpers are deterministic and artifact/profile-driven; they do not add a generic remote shell surface
- `rustynet-cli` now makes `force-local-assignment-refresh-now` wait for the daemon to report a runtime-ready, non-restricted status after restart before handing control back to the live-lab runner.
- Runtime WireGuard key preparation for the userspace-shared backend is fixed.
- The privileged helper now exposes `/dev/net/tun` so helper-assisted Linux TUN creation no longer fails on missing device access.
- The Rust live-lab binaries now resolve pinned `known_hosts` lookup candidates from the effective SSH target (`hostkeyalias`, raw host, resolved hostname, and port-aware bracket form) instead of checking only the raw host token.
- The Rust live-lab binaries that build `NODES_SPEC` or probe targets from SSH host inputs now resolve the effective SSH hostname via `ssh -G` instead of reusing raw SSH aliases as if they were authoritative underlay IP endpoints.

### 1.2 What The Reduced Live Lab Now Proves
The latest reduced five-node helper rerun against the current working tree with `--skip-gates --skip-soak --skip-cross-network` is:
- `artifacts/live_lab/20260404_runtime_recovery`

That rerun advanced through and passed:
- `bootstrap_hosts`
- `collect_pubkeys`
- `membership_setup`
- `distribute_membership_state`
- `issue_and_distribute_assignments`
- `issue_and_distribute_traversal`
- `enforce_baseline_runtime`
- `validate_baseline_runtime`
- `live_role_switch_matrix`
- `live_exit_handoff`
- `live_two_hop`
- `live_lan_toggle`
- `live_managed_dns`
- `fresh_install_os_matrix_report`

The reduced helper flow no longer stops on the earlier route-application, exit-mode placeholder, handoff-cadence, or runtime-worker-liveness failures.

What the latest captured rerun proves:
- the current tree still bootstraps, compiles, and installs successfully on all five Linux hosts under `linux-wireguard-userspace-shared`
- the direct-probe exhaustion regression remains fixed on the reduced live topology:
  - exit and client nodes remain `restricted_safe_mode=false`
  - baseline route advertisement succeeds
  - client nodes now report `path_mode=direct_programmed`
  - client nodes now report `traversal_probe_reason=direct_probe_exhausted_unproven_direct`
- the role-switch host-key lookup fix remains live-proven from earlier reruns
- the role-switch converge-before-sample regression remains live-proven closed:
  - `live_role_switch_matrix` passes on the current rerun
  - the stricter readiness predicate no longer records transient `node_role=<target>` / `state=FailClosed` windows as success
- the exit-handoff proof now passes with the post-switch cadence fix and the backend runtime-recovery patch in place:
  - `live_exit_handoff` keeps endpoint visibility, NAT, reconvergence, route-leak, and managed-DNS checks green
  - the runtime-worker-loss failure no longer reproduces on the current tree
  - the backend recovery path remains strictly fail-closed if replacement-worker replay were ever to fail
- the later reduced stages now also pass on the same rerun:
  - `live_two_hop` passes
  - `live_lan_toggle` passes
  - `live_managed_dns` passes
  - `fresh_install_os_matrix_report` passes

That reduced skip-gates rerun proves the live path is no longer blocked on shared transport, route/exit-mode programming, handoff cadence, or runtime-worker recovery.

However, a later stricter five-node rerun with local gates enabled and cross-network still skipped:
- `artifacts/live_lab/20260404_five_node_local_gates`
- reached `live_two_hop`
- failed `second_client_route_via_rustynet0`
- kept `entry_peer_visibility=pass`, where that check is sourced from backend-authoritative `managed_peer_endpoints` rather than debug-only `wg show ... endpoints`

So the current first blocker is no longer endpoint visibility. It is the second-client route enforcement gap during `live_two_hop` on the stricter five-node path.

### 1.3 The Exact Remaining Gap After Baseline Runtime
Delta Phase 1 and Delta Phase 2 are now real-host-proven for the reduced baseline-runtime slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs): `apply_routes(...)` is now real for `linux-wireguard-userspace-shared`
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs): `set_exit_mode(...)` is now real for `linux-wireguard-userspace-shared`, and backend capabilities now truthfully advertise Linux userspace-shared route and exit-node support
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs): the runtime worker now owns both route reconciliation state and current exit-mode state, and clears exit-mode state during shutdown before runtime teardown
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs): non-default route reconcile/rollback and backend exit-mode rule reconcile/rollback are now implemented for direct, helper-backed, and test TUN lifecycles
- [scripts/e2e/live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh): baseline enforcement now refreshes freshly issued signed traversal bundles before exit-route advertisement so the 30-second signed coordination window is not consumed by earlier stages

The remaining delta is no longer a backend route/exit-mode runtime gap, a baseline traversal-runtime instability, or a handoff/runtime-worker-liveness gap. The next step is:
- keep the now-fixed baseline-runtime, role-switch, exit-handoff, and two-hop endpoint-visibility slices intact
- fix the stricter five-node `live_two_hop` second-client route enforcement regression without weakening backend-authoritative proof
- then continue with dependency-policy and cross-network evidence cleanup

## 2. Why This Gap Mattered And Why The Next Step Is Operational Proof
Phase 10 relies on backend route and exit-mode programming during baseline enforcement in:
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)

Current apply order:
1. configure peers
2. apply endpoint-bypass routes in the system layer
3. `backend.apply_routes(routes.clone())`
4. `system.apply_routes(&routes)`
5. firewall / NAT / DNS / IPv6 hardening
6. `backend.set_exit_mode(options.exit_mode)`
7. final killswitch assertion

Rollback order already expects the backend path to be real:
- `backend.set_exit_mode(ExitMode::Off)`
- `backend.apply_routes(Vec::new())`

The older reduced live-lab rerun proved that fail-closed placeholders in those backend calls prevented a fully reconciled baseline dataplane state.

The current tree now implements those backend calls locally and validates them under targeted backend and daemon tests. It also proves the old route/exit-mode placeholder failures are gone. However, the latest fresh committed-tree rerun does not yet prove later-stage stability end-to-end, because the client backend can still lose its single runtime worker during the forced assignment-refresh restart inside `live_exit_handoff`, leaving the daemon fail-closed until the backend can reconstruct and replay its worker-owned state.

## 3. Exact Remaining Delta
There are now three remaining buckets. The backend route/exit implementation bucket is code-complete, the immediate next blocker is the `live_exit_handoff` userspace runtime-worker recovery gap on the reduced committed-tree topology, and the final bucket remains the already-documented repo-level policy/evidence cleanup.

### 3.1 Bucket A: Implement Linux Userspace-Shared Route And Exit-Mode Programming
This bucket is now code-complete locally.

#### Required behavior
Implement honest Linux userspace-shared parity for:
- `apply_routes(...)`
- `set_exit_mode(...)`

Current status:
- `apply_routes(...)`: implemented locally and validated in Delta Phase 1
- `set_exit_mode(...)`: implemented locally and validated in Delta Phase 2

#### Parity target
The reference behavior is already present in the Linux command backend:
- [crates/rustynet-backend-wireguard/src/linux_command.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/linux_command.rs)

That reference currently does two important things:
- route reconciliation:
  - removes stale interface routes that are no longer present
  - adds or replaces interface routes for non-default route kinds
  - skips `RouteKind::ExitNodeDefault` at the backend route layer
- exit-mode programming:
  - removes any stale `ip rule` state for table `51820`
  - adds the rule only for `ExitMode::FullTunnel`
  - clears the rule for `ExitMode::Off`

#### Required implementation shape
The Linux userspace-shared backend must implement the same behavior honestly without changing the architectural security boundaries:
- keep the authoritative UDP socket owned by the backend runtime
- keep userspace engine state owned by the backend runtime
- keep TUN ownership in the backend/runtime path
- keep backend route state and exit-mode state runtime-owned so rollback and shutdown can clear them deterministically
- if privileged route or rule mutation is required, use the existing hardened helper or equivalent Rust-only narrow boundary for host setup only
- keep helper execution argv-only with strict input validation; do not construct shell commands from route or interface input
- do **not** move socket, engine, or long-lived forwarding authority into the helper
- do **not** create a second transport authority path
- do **not** silently downgrade to the command-only backend
- do **not** shift backend-owned route obligations into `RuntimeSystem::apply_routes(...)` as a shortcut; backend and system layers already have distinct responsibilities in [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- do **not** turn `set_exit_mode(...)` into a no-op that relies on later system stages to hide the missing backend state

#### Minimum code surfaces
Primary implementation surfaces:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs)

Helper / daemon touch only if required by privilege boundaries:
- [crates/rustynetd/src/privileged_helper.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [scripts/systemd/rustynetd-privileged-helper.service](/Users/iwanteague/Desktop/Rustynet/scripts/systemd/rustynetd-privileged-helper.service)
- [crates/rustynet-cli/src/ops_install_systemd.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_install_systemd.rs)

#### Required validation for Bucket A
Current local proof now includes:
- route reconciliation adds the expected interface routes
- route reconciliation removes stale interface routes
- `RouteKind::ExitNodeDefault` is not incorrectly programmed as a backend interface route
- `set_exit_mode(ExitMode::FullTunnel)` applies the expected table/rule state
- `set_exit_mode(ExitMode::Off)` clears that state
- startup, rollback, and shutdown do not leave stale backend-owned route or exit-mode state behind
- userspace-shared mode still does not silently downgrade to command-only behavior
- authoritative shared-transport behavior remains unchanged
- route and exit-mode mutations do not change `transport_socket_identity_state=authoritative_backend_shared_transport`

What remains for Bucket A:
- preserve the now-working route and exit-mode behavior on future commits
- keep repo-level gates and evidence cleanup fail-closed

### 3.2 Bucket B: Reduced Five-Node Linux Helper Lab Proof
This bucket is reopened by the stricter five-node local-gates rerun.

#### Current blocker
The current first reduced five-node blocker is:
- `live_two_hop`
- failing check: `second_client_route_via_rustynet0`

The endpoint-visibility subcheck is not the blocker:
- `entry_peer_visibility=pass`
- it already uses backend-authoritative `managed_peer_endpoints`
- `wg show rustynet0 endpoints` remains debug-only in this stage

#### Required proof before closing Bucket B
- restore a clean stricter five-node rerun through `live_two_hop`, `live_lan_toggle`, `live_managed_dns`, and the local gate bundle
- preserve the backend-authoritative endpoint-visibility proof source
- later repo-level gate work must not reopen any already-completed reduced-lab slice

#### Required helper flow
Keep using the built-in helper flow rather than ad hoc SSH orchestration:
- preferred narrow wrapper for reduced five-node iteration:
  - `ops vm-lab-iterate-live-lab`
- `ops vm-lab-write-live-lab-profile`
- `ops vm-lab-preflight`
- `ops vm-lab-run-live-lab`

The new wrapper is the standard path for iterative reduced-lab debugging because it:
- keeps validation typed and local
- preserves the existing generated-profile and orchestrator path
- waits for completion and prints deterministic failure pointers
- avoids broadening the live-lab execution surface to generic command execution
- keeps provenance explicit when `--require-clean-tree` and `--require-local-head` are used

The supporting helper set around the wrapper is now:
- `ops vm-lab-validate-live-lab-profile` before a run when profile correctness or backend/source provenance is in doubt
- `ops vm-lab-diagnose-live-lab-failure` after a red run to capture `vm-lab-status` and optional artifact collection for the configured live-lab targets
- `ops vm-lab-diff-live-lab-runs` to show the first divergent stage when a patch moves the blocker forward

Required backend selection for this slice:
- `RUSTYNET_BACKEND=linux-wireguard-userspace-shared`

### 3.3 Bucket C: Remaining Repo-Level Blockers After The Runtime Gap
Even after Bucket A and Bucket B succeed, the repo is still not fully pre-live-lab clean until the following are resolved:
- dependency-policy cleanup:
  - remove or replace the `tun-rs 2.8.2` dependency path that introduces `RUSTSEC-2024-0436` through unmaintained `paste 1.0.15`, or land a policy-approved secure alternative
  - resolve the `cargo deny` license-policy failures introduced by the `boringtun` / `tun-rs` dependency chain without weakening the policy gate
- stale fresh-install evidence:
  - regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` for current `HEAD`
- missing live cross-network evidence:
  - generate the six canonical live reports for current `HEAD`

These later blockers must remain fail-closed and must not be patched around.

## 4. Remaining Delta Implementation Phases
These phases are for the **remaining live-lab delta only**. They do not replace the already completed Phase 1 through Phase 7 work in the broader production backend plan.

### 4.1 Delta Phase 1: Backend Route Programming
Goal:
- implement honest Linux userspace-shared `apply_routes(...)`

Status:
- Code-complete on 2026-04-02
- Live-proven on 2026-04-04 via the successful reduced five-node rerun

Required code focus:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs)
- helper or daemon surfaces only if Linux privilege boundaries require them

Required behavior:
- reconcile interface routes against the backend-owned userspace-shared runtime
- remove stale backend-programmed routes during updates and rollback
- add or replace current non-default routes on the userspace-backed interface
- continue to skip `RouteKind::ExitNodeDefault` at the backend route layer
- keep default-route, DNS-protection, firewall, NAT, and killswitch enforcement in the existing system layer; this phase is backend route parity, not a second policy plane
- fail closed on invalid route state, helper failure, or partial apply

Required proof before advancing:
- targeted backend tests prove route add, replace, and stale-route removal behavior
- rollback clears backend route state without leaving residue
- authoritative shared-transport behavior remains unchanged
- targeted daemon reconciliation tests still show fail-closed semantics on backend or system errors

Phase 1 evidence now present in the current tree:
- backend route reconciliation is runtime-owned rather than placeholder-backed
- route rollback is covered for replace-side and delete-side failures
- `RouteKind::ExitNodeDefault` is explicitly skipped at the backend route layer for both add and stale-delete paths
- authoritative transport identity and transport generation remain unchanged across `apply_routes(...)`

Stop condition:
- do not advance to repo-level cleanup until the reduced five-node rerun proves the completed route/exit-mode slice under real host enforcement

### 4.2 Delta Phase 2: Exit-Mode Programming
Goal:
- implement honest Linux userspace-shared `set_exit_mode(...)`

Status:
- Code-complete on 2026-04-02
- Live-proven on 2026-04-04 via the successful reduced five-node rerun

Required code focus:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)
- helper boundary only if Linux policy-rule mutation requires it

Required behavior:
- mirror the Linux command backend table/rule behavior for `ExitMode::Off` and `ExitMode::FullTunnel`
- clear stale rule state before re-applying
- keep backend/runtime state consistent with actual host programming
- keep exit-mode rollback idempotent because [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs) already calls backend rollback on failure paths and shutdown paths
- fail closed on partial apply, rollback failure, or privilege/setup failure

Required proof before advancing:
- targeted backend tests prove `ExitMode::FullTunnel` applies the expected table/rule state
- targeted backend tests prove `ExitMode::Off` clears that state
- rollback and shutdown clear backend exit-mode state
- no silent downgrade to command-only mode occurs
- targeted daemon tests still keep `direct_active` and `relay_active` truthfulness unchanged

Phase 2 evidence now present in the current tree:
- full-tunnel backend exit-mode programming mirrors the Linux command backend `ip rule` semantics without moving transport ownership into the helper
- exit-mode rollback preserves runtime-owned state on failed host mutation and clears state deterministically on shutdown
- Linux userspace-shared capabilities now honestly advertise exit-node and LAN-route support
- authoritative transport identity and transport generation remain unchanged across `set_exit_mode(...)`

Stop condition:
- do not advance to repo-level cleanup until the reduced five-node rerun proves the completed route and exit-mode slice under real host enforcement

### 4.3 Delta Phase 3: Focused Validation And Reduced Five-Node Rerun
Goal:
- prove the runtime slice is now sufficient for baseline enforcement on the current reduced Linux lab

Status:
- Complete on 2026-04-04
- The reduced five-node rerun is now live-proven on the current working tree
- `validate_baseline_runtime` remains aligned to the actual Delta Phase 3 contract:
  - it explicitly requires authoritative backend shared transport state, encrypted key custody, auto-tunnel enforcement, correct membership-node count, client routes via `rustynet0`, and absence of plaintext passphrase files
  - it explicitly rejects the old route-application and exit-mode placeholder strings
  - it does not overclaim later-stage role-switch or live-handshake proof

Required validation:
- targeted backend and daemon validation from Section 7.1
- reduced five-node helper flow using `linux-wireguard-userspace-shared`

Required proof before advancing:
- preserve the passing reduced-lab path on future commits
- if a later change reopens a live-lab blocker, fix that exact blocker rather than reopening the already completed route/exit-mode, baseline-runtime, role-switch, handoff, two-hop, LAN-toggle, or managed-DNS slices

Stop condition:
- keep the successful reduced-lab path intact and move only to repo-level gate and evidence cleanup

Delta Phase 3 evidence now present in the current tree:
- the reduced five-node rerun now passes end-to-end on the current working tree
- `live_exit_handoff`, `live_two_hop`, `live_lan_toggle`, and `live_managed_dns` all pass on the same rerun
- `fresh_install_os_matrix_report` passes on the same rerun
- the runtime-worker recovery path remains strictly fail-closed if replacement-worker replay were ever to fail

### 4.4 Delta Phase 4: Repo-Level Cleanup After Runtime Success
Goal:
- clear the remaining non-runtime blockers without weakening gates or inventing evidence

Required work:
- dependency-policy cleanup for `cargo audit` / `cargo deny`
- fresh-install evidence regeneration for current `HEAD`
- canonical live cross-network evidence generation for current `HEAD`

Required proof before closing this delta:
- policy gates are green without relaxed rules
- fresh-install evidence is current
- canonical live reports are current

Stop condition:
- do not claim repo-level pre-live-lab readiness until this phase is also complete

## 5. Non-Negotiable Security Rules For The Remaining Delta
- Keep one hardened execution path per security-sensitive workflow.
- Fail closed on missing, invalid, stale, malformed, unauthorized, or unproven state.
- Do not create a daemon-owned or helper-owned side socket.
- Do not treat same-local-port behavior as authoritative transport identity.
- Do not silently downgrade `linux-wireguard-userspace-shared` to `linux-wireguard`.
- Do not move long-lived transport ownership into the helper.
- Do not fake route or exit-mode success to satisfy the lab.
- Do not widen macOS or Windows capability claims from Linux-only work.
- Do not soften `cargo audit`, `cargo deny`, `phase10_gates`, `membership_gates`, or `phase10_cross_network_exit_gates`.

## 6. Exact Execution Order
Follow this order for the remaining work:

1. Preserve the now-proven route, exit-mode, and traversal-refresh timing slices in [mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs), [runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs), [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs), and [live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh).
2. Preserve the now-landed Rust live-lab endpoint resolver fix so signed topology specs continue using effective SSH-resolved underlay hosts instead of raw aliases.
3. Preserve the current backend-local runtime recovery path so a dead userspace-shared worker is rebuilt from runtime-owned desired state instead of leaving the daemon permanently fail-closed after restart.
4. Re-run the reduced five-node helper lab on the current committed tree through `live_exit_handoff` with the local backend recovery fix.
5. If `live_exit_handoff` passes, continue through the later reduced-live-lab stages and capture the first new blocker honestly.
6. If `live_exit_handoff` still fails, capture the exact next blocker instead of reopening the already-completed route/exit-mode, baseline traversal-refresh, role-switch, or proof-source slices.
7. After the helper flow is clean again, resume the dependency-policy cleanup and evidence-regeneration buckets.

## 7. Validation Order For The Remaining Delta
Use this order so failures are local and explainable:

### 7.1 Targeted code validation
- `rustfmt --edition 2024` on touched Rust files
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check -p rustynet-backend-wireguard`
- `cargo check -p rustynetd` if helper or daemon surfaces change
- targeted `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
- targeted `cargo test -p rustynetd ... -- --nocapture` only for directly affected userspace-shared/helper/runtime tests

### 7.2 Reduced live-lab rerun
- preferred one-command iteration helper:
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-iterate-live-lab --inventory documents/operations/active/vm_lab_inventory.json --ssh-identity-file /Users/iwanteague/.ssh/rustynet_lab_ed25519 --ssh-known-hosts-file /Users/iwanteague/.ssh/known_hosts --exit-vm debian-headless-1 --client-vm debian-headless-2 --entry-vm debian-headless-3 --aux-vm debian-headless-4 --extra-vm debian-headless-5 --require-same-network --backend linux-wireguard-userspace-shared --require-clean-tree --require-local-head --validation-step fmt --validation-step check:rustynetd --validation-step check:rustynet-cli --validation-step test-bin:rustynet-cli:live_linux_exit_handoff_test --validation-step test-bin:rustynet-cli:live_linux_two_hop_test --validation-step test-bin:rustynet-cli:live_linux_lan_toggle_test --collect-failure-diagnostics`
- optional pre-run profile validation:
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-validate-live-lab-profile --profile profiles/live_lab/generated_vm_lab_iteration_<id>.env --expected-backend linux-wireguard-userspace-shared --expected-source-mode local-head --require-five-node`
- post-failure diagnostic capture:
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-diagnose-live-lab-failure --inventory documents/operations/active/vm_lab_inventory.json --profile profiles/live_lab/generated_vm_lab_iteration_<id>.env --report-dir artifacts/live_lab/iteration_<id> --collect-artifacts`
- run-to-run blocker comparison:
  - `cargo run --quiet -p rustynet-cli -- ops vm-lab-diff-live-lab-runs --old-report-dir artifacts/live_lab/<old> --new-report-dir artifacts/live_lab/<new>`
- underlying built-in flow that the helper wraps:
- `cargo run --quiet -p rustynet-cli -- ops vm-lab-write-live-lab-profile ... --backend linux-wireguard-userspace-shared --source-mode local-head --repo-ref HEAD`
- `cargo run --quiet -p rustynet-cli -- ops vm-lab-preflight ...`
- `cargo run --quiet -p rustynet-cli -- ops vm-lab-run-live-lab --profile profiles/live_lab/generated_vm_lab_5node.env --skip-gates --skip-soak --skip-cross-network`

### 7.3 Follow-on repo-level validation after the runtime slice is clean
Do not claim repo-level pre-live-lab readiness until these are revisited honestly:
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`
- `scripts/ci/check_backend_boundary_leakage.sh`
- `scripts/ci/security_regression_gates.sh`
- `./scripts/ci/phase10_hp2_gates.sh`
- `./scripts/ci/membership_gates.sh`
- `./scripts/ci/phase10_cross_network_exit_gates.sh`
- `./scripts/ci/phase10_gates.sh`

## 8. Gate Alignment Requirements
The remaining implementation must be written to satisfy the gates Rustynet already has today. Passing the reduced live-lab rerun while regressing these gates is not acceptable.

### 8.1 Phase 10 HP2 Traversal Gates
Current gate entrypoint:
- [scripts/ci/phase10_hp2_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_hp2_gates.sh)

Current gate implementation runs:
- traversal authority and probe-selection tests in `rustynetd`
- transport-identity blocker fail-closed tests
- adversarial traversal validation
- backend blocker-reporting tests for command-only Linux and macOS backends

Implementation consequence:
- route and exit-mode work must not regress authoritative shared-transport semantics
- command-only backends must remain blocked
- traversal/direct/relay truthfulness semantics must remain unchanged

### 8.2 Phase 10 CI Gates
Current gate entrypoint:
- [scripts/ci/phase10_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_gates.sh)

Current gate implementation in [ops_ci_release_perf.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_ci_release_perf.rs) runs:
- fresh-install readiness scripts
- workspace `fmt`, `clippy`, `check`, and `test`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`
- Phase 9 gates
- [scripts/ci/check_backend_boundary_leakage.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_backend_boundary_leakage.sh)
- secret-pattern scan under `crates/`
- required `rustynetd phase10::tests`
- `cargo test -p rustynet-backend-wireguard --all-targets --all-features`
- Phase 10 HP2 gates
- security regression gates
- cross-network remote-exit schema/NAT-matrix gates
- phase10 provenance and readiness verification

Implementation consequence:
- do not leak WireGuard-specific names into `rustynet-control`, `rustynet-policy`, `rustynet-crypto`, `rustynet-backend-api`, or `rustynet-relay`
- do not add hard-coded secrets, private keys, tokens, or passwords under `crates/`
- do not introduce warnings that only disappear under non-strict clippy
- keep `rustynet-backend-wireguard --all-targets --all-features` green, not only targeted tests
- keep `rustynetd` Phase 10 reconciliation tests green, especially around fail-closed rollback behavior

### 8.3 Membership Gates
Current gate entrypoint:
- [scripts/ci/membership_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/membership_gates.sh)

Current gate implementation:
- membership-targeted clippy/tests
- membership evidence file existence/schema checks
- nested `ops run-membership-ci-gates`, which itself nests the full Phase 10 gate chain

Implementation consequence:
- the remaining Linux backend work must not introduce any new membership or daemon authorization regressions
- the only acceptable remaining membership red state before fresh-install evidence regeneration is the already documented stale fresh-install evidence dependency

### 8.4 Cross-Network Exit Gates
Current gate entrypoint:
- [scripts/ci/phase10_cross_network_exit_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh)

Current gate implementation:
- validates cross-network report schemas
- validates NAT-matrix completeness
- binds reports to current `HEAD`
- fails closed on missing canonical reports or stale evidence

Implementation consequence:
- do not patch around missing reports
- do not claim success from reduced-lab proof alone
- keep current acceptable red state explicit until canonical reports are regenerated

### 8.5 Acceptable And Unacceptable Red States
Acceptable remaining red states while Delta Phase 4 is still open:
- `cargo audit --deny warnings` only for the already documented `tun-rs` dependency-policy blocker
- `cargo deny check bans licenses sources advisories` only for the already documented advisory/license-policy blocker
- `./scripts/ci/phase10_cross_network_exit_gates.sh` only because the six canonical live reports are missing for current `HEAD`
- `./scripts/ci/phase10_gates.sh` only because of the already documented blockers it currently composes:
  - dependency-policy failures from `cargo audit` / `cargo deny`
  - stale `artifacts/phase10/fresh_install_os_matrix_report.json`
  - missing canonical live cross-network reports once the earlier blockers are cleared
- `./scripts/ci/membership_gates.sh` only when it delegates into the same already-documented dependency-policy or evidence blockers, not because of a new runtime regression

Unacceptable red states:
- any new failure in `phase10_hp2_gates`
- any new failure in backend-boundary leakage checks
- any new failure in security regression gates
- any new failure in `rustynetd phase10::tests`
- any new failure in `cargo test -p rustynet-backend-wireguard --all-targets --all-features`
- any new failure that reintroduces second-socket authority, helper-owned transport authority, or silent downgrade behavior

## 9. Definition Of Done
### 9.1 Ready For The Next Honest Reduced Live-Lab Rerun
This narrower target is complete only when all are true:
- Linux userspace-shared route application is implemented honestly.
- Linux userspace-shared exit-mode programming is implemented honestly.
- targeted backend/runtime tests covering those paths pass.
- `./scripts/ci/phase10_hp2_gates.sh` remains green.
- backend-boundary leakage and security-regression checks remain green for the modified tree.
- no second-socket authority, no helper-owned transport authority, and no silent downgrade were introduced.

Current status:
- route application and exit-mode programming are code-complete locally
- targeted backend/runtime proof is present
- the reduced five-node helper rerun is now complete and passing on the current working tree

### 9.2 Reduced Live-Lab Runtime Proof Complete
This narrower operational target is complete only when all are true:
- Section 9.1 is complete.
- the reduced five-node helper lab reaches and completes `enforce_baseline_runtime` on all nodes.
- `validate_baseline_runtime` completes on all nodes.
- `live_role_switch_matrix` completes on the same rerun.
- `live_exit_handoff`, `live_two_hop`, `live_lan_toggle`, `live_managed_dns`, and `fresh_install_os_matrix_report` complete on the same rerun.
- no new reconcile blocker replaces the old route/exit-mode placeholder failures.

Current status:
- complete for the reduced skip-gates five-node proof path on the current working tree
- reopened for the stricter five-node local-gates path at `live_two_hop`
- the current first failing check there is `second_client_route_via_rustynet0`
- the two-hop endpoint-visibility proof remains green and backend-authoritative

### 9.3 Ready For An Honest Repo-Level Pre-Live-Lab Claim
This broader target is complete only when all are true:
- Section 9.2 is complete.
- dependency-policy blockers are resolved without weakening gates.
- fresh-install evidence is current for `HEAD`.
- the six canonical live cross-network reports are current for `HEAD`.

### 9.4 Still Explicitly Out Of Scope
This document does **not** claim:
- macOS userspace-shared parity
- Windows backend parity
- live evidence already exists
- repo-wide release readiness

## 10. Current Bottom Line
The Linux production transport-owning backend is no longer blocked on shared transport, TUN ownership, helper selection, or lab-profile propagation.

The reduced live-lab delta is not fully closed on the stricter five-node path:
- keep the now-fixed baseline-runtime slice intact on future commits
- keep the backend-authoritative two-hop endpoint-visibility proof intact
- fix the current `live_two_hop` second-client route enforcement blocker
- only after that resume repo-level gate and evidence cleanup

The remaining blockers are now narrower than before, but they are not yet policy-and-evidence-only on the stricter five-node path.
