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

## 1. Current Audited Truth As Of 2026-04-03
The following repository state is already true and must not be regressed.

### 1.1 What Is Already Working
- The Linux `linux-wireguard-userspace-shared` backend now exists and is explicitly selectable.
- The backend owns the authoritative UDP socket, userspace WireGuard engine state, TUN runtime state, authoritative control operations, and handshake telemetry.
- Shared-transport proof for peer ciphertext, STUN, and relay control already exists in local simulated tests.
- The daemon/helper/start/install surfaces now preserve the explicit userspace-shared backend mode instead of silently rewriting it away.
- Runtime WireGuard key preparation for the userspace-shared backend is fixed.
- The privileged helper now exposes `/dev/net/tun` so helper-assisted Linux TUN creation no longer fails on missing device access.
- The Rust live-lab binaries now resolve pinned `known_hosts` lookup candidates from the effective SSH target (`hostkeyalias`, raw host, resolved hostname, and port-aware bracket form) instead of checking only the raw host token.
- The Rust live-lab binaries that build `NODES_SPEC` or probe targets from SSH host inputs now resolve the effective SSH hostname via `ssh -G` instead of reusing raw SSH aliases as if they were authoritative underlay IP endpoints.

### 1.2 What The Reduced Live Lab Now Proves
The latest reduced five-node helper rerun against the current working tree is:
- `artifacts/live_lab/20260403T212500Z_lantogglefix`

That rerun advanced through:
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

and then failed at:
- `live_lan_toggle`

The reduced helper flow no longer stops on the earlier route-application or exit-mode placeholder failures. The route-programming and exit-mode-programming slices are no longer the first runtime blocker, and the Rust role-switch host-key precheck slice is now aligned with the shell helper and covered by unit tests.

What the latest captured rerun proves:
- the current tree still bootstraps, compiles, and installs successfully on all five Linux hosts under `linux-wireguard-userspace-shared`
- the direct-probe exhaustion regression is now fixed on the reduced live topology:
  - exit and client nodes remain `restricted_safe_mode=false`
  - baseline route advertisement succeeds
  - client nodes now report `path_mode=direct_programmed`
  - client nodes now report `traversal_probe_reason=direct_probe_exhausted_unproven_direct`
- the role-switch host-key lookup fix is now live-proven because `live_role_switch_matrix` completed successfully on the same rerun
- the earlier `live_exit_handoff` endpoint-construction failure is fixed and now live-proven
- the earlier `live_two_hop` entry-peer proof bug is fixed and now live-proven
- the earlier `live_lan_toggle` traversal-coordination-expiry failure is fixed:
  - the client now stays `restricted_safe_mode=false`
  - `lan_access=on` persists under the stage
  - the client route to `192.168.1.1` remains via `rustynet0`
  - the client no longer fails closed on expired traversal coordination during the observation window
- the current first blocker is narrower and later:
  - `live_lan_toggle` still fails `lan_on_allows`
  - the stage now shows route installation and healthy signed state, but the actual LAN probe never becomes reachable

The current blocker is therefore no longer endpoint construction, two-hop endpoint proof, or traversal-expiry timing. The next required proof is a fix for real LAN dataplane reachability during `lan_access=on`.

### 1.3 The Exact Remaining Gap After Baseline Runtime
Delta Phase 1 and Delta Phase 2 are now real-host-proven for the reduced baseline-runtime slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs): `apply_routes(...)` is now real for `linux-wireguard-userspace-shared`
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs): `set_exit_mode(...)` is now real for `linux-wireguard-userspace-shared`, and backend capabilities now truthfully advertise Linux userspace-shared route and exit-node support
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs): the runtime worker now owns both route reconciliation state and current exit-mode state, and clears exit-mode state during shutdown before runtime teardown
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs): non-default route reconcile/rollback and backend exit-mode rule reconcile/rollback are now implemented for direct, helper-backed, and test TUN lifecycles
- [scripts/e2e/live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh): baseline enforcement now refreshes freshly issued signed traversal bundles before exit-route advertisement so the 30-second signed coordination window is not consumed by earlier stages

The remaining delta is no longer a backend route/exit-mode runtime gap, a baseline traversal-runtime instability, or the previously captured handoff/two-hop proof bugs. The next step is now later-stage operational proof:
- keep the now-fixed baseline-runtime and role-switch slices intact
- fix the real LAN dataplane reachability failure exposed by `live_lan_toggle`
- rerun the reduced five-node helper flow through `live_lan_toggle`
- then resume the repo-level policy/evidence cleanup

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

The current tree now implements those backend calls locally and validates them under targeted backend and daemon tests. It also proves the old route/exit-mode placeholder failures are gone. However, the latest fresh reduced rerun does not yet prove stable baseline-runtime completion end-to-end, because the exit node still re-enters restricted-safe mode during exit-route advertisement after the refreshed signed traversal state is applied.

## 3. Exact Remaining Delta
There are now three remaining buckets. The backend route/exit implementation bucket is code-complete, the immediate next blocker is real LAN dataplane reachability during `lan_access=on` on the reduced live topology, and the final bucket remains the already-documented repo-level policy/evidence cleanup.

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

What still remains for Bucket A:
- real-host proof under the reduced five-node rerun in Bucket B
- confirmation that no new reconcile failure replaces the old route/exit-mode placeholders

### 3.2 Bucket B: Reduced Five-Node Linux Helper Lab Proof
This bucket is reopened on 2026-04-02 by the latest fresh rerun.

#### Current blocker
The latest fresh rerun now fails at the end of `enforce_baseline_runtime`:
- the exit-node `rustynet route advertise 0.0.0.0/0` call returns `error: daemon is in restricted-safe mode`
- exit-node status shows traversal-authority reconcile failures rather than route/exit-mode placeholder failures
- repeated status polling shows the exit daemon falls back into `restricted_safe_mode=true` with traversal-related reconcile errors
- the role-switch `known_hosts` slice is implemented and unit-tested locally, but it is not yet live-proven because the rerun does not currently reach `live_role_switch_matrix`

#### Required proof before closing Bucket B
- a fresh reduced rerun passes `enforce_baseline_runtime` on all five nodes
- `rustynet route advertise 0.0.0.0/0` on the exit node no longer trips restricted-safe mode during the baseline-runtime slice
- baseline validation again sees authoritative backend shared transport state and the absence of the old route/exit-mode placeholder failures
- the rerun reaches `live_role_switch_matrix` so the already-landed host-key candidate fix is proven under the helper flow

#### Required helper flow
Keep using the built-in helper flow rather than ad hoc SSH orchestration:
- `ops vm-lab-write-live-lab-profile`
- `ops vm-lab-preflight`
- `ops vm-lab-run-live-lab`

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
- Earlier live-rerun proof present via Delta Phase 3 baseline-runtime validation
- Fresh rerun currently blocked again by the Delta Phase 3 restricted-safe / traversal-reconcile issue

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
- Earlier reduced-live-lab proof present via Delta Phase 3 baseline-runtime validation
- Fresh rerun currently blocked again by the Delta Phase 3 restricted-safe / traversal-reconcile issue

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
- Complete as of the latest fresh rerun on 2026-04-02
- The current tree now reproduces stable `enforce_baseline_runtime` success on a fresh rerun
- The same rerun also reaches and passes `validate_baseline_runtime` and `live_role_switch_matrix`
- `validate_baseline_runtime` remains aligned to the actual Delta Phase 3 contract:
  - it explicitly requires authoritative backend shared transport state, encrypted key custody, auto-tunnel enforcement, correct membership-node count, client routes via `rustynet0`, and absence of plaintext passphrase files
  - it explicitly rejects the old route-application and exit-mode placeholder strings
  - it does not overclaim later-stage role-switch or live-handshake proof

Required validation:
- targeted backend and daemon validation from Section 7.1
- reduced five-node helper flow using `linux-wireguard-userspace-shared`

Required proof before advancing:
- `enforce_baseline_runtime` succeeds on all five nodes
- `rustynet status` no longer reports backend route-application or exit-mode placeholder failures
- managed DNS no longer fails as a downstream symptom of missing dataplane interface state
- authoritative shared-transport status remains intact
- the rerun reaches `live_role_switch_matrix`
- `live_role_switch_matrix` completes successfully on the same rerun

Stop condition:
- if the reduced lab still fails, stop and record the exact next blocker in the owning ledger before taking on repo-level cleanup

Delta Phase 3 evidence now present in the current tree:
- the completed route and exit-mode runtime slice no longer fails with the old backend placeholder errors
- freshly reissued traversal coordination is now installed before exit-route advertisement so the short signed coordination window is not consumed by earlier helper stages
- the Rust live-lab support modules now validate pinned host keys against the effective SSH target candidates rather than the raw host token only
- the Rust live-lab support modules and affected live-lab binaries now resolve effective SSH hostnames before building signed topology specs or probe targets, so raw SSH aliases are no longer treated as authoritative underlay endpoints
- the former exit-node restricted-safe / traversal-reconcile instability is fixed:
  - exit and client nodes now stay out of restricted-safe mode during the post-traversal baseline refresh
  - host-only signed traversal with exhausted direct probes now remains `direct_programmed` and unproven instead of poisoning traversal state
- the former role-switch `known_hosts` precheck slice is now live-proven because `live_role_switch_matrix` passes on the same rerun
- `live_exit_handoff` is now live-proven on the current working tree
- `live_two_hop` is now live-proven on the current working tree
- the former `live_lan_toggle` traversal-expiry failure is fixed:
  - the stage now keeps traversal coordination fresh throughout the observation window
  - the client remains `restricted_safe_mode=false` with `lan_access=on`
  - the client route to the synthetic LAN probe remains via `rustynet0`
- the current first blocker is now the narrower `live_lan_toggle` `lan_on_allows` failure:
  - route selection and signed-state health remain correct
  - the actual LAN probe still never becomes reachable

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
3. Re-run the reduced five-node helper lab on the current working tree through `live_lan_toggle`.
4. If `live_lan_toggle` still fails, capture the exact next blocker instead of reopening the already-completed route/exit-mode, traversal-refresh, handoff, or two-hop slices.
5. After the helper flow is clean again, resume the dependency-policy cleanup and evidence-regeneration buckets.

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
- route application and exit-mode programming are now code-complete locally
- targeted backend/runtime proof is present
- the next missing proof is the reduced five-node helper rerun itself

### 9.2 Reduced Live-Lab Runtime Proof Complete
This narrower operational target is complete only when all are true:
- Section 9.1 is complete.
- the reduced five-node helper lab reaches and completes `enforce_baseline_runtime` on all nodes.
- `validate_baseline_runtime` completes on all nodes.
- `live_role_switch_matrix` completes on the same rerun.
- no new reconcile blocker replaces the old route/exit-mode placeholder failures.

Current status:
- complete for the baseline-runtime and role-switch slices
- the last captured reduced-live-lab blocker is `live_exit_handoff`
- the specific Rust-side endpoint-construction bug behind that captured failure is now patched locally
- the handoff endpoint-visibility proof path is also patched locally so it now reads the daemon's backend-authoritative `selected_exit_peer_endpoint` status field instead of treating `wg show rustynet0 endpoints` as authority for `linux-wireguard-userspace-shared`
- a fresh rerun is still required before claiming the stage is clear

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

The remaining live-lab delta is now narrower and more concrete:
- keep the now-fixed baseline-runtime and role-switch slices intact on the current committed tree
- rerun `live_exit_handoff` on the current committed tree now that:
  - the Rust-side endpoint builder uses effective SSH-resolved hosts instead of raw aliases
  - the endpoint-visibility check uses the daemon's backend-owned selected-exit peer endpoint rather than kernel `wg show` output
- if that later-stage rerun exposes a new blocker, document and fix that exact blocker instead of reopening the already completed route/exit-mode or traversal-runtime slices

After that, the remaining blockers are policy-and-evidence work, not another broad backend architecture phase.
