# Phase 5 Release Readiness Summary

Prepared: 2026-04-12
Updated: 2026-04-15
Repository root: `/Users/iwan/Desktop/Rustynet`
Overall readiness: **not release-ready**
Current authoritative target commit: `7dd8cf3a585a24adac92a142cf9e4f25a201e179`

## Decision

Rustynet should not currently be described as fully release-ready.

What is now durable:

- there is one explicit final sign-off gate:
  - `./scripts/ci/release_readiness_gates.sh`
- Phase 5 now executes:
  - `cargo audit --deny warnings`
  - `cargo deny check advisories bans licenses sources`
  as hard gates, not advisory side notes
- the operator docs state:
  - pinned host-key handling only
  - no SSH TOFU in automation
  - passwordless sudo expectations for live-lab automation
  - credential-only secret custody for unattended runtime
- the gate layer now writes authoritative machine-readable reports:
  - `artifacts/release/phase5_gate_report.json`
  - `artifacts/release/phase5_readiness_bundle.json`
  - both distinguish `executed_passed`, `executed_failed`, and `not_executed`

What is still missing:

- commit-bound fresh-install evidence for current `HEAD`
- canonical cross-network evidence for current `HEAD`

Those are release blockers, not documentation gaps.

## Current Authoritative Gate Result

Current release-readiness result for the repository state exercised on 2026-04-13:

- `cargo fmt --all -- --check`: pass
- `cargo check --workspace --all-targets --all-features`: pass
- `cargo test --workspace --all-targets --all-features`: fail in this host environment
- `cargo audit --deny warnings`: pass
- `cargo deny check advisories bans licenses sources`: pass
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`: pass
- `./scripts/ci/phase5_gates.sh`: fail
- `./scripts/ci/release_readiness_gates.sh`: fail

The top-level release gate is therefore an authoritative **fail**.

Why it fails:

1. Phase 5 hard gate failure
   - `./scripts/ci/phase5_gates.sh` now fails at the workspace test step, not at
     `clippy`.
   - `artifacts/release/phase5_gate_report.json` records:
     - `cargo_fmt = executed_passed`
     - `cargo_clippy = executed_passed`
     - `cargo_check = executed_passed`
     - `cargo_test = executed_failed`
   - The current failing test surface is inside
     `crates/rustynet-backend-wireguard` userspace-shared tests, where the host
     environment returns:
     - `ephemeral port should be available: Os { code: 1, kind: PermissionDenied, message: "Operation not permitted" }`
   - Because `phase5_gates` stops there, later Phase 5 steps are correctly
     recorded as `not_executed`.

2. Windows fresh-install evidence is still absent for current `HEAD`
   - Windows remains intentionally outside the required OS/scenario set in
     `documents/operations/FreshInstallOSMatrixReleaseGate.md`.
   - The latest Windows VM-lab validation on 2026-04-15 did not produce clean
     current-`HEAD` evidence:
     - discovery matched `windows-utm`, but did not establish an authoritative
       live IP or SSH-ready state
     - `verify-runtime`, `install-release`, and `restart-runtime` all failed on
       the local UTM guest path with:
       - `UTM Windows capture output was missing rc marker`
   - That means there are still no dated Windows clean-install/runtime artifacts
     that could justify adding `windows` to the release-gated OS matrix.

3. Fresh-install and canonical cross-network release evidence remain outside the current pass set
   - Because `release_readiness_gates.sh` stops at the failing Phase 5 gate,
     Phase 10 release-evidence steps are currently `not_executed`.
   - Even if the workspace test blocker were cleared, Windows would still remain
     outside the release gate until there is measured, commit-bound Windows
     clean-install/runtime/service evidence for the supported scope.

## Reduced Helper Evidence

The refreshed reduced/local-gate evidence currently available is:

- role-switch:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/role_switch_matrix_report_12ebe96.json`
- two-hop:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json`
  - this report records `second_client_route_via_rustynet0 = pass`
- LAN toggle:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_lan_toggle_report.json`
- managed DNS isolated rerun:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
- exit handoff isolated rerun:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`

All of those reports are tied to:

- `git_commit=12ebe9682320fdc3b15219e8657a20cb3568a273`

What this proves:

- the stricter five-node local-gates route-truth blocker is cleared
- managed DNS and exit handoff have current measured green artifacts on the local UTM lab

What it does **not** prove:

- it does not replace commit-bound fresh-install release evidence
- it does not replace canonical cross-network release evidence
- it does not justify a full release-gate pass claim

## Evidence Inventory

### Local / Reduced Evidence

Available and useful for defect isolation, but not authoritative release proof:

- `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/role_switch_matrix_report_12ebe96.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_lan_toggle_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`

### Strict Five-Node Local-Gate Evidence

Available and green for commit `12ebe9682320fdc3b15219e8657a20cb3568a273`:

- route-truth two-hop report:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json`
- LAN toggle report:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_lan_toggle_report.json`
- managed DNS retry report:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
- exit handoff retry report:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`

This is strong local evidence, but it is not current-`HEAD` canonical release evidence.

### Canonical Cross-Network Evidence

Missing for current `HEAD`.

Required reports:

- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_direct_remote_exit_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_relay_remote_exit_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_failback_roaming_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_traversal_adversarial_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_remote_exit_dns_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_remote_exit_soak_report.json`

### Extended Soak Evidence

Missing for current `HEAD`.

The authoritative canonical soak report path remains:

- `/Users/iwan/Desktop/Rustynet/artifacts/phase10/cross_network_remote_exit_soak_report.json`

The older same-underlay or reduced-helper soak artifacts under `artifacts/live_lab/` and older dated files under `artifacts/phase10/` are not substitutes.

### Full Release-Gate Result

Current machine-readable release-gate outputs:

- `/Users/iwan/Desktop/Rustynet/artifacts/release/phase5_gate_report.json`
- `/Users/iwan/Desktop/Rustynet/artifacts/release/phase5_readiness_bundle.json`

Those artifacts currently record an authoritative fail, not a pass.

### Windows Fresh-Install Evidence

Missing for current `HEAD`.

Current dated Windows validation facts:

- 2026-04-15 local UTM discovery report:
  - `/tmp/rustynet-win-phase4-discovery`
- current branch truth:
  - Windows runtime host/config wiring exists
  - Windows backend truth remains `windows-unsupported`
  - no clean-install Windows artifact set exists for current `HEAD`

The 2026-04-15 Windows VM-lab attempts are not fresh-install release evidence.
They are blocker evidence only.

## Full Release-Gate Evidence

The release-ready claim still requires all of the following to be current and
valid:

- `./scripts/ci/phase5_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `artifacts/phase10/fresh_install_os_matrix_report.json`
- the six canonical cross-network reports under `artifacts/phase10/`

Current blocker state:

1. Fresh-install evidence
   - blocked by missing current-`HEAD` fresh-install artifacts
   - Windows specifically remains outside the release gate because there is no
     clean-install Windows runtime evidence for current `HEAD`
   - the latest Windows UTM attempt is blocked at the guest exec/output layer,
     so it cannot be promoted into release evidence

2. Canonical cross-network evidence
   - not exercised in the current top-level gate run because `phase5_gates`
     failed earlier
   - still required for a release-ready claim after the Phase 5 gate is green

3. Phase 5 gate execution
   - currently blocked by workspace test failures in
     `rustynet-backend-wireguard` userspace-shared tests on this host
   - until that failure is resolved in a proper validation environment, the
     top-level release gate will stop before Phase 10 and correctly record
     later release-evidence steps as `not_executed`

## Release Guardrails

The durable sign-off path is:

```bash
./scripts/ci/release_readiness_gates.sh
```

That gate intentionally requires:

- critical Rust quality gates
- advisory and license policy gates
- live-evidence gates
- final readiness docs and bundle

It should fail closed until the missing full-gate evidence exists.
It also must not treat a pre-existing bundle file as proof; the current gate run
must regenerate the report state and validate the Phase 5 step set, including
`cargo audit` and `cargo deny`.

## Attached Artifacts

- readiness bundle:
  - `/Users/iwan/Desktop/Rustynet/artifacts/release/phase5_readiness_bundle.json`
- phase5 gate report:
  - `/Users/iwan/Desktop/Rustynet/artifacts/release/phase5_gate_report.json`
- fresh-install report currently on disk:
  - `/Users/iwan/Desktop/Rustynet/artifacts/phase10/fresh_install_os_matrix_report.json`
- current cross-network blocker ledger:
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/Phase6CrossNetworkAndSharedTransportChecklist_2026-04-13.md`
- Phase 3 policy outcome:
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/Phase3DependencyAndPolicyCleanupChecklist_2026-04-12.md`
- Phase 4 local-gate evidence:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/role_switch_matrix_report_12ebe96.json`
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json`
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_lan_toggle_report.json`
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`
- current Phase 4 blocker ledger:
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/Phase4LiveLabEvidenceRefreshChecklist_2026-04-12.md`

## Next Required Steps

1. Fix the current `clippy` hard failure at `crates/rustynet-cli/src/bin/live_linux_managed_dns_test.rs:1021`.
2. Run the release gates in a validation environment where the
   `rustynet-backend-wireguard` userspace-shared tests can bind their required
   sockets without `Operation not permitted`.
3. Commit the current code state cleanly and keep the tree clean for the
   authoritative evidence run.
4. Generate dated, commit-bound Windows clean-install/runtime/service evidence
   only after the local UTM Windows guest exec/output path is authoritative.
5. Regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` on that
   clean current commit for the supported release-gated OS set.
6. Generate the six canonical cross-network reports on that clean commit.
7. Re-run:
   - `./scripts/ci/phase10_gates.sh`
   - `./scripts/ci/release_readiness_gates.sh`
