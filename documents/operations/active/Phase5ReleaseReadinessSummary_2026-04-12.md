# Phase 5 Release Readiness Summary

Prepared: 2026-04-12
Repository root: `/Users/iwan/Desktop/Rustynet`
Overall readiness: **not release-ready**

## Decision

Rustynet should not currently be described as fully release-ready.

What is now durable:

- there is one explicit final sign-off gate:
  - `./scripts/ci/release_readiness_gates.sh`
- the operator docs state:
  - pinned host-key handling only
  - no SSH TOFU in automation
  - passwordless sudo expectations for live-lab automation
  - credential-only secret custody for unattended runtime

What is still missing:

- commit-bound fresh-install evidence for current `HEAD`
- canonical cross-network evidence for current `HEAD`

Those are release blockers, not documentation gaps.

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

What this proves:

- the stricter five-node local-gates route-truth blocker is cleared
- managed DNS and exit handoff have current measured green artifacts on the local UTM lab

What it does **not** prove:

- it does not replace commit-bound fresh-install release evidence
- it does not replace canonical cross-network release evidence
- it does not justify a full release-gate pass claim

## Full Release-Gate Evidence

The release-ready claim still requires all of the following to be current and
valid:

- `./scripts/ci/phase5_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `artifacts/phase10/fresh_install_os_matrix_report.json`
- the six canonical cross-network reports under `artifacts/phase10/`

Current blocker state:

1. Fresh-install evidence
   - blocked by provenance
   - the latest Phase 4 live run used `SOURCE_MODE="working-tree"`
   - the recorded git status for that run is dirty, so the generator correctly refuses to issue commit-bound fresh-install evidence from it

2. Canonical cross-network evidence
   - blocked by topology and trust material
   - the five UTM lab nodes are all on the same underlay
   - the only distinct-underlay inventory target is `debian-lan-11`
   - strict preflight still fails because `/Users/iwan/.ssh/known_hosts` lacks a pinned host key for `debian-lan-11` / `192.168.0.11`

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

## Attached Artifacts

- readiness bundle:
  - `/Users/iwan/Desktop/Rustynet/artifacts/release/phase5_readiness_bundle.json`
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

1. Commit the current code state cleanly, then regenerate fresh-install evidence on that commit.
2. Provision trusted pinned host-key coverage for `debian-lan-11`, verify reachability, then generate the canonical cross-network reports on that clean commit.
3. Re-run `./scripts/ci/release_readiness_gates.sh`.
