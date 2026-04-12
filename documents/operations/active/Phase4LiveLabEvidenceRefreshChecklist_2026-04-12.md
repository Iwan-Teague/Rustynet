# Phase 4 Live-Lab Evidence Refresh Checklist

Prepared: 2026-04-12
Scope: live UTM/Debian validation artifacts under `artifacts/live_lab/`, canonical Phase 10 evidence under `artifacts/phase10/`, and active operational truth documents
Objective: prove the current fixes on the real Debian 12 lab, keep `second_client_route_via_rustynet0` backend-authoritative, and regenerate the stale commit-bound evidence set only when the repo's own provenance rules allow it

## Checklist

- [x] Typed local validation steps ran first
  Evidence:
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynetd`
  - `cargo check -p rustynet-cli`
  - `cargo test -p rustynetd phase10 -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_two_hop_test -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_exit_handoff_test -- --nocapture`
  - `cargo test -p rustynet-cli --bin live_linux_lan_toggle_test -- --nocapture`
  - `cargo test -p rustynet-backend-wireguard userspace_shared -- --nocapture`

- [x] Reduced helper reruns were used only to isolate the first failing live stage
  Evidence:
  - managed DNS isolation artifact: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
  - managed DNS isolation log: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry.log`
  - exit handoff isolation artifact: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`
  - exit handoff isolation log: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry.log`

- [x] Stricter five-node local-gates evidence is green through `live_two_hop` for the right reason
  Evidence:
  - role-switch report: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/role_switch_matrix_report_12ebe96.json`
  - exit-handoff retry report: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json`
  - two-hop report: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json`
  - LAN-toggle report: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_lan_toggle_report.json`
  - managed-DNS retry report: `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_managed_dns_retry_report.json`
  Notes:
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_two_hop_report.json` records `second_client_route_via_rustynet0 = pass`.
  - `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/live_linux_exit_handoff_retry_report.json` records a pass with the final client route still measured on `rustynet0` after the exit switch.

- [ ] Fresh-install evidence regenerated for current HEAD
  Blocker:
  - current Phase 4 provenance is still `SOURCE_MODE="working-tree"` with a dirty workspace recorded in `/Users/iwan/Desktop/Rustynet/artifacts/live_lab/20260412T_phase4_local_gates_worktree/state/git_status.txt`
  - the generator is intentionally fail-closed here: `crates/rustynet-cli/src/ops_fresh_install_os_matrix.rs` rejects commit-bound fresh-install evidence from a dirty working tree
  Required next step:
  - create a clean commit for the current fixes, rerun the relevant live evidence on that commit, then generate `/Users/iwan/Desktop/Rustynet/artifacts/phase10/fresh_install_os_matrix_report.json`

- [ ] Canonical cross-network evidence regenerated for current HEAD
  Blocker:
  - the five UTM nodes in `/Users/iwan/Desktop/Rustynet/documents/operations/active/vm_lab_inventory.json` are all on the same underlay `utm-shared-192.168.64.0/24`, so they cannot honestly satisfy the repo's cross-network proof contract by themselves
  - the only distinct-underlay inventory entry is `debian-lan-11`, but strict preflight currently stops before reachability proof because pinned host-key coverage is missing for `debian-lan-11`
  Evidence:
  - inventory: `/Users/iwan/Desktop/Rustynet/documents/operations/active/vm_lab_inventory.json`
  - topology contract: `/Users/iwan/Desktop/Rustynet/documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md`
  Required next step:
  - add pinned `known_hosts` coverage for `debian-lan-11`, verify SSH reachability, then run the cross-network suites on a clean commit so the six canonical reports under `/Users/iwan/Desktop/Rustynet/artifacts/phase10/` are current and truthful

- [x] Active operational docs updated with final current truth
  Evidence:
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md`
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/LinuxUserspaceSharedLiveLabReadinessDelta_2026-04-02.md`
  - `/Users/iwan/Desktop/Rustynet/documents/operations/active/MasterWorkPlan_2026-03-22.md`
  Notes:
  - the updated docs explicitly record that the stricter five-node local-gates route-truth blocker is cleared
  - the updated docs also explicitly record that Phase 4 remains incomplete until commit-bound fresh-install evidence and canonical cross-network evidence exist for current `HEAD`

## Current Phase 4 Truth

- The route-truth blocker named by the audit pack is cleared in measured local-gate evidence:
  - `second_client_route_via_rustynet0` is now `pass`
- The managed-DNS and exit-handoff stages also have measured green retry artifacts for current code in the live UTM lab
- Phase 4 is not complete because the repo still lacks:
  - fresh-install matrix evidence for a clean current commit
  - canonical cross-network evidence for a clean current commit

## Validation Notes

- A rerun of `ops vm-lab-run-live-lab` in the same report directory unexpectedly restarted setup instead of reusing the already-complete setup state.
- That behavior is separate from the local-gate dataplane fixes above and should be investigated as a wrapper/reuse issue after the current evidence blockers are cleared.
