# Rustynet Adversarial Hardening Assessment

Generated: 2026-03-14 21:37:21Z

## Scope And Authorization

- Lab-only authorization confirmed: code-audit-only
- In-scope systems: Rustynet source tree, tracked Phase 10 release-evidence artifacts, gate scripts, daemon/CLI local trust surfaces, and managed-DNS resolver behavior.
- Out-of-scope systems: live VM lab execution, underlay network behavior, hypervisor state, internet-exposed surfaces, and production deployment validation.
- Success criteria: identify concrete security findings that can be defended from source and test evidence, and distinguish them from attack families that appear covered in code but still require live-lab confirmation.

## Topology

exit (admin), client1 (client), client2 (client), relay (entry)

## Attack Plan

- Control-Plane Replay And Rollback
- Local Control Surface Spoofing
- DNS Integrity And Namespace Abuse
- Missing-State Fail-Closed Validation
- Release Evidence Integrity

## Attack Matrix

| Attack Family | Primary Nodes | Hypothesis | Expected Secure Behavior | Result | Evidence |
| --- | --- | --- | --- | --- | --- |
| Control-Plane Replay And Rollback | exit | Stale or tampered signed artifacts must be rejected without widening runtime state. | Reject artifact and preserve secure state or fail closed. | pass (generator path), fail (release gate path) | `scripts/e2e/generate_linux_fresh_install_os_matrix_report.py` enforces child `git_commit` binding; `scripts/ci/check_fresh_install_os_matrix_readiness.sh` does not recurse into child reports |
| Local Control Surface Spoofing | exit, client1, client2, relay | Clients must reject insecure or attacker-owned local control surfaces before connecting. | Reject path based on ownership, symlink, or mode checks. | pass | `cargo test -p rustynet-cli control_socket_validator -- --nocapture` passed (`3/3`) |
| DNS Integrity And Namespace Abuse | exit | Managed DNS must reject stale, mismatched, or unauthorized name-to-node mappings. | Managed names fail closed and non-managed names are refused. | pass | `cargo test -p rustynetd dns_resolver_servfails_managed_name_when_zone_is_missing -- --nocapture` passed (`1/1`) |
| Missing-State Fail-Closed Validation | exit, client1, client2, relay | Removing required trust inputs must make the system restrictive, not permissive. | Operation fails closed with explicit error. | pass (selected paths only) | `cargo test -p rustynetd traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback -- --nocapture` passed (`1/1`) |
| Release Evidence Integrity | exit, client1, client2, relay | Release evidence must bind to the exact source state and portable artifact paths. | Mismatched or stale evidence is rejected. | fail | `./scripts/ci/check_fresh_install_os_matrix_readiness.sh` fails on the tracked report; top-level-only `git_commit` rewrite in a temp report still passes under `RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux` |

## Findings

### [P1] Tracked fresh-install OS matrix evidence is stale for current HEAD

- Attack family: Release Evidence Integrity
- Evidence:
  - [fresh_install_os_matrix_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/fresh_install_os_matrix_report.json#L6) still binds the tracked report to commit `4500e386d557ef59b7d5744d188654a0035e5272`
  - local `HEAD` during this audit is `85884c49a6ea6e672b05b4158ebeb43d0f79eb9b`
  - `./scripts/ci/check_fresh_install_os_matrix_readiness.sh` fails with `report=4500e386... expected=85884c49...`
- Affected files/subsystems:
  - [fresh_install_os_matrix_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/fresh_install_os_matrix_report.json#L1)
  - [check_fresh_install_os_matrix_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_fresh_install_os_matrix_readiness.sh#L146)
- Expected secure behavior:
  - tracked release evidence for the current branch tip should either be current and commit-bound, or absent
  - stale evidence must not look like valid current evidence inside the repo
- Actual behavior:
  - the tracked report is stale and immediately fails its own readiness gate
  - anyone relying on the checked-in artifact rather than the gate output would be looking at invalid evidence
- Remediation:
  - regenerate the fresh-install OS matrix report on the current commit before treating the repo as release-ready
  - require tracked release evidence refresh as part of the merge/publish path, not as an optional follow-up
- Required regression test or gate:
  - `./scripts/ci/check_fresh_install_os_matrix_readiness.sh`
  - `./scripts/ci/phase10_gates.sh`

### [P1] Fresh-install readiness validates only the top-level report commit, not the child evidence commit bindings

- Attack family: Release Evidence Integrity
- Evidence:
  - the report generator explicitly rejects child report commit drift in [generate_linux_fresh_install_os_matrix_report.py](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/generate_linux_fresh_install_os_matrix_report.py#L78)
  - the readiness gate checks only the top-level report `git_commit` in [check_fresh_install_os_matrix_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_fresh_install_os_matrix_readiness.sh#L146) and then only verifies child source artifact existence in [check_fresh_install_os_matrix_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_fresh_install_os_matrix_readiness.sh#L211)
  - the currently rebound child reports are all still bound to the stale commit `4500e386...`:
    - [live_linux_two_hop_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/source/fresh_install_os_matrix/live_linux_two_hop_report.json#L7)
    - [live_linux_lan_toggle_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/source/fresh_install_os_matrix/live_linux_lan_toggle_report.json#L7)
    - [live_linux_exit_handoff_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/source/fresh_install_os_matrix/live_linux_exit_handoff_report.json#L7)
  - proof-of-gap: a temporary copy of the top-level report with only `git_commit` rewritten to current `HEAD` passed `check_fresh_install_os_matrix_readiness.sh` under `RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux`, even though all child evidence remained stale
- Affected files/subsystems:
  - [check_fresh_install_os_matrix_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_fresh_install_os_matrix_readiness.sh#L139)
  - [generate_linux_fresh_install_os_matrix_report.py](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/generate_linux_fresh_install_os_matrix_report.py#L78)
  - [artifacts/phase10/source/fresh_install_os_matrix](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/source/fresh_install_os_matrix)
- Expected secure behavior:
  - readiness verification should recursively enforce commit binding for all referenced measured child reports, not only the wrapper report
- Actual behavior:
  - the gate can be satisfied by rewriting the wrapper report commit while leaving stale child evidence in place
- Remediation:
  - extend `check_fresh_install_os_matrix_readiness.sh` to parse referenced child JSON reports and verify their `git_commit`, `evidence_mode`, and timestamps against the same expected commit
  - reject commit-mismatched source artifact filenames or reports before the top-level report is accepted
- Required regression test or gate:
  - add a negative test fixture where the top-level report commit matches `HEAD` but one referenced child report does not
  - gate must fail on that fixture before `phase10_gates.sh` can pass

## Code Audit Notes

- Trust boundaries reviewed:
  - signed evidence ingestion and commit binding for fresh-install release evidence
  - CLI daemon socket trust validation
  - managed-DNS authoritative resolver fail-closed behavior
- Privileged boundaries reviewed:
  - local daemon socket validation in [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs#L5941)
  - helper/socket path checks remain present and tested; no new finding raised in this pass
- Fallback or legacy paths found:
  - the main live release-evidence problem is provenance drift, not a raw shell fallback branch
  - the release gate still trusts wrapper-report commit binding more than child-report commit binding
- Tests and gates reviewed:
  - `cargo test -p rustynet-cli control_socket_validator -- --nocapture` passed
  - `cargo test -p rustynetd dns_resolver_servfails_managed_name_when_zone_is_missing -- --nocapture` passed
  - `cargo test -p rustynetd traversal::tests::adversarial_gate_nat_mismatch_blocks_unauthorized_direct_and_keeps_safe_relay_fallback -- --nocapture` passed
  - `./scripts/ci/check_fresh_install_os_matrix_readiness.sh` failed on the tracked stale report
  - top-level-only rewrite replay test passed unexpectedly under the linux profile, confirming the child-binding gap

## Recommended Hardening Work

1. Regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` and its child evidence on current `HEAD` before using the repo for any release-readiness claim.
2. Harden `check_fresh_install_os_matrix_readiness.sh` so it recursively validates the `git_commit` and freshness of all referenced measured child reports.
3. Add a dedicated negative-test fixture for wrapper-report commit rewrite with stale child evidence, and make it gate Phase 10 readiness.

## Verification Plan

1. Add a readiness negative test where the wrapper report commit matches `HEAD` but at least one child report commit is stale; require failure.
2. Re-run `./scripts/ci/check_fresh_install_os_matrix_readiness.sh` and `./scripts/ci/phase10_gates.sh` after regenerating evidence on the current commit.
3. Re-run the five-node Linux lab tomorrow so the report reflects fresh measured evidence rather than stale tracked artifacts.
