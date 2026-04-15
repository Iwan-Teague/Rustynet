# Fresh Install OS Matrix Release Gate

## Purpose
Enforce a fail-closed release gate that requires fresh, measured cross-platform install/runtime evidence before Phase10 release gates pass.

This gate blocks release if any required OS/scenario evidence is missing, stale, malformed, or not bound to the exact commit under test.

## Gate Commands

```bash
./scripts/ci/check_fresh_install_os_matrix_readiness.sh
./scripts/ci/fresh_install_os_matrix_release_gate.sh
```

`phase10_gates.sh` invokes `fresh_install_os_matrix_release_gate.sh` as an early preflight, so Phase10 release gating fails closed immediately when this evidence is absent or invalid.

## Required Report
- Path: `artifacts/phase10/fresh_install_os_matrix_report.json`
- Schema:
  - `schema_version = 1`
  - `evidence_mode = "measured"`
  - `environment` non-empty string
  - `captured_at_unix` positive integer and fresh
  - `git_commit` exact 40-char lowercase SHA matching `git rev-parse HEAD`
  - `source_artifacts` non-empty list of existing paths
  - `security_assertions` object with required booleans set `true`
  - `scenarios` object containing exactly:
    - `debian13`
    - `ubuntu`
    - `fedora`
    - `mint`
    - `macos`

## Current Windows Exclusion

- Windows is intentionally not part of the required OS/scenario set on the
  current branch.
- Windows VM-lab bootstrap support does not satisfy this release gate.
- Do not add a `windows` scenario key until there is measured, commit-bound
  Windows clean-install, one-hop, two-hop, role-switch, and runtime/service
  evidence for the current `HEAD`.

## Per-OS Scenario Requirements
Each OS scenario must be `status=pass` and include:
- `clean_install`
- `one_hop`
- `two_hop`
- `role_switch`

Each scenario section must contain:
- `status=pass`
- `captured_at_unix` fresh timestamp
- `source_artifacts` non-empty existing-path list
- `checks` object with required keys, all set to `"pass"`

Additional strict checks:
- `one_hop.hop_count == 1`
- `two_hop.hop_count == 2`
- `role_switch.transitions` includes at least one real role change (`from_role != to_role`) and all transitions are `status=pass`

## Security Assertions Enforced
All must be `true`:
- `no_plaintext_secrets_at_rest`
- `encrypted_transport_required`
- `default_deny_enforced`
- `fail_closed_enforced`
- `least_privilege_role_switch`

## Freshness Policy
- Default max age: `604800` seconds (7 days)
- Override: `RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS`
- Report path override: `RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH`
- Profile override:
  - `RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=cross_platform` (default release mode: requires `debian13`, `ubuntu`, `fedora`, `mint`, `macos`)
  - `RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE=linux` (Linux-only validation mode: requires `debian13`, `ubuntu`, `fedora`, `mint`)

## Fail-Closed Behavior
The gate fails when any of the following occurs:
- missing OS key (`debian13`, `ubuntu`, `fedora`, `mint`, `macos`)
- missing section (`clean_install`, `one_hop`, `two_hop`, `role_switch`)
- any required check missing or not `pass`
- stale timestamps
- missing source artifact paths
- commit SHA mismatch with current `HEAD`
- any required security assertion is not `true`
