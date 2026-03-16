# Rustynet Audit Surface Map

Use this reference as the Rustynet-specific navigation layer for the skill.

## Normative Rustynet Documents

Read these first, in this order:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. `README.md`
5. `AGENTS.md`
6. `CLAUDE.md`

## Rustynet Live Validators

Primary Rustynet live validators currently used by the skill:
- `scripts/e2e/live_linux_control_surface_exposure_test.sh`
- `scripts/e2e/live_linux_server_ip_bypass_test.sh`
- `scripts/e2e/live_linux_endpoint_hijack_test.sh`

Canonical runner:
- `tools/skills/rustynet-security-auditor/scripts/run_rustynet_live_validations.py`
- runner preflight requirements:
  - pinned `known_hosts` file
  - host-key presence for every targeted host
  - active SSH reachability for every targeted host before validators start
  - required remote binaries present on every targeted host:
    - `rustynet`
    - `rustynetd`
    - `wg`
    - `systemctl`
    - `ss`
    - `python3`
  - `rustynetd.service` present and active on every targeted host before validators start

## Rustynet Comparative Coverage

Primary comparative exploit tooling:
- `tools/skills/rustynet-security-auditor/scripts/generate_comparative_exploit_coverage.py`

Expected comparative report location:
- `documents/operations/RustynetComparativeVpnExploitCoverage_<date>.md`

Current live-evidence promotion helpers:
- `tools/skills/rustynet-security-auditor/scripts/validate_live_lab_reports.py`
- `tools/skills/rustynet-security-auditor/scripts/generate_live_lab_findings.py`
- `tools/skills/rustynet-security-auditor/scripts/evaluate_live_coverage_promotion.py`

## Rustynet Artifact Paths

Common live-lab output roots:
- `artifacts/phase10/`
- `artifacts/live_lab/`
- `documents/operations/`

Current live-lab runner outputs:
- `live_linux_control_surface_exposure_report.json`
- `live_linux_server_ip_bypass_report.json`
- `live_linux_endpoint_hijack_report.json`
- `live_lab_schema_validation.md`
- `live_lab_findings.md`
- `live_lab_coverage_promotion.md`
- `live_lab_validation_summary.md`

## Rustynet Source Hotspots

Most likely enforcement files for the current exploit classes:
- control surface:
  - `crates/rustynet-cli/src/main.rs`
  - `crates/rustynetd/src/privileged_helper.rs`
  - `crates/rustynetd/src/daemon.rs`
- route / bypass / TunnelCrack class:
  - `crates/rustynetd/src/phase10.rs`
  - `crates/rustynetd/src/dataplane.rs`
  - `crates/rustynet-backend-wireguard/src/lib.rs`
- traversal / endpoint hijack:
  - `crates/rustynetd/src/daemon.rs`
  - `crates/rustynetd/src/traversal.rs`
  - `crates/rustynetd/src/phase10.rs`

## Rustynet Gate Scripts

Important Rustynet gate paths:
- `scripts/ci/phase10_gates.sh`
- `scripts/ci/check_fresh_install_os_matrix_readiness.sh`
- `scripts/ci/test_check_fresh_install_os_matrix_readiness.sh`

Use gate failures as evidence of broken enforcement, not as something to bypass.
