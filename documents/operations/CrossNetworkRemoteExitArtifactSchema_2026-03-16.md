# Cross-Network Remote Exit Artifact Schema (2026-03-16)

## 1. Purpose
Define the canonical measured artifact contract for the future cross-network remote-exit Phase 10 reports.

This schema exists before the implementation is complete so the evidence contract can be stable, testable, and fail-closed.

Primary validator command:
- `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports ...`

Shared Rust schema/validator implementation:
- [ops_cross_network_reports.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_cross_network_reports.rs)

Local schema self-test:
- [test_validate_cross_network_remote_exit_reports.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/test_validate_cross_network_remote_exit_reports.sh)

## 2. Required Reports
The following measured reports are required for the cross-network remote-exit claim:
1. `cross_network_direct_remote_exit_report.json`
2. `cross_network_relay_remote_exit_report.json`
3. `cross_network_failback_roaming_report.json`
4. `cross_network_traversal_adversarial_report.json`
5. `cross_network_remote_exit_dns_report.json`
6. `cross_network_remote_exit_soak_report.json`

## 3. Common Required Fields
Every report must contain:
- `schema_version = 1`
- `phase = "phase10"`
- `suite`
- `environment`
- `evidence_mode = "measured"`
- `captured_at_unix`
- `git_commit`
- `status`
- `participants`
- `network_context`
- `checks`
- `source_artifacts`
- `log_artifacts`

## 4. Common Security Rules
Every report is rejected if:
1. `git_commit` is missing or not a full commit id.
2. `captured_at_unix` is invalid or stale.
3. `source_artifacts` or `log_artifacts` are missing or point to nonexistent files.
4. `client_network_id == exit_network_id`.
5. `status = pass` but any required check is not `pass`.
6. `status = fail` but `failure_summary` is missing.
7. `source_artifacts` or `log_artifacts` include symlinks, non-files, control-character paths, or files outside the report directory / repository root trust boundary.

## 5. Suite-Specific Required Checks
### 5.1 `cross_network_direct_remote_exit`
- `direct_remote_exit_success`
- `remote_exit_no_underlay_leak`
- `remote_exit_server_ip_bypass_is_narrow`

### 5.2 `cross_network_relay_remote_exit`
- `relay_remote_exit_success`
- `remote_exit_no_underlay_leak`
- `remote_exit_server_ip_bypass_is_narrow`

### 5.3 `cross_network_failback_roaming`
- `relay_to_direct_failback_success`
- `endpoint_roam_recovery_success`
- `remote_exit_no_underlay_leak`

### 5.4 `cross_network_traversal_adversarial`
- `forged_traversal_rejected`
- `stale_traversal_rejected`
- `replayed_traversal_rejected`
- `rogue_endpoint_rejected`
- `control_surface_exposure_blocked`

### 5.5 `cross_network_remote_exit_dns`
- `managed_dns_resolution_success`
- `remote_exit_dns_fail_closed`
- `remote_exit_no_underlay_leak`

### 5.6 `cross_network_remote_exit_soak`
- `long_soak_stable`
- `remote_exit_no_underlay_leak`
- `remote_exit_server_ip_bypass_is_narrow`
- `cross_network_topology_heuristic`
- `direct_remote_exit_ready`
- `post_soak_bypass_ready`
- `no_plaintext_passphrase_files`

## 6. Suite-Specific Participants
### 6.1 Direct remote exit
- `client_host`
- `exit_host`

### 6.2 Relay remote exit
- `client_host`
- `exit_host`
- `relay_host`

### 6.3 Failback and roaming
- `client_host`
- `exit_host`
- `relay_host`

### 6.4 Traversal adversarial
- `client_host`
- `exit_host`
- `probe_host`

### 6.5 DNS
- `client_host`
- `exit_host`

### 6.6 Soak
- `client_host`
- `exit_host`

## 7. Suite-Specific Network Context
Every report must include:
- `client_network_id`
- `exit_network_id`
- `nat_profile`
- `impairment_profile`

Reports that require a relay also include:
- `relay_network_id`

The client and exit network ids must differ, otherwise the report is not proving a cross-network condition.

## 8. Design Intent
This schema is intentionally strict:
- one measured artifact path only
- explicit commit binding
- explicit cross-network proof
- explicit adversarial rejection proof
- no placeholder success without real source/log artifacts

These reports are meant to become release evidence, not informal test output.
