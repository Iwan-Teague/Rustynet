# Measured Evidence Generation

## Purpose
Generate Phase 6 and Phase 9 release-gate artifacts only from measured evidence. Static/pass-through artifact commits are not accepted.

## Phase 6: Platform Parity Report

### Required raw inputs
Create these files before generation:
- `artifacts/release/raw/platform_parity_linux.json`
- `artifacts/release/raw/platform_parity_macos.json`
- `artifacts/release/raw/platform_parity_windows.json`

Each raw file must be a JSON object with boolean fields:
- `route_hook_ready`
- `dns_hook_ready`
- `firewall_hook_ready`
- `leak_matrix_passed`

### Generate and validate
```bash
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh
```

Generated artifact:
- `artifacts/release/platform_parity_report.json`

## Phase 9: Operational Readiness Reports

### Required raw inputs
Create these files before generation:
- `artifacts/operations/raw/compatibility_policy.json`
- `artifacts/operations/raw/slo_error_budget_report.json`
- `artifacts/operations/raw/performance_budget_report.json`
- `artifacts/operations/raw/incident_drill_report.json`
- `artifacts/operations/raw/dr_failover_report.json`
- `artifacts/operations/raw/backend_agility_report.json`
- `artifacts/operations/raw/crypto_deprecation_schedule.json`

Raw backend agility evidence must not use simulated backend paths or stub backend command evidence.

### Generate and validate
```bash
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh
```

Generated artifacts:
- `artifacts/operations/compatibility_policy.json`
- `artifacts/operations/slo_error_budget_report.json`
- `artifacts/operations/performance_budget_report.json`
- `artifacts/operations/incident_drill_report.json`
- `artifacts/operations/dr_failover_report.json`
- `artifacts/operations/backend_agility_report.json`
- `artifacts/operations/crypto_deprecation_schedule.json`

## CI validation
```bash
./scripts/ci/check_phase6_platform_parity.sh
./scripts/ci/check_phase9_readiness.sh
```
