# Measured Evidence Generation

## Purpose
Generate Phase 6 and Phase 9 release-gate artifacts only from measured evidence. Static/pass-through artifact commits are not accepted.

## Phase 1: Runtime Baseline Inputs

### Automated measured env collector
Generate required Phase 1 baseline environment variables from measured evidence:

```bash
./scripts/perf/collect_phase1_measured_env.sh
```

Supported measured sources (checked in order unless overridden):
- `artifacts/perf/phase1/source/performance_samples.ndjson`
- `artifacts/operations/source/performance_samples.ndjson`
- `artifacts/operations/performance_budget_report.json`
- `artifacts/phase10/perf_budget_report.json`
- `artifacts/operations/raw/performance_budget_report.json`

Override source explicitly:
```bash
RUSTYNET_PHASE1_PERF_SAMPLES_PATH=/absolute/path/to/performance_samples.ndjson \
./scripts/perf/collect_phase1_measured_env.sh
```

Generated file:
- `artifacts/perf/phase1/measured_env.sh` (owner-readable only)

Then run baseline:
```bash
./scripts/perf/run_phase1_baseline.sh
```

`run_phase1_baseline.sh` auto-invokes the collector (fail-closed) when required `RUSTYNET_PHASE1_*` vars are missing.

## Phase 6: Platform Parity Report

### Automated collector
Generate host-specific probe evidence directly from platform commands and leak-test report:
```bash
./scripts/release/collect_platform_probe.sh
```

Generate full three-platform bundle (collects local host probe, imports missing probes from inbox, then builds report):
```bash
./scripts/release/collect_platform_parity_bundle.sh
```

Optional inbox location for probes collected on other hosts:
- `artifacts/release/inbox/platform_parity_linux.json`
- `artifacts/release/inbox/platform_parity_macos.json`
- `artifacts/release/inbox/platform_parity_windows.json`

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

### Automated collector
Collect raw phase9 evidence from concrete source logs/config plus backend command probes:
```bash
./scripts/operations/collect_phase9_raw_evidence.sh
```

This collector writes:
- `artifacts/operations/raw/compatibility_policy.json`
- `artifacts/operations/raw/slo_error_budget_report.json`
- `artifacts/operations/raw/performance_budget_report.json`
- `artifacts/operations/raw/incident_drill_report.json`
- `artifacts/operations/raw/dr_failover_report.json`
- `artifacts/operations/raw/backend_agility_report.json`
- `artifacts/operations/raw/crypto_deprecation_schedule.json`

### Required raw inputs
Create these source files before collection:
- `artifacts/operations/source/compatibility_policy.json`
- `artifacts/operations/source/crypto_deprecation_schedule.json`
- `artifacts/operations/source/slo_windows.ndjson`
- `artifacts/operations/source/performance_samples.ndjson`
- `artifacts/operations/source/incident_drills.ndjson`
- `artifacts/operations/source/dr_drills.ndjson`
- `artifacts/operations/source/backend_security_review.json`

Expected minimal schema notes:
- `slo_windows.ndjson` entries:
  - `window_start_utc`, `window_end_utc`
  - `availability_slo_percent`, `measured_availability_percent`
  - `max_error_budget_consumed_percent`, `measured_error_budget_consumed_percent`
- `performance_samples.ndjson` entries:
  - `measured_at_utc` or `timestamp_utc`
  - `idle_cpu_percent`, `idle_memory_mb`
  - `reconnect_seconds` (or `reconnect_p95_seconds`)
  - `route_apply_p95_seconds` (or `route_apply_seconds_p95`)
  - `throughput_overhead_percent` (or `throughput_overhead_vs_wireguard_percent`)
- `incident_drills.ndjson` entries:
  - `drill_id`, `executed_at_utc`, `scenario`
  - `detection_minutes`, `containment_minutes`, `recovery_minutes`
  - `postmortem_completed`, `action_items_closed`, `oncall_readiness_confirmed`
- `dr_drills.ndjson` entries:
  - `drill_id`, `executed_at_utc`, `regions_tested`, `region_count`
  - `rpo_target_minutes`, `rto_target_minutes`
  - `measured_rpo_minutes`, `measured_rto_minutes`
  - `restore_integrity_verified`
- `backend_security_review.json`:
  - `additional_backend_paths` (non-empty list)
  - `security_review_complete` (bool)
  - `wireguard_is_adapter_boundary` (bool)
  - optional `default_backend`

Then generate measured phase9 artifacts:
```bash
RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase9_artifacts.sh
```

Create these raw files before generation if not using the collector:
- `artifacts/operations/raw/compatibility_policy.json`
- `artifacts/operations/raw/slo_error_budget_report.json`
- `artifacts/operations/raw/performance_budget_report.json`
- `artifacts/operations/raw/incident_drill_report.json`
- `artifacts/operations/raw/dr_failover_report.json`
- `artifacts/operations/raw/backend_agility_report.json`
- `artifacts/operations/raw/crypto_deprecation_schedule.json`

Raw backend agility evidence must not use simulated backend paths or stub backend command evidence.

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

Optional CI automation flags:
```bash
RUSTYNET_PHASE6_COLLECT_PARITY=1 ./scripts/ci/phase6_gates.sh
RUSTYNET_PHASE9_COLLECT_RAW=1 RUSTYNET_PHASE9_GENERATE_ARTIFACTS=1 RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=ci ./scripts/ci/phase9_gates.sh
```
