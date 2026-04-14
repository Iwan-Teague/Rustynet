# Measured Evidence Generation

## Purpose
Generate Phase 6 and Phase 9 release-gate artifacts only from measured evidence. Static/pass-through artifact commits are not accepted.

Related format-hardening plan:
- [SerializationFormatHardeningPlan_2026-03-25.md](./active/SerializationFormatHardeningPlan_2026-03-25.md)

## Phase 1: Runtime Baseline Inputs

### Automated measured input collector
Generate required Phase 1 baseline measured inputs from measured evidence:

```bash
./scripts/perf/collect_phase1_measured_env.sh
```

Measured source requirement:
- `RUSTYNET_PHASE1_PERF_SAMPLES_PATH` must resolve to a concrete measured source file.
- default path is `artifacts/perf/phase1/source/performance_samples.ndjson`.
- source discovery fallback chain is removed from the active Phase 1 gate path.
- missing source files fail closed.

Override source explicitly:
```bash
RUSTYNET_PHASE1_PERF_SAMPLES_PATH=/absolute/path/to/performance_samples.ndjson \
./scripts/perf/collect_phase1_measured_env.sh
```

Generated file:
- `artifacts/perf/phase1/measured_input.json` (owner-readable only by default)
  - override path with `RUSTYNET_PHASE1_MEASURED_INPUT_OUT`

Then run baseline:
```bash
./scripts/perf/run_phase1_baseline.sh
```

`run_phase1_baseline.sh` now requires a measured source path and exports
`RUSTYNET_PHASE1_PERF_SAMPLES_PATH` into the Rust command path directly.

Security hardening note:
- legacy shell `source` ingestion of generated phase1 env scripts has been removed from the active baseline path.
- phase1 collection/baseline validation is Rust-backed; shell wrappers only dispatch to Rust commands.
- phase1 measured source files and output directories must not be group/world writable (fail closed).

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

Bundle-collection import policy:
- the collector imports a probe from `artifacts/release/inbox/` when the raw probe is missing
- the collector also replaces a stale or older raw probe with a fresher inbox probe for the same platform
- stale seeded raw probes are not authoritative if fresher measured inbox evidence exists
- when a fresh external measured probe file already exists on disk, you can stage it into the inbox during bundle collection with:
  - `RUSTYNET_PHASE6_LINUX_PROBE_SOURCE=/absolute/path/to/platform_parity_linux.json`
  - `RUSTYNET_PHASE6_MACOS_PROBE_SOURCE=/absolute/path/to/platform_parity_macos.json`
  - `RUSTYNET_PHASE6_WINDOWS_PROBE_SOURCE=/absolute/path/to/platform_parity_windows.json`
- staged external probe files must already be measured, platform-matching, and fresh; stale or future-dated probe files fail closed and are not imported

Optional inbox location for probes collected on other hosts:
- `artifacts/release/inbox/platform_parity_linux.json`
- `artifacts/release/inbox/platform_parity_macos.json`
- `artifacts/release/inbox/platform_parity_windows.json`

### Required raw inputs
Create these files before generation:
- `artifacts/release/raw/platform_parity_linux.json`
- `artifacts/release/raw/platform_parity_macos.json`
- `artifacts/release/raw/platform_parity_windows.json`

Repository bootstrap note:
- The repo seeds `artifacts/release/raw/platform_parity_{linux,macos,windows}.json` so Phase 6 parity report generation can run on fresh workspaces.
- Keep these as measured probe records and refresh them from current host probes/inbox evidence before release sign-off.

Each raw file must be a JSON object with boolean fields:
- `route_hook_ready`
- `dns_hook_ready`
- `firewall_hook_ready`
- `leak_matrix_passed`

### Generate and validate
```bash
RUSTYNET_PHASE6_PARITY_ENVIRONMENT=lab \
./scripts/release/generate_platform_parity_report.sh
cargo run --quiet -p rustynet-cli -- ops verify-phase6-parity-evidence
```

Generated artifact:
- `artifacts/release/platform_parity_report.json`
- `artifacts/release/platform_parity_report.attestation.json`

## Phase 9: Operational Readiness Reports

### Automated collector
Collect raw phase9 evidence from concrete source logs/config plus backend command probes:
```bash
./scripts/operations/collect_phase9_raw_evidence.sh
```

The script is a thin wrapper over:
- `rustynet ops collect-phase9-raw-evidence`

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
cargo run --quiet -p rustynet-cli -- ops verify-phase9-evidence
```

The script is a thin wrapper over:
- `rustynet ops generate-phase9-artifacts`

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
- `artifacts/operations/phase9_evidence.attestation.json`

## Phase 10: Dataplane Readiness Reports

Generate measured phase10 artifacts from measured source evidence:
```bash
RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT=prod-lab \
./scripts/operations/generate_phase10_artifacts.sh
```

The script is a thin wrapper over:
- `rustynet ops generate-phase10-artifacts`

Required source files:
- `artifacts/phase10/source/netns_e2e_report.json`
- `artifacts/phase10/source/leak_test_report.json`
- `artifacts/phase10/source/perf_budget_report.json`
- `artifacts/phase10/source/direct_relay_failover_report.json`
- `artifacts/phase10/source/state_transition_audit.log`

Source evidence requirements:
- each JSON source must set `evidence_mode=measured`
- each JSON source must include positive integer `captured_at_unix`
- source timestamps must be fresh (default max age: 31 days)
- netns/leak/direct reports must have `status=pass`
- perf report must have `soak_status=pass` and no failing metric entries
- state transition log must include `generation=` entries

Provenance requirements (fail-closed):
- `RUSTYNET_PHASE10_PROVENANCE_SIGNING_KEY_PATH` and `RUSTYNET_PHASE10_PROVENANCE_VERIFIER_KEY_PATH` are optional. If unset, Rustynet uses:
  - `artifacts/phase10/provenance/signing_seed.hex`
  - `artifacts/phase10/provenance/verifier_key.hex`
- when both default key files are absent, Rustynet generates a matching Ed25519 keypair and writes owner-only files (`0600`) under an owner-only directory (`0700`); partial key-material state fails closed.
- if `RUSTYNET_PHASE10_PROVENANCE_HOST_ID` is unset, Rustynet defaults to `ci-localhost`.
- when set explicitly, key paths must resolve to absolute owner-only files (`<=0600`) and host id is bound into signed provenance payloads.
- `check_phase10_readiness.sh` now requires successful `rustynet ops verify-phase10-provenance` before structural checks.

Generated artifacts:
- `artifacts/phase10/netns_e2e_report.json`
- `artifacts/phase10/leak_test_report.json`
- `artifacts/phase10/perf_budget_report.json`
- `artifacts/phase10/direct_relay_failover_report.json`
- `artifacts/phase10/state_transition_audit.log`
- `artifacts/phase10/phase10_provenance.attestation.json`

Optional standalone provenance verification:
```bash
cargo run --quiet -p rustynet-cli -- ops verify-phase10-provenance
```

## Membership: Governance Evidence Reports

Generate membership measured evidence from runtime membership snapshot/log:
```bash
cargo run -p rustynet-cli -- membership generate-evidence \
  --snapshot /var/lib/rustynet/membership.snapshot \
  --log /var/lib/rustynet/membership.log \
  --output-dir artifacts/membership \
  --environment prod-lab
```

Bootstrap behavior in CI/dev workspaces:
- when `/var/lib/rustynet/membership.snapshot` and `/var/lib/rustynet/membership.log` are absent, `membership_gates.sh` uses seed files under `artifacts/membership/source/`.
- seed files are copied into `artifacts/membership/tmp_membership/` with mode `0600` before evidence generation.
- runtime paths remain preferred and unchanged on Debian hosts where `/var/lib/rustynet/*` exists.

Bootstrap source files:
- `artifacts/membership/source/membership.snapshot`
- `artifacts/membership/source/membership.log`

Generated artifacts:
- `artifacts/membership/membership_conformance_report.json`
- `artifacts/membership/membership_negative_tests_report.json`
- `artifacts/membership/membership_recovery_report.json`
- `artifacts/membership/membership_audit_integrity.log`

## CI validation
```bash
./scripts/ci/check_phase6_platform_parity.sh
./scripts/ci/check_phase9_readiness.sh
./scripts/ci/check_phase10_readiness.sh
```

Optional CI automation flags:
```bash
RUSTYNET_PHASE6_COLLECT_PARITY=1 ./scripts/ci/phase6_gates.sh
RUSTYNET_PHASE9_COLLECT_RAW=1 RUSTYNET_PHASE9_GENERATE_ARTIFACTS=1 RUSTYNET_PHASE9_EVIDENCE_ENVIRONMENT=ci ./scripts/ci/phase9_gates.sh
RUSTYNET_PHASE10_GENERATE_ARTIFACTS=1 RUSTYNET_PHASE10_EVIDENCE_ENVIRONMENT=ci ./scripts/ci/phase10_gates.sh
./scripts/ci/membership_gates.sh
```
