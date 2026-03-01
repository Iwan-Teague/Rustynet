# Disaster Recovery and Multi-Region Failover Validation

## Targets
- RPO target: `<= 15 minutes`
- RTO target: `<= 60 minutes`
- Multi-region requirement: at least `2` production regions
- Restore integrity verification required for every drill

## Drill Procedure
1. Simulate regional control-plane outage.
2. Trigger failover to secondary region.
3. Restore state from latest backups.
4. Reconcile session/control-state and validate signatures/integrity.
5. Measure achieved RPO/RTO and record evidence.

## Latest Validation Evidence
Artifact:
- `artifacts/operations/dr_failover_report.json`
- Generated via `scripts/operations/generate_phase9_artifacts.sh` from measured raw evidence inputs.

## Fail-Closed Decision
If RPO/RTO or restore-integrity checks fail, stable release promotion is blocked.

## Enforcement Points
- `crates/rustynet-control/src/ga.rs`
  - `DisasterRecoveryValidation::passes`
  - `GaReleaseReadiness::evaluate`
- `scripts/ci/check_phase9_readiness.sh`
  - enforces region count, RPO/RTO thresholds, and restore integrity signal.

## Verification
- `scripts/ci/check_phase9_readiness.sh`
- `scripts/ci/phase9_gates.sh`
