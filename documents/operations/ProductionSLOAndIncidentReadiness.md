# Production SLO and Incident Readiness

## Service Level Objectives
Release gate thresholds:
- Availability SLO: `>= 99.9%`
- Error budget consumed: `<= 100%` of monthly budget
- Performance budgets:
  - idle CPU `<= 2%` of one core
  - idle memory `<= 120MB RSS`
  - reconnect `<= 5s`
  - route apply p95 `<= 2s`
  - throughput overhead `<= 15%`
  - soak duration `>= 24h`

Operational evidence artifacts:
- `artifacts/operations/slo_error_budget_report.json`
- `artifacts/operations/performance_budget_report.json`

## Alerting and Gate Behavior
- Alerting policy is default-deny for release progression: if any SLO/performance gate fails, promotion blocks.
- Promotion tracks remain staged (`unstable -> canary -> stable`).
- Security-sensitive changes require canary stability and gate pass before stable.

## Incident Drill Standard
Required per drill:
1. Scenario scope and trigger conditions.
2. Detection, containment, and recovery timings.
3. Postmortem with actionable controls and closed actions.
4. Confirmation that on-call handoff and escalation paths worked.

Drill evidence artifact:
- `artifacts/operations/incident_drill_report.json`

## On-Call Readiness
- 24/7 primary and secondary responder schedule for production incidents.
- Escalation path: on-call -> security owner -> engineering owner -> operations owner.
- Mandatory incident communications channels documented before GA.
- Every drill must confirm on-call readiness flag.

## Enforcement Points
- `crates/rustynet-control/src/ga.rs`
  - `ErrorBudgetGate::passes`
  - `PerformanceBudgetSnapshot::passes`
  - `GaReleaseReadiness::evaluate`
- `scripts/ci/check_phase9_readiness.sh`
  - blocks release when SLO/performance/incident evidence is out of policy.

## Verification
- `scripts/ci/check_phase9_readiness.sh`
- `scripts/ci/phase9_gates.sh`
