# Production Runbook

## Scope
Operational runbook for Rustynet control plane, relay plane, and client-release promotion pipeline.

## Normal Operations
1. Verify service health and alert dashboards at shift start.
2. Confirm error-budget trend and active incident state.
3. Validate artifact integrity for current release channel.
4. Confirm backup jobs and restore checks completed in last 24 hours.

## Deployment Procedure
1. Run `scripts/ci/phase9_gates.sh`.
2. Promote release in staged order: `unstable -> canary -> stable`.
3. Monitor canary for SLO regression before stable promotion.
4. If any gate regresses, stop promotion and roll back.

## Incident Handling
1. Page primary on-call; page secondary if no ack within 5 minutes.
2. Classify severity and enforce response SLA.
3. Contain blast radius (auth/token revoke, route policy lockdown, relay traffic steering).
4. Record timeline and complete postmortem.

## Emergency Rollback
- Trigger conditions:
  - trust-state verification failure,
  - security gate failure,
  - SLO/performance gate breach,
  - DR readiness regression.
- Actions:
  1. Halt rollout.
  2. Revert to last signed stable artifact.
  3. Re-validate signing/SBOM/provenance.
  4. Run incident bridge until service is stable.

## On-Call Readiness Requirements
- 24/7 rotation with primary and secondary responder.
- Escalation chain documented and tested in drills.
- Access credentials use least privilege and MFA.
- On-call readiness must be asserted in drill evidence before GA.
