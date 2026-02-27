# Rustynet Policy Rollout Runbook

## Preconditions
- Policy must pass `ContextualPolicySet` validation.
- Any revision containing allow-all behavior is rejected.
- Change owner and rollback owner are assigned before rollout.

## Rollout Steps
1. Stage revision in `PolicyRolloutController`.
2. Run policy validation tests in CI.
3. Promote staged revision to canary.
4. Observe canary metrics and audit events.
5. Promote canary to active revision.

## Rollback
1. Select previous known-good revision ID.
2. Execute rollback using `PolicyRolloutController::rollback_to`.
3. Verify policy evaluation and access controls with regression tests.
4. Record rollback reason and outcome in audit trail.

## Safety Requirements
- Default-deny behavior must be preserved across revisions.
- Protocol filters must not widen in shared subnet-router/shared-exit contexts.
- Rollout and rollback actions must be audited with actor identity and timestamp.
