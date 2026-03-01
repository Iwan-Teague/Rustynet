# Membership Governance Incident Response Runbook

## Purpose
Define production incident response for Rustynet membership governance, covering approver compromise, node compromise, emergency revocation, quorum reconstitution, and backup/restore drills.

This runbook is authoritative for membership-related trust incidents and must be executed with fail-closed defaults.

## Non-Negotiables
- Rust-first codebase. Non-Rust only for unavoidable OS integration.
- WireGuard remains adapter-only; membership logic is protocol-agnostic.
- SecurityMinimumBar controls are release-blocking.
- No custom cryptography/protocol design in production paths.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.
- Default-deny policy is mandatory.

## Preconditions
- Membership files are present and permission-hardened:
  - `membership.snapshot` mode `0600`
  - `membership.log` mode `0600`
  - membership watermark mode `0600`
- At least one owner approver and one guardian approver are active.
- On-call operators have approved offline backups of:
  - `membership.snapshot`
  - `membership.log`
  - approver public-key set and threshold policy

## Detection and Triage
Trigger this runbook immediately when any of the following is observed:
- Unexpected membership update appears in log/audit.
- Daemon enters restricted-safe mode due to membership trust failure.
- Unauthorized node appears active in membership state.
- Approver private key exposure is suspected.
- Repeated watermark replay/rollback errors occur.

Initial triage checklist:
1. Freeze all membership applies (`membership apply-update` halted).
2. Collect forensic artifacts:
   - `membership.snapshot`
   - `membership.log`
   - `membership_audit_integrity.log`
3. Validate integrity:
   - `rustynet-cli membership verify-log --snapshot <snapshot> --log <log> --audit-output <audit>`
4. Confirm currently active root/epoch from each affected daemon.
5. Classify incident as `approver_compromise`, `node_compromise`, `replay_or_rollback`, or `unknown`.

## Playbook A: Approver Key Compromise
Objective: remove compromised approver authority without breaking quorum.

Steps:
1. Generate `rotate_approver` proposal for compromised approver with `status=revoked`.
2. Require owner + threshold signatures from still-trusted approvers.
3. Verify update on offline validation host:
   - `rustynet-cli membership verify-update --signed-update <file> --snapshot <snapshot> --log <log> --dry-run`
4. Apply update:
   - `rustynet-cli membership apply-update --signed-update <file> --snapshot <snapshot> --log <log>`
5. Rotate any quorum threshold only after compromised approver is revoked.
6. Publish updated approver public-key inventory to operators.

Fail-closed rule:
- If minimum threshold cannot be reached, do not apply any membership change; keep cluster in restricted-safe for trust-required operations.

## Playbook B: Node Key Compromise
Objective: revoke compromised node immediately and prevent dataplane re-entry.

Steps:
1. Create `propose-revoke` for compromised `node_id`.
2. Obtain quorum signatures.
3. Verify and apply update.
4. Confirm daemon behavior:
   - revoked node selection is denied,
   - revoked node routes/peers are removed on reconcile/fail-closed transition.
5. If device is recoverable, perform controlled key rotation:
   - `propose-rotate-key` + quorum signatures + apply.

Fail-closed rule:
- Unknown/revoked node cannot be allowed by ACL, even if legacy policy would allow it.

## Playbook C: Emergency Revocation
Objective: remove active malicious membership influence in shortest safe path.

Steps:
1. Enter emergency mode:
   - block non-essential operator changes,
   - disable automated rollout for membership intents.
2. Generate and sign revoke/remove update for target node(s) or approver(s).
3. Apply update to authoritative membership log/snapshot.
4. Force daemon reconcile cycle (or restart daemons) to enforce immediate deny.
5. Confirm:
   - `rustynet-cli status` shows no revoked node selected as exit,
   - route mutation attempts through revoked node are denied.

## Playbook D: Quorum Reconstitution
Objective: recover governance after multiple key losses/compromises.

Steps:
1. Restore last known good snapshot/log from signed backup.
2. Validate log chain and replay.
3. Propose approver-set rebuild (new owner/guardian keys).
4. Require strictest currently valid quorum to authorize rebuild.
5. Apply and distribute new approver public keys.
6. Rotate all non-compromised but potentially exposed approver keys.

Hard stop:
- If authoritative backup integrity cannot be proven, no membership apply is permitted.

## Backup/Restore Integrity Drill
Run weekly or before release:
1. Execute:
   - `./scripts/operations/membership_incident_drill.sh`
2. Validate generated artifacts in drill output:
   - `membership_conformance_report.json`
   - `membership_negative_tests_report.json`
   - `membership_recovery_report.json`
   - `membership_audit_integrity.log`
   - `drill_summary.log`
3. Record drill ID, operator, and pass/fail in incident tracker.

## Patch-SLA Tracking Hooks
Membership-critical vulnerabilities are tracked with these hooks:
1. Severity label must include `membership-critical`.
2. SLA timers:
   - Critical: mitigation/patch in 48 hours.
   - High: patch in 7 days.
   - Medium: patch in 30 days.
3. CI blocker:
   - unresolved `membership-critical` issue blocks release tag creation.
4. Each incident must link:
   - root cause,
   - remediation PR,
   - verification evidence (tests + artifacts).

## Evidence Requirements per Incident
- Exact command transcript used for verify/apply actions.
- Artifact bundle containing:
  - pre-incident snapshot/log hash
  - post-incident snapshot/log hash
  - audit log diff
  - daemon restricted-safe events (if triggered)
- Final statement that default-deny and fail-closed behavior remained intact.

## Closure Criteria
Incident is closed only when:
1. Compromised principals are revoked or rotated.
2. Membership integrity chain verifies on all targeted nodes.
3. Daemon and policy behavior confirms revoked/unknown deny path.
4. Evidence bundle is archived and reviewed by security + engineering owners.
