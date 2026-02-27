# Privacy and Data Retention Policy

## Data Classes
- `auth_events`: authentication and abuse-control telemetry.
- `audit_events`: security-relevant administrative actions.
- `diagnostic_metrics`: operational health/performance metrics.
- `credential_material_references`: non-secret references to vaulted secrets.

## Retention Windows
- `auth_events`: 90 days.
- `audit_events`: 365 days.
- `diagnostic_metrics`: 30 days raw, 180 days aggregated.
- `credential_material_references`: lifetime of associated credential plus 30 days.

## Minimization Rules
- No plaintext secrets in telemetry or logs.
- Hash or redact identity-sensitive fields when full fidelity is not required for operations.
- Collect only fields needed for security triage and reliability diagnostics.

## Deletion and Review
- Retention expiration is enforced during scheduled maintenance jobs.
- Quarterly privacy review validates class mappings and retention compliance.
