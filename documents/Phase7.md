# Rustynet Phase 7 Plan (Scale and Commercial Foundation)

## 0) Document Relationship and Scope
- This plan extends product expansion outputs from [Phase6.md](./Phase6.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 7 outputs are prerequisites for [Phase8.md](./Phase8.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 7 Objective
Scale the platform architecture and add commercial control primitives for broader customer readiness.

## 2) Phase 7 Scope
1. Control-plane high availability:
- Postgres-backed persistence for production.
- Stateless API replicas and failover behavior.
- Migration and rollback discipline.

2. Relay fleet maturity:
- Multi-relay deployment support.
- Health-based relay selection.
- Regional relay options.

3. Commercial controls:
- Multi-tenant organization model.
- Plan/feature gating primitives.
- Tenant-level policy boundaries and delegated administration.

4. Enterprise auth baseline:
- OIDC/SSO support.
- Enterprise MFA policy integration and step-up auth compatibility.

5. Control-plane trust hardening mode:
- Add optional coordination-compromise-resilient key authorization mode (tailnet-lock-style trust model).
- Require trusted key set for node-key authorization and auditable key-authority changes.
- Define and test break-glass/disable procedure with explicit secret/material requirements.
- Require trusted-state persistence and integrity checks for trust-hardening mode.
- If trusted state is unavailable/corrupt, trust-hardening mode must fail closed with explicit operator-visible erroring.

## 3) Deliverables
- HA control-plane deployment reference.
- Multi-relay control and health behavior in staging.
- Tenant controls and delegated admin boundaries implemented.
- SSO/MFA integration available for production use.
- Control-plane trust-hardening mode available and documented.

## 4) Security Gates
- Tenant-boundary isolation tests pass.
- Privileged operations enforce MFA and auditable authorization.
- HA failover does not bypass policy or revocation controls.
- Trust-hardening mode cannot be bypassed by compromised coordination service alone.
- Trust-hardening mode refuses to operate when trusted state cannot be safely loaded or persisted.

## 5) Phase 7 Exit Criteria
- Platform remains available through tested failover scenarios.
- Multi-tenant boundaries are validated.
- Commercial account controls function with auditable changes.
- Relay fleet behavior is stable under regional or node-level faults.

## 6) Handoff to Phase 8
- Phase 8 adds advanced assurance, compliance maturity, and stronger key custody controls.
- Use [Phase8.md](./Phase8.md) as the next execution plan once Phase 7 exit criteria are met.
