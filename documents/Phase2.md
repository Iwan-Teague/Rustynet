# Rustynet Phase 2 Plan (Identity, Enrollment, and Control-Plane Core)

## 0) Document Relationship and Scope
- This plan extends architecture outputs from [Phase1.md](./Phase1.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 2 outputs are prerequisites for [Phase3.md](./Phase3.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 2 Objective
Deliver secure identity and enrollment flows with auditable control-plane APIs, without yet taking on full data-plane feature scope.

## 2) Phase 2 Scope
1. Identity and auth core:
- User auth baseline (local auth first, extensible for OIDC later).
- Device/node identity key registration.
- Short-lived access tokens and refresh/renew patterns.

2. Throwaway credential lifecycle:
- Implement one-time credential states: `created`, `used`, `expired`, `revoked`.
- Enforce `max_uses = 1` with immediate invalidation after first successful use.
- Enforce atomic consume semantics using write-time revalidation in a single transaction.
- Add uniqueness constraints preventing key reuse under concurrent consume attempts.
- Add audit events for every lifecycle transition.

3. Control-plane API core:
- Enrollment endpoints.
- Node registration and metadata update endpoints.
- Signed peer-map delivery mechanism.
- Policy-fetch endpoint scaffolding.

4. Persistence baseline:
- Persist users, nodes, credentials, and lifecycle events.
- SQLite-first schema designed for later Postgres migration.

5. Trust-state persistence baseline:
- Persist trusted authorization/signing state with integrity checks.
- If trusted state is missing/corrupt/unwritable, trust-required operations must fail closed.

6. Authentication and API abuse hardening:
- Enforce per-IP and per-identity rate limiting for auth/enrollment endpoints.
- Enforce lockout/backoff controls for repeated failures.
- Enforce anti-replay controls (nonce/state checks and bounded token lifetimes).
- Add API abuse detection signals and operator alerts.

7. Endpoint key custody baseline:
- Use OS key store where available.
- If unavailable, enforce encrypted-at-rest fallback with strict permissions and startup permission validation.
- Ensure in-memory secret zeroization strategy is implemented for sensitive materials.

8. Credential lifecycle hardening:
- Make one-time enrollment credentials the default.
- Restrict reusable enrollment credentials to automation workflows with short expiry and strict scopes.
- Require secure storage policy for reusable credentials (vault/secret manager; no plaintext distribution).
- Enforce rapid revocation propagation for compromised credentials.

## 3) Deliverables
- Working enrollment flow through CLI + control-plane APIs.
- Throwaway credential generation and lifecycle enforcement.
- Signed peer-map distribution path in place.
- Audit log entries for auth and enrollment actions.
- Reusable credential safety controls and policy enforcement documented and tested.

## 4) Security Gates
- TLS 1.3 enforced on control-plane endpoints.
- Token and credential secrets are never logged.
- Revocation and offboarding path tested for correctness.
- Rate-limit, lockout/backoff, and replay-protection controls are verified with negative tests.
- Auth/enrollment endpoints enforce abuse controls without bypass paths.
- Endpoint key storage fallback passes permission and encryption checks.
- Reusable-credential constraints (scope, expiry, storage policy) are enforced and test-verified.
- Concurrent one-time-key consume tests prove no double-consume behavior.
- Trust-state corruption/unavailability tests prove fail-closed behavior for trust-required operations.

## 5) Phase 2 Exit Criteria
- Normal enrollment and one-time throwaway enrollment both succeed.
- Revoked/expired credentials are rejected deterministically.
- Signed peer maps are validated by clients.
- API and data models remain protocol-agnostic.
- Replay, brute-force, and high-rate abuse test cases are blocked as designed.
- TOCTOU race tests for one-time credentials are passing in CI.

## 6) Handoff to Phase 3
- Phase 3 implements Linux data-plane connectivity using the Phase 1 backend boundary and Phase 2 identity/control artifacts.
- Any data-plane design that leaks WireGuard specifics into control APIs must be rejected.
- Use [Phase3.md](./Phase3.md) as the next execution plan once Phase 2 exit criteria are met.
