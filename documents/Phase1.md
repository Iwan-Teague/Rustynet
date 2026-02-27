# Rustynet Phase 1 Plan (Architecture and Security Foundations)

## 0) Document Relationship and Scope
- This plan implements the first execution slice of [Requirements.md](./Requirements.md).
- Phase 1 is intentionally narrow: it builds architecture and security bones only.
- Phase 1 outputs are prerequisites for [Phase2.md](./Phase2.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 1 Objective
Establish a secure, Rust-first architecture baseline with strict protocol modularity so future phases can deliver features without rework.

## 2) Phase 1 Scope
1. Repository and crate boundaries:
- Create Rust workspace and core crates (`rustynet-control`, `rustynetd`, `rustynet-cli`, `rustynet-policy`, `rustynet-crypto`, `rustynet-relay`).
- Define crate ownership and boundaries to avoid coupling.

2. Transport abstraction hard requirement:
- Create protocol-agnostic backend API crate (`rustynet-backend-api`).
- Define `TunnelBackend` interface and capability model.
- Enforce rule: no WireGuard-specific types in control-plane API, policy schema, or domain models.

3. Security baseline setup:
- Define key hierarchy (node identity, session, control-plane signing).
- Define token model and revocation paths.
- Define threat model v1 and trust boundaries.
- Define authentication attack-surface controls (rate limits, lockout/backoff, replay/nonce strategy).
- Define endpoint key-custody fallback standard when OS key store is unavailable.

4. Cryptography and protocol assurance baseline:
- Define explicit cryptographic allowlist and weak-algorithm denylist policy.
- Define formal/properties-based protocol assurance plan for handshake and key lifecycle invariants.

5. Engineering quality baseline:
- CI pipeline: `cargo fmt`, `cargo clippy`, `cargo test`, dependency checks.
- Basic integration-test harness skeleton for later network tests.
- Performance benchmark harness skeleton and baseline budget definitions.

## 3) Deliverables
- Rust workspace and crate skeleton committed.
- Backend abstraction interface and capability flags defined.
- Initial architecture and trust-boundary documentation.
- CI gates active for lint/test/security hygiene.
- Cryptographic policy baseline (allowlist/denylist + deprecation rules) approved.
- Protocol assurance test strategy approved.

## 4) Security Gates
- No custom crypto design introduced.
- TLS 1.3 (`rustls`) and key-management standards documented for implementation phases.
- Secrets-handling policy established (no secret/token logging).
- Threat model explicitly covers external API abuse, credential stuffing, replay, and admin-surface threats.
- Weak/legacy algorithm denylist and deprecation approach are explicitly documented.

## 5) Phase 1 Exit Criteria
- All core crates compile and test harness runs.
- Backend interface exists and WireGuard is not yet coupled into core domain models.
- Security baseline artifacts (threat model v1 + key model) are approved.
- Performance and attack-surface baseline standards are documented and accepted.

## 6) Handoff to Phase 2
- Phase 2 may implement identity/enrollment features only through the established crate and backend boundaries.
- Any requirement discovered during implementation must be reflected in [Requirements.md](./Requirements.md) before proceeding.
- Use [Phase2.md](./Phase2.md) as the next execution plan once Phase 1 exit criteria are met.
