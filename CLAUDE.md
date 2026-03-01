# Rustynet Agent Operating Contract

Use this file as mandatory execution guidance for AI implementation agents working in this repository.

## 1) Mission
- Build Rustynet features to production-grade quality.
- Keep security as first priority.
- Keep architecture Rust-first and transport-backend modular.

## 2) Source-of-Truth and Precedence
When documents disagree, apply this precedence:
1. `documents/Requirements.md` (normative product requirements)
2. `documents/SecurityMinimumBar.md` (release-blocking controls)
3. Scope document for the active task (for example `documents/Phase*.md`, `documents/phase10.md`, `documents/MembershipImplementationPlan.md`)
4. Design docs (for example `documents/MembershipConsensus.md`)
5. README and operational docs

Rules:
- If ambiguity exists, choose the strictest secure practical default and document that choice.
- Never weaken a higher-precedence requirement.

## 3) Non-Negotiable Engineering Constraints
- Rust-first codebase. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography and no custom VPN protocol invention in production paths.
- WireGuard must remain an adapter behind stable backend abstractions and be easy to replace.
- No WireGuard-specific leakage into protocol-agnostic control/policy/domain crates.
- Default-deny policy is mandatory across ACL, routes, and trust-sensitive flows.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.
- Do not defer in-scope requirements behind TODO/FIXME/placeholders in completed deliverables.

## 4) Security Baseline Requirements
- Enforce signed control/trust state validation before mutation.
- Enforce anti-replay and rollback protection (nonce/update-id/epoch/watermark/root checks as applicable).
- Enforce strict key custody behavior:
  - use OS-secure key storage when available,
  - otherwise encrypted-at-rest fallback with strict permissions and startup permission checks.
- Never log secrets or private key material.
- Preserve privileged-boundary hardening: argv-only exec for helpers, strict input validation, no shell construction with untrusted values.
- Preserve tunnel/DNS fail-closed behavior in protected modes.

Each security control implemented must include:
1. enforcement point in code, and
2. verification method (unit/integration/negative test or gate check).

## 5) Required Working Style
- Before coding, read relevant docs in precedence order.
- Build a concrete checklist from scope requirements.
- Implement in small, verifiable increments.
- Run gates repeatedly during implementation, not only at the end.
- Record what changed and how it was verified in progress/report docs when requested by scope.
- Keep documentation synchronized with implementation changes.

## 6) Validation and CI Gates
Run these as mandatory quality gates for substantial work:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- `cargo audit --deny warnings`
- `cargo deny check bans licenses sources advisories`

Run scope-specific scripts when present:
- `./scripts/ci/phase9_gates.sh`
- `./scripts/ci/phase10_gates.sh`
- `./scripts/ci/membership_gates.sh`
- any active-phase gate script required by the scope document.

If any gate fails:
1. stop phase progression,
2. fix root cause (not superficial bypass),
3. re-run impacted gates,
4. record failure/fix/proof in the relevant progress log.

## 7) Architecture Boundary Rules
- Keep domain models and policy evaluation transport-agnostic.
- Keep backend-specific behavior in backend adapter crates.
- Expose capabilities via backend interfaces rather than leaking backend types.
- Maintain deterministic, testable state transitions for trust-sensitive systems.

## 8) Documentation and Evidence Rules
- When scope requires progress tracking, maintain the designated progress document fully.
- Keep checklist items evidence-backed before marking complete.
- Generate required artifacts exactly at specified paths.
- Final completion reports must include:
  - deliverable summary,
  - requirement/security compliance mapping,
  - gate/test results,
  - explicit statement that no in-scope items were deferred.

## 9) Definition of Done (Repository Standard)
Work is complete only when all are true:
- in-scope requirements implemented end-to-end,
- security minimum bar controls satisfied for that scope,
- all mandatory gates pass,
- required artifacts exist and validate,
- no unresolved blockers,
- no TODO/FIXME/placeholders in completed scope deliverables.
