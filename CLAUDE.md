# Rustynet Agent Operating Contract

Use this file as mandatory execution guidance for AI implementation agents working in this repository.

`AGENTS.md` and `CLAUDE.md` are intentionally mirrored. Keep them aligned.

## 1) Mission
- Build Rustynet to production-grade quality.
- Keep security as the first priority.
- Keep architecture Rust-first and transport-backend modular.
- Prefer code, tests, gates, and evidence over design-only churn.

## 2) Read Order and Source of Truth
When documents disagree, apply this precedence:
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. The active scope document for the task
4. Supporting design docs
5. `README.md` and operational runbooks

Read in this order before touching code:
1. `AGENTS.md`
2. `CLAUDE.md`
3. `README.md`
4. `documents/README.md`
5. `documents/Requirements.md`
6. `documents/SecurityMinimumBar.md`
7. The active scope document
8. Relevant runbooks under `documents/operations/`

Current primary execution ledgers:
- `documents/operations/active/MasterWorkPlan_2026-03-22.md` for repo-wide remaining work
- `documents/operations/active/PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md` for traversal, relay, and live-lab readiness

Current lab-reference assets:
- `documents/operations/active/UTMVirtualMachineInventory_2026-03-31.md`
- `documents/operations/active/vm_lab_inventory.json`

Rules:
- If ambiguity exists, choose the strictest secure practical default and document that choice.
- Never weaken a higher-precedence requirement.
- Standalone prompt documents are not part of the repository source of truth. Use the active ledgers, runbooks, and index files instead.

## 3) Non-Negotiable Engineering Constraints
- Rust-first codebase. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography and no custom VPN protocol invention in production paths.
- WireGuard must remain an adapter behind stable backend abstractions and be easy to replace.
- No WireGuard-specific leakage into protocol-agnostic control, policy, or domain crates.
- Default-deny policy is mandatory across ACL, routes, and trust-sensitive flows.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.
- Do not defer in-scope requirements behind TODO/FIXME/placeholders in completed deliverables.
- Enforce one hardened execution path per security-sensitive workflow. No runtime fallback, downgrade, or legacy branch in production paths.

## 4) Security Baseline Requirements
- Enforce signed control/trust state validation before mutation.
- Enforce anti-replay and rollback protection where state freshness matters.
- Enforce strict key custody behavior:
  - use OS-secure key storage when available
  - otherwise use encrypted-at-rest fallback with strict permissions and startup permission checks
- Never log secrets or private key material.
- Preserve privileged-boundary hardening: argv-only exec for helpers, strict input validation, no shell construction with untrusted values.
- Preserve tunnel and DNS fail-closed behavior in protected modes.
- During shell-to-Rust migration, remove superseded shell implementations from active paths. Wrappers may only dispatch to the Rust command and must fail closed on error.

Each implemented security control must include:
1. an enforcement point in code
2. a verification method such as a unit test, integration test, negative test, or gate check

## 5) Required Working Style
- Before coding, read the relevant docs in precedence order.
- Build a concrete checklist from the scope requirements.
- Implement in small, verifiable increments.
- Run the closest relevant tests and gates during implementation, not only at the end.
- Keep the owning ledger or work document current. Do not maintain a hidden private checklist that diverges from repository state.
- Keep documentation synchronized with implementation changes.
- Remove dead links, stale index entries, and prompt-only guidance when you find them.

## 6) Documentation Rules
- `documents/README.md` is the top-level map of the docs tree.
- `documents/operations/README.md` is the operations/runbook map.
- `documents/operations/active/README.md` is the active-work map.
- If you add, remove, rename, archive, or materially repurpose docs, update the relevant index file in the same change.
- If a document becomes historical rather than active, move or classify it honestly.
- Do not reintroduce standalone prompt documents; keep execution guidance in the active ledgers themselves.

## 7) Validation and CI Gates
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
- any active-phase gate script required by the scope document

If any gate fails:
1. stop phase progression
2. fix the root cause, not the symptom
3. re-run the impacted gates
4. record failure, fix, and proof in the relevant progress document when scope requires it

## 8) Architecture Boundary Rules
- Keep domain models and policy evaluation transport-agnostic.
- Keep backend-specific behavior in backend adapter crates.
- Expose capabilities via backend interfaces rather than leaking backend types.
- Maintain deterministic, testable state transitions for trust-sensitive systems.

## 9) Definition of Done
Work is complete only when all are true:
- in-scope requirements are implemented end-to-end
- security minimum bar controls are satisfied for that scope
- all mandatory gates pass, or the remaining blocker is explicitly documented and outside the claimed completion
- required artifacts exist and validate
- no unresolved in-scope blockers remain
- no TODO/FIXME/placeholders remain in completed deliverables
