# Rustynet Membership Implementation Plan

## 0) Objective
Implement quorum-signed membership governance end-to-end so node membership changes (add/remove/revoke/rotate) are:
- authorized by threshold signatures,
- tamper/replay/rollback resistant,
- enforced fail-closed by daemons before dataplane changes,
- fully aligned with Rust-first and WireGuard-modular architecture constraints.

This plan operationalizes [MembershipConsensus.md](./MembershipConsensus.md) into concrete build steps and release gates.

## 1) Precedence and Guardrails
- [Requirements.md](./Requirements.md) is normative source of truth.
- [SecurityMinimumBar.md](./SecurityMinimumBar.md) is release-blocking.
- [MembershipConsensus.md](./MembershipConsensus.md) defines required architecture and security behavior.

Non-negotiable constraints:
- Rust-first implementation.
- No custom cryptography/protocol invention.
- Default-deny and fail-closed in all trust-sensitive paths.
- No WireGuard-specific leakage into protocol-agnostic control/policy/domain boundaries.

## 2) Scope
### 2.1 In Scope
- Canonical membership state model and state-root computation.
- Threshold-signed membership update records.
- Membership snapshot + append-only log + integrity validation.
- Daemon-side membership verification gate before peer/route apply.
- Revoke/remove immediate enforcement.
- CLI/operator tooling for propose/sign/verify/apply flows.
- Test and CI evidence for security properties.

### 2.2 Out of Scope
- New transport protocol design.
- Replacing WireGuard backend.
- Monthly/yearly governance UX polish.
- Anonymous threshold-signature privacy schemes for v1.

## 3) Phase Sequence

## Phase M0: Foundations and Schema Lock
Goal:
- lock deterministic schema and invariants before coding broad features.

Tasks:
1. Define canonical membership schema types in `crates/rustynet-control`.
2. Define canonical membership update record schema.
3. Choose canonical encoding for v1 (`canonical JSON` or `canonical CBOR`) and freeze it.
4. Document exact hashing input format and versioning field.
5. Add schema version constants and migration rejection behavior for unknown versions.

Acceptance:
- golden vectors for canonical encoding and root hash pass.
- unknown schema versions fail closed.

## Phase M1: State Root and Update Engine
Goal:
- deterministic state transition + root chaining engine.

Tasks:
1. Implement pure deterministic reducer:
- `state + update -> new_state` or explicit error.
2. Validate operation legality:
- add existing node forbidden,
- remove unknown node forbidden,
- epoch monotonicity required.
3. Compute `prev_state_root` and `new_state_root` deterministically.
4. Add anti-replay fields (`update_id`, `expires_at_unix`) and validation.
5. Add rollback prevention (`prev_state_root` must match trusted local root).

Acceptance:
- reducer unit tests cover valid and invalid transitions.
- root mismatch, stale, and duplicate update-id are rejected.

## Phase M2: Quorum Signature Verification
Goal:
- threshold authorization for all membership changes.

Tasks:
1. Implement approver-set model and status (`active|revoked`).
2. Implement signature verification for update payload.
3. Implement threshold counting:
- unique signer enforcement,
- active-signer requirement,
- threshold check from current trusted state.
4. Implement stricter policy for approver-set or quorum-threshold changes.
5. Add replay-safe signature validation path bound to exact canonical payload bytes.

Acceptance:
- under-threshold signatures rejected.
- duplicate signer IDs rejected.
- signer not active rejected.
- modified payload after signing rejected.

## Phase M3: Persistence and Integrity
Goal:
- durable tamper-evident storage for membership trust state.

Tasks:
1. Implement `membership.snapshot` (latest full canonical state).
2. Implement append-only `membership.log` with integrity metadata.
3. Add atomic write strategy and strict permission checks.
4. Add startup integrity verification:
- snapshot decode,
- log replay,
- final root equality.
5. Add recovery path:
- keep last-known-safe state,
- deny trust-required apply if integrity fails.

Acceptance:
- tampered snapshot/log detected.
- daemon enters restricted-safe mode on integrity failure.
- valid restore/replay reaches expected state root.

## Phase M4: Daemon Enforcement Gate (`rustynetd`)
Goal:
- membership trust required before peer/route/dataplane mutation.

Tasks:
1. Add membership verification module in `rustynetd`.
2. Gate all peer/route intents on trusted membership state.
3. Enforce revoke/remove immediate actions:
- drop peer,
- remove routes,
- deny future re-add without valid update.
4. Ensure membership failures trigger fail-closed transitions.
5. Keep local watermark/epoch to reject replay and rollback.

Acceptance:
- no untrusted membership update can mutate dataplane.
- revoked node cannot reconnect without valid signed re-add.
- fail-closed behavior demonstrated by tests.

## Phase M5: Policy Coupling and Default-Deny
Goal:
- preserve strict policy semantics while adopting membership governance.

Tasks:
1. In `rustynet-policy`, require membership-active status for node selectors.
2. Deny unknown or revoked nodes by default regardless of legacy ACL allow.
3. Ensure shared-exit/shared-router protocol filters still enforce exactly as today.
4. Add policy + membership integration tests across mesh/exit contexts.

Acceptance:
- policy allow cannot bypass revoked/unknown membership.
- protocol filters remain intact under membership updates.

## Phase M6: CLI and Operator Workflow
Goal:
- safe operational path for membership governance.

Tasks:
1. Add CLI commands:
- `membership status`,
- `membership propose-*`,
- `membership sign-update`,
- `membership verify-update`,
- `membership apply-update`,
- `membership verify-log`.
2. Add clear operator error messages for fail-closed reasons.
3. Add dry-run verification mode to inspect updates before apply.
4. Add explicit command-level input validation and redaction.

Acceptance:
- operators can complete add/revoke/rotate flows without direct file editing.
- malformed input is rejected with no side effects.

## Phase M7: Hardening, Runbooks, and Incident Drills
Goal:
- production-readiness for security response.

Tasks:
1. Write runbooks:
- approver key compromise,
- node key compromise,
- emergency revocation,
- quorum reconstitution.
2. Add incident drill scripts and evidence capture.
3. Add patch-SLA operational tracking hooks for membership-critical vulnerabilities.
4. Add backup/restore integrity drill for snapshot/log.

Acceptance:
- drills executed and recorded.
- emergency revoke tested end-to-end.
- recovery from compromised approver documented and verified.

## Phase M8: CI Gates and Release Blockers
Goal:
- enforce non-regression and security baseline in automation.

Tasks:
1. Add membership-focused CI script:
- `scripts/ci/membership_gates.sh`.
2. Include mandatory checks:
- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo check --workspace --all-targets --all-features`
- `cargo test --workspace --all-targets --all-features`
- boundary leak checks (no WireGuard leakage in control/policy/domain crates)
- integrity/negative membership tests
3. Emit artifacts under `artifacts/membership/`:
- `membership_conformance_report.json`
- `membership_negative_tests_report.json`
- `membership_recovery_report.json`
- `membership_audit_integrity.log`

Acceptance:
- all membership gates pass.
- artifacts present and marked pass.

## 4) Crate-by-Crate Task Map

`crates/rustynet-control`
- canonical membership types and reducer.
- quorum verifier and approver-set controls.
- signed update generation and validation.
- snapshot/log write and integrity verification.

`crates/rustynetd`
- membership trust verifier and watermark state.
- pre-dataplane trust gating.
- revoke/remove immediate enforcement.
- fail-closed transition on trust failure.

`crates/rustynet-policy`
- membership-aware selector validation.
- explicit deny on unknown/revoked nodes.
- integration coverage with protocol-specific ACL behavior.

`crates/rustynet-cli`
- operator workflows for propose/sign/verify/apply.
- safe defaults, validation, and redacted output.

`scripts/ci`
- membership-specific gate script + artifact checks.

`documents/operations`
- compromise and recovery runbooks.

## 5) Security Controls Mapping
Control 1 (proven crypto only):
- Use standard Ed25519 signatures and approved hash algorithms only.
- Enforced by fixed algorithm allowlist in membership modules.
- Verified by unit tests and clippy lint policy.

Control 2 (signed control data):
- Membership updates require valid threshold signatures over canonical payload.
- Enforced at daemon apply gate.
- Verified by tamper/under-threshold tests.

Control 4 (trusted state fail-closed):
- Snapshot/log integrity mismatch or missing trust state causes restricted-safe mode.
- Enforced in daemon bootstrap and reconcile.
- Verified by corruption/replay tests.

Control 5 (default deny):
- Unknown/revoked nodes denied regardless of permissive ACL entries.
- Enforced in policy+membership integration path.
- Verified by integration tests.

Control 8 (tamper-evident audit):
- Append-only membership log with integrity checks and forensic export.
- Verified by corruption detection tests.

## 6) Threat-Driven Test Matrix
1. Forged signature on valid-looking update.
Expected: reject, no state mutation.
2. Under-threshold signer set.
Expected: reject, alert/audit event.
3. Replayed old valid update.
Expected: reject due to epoch/root/update-id/watermark checks.
4. Rollback attempt to older snapshot.
Expected: integrity mismatch and fail-closed.
5. Conflicting same-epoch updates.
Expected: one accepted by chain continuity, others rejected.
6. Compromised node tries self-readd without quorum.
Expected: reject.
7. Revoked node attempts dataplane reconnect.
Expected: deny and remove runtime intents.
8. Time skew beyond policy.
Expected: deny trust-required apply.

## 7) State and Failure Policy
- Last-known-safe state is authoritative fallback.
- Any ambiguity in trust path results in deny/no apply.
- Membership apply is transactional:
- success commits new root/epoch/watermark.
- failure retains previous root and emits audit/security event.

## 8) Performance and Reliability Targets
- Membership verification must not regress existing route/policy apply SLOs:
- route/policy apply <= 2s p95 target.
- reconnect <= 5s target.
- idle resource targets unchanged from SecurityMinimumBar.

Reliability requirements:
- restart-safe state reload.
- deterministic behavior under concurrent update delivery.

## 9) Deliverables
1. Membership reducer + signature verifier implementation.
2. Snapshot/log persistence with integrity verification.
3. Daemon membership gate integrated into dataplane apply flow.
4. CLI membership workflows.
5. Membership CI gates and artifacts.
6. Operations runbooks and incident drill evidence.

## 10) Definition of Done
This implementation plan is complete only when:
- all phases M0-M8 are implemented,
- all mandatory tests and gates pass,
- no unresolved TODO/FIXME placeholders remain in membership scope,
- fail-closed behavior is verified for all trust-failure scenarios,
- WireGuard remains adapter-only and easily swappable,
- security owner and engineering owner sign-off is recorded.
