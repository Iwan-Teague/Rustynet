# Rustynet Membership Consensus and Signed State Design

## 0) Purpose and Scope
- Define a secure, practical way to approve node membership changes (add/remove/rotate/revoke) with stronger guarantees than single-control-plane trust.
- Provide a production-implementable design aligned with Rustynet constraints:
- Security-first and fail-closed.
- Rust-first codebase.
- No custom cryptography/protocol invention.
- Keep WireGuard modular and replaceable behind backend abstractions.

This document covers:
- What to build.
- How to build it.
- Threats and mitigations.
- Validation and acceptance criteria.
- Detailed execution sequencing is defined in [MembershipImplementationPlan.md](./MembershipImplementationPlan.md).

## 1) Precedence and Non-Negotiables
- [Requirements.md](./Requirements.md) is source of truth.
- [SecurityMinimumBar.md](./SecurityMinimumBar.md) is release-blocking.
- If conflict exists, stricter security interpretation wins.

Must-hold constraints:
- No private key sharing between nodes.
- No requirement for "all node private keys" to authorize a new node.
- No custom cryptographic primitives.
- Membership approval must fail closed on missing, stale, invalid, or replayed trust state.
- WireGuard details must not leak into protocol-agnostic policy/control/domain models.

## 2) Design Summary
Rustynet should use a **Quorum-Signed Membership Ledger**:
- A canonical membership state is represented by a deterministic state root.
- Every membership change references the previous root and produces a new root.
- Change proposals are valid only with threshold signatures from authorized approver keys.
- Clients and daemons verify signatures, chain continuity, freshness, and policy before applying changes.

This gives tamper-evident, ordered membership history without blockchain mining/PoW complexity.

## 3) Why This Over Blockchain Mining
Use ledger + signatures, not PoW/PoS:
- No economic consensus needed in a private VPN trust domain.
- Lower complexity and attack surface.
- Deterministic, auditable, and operationally manageable.
- Better fit for home/self-hosted and small-team commercial deployments.

## 4) Security Goals
1. Prevent unauthorized node joins/removals.
2. Detect tampering and rollback/replay of membership state.
3. Require compromise of multiple approver identities to forge changes.
4. Ensure each node independently verifies trust and fails closed on invalid state.
5. Preserve policy-default-deny even when membership changes are valid.

## 5) Trust Model
Roles:
- `OwnerApprover`: highest-trust signer, can rotate quorum set with stricter threshold.
- `GuardianApprover`: independent signer used for quorum.
- `DeviceNode`: data-plane participant, verifies and applies signed state, does not authorize by default.

Recommended default:
- Minimum `2-of-3` approver quorum for homelab/small deployments.
- `3-of-5` for commercial/multi-admin environments.

Key properties:
- Approver keys are distinct from node tunnel keys.
- Node keys identify devices; approver keys authorize governance.
- Compromise of one approver key alone must not grant control.

## 6) Data Model (Normative)
All encoded objects must use deterministic canonical serialization (for example canonical CBOR or strict canonical JSON).

### 6.1 Membership State
Fields:
- `network_id`
- `epoch` (monotonic integer)
- `nodes[]` sorted by `node_id`:
- `node_id`
- `node_pubkey`
- `owner`
- `status` (`active|revoked|quarantined`)
- `roles` (tags/policy selectors only; no WireGuard-specific fields)
- `joined_at_unix`
- `updated_at_unix`
- `approver_set[]` sorted by `approver_id`:
- `approver_id`
- `approver_pubkey`
- `role` (`owner|guardian`)
- `status` (`active|revoked`)
- `quorum_threshold`
- `created_at_unix`
- `metadata_hash` (optional integrity pin for non-authoritative metadata)

Derived:
- `state_root = HASH(canonical_membership_state)`.

### 6.2 Membership Update Record
Fields:
- `network_id`
- `update_id` (random nonce/UUID)
- `operation` (`add_node|remove_node|rotate_node_key|revoke_node|restore_node|rotate_approver|set_quorum`)
- `target`
- `prev_state_root`
- `new_state_root`
- `epoch_prev`
- `epoch_new = epoch_prev + 1`
- `created_at_unix`
- `expires_at_unix`
- `reason_code`
- `policy_context` (optional; for audit)

Signatures:
- `approver_signatures[]`:
- `approver_id`
- `signature`

Validation:
- Signature set cardinality must satisfy current threshold.
- Signers must be active in current approver set.
- Duplicate signer IDs forbidden.

### 6.3 Snapshot + Log
- `membership.snapshot` contains latest full canonical state and root.
- `membership.log` append-only sequence of update records.
- Nodes can reconstruct/verify by replaying log onto trusted snapshot.

## 7) Verification Rules (Fail-Closed)
Node/daemon must reject update unless all pass:
1. `network_id` matches local network.
2. `expires_at_unix` not exceeded; creation not future-dated beyond skew tolerance.
3. `epoch_new == epoch_prev + 1`.
4. `prev_state_root` equals local trusted root.
5. `new_state_root` recomputed exactly from canonical post-update state.
6. Quorum signatures verify and satisfy threshold over exact update payload.
7. Signers are active, authorized approvers in current trusted state.
8. Update operation is legal for current role/policy.
9. Anti-replay checks pass (`update_id` and epoch monotonicity).

On failure:
- Keep previous trusted state.
- Enter or remain restricted-safe mode for trust-required operations.
- Emit explicit audit/security event.

## 8) Operational Flows

### 8.1 Add Node
1. Enrollment request is authenticated (existing Rustynet controls).
2. Proposed node record constructed.
3. Candidate next state built deterministically.
4. Update record generated with `prev_state_root -> new_state_root`.
5. Required approvers sign update.
6. Update distributed to nodes/daemons.
7. Each daemon verifies and applies.
8. Node enters active peer assignment only after successful verification.

### 8.2 Remove/Revoke Node
1. Generate signed revoke update with quorum.
2. Nodes verify and apply.
3. Remove node from active peer maps and route permissions.
4. Drop active sessions and keys for revoked node.
5. Emit incident-grade audit event.

### 8.3 Rotate Node Key
1. Signed update links old and new node key under same `node_id`.
2. Daemons apply key replacement without identity reset.
3. Old key invalidated immediately after confirmed apply window.

### 8.4 Rotate Approver/Threshold
1. Require stricter auth policy (for example owner + quorum).
2. Apply as signed update.
3. Enforce future updates against new approver set/threshold.

## 9) Threat Model and Mitigations

### T1: Single approver key compromise
- Risk: attacker signs unauthorized add/remove.
- Mitigation:
- Threshold signatures (`M-of-N`).
- Distinct owner/guardian keys.
- Rapid approver revocation update path.

### T2: Control-plane server compromise
- Risk: attacker serves forged membership updates.
- Mitigation:
- Nodes independently verify quorum signatures and root continuity.
- Unsigned or under-signed updates rejected.
- Fail closed on trust failure.

### T3: Replay/Rollback attack
- Risk: attacker replays old valid update to restore revoked node.
- Mitigation:
- Monotonic epoch.
- `prev_state_root` chain check.
- `update_id` replay cache.
- Expiry timestamps + clock-skew limits.

### T4: Log tampering/deletion
- Risk: history manipulation.
- Mitigation:
- Append-only tamper-evident log with hash chaining.
- Periodic signed checkpoint snapshots.
- Multi-replica replication and integrity compare.

### T5: Partition/split-brain
- Risk: inconsistent membership views.
- Mitigation:
- Single monotonic epoch acceptance.
- Reject conflicting same-epoch updates.
- Recovery flow requires authoritative signed checkpoint.

### T6: Malicious insider attempts policy bypass
- Risk: valid membership change but over-broad access.
- Mitigation:
- Membership acceptance separate from ACL acceptance.
- Default-deny policy remains enforced.
- Route/exit permissions still require policy grants.

### T7: Private key exfiltration from disk
- Risk: forged signatures or node impersonation.
- Mitigation:
- OS secure store preferred.
- Encrypted-at-rest fallback + strict permissions + startup checks.
- Optional hardware-backed approver keys for commercial profile.

### T8: Time manipulation
- Risk: bypass expiry checks.
- Mitigation:
- Bounded skew policy.
- Monotonic counters and replay watermark checks.
- Alert on drift and deny trust-required apply when out-of-bounds.

## 10) Rust-First Architecture Plan

### 10.1 `crates/rustynet-control`
Add:
- `membership` module for canonical state, update generation, state-root computation.
- `approver` module for threshold verification orchestration.
- signed snapshot/log persistence.

Enforcement points:
- All membership mutations require quorum verification before publication.
- Immutable append-only update log writer.

### 10.2 `crates/rustynetd`
Add:
- membership verifier + replay/rollback guard.
- trusted state cache and watermark persistence.
- fail-closed mode transitions tied to membership-trust validation.

Enforcement points:
- No peer/route apply from untrusted membership state.
- Revoked nodes removed immediately from active dataplane intents.

### 10.3 `crates/rustynet-policy`
Add:
- membership-aware selector validation hooks.
- explicit deny-on-unknown-node behavior.

Enforcement points:
- route/exit grants only for active trusted nodes.

### 10.4 `crates/rustynet-cli`
Add commands:
- `membership status`
- `membership propose-add`
- `membership propose-remove`
- `membership sign-update`
- `membership apply-update`
- `membership verify-log`

CLI must only orchestrate signed flows; no bypass path.

## 11) WireGuard Modularity Requirements
- Membership objects must never include WireGuard backend internals.
- Membership approval influences intent (`allowed node`, `denied node`) only.
- Backend adapters consume intents through `TunnelBackend` interfaces.
- Swapping WireGuard backend must not require membership model changes.

## 12) Crypto and Library Policy
Allowed patterns:
- Ed25519 signatures for update authorization.
- SHA-256/BLAKE2 for state roots and log chaining.
- Standard Rust crates with active maintenance and audits.

Forbidden:
- Custom signature algorithms.
- Custom proof systems in production path.
- "All device private key possession" verification model.

Future optional enhancement:
- Threshold signature aggregation for signature privacy/size reduction.
- Only after baseline multi-signature path is stable and audited.

## 13) Implementation Work Plan

### Phase A: Canonical State and Root
- Define canonical serialization schema.
- Implement deterministic state-root generation.
- Add golden test vectors for canonicalization and roots.

### Phase B: Signed Update Engine
- Implement update creation and threshold signature verification.
- Enforce update legality rules and epoch/root chaining.
- Add replay cache and timestamp checks.

### Phase C: Persistence and Replication
- Append-only membership log with integrity records.
- Signed snapshots + recovery logic.
- Backup/restore with integrity verification.

### Phase D: Daemon Enforcement
- Integrate membership verification gate before peer/route apply.
- Immediate revoke/remove handling and session teardown.
- Restricted-safe mode on trust failure.

### Phase E: Operations and Recovery
- Key rotation runbooks (approver and node keys).
- Compromise response runbooks.
- Incident drill scenarios.

## 14) Test and Evidence Requirements

Unit tests:
- Canonical serialization determinism.
- Root computation determinism.
- Signature verification and threshold counting.
- Replay and rollback rejection.
- Illegal operation rejection.

Integration tests:
- Add node with valid quorum and apply across two+ daemons.
- Remove/revoke node and enforce immediate dataplane deny.
- Rotate node key while preserving node identity.
- Rotate approver set/threshold and enforce new rules.

Negative/security tests:
- Forged signature rejected.
- Under-threshold signatures rejected.
- Expired update rejected.
- Future-dated update beyond skew rejected.
- Replayed update rejected.
- Wrong `prev_state_root` rejected.
- Conflicting same-epoch update rejected.

Operational evidence:
- Tamper-evident membership audit artifacts.
- Restore-from-snapshot consistency report.
- Incident drill logs for compromised approver and compromised node.

## 15) Failure Modes and Fail-Closed Decisions
- If membership log unreadable/corrupt: deny new membership applies, retain last safe state.
- If snapshot and log diverge: deny apply, require operator recovery flow.
- If quorum verification unavailable: deny apply.
- If clock drift exceeds policy: deny trust-required updates.
- If local state root cannot persist: deny apply and alert.

## 16) Minimum Viable Deployment Profile
For first hardened rollout:
- 3 approvers (1 owner + 2 guardians), threshold 2.
- All membership changes signed by at least 2 approvers.
- 5-minute update expiry window.
- Strict replay and epoch checks.
- Mandatory daemon fail-closed on trust errors.

## 17) Open Choices (Decide Early)
1. Canonical encoding choice: canonical CBOR vs canonical JSON.
2. Snapshot interval policy (for example every 100 updates).
3. Quorum defaults for homelab vs commercial tiers.
4. Whether approver keys are software-only or hardware-backed by tier.

## 18) Definition of Done
This design is complete for implementation when:
- All verification rules in this document are enforced in code.
- Membership updates cannot be applied without threshold signatures.
- Replay/rollback attacks are rejected by tests.
- Revoked nodes are blocked from dataplane and policy paths.
- WireGuard remains isolated behind backend abstractions.
- SecurityMinimumBar critical controls remain green.
