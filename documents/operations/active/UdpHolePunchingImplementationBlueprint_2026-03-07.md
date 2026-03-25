# Rustynet UDP Hole Punching + Relay Security Implementation Blueprint (2026-03-07)

## AI Implementation Prompt

```text
You are the implementation agent for the remaining work in this document.
Repository root: /Users/iwanteague/Desktop/Rustynet

Mission:
Complete the remaining in-scope work in this file in one uninterrupted execution if feasible. Security is the top priority. Do not stop at planning if you can still write, test, and verify code safely.

Mandatory reading order:
1. /Users/iwanteague/Desktop/Rustynet/AGENTS.md
2. /Users/iwanteague/Desktop/Rustynet/CLAUDE.md
3. /Users/iwanteague/Desktop/Rustynet/README.md
4. /Users/iwanteague/Desktop/Rustynet/documents/Requirements.md
5. /Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md
6. This document
7. Directly linked scope/design docs and the code you will touch

Non-negotiables:
- one hardened execution path for each security-sensitive workflow
- fail closed on missing, stale, invalid, replayed, or unauthorized state
- no insecure compatibility paths, no legacy fallback branches, and no weakening of tests to make results pass
- no TODO/FIXME/placeholders for in-scope deliverables
- do not mark work complete until code, tests, and evidence exist

Execution workflow:
1. Read this document fully and convert every unchecked, open, pending, partial, or blocked item into a concrete checklist.
2. Execute the remaining work in the ordered sequence listed below.
3. Implement in small, verifiable increments, but continue until the remaining in-scope slice is complete or a real external blocker stops you.
4. After every material code change:
   - run targeted unit and integration tests for touched crates and modules
   - run smoke tests, dry runs, or CLI/service validators for the exact workflow you changed
   - rerun the most relevant gate before moving on
5. After every completed item:
   - update this document immediately instead of maintaining a separate private checklist
   - mark checkboxes and status blocks complete only after verification
   - append concise evidence: files changed, tests run, artifacts produced, residual risk, and blocker state if any
   - keep any existing session log, evidence table, acceptance checklist, or status summary current
6. Before claiming completion:
   - run repository-standard gates when the scope is substantial:
     cargo fmt --all -- --check
     cargo clippy --workspace --all-targets --all-features -- -D warnings
     cargo check --workspace --all-targets --all-features
     cargo test --workspace --all-targets --all-features
     cargo audit --deny warnings
     cargo deny check bans licenses sources advisories
   - run the scope-specific validations listed below
   - if live or lab validation is available, run it; if it is not available, do not fake success and record the blocker precisely
7. If a test or gate fails, fix the root cause. Never weaken the check, bypass the security control, or mark a synthetic path as good enough.

Document-specific execution order:
1. Close the blueprint gaps in the order of security dependency: trust artifacts and authorization chain first, then runtime path-state enforcement, then backend API surfaces, then relay transport, then phase10 gate coverage.
2. Preserve the non-negotiable invariants in Section 2 while implementing every touched surface.
3. For new traversal or relay artifacts, centralize signing, verification, freshness, and replay checks before wiring them into runtime state transitions.
4. Extend phase10 and traversal security gates as part of the implementation, not afterward.
5. Update the current-state and gap tables when code reality changes so the blueprint stays code-accurate.

Scope-specific validation for this document:
- Targeted rustynet-control, rustynetd, and rustynet-relay tests for artifact validation, runtime state transitions, and relay transport.
- Parser adversarial tests for malformed, replayed, stale, oversized, and wrong-signer traversal or relay inputs.
- bash ./scripts/ci/phase10_hp2_gates.sh
- ./scripts/ci/phase10_gates.sh

Definition of done for this document:
The gap table and trust-chain requirements in this blueprint match the implemented code, touched invariants are enforced in code and tests, and traversal or relay work does not rely on undocumented weak paths.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- This blueprint remains active because the gap table is not yet fully closed.
- **Updated 2026-03-25**: Relay crate row updated. Production relay transport now implemented with constant-time auth, replay protection, and 31 tests.
- **Updated 2026-03-25**: HP-4 relay client module added to daemon (`rustynetd/src/relay_client.rs`) with 8 tests.
- Remaining open areas: signed traversal-hint bundle, backend probe surfaces, HP-4 wiring into daemon reconcile loop, traversal/phase10 gate coverage.

`Do first`
- Wire `RelayClient` into daemon reconcile loop to complete HP-4.
- Add relay endpoint refresh on token expiry.
- Keep the gap table current as you go so the file remains code-accurate.

`Completion proof`
- Every touched row in the gap table is either updated to current code reality or remains open with a precise reason.
- Relay crate row updated 2026-03-25 with implementation evidence.
- HP-4 relay client module added 2026-03-25 with session establishment and wire protocol.
- The corresponding tests and gates named by the touched sections pass.

`Do not do`
- Do not let the blueprint drift into stale architecture fiction after code changes.
- Do not wire traversal or relay state into runtime before signatures, freshness, replay, and policy checks are centralized.

`Clarity note`
- Use this file to keep the architecture and gate model honest while implementing lower-level HP2 or HP3 details.

## 1) Purpose
This document is the implementation blueprint for making Rustynet internet-reachable with direct UDP hole punching plus encrypted relay fallback, while preserving strict security invariants.

This is not a side note. It defines the concrete code and gate work needed so traversal is part of the main architecture.

Primary references in this repository:
- `documents/Requirements.md` (normative requirements)
- `documents/SecurityMinimumBar.md` (release-blocking controls)
- `documents/phase10.md` (dataplane architecture and gates)
- `documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md` (high-level plan)

## 2) Non-Negotiable Security Invariants
1. One hardened route only for traversal-sensitive decisions.
- No legacy/parallel/fallback control paths that can bypass signature or freshness checks.

2. Fail closed.
- If signed traversal state is missing, stale, invalid, replayed, or policy-denied, endpoint mutation is denied and protected mode remains blocked.

3. Signed control data only.
- Peer endpoint updates are accepted only from signed traversal artifacts validated against pinned verifier keys.

4. Replay resistance.
- Nonce + freshness window + watermark/monotonic checks are required for traversal artifacts and relay session credentials.

5. Default deny.
- Traversal only enables paths that are already authorized by membership + assignment + policy allow edges.

6. Ciphertext-only relay trust model.
- Relay can forward encrypted payloads but cannot decrypt them.

7. No custom cryptography.
- Reuse existing Ed25519 signing/verification patterns already used for trust/assignment/membership artifacts.

## 3) Current Baseline and Gaps (Code-Accurate)

| Area | Current state | Gap to close |
| --- | --- | --- |
| Runtime path state | `Phase10Controller` stores authoritative per-peer direct/relay endpoints, refreshes peer endpoint bypass routing on path changes, executes a bounded one-sided direct probe loop, and auto-tunnel runtime consumes the controller decision during traversal sync (`crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/daemon.rs`) | Still missing full simultaneous-open WAN traversal and health-driven automatic failover/failback |
| CLI netcheck | Returns structured runtime diagnostics (`path_mode`, `path_reason`, `traversal_authority`, artifact freshness/candidate/error fields, and probe result/reason/attempt count) (`crates/rustynetd/src/daemon.rs`) | Still lacks full multi-peer HP-2 telemetry and relay-transport health evidence |
| Backend API | `TunnelBackend` now supports controlled endpoint rotation plus per-peer handshake-recency evidence via `update_peer_endpoint`, `current_peer_endpoint`, and `peer_latest_handshake_unix` (`crates/rustynet-backend-api/src/lib.rs`) | Still needs richer endpoint-set/probe surfaces for full HP-2/HP-3 |
| WireGuard backend | Can configure peers, rotate endpoints, and read bounded handshake-recency evidence via strict `wg` argv calls (`crates/rustynet-backend-wireguard/src/lib.rs`) | Still needs transport-level probe traffic generation beyond endpoint rotation + handshake observation |
| Control signing model | Signed peer-map, signed assignment bundle, and **RelaySessionToken** (ed25519 signed with ct_eq) are implemented (`crates/rustynet-control/src/lib.rs`). **11 RelaySessionToken tests** cover signing, verification, expiry, ct_eq, and debug redaction. | **UPDATED 2026-03-25**: relay-session token complete. Still needs signed traversal-hint bundle. |
| Relay crate | **UPDATED 2026-03-25**: Production relay transport implemented with authenticated sessions (`RelayTransport`), constant-time auth, replay protection, rate limiting, per-node session caps, idle/half-open cleanup, and ciphertext-only forwarding (31 tests pass) (`crates/rustynet-relay/src/transport.rs`) | **HP-4 relay client module added** (`crates/rustynetd/src/relay_client.rs`, 8 tests). Remaining: wire into daemon reconcile loop. |
| Phase10 gates | Current artifacts: netns/leak/perf/failover/state-audit (`scripts/ci/check_phase10_readiness.sh`) | Must add traversal security artifact checks (tamper/replay/failback integrity) |

## 4) Required Trust and Key Artifacts
Traversal activation must require all of the following to validate successfully.

| Artifact | Producer | Consumer | Proposed path | Required mode | Notes |
| --- | --- | --- | --- | --- | --- |
| Membership snapshot/log + watermark | Membership workflow | `rustynetd` | existing `membership.*` paths | existing strict modes | Must show nodes are active and not revoked |
| Trust evidence + watermark | trust refresh path | `rustynetd` | existing `rustynetd.trust*` paths | existing strict modes | TLS/signing freshness gate |
| Assignment bundle + watermark | assignment issuer/refresh | `rustynetd` | existing assignment paths | existing strict modes | Authorizes peer graph/allowed edges |
| Traversal signing secret (new) | control ops | control signer only | `/etc/rustynet/traversal.signing.secret` | `0600 root:root` | Encrypted-at-rest, passphrase credential-only |
| Traversal verifier key (new) | control ops | `rustynetd` verify | `/etc/rustynet/traversal.pub` | `0644 root:root` | Pinned verifier for traversal bundles |
| Signed traversal bundle (new) | control plane | `rustynetd` | `/var/lib/rustynet/rustynetd.traversal` | `0640 root:<daemon-group>` | Short TTL, nonce, digest-bound watermark |
| Traversal watermark (new) | `rustynetd` apply path | `rustynetd` | `/var/lib/rustynet/rustynetd.traversal.watermark` | `0640 root:<daemon-group>` | Prevent replay/rollback |
| Relay session token (new) | control plane | relay + node | runtime memory or `/run/rustynet/*` only | runtime-only | Never persist as plaintext at rest |

Key derivation recommendation:
- Extend `ControlPlaneCore` key derivation with a dedicated label (example: `rustynet-control-traversal-signing-v1`) instead of reusing assignment signatures directly.
- Keep separate verifier distribution (`traversal.pub`) for operational compartmentalization.

## 5) Access Authorization Chain (What Must Be Valid Before Any Hole-Punch Path Is Used)
A node must not attempt or accept traversal endpoint changes until all checks pass:
1. Local trust evidence valid (TLS/signature/freshness gate passes).
2. Membership state valid and peer is active.
3. Signed assignment bundle valid and non-stale.
4. Policy graph allows source->destination pair.
5. Signed traversal bundle validates with pinned traversal verifier key.
6. Traversal bundle `generated_at`/`expires_at` within allowed skew.
7. Traversal nonce/watermark is newer than last accepted for `(source_node, target_node)`.
8. Candidate set passes strict schema validation (count, families, ports, type allowlist).
9. Runtime path controller approves transition according to deterministic state machine.
10. Kill-switch/leak-prevention invariants remain asserted before and after transition.

If any item fails: reject mutation and keep/enter fail-closed behavior.

## 6) Protocol Objects (Signed Data to Add)

## 6.1 Signed Traversal Hint Bundle (new)
Canonical payload fields (ordered, deterministic serialization):
- `version=1`
- `network_id`
- `source_node_id`
- `target_node_id`
- `generated_at_unix`
- `expires_at_unix`
- `nonce`
- `path_policy` (`direct_preferred_relay_allowed` only in v1)
- `candidate_count`
- `candidate.N.type` (`host`, `srflx`, `relay`)
- `candidate.N.addr`
- `candidate.N.port`
- `candidate.N.family`
- `candidate.N.relay_id` (required when type=`relay`)
- `candidate.N.priority`

Envelope fields:
- `payload`
- `signature_hex`

Validation rules:
- `expires_at_unix > generated_at_unix`
- Max TTL v1: `120s`
- Max candidates v1: `8`
- Reject private/special-address violations based on candidate type policy.
- Reject duplicate candidate tuples.

## 6.2 Signed Relay Session Token (new)
Canonical payload fields:
- `version=1`
- `network_id`
- `relay_id`
- `source_node_id`
- `target_node_id`
- `issued_at_unix`
- `expires_at_unix`
- `nonce`
- `scope=forward_ciphertext_only`

Relay must validate signature and expiry before opening forwarding session.

## 6.3 Watermark Rules
- Add traversal watermark parser aligned with trust/assignment watermark rigor.
- Digest-bind watermark to accepted payload.
- Enforce strictly increasing `(generated_at_unix, nonce)` semantics per source-target pair.

## 7) Concrete Code Changes by Component

## 7.1 `crates/rustynet-backend-api/src/lib.rs`
Add traversal-safe backend contract surfaces:
- New types:
  - `TraversalCandidate`
  - `PeerEndpointSet`
  - `PathSelectionReason`
- Trait additions:
  - `fn update_peer_endpoint(&mut self, node_id: &NodeId, endpoint: SocketEndpoint) -> Result<(), BackendError>;`
  - `fn current_peer_endpoint(&self, node_id: &NodeId) -> Result<Option<SocketEndpoint>, BackendError>;`

Security contract:
- Backend methods are not authority. Callers must prove signed traversal authorization before invoking.

## 7.2 `crates/rustynet-backend-wireguard/src/lib.rs`
Implement hardened endpoint rotation:
- `update_peer_endpoint` uses strict `wg set ... endpoint ...` with validated address/port.
- Keep endpoint bypass route reconciliation correct during endpoint churn.
- Do not allow endpoint mutation when backend not started.
- Add tests for repeated update, malformed endpoint rejection, and rollback behavior.

## 7.3 `crates/rustynet-control/src/lib.rs`
Add traversal artifact issuance and verification:
- New structs:
  - `TraversalHintBundleRequest`
  - `SignedTraversalHintBundle`
  - `RelaySessionTokenRequest`
  - `SignedRelaySessionToken`
- New key derivation label and signer/verifier material for traversal domain.
- Methods:
  - `signed_traversal_hint_bundle(...)`
  - `verify_signed_traversal_hint_bundle(...)`
  - `signed_relay_session_token(...)`
  - `verify_signed_relay_session_token(...)`

Checks to enforce at signing time:
- source/target node exist and are active.
- policy and assignment edge allow source->target.
- generated/expires windows and nonce policy valid.

## 7.4 `crates/rustynet-control/src/persistence.rs` + migrations
Create new migration (`0002_traversal.sql`) with at least:
- `traversal_hints` table:
  - key: `(source_node_id, target_node_id)`
  - stores latest signed bundle metadata and expiry.
- `relay_tokens` table:
  - key: token nonce or digest
  - expiry index.
- `traversal_watermarks` table:
  - key: `(source_node_id, target_node_id)`
  - stores last accepted generated_at + nonce + payload digest.

All writes must be atomic; replay checks must happen in same transaction boundary.

## 7.5 `crates/rustynetd/src/daemon.rs`
Add traversal artifact bootstrap and runtime enforcement:
- Config fields (similar pattern to trust/assignment):
  - `traversal_bundle_path`
  - `traversal_verifier_key_path`
  - `traversal_watermark_path`
- New bootstrap parser/validator for traversal bundle.
- Refuse startup in protected mode if traversal is required but verifier/bundle is invalid.
- Replace static `netcheck` message with structured diagnostics:
  - path mode,
  - signed traversal age,
  - last transition reason,
  - candidate counts,
  - relay token expiry status.

## 7.6 `crates/rustynetd/src/phase10.rs`
Integrate deterministic traversal controller into apply/reconcile:
- Add traversal stage in apply order after trust validation and before endpoint mutation.
- Use `PathMode` transitions only from verified traversal events.
- Preserve kill-switch and DNS protections across transitions.
- Ensure transition auditing includes traversal reason codes:
  - `direct_probe_success`
  - `direct_probe_timeout`
  - `relay_token_expired`
  - `signed_traversal_stale`

## 7.7 New module: `crates/rustynetd/src/traversal.rs`
Implement core traversal engine with no insecure alternate path:
- Candidate gatherer:
  - local host candidates,
  - server-reflexive candidates via STUN,
  - relay candidates from signed bundle.
- Probe scheduler with bounded cadence and jitter.
- Endpoint scoring and deterministic selection.
- Anti-flood limits per peer and global rate limits.
- Strict parser for external probe responses.

No shell calls; Rust-only networking path.

## 7.8 `crates/rustynetd/src/ipc.rs` and `crates/rustynet-cli/src/main.rs`
- Keep `netcheck` command but return parseable structured output (JSON or key-value lines) including traversal security status.
- Optional new read-only command: `traversal inspect`.
- No mutating traversal IPC command that bypasses signed artifact flow.

## 7.9 `crates/rustynet-relay/src/lib.rs` + `crates/rustynet-relay/src/main.rs`
Replace selector-only behavior with authenticated relay transport service:
- Session auth via signed relay token.
- Strict binding of session to `(relay_id, source_node_id, target_node_id, expiry)`.
- Rate limits and per-node quotas.
- No payload inspection/parsing beyond framing needed to forward ciphertext.
- Structured audit logs without secret leakage.

## 8) Remove Weak/Legacy Paths (Required)
At cutover, remove superseded traversal behavior paths:
1. Remove any runtime peer endpoint mutation not driven by signed traversal bundle verification.
2. Remove static endpoint-only assumptions in operational status code paths.
3. Remove any convenience mutation command that sets peer endpoint directly.
4. Keep exactly one production traversal path: signed bundle -> verified -> deterministic controller -> backend update.

## 9) Security Hardening Controls Specific to Hole Punching
1. Candidate input hard limits:
- max candidates per peer: 8
- max candidate payload bytes: 4096
- reject unknown candidate types

2. Strict time windows:
- traversal hint max TTL: 120s
- relay token max TTL: 120s
- max clock skew: 90s (align with existing trust policy)

3. Anti-replay:
- nonce uniqueness per `(source,target)` within TTL window
- watermark monotonic checks with digest binding

4. Path downgrade prevention:
- direct->relay and relay->direct transitions require policy/trust revalidation
- disallow transitions if any protected-mode assertion fails

5. Abuse resistance:
- publish rate limits per node/IP
- probe rate limits per peer
- relay session quota caps per node

6. Secret handling:
- traversal signing secrets encrypted-at-rest
- no plaintext signing passphrases in files at rest
- zeroize transient decoded key buffers

## 10) Gate and Test Changes (Mandatory)

## 10.1 New/Extended Unit Tests
- `rustynet-control`:
  - signed traversal bundle verification,
  - replay rejection,
  - expiry/clock skew rejection,
  - policy-edge enforcement.
- `rustynetd`:
  - traversal controller state transitions,
  - fail-closed on invalid traversal bundle,
  - no endpoint mutation on unsigned/replayed hints.
- `rustynet-relay`:
  - token validation,
  - scope enforcement,
  - quota/rate-limit behavior.

## 10.2 Integration Tests
Add NAT-behavior coverage under Linux netns harness:
- direct hole punch success scenario,
- hard NAT -> relay fallback scenario,
- relay -> direct failback when direct probe recovers,
- two-hop scenario with relay/entry + blind exit final hop.

## 10.3 Negative/Security Tests
- Tampered traversal signature must fail.
- Replayed nonce must fail.
- Expired traversal/relay token must fail.
- Candidate flood attempts trigger rate limits and do not alter path mode.
- During path flaps, kill-switch and DNS fail-close remain effective.

## 10.4 CI Gate Changes
Update:
- `scripts/ci/phase10_gates.sh`
- `scripts/ci/check_phase10_readiness.sh`

Add required artifact:
- `artifacts/phase10/traversal_path_selection_report.json`

Artifact must include:
- `status=pass`
- `checks.direct_probe_success`
- `checks.relay_fallback_success`
- `checks.direct_failback_success`
- `checks.replay_rejected`
- `checks.tamper_rejected`
- `checks.fail_closed_on_invalid_traversal`
- measured source provenance entries.

## 11) Deployment and Cutover Strategy (No Security Downgrade)

Stage 1: Build-only integration
- Land code with traversal feature behind compile-time integration path, run full unit/integration gates.

Stage 2: Lab activation (single hardened path only)
- Enable signed traversal bundle verification and runtime controller.
- Disallow old endpoint mutation logic in runtime.

Stage 3: Relay productionization
- Deploy authenticated relay service.
- Require relay session tokens for relay path usage.

Stage 4: Enforce gates as release blockers
- Phase10 readiness fails if traversal artifact is missing or not measured-pass.

Rollback policy:
- Roll back by versioned deployment if severe fault; do not re-enable unsigned endpoint mutation behavior.
- Keep fail-closed controls active during rollback.

## 12) Operator Inputs Required (What the User Must Have)
To connect peers through traversal safely, operators must provision:
1. Valid membership state (signed governance state).
2. Valid trust evidence/verifier key.
3. Valid assignment bundle/verifier key authorizing source->target edge.
4. Valid traversal verifier key (`traversal.pub`) and signed traversal bundle.
5. Valid relay token for relay path sessions (if direct not available).

Without all required signed artifacts, traversal connection setup must fail closed.

## 13) Definition of Done
Traversal implementation is complete only when all are true:
1. Endpoint updates are impossible without valid signed traversal artifacts.
2. Replay/tamper/freshness checks are enforced and test-proven.
3. Relay path is authenticated, token-scoped, and ciphertext-only.
4. `phase10_gates.sh` and readiness checks enforce traversal evidence artifacts.
5. No legacy endpoint mutation paths remain in active runtime.
6. Linux/macOS documented behavior is accurate and updated in architecture/security/runbook docs.

## 14) Recommended Execution Order
1. Control-plane traversal artifact types + signing/verification.
2. Daemon traversal artifact parsing + watermark/replay enforcement.
3. Traversal runtime controller module and endpoint update path.
4. Relay authenticated transport service.
5. CLI/netcheck diagnostics for traversal security state.
6. Gate/evidence updates and full CI enforcement.
7. VM matrix validation and soak under transition churn.

This sequence minimizes exposure by establishing cryptographic authorization and replay protections before enabling runtime path switching behavior.
## Agent Update Rules

Use these rules every time you modify this document during implementation work.

1. Update the document immediately after each materially completed slice.
- Do not keep a private checklist that diverges from this file.
- This document must remain the public execution record.

2. Mark completion conservatively.
- Use `[x]` only after the code is implemented and verified.
- Use `Status: partial` when some hardening landed but real work remains.
- Use `Status: blocked` only for real external blockers; name the blocker precisely.

3. Record evidence under the section you touched, or in the existing session log/evidence table if the document already has one.
- Minimum evidence fields:
  - `Changed files:` exact paths
  - `Verification:` exact commands, tests, smoke runs, dry runs, gates
  - `Artifacts:` exact generated paths, if any
  - `Residual risk:` what still remains, if anything
  - `Blocker / prerequisite:` only when applicable

4. Use exact timestamps and commit references where possible.
- Prefer UTC timestamps in ISO-8601 format.
- If commits exist, record the commit SHA that contains the work.

5. Do not delete historical context that still matters.
- Correct stale claims when they are inaccurate.
- Do not erase previous findings, checklist items, or session history just to make the document look cleaner.

6. Keep security claims evidence-backed.
- Never write that a path is secure, complete, hardened, or production-ready without code and verification proof.
- If live validation is unavailable, state that explicitly and record the missing prerequisite.

7. If tests fail, record the failure honestly and fix the root cause.
- Do not weaken gates, remove checks, or relabel failures as acceptable.
- If a fix is incomplete, mark the item partial instead of complete.

