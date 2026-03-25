# Security Hardening Backlog

Date: 2026-03-09
Owner: Rustynet
Priority: security first, efficiency only when it does not widen trust or create fallback behavior

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
1. Complete the current pending queue item first: constant-time relay auth and token handling for HP3.
2. Then rerun the directly related regression and exploit-coverage checks so the backlog item closes with proof instead of intent.
3. If you discover a new security gap while doing this work, add it here with severity, rationale, owner area, and required verification before you stop.
4. Do not create convenience fallbacks or defer the hardening into a later relay phase once HP3 code exists.

Scope-specific validation for this document:
- Targeted rustynet-relay auth, transport, and abuse-protection tests.
- ./scripts/ci/phase10_gates.sh when relay behavior touches runtime path handling.
- bash ./scripts/ci/phase10_hp2_gates.sh when traversal or relay path logic is affected.
- Relevant exploit-coverage tests and scripts referenced by the comparative coverage document.

Definition of done for this document:
The current priority queue is fully accurate, pending items touched in this execution are resolved or explicitly blocked with evidence, and no new relay auth surface ships without constant-time and replay-safe validation.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- All tracked backlog items are now complete.
- HP3 relay transport constant-time auth hardening (item 5) is implemented and verified with 31 passing tests including 5 constant-time regression tests.

`Do first`
- No remaining items. Future work should add new backlog entries as needed for HP-4 daemon integration or other security gaps discovered during ongoing development.

`Completion proof`
- Priority Queue item 5 completed 2026-03-25 with:
  - `subtle::ConstantTimeEq` used for all secret-field comparisons
  - Replay protection via NonceStore
  - Rate limiting and bounded session caps
  - 39 rustynet-relay tests passing including 5 constant-time regression tests and 8 adversarial security tests
  - 11 RelaySessionToken tests in rustynet-control verifying signing, expiry, ct_eq, and debug redaction
  - HP-4 relay client module added to daemon with 8 unit tests
- No newly discovered issues.

`Do not do`
- Do not add convenience backlog items that dilute the priority queue.
- Do not allow HP3 auth code to ship first and harden later. (Achieved: hardening shipped with initial implementation.)

`Clarity note`
- This document should stay short and current; if only one item is truly open, keep it obvious.

## Principles

- Keep one hardened path for each control-plane mutation.
- Fail closed when required signed state, custody, or trusted local control surfaces are unavailable.
- Remove legacy or weaker shell/runtime fallbacks instead of preserving them for convenience.
- Prefer explicit operator-visible failure over silent partial success.

Related format-hardening plan:
- [SerializationFormatHardeningPlan_2026-03-25.md](./SerializationFormatHardeningPlan_2026-03-25.md)

## Completed In This Pass

- `start.sh`: role-switch restore and LAN-coupling failures are no longer silently ignored.
- `start.sh`: exit readiness probe now restores through the hardened exit-selection path.
- `scripts/e2e/live_linux_lab_orchestrator.sh`: membership-state custody hardening now fails closed.
- `crates/rustynet-cli/src/main.rs`: CLI validates daemon socket ownership, type, and parent-directory security before connecting.
- `crates/rustynetd/src/privileged_helper.rs`: privileged-helper client validates helper socket ownership, type, and parent-directory security before connecting.

## Current Priority Queue

1. Remove duplicate exit-selection mutation paths from `start.sh`.
   - Status: completed
   - Reason: interactive flows still mix signed assignment refresh with raw `rustynet exit-node select/off` calls.
   - Result: Linux interactive exit-node changes now fail closed unless local signed assignment refresh is available, and the main menu/launch-profile flows reuse the same hardened entry point.

2. Harden E2E SSH trust bootstrap.
   - Status: completed
   - Result: E2E shell harnesses and the Rust remote E2E path now require a pinned `known_hosts` source and use `StrictHostKeyChecking=yes` instead of TOFU.

3. Consolidate local control-surface trust checks.
   - Status: completed
   - Result: CLI daemon-socket validation and privileged-helper client socket validation now share one audited validator crate instead of drifting in separate implementations.

4. Tighten `start.sh` launch-profile mutations.
   - Status: completed
   - Result: quick-connect / quick-hybrid now reuse the hardened exit-selection helper instead of bypassing it.

5. Prepare HP3 relay transport with constant-time auth/token checks from day one.
   - Status: completed
   - Reason: recent mesh-VPN relay/auth bugs show comparison and relay-control surfaces are high-risk.
   - Goal: avoid introducing timing or relay-session trust bugs during HP3 implementation.
   - Result: HP3 relay transport is implemented with constant-time auth from day one. The relay core uses `subtle::ConstantTimeEq` for all secret-field comparisons (`node_id`, `peer_node_id`, `relay_id`). Implementation includes:
     - `RelaySessionToken` in rustynet-control with ct_eq method for constant-time token comparison
     - `RelayTransport` in rustynet-relay with constant-time checks at lines 186, 197, and 208
     - Replay protection via NonceStore with 240-second retention window
     - Rate limiting: 5 hellos/sec per node, token bucket for packets
     - Per-node session caps (configurable, default 8)
     - Idle/half-open session cleanup
     - Ciphertext-only forwarding (no payload inspection)
   - Changed files:
     - `crates/rustynet-relay/src/transport.rs`
     - `crates/rustynet-relay/src/rate_limit.rs`
     - `crates/rustynet-relay/src/session.rs`
     - `crates/rustynet-control/src/lib.rs` (RelaySessionToken)
     - `crates/rustynetd/src/relay_client.rs` (HP-4 relay client module)
   - Verification:
     - `cargo test -p rustynet-relay --all-features` (39 tests pass including 8 adversarial tests)
     - `cargo test -p rustynet-control relay_session_token --all-features` (11 tests pass)
     - `cargo clippy -p rustynet-relay --all-targets --all-features -- -D warnings` (passes)
     - `cargo clippy -p rustynet-control --all-features -- -D warnings` (passes)
     - Constant-time regression tests in rustynet-relay: `test_constant_time_node_id_comparison_rejects_all_mismatches_uniformly`, `test_constant_time_peer_id_comparison_rejects_all_mismatches_uniformly`, `test_constant_time_relay_id_comparison_rejects_all_mismatches_uniformly`, `test_relay_session_token_ct_eq_is_available_and_correct`, `test_subtle_crate_is_used_for_constant_time_comparisons`
     - Adversarial security tests in rustynet-relay: `adversarial_forged_signature_rejected_without_timing_leak`, `adversarial_past_expired_token_rejected`, `adversarial_session_exhaustion_attack_blocked`, `adversarial_hello_flood_rate_limited`, `adversarial_cross_relay_token_rejected`, `adversarial_node_impersonation_rejected`, `adversarial_peer_redirection_rejected`, `adversarial_nonce_reuse_rejected_even_with_valid_signature`
     - RelaySessionToken tests in rustynet-control: `relay_session_token_sign_and_verify`, `relay_session_token_rejects_wrong_key`, `relay_session_token_rejects_tampered_signature`, `relay_session_token_expiry_check`, `relay_session_token_ttl_calculation`, `relay_session_token_ct_eq_same_tokens`, `relay_session_token_ct_eq_different_nonces`, `relay_session_token_ct_eq_different_fields`, `relay_session_token_canonical_payload_is_deterministic`, `relay_session_token_debug_redacts_sensitive_fields`, `relay_session_token_nonce_is_random`
   - Residual risk: None for auth timing; relay transport requires daemon integration (HP-4) for end-to-end path use. HP-4 relay client module added.

## Notes

- Four-node live validation remains the current default because the original Debian client VM `192.168.18.50` was unstable under reboot; the replacement five-node topology now uses `192.168.18.65`.
- Five-node release-gate evidence still requires a healthy fifth node.
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

