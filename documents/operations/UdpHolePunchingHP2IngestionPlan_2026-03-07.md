# Rustynet HP-2 Ingestion Plan (Security-First, One Hardened Path)

## 1) Purpose
Define a concrete, implementation-ordered HP-2 plan to wire real direct UDP hole-punch behavior into runtime control flow without adding legacy/fallback execution branches.

This plan is intentionally strict:
- one authoritative path for endpoint mutation,
- fail-closed on any missing/invalid traversal trust state,
- no runtime bypass from assignment endpoint fields.

## 2) Normative Inputs (Precedence Applied)
1. `documents/Requirements.md`
2. `documents/SecurityMinimumBar.md`
3. `documents/phase10.md`
4. `documents/operations/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md`
5. `documents/operations/UdpHolePunchingImplementationBlueprint_2026-03-07.md`

Key mandatory constraints carried into this plan:
- signed, short-lived traversal hints with anti-replay before endpoint mutation,
- deterministic direct/relay controller with fail-closed outcomes,
- relay/traversal transitions must not bypass ACL/trust/leak-prevention controls,
- no parallel legacy/fallback path logic.

## 3) Current Baseline (Verified in Code)
- `rustynet-control` can issue and verify signed endpoint-hint bundles.
- `rustynetd` parses/validates traversal bundles with strict schema, signature, freshness, and watermark replay checks.
- `rustynet netcheck` reports traversal diagnostics.
- `Phase10Controller` path toggles are no longer bookkeeping-only for runtime state: traversal endpoint programming updates the managed peer endpoint and bypass routing, but it is still not driven by a live probe executor.
- Auto-tunnel runtime now exposes an explicit internal authority mode (`TraversalAuthorityMode::EnforcedV1`) and applies traversal-authoritative peer endpoints during bootstrap/reconcile for covered peers; assignment `peer.N.endpoint` still remains the fallback input for peers that do not yet have verified traversal state.
- Traversal runtime programming errors now fail closed instead of being silently swallowed.
- Backend contract already supports controlled endpoint rotation (`update_peer_endpoint` / `current_peer_endpoint`).
- `rustynet-relay` is still selector-only (HP-3 scope for real relay transport).

Implication: HP-2 must finish the probe-evidence path, expand authority from “covered peers” to all traversal-managed peers, and remove remaining assignment-endpoint fallback authority for runtime mutation.

## 4) HP-2 Security Contract (Non-Negotiable)
1. Traversal artifact validity is a hard precondition for endpoint mutation.
2. Endpoint mutation authority is only: `verified traversal hints -> deterministic controller decision -> backend apply`.
3. Assignment `peer.N.endpoint` is not used as mutable runtime authority once HP-2 cutover is enabled.
4. Unknown/malformed/oversized traversal inputs always fail closed.
5. If direct cannot be proven and no trusted relay candidate exists, remain/enter fail-closed.
6. No shell-based probe logic; Rust + argv-only privileged boundaries only.

## 5) Strict Wiring Order

### HP2-00: Authority Cutover Guard (First)
Goal:
- Introduce a single control switch in daemon runtime for HP-2 enforcement (`TraversalAuthorityMode::EnforcedV1`), default `EnforcedV1` in protected/auto-tunnel mode.

Files:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/main.rs`

Changes:
- Add explicit runtime mode with no permissive fallback branch.
- If mode is enforced and traversal state for a peer is missing/invalid, endpoint mutation is denied and controller fail-closes.

Exit criteria:
- Unit test proves missing traversal state blocks peer mutation in enforced mode.

Status (2026-03-08):
- partially implemented
- runtime now has `TraversalAuthorityMode::EnforcedV1` in auto-tunnel mode,
- covered peers are mutated from verified traversal state during bootstrap/reconcile,
- inconsistent traversal runtime programming now fail-closes instead of being ignored,
- fully blocking peers with missing traversal state remains open until the verified traversal index / multi-peer authority model is completed.

---

### HP2-01: Unify Traversal Types and Authority Index
Goal:
- Remove duplicated local traversal model drift and centralize runtime traversal input into one typed index.

Files:
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/daemon.rs`

Changes:
- Create/extend a `VerifiedTraversalIndex` keyed by `(source_node_id, target_node_id)`.
- Convert parsed bundle candidates into traversal engine types once, then consume typed state everywhere.
- Validate local node/peer membership activity before index admission.

Exit criteria:
- Unit tests for index build/rejection on wrong target, inactive nodes, duplicates.

---

### HP2-02: Backend Contract for Probe Evidence + Endpoint Rotation
Goal:
- Add minimal backend surfaces needed for deterministic direct probe decisions without introducing alternate control paths.

Files:
- `crates/rustynet-backend-api/src/lib.rs`
- `crates/rustynet-backend-wireguard/src/lib.rs`
- `crates/rustynet-backend-stub/src/lib.rs`

Changes:
- Add backend methods:
  - `update_peer_endpoint(node_id, endpoint)`
  - `peer_latest_handshake_unix(node_id)` (or equivalent per-peer handshake recency evidence)
- WireGuard backend implements via strict `wg` argv operations and bounded parser for handshake output.
- Preserve existing `configure_peer` for initial provisioning only; endpoint roaming/probing uses new endpoint-update method.

Exit criteria:
- Parser fuzz/negative tests: unknown tokens, oversized output, malformed lines, no panic.
- Unit tests: endpoint update only for known peers; unknown peer rejected.

Status (2026-03-08):
- partially implemented
- `update_peer_endpoint(node_id, endpoint)` and `current_peer_endpoint(node_id)` are now present in the backend contract and wired through the WireGuard backends,
- handshake-recency evidence is still missing and remains the next backend primitive required for probe-driven HP-2 decisions.

---

### HP2-03: Direct Probe Executor (Deterministic, Bounded)
Goal:
- Execute candidate checks in deterministic rounds using `TraversalEngine` and produce a signed-state-backed endpoint decision.

Files:
- `crates/rustynetd/src/traversal.rs`
- `crates/rustynetd/src/phase10.rs`
- `crates/rustynetd/src/daemon.rs`

Changes:
- Add `TraversalDecision` (`Direct(endpoint)` / `Relay(endpoint)` / `FailClosed(reason)`).
- Implement bounded probe loop:
  - input candidates: direct-eligible (`host`,`srflx`) only for direct attempts,
  - round limits and timing from config,
  - success condition from backend handshake recency evidence,
  - no unbounded retries.
- Relay selection at HP-2 is candidate-based path state only (transport service remains HP-3).

Exit criteria:
- Unit tests:
  - direct success path chosen when handshake evidence observed,
  - relay chosen only when direct fails and trusted relay candidate exists,
  - fail-closed when neither condition is met.

---

### HP2-04: Integrate Traversal Stage into Apply/Reconcile (Before Peer Mutation)
Goal:
- Move traversal decision into the mandatory apply order so peer endpoints are derived before backend peer apply.

Files:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/phase10.rs`

Changes:
- In bootstrap/reconcile, build peer endpoint decisions from verified traversal index first.
- Provide resolved peer configs to `apply_dataplane_generation`.
- Remove default path initialization that marks all peers direct before evidence.
- Path transition reason codes become evidence-derived, not operator/manual toggles.

Exit criteria:
- Integration tests prove:
  - stale/forged/replayed traversal cannot mutate endpoint,
  - successful decision mutates endpoint once and records reason,
  - failed decision transitions controller to fail-closed.

---

### HP2-05: Remove Runtime Bypass Paths
Goal:
- Eliminate legacy runtime branches that can mutate endpoints outside traversal authority.

Files:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynetd/src/phase10.rs`

Changes:
- Remove or test-gate `mark_direct_failed` / `mark_direct_recovered` from production mutation flow.
- Assignment `peer.N.endpoint` remains data input but not endpoint-mutation authority in enforced mode.
- Ensure all endpoint updates route through one internal function with trust checks at entry.

Exit criteria:
- Grep gate: no production endpoint mutation callsites outside the traversal-authorized path.

---

### HP2-06: Observability and Operator Diagnostics
Goal:
- Make security state explicit and auditable.

Files:
- `crates/rustynetd/src/daemon.rs`
- `crates/rustynet-cli/src/main.rs` (if needed for display polish)

Changes:
- Extend netcheck/status with:
  - per-peer path mode,
  - last transition reason,
  - probe rounds attempted,
  - last fail-closed traversal reason.
- Ensure all values are bounded/sanitized for IPC output.

Exit criteria:
- Tests for parseable deterministic netcheck/status output under direct, relay, and fail-closed states.

## 6) Gate Plan (How HP-2 Is Enforced)

### 6.1 New Gate Script
Add:
- `scripts/ci/phase10_hp2_gates.sh`

This script must fail closed and run:
1. `cargo test -p rustynetd traversal --all-features`
2. `cargo test -p rustynetd daemon::tests::traversal_* --all-features`
3. `cargo test -p rustynet-backend-wireguard --all-targets --all-features`
4. HP-2-specific integration tests (new namespaces where applicable)

### 6.2 CI Wiring
Update:
- `scripts/ci/phase10_gates.sh` to invoke `phase10_hp2_gates.sh` before readiness checks.
- `scripts/ci/check_phase10_readiness.sh` to require HP-2 traversal artifacts.

### 6.3 Required HP-2 Artifacts
Add/require:
- `artifacts/phase10/traversal_path_selection_report.json`
- `artifacts/phase10/traversal_probe_security_report.json`

Minimum required checks in artifact payload:
- `checks.direct_probe_success`
- `checks.relay_fallback_success`
- `checks.replay_rejected`
- `checks.fail_closed_on_invalid_traversal`
- `checks.no_unauthorized_endpoint_mutation`

## 7) Test Matrix (HP-2)

### Unit/Negative
- Candidate planner bounds, duplicates, and NAT-viability cases.
- Handshake parser fuzz and malformed-output rejection.
- Missing verifier key / stale bundle / wrong signer / nonce replay rejection.
- Unknown token and oversized input rejection with no panic.

### Integration (Local/Netns)
- Direct path establishment success under permissive NAT simulation.
- Forced direct failure with trusted relay candidate results in relay path state.
- Forced direct failure with no trusted relay candidate results in fail-closed.
- Path transitions preserve ACL and kill-switch invariants.

### Active-Network (Optional in HP-2, required before HP-3 cutover)
- Two-node direct traversal smoke test with endpoint roam and failback.
- Adversarial stale/forged hint injection during active session; endpoint must not switch.

## 8) Definition of Done for HP-2
- Endpoint mutation authority is traversal-only in enforced mode.
- Probe executor drives real direct-path decisions with bounded deterministic policy.
- No runtime bypass branch remains for endpoint mutation.
- All HP-2 gates green in CI.
- Artifacts generated and readiness check enforces them.
- Documentation synchronized and explicitly notes HP-3 still required for authenticated ciphertext relay transport service.
