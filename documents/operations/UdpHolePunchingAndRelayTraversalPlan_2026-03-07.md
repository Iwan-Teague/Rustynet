# Rustynet UDP Hole Punching + Relay Traversal Plan (2026-03-07)

Detailed implementation blueprint:
- [`UdpHolePunchingImplementationBlueprint_2026-03-07.md`](./UdpHolePunchingImplementationBlueprint_2026-03-07.md)
- Concrete HP-2 ingestion order and gating plan:
- [`UdpHolePunchingHP2IngestionPlan_2026-03-07.md`](./UdpHolePunchingHP2IngestionPlan_2026-03-07.md)

## 1) Objective
Implement seamless internet-reachable Rustynet connectivity without manual consumer-router port forwarding, using:
- direct UDP when possible (hole punching), and
- encrypted relay path when direct cannot be established,
while preserving Rustynet security constraints (default-deny, fail-closed, signed control state, no custom cryptography).

## 2) Current State (Codebase Reality)
- `Requirements.md` already requires NAT traversal + relay fallback (`3.2`).
- `rustynetd` now validates signed traversal bundles, programs authoritative per-peer direct/relay endpoint targets into the Phase 10 runtime controller, gathers backend handshake-recency evidence, and uses a bounded one-sided direct-probe loop before falling back to relay; auto-tunnel runtime applies traversal-authoritative peer endpoints during bootstrap/reconcile for covered peers, and netcheck reflects runtime path state instead of a static traversal slogan.
- `rustynet-relay` currently provides relay fleet selection primitives, not full encrypted packet relay transport.
- Auto-tunnel assignment currently carries a single signed endpoint per peer (`peer.N.endpoint`).

Implication:
- To match Tailscale-like UX, Rustynet still needs the remainder of HP-2 beyond the current one-sided probe model, plus HP-3 production relay transport, not just signed endpoint provisioning.

## 3) External Reference Constraints (Primary Sources)
- Tailscale design notes indicate NAT traversal and protocol behavior must share socket/port behavior to make hole punching effective, and they combine direct attempts with relay fallback.
- Tailscale docs describe typical operation without opening inbound ports, using direct connections when possible and DERP relay when not.
- IETF model: ICE connectivity checks over STUN-discovered candidates with TURN relay fallback (RFC 8445 / RFC 5389 / RFC 8656).

Rustynet design decision:
- Follow ICE-style candidate/check model and relay fallback semantics.
- Keep WireGuard encryption model unchanged; relay only forwards ciphertext.

## 4) Security Model (Non-Negotiable)
1. No plaintext payload visibility in relay.
2. No unsigned endpoint/control mutation accepted by daemon.
3. Replay-resistant endpoint update messages (nonce + monotonic timestamp + signature).
4. Fail-closed path selection in protected mode:
- If no valid direct/relay path, no unprotected egress.
5. One hardened connectivity state machine:
- direct and relay are states in one controller, not independent legacy/fallback code paths.

## 5) Target Architecture

### 5.1 New Runtime Module in `rustynetd`
Add `nat_traversal` module with:
- Candidate gatherer:
  - local interface candidates,
  - server-reflexive candidates from STUN,
  - relay candidates.
- Connectivity check engine:
  - paced checks,
  - simultaneous-open attempts,
  - liveness scoring.
- Path controller:
  - chooses `Direct` or `Relay` using deterministic policy,
  - automatic failover/failback,
  - exposes selected path + reason in status.

### 5.2 Control-Plane Extensions (`rustynet-control`)
- Add signed endpoint-hint objects per node:
  - `node_id`, `candidate[]`, `generated_at_unix`, `expires_at_unix`, `nonce`, `signature`.
- Keep strict anti-replay/watermark semantics aligned with existing trust/assignment models.
- Add bounded TTL to endpoint hints (short-lived freshness).

### 5.3 Relay Service (`rustynet-relay`)
- Evolve from fleet-selector to actual relay transport service:
  - authenticated node sessions,
  - ciphertext forwarding only,
  - per-node rate limits and abuse protections,
  - regional relay selection integration.

### 5.4 Backend/API Surface
- Extend backend API with path telemetry and endpoint update hooks.
- Keep control/policy crates transport-agnostic.
- No WireGuard-specific leakage into policy domain.

## 6) Protocol and Data Flow (Planned)
1. Node boots and validates signed assignment/trust as today.
2. Node gathers candidates (local, reflexive, relay) and publishes signed endpoint hints.
3. Node receives peer endpoint hints and runs connectivity checks.
4. If direct path validated, set peer endpoint direct.
5. If direct fails, use relay path.
6. Continuously probe for direct recovery and fail back from relay when stable.

## 7) Implementation Phases

## Phase HP-1: Endpoint Intelligence Foundation
Deliverables:
- Signed endpoint-hint schema and verification in control + daemon.
- NAT type/netcheck classification output.
- CLI: `rustynet netcheck` includes candidate and path diagnostics.

Acceptance:
- Signed endpoint hints reject tamper/replay.
- Netcheck reports deterministic, auditable path reasoning.

### HP-1 Implementation Status (2026-03-07)
- `rustynet-control` now issues and verifies signed endpoint-hint bundles with a dedicated signer domain (`rustynet-control-endpoint-hint-signing-v1`) and deterministic canonical payload serialization.
- Endpoint-hint issuance enforces strict TTL bounds (max 120s), source/target policy gating, candidate schema checks, and duplicate-candidate rejection.
- `rustynetd` now includes signed traversal bundle parsing with signature validation, strict schema checks, freshness bounds, and digest-bound watermark replay/rollback protection.
- `rustynet netcheck` now emits structured traversal diagnostics (path mode/reason, traversal artifact freshness, candidate counts by type, and validation error state) instead of the prior static message.
- Traversal artifact paths are now wired through daemon config + CLI flags + Linux systemd installer/env (`RUSTYNET_TRAVERSAL_BUNDLE`, `RUSTYNET_TRAVERSAL_VERIFIER_KEY`, `RUSTYNET_TRAVERSAL_WATERMARK`, `RUSTYNET_TRAVERSAL_MAX_AGE_SECS`) and propagated into runtime launch arguments.
- Daemon preflight now treats traversal verifier custody as conditional on traversal bundle presence: no bundle means verifier is not required, while a present bundle still fails closed if verifier key custody/validation is missing or invalid.
- Auto-tunnel runtime now applies traversal-authoritative peer endpoints before backend peer provisioning for covered peers and fail-closes on traversal runtime programming errors instead of silently ignoring them.
- Unit tests were added for tamper detection, replay rejection, watermark persistence, and deterministic netcheck diagnostics.

## Phase HP-2: Direct UDP Hole Punching Engine
Deliverables:
- Candidate checks + simultaneous open orchestration.
- Keepalive tuning + endpoint roaming updates.

Acceptance:
- Two NATed nodes establish direct path when NAT combination allows.
- Path survives endpoint change events.

## Phase HP-3: Production Relay Transport
Deliverables:
- Relay service forwarding ciphertext only.
- Client/daemon relay session support + policy gates.

Acceptance:
- Encrypted traffic succeeds when direct path blocked.
- Relay sees no plaintext.

## Phase HP-4: Seamless Path Controller
Deliverables:
- Unified direct/relay state machine in `rustynetd`.
- Automatic failover and direct failback with hysteresis.

Acceptance:
- Live handoff under load with no policy bypass and no leak.

## Phase HP-5: Hardening and Gates
Deliverables:
- VM matrix tests: Debian, Ubuntu, Fedora, Mint, macOS.
- Gate coverage for traversal/replay/abuse/fail-closed.

Acceptance:
- All security gates pass.
- Path behavior documented and reproducible.

## 8) UX Plan (Seamless by Default)
- Keep wizard simple:
  - `Traversal Mode: Auto (recommended)` default.
- Optional advanced diagnostics only in expert menu.
- Do not require users to understand STUN/relay terms to connect.

## 9) Why This Is Better Than Auto Port Forward Alone
- Auto port forwarding (NAT-PMP/PCP/UPnP) is opportunistic and router-dependent.
- Hole punching + relay provides broad compatibility without router admin access.
- Port mapping can remain optional optimization, not a correctness dependency.

## 10) Immediate Next Code Work (Recommended Sequence)
1. Implement HP-1 schema + signed endpoint hints + parser/validator tests.
2. Add `rustynet netcheck` NAT/candidate reporting fields.
3. Build minimal STUN probe client module in Rust (`rustynetd`) with strict parser and timeout policy.
4. Integrate candidate set into peer endpoint selection logic.

## 11) Security Test Additions Required
- Replay/tamper tests for endpoint hints.
- Candidate flooding/rate-limit tests.
- Path downgrade prevention tests (direct->relay->direct transitions must preserve ACL/fail-closed).
- Leak tests during path flap and handshake failure.

## 12) Risk Notes
- Symmetric NAT pairs may still require relay path.
- Relay capacity and abuse controls become production-critical.
- Endpoint freshness must be tightly time-bounded to avoid stale routing risk.

## 13) Primary References
- Tailscale blog: How NAT traversal works.
- Tailscale docs: Firewall ports and connectivity behavior (direct + DERP relay fallback).
- RFC 8445 (ICE), RFC 5389 (STUN), RFC 8656 (TURN), RFC 6887 (PCP).
