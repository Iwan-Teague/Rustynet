# Rustynet UDP Hole Punching + Relay Traversal Plan (2026-03-07)

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
1. Implement the immediate next code work in Section 10 in order: finish full simultaneous-open and STUN-assisted WAN candidate acquisition beyond the current one-sided proof model.
2. Then add live WAN and NAT validation harnesses and measured evidence for direct success, relay fallback, and secure failback.
3. Then implement HP3 relay transport in rustynet-relay.
4. Only after those are real should you update user-facing claims about internet reachability or connect-from-anywhere behavior.
5. Keep the required security tests in Section 11 coupled to the implementation as you go.

Scope-specific validation for this document:
- Targeted rustynetd traversal tests and rustynet-relay transport tests.
- bash ./scripts/ci/phase10_hp2_gates.sh
- ./scripts/ci/phase10_gates.sh
- Live WAN or lab validation harnesses when the environment exists.

Definition of done for this document:
Section 10 immediate next code work is implemented with evidence, required security tests exist and pass, and the project has measured proof for direct and relay behavior rather than design-only intent.

If full completion is impossible in one execution, continue until you hit a real external blocker, then mark the exact remaining items as blocked with the reason, the missing prerequisite, and the next concrete step.
```

## Current Open Work

This block is the quick source of truth for what remains in this document.
If historical notes later in the file conflict with this block, the AI prompt, or current code reality, update the stale section instead of following the stale note.

`Open scope`
- HP-1 is implemented enough to proceed, but HP-2 and HP-3 remain the real unfinished core.
- Open work is the Section 10 immediate next code sequence: full simultaneous-open and STUN-assisted WAN candidate acquisition, live WAN or NAT evidence, and HP3 relay transport.

`Do first`
- Finish the direct WAN traversal work before extending the relay path.
- Then add measured validation harnesses so HP2 claims are evidence-backed before HP3 broadens the runtime surface.

`Completion proof`
- Measured evidence for direct success, relay fallback, and secure failback under realistic NAT or WAN conditions.
- Updated security tests in Section 11 with passing outputs.

`Do not do`
- Do not describe the project as internet-reachable or connect-from-anywhere unless the live evidence exists.
- Do not treat opportunistic port forwarding as the primary correctness path.

`Clarity note`
- This document is the high-level execution order; use the HP2 ingestion plan and the implementation blueprint for lower-level file and gate details.

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
- `rustynetd` now validates signed traversal bundles, programs authoritative per-peer direct/relay endpoint targets into the Phase 10 runtime controller, gathers backend handshake-recency evidence, uses a bounded one-sided direct-probe loop before falling back to relay, periodically reprobes relay-backed peers on reconcile, and uses live backend handshake evidence to avoid stale cached direct-path downgrades; auto-tunnel runtime requires traversal-authoritative peer coverage for all managed peers in enforced mode, probe fanout/freshness/reprobe policy is now explicit in daemon config/status/netcheck, and netcheck reflects runtime path state instead of a static traversal slogan.
- `rustynet-relay` currently provides relay fleet selection primitives, not full encrypted packet relay transport.
- Auto-tunnel assignment currently carries a single signed endpoint per peer (`peer.N.endpoint`).

Implication:
- To match Tailscale-like UX, Rustynet still needs the remainder of HP-2 beyond the current one-sided probe model, plus HP-3 production relay transport, not just signed endpoint provisioning.
- Health-driven periodic reprobe/direct failback is now present for the current signed traversal controller, but full WAN simultaneous-open behavior is not.

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
- Auto-tunnel runtime now applies traversal-authoritative peer endpoints before backend peer provisioning for all managed peers in enforced mode and fail-closes on traversal runtime programming errors instead of silently ignoring them.
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
1. Build full simultaneous-open/STUN-assisted WAN candidate acquisition beyond the current one-sided signed-candidate proof model.
2. Add live WAN/NAT validation harnesses and evidence for direct success, relay fallback, and secure failback.
3. Implement HP-3 relay transport in `rustynet-relay`.

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

