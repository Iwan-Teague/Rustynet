# Rustynet Cross-Network Remote Exit Node Plan (2026-03-16)

## 1. Objective
Deliver Tailscale-like remote exit-node behavior for Rustynet:
- a device on one network can securely use an authorized Rustynet exit node on a different network,
- direct UDP is used when NAT conditions allow,
- encrypted relay is used when direct UDP cannot be established,
- fail-closed behavior is preserved for traffic, DNS, routing, and control-plane trust.

This document is implementation-oriented. It starts from the repository's current state and defines the remaining work in phases.

## 2. Document Relationship and Precedence
This plan extends, but does not replace:
- [Requirements.md](/Users/iwanteague/Desktop/Rustynet/documents/Requirements.md)
- [SecurityMinimumBar.md](/Users/iwanteague/Desktop/Rustynet/documents/SecurityMinimumBar.md)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md)
- [UdpHolePunchingHP2IngestionPlan_2026-03-07.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/UdpHolePunchingHP2IngestionPlan_2026-03-07.md)

If any conflict exists, the stricter security interpretation wins.

## 3. User Outcome
The target user experience is:
1. A user enrolls a device on network A.
2. Another enrolled device on network B is authorized as an exit node.
3. The client selects that remote exit node.
4. Rustynet establishes the tunnel automatically:
   - direct UDP if possible,
   - encrypted relay if direct UDP is not possible.
5. Full-tunnel traffic and managed DNS flow through the selected remote exit node without manual consumer-router port forwarding.

The phrase "from anywhere" is not acceptable as a claim until the direct path and relay path are both proven under real cross-network conditions.

## 4. Current Repository Reality
### 4.1 What already exists
- Signed traversal bundle verification, freshness enforcement, and replay/rollback protection.
- Traversal-authoritative endpoint control in `rustynetd`.
- Bounded direct-probe logic with relay fallback decisions.
- Periodic reprobe for relay-backed sessions and relay-to-direct failback using live handshake evidence.
- Structured traversal diagnostics in `status` and `netcheck`.
- Phase 10 HP2 CI artifacts showing passing traversal path-selection and traversal-security checks.

Primary source references:
- [README.md:48](/Users/iwanteague/Desktop/Rustynet/README.md#L48)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [traversal_path_selection_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/traversal_path_selection_report.json)
- [traversal_probe_security_report.json](/Users/iwanteague/Desktop/Rustynet/artifacts/phase10/traversal_probe_security_report.json)

### 4.2 What does not exist yet
- Full WAN simultaneous-open traversal behavior.
- Production relay transport service.
- End-to-end live proof that a client on one network can use a remote exit node on a different network under real NAT conditions.

Primary source references:
- [README.md:48](/Users/iwanteague/Desktop/Rustynet/README.md#L48)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md:17](/Users/iwanteague/Desktop/Rustynet/documents/operations/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md#L17)

### 4.3 Important architecture truth
- [rustynet-relay](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs) currently contains relay fleet selection primitives, not a production ciphertext relay transport.
- The traversal controller is partially complete, but it still operates on a one-sided proof model rather than full WAN simultaneous-open behavior.

## 5. Non-Negotiable Security Invariants
These must hold throughout every phase:
1. One hardened path only for endpoint mutation.
   - `verified signed traversal state -> deterministic controller decision -> backend apply`
2. No unsigned endpoint mutation.
3. No silent fallback to weaker path logic.
4. No plaintext visibility at the relay.
5. No unprotected egress if no valid direct or relay path exists.
6. Replay, rollback, stale-state, and wrong-signer artifacts must fail closed.
7. Route and DNS protections must survive direct/relay transitions.
8. Exit-node selection must never widen LAN or underlay access beyond explicit policy.
9. Local control surfaces remain Unix-socket or root-only system integration surfaces, never ad hoc LAN/localhost HTTP management surfaces.
10. Every new cross-network behavior must land with measured gate evidence, not just unit-test assertions.

## 6. Minimum Functional Definition of Done
Rustynet can claim cross-network remote exit-node support only when all of the following are true:
1. A client behind NAT can use a remote exit node behind a different NAT via direct UDP when NAT conditions allow.
2. A client can use the same remote exit node via encrypted relay when direct UDP does not work.
3. Direct-to-relay and relay-to-direct transitions preserve:
   - ACLs,
   - kill-switch behavior,
   - DNS fail-closed behavior,
   - narrow server-IP bypass semantics.
4. The system remains functional after endpoint roaming.
5. Live validation artifacts exist and pass on a multi-network Linux lab.

## 7. Gap Summary
The remaining work falls into four technical gaps:
1. Candidate acquisition:
   - Rustynet needs real public/reflexive candidate discovery, not just signed endpoint hints carrying static or pre-known addresses.
2. WAN simultaneous-open behavior:
   - Rustynet needs shared-socket, real NAT traversal behavior rather than only one-sided bounded probe logic.
3. Relay transport:
   - Rustynet needs a real ciphertext relay service and client integration.
4. Cross-network exit-path validation:
   - Rustynet needs measured live evidence that full-tunnel routing and DNS remain secure across direct and relay paths.

## 8. Implementation Phases
### Phase 0: Truth Lock and Threat Model Baseline
Goal:
- Align all remaining work under one current-state plan and stop overstating completion.

Tasks:
1. Keep current docs explicit that WAN simultaneous-open and production relay are still open.
2. Maintain the exploit-comparison and live-auditing skill outputs as release inputs for traversal and relay work.
3. Treat HP2 and HP3 as release-blocking for cross-network remote-exit claims.

Primary touchpoints:
- [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)
- [phase10.md](/Users/iwanteague/Desktop/Rustynet/documents/phase10.md)
- [tools/skills/rustynet-security-auditor](/Users/iwanteague/Desktop/Rustynet/tools/skills/rustynet-security-auditor/SKILL.md)

Acceptance:
- No repo document claims "connect from anywhere" without measured evidence.

### Phase 1: Candidate Acquisition and Signed Traversal Inputs
Goal:
- Complete the authenticated candidate-discovery foundation required for real cross-network connectivity.

Tasks:
1. Add real candidate acquisition for:
   - local interface candidates,
   - public reflexive candidates,
   - relay candidates.
2. Keep the signed traversal artifact model:
   - source node,
   - target node,
   - candidate list,
   - short TTL,
   - nonce,
   - watermark/replay protection,
   - signature.
3. Ensure candidate acquisition does not create an alternate runtime authority path.
4. Bind every candidate the daemon consumes to:
   - a signed artifact,
   - freshness window,
   - authorization scope.

Primary touchpoints:
- [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)

Security constraints:
- No raw peer endpoint gossip.
- No unsigned STUN-like observations used directly for endpoint mutation.
- Candidate TTLs must remain short and bounded.
- Oversized or malformed candidate artifacts must fail closed.

Acceptance:
- Measured artifact proving:
  - signed candidate publication,
  - replay rejection,
  - wrong-signer rejection,
  - stale candidate rejection,
  - no endpoint mutation without signed traversal authority.

### Phase 2: Complete HP2 for Real WAN Simultaneous-Open
Goal:
- Turn the current one-sided probe model into a real cross-network direct-path engine.

Tasks:
1. Ensure traversal attempts use the same UDP socket and port behavior as the actual WireGuard transport path.
2. Implement simultaneous-open scheduling suitable for unrelated NATs.
3. Extend endpoint-roam handling to real WAN path changes.
4. Keep bounded, deterministic probe fanout and pacing from daemon config.
5. Preserve direct/relay decision control in one state machine only.

Primary touchpoints:
- [crates/rustynetd/src/traversal.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/traversal.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs)

Security constraints:
- No manual or operator-driven endpoint override as a production path.
- No path transition without signed traversal proof and deterministic controller approval.
- Direct-path establishment must not disable kill-switch or route-leak protections.
- Direct-path success criteria must be based on bounded authenticated runtime evidence, not optimistic assumption.

Acceptance:
- Live measured evidence showing:
  - two nodes on different networks establish direct UDP when NAT conditions allow,
  - direct path survives endpoint roaming,
  - direct-path failure falls back safely without leak.

### Phase 3: Build HP3 Production Relay Transport
Goal:
- Provide a secure fallback path when direct UDP is impossible.

Tasks:
1. Convert [rustynet-relay](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs) from selector-only logic into a real ciphertext relay service.
2. Add authenticated relay session setup and expiry.
3. Add per-session replay protection.
4. Use constant-time comparison for relay auth/token validation.
5. Add abuse protections:
   - rate limiting,
   - bounded queues,
   - idle expiry,
   - per-node/session scoping.
6. Keep relay blind to payload plaintext.

Primary touchpoints:
- [crates/rustynet-relay/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/lib.rs)
- [crates/rustynet-relay/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-relay/src/main.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynet-control/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-control/src/lib.rs)

Security constraints:
- Relay sees only ciphertext and minimal routing metadata.
- No plaintext session negotiation outside the existing trust model.
- Relay token/session validation must be constant-time.
- Relay path use must still obey assignment/trust/ACL policy.

Acceptance:
- Measured evidence showing:
  - direct-blocked peers can still connect through relay,
  - relay transport does not expose plaintext,
  - auth failures, stale sessions, and replay attempts fail closed.

### Phase 4: Remote Exit-Node Dataplane Integration
Goal:
- Make remote exit-node use work over either direct or relay path without weakening policy.

Tasks:
1. Ensure the client can select a remote exit node on another network and use it as:
   - full-tunnel egress,
   - managed DNS path,
   - optional LAN toggle path where authorized.
2. Preserve narrow server-IP bypass semantics for control traffic.
3. Ensure the exit node enforces:
   - route scope,
   - forwarding/NAT policy,
   - DNS policy,
   - ACL constraints.
4. Ensure path changes do not cause transient underlay leaks.

Primary touchpoints:
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/dataplane.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/dataplane.rs)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)
- [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh)

Security constraints:
- Exit selection remains signed-state-driven.
- No raw route mutation fallback in `start.sh` or daemon control flow.
- DNS must remain managed-zone fail-closed.
- LAN access remains explicit and policy-limited.

Acceptance:
- Live measured evidence showing:
  - client on network A uses exit on network B,
  - DNS remains protected,
  - no route leak or underlay bypass occurs during steady state or path transition.

### Phase 5: Testing, Security Gates, and Release Enforcement
Goal:
- Convert the feature from "implemented in code" to "proven secure in the lab".

Tasks:
1. Extend the existing live validation skill and orchestrator coverage to include:
   - direct cross-network exit-node success,
   - relay-backed cross-network exit-node success,
   - relay-to-direct failback,
   - endpoint roaming recovery,
   - stale/forged traversal rejection during active sessions.
2. Bind those results into canonical tracked artifacts under `artifacts/phase10/`.
3. Extend Phase 10 readiness to require those artifacts.
4. Keep comparative exploit coverage honest:
   - do not promote partially covered classes without measured live evidence.
5. Add a dedicated cross-network exit-node gate bundle rather than relying on generic traversal success alone.

Primary touchpoints:
- [scripts/ci/phase10_hp2_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_hp2_gates.sh)
- [scripts/ci/check_phase10_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_phase10_readiness.sh)
- [scripts/e2e/live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh)
- [tools/skills/rustynet-security-auditor](/Users/iwanteague/Desktop/Rustynet/tools/skills/rustynet-security-auditor/SKILL.md)

Security constraints:
- No release gate may be weakened to compensate for missing WAN evidence.
- Evidence must remain commit-bound and measured.
- Stale child evidence must fail closed.
- A passing local/unit gate is not sufficient to claim cross-network readiness.

Acceptance:
- Phase 10 gates require and pass on:
  - cross-network direct remote-exit evidence,
  - cross-network relay remote-exit evidence,
  - fail-closed adversarial traversal evidence.

## 9. Mandatory Test and Gate Contract for "Connect From Anywhere"
This is release-blocking. Rustynet must not claim cross-network remote-exit capability until all required tests and gates below exist and pass on the target commit.

### 9.1 Required test classes
1. Unit and property tests
   - signed candidate parsing and verification
   - replay, rollback, stale-state, wrong-signer rejection
   - bounded simultaneous-open scheduling
   - relay session token/auth validation
   - constant-time auth/token comparison for relay control surfaces
   - route and DNS fail-closed transitions during path changes
2. Local integration tests
   - backend endpoint rotation on valid traversal decision only
   - direct-path establishment success when handshake evidence advances
   - safe fallback to relay when direct cannot be proven
   - safe failback from relay to direct when direct becomes healthy
   - exit-node routing and DNS enforcement under path transitions
3. Live multi-network lab tests
   - direct remote-exit success across different networks
   - relay-backed remote-exit success across different networks
   - relay-to-direct failback after reprobe
   - endpoint roaming recovery
   - reboot recovery while remote-exit path remains policy-safe
4. Adversarial live tests
   - forged traversal state during active session
   - stale traversal state during active session
   - replayed traversal state during active session
   - rogue endpoint injection
   - route-bypass / TunnelCrack-style leak attempts during path change
   - control-surface exposure checks while cross-network exit path is active
5. Soak and resilience tests
   - long-running direct session across networks
   - long-running relay session across networks
   - repeated direct/relay flaps without policy leak

### 9.2 Required measured artifacts
At minimum, the following tracked measured artifacts must exist under `artifacts/phase10/` and be required by readiness checks:
- `cross_network_direct_remote_exit_report.json`
- `cross_network_relay_remote_exit_report.json`
- `cross_network_failback_roaming_report.json`
- `cross_network_traversal_adversarial_report.json`
- `cross_network_remote_exit_dns_report.json`
- `cross_network_remote_exit_soak_report.json`

Each artifact must be:
- `evidence_mode = measured`
- commit-bound to the current `HEAD`
- tagged with `nat_profile` and `impairment_profile`
- sourced from canonical tracked inputs, not gitignored run-only paths
- rejected if stale, incomplete, or schema-invalid

Canonical schema reference:
- [CrossNetworkRemoteExitArtifactSchema_2026-03-16.md](/Users/iwanteague/Desktop/Rustynet/documents/operations/CrossNetworkRemoteExitArtifactSchema_2026-03-16.md)
- `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports ...`

### 9.3 Required checks inside those artifacts
The measured reports must prove all of the following checks as `pass`:
1. `direct_remote_exit_success`
2. `relay_remote_exit_success`
3. `relay_to_direct_failback_success`
4. `endpoint_roam_recovery_success`
5. `remote_exit_dns_fail_closed`
6. `remote_exit_no_underlay_leak`
7. `remote_exit_server_ip_bypass_is_narrow`
8. `forged_traversal_rejected`
9. `stale_traversal_rejected`
10. `replayed_traversal_rejected`
11. `rogue_endpoint_rejected`
12. `control_surface_exposure_blocked`
13. `long_soak_stable`
14. `cross_network_topology_heuristic`
15. `direct_remote_exit_ready`
16. `post_soak_bypass_ready`
17. `no_plaintext_passphrase_files`

### 9.4 Required gate wiring
The repo should add or extend gate entry points so this evidence is enforced automatically:
1. Add a dedicated gate bundle:
   - [phase10_cross_network_exit_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh)
   - include `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-nat-matrix ...` as a hard-fail matrix coverage check
2. Keep `scripts/ci/phase10_hp2_gates.sh` for traversal engine correctness, but do not treat it as sufficient evidence for remote exit-node readiness.
3. Extend [check_phase10_readiness.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/check_phase10_readiness.sh) to require every cross-network remote-exit artifact and its mandatory checks.
   - that readiness path must invoke `cargo run --quiet -p rustynet-cli -- ops validate-cross-network-remote-exit-reports ...` before interpreting pass/fail checks
4. Extend [live_linux_lab_orchestrator.sh](/Users/iwanteague/Desktop/Rustynet/scripts/e2e/live_linux_lab_orchestrator.sh) so the cross-network exit suite is a distinct hard-fail stage.
5. Extend the Rustynet security auditor skill so coverage promotion only happens when those measured reports pass schema validation and required checks.

### 9.5 Failure policy
If any required test or artifact fails:
1. Rustynet must not claim "connect from anywhere".
2. Coverage remains `partially_covered`.
3. Release readiness must fail closed.
4. The fix must land with a regression test or measured validator that proves the failure class is covered.

### 9.6 Security interpretation of pass/fail
- A passing direct-path test without relay proof is insufficient.
- A passing relay-path test without direct-path proof is insufficient.
- A passing happy-path test without adversarial rejection proof is insufficient.
- A passing unit/integration suite without measured live evidence is insufficient.

## 10. Recommended Build Order
The correct implementation order from the current repo state is:
1. Finish candidate acquisition and signed traversal input completeness.
2. Finish true WAN simultaneous-open behavior in HP2.
3. Implement real relay transport in HP3.
4. Bind exit-node full-tunnel semantics to those paths.
5. Add live measured evidence and gate enforcement.

This order matters. Shipping relay before the direct-path controller is secure enough would multiply trust surfaces unnecessarily. Shipping direct-path claims before live cross-network validation would overstate the feature and weaken release integrity.

## 11. What Must Not Be Done
1. Do not add a second endpoint mutation path.
2. Do not accept unsigned or locally guessed external endpoints.
3. Do not rely on manual port forwarding as the product correctness path.
4. Do not treat a public-IP exit node as proof that hole punching is complete.
5. Do not add "temporary" raw shell fallbacks for relay or traversal control.
6. Do not claim "works from anywhere" until live multi-network evidence exists.

## 12. Immediate Next Code Work
The highest-value next code steps are:
1. Finish the candidate acquisition side for real public/reflexive candidates.
2. Complete shared-socket simultaneous-open behavior in the traversal engine and backend integration.
3. Begin the real ciphertext relay transport implementation in `rustynet-relay`.
4. Define the cross-network remote-exit measured artifact schemas and readiness checks before implementation claims start to drift.

## 13. Exit Criteria for This Plan
This plan is complete only when:
1. Rustynet can securely connect a client on one network to an exit node on another network without manual port forwarding when direct NAT traversal is possible.
2. The same workflow securely succeeds via relay when direct traversal is not possible.
3. The measured live artifacts and Phase 10 gates prove that behavior on the current commit.
4. The required cross-network remote-exit tests and adversarial gates in Section 9 pass without weakening any release checks.
