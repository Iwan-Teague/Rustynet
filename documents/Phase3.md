# Rustynet Phase 3 Plan (Linux Data Plane MVP and Backend Conformance)

## 0) Document Relationship and Scope
- This plan extends identity/control outputs from [Phase2.md](./Phase2.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 3 outputs are prerequisites for [Phase4.md](./Phase4.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 3 Objective
Deliver secure Linux mesh connectivity using a modular WireGuard backend implementation with conformance checks.

## 2) Phase 3 Scope
1. Linux client daemon core (`rustynetd`):
- TUN lifecycle management.
- Route programming basics.
- Peer session orchestration.

2. WireGuard backend adapter:
- Implement `rustynet-backend-wireguard` against `rustynet-backend-api`.
- Keep WireGuard-specific logic isolated to adapter crate.

3. Connectivity baseline:
- Encrypted node-to-node connectivity for at least 3 nodes.
- Direct path preference with basic relay fallback behavior.
- Session stability across reconnect scenarios.
- Initial performance baseline measurement against declared budgets.

4. Policy enforcement baseline:
- Default-deny behavior active.
- Core allow/deny enforcement in data path.

5. Backend conformance suite v1:
- Define and run tests every backend must pass.
- Include connect/disconnect, peer update, route apply, and teardown behaviors.

6. Handshake and data-plane resilience hardening:
- Add early-drop protections against unauthenticated flood/state exhaustion (for example cookie/challenge or equivalent stateless guard).
- Add handshake path rate controls and adversarial load tests.
- Define and test key rotation/rekey behavior to preserve forward secrecy over long-running sessions.

## 3) Deliverables
- Linux mesh connectivity functioning end-to-end.
- WireGuard adapter passing backend conformance v1.
- Policy enforcement active for baseline mesh flows.
- CI integration tests for 3-node mesh scenarios.
- Performance benchmark report (CPU, memory, reconnect, route-apply latency).
- Handshake-flood resilience test report and mitigations in place.

## 4) Security Gates
- All mesh payload traffic encrypted.
- Client validates signed control-plane data before applying peer updates.
- No leakage of WireGuard types into control-plane API or policy domain.
- Handshake exhaustion and flood tests demonstrate bounded resource impact.

## 5) Phase 3 Exit Criteria
- Three-node Linux mesh passes integration tests consistently.
- Relay fallback functions when direct path is unavailable.
- Backend conformance suite is green for WireGuard adapter.
- Architectural boundary checks confirm protocol-agnostic core model.
- Initial performance budgets are measured and no critical regressions are open.

## 6) Handoff to Phase 4
- Phase 4 adds user-facing networking features (exit node, LAN toggle, Magic DNS) on top of a proven Linux mesh base.
- Use [Phase4.md](./Phase4.md) as the next execution plan once Phase 3 exit criteria are met.
