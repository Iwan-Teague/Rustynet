# Rustynet Phase 4 Plan (Exit Nodes, LAN Toggle, and Magic DNS)

## 0) Document Relationship and Scope
- This plan extends mesh baseline outputs from [Phase3.md](./Phase3.md).
- Requirement ownership remains in [Requirements.md](./Requirements.md).
- Phase 4 outputs are prerequisites for [Phase5.md](./Phase5.md).
- If this plan conflicts with [Requirements.md](./Requirements.md), requirements take precedence.

## 1) Phase 4 Objective
Deliver core end-user network features: exit-node routing, LAN access toggling, and Magic DNS.

## 2) Phase 4 Scope
1. Exit-node feature set:
- Node capability to act as exit node.
- Client-side exit-node selection and disable flows.
- Policy controls for allowed users/groups.

2. LAN access toggle:
- Per-client on/off toggle for exit-node LAN subnets.
- Explicit route advertisement and ACL-gated LAN route access.
- Enforced behavior difference between internet-only and LAN-enabled modes.
- Tunnel and DNS fail-close behavior design for protected-routing modes.

3. Magic DNS baseline:
- Internal DNS naming for nodes.
- Deterministic duplicate-name conflict handling.
- CLI DNS inspection and troubleshooting commands.

4. CLI completion for core networking flows:
- `exit-node select/off`, `lan-access on/off`, `dns inspect`.

5. Leak-class mitigation program:
- Implement route and DNS leak mitigations informed by known VPN leak classes (for example local-network and server-IP leak paths).
- Define OS-specific leak test matrix, starting with Linux and planned parity gates for macOS/Windows.
- Include protocol-filter correctness matrix for shared subnet-router and shared-exit configurations.

## 3) Deliverables
- Exit-node end-to-end traffic routing.
- LAN toggle behavior enforced by policy and routing controls.
- Magic DNS resolution for online nodes.
- Integration tests validating exit + LAN + DNS behavior.
- Leak-class test suite and mitigation matrix for current platform support.

## 4) Security Gates
- LAN routes are never exposed unless explicitly enabled and authorized.
- Default deny remains active for route and peer access.
- DNS record updates require authenticated, authorized control-plane actions.
- Tunnel drop events in protected modes do not leak traffic outside policy (kill-switch behavior).
- Protected DNS modes do not leak DNS requests outside Rustynet policy.
- Protocol-specific ACL intent is preserved for shared-router/shared-exit traffic and never widened during policy transformation.

## 5) Phase 4 Exit Criteria
- Exit-node selection works and can be reverted without stale routes.
- LAN-off mode blocks RFC1918 access through exit node.
- LAN-on mode allows only authorized subnets.
- Magic DNS reliability and naming rules pass integration tests.
- Leak-prevention tests pass for tunnel-failure and DNS-failure scenarios.
- Shared-router/shared-exit protocol-filter test matrix passes without regressions.

## 6) Handoff to Phase 5
- Phase 5 focuses on observability, diagnostics, and reliability hardening of Phase 4 functionality.
- Use [Phase5.md](./Phase5.md) as the next execution plan once Phase 4 exit criteria are met.
