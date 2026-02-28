# Rustynet Phase 10 Plan (Production Exit-Node Dataplane Enablement)

## 0) Document Relationship and Precedence
- This plan extends [Phase9.md](./Phase9.md) and converts simulated dataplane behavior into real encrypted packet transport for exit-node usage.
- [Requirements.md](./Requirements.md) remains normative source of truth.
- [SecurityMinimumBar.md](./SecurityMinimumBar.md) remains release-blocking.
- If conflict exists, the stricter security interpretation applies and lower-precedence docs must be updated.

## 1) Phase 10 Objective
Deliver real Linux dataplane execution so one enrolled device can act as an authorized exit node and securely route another enrolled device's traffic through encrypted transport, with mandatory fail-closed behavior for traffic and DNS.

## 2) Exact Phase 10 Boundaries
### 2.1 In Scope
- Real Linux WireGuard backend implementation behind `TunnelBackend`.
- Persistent `rustynetd` daemon + authenticated local IPC control path.
- Real route/rule/firewall/NAT programming for exit-node full-tunnel and LAN-toggle flows.
- Tunnel and DNS fail-closed enforcement and validation.
- Direct/relay fallback/failback behavior under real networking.
- End-to-end Linux netns/VM validation and production-grade gate scripts.

### 2.2 Out of Scope
- New cryptographic protocol design.
- Non-Linux dataplane implementations.
- UI redesign or policy language redesign.
- Replacing WireGuard backend in this phase (only preserving replaceability).

## 3) Immutable Constraints (Must Hold)
- Rust-first implementation. Non-Rust only for unavoidable OS integration boundaries.
- No custom cryptography or custom VPN protocol invention in production paths.
- WireGuard remains an adapter behind `TunnelBackend`; no WireGuard-specific leakage into protocol-agnostic control/policy/domain layers.
- Default-deny and least privilege across ACL, routing, firewalling, DNS, and helper execution.
- Fail closed when trust/security state is missing, invalid, stale, or unavailable.

## 4) Platform and Runtime Prerequisites
| Area | Requirement | Enforcement |
| --- | --- | --- |
| OS | Linux-only for Phase 10 dataplane | startup capability check |
| Kernel features | WireGuard + netfilter/nftables + policy routing | startup probe; fail closed |
| Privileges | minimal required capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW` only where required) | process capability audit at startup |
| Tooling | Rust native route/rule/firewall APIs preferred; no shell composition | CI check + code review gate |
| Distros in test matrix | Debian 12 baseline + one secondary Linux distro | phase10 gate matrix |

If prerequisites are not satisfied, daemon remains in restricted-safe mode and refuses tunnel/exit activation.

## 5) Gap Assessment (Previous Draft)
Previous Phase 10 draft was directionally correct but underspecified in these areas:
1. No explicit in-scope/out-of-scope boundary.
2. No deterministic dataplane state machine with transition guards.
3. No formal transactional apply/rollback sequence.
4. No explicit IPv6 policy for leak-prevention behavior.
5. No concrete evidence artifact contract for acceptance gates.
6. No requirement-to-implementation matrix tied to Requirements and Security Minimum Bar.

This revised document closes those gaps.

## 6) Final Architecture for Phase 10
### 6.1 `rustynetd` Runtime Modules
1. `backend_manager`: owns `TunnelBackend` lifecycle and peer sync.
2. `route_manager`: installs/removes routes and policy rules transactionally.
3. `firewall_manager`: applies nftables policy, NAT, kill-switch chains.
4. `dns_manager`: applies protected-DNS routing and resolver restrictions.
5. `exit_manager`: owns exit-node selection, LAN-toggle, and ACL-validated route grants.
6. `ipc_server`: authenticated local control RPC over Unix socket.
7. `health_monitor`: path/tunnel/dns health and fail-closed transitions.
8. `state_store`: durable runtime state with integrity checks.

### 6.2 Linux Integration Choices
- nftables-first firewall and NAT.
- netlink-driven route/rule updates from Rust.
- argv-only privileged helper path only when kernel APIs are unavailable.
- Idempotent apply and deterministic rollback.

### 6.3 Local IPC Security Contract
- Unix socket in runtime dir with strict owner permissions.
- Peer identity verification (`SO_PEERCRED`) for all mutating commands.
- Role check before mutation.
- IPC auth failure results in deny with zero side effects.

## 7) Dataplane State Machine (Normative)
States:
1. `init`
2. `control_trusted`
3. `dataplane_applied`
4. `exit_active`
5. `fail_closed`

Required transitions:
- `init -> control_trusted`: control TLS1.3 valid + signed control data valid + freshness checks pass.
- `control_trusted -> dataplane_applied`: backend/routing/firewall/dns transactional apply succeeds.
- `dataplane_applied -> exit_active`: exit policy + ACL + route advertisement + LAN-toggle constraints valid.
- `* -> fail_closed`: any trust loss, apply failure, integrity failure, or health loss in protected mode.
- `fail_closed -> control_trusted`: only after trust and safety preconditions re-validated.

Forbidden behavior:
- No transition may permit unprotected egress when protected mode is expected.
- No transition may apply stale unsigned control state.

## 8) Transactional Apply and Rollback Algorithm (Normative)
Apply order:
1. Validate trust/freshness preconditions.
2. Stage backend peer/interface changes.
3. Stage route/rule changes.
4. Stage firewall + kill-switch baseline.
5. Stage NAT/forwarding for exit mode.
6. Stage DNS protection rules.
7. Commit active generation marker.

Rollback rules:
- Any failure in steps 2-6 triggers reverse-order rollback of all staged changes.
- If rollback itself partially fails, force `fail_closed` with explicit operator-visible error.
- Daemon must preserve last-known-safe generation and refuse unsafe partial generations.

## 9) Security Baseline for Real Dataplane
### 9.1 Trust/Freshness Preconditions
- Do not apply peer/route state unless control transport is TLS1.3-valid.
- Do not apply peer/route state unless signed control/peer data verification succeeds.
- Enforce max age for signed control data; stale state is rejected.
- Enforce strict clock-skew bounds for freshness checks.

### 9.2 Key and Secret Handling
- Node private keys from OS secure store when available.
- Encrypted-at-rest fallback with strict file permissions and startup permission validation.
- No cleartext key material in logs, debug output, CLI output, env vars, or panic paths.

### 9.3 Privileged Boundary Hardening
- Daemon/hardening profile must restrict filesystem and syscall surface to minimum required.
- Helper invocation must be argv-only with strict input validation.
- No shell interpolation for untrusted values.

### 9.4 Exit-Node Threat Controls
- Compromised exit node: enforce ACL boundaries and explicit trust model; no implicit LAN access.
- Route injection: validate advertised routes against policy and CIDR sanity constraints.
- DNS poisoning/leak: protected mode requires trusted resolver path and fail-close behavior.
- Lateral pivot risk: LAN route access requires explicit toggle + ACL allow + advertised route.

### 9.5 IPv6 Policy (Explicit)
- Phase 10 must explicitly choose one behavior and test it:
1. Full IPv6 support path with equivalent ACL/kill-switch/DNS protections, or
2. Hard-disable IPv6 egress in protected modes to prevent dual-stack leakage.

Default for Phase 10: if equivalent protections are not implemented for IPv6, enforce hard-disable fail-closed behavior.

### 9.6 Fail-Closed Decisions (Explicit)
- If firewall install fails: do not enable tunnel routing.
- If route install partially fails: rollback and deny activation.
- If kill-switch cannot be asserted: keep egress blocked.
- If trust-state load/verify fails: deny trust-required connectivity.
- If daemon state restore fails integrity checks: start in restricted-safe mode.

## 10) Detailed Workstreams
### Workstream A: Real Linux WireGuard Backend (`rustynet-backend-wireguard`)
- Implement interface create/configure/start/stop.
- Implement peer add/remove/update and route reconciliation.
- Implement stats collection mapped to `TunnelStats`.
- Add backend conformance tests for lifecycle, route replacement, exit-mode transitions, recovery.

### Workstream B: Persistent Daemon + CLI Control (`rustynetd`, `rustynet-cli`)
- Add daemon process mode with runtime state persistence and integrity checks.
- Add IPC API for status, netcheck, exit-node select/off, lan-access on/off, dns inspect, route advertise.
- Update CLI to call daemon IPC only.

### Workstream C: Exit Routing/NAT + Kill-Switch
- Implement forwarding/NAT apply/remove.
- Implement protected-routing kill-switch chain and rollback-safe updates.
- Implement protected DNS egress restrictions and resolver routing.

### Workstream D: Policy and ACL Enforcement in Dataplane
- Enforce protocol-aware ACL decisions for exit and shared-router contexts.
- Validate route advertisements and ACL grants before route installation.
- Keep default-deny posture for all non-explicitly-allowed flows.

### Workstream E: E2E Harness and Operationalization
- Netns/VM scenario runner for multi-device tests.
- Packet-capture verification for encrypted tunnel transport.
- Ops runbook updates for deployment, rollback, and incident handling.

## 11) Observability and Alerting Contract
Required metrics:
- tunnel state, peer count, direct/relay path mode, handshake recency.
- apply generation success/failure counts and durations.
- kill-switch asserted state.
- DNS protection state and blocked-leak events.
- exit-node activation failures by reason.

Required structured logs:
- transition events (`from_state`, `to_state`, `reason`).
- apply generation id, rollback id, and failure category.
- trust/freshness reject reasons (without secrets).

Required alerts:
- fail-closed entered.
- repeated apply failures.
- DNS protection unavailable in protected mode.

## 12) Testing and Validation Requirements
### 12.1 Unit Tests
- Backend lifecycle and error invariants.
- IPC authn/authz and command validation.
- Route/firewall planner idempotency and rollback behavior.
- Kill-switch state-machine transitions.

### 12.2 Integration Tests
- Device A selects device B as exit node and reaches internet through B.
- Device A LAN access denied with toggle off.
- Device A LAN access allowed only with toggle on + ACL allow + advertised route.
- Direct-path failure triggers relay fallback, then direct failback when healthy.
- Roaming endpoint change preserves connectivity.

### 12.3 Security/Negative Tests
- Tunnel drop in protected mode blocks egress.
- DNS path loss in protected DNS mode blocks DNS egress.
- Invalid or stale signed control data rejected before dataplane mutation.
- Privileged helper rejects unsafe input and shell-like payloads.
- WireGuard leakage check outside backend adapter crates.

### 12.4 Performance/Soak Gates
- Idle CPU <= 2% one core.
- Idle RSS <= 120 MB.
- Reconnect <= 5s.
- Route/policy apply <= 2s p95.
- Throughput overhead <= 15% vs baseline WG path.
- Soak duration >= 24h on declared benchmark matrix.

## 13) CI, Gate Script, and Evidence Contract (Mandatory)
Run from repository root:
```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo audit --deny warnings
cargo deny check bans licenses sources advisories
./scripts/ci/phase9_gates.sh
./scripts/ci/phase10_gates.sh
```

`phase10_gates.sh` is a required deliverable in this phase. The phase fails if the script is absent.

`phase10_gates.sh` must verify at minimum:
- Real Linux backend integration tests pass.
- Exit-node full-tunnel and LAN-toggle E2E tests pass.
- Tunnel and DNS fail-close leak tests pass.
- WireGuard boundary leakage check passes.
- Performance budgets and soak evidence satisfy thresholds.

`phase10_gates.sh` must emit evidence artifacts under `artifacts/phase10/`:
- `netns_e2e_report.json`
- `leak_test_report.json`
- `perf_budget_report.json`
- `direct_relay_failover_report.json`
- `state_transition_audit.log`

## 14) Rollout and Rollback Plan
Rollout:
1. Ship daemon/backend in disabled mode.
2. Enable canary on limited nodes.
3. Validate gate evidence and operational SLOs.
4. Gradually expand to stable channel.

Rollback:
1. Disable exit mode and revert to last-known-safe generation.
2. Reapply previous firewall/route generation.
3. Keep fail-closed protections active until trust and dataplane health restored.
4. Emit incident marker and required forensics artifact bundle.

## 15) Requirement-to-Implementation Traceability Matrix (Phase 10)
| Source Clause | Requirement | Implementation Direction | Owner |
| --- | --- | --- | --- |
| Requirements 3.2 | Encrypted mesh networking | real WireGuard backend via `TunnelBackend` | `rustynet-backend-wireguard` |
| Requirements 3.3 | Exit node selection/full-tunnel | `exit_manager` + route/firewall/NAT apply | `rustynetd` |
| Requirements 3.4 | LAN toggle with ACL gates | toggle + advertised route + ACL precondition enforcement | `rustynetd` + `rustynet-policy` |
| Requirements 3.5 | Magic DNS behavior safety | protected DNS routing + resolver constraints | `dns_manager` |
| Requirements 3.6 | Default-deny ACL and protocol-aware rules | dataplane route/filter apply from policy decisions | `rustynet-policy` + `rustynetd` |
| Requirements 4/5 | Reliability and security-first defaults | state machine + fail-closed + trust gating | `health_monitor` + `state_store` |
| Security Minimum Bar Critical 1 | Proven crypto only | WireGuard-only production dataplane | backend adapter layer |
| Security Minimum Bar Critical 2 | TLS1.3 + signed control validation | trust preconditions before dataplane apply | control client path |
| Security Minimum Bar Critical 7 | Leak prevention | kill-switch + DNS fail-close tests | firewall/dns managers |
| Security Minimum Bar Critical 9 | Supply-chain integrity | phase10 gate includes artifact verification and evidence | CI scripts |

## 16) Deliverables
- Real Linux WireGuard adapter implementation behind `TunnelBackend`.
- Persistent `rustynetd` daemon with secure local IPC.
- CLI wired to daemon IPC (no ephemeral command-local state).
- Exit-node forwarding/NAT + kill-switch + protected DNS enforcement.
- E2E Linux network harness and acceptance/security test suite.
- Updated operations runbook and incident drill procedures for exit-node dataplane incidents.
- New Phase 10 gate scripts and required evidence artifacts.

## 17) Phase 10 Exit Criteria
- Two real enrolled Linux nodes complete encrypted tunnel communication.
- One node can be selected as exit node by authorized client and route client internet traffic.
- LAN-route access behavior is exactly ACL/toggle/advertisement constrained.
- Tunnel and DNS fail-close behavior is proven in negative tests.
- Direct/relay fallback and failback works under controlled fault tests.
- All mandatory CI/security/performance/soak gates pass.
- Required evidence artifacts exist and are valid.
- No unresolved phase-scope TODO/FIXME/placeholders remain.
