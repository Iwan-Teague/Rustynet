# Rustynet Requirements (Brainstorm v0.3)

## 0) Document Map and Governance
- This file is the normative source of truth for product requirements across all phases.
- [Phase1.md](./Phase1.md) defines the first execution slice (architecture and security foundations).
- [Phase2.md](./Phase2.md) defines identity, enrollment, and control-plane core delivery.
- [Phase3.md](./Phase3.md) defines Linux data-plane MVP and backend-conformance delivery.
- [Phase4.md](./Phase4.md) defines exit-node, LAN toggle, and Magic DNS delivery.
- [Phase5.md](./Phase5.md) defines observability, reliability hardening, tamper-evident auditability, and early release-integrity delivery.
- [Phase6.md](./Phase6.md) defines admin UX, baseline RBAC/MFA controls, and cross-platform expansion delivery.
- [Phase7.md](./Phase7.md) defines scale and commercial foundation delivery.
- [Phase8.md](./Phase8.md) defines advanced security assurance and compliance delivery.
- [Phase9.md](./Phase9.md) defines completion readiness, long-term operations, and protocol-agility validation.
- [phase10.md](./phase10.md) defines production dataplane enablement for real encrypted exit-node traffic and LAN-toggle enforcement.
- [SecurityMinimumBar.md](./SecurityMinimumBar.md) defines mandatory release-blocking security controls and evidence expectations.
- If a phase document conflicts with this file, this file takes precedence until requirements are explicitly updated.
- Any new phase capability that changes product behavior must be reflected back into this file.

## 1) Vision
Rustynet is a self-hostable, Rust-first mesh VPN for home servers and homelabs, inspired by Tailscale-style usability while remaining transparent and local-control friendly.

Primary goal:
- Securely connect personal devices and home servers into one private network, with optional exit-node routing, optional LAN access through exit nodes, and Magic DNS-like naming.

## 2) Core User Stories
- As a homelab owner, I can join all my devices to one private mesh network.
- As a user, I can select a specific node as an exit node for internet traffic.
- As a user, I can toggle whether I can access the exit node’s local LAN subnets.
- As a user, I can resolve devices by friendly names instead of IP addresses.
- As an admin, I can control who can join, what routes are allowed, and which nodes can be exit nodes.

## 3) Functional Requirements

### 3.1 Identity and Enrollment
- Each device (node) has a stable node identity (public/private keypair).
- Users authenticate to a control plane (self-hosted first; optional hosted later).
- Enrollment methods:
- CLI login flow (device code or auth URL).
- Optional pre-auth keys for headless servers.
- One-time throwaway account/credential generation for temporary access.
- Throwaway accounts must be single-use and become invalid immediately after first successful enrollment.
- Throwaway accounts should support short TTLs, strict scope, and manual revocation before use.
- Node metadata:
- Hostname, OS, tags, owner, last-seen timestamp.

### 3.1.1 Throwaway Account Lifecycle
- `created`: single-use credential is generated with creator identity, scope, TTL, and `max_uses = 1`.
- `used`: first successful enrollment consumes the credential and invalidates it immediately.
- `expired`: TTL reached before use; credential is permanently invalid.
- `revoked`: admin/operator revokes before use; credential is permanently invalid.
- Valid transitions: `created -> used`, `created -> expired`, `created -> revoked`.
- Invalid transitions: no transitions are allowed from `used`, `expired`, or `revoked`.
- Single-use credential consumption must be enforced with atomic write-time revalidation (race-safe, TOCTOU-resistant).
- Credential stores must enforce uniqueness constraints preventing double-consumption under concurrent requests.
- Audit events must be recorded for `created`, `used`, `expired`, and `revoked`.

### 3.2 Mesh Networking
- Node-to-node encrypted tunnels (WireGuard protocol model preferred).
- Automatic peer discovery through control plane.
- NAT traversal using UDP hole punching when possible.
- Relay fallback when direct P2P cannot be established.
- Keepalive and roaming support (IP changes, Wi-Fi to LTE transitions).

### 3.3 Exit Nodes
- Admin can enable/disable exit-node capability per node.
- Client can choose zero or one active exit node at a time.
- Split mode:
- `off`: no exit node (normal local internet).
- `full`: route all internet traffic via exit node.
- Exit node policy constraints:
- Which users/groups can use which exit nodes.
- Optional time-based or tag-based restrictions.

### 3.4 LAN Access Toggle (via Exit Node)
- Per-client toggle: allow/disallow access to exit node local subnets.
- If enabled:
- Client can reach configured RFC1918 subnets behind exit node.
- If disabled:
- Client only gets internet egress through exit node, no LAN reachability.
- Exit node must explicitly advertise allowed LAN routes.
- Route ACLs determine which users may access which LAN subnets.
- Tunnel fail-close behavior must prevent traffic leakage if VPN path drops unexpectedly.
- DNS fail-close behavior must prevent DNS leakage outside Rustynet policy when VPN mode requires protected DNS.

### 3.5 Magic DNS
- Internal DNS zone (example: `*.rustynet`).
- Automatic hostname records for enrolled nodes.
- Optional aliases (e.g., `nas.rustynet` -> specific node).
- Search domain support for clients.
- Conflict handling:
- deterministic naming if duplicate hostnames appear.
- Optional DNS over UDP first; add DoH/DoT later.

### 3.6 ACL and Policy Engine
- Central policy file/API:
- Who can connect to whom.
- Who can use exit nodes.
- Who can access advertised LAN routes.
- Tag-based policy (e.g., `tag:servers`, `tag:family`, `tag:iot`).
- Default deny with explicit allow rules.
- Protocol-specific ACL rules (for example ICMP/UDP/TCP-specific grants) must be preserved and enforced end-to-end, including shared subnet-router and shared-exit contexts.

### 3.7 Administration and UX
- First-class CLI (`rustynet`) for:
- login/logout
- status/peers
- exit-node select
- lan-access toggle
- dns inspect
- route advertise
- Lightweight web admin UI (phase 6) for policy and node management.

### 3.8 Observability
- Node health status (online/offline, relay/direct, latency).
- Connection diagnostics (`rustynet netcheck` style command).
- Audit log for policy changes and auth events.

## 4) Non-Functional Requirements
- Security-first defaults.
- Rust implementation for control plane + client daemon + CLI (as much as possible).
- Minimal external runtime dependencies.
- The WireGuard implementation must be modular and replaceable through a stable backend interface.
- No WireGuard-specific types, config shapes, or assumptions may leak into control-plane APIs or policy schemas.
- A future non-WireGuard backend must be swappable with minimal changes outside backend adapter crates.
- Cross-platform clients:
- Linux (priority), macOS, Windows.
- Performance budgets (to be benchmarked and enforced in CI):
- Idle daemon CPU target: <= 2% of one core on Raspberry Pi-class hardware.
- Idle daemon memory target: <= 120 MB RSS under normal operating profile.
- Reconnect target after transient network interruption: <= 5 seconds.
- Route/policy update apply target on active clients: <= 2 seconds p95.
- Throughput overhead target versus baseline WireGuard path: <= 15%.
- Benchmarking must run against a documented environment matrix (hardware class, network profile, and OS profile).
- Soak tests for release candidates must run long enough to catch memory/session drift (minimum 24-hour continuous test run).
- Reliability:
- Survive control plane restarts without dropping existing sessions immediately.

## 5) Security Requirements
- Use proven protocols and libraries; no custom cryptographic protocol design.
- Encrypt all node-to-node and node-to-exit traffic with WireGuard-style authenticated encryption.
- Keep the control plane separate and protect it with TLS 1.3 and signed peer maps.
- Use long-lived node identity keys with ephemeral session keys for forward secrecy.
- Support key rotation and rapid revocation/offboarding.
- Relay servers must only forward ciphertext and must not decrypt payload data.
- Store private keys in OS-secure key storage when available; if unavailable, require encrypted-at-rest fallback with strict file permissions, in-memory zeroization, and startup permission checks.
- Treat exit nodes as trusted egress points and rely on end-to-end application encryption (HTTPS/TLS) for internet destinations.
- Enforce authentication attack-surface controls: rate limiting, lockout/backoff controls, and abuse throttling for auth/enrollment endpoints.
- Enforce anti-replay protections for enrollment/auth flows with bounded token lifetime, nonce/state checks, and strict clock-skew policy.
- Enforce web/admin surface protections: CSRF protections, secure cookie/session policy, and clickjacking defenses.
- Enforce API abuse protections (per-identity and per-IP quotas, burst limits, and anomaly alerting).
- Audit logs must be tamper-evident and append-only, with retention rules and forensic integrity verification.
- VPN operating modes requiring protected routing must fail closed for traffic and DNS on tunnel failure.
- Enforce a cryptographic allowlist/denylist policy: reject weak legacy algorithms (for example SHA-1-only integrity, 3DES/BF-CBC-class ciphers, weak DH groups) except behind explicit time-bounded risk acceptance.
- Maintain an algorithm deprecation cadence to remove legacy compatibility debt over time.
- Insecure compatibility modes must be disabled by default; temporary enablement requires explicit, time-bounded risk acceptance and automatic expiry.
- Enrollment key hygiene: one-time credentials default; reusable credentials require strict scope, short expiry, and secret-vault storage policy.
- Require tested vulnerability response workflow with patch SLAs and emergency release capability.
- Require staged release tracks (for example unstable/canary before stable) for security-sensitive changes.
- Patch SLA minimums:
- Critical: mitigation or patched build available within 48 hours.
- High: patched build available within 7 calendar days.
- Medium: patched build available within 30 calendar days.
- Trusted-signing/authorization state must fail closed: when trust state cannot be loaded or persisted, trust-required connectivity must be denied with explicit operator-visible errors.
- Privileged helper and system-integration code must use argv-based exec with strict input validation and must not invoke shell command construction for untrusted values.
- Tunnel/data-path compression for sensitive traffic must be disabled by default to avoid compression side-channel classes.
- Redaction and secret handling requirements apply to all config ingestion paths (MDM, CLI flags, env vars, API payloads, UI forms, and logs).
- Time correctness controls must exist for monotonic-counter dependent handshake logic (clock skew/drift detection and fail-safe handling).
- Threat considerations:
- Compromised node
- Stolen pre-auth key
- Replay and MITM attempts during bootstrap

## 6) Suggested Architecture (Rust-Centric)

### 6.1 Components
- `rustynet-control`:
- Auth, node registry, policy engine, peer map distribution, DNS records.
- `rustynetd`:
- Client daemon handling tunnels, route programming, DNS config, exit-node logic.
- `rustynet`:
- CLI frontend to daemon + control API.
- `rustynet-relay` (optional in MVP if embedded in control):
- Relay/DERP-like transport for hard NAT cases.

### 6.2 Data Plane
- WireGuard-compatible transport behavior.
- Prefer direct P2P UDP path.
- Relay path fallback with health probing and automatic failback to direct.

### 6.3 Transport Backend Abstraction (Hard Requirement)
- Define a transport backend interface in Rust (e.g., start tunnel, add/remove peer, apply routes, collect stats, shutdown).
- Implement WireGuard as one backend adapter crate, not as globally coupled core logic.
- Core components (`rustynet-control`, `rustynet-policy`, DNS, ACL, identity) must remain protocol-agnostic.
- Backend capability flags must be explicit so alternate backends can degrade gracefully.
- A backend conformance test suite must validate all supported backends against the same networking and policy behaviors.

### 6.4 Control Plane APIs
- gRPC or HTTPS+JSON API for:
- enrollment/auth
- node updates
- peer map fetch/stream
- policy fetch
- DNS record updates

## 7) Roadmap Distribution (10 Phases)
- `Phase 1`: Architecture, crate boundaries, backend abstraction boundary, and security baseline setup.
- `Phase 2`: Identity, enrollment, throwaway credentials, and control-plane core APIs.
- `Phase 3`: Linux data-plane MVP, WireGuard adapter, relay fallback basics, and backend conformance.
- `Phase 4`: Exit nodes, LAN access toggle enforcement, Magic DNS, and CLI feature completion.
- `Phase 5`: Observability, diagnostics, reliability hardening, tamper-evident auditing, and early release-integrity guardrails.
- `Phase 6`: Web admin UX, multi-user workflows, baseline RBAC+MFA controls, and macOS/Windows client expansion.
- `Phase 7`: High-availability scale-out, relay fleet maturity, commercial controls, and control-plane trust-hardening mode.
- `Phase 8`: Security assurance program, key custody hardening, compliance, and privacy maturity.
- `Phase 9`: Completion readiness, API compatibility guarantees, operational excellence, and long-term protocol agility validation.
- `Phase 10`: Real Linux dataplane enablement for encrypted exit-node traffic, persistent daemon IPC control, NAT/forwarding enforcement, and fail-closed leak prevention validation.

## 8) Phase Planning Rules
- Earlier phases must land the abstractions required by later phases before feature expansion.
- No phase may weaken default-deny policy behavior, key-management controls, or protocol-agnostic backend boundaries.
- WireGuard remains the initial backend implementation, but architecture must remain backend-swappable across all phases.

## 9) Open Decisions to Resolve Early
- Auth model:
- local accounts only vs OIDC first.
- Persistence:
- SQLite for MVP vs Postgres from day one.
- Policy format:
- JSON, YAML, or HCL.
- DNS strategy:
- embedded DNS server only vs OS resolver integrations per platform.
- Relay deployment:
- bundled with control vs dedicated service.
- Licensing:
- permissive OSS vs source-available.

## 10) API / Config Sketch

### 10.1 Node Config Example
```toml
[node]
name = "mini-pc-1"
tags = ["servers", "exit-capable"]

[network]
advertise_routes = ["192.168.1.0/24"]
can_be_exit_node = true

[dns]
magic_dns = true
search_domain = "rustynet"
```

### 10.2 Client Preferences Example
```toml
[client]
exit_node = "mini-pc-1"
allow_exit_node_lan_access = true
```

### 10.3 Policy Sketch
```yaml
groups:
  family:
    - "alice@example.local"
    - "bob@example.local"

tags:
  servers:
    owners: ["group:family"]

rules:
  - action: allow
    src: ["group:family"]
    dst: ["tag:servers:*"]

exit_node_use:
  - users: ["group:family"]
    nodes: ["tag:servers"]

lan_route_access:
  - users: ["group:family"]
    routes: ["192.168.1.0/24"]
```

## 11) Rust Implementation Notes
- Candidate crates:
- `tokio` (async runtime)
- `axum` or `actix-web` (control APIs)
- `tonic` (if gRPC chosen)
- `serde` + `toml`/`serde_yaml` (config/policy parsing)
- `rustls` (TLS)
- `sqlx` (DB)
- Keep unsafe code minimized and isolated.
- Prefer integration tests around networking behaviors and ACL decisions.

## 12) Testing and Validation Requirements
- Unit tests:
- policy evaluation
- DNS naming collision handling
- route/exit-node toggling logic
- Integration tests:
- 2-node and 3-node mesh connection scenarios
- exit node internet routing
- LAN access on/off behavior validation
- relay fallback behavior under blocked UDP
- tunnel fail-close behavior on drop events
- DNS leak prevention behavior under protected-routing modes
- authentication endpoint abuse/rate-limit behavior
- one-time key race/concurrency (TOCTOU) resistance
- protocol-filter enforcement correctness for shared subnet-router and shared-exit contexts
- trusted-state unavailable behavior (must fail closed where trust is required)
- privileged-helper command-input safety tests
- Security tests:
- invalid token rejection
- key revocation propagation
- unauthorized route access attempts
- replay-attempt rejection and CSRF defense validation
- tamper-evident audit log integrity verification
- secret-redaction coverage across all ingestion paths (MDM/env/CLI/API/UI)
- Performance tests:
- daemon idle CPU and memory budget checks
- reconnect latency benchmarks
- policy/route apply latency benchmarks
- throughput overhead benchmarks against baseline
- benchmark matrix coverage checks and 24-hour soak stability checks

## 13) Operational Requirements
- Single binary per component where practical.
- Systemd service files for Linux deployment.
- Structured logging (JSON option).
- Metrics endpoint (Prometheus format preferred).
- Backup/restore strategy for control-plane state.

## 14) Suggested Next Steps
1. Approve the 9-phase split and lock phase boundaries.
2. Build execution backlog for Phases 1-3 (foundations, identity/control, Linux data plane).
3. Define milestone acceptance tests per phase before coding each phase.
4. Track phase handoff risks explicitly (security, modularity, API coupling).
5. Run recurring roadmap reviews to keep `Requirements.md` and phase docs synchronized.

## 15) Cross-Document Consistency Rules
- Requirement changes here must trigger updates in [Phase1.md](./Phase1.md), [Phase2.md](./Phase2.md), [Phase3.md](./Phase3.md), [Phase4.md](./Phase4.md), [Phase5.md](./Phase5.md), [Phase6.md](./Phase6.md), [Phase7.md](./Phase7.md), [Phase8.md](./Phase8.md), [Phase9.md](./Phase9.md), or [phase10.md](./phase10.md) where applicable.
- Phase documents may add implementation detail, but may not relax security, ACL, or modular-backend requirements defined here.
- Transport backend abstraction and protocol-agnostic control-plane design are mandatory across all phases.

## 16) Battle-Tested Lessons Applied
- Keep the cryptographic core small, auditable, and protocol-conservative (WireGuard principle).
- Protect handshake/control paths against unauthenticated flood and state-exhaustion attacks with cheap early-drop controls (WireGuard/OpenVPN lesson).
- Treat relays and coordination as untrusted for traffic confidentiality, and preserve end-to-end encryption guarantees (WireGuard/Tailscale principle).
- Enforce strict key lifecycle hygiene (short-lived credentials, revocation, and rotation), especially for automation credentials (Tailscale lesson).
- Enforce explicit policy behavior and test policy changes continuously before release (Tailscale lesson).
- Detect and mitigate routing/DNS leak classes across operating systems (OpenVPN TunnelCrack-era lesson).
- Maintain aggressive patching, security advisories, and staged rollout practices to handle real-world vulnerabilities quickly (OpenVPN operational lesson).
- Keep algorithm policy modern and remove weak/legacy options over time (strongSwan/OpenVPN lesson).
