# Rustynet Code Map

Symbol-level reference for AI agents: key types, traits, functions, and where they live.

## Architecture Layers

```
┌─────────────────────────────────────────────────┐
│  CLI / UX Layer                                  │
│  rustynet-cli (ops, vm-lab, orchestrator)        │
│  rustynet-operator (wizards, config)             │
├─────────────────────────────────────────────────┤
│  Domain Layer (transport-agnostic)               │
│  rustynet-control (membership, enrollment, roles)│
│  rustynet-policy (ACL, policy eval)              │
│  rustynet-dns-zone (Magic DNS)                   │
│  rustynet-crypto (signing, key types)            │
├─────────────────────────────────────────────────┤
│  Daemon Layer                                    │
│  rustynetd (WG mgmt, STUN, gossip, killswitch)   │
│  rustynet-relay (frame forwarding)               │
├─────────────────────────────────────────────────┤
│  Backend Abstraction Layer                       │
│  rustynet-backend-api (Backend trait)            │
│  rustynet-backend-wireguard (kernel WG)          │
│  rustynet-backend-userspace (boringtun)          │
│  rustynet-backend-stub (test stub)               │
├─────────────────────────────────────────────────┤
│  Platform Layer                                  │
│  rustynet-windows-native (WFP, DPAPI, pipes)     │
│  rustynet-local-security (ACL verifiers)         │
│  rustynet-sysinfo (OS detection, interfaces)     │
└─────────────────────────────────────────────────┘
```

## Key Types by Domain

### Identity & Membership (`rustynet-control`)

| Type | Location | Purpose |
|---|---|---|
| `MembershipBundle` | `src/membership.rs` | Signed membership snapshot — the core state object |
| `MembershipSnapshot` | `src/membership.rs` | Unsigned pre-image of a bundle |
| `MembershipUpdateRecord` | `src/membership.rs` | Proposed change to membership (add/remove peer, change capabilities) |
| `NodeId` | `src/node_id.rs` | Unique node identifier |
| `MembershipOwnerKey` | `src/membership.rs` | The signing key for bundles |
| `EnrollmentToken` | `src/enrollment.rs` | One-time HMAC token for device onboarding |
| `ReplayWatermark` | `src/membership.rs` | Epoch-based anti-replay protection |

### Roles (`rustynet-control`)

| Type | Location | Purpose |
|---|---|---|
| `NodeRole` | `src/role_presets.rs` | Enum: Relay, Anchor, Exit, BlindExit, Client, Admin |
| `RolePreset` | `src/role_presets.rs` | Pre-composed capability sets for each role |
| `validate_transition()` | `src/role_presets.rs` | **Authoritative** transition validation — gatekeeper for all role changes |
| `is_supported_for_platform()` | `src/role_presets.rs` | Per-platform role eligibility |

### Policy (`rustynet-policy`)

| Type | Location | Purpose |
|---|---|---|
| `Policy` | `src/types.rs` | ACL policy definition (tags, rules, src/dst) |
| `PolicyEngine` | `src/eval.rs` | Evaluates policy against membership + traffic context |
| `Route` | `src/types.rs` | Route advertisement (exit node advertises subnets) |

### Advisor (`rustynet-advisor`)

| Type | Location | Purpose |
|---|---|---|
| `compute_role_score()` | `src/lib.rs` | Weighted-sum MCDA over one candidate's observations (FIS-0005) |
| `recommend_role_placement()` | `src/lib.rs` | Ranked, deterministic role-placement recommendation; empty input recommends nobody |
| `CandidateObservation` | `src/lib.rs` | Per-node placement signals (permille ratios; `None` = no evidence, never fabricated) |

### Backend Abstraction (`rustynet-backend-api`)

| Type | Location | Purpose |
|---|---|---|
| `Backend` trait | `src/lib.rs` | The interface every transport backend implements |
| `BackendConfig` | `src/lib.rs` | Configuration passed to backend at init |
| `TransportSocket` | `src/lib.rs` | The shared UDP socket for direct + relay paths |
| `PeerEndpoint` | `src/lib.rs` | Candidate endpoint (v4/v6 host/srflx/relay) |

### Daemon (`rustynetd`)

| Type | Location | Purpose |
|---|---|---|
| `DaemonRuntime` | `src/daemon.rs` | Main daemon state machine — owns all subsystems |
| `GossipNode` | `src/gossip_runtime.rs` | Per-peer gossip logic (sequence, replay ledger, re-push) |
| `StunClient` | `src/stun_client.rs` | STUN binding request → srflx candidate |
| `RelayClient` | `src/relay_client.rs` | Attaches to authoritative transport, sends keepalive |
| `PortMappingSupervisor` | `src/port_mapper.rs` | PCP → NAT-PMP → uPnP lifecycle |
| `CandidateSet` | `src/dataplane_candidates.rs` | Gathered v4/v6 host + srflx candidates |
| `Killswitch` | `src/killswitch.rs` | Pre-start + post-start killswitch (nftables/WFP/pf) |
| `MacosPfLoadSpec` | `src/macos_pf_load_spec.rs` | Structured spec for the `macos-pf-load` privileged builtin — daemon sends params, root helper re-renders the `pf` rule text + owns the `pfctl -f` (closes the `pfctl -f` boundary) |
| `ReconnectPolicy` + `next_reconnect_delay_jittered_ms` | `src/resilience.rs` | Shared backoff primitive (deterministic ceiling + AWS Full Jitter, FIS-0016). Adoption rule: any NEW reconnect loop with inter-attempt delays MUST use the jittered fn; existing spec-timed ladders / condition-polls / local-race retries stay independent per the FIS-0016 classification |

### Live-lab stage contract (`rustynet-cli/src/`)

| Type | Location | Purpose |
|---|---|---|
| `StageSpec` + `STAGES` | `live_lab_stage_registry.rs` | Single owner of the live-lab stage vocabulary: names, aliases, groups, CSV column mappings, enablement rules, budgets, `proves` control-IDs |
| `StageStatus` | `live_lab_stage_registry.rs` | Closed terminal-state taxonomy for recorded stage outcomes |
| `StageManifest` | `live_lab_stage_manifest.rs` | Run-scoped resolved plan written to `<report_dir>/orchestration/stage_manifest.json` at run start |
| `LiveLabRunMatrixRowRole` | `live_lab_run_matrix.rs` | Interim/final row ownership for the run-matrix upsert-by-run-key |

### Orchestrator (`rustynet-cli/src/vm_lab/orchestrator/`)

| Type | Location | Purpose |
|---|---|---|
| `NodeAdapter` trait | `adapter/node_adapter.rs` | Per-OS adapter interface — install, membership, traffic, validators |
| `NodeConnection` enum | `connection.rs` | Transport injection: Ssh, Adb, Mdm |
| `OrchestrationStage` trait | `stage/mod.rs` | Single stage in the orchestration pipeline |
| `PlanBuilder` | `plan.rs` | Builds the stage execution plan from role assignments |
| `LinuxNodeAdapter` | `adapter/linux.rs` | Full Linux adapter |
| `WindowsNodeAdapter` | `adapter/windows.rs` | Windows adapter (PowerShell-based) |
| `MacosNodeAdapter` | `adapter/macos.rs` | macOS adapter |
| `node_adapter_for()` | `adapter/factory.rs` | Factory: (platform, connection) → NodeAdapter |

### Security Verifiers (`rustynet-local-security`)

| Type | Location | Purpose |
|---|---|---|
| `RuntimeAcls` check | linux/windows subcommands | File permission verification |
| `KeyCustody` check | linux/windows subcommands | OS-secure key storage verification |
| `ServiceHardening` check | linux/windows subcommands | Service unit/SCM hardening |
| `DnsFailclosed` check | linux/windows subcommands | DNS leak prevention verification |

## Common Import Patterns

```rust
// Domain types (safe to use anywhere)
use rustynet_control::membership::{MembershipBundle, MembershipSnapshot};
use rustynet_control::role_presets::{NodeRole, validate_transition};
use rustynet_policy::eval::PolicyEngine;

// Backend types (only in backend crates)
use rustynet_backend_api::Backend;

// Daemon types (only in daemon/CLI)
use rustynetd::daemon::DaemonRuntime;

// Crypto (anywhere that needs signing/verification)
use rustynet_crypto::{SigningKey, VerificationKey, verify_detached};

// Never import backend-specific types in domain crates:
// ❌ use rustynet_backend_wireguard::... in rustynet-control
```

## Where To Add New Code

| If you're adding... | Put it in... |
|---|---|
| A new WireGuard feature | `rustynet-backend-wireguard` or `rustynet-backend-userspace` |
| A new policy rule | `rustynet-policy/src/eval.rs` |
| A new node role | `rustynet-control/src/role_presets.rs` (add variant, update matrix) |
| A new daemon subsystem | `rustynetd/src/<subsystem>.rs` + wiring in `daemon.rs` |
| A new CLI subcommand | `rustynet-cli/src/ops_<name>.rs` or `src/vm_lab/` |
| A new security verifier | `rustynet-local-security` + per-OS adapter |
| A new orchestration stage | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/<name>.rs` |
| A new MCP tool | `crates/rustynet-mcp/src/bin/<server>.rs` |

## Key Files For Common Tasks

| Task | Files to touch |
|---|---|
| Add enrollment feature | `rustynet-control/src/enrollment.rs`, `rustynetd/src/daemon.rs`, `rustynet-cli/src/main.rs` |
| Fix a killswitch bug | `rustynetd/src/killswitch.rs` (all platforms), `rustynet-windows-native/` (WFP) |
| Add a role | `rustynet-control/src/role_presets.rs`, `rustynet-cli/src/vm_lab/orchestrator/role.rs`, `rustynet-cli/src/role_cli.rs` |
| Add a backend | New crate in `crates/`, impl `Backend` trait |
| Wire a new CLI flag | `rustynetd/src/daemon.rs` (flag def), `rustynet-cli/src/main.rs` (CLI wiring) |
| Add a live-lab stage | New `stage/<name>.rs`, register in `plan.rs`, add to `stage/mod.rs` |

## The `fail_closed` Call Sites

When working on trust/security paths, every call site that reads state must
fail closed. The canonical pattern lives in `rustynetd/src/daemon.rs` — look
for the `force_fail_closed` helper. There are 44 call sites; 10 were
discarded (RN-03, open P0). When adding a new trust-sensitive path, add
the fail-closed guard.

## The Gate Pipeline

```
cargo fmt --all -- --check       (formatting)
→ cargo check --workspace        (compilation)
→ cargo clippy --workspace       (lints)
→ cargo test --workspace         (tests)
→ cargo audit --deny warnings    (vulnerabilities)
→ cargo deny check               (dependency policy)
```

Convenience: `cargo run -p rustynet-xtask -- gates`
Fast skip: `cargo run -p rustynet-xtask -- gates --skip-test`
