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
│  rustynet-crypto (signing, key types, custody)   │
│  rustynet-advisor (role-placement scoring)       │
├─────────────────────────────────────────────────┤
│  Daemon + Services Layer                         │
│  rustynetd (WG mgmt, STUN, gossip, killswitch)   │
│  rustynet-relay (frame forwarding)               │
│  rustynet-nas (storage, per-peer namespaces)     │
│  rustynet-llm-gateway (inference identity auth)  │
├─────────────────────────────────────────────────┤
│  Backend Abstraction Layer                       │
│  rustynet-backend-api (TunnelBackend)            │
│  rustynet-backend-wireguard (per-OS WG adapters, │
│    shared userspace engine)                      │
│  rustynet-backend-userspace (boringtun wrapper)  │
│  rustynet-backend-stub (test stub)               │
├─────────────────────────────────────────────────┤
│  Platform Layer                                  │
│  rustynet-windows-native (WFP, DPAPI, pipes)     │
│  rustynet-local-security (ACL verifiers)         │
│  rustynet-sysinfo (OS detection, interfaces)     │
│  rustynet-mobile-ffi (mobile C ABI, JNI shim)    │
├─────────────────────────────────────────────────┤
│  Tooling (not part of the shipped runtime)       │
│  rustynet-mcp (MCP servers)                      │
│  rustynet-xtask (gate runner)                    │
│  rustynet-netns-probe (lab STUN/NAT probes)      │
│  rustynet-lab-monitor (standalone TUI; its own   │
│    workspace, excluded from `--workspace`)       │
└─────────────────────────────────────────────────┘
```

## Key Types by Domain

### Identity & Membership (`rustynet-control`)

| Type | Location | Purpose |
|---|---|---|
| `SignedMembershipUpdate` | `src/membership.rs` | Signed membership change — the core state object (replaced the former `MembershipBundle`) |
| `MembershipState` | `src/membership.rs` | The verified signed membership snapshot (carries `tombstones`, always canonicalised, required on parse) |
| `MembershipTombstoneRecord`, `TombstoneAuthority` | `src/membership.rs` | Retired identity `(node_id, pubkey)` + who retired it; `AddNode` of a tombstoned id/key is owner-gated; only the owner-only `MembershipOperation::PruneTombstones` removes rows (`MembershipTombstoneDesign_2026-09-08.md`) |
| `MembershipSignature` | `src/membership.rs` | Ed25519 signature carried by a signed update |
| `MembershipUpdateRecord` | `src/membership.rs` | Proposed change to membership (add/remove peer, change capabilities) |
| `NodeId` | `rustynet-backend-api/src/lib.rs` | Unique node identifier (there is **no** `control/src/node_id.rs`) |
| `MembershipOwnerKey` | `rustynet-cli/src/vm_lab/orchestrator/` (error, adapters) | Orchestrator-side membership owner-key material — **not** in `rustynet-control` |
| `EnrollmentToken` | `rustynetd/src/enrollment_token.rs` | One-time HMAC token for device onboarding |
| `MembershipWatermark` | `src/membership.rs` + `src/key_rotation.rs` (`PerEpochReplayWatermark`) | Epoch-based anti-replay protection (replaced the former `ReplayWatermark`) |

### Roles (`rustynet-control`)

| Type | Location | Purpose |
|---|---|---|
| `RolePreset` | `src/role_presets.rs` | The 9-value role enum: Client, Admin, Exit, BlindExit, Relay, Anchor, Nas, Llm, BlindRelay (`BlindRelay` is the gated, design-stage privacy-preserving relay preset — `BlindRelayRoleDesign_2026-08-27.md`) |
| `PrimaryRole` / `Capability` | `src/role_presets.rs` | The two axes behind a preset: the local primary role (`Admin \| Client \| BlindExit \| BlindRelay`) and the composable signed mesh capabilities |
| `RolePresetComposition` | `src/role_presets.rs` | The capability-set composition attached to each role preset |
| `RoleAuditEntry` / `RoleTransitionEvent` | `src/role_audit.rs` | D12.e tamper-evident audit log for node-role transitions |
| `SubflowStep` / `NodeTransitionState` | `src/role_signing_subflow.rs` | D-4a pure step sequencer for the capability-signing sub-flow of `SignedMembership` role transitions (ordering + fail-closed + recovery directives) |
| `RoleCapability` | `src/roles.rs` | The membership-side capability enum (Anchor, ExitServer, RelayHost, ServesNas, ServesLlm, BlindRelay, …). **Append-only**: its derived ordering feeds the canonical signed pre-image, so reordering variants silently changes signed payloads |
| `NodeRole` | `rustynetd/src/daemon.rs` + `rustynet-operator/src/role.rs` | Running node role in the daemon/operator (the control crate uses `RolePreset`) |
| `validate_transition()` | `src/role_presets.rs` | **Authoritative** transition validation — gatekeeper for all role changes |
| `is_supported_for_platform()` | `rustynet-cli/src/vm_lab/orchestrator/role.rs` | Per-platform role eligibility (not in `rustynet-control`) |

### Control-plane modules (`rustynet-control/src/`)

`lib.rs` owns the bundle-issuing core; the sibling modules below are declared in
`lib.rs`. `main.rs` is a tiny scaffold binary (prints a ready banner; no
operational surface).

| Module / type | Location | Purpose |
|---|---|---|
| `ControlPlaneCore` + `TrustState` (`persist_trust_state`/`load_trust_state`) | `src/lib.rs` | Control-plane core and its persisted trust state; issues the signed bundles below |
| `SignedAutoTunnelBundle` / `SignedEndpointHintBundle` / `SignedRelayFleetBundle` / `SignedTraversalCoordinationRecord` / `SignedPeerMap` | `src/lib.rs` | The signed artifacts the control plane issues (assignment, traversal hints, relay fleet, coordination records) |
| `RelaySessionToken` + `relay_session_token_to_wire` / `parse_relay_session_token_wire` | `src/lib.rs` | Relay session token v1 mint/parse (the relay checks it in `rustynet-relay/src/transport.rs`) |
| `AuthSurfaceGuard` / `ApiAbuseMonitor` / `ThrowawayCredentialStore` / `PolicyGuard` / `NodeRegistry` | `src/lib.rs` | Auth-surface rate limiting + lockout, abuse alerts, throwaway-credential lifecycle, policy check wrapper, node registry |
| `AdminAuthorizer` + `AdminAction` | `src/admin.rs` | Admin RBAC (`Viewer`/`Operator`/`Admin`, MFA-verified principal) |
| `BlindRelayLegTokenV2` / `BlindRelayHelloV2` / `BlindRelayFleetDescriptorV2` | `src/blind_relay.rs` | Blind-relay protocol v2 wire types (canonical line grammar); production advertisement is gated off (design-stage) |
| `CredentialUnwrapBackend` (+ `LinuxSystemdCredsBackend`, `MacosKeychainBackend`, `WindowsDpapiBackend`) | `src/credential_unwrap.rs` | Cross-platform unwrap of the membership owner's signing-key passphrase for owner-signed mutations |
| `EnrolleeAdmitContext` | `src/enrollment.rs` | D2.7 enrollment-to-membership bridge: admits a consumed enrollment token into signed membership |
| `ApiVersion` / `CompatibilityPolicy` / `CryptoDeprecationCalendar` / `InsecureCompatibilityException` | `src/ga.rs` | GA compatibility window, crypto-deprecation calendar, and the time-bounded insecure-compatibility exception (the crypto crate itself carries no exception facility) |
| `RotationEpoch` / `VerifierArchive` / `PerEpochReplayWatermark` | `src/key_rotation.rs` | Local-node key rotation lifecycle primitives and per-epoch replay watermark |
| `ManagedDnsHandoffDecision` | `src/managed_dns_handoff.rs` | D-6b managed-DNS handoff decision |
| `TandemMode` / `TandemTogglePhase` | `src/tandem_dns.rs` | D-6a RustyDNS tandem toggle surface + fail-closed state machine (control plane only) |
| `TandemDnsRedirectDecision` | `src/tandem_dns_redirect.rs` | D-6c transparent `:53` redirect decision over the tandem toggle state |
| `StructuredLogger` / `HealthSnapshot` / `AuditEntry` | `src/operations.rs` | Redacting structured logging, health/diagnostics snapshots, audit entries |
| `SqliteStore` | `src/persistence.rs` | Control-plane SQLite store (behind the `persistence` cargo feature); refuses a DB path or `-wal`/`-shm` sidecar that is a symlink or has insecure mode/owner (RSA-0017). Schema migrations live in `crates/rustynet-control/migrations/` |
| `ValueCipher` / `ValueAad` | `src/atrest.rs` | AQ-45 value-level at-rest sealing for `control.db` (XChaCha20-Poly1305 envelope bound to database/table/column/row via AAD); sealing primitives only |
| `ControlDbKeySource` / `OsSecureStoreControlDbKeySource` | `src/atrest_key.rs` | AQ-45 step 2: the value-encryption key lives in the OS secure store (never in the DB, a config file, or a passphrase); `load_or_provision` |
| `HaCluster` / `ControlPlaneReplica` / `TenantRole` | `src/scale.rs` | HA replica selection and tenant-scoped authorization |

### Policy (`rustynet-policy`)

Note: `rustynet-policy` is a single-file crate (`src/lib.rs`) — there is **no** `types.rs` or `eval.rs`.

| Type | Location | Purpose |
|---|---|---|
| `PolicySet` | `src/lib.rs` | Ordered set of `PolicyRule` entries forming the ACL policy |
| `PolicyRule` | `src/lib.rs` | Single ACL rule (tags, src/dst, disposition) |
| `AccessRequest` | `src/lib.rs` | Evaluator input: membership identity + traffic context |
| `ContextualPolicySet` / `ContextualAccessRequest` | `src/lib.rs` | Context-aware (traffic-context) variant of the evaluator |
| `MembershipDirectory` | `src/lib.rs` | Membership-status lookup the evaluator consults |
| `LlmAccessScope` / `LlmScopePolicy` | `src/lib.rs` | `llm`-role per-peer scopes; scopes only ever narrow an allow |
| `PolicyRolloutController` | `src/lib.rs` | Canary → promote → rollback policy revisions; refuses allow-all, duplicate ids, and rollback to a never-promoted revision |
| `Route` | `rustynet-backend-api/src/lib.rs` | Route advertisement (exit node advertises subnets) |

### Crypto (`rustynet-crypto`)

Two files: `src/lib.rs` and `src/mlkem.rs` (+ `src/mlkem/tests.rs`).

| Type / fn | Location | Purpose |
|---|---|---|
| `PublicKey` / `SecretKey` / `NodeKeyPair` | `src/lib.rs` | Key types (`SecretKey::ct_eq` is constant-time) |
| `AlgorithmPolicy` / `CryptoAlgorithm` | `src/lib.rs` | Pure default-deny algorithm allow-list (RSA-0003: the crypto-layer compatibility-exception facility was deleted; exceptions are governed in `rustynet-control/src/ga.rs`) |
| `MlKem768EncapsulationKey` / `MlKem768DecapsulationKey` / `MlKemSharedSecret` + `generate_keypair` / `derive_tunnel_psk` | `src/mlkem.rs` | AQ-35 ML-KEM-768 (FIPS 203) encapsulation and the HKDF-SHA256 tunnel-PSK derivation; the raw shared secret has no `Debug`/`Clone`/byte accessor, so `derive_tunnel_psk` is the only way to a PSK |
| `KeyCustodyManager<S: OsSecureStore>` + `OsStoreFallbackPolicy` | `src/lib.rs` | Key custody: OS-secure store first, encrypted-at-rest fallback only per policy |
| `PlatformOsSecureStore` / `NoOsSecureStore` + `store_macos_generic_password*` / `load_macos_generic_password*` | `src/lib.rs` | OS secure-store adapters (macOS Keychain helpers live here) |
| `encrypt_private_key_envelope` / `decrypt_private_key_envelope` / `write_encrypted_key_file` | `src/lib.rs` | Encrypted-at-rest key envelope |
| `aead_seal` / `aead_open` (`AeadSealedBlob`) | `src/lib.rs` | AEAD sealing primitive |
| `SigningProvider` trait + `Ed25519SigningProvider` + `SigningProviderPolicy` + `create_provider_attestation` / `verify_provider_attestation` | `src/lib.rs` | Signing provider abstraction and attestation |
| `KeyCustodyPermissionPolicy` + `validate_key_custody_permissions` / `windows_key_custody_sddl_is_hardened` | `src/lib.rs` | Key-file permission policy (Unix mode/owner; Windows SDDL hardening checks) |

### Relay (`rustynet-relay`)

Binary `rustynet-relay` is built only with the `daemon` feature
(`required-features`); the library re-exports the session/transport types.

| Type / module | Location | Purpose |
|---|---|---|
| `RelayNode` / `RelayFleet` / `RelaySelectionPolicy` | `src/lib.rs` | Fleet + selection types |
| `RelayHello` / `RelayHelloAck` / `RelayTransport` / `RelayForwardTarget` | `src/transport.rs` | Relay session authentication and bidirectional ciphertext frame forwarding |
| `RelaySession` / `SessionId` | `src/session.rs` | Session tracking and pairing |
| `RateLimiter` | `src/rate_limit.rs` | Token-bucket rate limiting per session |
| `run_hello_limiter_flood_audit` | `src/hello_limiter_audit.rs` | DOS-1 adversarial self-audit: a pre-auth flood of distinct `node_id`s against `HelloLimiter::check` (`src/transport.rs`) must not grow the limiter's map without bound |
| `BlindAdmissionObserver` / `BlindRejectReason` / `BlindListenerOpenError` | `src/blind_relay_listener.rs` | Blind-relay v2 admission listener (phase 4); dormant — gated off from production |
| daemon (`main.rs`) | `src/main.rs` | The relay server binary (`daemon` feature); carries its own `PreAuthHelloLimiter` |

### Advisor (`rustynet-advisor`)

| Type | Location | Purpose |
|---|---|---|
| `compute_role_score()` | `src/lib.rs` | Weighted-sum MCDA over one candidate's observations (FIS-0005) |
| `recommend_role_placement()` | `src/lib.rs` | Ranked, deterministic role-placement recommendation; empty input recommends nobody |
| `CandidateObservation` | `src/lib.rs` | Per-node placement signals (permille ratios; `None` = no evidence, never fabricated) |

### Backend Abstraction (`rustynet-backend-api`)

| Type | Location | Purpose |
|---|---|---|
| `TunnelBackend` trait | `src/lib.rs` | The interface every transport backend implements (formerly named `Backend`) |
| `BackendCapabilities` | `src/lib.rs` | Static capabilities a backend advertises at init |
| `RuntimeContext` | `src/lib.rs` | Runtime context passed to the backend at init |
| `PeerConfig` | `src/lib.rs` | Per-peer configuration for the managed tunnel |
| `SocketEndpoint` | `src/lib.rs` | Candidate endpoint (v4/v6 host/srflx/relay) |

### WireGuard Backend (`rustynet-backend-wireguard`)

| Type | Location | Purpose |
|---|---|---|
| `LinuxWireguardBackend` / `MacosWireguardBackend` / `WindowsWireguardBackend` | `src/linux_command.rs`, `src/macos_command.rs`, `src/windows_command.rs` | Command-driven per-OS adapters that drive OS tooling (`ip`/`wg` on Linux) through an argv-only `WireguardCommandRunner`; `SAFE_BRINGUP_TUNNEL_MTU` and `bringup_tunnel_mtu` live in `linux_command.rs` |
| `LinuxUserspaceSharedBackend` / `MacosUserspaceSharedBackend` | `src/userspace_shared/`, `src/userspace_shared_macos/` | The shared userspace (boringtun) dataplane engine that owns the peer sockets (the "authoritative shared transport"); `rustynet-backend-userspace::UserspaceBackend` wraps these |
| `WireguardBackend` + `RecordedAuthoritativeTransportOperation` | `src/in_memory.rs` | The base `WireguardBackend`; also defines the recorded authoritative-transport operation types the tests assert on |
| `UdpOffloadCapabilities` / `probe_udp_offload_capabilities` | `src/udp_offload_probe.rs` | FIS-0028 Phase 1: read-only detection of `sendmmsg`/`recvmmsg`/`UDP_SEGMENT`/`UDP_GRO` support (kernel-release gate + socket2 plumbing smoke-check); not called from any packet path |

### Daemon (`rustynetd`)

| Type | Location | Purpose |
|---|---|---|
| `DaemonRuntime` | `src/daemon.rs` | Main daemon state machine — owns all subsystems |
| `DnsProbeServicer` + `DnsResponderState` | `src/daemon.rs` | M1 ordering fix (MacosClientResolverNotServingDiagnosisReview_2026-09-02 §3.3): `run_daemon` binds the resolver socket BEFORE `bootstrap()` and installs the servicer (hoisted `Arc<UdpSocket>` + a pre-zone-load responder snapshot). The macOS probe's wait window (`verify_loopback_resolver_live`) drains the SAME socket through `build_dns_response_with` — the one hardened responder the main loop also drains — so an in-bootstrap `FullyProtected` probe is answered without a second DNS implementation or fallback branch. Socket identity is the only equality (`UdpSocket` has no value equality) |
| `GossipNode` | `src/gossip_runtime.rs` | Per-peer gossip logic (sequence, replay ledger, re-push) |
| `StunClient` | `src/stun_client.rs` | STUN binding request → srflx candidate |
| `RelayClient` | `src/relay_client.rs` | Attaches to authoritative transport, sends keepalive |
| `PortMappingSupervisor` | `src/port_mapper.rs` | PCP → NAT-PMP → uPnP lifecycle |
| `CandidateSet` | `src/dataplane_candidates.rs` | Gathered v4/v6 host + srflx candidates |
| Killswitch (no single struct — `src/killswitch.rs` was removed) | `src/killswitch_precedence.rs`, `src/linux_killswitch_boot.rs`, `src/macos_exit_killswitch_precedence.rs`, `src/windows_killswitch_smoke.rs` | Pre-start + post-start killswitch (nftables/WFP/pf) split into the shared precedence model (`killswitch_precedence.rs`) plus per-OS apply/boot/smoke modules |
| `ShutdownResidueMarker` + `ResidueScan` | `src/shutdown_residue.rs` | QH-40: durable, schema-versioned "the last shutdown left dataplane residue" marker written beside the daemon state file when `Phase10Controller::shutdown` fails. Never cleared automatically (only `rustynetd shutdown-residue-check --acknowledge`); an undecodable or unknown-schema marker fails closed as `ResidueScan::Unreadable`, never as `Clean`. Consumed by the daemon at startup (grep token `shutdown_rollback_residue_detected`) and by the read-only `shutdown-residue-check` probe, which exits `ExitCode::PolicyReject` (78) on residue |
| `RuleDisposition` + `terminator_is_reachable` + `ContainedInterfaces` | `src/killswitch_precedence.rs` | S2: the shared precedence model for killswitch containment — walks a chain as an ORDERED rule list and asks whether the terminal drop/block is actually REACHABLE, not merely present. Transport-agnostic core (pf and nftables differ in syntax, not precedence semantics); each backend supplies a `classify` closure. `Escapes` is the fail-closed default, so an unrecognised rule withholds the containment verdict. `nft_chain_rules_in_evaluation_order` moves an nft chain `policy` last, since nft PRINTS it above the rules but APPLIES it below them. Used by `linux_ipv6_leak` (IPV-03), `macos_exit_killswitch_precedence` (PF-05), `macos_blind_exit` (PF-11), and `phase10::assert_firewall_ruleset` (RN-27) |
| `DnsPosture` + `macos_dns_posture` | `src/phase10.rs` | The three-state macOS DNS posture (MacosClientDnsFailclosedDiagnosis_2026-09-02 §6, review A1): `FullyProtected` (full machine-wide fail-closed posture — exit/full-tunnel nodes), `ScopedResolverOnly` (plain mesh client — ONLY the scoped `/etc/resolver/rustynet` file, no general pins/floor/primary rewrite), `Untouched` (reserved for the `protected_dns=false` opt-out; never returned by the decision fn). `apply_dns_protection_for_posture` dispatches per posture (trait default forwards to full protection; `RuntimeSystem` forwards arm-by-arm so the posture cannot be silently dropped); macOS hardening: `verify_loopback_resolver_live` (in-apply UDP probe before any mutation; probe wait drains the daemon's hoisted socket via the M1 `DnsProbeServicer` when installed — same responder, existing 2 s bound), `verify_live_pf_dns_floor` (live anchor rules after load), `apply_scoped_resolver_only` (probe + stranded-pin refusal + fail-closed scoped write), `has_live_loopback_dns_pins` (fail-closed pin latch in `killswitch_spec` so no pf re-render drops the floor under live pins), all-or-nothing rollback on any incomplete step. `assert_dns_protection` branches on the installed posture. Posture-split invocation timing (review §3.3): `ApplyOptions::defer_scoped_dns_posture` (bootstrap-time applies only) skips the scoped sub-apply so the first reconcile pass — serve loop live — applies it via the `dns_posture_reassert_pending` latch; `FullyProtected` stays in-bootstrap (M1 hoisted bind + probe servicer). A scoped `DnsApplyFailed` failure takes the daemon's M3 DNS-degraded branch (no restriction, latch re-armed, `dns_scoped_apply_degraded` surfaced); `FullyProtected` failures keep the full restriction ladder |
| `MacosDnsFailclosedReport` (posture-aware) + `evaluate_macos_dns_failclosed_snapshot_for_posture` + `parse_macos_dns_posture` | `src/macos_dns_failclosed.rs` | Posture-scoped DNS failclosed verifier (review A7): schema_version 2 embeds the `posture` the report was evaluated FOR; `FullyProtected` keeps the original seven-condition contract UNCHANGED, `ScopedResolverOnly` requires the scoped resolver present + zero loopback general pins + readable enumeration (machine resolv.conf/scutil/pf deliberately not demanded), `Untouched` always drifts. Posture is THREADED from the node's planned role (daemon check `--posture`, orchestrator stage, CLI evaluator mismatch rejection) — never inferred from the observed state |
| `wfp_filter_shape` | `rustynet-windows-native/src/lib.rs` | WIN-03: portable validation of a read-back WFP filter's SHAPE (action == PERMIT, exactly one condition, `IP_LOCAL_INTERFACE`, LUID == tunnel). Deliberately OUTSIDE the `#[cfg(windows)]` FFI shim so it is tested on every CI leg — the shim marshals, this decides. Constants are drift-pinned to `windows_sys` by `const` assertions on the Windows build |
| `MacosPfLoadSpec` | `src/macos_pf_load_spec.rs` | Structured spec for the `macos-pf-load` privileged builtin — daemon sends params, root helper re-renders the `pf` rule text + owns the `pfctl -f` (closes the `pfctl -f` boundary) |
| `ReconnectPolicy` + `next_reconnect_delay_jittered_ms` | `src/resilience.rs` | Shared backoff primitive (deterministic ceiling + AWS Full Jitter, FIS-0016). Adoption rule: any NEW reconnect loop with inter-attempt delays MUST use the jittered fn; existing spec-timed ladders / condition-polls / local-race retries stay independent per the FIS-0016 classification |
| `PathMtuDiscovery` + `PathMtuConfig` | `src/path_mtu.rs` | FIS-0027 Phase 1: pure RFC 8899 DPLPMTUD per-path MTU search machine (no I/O, no clocks; Base → Searching → SearchComplete, blackhole → Base). PTB is advisory-only (can never raise or override a confirmed value); unconfirmed ⇒ 1280 floor. Probe carriage (Phase 3) and dynamic apply (Phase 4) not yet wired. Static bring-up MTU (`SAFE_BRINGUP_TUNNEL_MTU`, 1420) is set by the `rustynet-backend-wireguard` per-OS command adapters (Phase 2) |
| `AnchorTlsIdentity` + `AnchorCertResolver` | `src/anchor_tls.rs` | QH-26: anchor control-plane TLS 1.3 identity — self-signed identity generation/reload with POSIX-mode custody (fails closed off-Unix), rustls server config without `tls12`; test-only `PinnedFingerprintVerifier` |

#### Daemon module families (`rustynetd/src/`)

`rustynetd/src/lib.rs` declares every module below as `pub mod`, with four
exceptions: `macos_pf_mesh_cidr` and `macos_utun_helper_unsafe` are
`pub(crate)`, `lab_substrate_transit` exists only on Linux under the
default-off `lab-substrate` feature, and `witness_listing` is a `#[cfg(test)]`
module. Per-OS files are named `<os>_<concern>.rs`.

| Family / module | Location | Purpose |
|---|---|---|
| `IpcCommand` + `parse_command` / `IpcResponse` / `RemoteCommandEnvelope` | `src/ipc.rs` | The daemon's local IPC command grammar and response; `remote-op-v1` envelope for remote ops |
| `PrivilegedCommandProgram` / `PrivilegedCommandClient` / `PrivilegedHelperConfig` | `src/privileged_helper.rs` | The privileged-helper boundary: argv allowlist, client, and server config (the only path to root-level system mutation) |
| `StateFetcher` + `WatermarkStore` + `RefreshScheduler` | `src/fetcher.rs` | Control-plane state fetcher with signature verification and watermark anti-replay |
| key custody helpers (`read_passphrase_file`, `decrypt_private_key`, `store_passphrase_in_os_secure_store`, `export_gossip_verifying_key_hex`) | `src/key_material.rs` | Runtime key-passphrase and private-key material handling |
| `TraversalEngine` + `CandidateGatherer` + `TraversalSession` + `EndpointMonitor` | `src/traversal.rs` | Signed-hint traversal engine: candidate gathering, probe plans, simultaneous open, direct/relay path state, flap breaker, path-quality tracking |
| `PrioritizedCandidate` / `CandidatePair` / `IceRole` | `src/ice_priority.rs` | D5.5 ICE-style candidate prioritisation (RFC 8445) |
| `PeerTraversalPrior` + `PeerPriorStore` | `src/peer_traversal_prior.rs` | FIS-0009 cross-session NAT-traversal priors |
| `KeepaliveEstimator` | `src/keepalive.rs` | FIS-0015 per-mapping censored-gap keepalive-interval estimator |
| `GossipBundle` + `SeenSequenceState` | `src/peer_gossip.rs` | D2.5 peer-distributed signed-bundle gossip (the pure logic; `GossipNode` in `gossip_runtime.rs` drives it) |
| `GossipTransport` | `src/gossip_transport.rs` | D2.5 UDP transport for gossip |
| `ConsumeOutcome` / `PushAddressPolicy` | `src/enrollment_consume.rs` | D2.7 enrollment-token consume + gossip-peer registration |
| `ExposedService` + `ServiceExposureController` + `ServiceHostingView` | `src/service_exposure.rs` | D13.b shared secure-exposure plumbing for the `nas`/`llm` roles |
| `ServiceAccessSnapshot` | `src/service_access_state.rs` | D13 per-service access-state derivation + atomic materialisation |
| `AnchorPortMappingStatusReport` | `src/anchor_port_mapping_status.rs` | Anchor port-mapping-authority status check |
| `load_coordination_replay_store` / `persist_coordination_replay_store` | `src/coordination_replay_store.rs` | RSA-0029 durable seen-nonce store for the traversal coordination replay window, so a daemon restart cannot reopen the replay window |
| `apply_startup_hardening` + `MemoryHygieneOutcome` | `src/core_hardening.rs` | AQ-40 Linux core-dump / debugger hygiene at daemon startup (keeps in-memory key material out of dumps) |
| `resolve_enrollment_secret` / `classify_enrollment_secret_location` / `migrate_plaintext_secret_to_keystore` | `src/enrollment_secret_custody.rs` | AQ-68 OS-keystore custody for the anchor-enrollment minting secret; a plaintext secret file is refused unless explicitly allowed; migration is the explicit `rustynet enrollment migrate-secret` step |
| `validate_terminate_wireguard_go_args` | `src/wireguard_go_terminate.rs` | RSA-0033 purpose-built privileged termination of `wireguard-go` processes (replaced a generic privileged `kill`) |
| `lab_substrate_transit` | `src/lab_substrate_transit.rs` | LAB-ONLY (feature `lab-substrate`, Linux): vxlan cross-network substrate transit attestation; host side is `ops vm-lab-write-substrate-transit` / `-remove-substrate-transit` |
| `ExitCode` | `src/exit_codes.rs` | X6 shared CLI exit-code taxonomy (`CliExitCodeTaxonomy.md`) |
| `ClientPlatform` + `validate_platform_parity` | `src/platform.rs` | Client-platform integration-status parity validation |
| `WindowsBackendMode` + `require_supported_windows_backend` | `src/windows_backend_gate.rs` | Windows backend label gate (`windows-unsupported` vs `windows-wireguard-nt`) |
| Windows host surface: `windows_service`, `windows_ipc`, `windows_paths`, `windows_runtime_boundary`, `windows_tunnel_smoke` | `src/windows_*.rs` | SCM service host, named-pipe IPC policy, reviewed `C:\ProgramData\RustyNet\…` path roots, runtime-boundary self-check, WireGuard-NT tunnel bring-up smoke |
| macOS utun fd-passing helper (`macos_utun_helper` client, `macos_utun_helper_server`, `macos_utun_helper_unsafe` SCM_RIGHTS companion) | `src/macos_utun_helper*.rs` | Privileged utun device handoff on macOS |
| `MetricRow` + `phase1_baseline_metrics` | `src/perf.rs` | Phase 1 baseline metric rows and report writer |
| Per-OS **verifiers** (read-only checks that emit evidence): `{linux,macos,windows}_runtime_acls`, `_key_custody`, `_service_hardening`, `_mesh_status`, `_dns_failclosed`, `_authenticode` (Linux/macOS are stubs), `windows_registry_acls`, `windows_backend_readiness`, `linux_runtime_nftables` | `src/<os>_<concern>.rs` | What the `rustynetd <os>-<concern>-check` subcommands (e.g. `linux-runtime-acls-check`) and the live-lab `role_validation/` stages invoke on a node |
| Per-OS **exit / blind-exit dataplane**: `linux_exit_nat_lifecycle`, `macos_exit_nat` + `macos_exit_nat_lifecycle`, `windows_exit_nat_lifecycle`, `{linux,macos}_exit_dns_failclosed`, `{linux,macos}_ipv6_leak`, `linux_blind_exit` + `linux_blind_exit_dataplane`, `macos_blind_exit`, `linux_conntrack_flush`, `linux_firewalld_zone`, `macos_pf_mesh_cidr` | `src/<os>_<concern>.rs` | Exit-NAT policy and lifecycle artefact producers, exit-mode DNS fail-closed, IPv6 leak captures, `blind_exit` firewall policy + dataplane verifier |
| Per-OS **DNS protection**: `linux_dns_protect`, `macos_dns_sc_protect`, `{linux,macos}_tandem_dns_redirect` | `src/<os>_<concern>.rs` | Protected-mode DNS enforcement (systemd-resolved / System Configuration) and the RustyDNS tandem transparent redirect rendering |
| `unix_shutdown_signals` | `src/unix_shutdown_signals.rs` | Unix graceful-shutdown signal scaffolding |
| Adversarial **self-audits** (`*_audit.rs`): `blind_exit_reversal_audit` (RT-2), `enrollment_replay_audit` (ENR-1), `gossip_revoked_readmit_audit` (GM-1), `membership_revoke_audit` (RSA-0009), `membership_signature_audit`, `policy_default_deny_audit`, `privileged_helper_allowlist_audit`, `revoked_peer_denied_audit` (DD-03/RSA-0007), `secret_log_audit` (X3 no-secret-leakage; its reviewed redacting-`Debug` registry is cross-checked by the test-only `witness_listing`, AQ-213) | `src/*_audit.rs` | Each proves a landed fix still holds by driving the real code path adversarially; wired into the `scripts/ci/` gates |

### Mobile FFI (`rustynet-mobile-ffi`)

`std`-only crate (cdylib + rlib) for the Android/iOS native shells
(`scripts/mobile/check-mobile-deps.sh` enforces the no-extra-dependency rule).
It is the one place in the mobile tree where `unsafe` is permitted: its
manifest downgrades the workspace `unsafe_code = "forbid"` to `deny`, every
unsafe site is narrowly `#[allow]`ed with a `// SAFETY:` comment, and
`scripts/ci/mobile_unsafe_confinement_gate.sh` pins the census.

| Item | Location | Purpose |
|---|---|---|
| `RN_MOBILE_ABI_VERSION` / `MobileStatus` / `rn_mobile_start_raw_fd` / `rn_mobile_stop` | `src/c_abi.rs` | C ABI v1: integer-only exports with stable status codes and defined descriptor-ownership rules; the engine is not wired yet (returns `Unsupported`) |
| `guard` / `guard_u32` | `src/panic.rs` | Panic containment: every export runs under `catch_unwind`; a panic becomes a status code |
| JNI shim skeleton | `src/jni_shim.rs` | Android JNI forwarding shim; holds no logic |

### Service-Hosting Roles (`rustynet-nas`, `rustynet-llm-gateway`)

| Type | Location | Purpose |
|---|---|---|
| `rustynet-nas` | `crates/rustynet-nas/` | NAS service-hosting role: tunnel-only storage exposure, per-peer namespace isolation via FUSE/chroot, at-rest encryption, RustyBackup client contract. Binary `rustynet-nas`. |
| `rustynet-llm-gateway` | `crates/rustynet-llm-gateway/` | LLM service-hosting role: identity-from-tunnel gateway in front of a loopback inference engine. No API keys. gRPC/HTTP-2 token streaming as plaintext inside WireGuard tunnel. RustyAI client contract. Binary `rustynet-llm-gateway`. |

### Lab Tooling (`rustynet-netns-probe`)

| Type | Location | Purpose |
|---|---|---|
| `rustynet-netns-probe` | `crates/rustynet-netns-probe/` | LAB TOOLING (not shipped): Rust-native STUN responder + NAT mapping/filtering probes for the `--node` cross-network netns simulator. Replaces former python3 scripts. `std`-only (offline-buildable). STUN wire byte-pinned to `rustynetd`'s `stun_client.rs`. |

### CLI modules (`rustynet-cli/src/`)

`main.rs` is the `rustynet` binary (`OpsCommand` enum + `execute_ops`
dispatcher; the lab variants are `vm-lab`-gated, see below). `lib.rs` is a
small library surface: `role_cli` always, plus the lab tree under `vm-lab`.
`src/bin/` holds the large family of standalone evidence/gate binaries
(`check_*`, `*_gates`, `phase*`, `live_*`), auto-discovered by Cargo.

| Module | Location | Purpose |
|---|---|---|
| `role_cli` | `role_cli.rs` | D12.b `rustynet role …` orchestrator and the pure role-transition planner; shared by `src/bin/rustynet-windows-trust-cli.rs` so there is one planner |
| `llm_cli` | `llm_cli.rs` | D13.d `rustynet llm` admin verbs |
| `AnchorInitPlan` / `build_anchor_init_plan` | `anchor_init.rs` | Anchor-init step plan |
| `format_env_assignment` / `parse_env_value` | `env_file.rs` | Quoted `EnvironmentFile` writer/parser shared by the install and refresh paths |
| `execute_ops_install_systemd` + exit/relay/service siblings | `ops_install_systemd.rs`, `ops_install_systemd_exit.rs`, `ops_install_systemd_relay.rs`, `ops_install_systemd_service.rs` | `ops install-systemd` (what `scripts/systemd/install_rustynetd_service.sh` dispatches to) and the install/uninstall of the exit, relay, and nas/llm sibling units |
| macOS launchd installers | `ops_install_macos_anchor.rs`, `ops_install_macos_exit.rs`, `ops_install_macos_relay.rs` | Install/uninstall the `com.rustynet.{anchor,exit,relay}` launchd services |
| `execute_ops_write_daemon_env` | `ops_write_daemon_env.rs` | Writes the daemon environment file |
| `execute_ops_peer_store_validate` / `_list` | `ops_peer_store.rs` | Peer-store inspection |
| network-discovery bundle validation | `ops_network_discovery.rs` | `ops validate-network-discovery-bundle` |
| Phase 1 / 9 / 10 gate and evidence commands | `ops_phase1.rs`, `ops_phase9.rs`, `ops_ci_release_perf.rs` | Rust implementations behind the thin `scripts/ci/`, `scripts/operations/`, `scripts/release/` wrappers |
| Security-audit workflow commands | `ops_security_audit.rs`, `ops_security_audit_workflows.rs`, `security_audit_catalog.rs` | Attack-matrix / live-lab findings / comparative-coverage generation and the check-metadata catalog |
| `self_exec` | `self_exec.rs` | Stable re-execution target for flows that spawn `rustynet` self-ops (a replaced on-disk binary reports `<path> (deleted)` via `current_exe()`) |
| `ops_control_surface_expected_set` | `ops_control_surface_expected_set.rs` | CS4 opt-in expected-listener-set control-surface check (owner approval required before it is made active; reachable only through `live_linux_control_surface_exposure_test --expected-listener-set`) |
| `ops_vm_lab_substrate_transit` | `ops_vm_lab_substrate_transit.rs` | `ops vm-lab-write-substrate-transit` / `ops vm-lab-remove-substrate-transit`: host side of the vxlan substrate-transit attestation the daemon's `lab-substrate` feature requires |
| `check_vendored_unsafe_counts` (bin) | `bin/check_vendored_unsafe_counts.rs` | Vendored `third_party/` unsafe-census drift gate against `third_party/UNSAFE_COUNTS.pinned` (`scripts/ci/vendored_unsafe_drift_gate.sh`) |
| `text_truncate` | `text_truncate.rs` | Char-boundary-safe clipping for evidence text (a byte-offset slice inside a multi-byte char would panic on exactly the failure-explaining paths) |

### Live-lab stage contract (`rustynet-cli/src/`)

RNQ-17: everything in this section — plus `vm_lab/`, `ops_live_lab_orchestrator.rs`,
`ops_cross_network_preflight.rs`, `ops_fresh_install_os_matrix.rs`,
`ops_live_lab_failure_digest.rs`, `live_lab_coverage.rs`, `live_lab_results.rs`,
the `vm-lab`-gated lab `OpsCommand` variants, and the `zip`/`toml`/`socket2`/`signal-hook`
deps — compiles only under the DEFAULT-OFF `vm-lab` cargo feature of
`rustynet-cli`. The shipped release binary (no features) has no lab command
surface; lab hosts/guests build with `--features vm-lab`. `ops_e2e.rs` and
`ops_cross_network_reports.rs` stay unconditionally compiled (product paths call
them: traversal-bundle refresh + Windows role-transition service actions, and
the phase9/phase10 readiness validators respectively) but their lab-facing
command surface is gated. Shared secret/nonce/time helpers live in
`secret_material.rs` (moved verbatim out of `main.rs`). Under `vm-lab` the
LIBRARY additionally compiles the vm_lab tree and re-exports the runner surface
as `rustynet_cli::orchestrator_test_surface` (RNQ-09 integration-test hook).

| Type | Location | Purpose |
|---|---|---|
| `StageSpec` + `STAGES` | `live_lab_stage_registry.rs` | Single owner of the live-lab stage vocabulary: names, aliases, groups, CSV column mappings, enablement rules, budgets, `proves` control-IDs |
| `StageStatus` | `live_lab_stage_registry.rs` | Closed terminal-state taxonomy for recorded stage outcomes |
| `StageManifest` | `live_lab_stage_manifest.rs` | Run-scoped resolved plan written to `<report_dir>/orchestration/stage_manifest.json` at run start |
| `LiveLabRunMatrixRowRole` | `live_lab_run_matrix.rs` | Interim/final row ownership for the run-matrix upsert-by-run-key |

### Orchestrator (`rustynet-cli/src/vm_lab/orchestrator/`)

| Type | Location | Purpose |
|---|---|---|
| `NodeAdapter` trait + `RoleValidatorKind` | `adapter/node_adapter.rs` | Per-OS adapter interface — install, membership, traffic, and typed OS-specific validator dispatch |
| `NodeConnection` enum | `connection.rs` | Transport injection: Ssh, Adb, Mdm |
| `OrchestrationContext` | `context.rs` | In-memory stage context plus persisted setup/run split state at `<report_dir>/state/orchestration_context.json` |
| `OrchestrationStage` trait | `stage/mod.rs` | Single stage in the orchestration pipeline |
| `define_stage_catalog!` / `StageId` / `StageSuite` | `stage/mod.rs` | The single typed stage authority (RNQ-16): one catalog row per stage = variant + canonical pipeline order + wire name + suite tag; plan build, mode filtering, suite lists, registry rust-native predicate, and matrix oracle derive from it |
| `PlanBuilder` | `plan.rs` | Builds the stage execution plan from role assignments, including live-suite, soak, cross-network, and chaos selectors |
| `StateMachineRunner` | `runner.rs` | Validated dependency-ordered stage runner; explicit omissions are `NotRun`, while prior stages become `Reused` only after sealed-evidence validation |
| Bounded node executor | `parallel.rs` | Deterministic, worker-capped, cancellation-aware per-node fanout |
| Rust-native readiness gate | `readiness.rs` | Local-UTM discovery, selected-node readiness, targeted restart, and rediscovery before stage execution |
| Rust-native failure diagnostics | `diagnostics.rs` | Fatal signal registration and pre-cleanup daemon/artifact capture |
| `execute_rust_native_orchestration()` + plan glue | `native.rs` | The `--node` engine entry point: mode validation, context load/bind, platform-selector role election, stage-plan construction/filtering, network-profile record (RNQ-15 extraction from `vm_lab/mod.rs`) |
| `RustNativeStageRecorder` + evidence finalization | `evidence.rs` | Realtime `stages.tsv` observer, per-stage logs, node-stage plan, `run_summary.json`/`nodes.tsv`, failure digest, report-state writers, reuse-evidence seal/validation (RNQ-15 extraction) |
| `LinuxNodeAdapter` | `adapter/linux.rs` | Full Linux adapter |
| `WindowsNodeAdapter` | `adapter/windows.rs` | Windows adapter (PowerShell-based) |
| `MacosNodeAdapter` | `adapter/macos.rs` | macOS adapter; exit-serving methods assert the daemon's own pf lifecycle verifier (A2-ordered precedence baseline inside `activate_exit_serving`) |
| `assess_exit_snapshot` / `parse_macos_pf_state_translation_line` / `select_macos_client_nat_state(_by_range)` / `evaluate_macos_exit_egress_evidence` + the A2 `MacosExitActivationSequence` driver, `capture_exit_snapshot`/`assert_exit_snapshot_serving`, `run_killswitch_precedence_baseline`, `activate_exit_serving`/`assert_exit_actively_serving`/`assert_mesh_client_nat_session` | `adapter/macos_exit_traffic.rs` | macOS exit-serving adapter core: daemon-snapshot asserting (no CLI pf parsing/mutation), validated-argv dispatch, the §5/A2 pre-activation-only precedence experiment with its restore-proof snapshot, and the pf-state client-NAT correlation |
| `validate_linux_exit_nat_lifecycle` / `validate_macos_exit_nat_lifecycle` | `role_validation/exit_nat_lifecycle.rs` | Two-phase snapshot→stop→snapshot→merge→evaluate exit NAT lifecycle proof per platform |
| `node_adapter_for()` | `adapter/factory.rs` | Factory: (platform, connection) → NodeAdapter |
| `ValidatedArg`/`ValidationError` + per-class validators, `validate_ip_arg`/`validate_utun_name`/`validate_windows_path` hoists | `adapter/validated_args.rs` | QH-01 validated-argument seam: the one home for per-class orchestrator argument validators (reject before any command string is built), plus the Step-5 pin tests (private `RemoteCommand` field; raw sink-call-site count may only go down) |
| `NetLeafRunner` / `SubstrateHandle` / `CrossNetworkSubstrateProvider` | `stage/cross_network/substrate.rs` | Cross-network substrate seam (CN-1/CN-2/CN-4): argv-only `ip`/`nft` leaf-op runners (local, remote-shell, mock), the provisioned-topology handle with its overlay/underlay `endpoint()` planes, the `NatProfileId`/`Support` honest-skip gate, `NatModifiers`/`SiteRef`/`NatApplyError` + `apply_nat_profile` (CN-4), `VxlanSubstrateProvider` with its router-namespace NAT boundary, the two topology-level lifecycle stages, and the `topology_level_seam()`/`provider_for_record()` dispatch |
| `NetnsSubstrateProvider` + `run_nat_gates` | `stage/cross_network/netns.rs` | Tier-A netns "internet in a box" (CN-2): namespace/bridge/NAT topology and the NAT mapping + filtering gates, ported from the deleted `netns_nat_classify.sh`/`netns_nat_filter.sh` and from `netns_internet_sim.sh` onto `NetLeafRunner`; CN-4 added the `rnsim-cgn-*` `double_nat_cgnat` carrier chain |
| `SlirpSubstrateProvider` | `stage/cross_network/slirp.rs` | Tier-C cross-OS smoke substrate (CN-4): provisions nothing (the NAT belongs to UTM `Shared Network`), verifies each participant's default route really goes via the slirp gateway, and claims no NAT profile because the type is not selectable |

### Scenario evidence framework (`rustynet-cli/src/vm_lab/orchestrator/`)

The truth-preserving oracle (`LiveLabTestCoverageImplementationDesign_2026-08-19`,
L0/L1): a `--node` run's pass is **independently re-derived from raw witnesses**,
not taken from the finalizer's own structural self-count. A stage emits a
`scenario.v1` referencing raw artifacts; the finalizer resolves it to an
independent contract and recomputes each required assertion.

| Type | Location | Purpose |
|---|---|---|
| `RunInstanceId` + `ReportDirLease` + `read_leased_run_instance_id()` | `run_instance.rs` | CSPRNG 128-bit generation binding + exclusive report-dir flock lease; the lease stamp (`state/.orchestrator.lock`) is the single canonical source a control reads its `run_identity` from (fail-closed) |
| `AssertionClass` / `StageContract` / `ScenarioEvidenceContract` / `AdmissionContract` | `stage/scenario/mod.rs` | Framework contract types — what KIND of proof each assertion carries and the typed admission/evidence a stage declares (consulted independently of anything the scenario self-reports) |
| `ScenarioV1` + `write_scenario_v1()` + `scenario_v1_path()` | `stage/scenario/schema.rs` | The `scenario.v1` on-disk schema and its atomic, fail-closed writer; one document per scenario at `<report_root>/scenarios/<stage_id>/scenario.v1.json`, referencing raw artifacts by relative path + sha256 |
| `validate_artifact()` + `ValidatedArtifact` | `stage/scenario/artifact.rs` | Containment-safe artifact validation (no absolute/`..`/symlink escape, byte budget, digest-bound) — an unverifiable artifact is never evidence |
| `PassCertificate` + `evaluate()` + `Recomputer` | `stage/scenario/pass_certificate.rs` | The SOLE gate that mints a pass: contract+generation binding, per-required-assertion artifact validation, and an independent `Recomputer` re-deriving each claim. No recomputer ⇒ `NotProven`, never a pass |
| `ScenarioContractRegistry` + `resolve_for()` | `stage/scenario/registry.rs` | The independent source-of-truth contract per stage (never read from a run artifact); a scenario whose stage is unknown or whose contract digest mismatches cannot certify a pass |
| `EvidenceVerdict` + `from_assessment()`/`bound()`/`run_level()` + `authorize_release()` | `stage/scenario/verdict.rs` | The durable `evidence_verdict.v1.json`; a `ReleaseAuthorization` (the `run_passed=true` gate) exists only for a Passed verdict bound to this run+plan digest |
| `evaluate_wired_scenarios()` + `wired_scenarios()` | `stage/scenario/finalize.rs` | The finalizer bridge (first non-test caller of `evaluate`): evaluates EVERY wired control's emitted scenario, demotes the run if any fails even when structurally green, aggregates the contract + artifact map |
| Negative-control T5 stages + `signed_bundle` emission/recomputers | `stage/negative_control.rs` | The four T5 deliberate-inversion controls; the two LOCAL ones (signed-bundle forgery, wrong-node substitution) emit `scenario.v1` + a time-stable verifier transcript their recomputers re-classify (never re-run the verifier — fixtures embed absolute timestamps) |
| HP-3 relay-frame-forwarding proof | `stage/relay_forwards_frame_validation.rs` | OPT-IN disruptive stage (`StageSuite::Disruptive`, `--enable-relay-forwarding-validation`): reuses the `vm_lab` relay-forward helper chain (topology election, script builders, nft peer blocks, counter-delta + ciphertext-only assertions, cleanup) to prove the relay forwards a frame between two peers; absent from the default plan |

### Orchestrator support modules and stage families (`rustynet-cli/src/vm_lab/`)

The remaining `vm_lab/` modules and the families of files under
`orchestrator/stage/`, `orchestrator/role_validation/` and
`orchestrator/adapter/`. A stage lives in `stage/<name>.rs`; most have an
offline decision core in `role_validation/<name>.rs` (or a `*_eval.rs` module)
so the pass/fail logic is unit-testable without a lab.

| Module / family | Location | Purpose |
|---|---|---|
| `TopologyProfile` / `TopologyRole` / `parse_topology_profile_file` | `vm_lab/topology.rs` | Cross-platform topology selection (`--topology-profile`) |
| `VmLabCapabilityStatus` / `VmLabCapabilityScope` | `vm_lab/capability.rs` | Pure capability evaluator behind `ops vm-lab-report-capabilities` |
| `canonical_guest_keys` / `GuestClaimRefs` + lock dir | `vm_lab/run_exclusion.rs` | QH-18 guest-scoped mutual exclusion between live-lab runs |
| `SprtClassifier` / `CusumDetector` | `vm_lab/run_history.rs` | FIS-0006 flake-vs-regression classifier over the run matrix |
| `execute_ops_vm_lab_overnight` + `agent` / `backlog` / `executor` / `safety` / `scheduler` / `manifest` | `vm_lab/overnight/` | The `ops vm-lab-overnight` unattended driver: frontier backlog of (platform, role) cells, scheduler, safety envelope, one fresh agent per work-unit; contains no LLM client |
| `VmBootstrapProvider` per-OS bootstrap phases | `vm_lab/bootstrap/mod.rs`, `vm_lab/bootstrap/windows.rs` | `ops vm-lab-bootstrap-phase` provider; the Windows file drives the PowerShell-first helper scripts |
| `RemoteShellHost` trait | `orchestrator/remote_shell.rs` | Cross-platform remote-shell seam for substages (tests in `remote_shell_tests.rs`) |
| `NodeRoleAssignment` / `parse_node_role_arg` / `translate_legacy_role_flags` | `orchestrator/role_assignment.rs` | `--node <alias>:<role>` parsing and legacy per-role flag translation |
| `PlanSelection` / `ResolvedPlan` / `StageGraph` | `orchestrator/resolved_plan.rs` | Plan resolution to an immutable, digest-stamped plan before any mutation (L0.4) |
| `SourceArchive` | `orchestrator/source_archive.rs` | The local working-tree tarball shipped to remote nodes (held in `OrchestrationContext`) |
| `LiveLabRunReport` / `StageReport` | `orchestrator/report.rs` | Run/stage report model |
| `ParityDiff` + `build_live_lab_run_report` | `orchestrator/parity.rs` | W5.5 cross-orchestrator parity diff (`ops vm-lab-emit-parity-input`, `ops vm-lab-diff-orchestrator-parity`) |
| Per-OS install/membership/traffic adapters | `orchestrator/adapter/{linux,macos,windows}_{install,membership,traffic}.rs` | The per-OS halves behind `LinuxNodeAdapter` / `MacosNodeAdapter` / `WindowsNodeAdapter`; `ssh.rs` is the SSH transport, `android.rs`/`ios.rs` are present-but-unsupported platform adapters, `verifier_key.rs` decodes relay-deploy verifier keys |
| Setup stages | `stage/{preflight,verify_ssh,source_archive,collect_pubkeys,membership_init,distribute_*,refresh_signed_bundles,install,enforce_runtime,validate_runtime,bundle_evidence}.rs` | Preflight → source archive → bootstrap → membership → signed-bundle distribution → runtime enforcement + baseline validation |
| Role/OS validation stages | `stage/*_validation.rs` with `role_validation/*.rs` | Cross-OS validators (mesh status, key custody, runtime ACLs, service hardening, DNS fail-closed, exit NAT lifecycle, IPv6 leak, authenticode, gossip convergence, blind-exit dataplane, exit-demotion residue, security audit) |
| Live suite stages | `stage/live_*_validation.rs`, `stage/{active_exit,exit_handoff,role_switch_matrix,relay_validation,deploy_relay,traffic_test_matrix,live_anchor,blind_exit,admin_issue}.rs` | Two-hop, managed DNS, LAN toggle, reboot recovery, network flap, key custody, secrets-not-in-logs, mixed topology, extended soak, enrollment restart, hello-limiter flood |
| macOS-specific stages | `stage/macos_*.rs` | macOS anchor profile deploy / bundle pull / port-mapping authority, role transition, reboot recovery |
| Lab-host safety and attestation stages | `stage/cloud_node_safety.rs`, `stage/underlay_attestation.rs`, `stage/node_diagnostics.rs` | Safety net for cloud nodes managed over a tailnet, `dataplane_endpoint` underlay attestation (AQ-254), best-effort per-node network diagnostics capture on failure |
| Exit/peer-path witnesses | `stage/exit_egress_leak_witness.rs` + `role_validation/exit_egress_leak_witness.rs`, `stage/peer_direct_not_via_exit_validation.rs` + `role_validation/peer_direct_not_via_exit.rs` | AQ-46 exit-egress leak witness (tcpdump on the exit's egress NIC) and the peer-direct-not-via-exit capture validator |
| Lab-only seams | `adapter/macos_manifest_seam.rs`, `adapter/linux_relay_tokens.rs` | LAB-ONLY throwaway per-run release-manifest signing for macOS installs; Linux side of the preissued relay session-token spool (HP-3) |
| Chaos, cleanup | `stage/chaos.rs`, `stage/cleanup.rs`, `stage/final_cleanup.rs` | Opt-in chaos suite; always-run teardown |
| Negative controls | `stage/negative_control*.rs` | T5 deliberate-inversion controls (enrollment-token replay, killswitch bypass, rogue anchor bundle, wire forgery) — see the scenario framework above |
| Cross-network scenarios | `stage/cross_network/scenario/*.rs` | Rust ports of the former cross-network shell validators (direct/relay remote exit, failback roaming, controller/endpoint/node-network switch, remote-exit DNS and soak, traversal adversarial, ACL-deny failover) plus their offline `*_verdict.rs` / `*_eval.rs` cores |

### VM-lab host-script renderer (`rustynet-cli/src/vm_lab/script_template.rs`)

The single audited boundary between a Rust value and a shell script that runs on a
lab host (QH-01). Host scripts were previously rendered by ordered `str::replace`
chains at the call site, which carried command-injection breakouts; every render
site now goes through this module.

| Type | Location | Purpose |
|---|---|---|
| `ScriptTemplate` | `script_template.rs` | Newtype over the template text with a **private field and no constructor**, so no other module can build one and `render_script_template` is its only consumer. The boundary is enforced by the compiler, not by a lint or a grep |
| `Binding` | `script_template.rs` | How one substituted value is spelled: `Literal` (`shell_quote`d), `Bare` (`[A-Za-z0-9._-]+`, unquoted positions), `QuotedWords`, `RawFragment` (verbatim syntax; confined to `DefaultHostSshPath`'s constants), `HeredocBody` (terminator/newline rule), `PowerShellLiteral`. **The variant is the safety argument** — which control applies depends on the sink context, so it has to be carried in the type (QH-19) |
| `render_script_template` | `script_template.rs` | Single-pass substitution that never re-scans emitted bytes, so substitution order cannot matter and a token appearing inside a value is inert literal text |
| `DefaultHostSshPath` | `script_template.rs` | The only inhabitants are three associated constants (private field, no constructor), which is what confines `RawFragment` — the one binding with no validation. `&'static str` alone does **not** mean "literal" (`String::leak`); verified by negative compile (`E0603`) |
| `render_host_*_script` / `render_*_repair_script` | `script_template.rs` | The named per-template render functions — the only way to reach a template. Includes the three `sudo bash -s` guest-repair scripts used by `recover_guest_network.rs`. All return `RenderedScript` |
| `RenderedScript` | `script_template.rs` | The typed renderer OUTPUT (QH-01 Step 4d-i): private field, no `From<String>`/`Display`, length-only `Debug`, constructed only by `render_script_template`. The adapter seam's `RemoteCommand::from_rendered` / `PowerShellScript::from_rendered` accept only this type; pinned by `rendered_script_is_constructed_only_inside_script_template` (whole-`src/` source scan) |
| `HOST_GUEST_CONSOLE_SCRIPT` | `script_template.rs` | The documented exception: `script -qec` re-parses its argument in a nested shell, so escaping at interpolation is **not** sufficient there — the nested command string is single-quoted and the value passed via the environment |
| `no_script_template_is_declared_outside_this_module` | `script_template.rs` | Backstop test for a second renderer appearing elsewhere. Its known holes (only `r#"…"#` raw strings, uppercase tokens, literal `.replace`/`.replacen` text) are enumerated in its doc — the type boundary is the control, this is a net |

### VM-lab network profile + audit (`rustynet-cli/src/vm_lab/`)

Read-only Slice A of the VM connectivity rulebook
(`documents/operations/LiveLabVmConnectivityRulebook.md` §15): typed profiles,
observation, drift detection, redacted evidence. No mutation path exists here.

| Type | Location | Purpose |
|---|---|---|
| `NetworkProfile` + `NetworkProfileId` + `parse_network_profile_toml` | `network_profile.rs` | Strict fail-closed TOML manifest model (`profiles/vm_lab/network/*.toml`) with canonical `sha256:` digest over the validated representation |
| `AttachmentMode` / `ManagementPolicy` / `ScenarioSubstrate` / `InternetMode` / `EvidenceTier` | `network_profile.rs` | Typed vocabulary for the dual-plane lab-network architecture |
| `NetworkEvidenceStatus` | `network_profile.rs` | External status vocabulary (`pass`/`fail`/`not_run`/`not_supported`/`expected_fail`); `skipped` is internal-only |
| `backend_attachment_support` / `backend_multi_nic_support` | `network_profile.rs` | The conservative UTM QEMU/Apple capability matrix (`IpCidr` is not defined here) |
| `UtmVmObservation` / `HostNetworkObservation` / `GuestNetworkObservation` | `network_audit.rs` | Redacted-by-construction observations of UTM configs (via `plutil -extract`), host routes/VPN/proxy, and guest addresses/routes/DNS/MTU |
| `detect_*_findings` + `overall_status_from_findings` | `network_audit.rs` | Pure drift/overlap/duplicate/stale detection (mixed attachments, bridged-to-`en0`, unpinned bridges, duplicate MAC/IP, stale `network_group`, netns transit vs mesh `100.64.0.0/10` collision) |
| `execute_ops_vm_lab_network_audit` / `..._preflight` | `network_audit.rs` | `ops vm-lab-network-audit` (report) and `ops vm-lab-network-preflight` (fail-closed gate); both write atomic owner-only `state/vm_network_evidence.json` behind a serialized-secret guard |
| `NetworkTransactionEngine` + `TxnStep` + `NetworkTxnJournal` | `network_prepare.rs` | The ONLY sanctioned VM network mutation path (Slice B): journal-driven step machine, auto-rollback with byte-digest verification, resumable after interruption |
| `NetworkMutationPort` (`LiveUtmMutationPort` + test mock) | `network_prepare.rs` | Side-effect seam: utmctl stop/start, stopped-VM-only plist rewrite, restore-bytes, management readiness; fully fault-injectable |
| `LeaseStore` + `NetworkLease` + `ProcessProbe` | `network_prepare.rs` | Atomic network lease: overlapping transactions refused, disjoint allowed, stale recovery via pid+command identity (never pid alone) |
| `execute_ops_vm_lab_network_prepare` / `..._restore` | `network_prepare.rs` | `ops vm-lab-network-prepare` (dry-run plan by default; `--approve-reconfigure` is the explicit mutation boundary) and `ops vm-lab-network-restore` (verified idempotent rollback) |
| `execute_ops_vm_lab_recover_guest_network` | `recover_guest_network.rs` | `ops vm-lab-recover-guest-network`: recover a vmnet guest that lost its IPv4 lease (stale netplan MAC-pin) with no IPv4/agent — resolve `fe80::…%bridgeN` from the NIC MAC via `ndp`/modified-EUI-64, SSH over link-local IPv6, distro-aware DHCP repair (netplan name-match / NetworkManager / systemd-networkd), report + optional inventory-update. `--dry-run` resolves the target without touching the guest. Proven by hand in `LiveLabFindings_2026-07-12.md` |
| `derive_link_local_from_mac` / `find_link_local_by_mac` / `parse_nic_mac_from_config_plist` / `pick_primary_interface` / `corrected_netplan_yaml` / `parse_ipv4_for_interface` | `recover_guest_network.rs` | Pure, unit-tested recovery primitives (MAC→EUI-64 link-local, `ndp -an` parse, plist MAC scan, interface pick, name-matched DHCP netplan render, `ip -4 addr` parse) |

### VM-lab base-image catalog + arch gate (`rustynet-cli/src/vm_lab/image_catalog.rs`)

Step 1 of `HostObservabilityStabilityPlan_2026-07-24.md` §7.9. Fail-closed model
for the tracked catalog at `documents/operations/active/lab_image_catalog.json`,
plus the host/image architecture gate that stops a wrong-architecture image being
provisioned (which otherwise surfaces only as an unreachable guest, minutes later).

| Type | Location | Purpose |
|---|---|---|
| `ImageCatalog` + `CatalogImage` | `image_catalog.rs` | `serde(deny_unknown_fields)` schema v1 model (following the `topology.rs` precedent). Deny-unknown makes a typo'd `arch`/`sha256` key loud, and the derive path rejects a duplicated JSON key instead of silently keeping the last — which on a digest field is a supply-chain hazard |
| `ImageCatalog::validate` | `image_catalog.rs` | Cross-entry rules: non-empty, version pinned to 1, case-insensitive duplicate names refused, and one pool `filename` must describe one file (identical sha256/arch/kind/os) so an alias cannot yield a different verdict for the same bytes |
| `LabArch` / `ImageArch` / `parse_catalog_arch` / `parse_probed_arch` | `image_catalog.rs` | Closed accept-lists with no fallback arm. Catalog values require canonical spelling; probed values are lenient because the fleet really does report `x86_64`/`aarch64`/`arm64`/`AMD64`. ASCII-only case folding, so non-ASCII lookalikes fail closed |
| `ProbedHostArch` | `image_catalog.rs` | Host arch that was established, not assumed: constructible only by `probe_host_arch` or the deliberately-greppable `assumed_by_operator`. Carries provenance so output distinguishes measured from asserted |
| `assert_image_runnable_on` | `image_catalog.rs` | The gate. Takes a parsed `CatalogImage` + `ProbedHostArch`, so "arch matched" is unreachable without both sides parsed, and the entry reported on is the entry checked. Mismatch wording avoids transient-sounding words so `classify_cli_error` maps it to PolicyReject, never a retryable failure |
| `CatalogImage::assert_declared_arch_matches_artifact_naming` | `image_catalog.rs` | Cross-checks the declared `arch` against arch tokens in the filename and the URL's final segment, closing the hole where a hand-typed `"arch": "amd64"` on an `…-arm64.qcow2` passes every other rule and then reports a green gate |
| `probe_host_arch` | `image_catalog.rs` | Measures a host's arch (`uname -m` over SSH for libvirt hosts; the compiled target for the local machine). Fails closed on unreachable/empty/unparseable — there is deliberately no declared-value fallback |
| `execute_ops_vm_lab_image_catalog` | `image_catalog.rs` | `ops vm-lab-image-catalog`. Mode is chosen by an explicit flag, never by absence of one: the ops option parser demotes a value-less `--foo` to a flag and rejects no unknown options, so mode-by-presence would exit 0 with the gate un-run. Prints `GATE: RAN` / `GATE: NOT RUN` |
| `write_inventory_live_ips` | `mod.rs` | Shared inventory live-IP writer (atomic + reload-verify) reused by the local-UTM readiness persister and guest-network recovery |

### Installer engine (`rustynet-cli/src/install/`)

The `rustynet install` verb: detect → preflight/elevation → acquire (verified
binaries) → per-OS live install → fail-closed terminal state. `--dry-run` renders
the plan per OS. Reuses the existing hardened `ops install-*` / `rustynetd key
init` / `key store-passphrase` verbs rather than reinventing them.

| Type | Location | Purpose |
|---|---|---|
| `run` (state machine) + `InstallRequest`/`InstallRole`/`AcquisitionMode`/`TrustAnchorSource` | `install/mod.rs` | Request parse, host detect (`rustynet_sysinfo::host_facts`), plan render, per-OS dispatch |
| `acquire()` (`VerifiedDownload`/`FromDir`/`BuildFromSource`) | `install/acquire.rs` | Stage + integrity-verify the shipping binaries before install (co-located signed manifest) |
| `require_elevation()` | `install/preflight.rs` | Root (Linux/macOS euid==0) / Administrator (Windows) gate; never self-elevate |
| Shared Unix primitives (`command`, `place_binaries`, `deliver_trust_anchor`, `resolve_node_id`, `which`, `run`/`ensure_dir`/`write_file`) | `install/common.rs` | OS-agnostic, argv-only, PATH-pinned exec + §6.B owner-key anchor delivery, shared by Linux + macOS |
| `live_linux::install()` | `install/live_linux.rs` | Linux: apt/dnf prereqs, placement, key custody (`key init` + systemd-creds), `ops install-systemd`, awaiting-enrollment classification |
| `live_macos::install()` | `install/live_macos.rs` | macOS: `wg` prereq, dscl identity, keychain unlock, place + `codesign`, key custody (`key init` + `key store-passphrase`), trust anchor, then gated launchd registration (embeds `Install-RustyNetMacosService.sh` via `include_str!`, `--no-daemon-start`: helper running, daemon plist installed + `launchctl disable`d → awaiting enrollment) |
| `live_windows::install()` | `install/live_windows.rs` | Windows: stages the acquired binaries, delivers the trust anchor, and runs the embedded reviewed service-installer script in its gated no-daemon-start mode (service created but Stopped → awaiting enrollment) |
| `--uninstall` path | `install/uninstall.rs` | `rustynet install --uninstall`: best-effort, idempotent reverse of a live install per OS (services, placed binaries, all local key custody + trust material; the unprivileged service identity is kept) |
| `ReleaseManifest` (ed25519 signed) | `release_manifest.rs` + `ops_release_manifest.rs` | The installer's trust root: `ops create/verify-release-manifest`; per-artifact sha256 verified before staging |

### Security Verifiers (`rustynet-local-security`)

Single-file crate (`src/lib.rs`) holding the Unix local-socket custody
validators (no symlinks, absolute path, socket type, owner/mode of the socket
and its parent directory). The per-OS runtime-ACL / key-custody /
service-hardening / DNS-failclosed **verifiers** are *not* here — they live in
`rustynetd/src/<os>_<concern>.rs` (see "Daemon module families" above).

| Function | Location | Purpose |
|---|---|---|
| `validate_owner_only_socket` | `src/lib.rs` | Owner-only socket + parent-directory mode/ownership check |
| `validate_root_managed_shared_runtime_socket` | `src/lib.rs` | Root-managed, group-shared (expected gid) runtime socket check; both functions fail closed off-Unix (Windows uses named-pipe IPC validation in `rustynetd/src/windows_ipc.rs`) |

### System Diagnostics (`rustynet-sysinfo`)

PKG-G bounded, **observation-only** host diagnostics (routes/interfaces/
DNS/listening-sockets/firewall/service), wired to the read-only CLI command
`rustynet diagnostics` (alias `diag`). Read-only by construction: every
external tool call is gated by a fixed `(program, argv)` read-only
allowlist and spawned under a timeout watchdog; all parsers are pure and
fail-safe. See the `diagnostics.rs` module doc-comment for the full
observation-only + bounded-execution guarantee.

| Type / fn | Location | Purpose |
|---|---|---|
| `observe_system_diagnostics()` | `src/diagnostics.rs` | Entry point: one bounded, observation-only snapshot → `DiagnosticsReport` (real subprocesses) |
| `observe_with(&dyn CommandRunner)` + `render_report()` | `src/diagnostics.rs` | Seam-injectable observe (for tests/custom runners) + human-readable render for the CLI |
| `DiagnosticsReport` | `src/diagnostics.rs` | Typed snapshot: interfaces+MTU, routes, DNS, listening sockets, firewall, Rustynet service |
| `FirewallStatus` + `FirewallBackend` | `src/diagnostics.rs` | Typed firewall status (nftables/iptables/pf/Windows-firewall); `queried` distinguishes confirmed-inactive from could-not-confirm; never carries raw ruleset text |
| `CommandRunner` + `SystemCommandRunner` + `CommandOutcome` | `src/diagnostics.rs` | Bounded command seam: `run_read_only` rejects any non-allowlisted `(program, argv)`; `Completed`/`TimedOut`/`Unavailable`/`RejectedNotAllowlisted` outcomes |
| `DEFAULT_COMMAND_TIMEOUT` | `src/diagnostics.rs` | 3s per-invocation upper bound enforced by `spawn_bounded` |
| `host_facts()` → `HostFacts` (`OsFamily`/`PkgFamily`) | `src/lib.rs` | Installer host detect: OS family / distro / pkg-manager / target-triple |

## Common Import Patterns

```rust
// Domain types (safe to use anywhere)
use rustynet_control::membership::{MembershipState, MembershipUpdateRecord, SignedMembershipUpdate};
use rustynet_control::role_presets::{RolePreset, validate_transition};
use rustynet_policy::{PolicySet, AccessRequest};

// Backend types (only in backend crates)
use rustynet_backend_api::TunnelBackend;

// Daemon types (only in daemon/CLI)
use rustynetd::daemon::DaemonRuntime;

// Crypto (anywhere that needs signing/verification)
use rustynet_crypto::{PublicKey, SecretKey, NodeKeyPair};

// Never import backend-specific types in domain crates:
// ❌ use rustynet_backend_wireguard::... in rustynet-control
```

## Where To Add New Code

| If you're adding... | Put it in... |
|---|---|
| A new WireGuard feature | `rustynet-backend-wireguard` or `rustynet-backend-userspace` |
| A new policy rule | `rustynet-policy/src/lib.rs` |
| A new node role | `rustynet-control/src/role_presets.rs` (add variant, update matrix); the membership-side capability goes in `rustynet-control/src/roles.rs` (`RoleCapability` is append-only) |
| A new daemon subsystem | `rustynetd/src/<subsystem>.rs` + wiring in `daemon.rs` |
| A new CLI subcommand | `rustynet-cli/src/ops_<name>.rs` or `src/vm_lab/` |
| A new `rustynet install` OS/step | `rustynet-cli/src/install/` (shared → `common.rs`, per-OS → `live_<os>.rs`) |
| A new security verifier | `rustynetd/src/<os>_<concern>.rs` + its `rustynetd <os>-<concern>-check` subcommand in `rustynetd/src/main.rs`, then the cross-OS validator `vm_lab/orchestrator/role_validation/<name>.rs` and stage `stage/<name>_validation.rs` (`rustynet-local-security` only holds the Unix socket-custody validators) |
| A new orchestration stage | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/<name>.rs` + one row in `define_stage_catalog!` (`stage/mod.rs`) + an instantiation arm in `PlanBuilder::build` (`plan.rs`) + a `StageSpec` in `live_lab_stage_registry.rs` |
| A new MCP tool | `crates/rustynet-mcp/src/bin/<server>.rs` |
| A new CI gate binary/script | `crates/rustynet-cli/src/bin/check_<name>.rs` (auto-discovered, no `[[bin]]` entry needed) + thin wrapper `scripts/ci/` |

## Key Files For Common Tasks

| Task | Files to touch |
|---|---|
| Add enrollment feature | `rustynetd/src/enrollment_token.rs`, `rustynetd/src/enrollment_consume.rs`, `rustynet-control/src/enrollment.rs`, `rustynetd/src/daemon.rs`, `rustynet-cli/src/main.rs` |
| Fix a killswitch bug | `rustynetd/src/killswitch_precedence.rs`, `rustynetd/src/linux_killswitch_boot.rs`, `rustynetd/src/macos_exit_killswitch_precedence.rs`, `rustynetd/src/windows_killswitch_smoke.rs`, `rustynet-windows-native/` (WFP). If it is an ASSERTION bug, check `rustynetd/src/killswitch_precedence.rs` first — presence-vs-precedence was the same defect at five sites |
| Add a role | `rustynet-control/src/role_presets.rs`, `rustynet-control/src/roles.rs`, `rustynetd/src/daemon.rs` (`NodeRole`), `rustynet-operator/src/role.rs`, `rustynet-cli/src/vm_lab/orchestrator/role.rs`, `rustynet-cli/src/role_cli.rs` |
| Add a backend | New crate in `crates/`, impl `TunnelBackend` trait |
| Wire a new CLI flag | `rustynetd/src/daemon.rs` (flag def), `rustynet-cli/src/main.rs` (CLI wiring) |
| Add a live-lab stage | New `stage/<name>.rs`; add the `define_stage_catalog!` row in `stage/mod.rs` (order, wire name, suite, tier, evidence declaration), the instantiation arm in `plan.rs`, and the `StageSpec` in `live_lab_stage_registry.rs` |

## The `fail_closed` Call Sites

When working on trust/security paths, every call site that reads state must
fail closed. The canonical pattern lives in `rustynetd/src/daemon.rs` — look
for the `force_fail_closed_or_restrict` helper. Every fail-close attempt in the
daemon routes through it (43 call sites at the time of the last audit below); on an
enforcement failure it does not swallow the error — it logs and moves the
daemon to restricted-safe mode. The former discarded-result sites (RN-03) were
fixed — see `SecurityReview_2026-05-24.md` RL-9 — and the unit test
`daemon_does_not_discard_force_fail_closed_results` in `daemon.rs` fails if a
`let _ = …force_fail_closed(…)` discard is reintroduced. When adding a new
trust-sensitive path, add the fail-closed guard.

## The Gate Pipeline

The authoritative definition is `CLAUDE.md` §7; this is the same list with the
flags CI uses:

```
cargo fmt --all -- --check                                            (formatting)
→ cargo check --workspace --all-targets --all-features                (compilation)
→ cargo clippy --workspace --all-targets --all-features -- -D warnings (lints)
→ cargo test --workspace --all-targets --all-features                 (tests)
→ cargo audit --deny warnings                                         (vulnerabilities)
→ cargo deny check bans licenses sources advisories                   (dependency policy)
```

`--workspace` does **not** cover `gui/`, `crates/rustynet-lab-monitor/` or
`fuzz/` (each is its own workspace). Gate them explicitly:
`./scripts/ci/lab_monitor_gates.sh`, `./scripts/ci/fuzz_build_gate.sh`.

Convenience: `cargo run -p rustynet-xtask -- gates`
Fast skip: `cargo run -p rustynet-xtask -- gates --skip-test`
Scope to changed crates plus their reverse-dependents:
`cargo run -p rustynet-xtask -- gates --affected [--base <ref>]` (default base
`origin/main`; falls back to the full workspace when a root build file changed).

## Citation Audit

Last citation audit: 2026-11-01, tree `d54625ff` (the merged base this revision was written against). This revision carries
**no `file.rs:NNN` line-number citations** — all citations are symbol→file
mappings. Every backticked file/directory citation was re-resolved against the
tracked tree (the only non-resolving ones are deliberate references to removed
or runtime-generated paths, each labelled as such: `src/killswitch.rs`,
`control/src/node_id.rs`, `types.rs`/`eval.rs`, the deleted
`netns_nat_classify.sh`/`netns_nat_filter.sh`, `MembershipBundle`,
`ReplayWatermark`, and `state/…` report-directory artifacts). Every symbol in a
type/location row was re-checked against its cited file. Corrections made in
this pass: `RolePreset` is now a 9-value enum (`BlindRelay` added); the
`rustynet-local-security` verifier table described per-OS checks that live in
`rustynetd/src/<os>_<concern>.rs`; the `force_fail_closed_or_restrict`
call-site count/RN-03 status paragraph; the `OpsCommand` count (removed rather
than re-stated); the "add a live-lab stage" steps now follow
`define_stage_catalog!`. Added this pass: control-plane module table, `rustynet-crypto`,
`rustynet-relay`, daemon module families, CLI modules, orchestrator support
modules/stage families, and the tooling crates.
`VerifiedDownload`/`FromDir`/`BuildFromSource` in `install/acquire.rs` are
`AcquisitionMode` enum variants (not standalone defs) — cited correctly.
