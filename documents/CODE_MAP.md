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
│  Daemon + Services Layer                         │
│  rustynetd (WG mgmt, STUN, gossip, killswitch)   │
│  rustynet-relay (frame forwarding)               │
│  rustynet-nas (storage, per-peer namespaces)     │
│  rustynet-llm-gateway (inference identity auth)  │
├─────────────────────────────────────────────────┤
│  Backend Abstraction Layer                       │
│  rustynet-backend-api (TunnelBackend)            │
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
| `SignedMembershipUpdate` | `src/membership.rs` | Signed membership change — the core state object (replaced the former `MembershipBundle`) |
| `MembershipState` | `src/membership.rs` | The verified signed membership snapshot |
| `MembershipSignature` | `src/membership.rs` | Ed25519 signature carried by a signed update |
| `MembershipUpdateRecord` | `src/membership.rs` | Proposed change to membership (add/remove peer, change capabilities) |
| `NodeId` | `rustynet-backend-api/src/lib.rs` | Unique node identifier (there is **no** `control/src/node_id.rs`) |
| `MembershipOwnerKey` | `rustynet-cli/src/vm_lab/orchestrator/` (error, adapters) | Orchestrator-side membership owner-key material — **not** in `rustynet-control` |
| `EnrollmentToken` | `rustynetd/src/enrollment_token.rs` | One-time HMAC token for device onboarding |
| `MembershipWatermark` | `src/membership.rs` + `src/key_rotation.rs` (`PerEpochReplayWatermark`) | Epoch-based anti-replay protection (replaced the former `ReplayWatermark`) |

### Roles (`rustynet-control`)

| Type | Location | Purpose |
|---|---|---|
| `RolePreset` | `src/role_presets.rs` | The 8-value role enum: Client, Admin, Exit, BlindExit, Relay, Anchor, Nas, Llm |
| `RolePresetComposition` | `src/role_presets.rs` | The capability-set composition attached to each role preset |
| `NodeRole` | `rustynetd/src/daemon.rs` + `rustynet-operator/src/role.rs` | Running node role in the daemon/operator (the control crate uses `RolePreset`) |
| `validate_transition()` | `src/role_presets.rs` | **Authoritative** transition validation — gatekeeper for all role changes |
| `is_supported_for_platform()` | `rustynet-cli/src/vm_lab/orchestrator/role.rs` | Per-platform role eligibility (not in `rustynet-control`) |

### Policy (`rustynet-policy`)

Note: `rustynet-policy` is a single-file crate (`src/lib.rs`) — there is **no** `types.rs` or `eval.rs`.

| Type | Location | Purpose |
|---|---|---|
| `PolicySet` | `src/lib.rs` | Ordered set of `PolicyRule` entries forming the ACL policy |
| `PolicyRule` | `src/lib.rs` | Single ACL rule (tags, src/dst, disposition) |
| `AccessRequest` | `src/lib.rs` | Evaluator input: membership identity + traffic context |
| `Route` | `rustynet-backend-api/src/lib.rs` | Route advertisement (exit node advertises subnets) |

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
| `UdpOffloadCapabilities` / `probe_udp_offload_capabilities` | `src/udp_offload_probe.rs` | FIS-0028 Phase 1: read-only detection of `sendmmsg`/`recvmmsg`/`UDP_SEGMENT`/`UDP_GRO` support (kernel-release gate + socket2 plumbing smoke-check); not called from any packet path |

### Daemon (`rustynetd`)

| Type | Location | Purpose |
|---|---|---|
| `DaemonRuntime` | `src/daemon.rs` | Main daemon state machine — owns all subsystems |
| `GossipNode` | `src/gossip_runtime.rs` | Per-peer gossip logic (sequence, replay ledger, re-push) |
| `StunClient` | `src/stun_client.rs` | STUN binding request → srflx candidate |
| `RelayClient` | `src/relay_client.rs` | Attaches to authoritative transport, sends keepalive |
| `PortMappingSupervisor` | `src/port_mapper.rs` | PCP → NAT-PMP → uPnP lifecycle |
| `CandidateSet` | `src/dataplane_candidates.rs` | Gathered v4/v6 host + srflx candidates |
| Killswitch (no single struct — `src/killswitch.rs` was removed) | `src/killswitch_precedence.rs`, `src/linux_killswitch_boot.rs`, `src/macos_exit_killswitch_precedence.rs`, `src/windows_killswitch_smoke.rs` | Pre-start + post-start killswitch (nftables/WFP/pf) split into the shared precedence model (`killswitch_precedence.rs`) plus per-OS apply/boot/smoke modules |
| `RuleDisposition` + `terminator_is_reachable` + `ContainedInterfaces` | `src/killswitch_precedence.rs` | S2: the shared precedence model for killswitch containment — walks a chain as an ORDERED rule list and asks whether the terminal drop/block is actually REACHABLE, not merely present. Transport-agnostic core (pf and nftables differ in syntax, not precedence semantics); each backend supplies a `classify` closure. `Escapes` is the fail-closed default, so an unrecognised rule withholds the containment verdict. `nft_chain_rules_in_evaluation_order` moves an nft chain `policy` last, since nft PRINTS it above the rules but APPLIES it below them. Used by `linux_ipv6_leak` (IPV-03), `macos_exit_killswitch_precedence` (PF-05), `macos_blind_exit` (PF-11), and `phase10::assert_firewall_ruleset` (RN-27) |
| `wfp_filter_shape` | `rustynet-windows-native/src/lib.rs` | WIN-03: portable validation of a read-back WFP filter's SHAPE (action == PERMIT, exactly one condition, `IP_LOCAL_INTERFACE`, LUID == tunnel). Deliberately OUTSIDE the `#[cfg(windows)]` FFI shim so it is tested on every CI leg — the shim marshals, this decides. Constants are drift-pinned to `windows_sys` by `const` assertions on the Windows build |
| `MacosPfLoadSpec` | `src/macos_pf_load_spec.rs` | Structured spec for the `macos-pf-load` privileged builtin — daemon sends params, root helper re-renders the `pf` rule text + owns the `pfctl -f` (closes the `pfctl -f` boundary) |
| `ReconnectPolicy` + `next_reconnect_delay_jittered_ms` | `src/resilience.rs` | Shared backoff primitive (deterministic ceiling + AWS Full Jitter, FIS-0016). Adoption rule: any NEW reconnect loop with inter-attempt delays MUST use the jittered fn; existing spec-timed ladders / condition-polls / local-race retries stay independent per the FIS-0016 classification |
| `PathMtuDiscovery` + `PathMtuConfig` | `src/path_mtu.rs` | FIS-0027 Phase 1: pure RFC 8899 DPLPMTUD per-path MTU search machine (no I/O, no clocks; Base → Searching → SearchComplete, blackhole → Base). PTB is advisory-only (can never raise or override a confirmed value); unconfirmed ⇒ 1280 floor. Probe carriage (Phase 3) and dynamic apply (Phase 4) not yet wired. Static bring-up MTU (`SAFE_BRINGUP_TUNNEL_MTU`, 1420) is set by the `rustynet-backend-wireguard` per-OS command adapters (Phase 2) |

### Service-Hosting Roles (`rustynet-nas`, `rustynet-llm-gateway`)

| Type | Location | Purpose |
|---|---|---|
| `rustynet-nas` | `crates/rustynet-nas/` | NAS service-hosting role: tunnel-only storage exposure, per-peer namespace isolation via FUSE/chroot, at-rest encryption, RustyBackup client contract. Binary `rustynet-nas`. |
| `rustynet-llm-gateway` | `crates/rustynet-llm-gateway/` | LLM service-hosting role: identity-from-tunnel gateway in front of a loopback inference engine. No API keys. gRPC/HTTP-2 token streaming as plaintext inside WireGuard tunnel. RustyAI client contract. Binary `rustynet-llm-gateway`. |

### Lab Tooling (`rustynet-netns-probe`)

| Type | Location | Purpose |
|---|---|---|
| `rustynet-netns-probe` | `crates/rustynet-netns-probe/` | LAB TOOLING (not shipped): Rust-native STUN responder + NAT mapping/filtering probes for the `--node` cross-network netns simulator. Replaces former python3 scripts. `std`-only (offline-buildable). STUN wire byte-pinned to `rustynetd`'s `stun_client.rs`. |

### Live-lab stage contract (`rustynet-cli/src/`)

RNQ-17: everything in this section — plus `vm_lab/`, `ops_live_lab_orchestrator.rs`,
`ops_cross_network_preflight.rs`, `ops_fresh_install_os_matrix.rs`,
`ops_live_lab_failure_digest.rs`, `live_lab_coverage.rs`, `live_lab_results.rs`,
the 120 lab `OpsCommand` variants, and the `zip`/`toml`/`socket2`/`signal-hook`
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
| `MacosNodeAdapter` | `adapter/macos.rs` | macOS adapter |
| `node_adapter_for()` | `adapter/factory.rs` | Factory: (platform, connection) → NodeAdapter |

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
| `render_host_*_script` / `render_*_repair_script` | `script_template.rs` | The named per-template render functions — the only way to reach a template. Includes the three `sudo bash -s` guest-repair scripts used by `recover_guest_network.rs` |
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
| `ReleaseManifest` (ed25519 signed) | `release_manifest.rs` + `ops_release_manifest.rs` | The installer's trust root: `ops create/verify-release-manifest`; per-artifact sha256 verified before staging |

### Security Verifiers (`rustynet-local-security`)

| Type | Location | Purpose |
|---|---|---|
| `RuntimeAcls` check | linux/windows subcommands | File permission verification |
| `KeyCustody` check | linux/windows subcommands | OS-secure key storage verification |
| `ServiceHardening` check | linux/windows subcommands | Service unit/SCM hardening |
| `DnsFailclosed` check | linux/windows subcommands | DNS leak prevention verification |

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
| A new node role | `rustynet-control/src/role_presets.rs` (add variant, update matrix) |
| A new daemon subsystem | `rustynetd/src/<subsystem>.rs` + wiring in `daemon.rs` |
| A new CLI subcommand | `rustynet-cli/src/ops_<name>.rs` or `src/vm_lab/` |
| A new `rustynet install` OS/step | `rustynet-cli/src/install/` (shared → `common.rs`, per-OS → `live_<os>.rs`) |
| A new security verifier | `rustynet-local-security` + per-OS adapter |
| A new orchestration stage | `crates/rustynet-cli/src/vm_lab/orchestrator/stage/<name>.rs` |
| A new MCP tool | `crates/rustynet-mcp/src/bin/<server>.rs` |

## Key Files For Common Tasks

| Task | Files to touch |
|---|---|
| Add enrollment feature | `rustynetd/src/enrollment_token.rs`, `rustynetd/src/daemon.rs`, `rustynet-cli/src/main.rs` |
| Fix a killswitch bug | `rustynetd/src/killswitch_precedence.rs`, `rustynetd/src/linux_killswitch_boot.rs`, `rustynetd/src/macos_exit_killswitch_precedence.rs`, `rustynetd/src/windows_killswitch_smoke.rs`, `rustynet-windows-native/` (WFP). If it is an ASSERTION bug, check `rustynetd/src/killswitch_precedence.rs` first — presence-vs-precedence was the same defect at five sites |
| Add a role | `rustynet-control/src/role_presets.rs`, `rustynet-cli/src/vm_lab/orchestrator/role.rs`, `rustynet-cli/src/role_cli.rs` |
| Add a backend | New crate in `crates/`, impl `TunnelBackend` trait |
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
