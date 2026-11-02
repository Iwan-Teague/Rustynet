# Rustynet Platform Support Matrix (Current Implementation)

Date verified: 2026-04-17 (re-checked against the tree on 2026-11-01: file:line citations were converted to
file references, rows whose code status changed were corrected, and the stale `start.sh` / Linux-only live-lab claims
were removed. Cells that depend on live-lab evidence were not re-verified and keep their earlier status; the live
per-role by per-OS status matrix is
[`active/CrossPlatformRoleParityRefresh_2026-07-23.md`](./active/CrossPlatformRoleParityRefresh_2026-07-23.md).)
Purpose: provide a single current-state view of platform capability, security posture, and evidence depth.

## Scope
- This matrix reflects **current implementation behavior**, not phase-plan scope text.
- For historical phase boundaries, see `documents/phase10.md`.
- Traversal architecture requirements are defined in `documents/Requirements.md` (section `3.2` + section `6`) and `documents/phase10.md`.
- Windows notes in this document are scoped explicitly as VM-lab/runtime-host
  truth unless a row or note says otherwise. They are not a release-gate
  claim.

## Windows VM-Lab Guest Truth

- `runtime-host-capable only`: `ops vm-lab-discover-local-utm`,
  `ops vm-lab-start`, `ops vm-lab-restart`, `ops vm-lab-sync-repo`, the
  PowerShell-first access bootstrap helper under
  `scripts/vm_lab/windows/Enable-WindowsVmLabAccess.ps1`, and the canonical
  helper root under `scripts/bootstrap/windows/` all dispatch through
  Windows-specific PowerShell/ZIP/helper paths for `platform=windows`
  inventory targets. The direct smoke helper
  `scripts/bootstrap/windows/Smoke-RustyNetWindowsServiceHost.ps1` validates
  the reviewed `rustynetd --windows-service --env-file` SCM host path and
  intentionally reports `blocked` while the backend label remains
  `windows-unsupported`.
- `Windows bootstrap-phase entrypoints exist`: `sync-source`, `build-release`,
  `smoke-service-host`, `install-release`, `restart-runtime`, `verify-runtime`,
  and `all` route into Windows-specific helper/provider paths.
  `smoke-service-host` validates the reviewed SCM host path and succeeds
  in-scope when the helper reports `host_surface_validated=true` together with
  the explicit `windows-unsupported` backend blocker. `build-release` still
  depends on verified MSVC/toolchain availability or explicit bootstrap
  configuration.
- `runtime-boundary-capable only`: reviewed Windows runtime paths are pinned
  under `C:\ProgramData\RustyNet\{config,logs,trust,membership,keys,secrets}`,
  the installer now provisions `secrets\key-custody` with protected ACLs plus
  an unrestricted service SID, and reviewed runtime passphrase custody uses
  DPAPI `.dpapi` blobs instead of plaintext long-lived files. The local
  privileged IPC surface is limited to reviewed `\\.\pipe\RustyNet\...`
  named-pipe probe/ACL-inspection requests, and
  `rustynetd windows-runtime-boundary-check` is the authoritative self-check
  that the Windows verify/diagnostics helpers call.
- `live-lab engine`: the Rust `--node` orchestrator (`ops vm-lab-orchestrate-live-lab`,
  `ops vm-lab-setup-live-lab`, `ops vm-lab-diagnose-live-lab-failure`) drives Linux, macOS and
  Windows nodes through per-OS adapters. `ops vm-lab-run-live-lab` and `ops vm-lab-iterate-live-lab`
  are no longer dispatched (the profile-driven bash wrappers were retired in W5.7), so the earlier
  "Linux-runtime only / `live_linux_*` stages" restriction no longer describes the engine. What each
  OS has actually proven on it is recorded in `live_lab_node_run_matrix.csv` /
  `live_lab_node_stage_results.csv`, not here.
- `not dataplane-capable`: `rustynetd` now exposes a reviewed Windows
  service/config host surface and carries the opt-in reviewed backend label
  `windows-wireguard-nt`, but current measured VM-lab proof still stops before
  install/runtime/node evidence and reviewed unsupported operations remain
  explicit fail-closed blockers. Windows therefore still must not be described
  as a supported dataplane target.
- `not fresh-install evidenced`: the latest measured local Windows UTM attempt
  for current `HEAD` on 2026-04-17 first recovered the guest to the shared
  subnet as `192.168.64.14`, then resynced/build current `HEAD` and passed
  `smoke-service-host`, but discovery still reported `execution_ready=false`
  because the Windows local-UTM callback/readiness probe timed out. On the
  same guest state, `install-release` failed closed on that callback timeout,
  guest-side SSH state remained absent (`sshd_service_count=0`,
  `sshd_registry_present=False`, `ssh_listener_count=0`), and diagnostics on
  the blocked path still hit `UTM Windows capture output was missing rc
  marker`. There is still no clean Windows install/runtime/service evidence to
  promote into the release gate. See
  `artifacts/windows_phase4/20260417T174942Z/phase4_evidence_summary.md`.
- `not release-gated and evidenced`: Windows is intentionally excluded from the
  current fresh-install OS matrix and Phase10 release gate because measured
  Windows install/runtime/role-switch evidence does not yet exist.

## Capability Matrix

| Capability | Linux | macOS | Security posture | Evidence |
| --- | --- | --- | --- | --- |
| Runtime backend mode | `linux-wireguard` (default; `linux-wireguard-userspace-shared` opt-in) | `macos-wireguard` (default; `macos-wireguard-userspace-shared` opt-in) | Implemented | `DaemonBackendMode` in `crates/rustynetd/src/daemon.rs` |
| Production in-memory backend | Disabled | Disabled | More secure than older findings | `crates/rustynetd/src/daemon.rs` ("in-memory backend is disabled in production daemon paths") |
| Service lifecycle hardening | `systemd` units | `launchd` daemon/helper bootstrap | Implemented | `scripts/systemd/rustynetd.service`, `scripts/launchd/*.plist`, `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`, `crates/rustynet-cli/src/ops_install_macos_*.rs` |
| Privileged tool integrity | Root-owned path checks | Root-owned path checks + non-admin fallback blocked | Implemented | privileged-helper binary-path checks in `crates/rustynetd/src/privileged_helper.rs`; macOS Homebrew prerequisite check in `scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh` |
| Passphrase custody default | systemd credential path | Keychain-backed custody path | Implemented with emergency override guard | `crates/rustynetd/src/key_material.rs`, `crates/rustynet-crypto/src/lib.rs` (macOS Keychain helpers), systemd credential wiring in `scripts/systemd/*.service` |
| Persistent plaintext passphrase file | Rejected in hardened runtime path | Rejected by macOS checks | More secure than older docs/assumptions | `crates/rustynetd/src/key_material.rs` |
| DNS fail-closed controls | Implemented | Implemented (PF-backed with assertions) | Implemented | `crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/phase10.rs` |
| Direct/relay failover path in Phase10 runtime | State tracking present | State tracking present | Needs more work for full relay dataplane transport switching | `crates/rustynetd/src/phase10.rs`, `crates/rustynetd/src/phase10.rs` |
| Traversal architecture posture (direct hole punch + relay fallback/failback) | First-class requirement; implementation in progress | First-class requirement; implementation in progress | Secure target posture is defined; runtime parity remains open work | `documents/Requirements.md`, `documents/phase10.md`, `documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md` |
| Router port-mapping autoconf (NAT-PMP, PCP, uPnP IGD) | Implemented (PCP→NAT-PMP→uPnP probe orchestrator, `--port-mapping-mode={auto,keepalive,disabled}`) | Implemented (same code path; gateway autodetection via `route -n get default`) | Keepalive is the strict-secure-practical default; Auto opts in to probing | `crates/rustynetd/src/port_mapper.rs` |
| Peer endpoint discovery (host + STUN srflx, dual-stack IPv4/IPv6) | Implemented (getifaddrs + per-family STUN, scope-classified) | Implemented (same code path) | RFC 1918 + RFC 6598 CGNAT + RFC 4193 ULA classified | `crates/rustynetd/src/dataplane_candidates.rs` |
| Peer-distributed signed-bundle gossip primitives (Ed25519 + anti-replay) | Implemented (mint / verify / accept primitives in `peer_gossip.rs`, UDP transport in `gossip_transport.rs`, epidemic runtime `GossipNode` in `gossip_runtime.rs`) | Implemented (same code path) | Domain-separated signatures + per-source monotonic sequence + freshness window | `crates/rustynetd/src/peer_gossip.rs` |
| Enrollment-token mint / verify / consume (HMAC-SHA256) | Implemented (mint / verify / consume primitives; CLI verbs `rustynet enrollment keygen\|issue\|verify\|export-verifier-key\|migrate-secret`) | Implemented (same code path) | Single-use ledger + TTL cap + constant-time tag compare | `crates/rustynetd/src/enrollment_token.rs` |
| ICE-style candidate prioritisation (RFC 8445) | Implemented (priority + pair-generation primitives, consumed by `traversal.rs` and `phase10.rs`) | Implemented (same code path) | RFC 8421 v6-preferred local preference + foundation dedupe | `crates/rustynetd/src/ice_priority.rs` |
| Anchor node role host capability (24/7 peer, gossip seed, bundle-pull endpoint, relay co-deploy, port-mapping authoritative) | Implemented in code (D11: anchor listeners and TLS identity in `rustynetd`; design in `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`); live evidence per OS is in the parity Refresh ledger | Implemented in code (same code path with macOS Keychain custody for the anchor secret); live evidence per OS is in the parity Refresh ledger | Anchor metadata never gates signature verification; secret custody is OS-secure | `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md` |
| Anchor node bundle-pull client (consumption only — bootstrap from anchor via single-use token) | Implemented (D11; CLI verb `rustynet anchor pull-bundle`) | Implemented (D11; same CLI verb) | Default loopback bind; LAN bind requires explicit ack flag | `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md` §5.2 |
| IPv6 protected-mode parity | `linux-wireguard`: `supports_ipv6=true`; `linux-wireguard-userspace-shared`: `supports_ipv6=false` | `macos-wireguard`: `supports_ipv6=true`; `macos-wireguard-userspace-shared`: `supports_ipv6=false` | Capability flags as coded in each backend's `capabilities()`; leak behaviour in protected mode is exercised by the live `ipv6_leak` stages, not by this table | `crates/rustynet-backend-wireguard/src/{linux_command,macos_command}.rs`, `userspace_shared*/mod.rs` |
| CI dataplane evidence | Real Linux WireGuard E2E | Workspace `cargo test` exercises macOS dataplane unit tests (pf rule rendering + DNS fail-closed, DNS rule parser, IPv6 parity; the macOS leg runs fmt, clippy `-D warnings` and `cargo nextest` over the whole workspace with `--locked`, plus the repo-hygiene gates) | Needs more work on macOS depth | `.github/workflows/cross-platform-ci.yml`, `.github/workflows/cross-platform-ci.yml`, `crates/rustynet-cli/src/main.rs`, `crates/rustynetd/src/phase10.rs` |
| Manual peer break-glass mutation path | Removed (fail-closed) | Removed (fail-closed) | More secure than older docs/assumptions | `crates/rustynet-operator/src/config/validate.rs` (rejects `MANUAL_PEER_OVERRIDE != 0` on load), `crates/rustynet-cli/src/main.rs` (peer-store ops are read-only `validate` / `list` verbs only) |
| Exit-node selection readiness UX | `SelectExitNode` IPC dispatch with current-selection marker in the exit-node listing; `Status` and `Netcheck` menu actions surface readiness after dispatch (the prior bash retry-probe loop did not survive the migration) | Same Rust operator menu on macOS host profile (compat runtime) | Implemented (probe-retry loop removed, post-migration) | `crates/rustynet-operator/src/menu.rs` (`SelectExitNode` item), `crates/rustynet-cli/src/main.rs` (dispatch → `IpcCommand::ExitNodeSelect`), `crates/rustynet-cli/src/main.rs` (`execute_exit_node_list` with `*` current-selection marker) |
| Additional non-simulated backend implementation | Not present in-tree beyond WireGuard | Not present in-tree beyond WireGuard | Needs more work (policy/code discrepancy) | `crates/rustynet-backend-wireguard/src/lib.rs`, `crates/rustynet-backend-stub/src/lib.rs` |

## Node Role Eligibility (Cross-Platform Truth)

The user-selectable node roles (canonical taxonomy:
`documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`; the base six
plus `nas`/`llm`, and a gated ninth `blind_relay` preset in code) have
per-platform host eligibility. Roles gated behind future dataplane
work are listed honestly here even when wizard UX shows them as
"locked".

| Role | Linux | macOS | Windows | iOS | Android |
| --- | --- | --- | --- | --- | --- |
| `client` | yes | yes | yes (today: `runtime-host-capable only`; full client when D7/D9 land) | yes | yes |
| `admin` | yes | yes | yes (gated on D7/D9 same as Windows client) | no | no |
| `exit` | yes | yes (admin-installed network tools required) | yes (gated on D7 NetNat + killswitch evidence) | no | no |
| `blind_exit` | yes | yes (PF-backed hard-lock; live evidence pending) | no (not in current dataplane plan) | no | no |
| `relay` | yes | yes (`rustynet-relay` builds on macOS) | yes (gated on D7/D9; `rustynet-relay` already builds with SCM feature) | no | no |
| `anchor` | yes | yes | yes (gated on D7/D9) | no (consume-only) | no (consume-only) |
| `nas` | ⛔ fail-closed (primary host; D13.c code landed, pending Linux live-lab evidence row) | ⛔ fail-closed (secondary host; pending cross-OS green run) | ⛔ fail-closed (gated on D7/D9 dataplane parity) | no (consume-only — RustyBackup client) | no (consume-only — RustyBackup client) |
| `llm` | ⛔ fail-closed (primary host; D13.d code landed, pending Linux live-lab evidence row) | ⛔ fail-closed (Apple-silicon inference candidate; pending green run) | ⛔ fail-closed (gated on D7/D9 dataplane parity) | no (consume-only — RustyAI client) | no (consume-only — RustyAI client) |

Notes:

- Mobile (iOS + Android) is `client` only by OS constraint
  (lifecycle suspension, address instability, sandboxing). Mobile
  shows a read-only "Role: client (mobile)" indicator. See
  `documents/mobile/RustynetMobileArchitectureDesign_2026-04-17.md`.
- Windows non-client roles all land together when D7/D9 in the
  dataplane execution plan land. Today every Windows non-client
  role fails closed at the wizard surface with an explicit
  "platform-blocked" message.
- macOS `blind_exit` now has a reviewed PF hard-lock path
  (`crates/rustynetd/src/macos_blind_exit.rs`), and the Rust-native lab role mapper resolves
  macOS `exit` to daemon `blind_exit`. Full promotion still needs live
  evidence for PF anchor installation, DNS precedence, and hard-lock
  persistence.
- The `anchor` row here is the higher-level role-eligibility view.
  The earlier two anchor-capability rows in the Capability Matrix
  (host capability + bundle-pull client) remain accurate at the
  capability level.

## Anchor Node Role (Cross-Platform Truth)

The anchor node role (canonical design:
`documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`) is
D11 in the dataplane execution plan and is implemented in code
(`rustynetd` anchor bundle-pull and enrollment listeners, `anchor_tls.rs`).
Per-platform host capability truth (live proof per OS: the parity Refresh ledger):

- Linux: anchor-eligible. Hosts every anchor capability
  (`gossip_seed`, `bundle_pull`, `enrollment_endpoint`,
  `relay_colocation`, `port_mapping_authoritative`). Primary host
  platform for the role.
- macOS: anchor-eligible. Hosts every anchor capability. Uses
  Keychain-backed custody for the anchor enrollment secret. Tracks
  Linux feature parity.
- Windows: anchor-eligible **once D7/D9 land**. Today Windows is
  `runtime-host-capable only` and not dataplane-evidenced; anchor on
  Windows is blocked behind the same dataplane-parity work that
  blocks Windows-as-exit and Windows-as-peer.
- iOS: anchor-bootstrap-client only. OS lifecycle constraints
  (`NEPacketTunnelProvider` suspension, address instability,
  sandboxing) make anchor hosting infeasible. iOS consumes anchor
  services via `anchor_bundle_pull_client` in `rustynet-mobile-core`.
- Android: anchor-bootstrap-client only. Same constraint shape as
  iOS (Doze, App Standby, lifecycle resets on network change).

Anchor metadata is never consulted before signature verification on
any platform; anchor is operational metadata, not trust authority.

## ARM Architecture Support (Future)

32-bit and 64-bit ARM Linux targets are a finished-product requirement. Current status:

| Target | Triple | Status | Blocker |
| --- | --- | --- | --- |
| 64-bit ARM Linux | `aarch64-unknown-linux-gnu` | Unverified / no CI coverage | No known compile blockers; boringtun explicitly supports this target. Needs CI gate + live-lab evidence run. |
| 32-bit ARM Linux | `armv7-unknown-linux-gnueabihf` | Not supported — compile blockers present | `AtomicU64` in `third_party/rustynet-alloc-meter/src/lib.rs` (not available on 32-bit ARM); `u128`/`i128` arithmetic in `crates/rustynetd/src/daemon.rs`, `crates/rustynet-cli/src/main.rs`, `crates/rustynetd/src/peer_gossip.rs`, `crates/rustynet-cli/src/ops_cross_network_reports.rs`. Upstream boringtun supports `armv7-unknown-linux-gnueabihf`. Rustynet's own code is the blocker. |

Primary use case for 32-bit ARM: low-power relay and exit/blind_exit nodes (Raspberry Pi Zero 2 W class, 512 MB RAM) serving 1–3 peers. At that scale the daemon's memory and CPU budgets are comfortable; the only blocker is compilation.

Fix required for 32-bit ARM:
1. Replace `AtomicU64` in `rustynet-alloc-meter` with `AtomicU32` pair or a mutex, guarded by `#[cfg(target_pointer_width = "64")]` where needed.
2. Refactor ~15 `u128`/`i128` sites to use `u64` pair arithmetic or add `cfg`-gated alternatives (IPv6 address math, timestamp deltas, membership counters).
3. Add `armv7-unknown-linux-gnueabihf` to CI cross-compile matrix.
4. Add live-lab evidence run on ARM hardware.

This work is not release-blocking for the current mandate (Linux/macOS/Windows role parity). Track it as a post-parity backlog item.

## Security Notes
- More secure than older docs/findings:
  - production in-memory backend path is blocked,
  - macOS non-admin privileged-tool fallback is blocked,
  - macOS key custody defaults to Keychain and plaintext passphrase files are rejected by default checks.
- Still needs more work:
  - macOS CI is currently smoke-level for dataplane security compared with Linux real E2E depth,
  - policy expects a second non-simulated backend path, but current in-tree implementation set is WireGuard + stub,
  - direct/relay failover in Phase10 runtime is currently state-mode signaling, not full relay transport path integration.
  - traversal architecture is now a core documented requirement, but full hole-punch + relay dataplane integration is not yet complete in runtime code.

## Operational Guidance
- Treat this document as the current support truth source for platform/security behavior.
- If this matrix conflicts with older phase/security reports, prefer this matrix plus direct code verification.
