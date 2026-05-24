# Rustynet Platform Support Matrix (Current Implementation)

Date verified: 2026-04-17
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
- `live-lab wrapper boundary is fail-closed`: `ops vm-lab-validate-live-lab-profile`,
  `ops vm-lab-setup-live-lab`, `ops vm-lab-run-live-lab`,
  `ops vm-lab-orchestrate-live-lab`, `ops vm-lab-iterate-live-lab`,
  `ops vm-lab-run-suite`, and `ops vm-lab-diagnose-live-lab-failure` are
  still Linux-runtime surfaces. They reject profiles with missing target
  metadata or any configured target that is not
  `platform=linux`/`remote_shell=posix`/`guest_exec_mode=linux_bash`/`service_manager=systemd`
  before any `live_linux_*` stage runs.
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
| Runtime backend mode | `linux-wireguard` | `macos-wireguard` | Implemented | `crates/rustynetd/src/main.rs:450-451` |
| Production in-memory backend | Disabled | Disabled | More secure than older findings | `crates/rustynetd/src/daemon.rs:526-530` |
| Service lifecycle hardening | `systemd` units | `launchd` daemon/helper bootstrap | Implemented | `scripts/systemd/rustynetd.service:47`, `start.sh:2214-2217` |
| Privileged tool integrity | Root-owned path checks | Root-owned path checks + non-admin fallback blocked | Implemented | `start.sh:1076-1080`, `start.sh:1956-1957` |
| Passphrase custody default | systemd credential path | Keychain-backed custody path | Implemented with emergency override guard | `start.sh:1533`, `start.sh:1612`, `start.sh:2178`, `crates/rustynetd/src/key_material.rs:337-340` |
| Persistent plaintext passphrase file | Rejected in hardened runtime path | Rejected by macOS checks | More secure than older docs/assumptions | `start.sh:1378`, `start.sh:1907` |
| DNS fail-closed controls | Implemented | Implemented (PF-backed with assertions) | Implemented | `crates/rustynetd/src/phase10.rs:1422-1434`, `crates/rustynetd/src/phase10.rs:1468-1495` |
| Direct/relay failover path in Phase10 runtime | State tracking present | State tracking present | Needs more work for full relay dataplane transport switching | `crates/rustynetd/src/phase10.rs:1954-1970`, `crates/rustynetd/src/phase10.rs:2692-2730` |
| Traversal architecture posture (direct hole punch + relay fallback/failback) | First-class requirement; implementation in progress | First-class requirement; implementation in progress | Secure target posture is defined; runtime parity remains open work | `documents/Requirements.md:59`, `documents/phase10.md:11`, `documents/operations/active/UdpHolePunchingAndRelayTraversalPlan_2026-03-07.md:1` |
| Router port-mapping autoconf (NAT-PMP, PCP, uPnP IGD) | Implemented (PCP→NAT-PMP→uPnP probe orchestrator, `--port-mapping-mode={auto,keepalive,disabled}`) | Implemented (same code path; gateway autodetection via `route -n get default`) | Keepalive is the strict-secure-practical default; Auto opts in to probing | `crates/rustynetd/src/port_mapper.rs` |
| Peer endpoint discovery (host + STUN srflx, dual-stack IPv4/IPv6) | Implemented (getifaddrs + per-family STUN, scope-classified) | Implemented (same code path) | RFC 1918 + RFC 6598 CGNAT + RFC 4193 ULA classified | `crates/rustynetd/src/dataplane_candidates.rs` |
| Peer-distributed signed-bundle gossip primitives (Ed25519 + anti-replay) | Implemented (mint / verify / accept primitives; daemon push-loop wiring queued) | Implemented (same code path) | Domain-separated signatures + per-source monotonic sequence + freshness window | `crates/rustynetd/src/peer_gossip.rs` |
| Enrollment-token mint / verify / consume (HMAC-SHA256) | Implemented (mint / verify / consume primitives; CLI verb wiring queued) | Implemented (same code path) | Single-use ledger + TTL cap + constant-time tag compare | `crates/rustynetd/src/enrollment_token.rs` |
| ICE-style candidate prioritisation (RFC 8445) | Implemented (priority + pair-generation primitives; traversal-path integration queued) | Implemented (same code path) | RFC 8421 v6-preferred local preference + foundation dedupe | `crates/rustynetd/src/ice_priority.rs` |
| Anchor node role host capability (24/7 peer, gossip seed, bundle-pull endpoint, relay co-deploy, port-mapping authoritative) | Planned (D11; design in `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md`) | Planned (D11; same code path with macOS Keychain custody for anchor secret) | Anchor metadata never gates signature verification; secret custody is OS-secure | `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md` |
| Anchor node bundle-pull client (consumption only — bootstrap from anchor via single-use token) | Planned (D11; CLI verb `rustynet anchor pull-bundle`) | Planned (D11; same CLI verb) | Default loopback bind; LAN bind requires explicit ack flag | `documents/operations/active/AnchorNodeRoleDesign_2026-05-21.md` §5.2 |
| IPv6 protected-mode parity | Supported | Explicitly not supported (`supports_ipv6=false`) until parity is complete | Secure short-term default | `crates/rustynet-backend-wireguard/src/lib.rs:775-781` |
| CI dataplane evidence | Real Linux WireGuard E2E | macOS dataplane smoke + targeted security tests | Needs more work on macOS depth | `.github/workflows/cross-platform-ci.yml:55-65`, `.github/workflows/cross-platform-ci.yml:26-28`, `scripts/ci/macos_dataplane_smoke.sh:44-46` |
| Manual peer break-glass mutation path | Removed (fail-closed) | Removed (fail-closed) | More secure than older docs/assumptions | `start.sh:3303-3356`, `start.sh:4213-4270` |
| Exit-node selection readiness probe UX | Membership+tunnel probe in `SELECT EXIT NODE`; current selection marker + connect/disconnect quick action | Same menu behavior on macOS host profile (compat runtime) | Implemented | `start.sh:3711-3774`, `start.sh:4257-4327` |
| Additional non-simulated backend implementation | Not present in-tree beyond WireGuard | Not present in-tree beyond WireGuard | Needs more work (policy/code discrepancy) | `crates/rustynet-backend-wireguard/src/lib.rs:54`, `crates/rustynet-backend-stub/src/lib.rs:38` |

## Node Role Eligibility (Cross-Platform Truth)

The six user-selectable node roles (canonical taxonomy:
`documents/operations/active/NodeRoleTaxonomy_2026-05-21.md`) have
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

Notes:

- Mobile (iOS + Android) is `client` only by OS constraint
  (lifecycle suspension, address instability, sandboxing). Mobile
  shows a read-only "Role: client (mobile)" indicator. See
  `documents/mobile/RustynetMobileArchitectureDesign_2026-04-17.md`.
- Windows non-client roles all land together when D7/D9 in the
  dataplane execution plan land. Today every Windows non-client
  role fails closed at the wizard surface with an explicit
  "platform-blocked" message.
- macOS `blind_exit` now has a reviewed PF hard-lock path. `start.sh`
  permits it on macOS, and the Rust-native lab role mapper resolves
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
planned for D11 in the dataplane execution plan. Per-platform host
capability truth:

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
