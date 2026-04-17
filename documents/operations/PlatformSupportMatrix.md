# Rustynet Platform Support Matrix (Current Implementation)

Date verified: 2026-04-15
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
- `live-lab wrapper boundary is fail-closed`: `ops vm-lab-validate-live-lab-profile`,
  `ops vm-lab-setup-live-lab`, `ops vm-lab-run-live-lab`,
  `ops vm-lab-orchestrate-live-lab`, `ops vm-lab-iterate-live-lab`,
  `ops vm-lab-run-suite`, and `ops vm-lab-diagnose-live-lab-failure` are
  still Linux-runtime surfaces. They reject profiles with missing target
  metadata or any configured target that is not
  `platform=linux`/`remote_shell=posix`/`guest_exec_mode=linux_bash`/`service_manager=systemd`
  before any `live_linux_*` stage runs.
- `not dataplane-capable`: `rustynetd` now exposes a reviewed Windows
  service/config host surface, but the only reviewed Windows backend label is
  `windows-unsupported`. Helper entrypoints therefore fail closed for the
  supported backend scope instead of claiming transport/runtime success.
- `not fresh-install evidenced`: the latest Mac + UTM validation for current
  `HEAD` still fails at the local Windows guest exec/output boundary
  (`UTM Windows capture output was missing rc marker`), so there is no clean
  Windows install/runtime/service evidence to promote into the release gate.
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
| IPv6 protected-mode parity | Supported | Explicitly not supported (`supports_ipv6=false`) until parity is complete | Secure short-term default | `crates/rustynet-backend-wireguard/src/lib.rs:775-781` |
| CI dataplane evidence | Real Linux WireGuard E2E | macOS dataplane smoke + targeted security tests | Needs more work on macOS depth | `.github/workflows/cross-platform-ci.yml:55-65`, `.github/workflows/cross-platform-ci.yml:26-28`, `scripts/ci/macos_dataplane_smoke.sh:44-46` |
| Manual peer break-glass mutation path | Removed (fail-closed) | Removed (fail-closed) | More secure than older docs/assumptions | `start.sh:3303-3356`, `start.sh:4213-4270` |
| Exit-node selection readiness probe UX | Membership+tunnel probe in `SELECT EXIT NODE`; current selection marker + connect/disconnect quick action | Same menu behavior on macOS host profile (compat runtime) | Implemented | `start.sh:3711-3774`, `start.sh:4257-4327` |
| Additional non-simulated backend implementation | Not present in-tree beyond WireGuard | Not present in-tree beyond WireGuard | Needs more work (policy/code discrepancy) | `crates/rustynet-backend-wireguard/src/lib.rs:54`, `crates/rustynet-backend-stub/src/lib.rs:38` |

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
