# Rustynet Platform Support Matrix (Current Implementation)

Date verified: 2026-03-05
Purpose: provide a single current-state view of platform capability, security posture, and evidence depth.

## Scope
- This matrix reflects **current implementation behavior**, not phase-plan scope text.
- For historical phase boundaries, see `documents/phase10.md`.

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
| IPv6 protected-mode parity | Supported | Explicitly not supported (`supports_ipv6=false`) until parity is complete | Secure short-term default | `crates/rustynet-backend-wireguard/src/lib.rs:775-781` |
| CI dataplane evidence | Real Linux WireGuard E2E | macOS dataplane smoke + targeted security tests | Needs more work on macOS depth | `.github/workflows/cross-platform-ci.yml:55-65`, `.github/workflows/cross-platform-ci.yml:26-28`, `scripts/ci/macos_dataplane_smoke.sh:44-46` |
| Break-glass/manual peer admin parity | Available | Linux-only guards block equivalent flows | Needs more work | `start.sh:2558`, `start.sh:2590`, `start.sh:2626` |
| Exit-node selection readiness probe UX | Membership+tunnel probe in `SELECT EXIT NODE`; current selection marker + connect/disconnect quick action | Same menu behavior on macOS host profile (compat runtime) | Implemented | `start.sh:3711-3774`, `start.sh:4257-4327` |
| Additional non-simulated backend implementation | Not present in-tree beyond WireGuard | Not present in-tree beyond WireGuard | Needs more work (policy/code discrepancy) | `crates/rustynet-backend-wireguard/src/lib.rs:54`, `crates/rustynet-backend-stub/src/lib.rs:38` |

## Security Notes
- More secure than older docs/findings:
  - production in-memory backend path is blocked,
  - macOS non-admin privileged-tool fallback is blocked,
  - macOS key custody defaults to Keychain and plaintext passphrase files are rejected by default checks.
- Still needs more work:
  - macOS CI is currently smoke-level for dataplane security compared with Linux real E2E depth,
  - Linux-only constraints still gate some manual admin peer flows,
  - policy expects a second non-simulated backend path, but current in-tree implementation set is WireGuard + stub,
  - direct/relay failover in Phase10 runtime is currently state-mode signaling, not full relay transport path integration.

## Operational Guidance
- Treat this document as the current support truth source for platform/security behavior.
- If this matrix conflicts with older phase/security reports, prefer this matrix plus direct code verification.
