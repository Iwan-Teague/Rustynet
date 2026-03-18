# Security Hardening Backlog

Date: 2026-03-09
Owner: Rustynet
Priority: security first, efficiency only when it does not widen trust or create fallback behavior

## Principles

- Keep one hardened path for each control-plane mutation.
- Fail closed when required signed state, custody, or trusted local control surfaces are unavailable.
- Remove legacy or weaker shell/runtime fallbacks instead of preserving them for convenience.
- Prefer explicit operator-visible failure over silent partial success.

## Completed In This Pass

- `start.sh`: role-switch restore and LAN-coupling failures are no longer silently ignored.
- `start.sh`: exit readiness probe now restores through the hardened exit-selection path.
- `scripts/e2e/live_linux_lab_orchestrator.sh`: membership-state custody hardening now fails closed.
- `crates/rustynet-cli/src/main.rs`: CLI validates daemon socket ownership, type, and parent-directory security before connecting.
- `crates/rustynetd/src/privileged_helper.rs`: privileged-helper client validates helper socket ownership, type, and parent-directory security before connecting.

## Current Priority Queue

1. Remove duplicate exit-selection mutation paths from `start.sh`.
   - Status: completed
   - Reason: interactive flows still mix signed assignment refresh with raw `rustynet exit-node select/off` calls.
   - Result: Linux interactive exit-node changes now fail closed unless local signed assignment refresh is available, and the main menu/launch-profile flows reuse the same hardened entry point.

2. Harden E2E SSH trust bootstrap.
   - Status: completed
   - Result: E2E shell harnesses and the Rust remote E2E path now require a pinned `known_hosts` source and use `StrictHostKeyChecking=yes` instead of TOFU.

3. Consolidate local control-surface trust checks.
   - Status: completed
   - Result: CLI daemon-socket validation and privileged-helper client socket validation now share one audited validator crate instead of drifting in separate implementations.

4. Tighten `start.sh` launch-profile mutations.
   - Status: completed
   - Result: quick-connect / quick-hybrid now reuse the hardened exit-selection helper instead of bypassing it.

5. Prepare HP3 relay transport with constant-time auth/token checks from day one.
   - Status: pending
   - Reason: recent mesh-VPN relay/auth bugs show comparison and relay-control surfaces are high-risk.
   - Goal: avoid introducing timing or relay-session trust bugs during HP3 implementation.

## Notes

- Four-node live validation remains the current default because the original Debian client VM `192.168.18.50` was unstable under reboot; the replacement five-node topology now uses `192.168.18.65`.
- Five-node release-gate evidence still requires a healthy fifth node.
