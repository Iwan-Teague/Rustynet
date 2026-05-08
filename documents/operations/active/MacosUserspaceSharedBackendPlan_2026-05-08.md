# macOS Userspace-Shared WireGuard Backend Plan

**Created:** 2026-05-08  
**Owner:** rustynet-backend-wireguard  
**Status:** Phase 1 complete — Phase 2 pending

---

## Goal

Implement a macOS equivalent of `LinuxUserspaceSharedBackend` so that:
- Daemon STUN gathering runs on the backend-owned authoritative UDP socket (no second daemon-side socket).
- Relay bootstrap uses the same transport identity as peer traffic.
- macOS is a first-class shared-transport platform alongside Linux.

This backend drives WireGuard entirely in userspace via the boringtun noise engine. The macOS kernel WireGuard module (`wireguard-go`) is not required.

---

## Architecture Reference

`LinuxUserspaceSharedBackend` (fully implemented) in  
`crates/rustynet-backend-wireguard/src/userspace_shared/` is the reference.  
The macOS equivalent lives (Phase 1 only so far) in  
`crates/rustynet-backend-wireguard/src/userspace_shared_macos/`.

Key modules in the Linux version:
- `engine.rs` — boringtun WireGuard noise engine wrapper
- `tun.rs` — TUN device lifecycle (`TunLifecycle` trait with `DirectTunLifecycle`, `HelperBackedTunLifecycle`, `TestTunLifecycle`)
- `socket.rs` — `AuthoritativeSocket` (UDP socket the daemon can share for STUN/relay)
- `runtime.rs` — async runtime worker (`RunningUserspaceRuntime`, `RuntimeControl`)
- `handshake.rs` — WireGuard handshake state helpers
- `mod.rs` — public `LinuxUserspaceSharedBackend` struct + `TunnelBackend` impl

---

## Transport Identity Contract

`MacosUserspaceSharedBackend` intentionally does **not** override  
`transport_socket_identity_blocker()` — the trait default returns `None`,  
signaling that this backend IS the authoritative shared-socket path.  
Once Phase 2+ implements the runtime, STUN and relay will run on the  
backend-owned UDP socket identity instead of a second daemon-owned socket.

Command-only backends (`MacosWireguardBackend`) correctly return `Some(reason)`  
from `transport_socket_identity_blocker()` and are unaffected by this plan.

---

## Phase 1 — Scaffolding (COMPLETE as of 2026-05-08)

**Files changed:**
- `crates/rustynet-backend-wireguard/src/userspace_shared_macos/mod.rs` — created  
  `MacosUserspaceSharedBackend` struct; all `TunnelBackend` methods return  
  `BackendError::internal("phase 1 scaffolding — runtime datapath not yet implemented")`.
- `crates/rustynet-backend-wireguard/src/lib.rs` — added `mod userspace_shared_macos`  
  and `pub use userspace_shared_macos::MacosUserspaceSharedBackend`.
- `crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs` — removed  
  redundant `MACOS_USERSPACE_SHARED_BACKEND_MODE` constant (moved to macOS module).
- `crates/rustynet-backend-userspace/src/lib.rs` — added `#[cfg(target_os = "macos")]`  
  arm delegating to `MacosUserspaceSharedBackend`; non-linux/macos arm now says  
  "only available on Linux and macOS".
- `crates/rustynetd/src/daemon.rs` — updated `userspace_shared_blocker()` message  
  from "not implemented" to "phase 1 scaffolding only" + updated test assertion.

**Tests added/updated:**
- `userspace_shared_macos::tests::macos_userspace_shared_backend_name_matches_mode_constant`
- `userspace_shared_macos::tests::macos_userspace_shared_backend_transport_socket_identity_blocker_returns_none`
- `userspace_shared_macos::tests::macos_userspace_shared_backend_phase1_start_returns_internal_error`
- `daemon::tests::validate_daemon_config_rejects_macos_userspace_shared_backend_with_precise_blocker` (updated)

**Gates verified:** cargo clippy -D warnings, cargo test for backend-wireguard + rustynetd.

---

## Phase 2 — TUN lifecycle (utun device)

**Goal:** Open a macOS `utun` device for the WireGuard TUN interface.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs`  
The Linux version creates a TUN device via `tun_tap` crate or `TUNSETIFF` ioctl.  
macOS uses `utun` (socket-based control channel with `SYSPROTO_CONTROL`).

**Tasks:**
- [ ] Add `tun.rs` to `userspace_shared_macos/` with `MacosTunLifecycle` implementing  
  the same `TunLifecycle` trait used by the Linux module (or a macOS-specific equivalent).
- [ ] Bind a `utun` device by name (e.g. `utun9`) on macOS.
- [ ] Support a test lifecycle that stubs the utun device for unit tests.
- [ ] Add `cfg(target_os = "macos")` guards on any macOS-only syscall code.

**Dependency:** requires adding `utun` crate or direct `IOKit`/`socket` bindings.  
Candidate: `tun` crate with macOS support, or raw `libsocket`/`IOKit` ffi.

---

## Phase 3 — Authoritative UDP socket

**Goal:** Bind and own the UDP socket that carries peer traffic, STUN, and relay control.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs`  
`AuthoritativeSocket` wraps a `UdpSocket` and provides `AuthoritativeTransportIdentity`.

**Tasks:**
- [ ] Add `socket.rs` to `userspace_shared_macos/` mirroring the Linux `AuthoritativeSocket`.
- [ ] Implement `authoritative_transport_round_trip()` and `authoritative_transport_identity()`  
  in `TunnelBackend for MacosUserspaceSharedBackend`.
- [ ] Add test coverage for socket identity reporting.

---

## Phase 4 — boringtun engine wiring

**Goal:** Wire the boringtun WireGuard engine to the utun TUN device and UDP socket.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`

**Tasks:**
- [ ] Add `engine.rs` to `userspace_shared_macos/` with `UserspaceEngine` wrapping  
  `boringtun::noise::Tunn`.
- [ ] Thread plaintext packets from the utun device through the engine and out the  
  authoritative UDP socket, and vice versa.
- [ ] Add `handshake.rs` with handshake freshness helpers.

---

## Phase 5 — Async runtime worker

**Goal:** Spin the engine in a background tokio task and expose `RuntimeControl` for  
peer management, route application, and stats queries.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs`

**Tasks:**
- [ ] Add `runtime.rs` to `userspace_shared_macos/` with `RunningUserspaceRuntime`  
  and `RuntimeControl`.
- [ ] Implement runtime recovery on worker exit (same pattern as Linux version).
- [ ] Wire `MacosUserspaceSharedBackend::start()` to spawn the runtime worker.
- [ ] Replace all `phase1_unimplemented()` returns in `TunnelBackend` with real dispatch.

---

## Phase 6 — Daemon integration

**Goal:** Allow the daemon to use `MacosWireguardUserspaceShared` backend mode on macOS.

**Tasks:**
- [ ] Remove `userspace_shared_blocker()` return for `MacosWireguardUserspaceShared`  
  in `crates/rustynetd/src/daemon.rs`.
- [ ] Add macOS-specific `validate_daemon_config` path (private key, listen port).
- [ ] Add `DaemonBackend::MacosWireguardUserspaceShared` variant wired to  
  `MacosUserspaceSharedBackend`.
- [ ] Update `validate_daemon_config_rejects_macos_userspace_shared_backend_with_precise_blocker`  
  test to confirm the backend is now accepted rather than blocked.
- [ ] Add `daemon_runtime_authoritative_stun_refresh_uses_macos_userspace_backend_transport_identity`  
  integration test mirroring the Linux version.

---

## Phase 7 — Live lab validation

**Goal:** Generate live-lab evidence on a macOS VM with the new backend active.

**Tasks:**
- [ ] Run `./scripts/ci/phase10_hp2_gates.sh` on macOS with `MacosWireguardUserspaceShared`.
- [ ] Generate a live `rustynet netcheck` artifact showing `transport_identity=macos-wireguard-userspace-shared`.
- [ ] Record evidence entry in `PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md §18.2`.

---

## Progress Ledger

### Phase 1 (complete)
- [x] `MacosUserspaceSharedBackend` scaffolding created (2026-05-08)
- [x] Transport-socket-identity blocker NOT set (shared-socket intent declared) (2026-05-08)
- [x] Exported from `rustynet-backend-wireguard` and wired into `rustynet-backend-userspace` (2026-05-08)
- [x] Daemon blocker message updated to reflect phase-1 scaffolding (2026-05-08)
- [x] 3 unit tests pass; daemon blocker test updated and passes (2026-05-08)

### Phase 2–7 (pending)
- [ ] TUN (utun) lifecycle — Phase 2
- [ ] Authoritative UDP socket — Phase 3
- [ ] boringtun engine — Phase 4
- [ ] Async runtime worker — Phase 5
- [ ] Daemon integration — Phase 6
- [ ] Live lab validation — Phase 7
