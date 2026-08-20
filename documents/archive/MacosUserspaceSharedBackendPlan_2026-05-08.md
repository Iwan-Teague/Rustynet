# macOS Userspace-Shared WireGuard Backend Plan

**Created:** 2026-05-08  
**Owner:** rustynet-backend-wireguard  
**Status:** Phase 6 daemon integration landed — live lab validation pending

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
The macOS equivalent lives in
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
  `MacosUserspaceSharedBackend` struct. Later phases replaced the scaffolding
  errors with real runtime dispatch.
- `crates/rustynet-backend-wireguard/src/lib.rs` — added `mod userspace_shared_macos`  
  and `pub use userspace_shared_macos::MacosUserspaceSharedBackend`.
- `crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs` — removed  
  redundant `MACOS_USERSPACE_SHARED_BACKEND_MODE` constant (moved to macOS module).
- `crates/rustynet-backend-userspace/src/lib.rs` — added `#[cfg(target_os = "macos")]`
  arm delegating to `MacosUserspaceSharedBackend`; non-linux/macos arm now says
  "only available on Linux and macOS".
- `crates/rustynetd/src/daemon.rs` — initially blocked daemon use while
  scaffolding was incomplete; Phase 6 removed that blocker.

**Tests added/updated:**
- `userspace_shared_macos::tests::macos_userspace_shared_backend_name_matches_mode_constant`
- `userspace_shared_macos::tests::macos_userspace_shared_backend_transport_socket_identity_blocker_returns_none`
- `daemon::tests::validate_daemon_config_accepts_macos_userspace_shared_backend` (updated in Phase 6)

**Gates verified:** cargo clippy -D warnings, cargo test for backend-wireguard + rustynetd.

---

## Phase 2 — TUN lifecycle (utun device)

**Goal:** Open a macOS `utun` device for the WireGuard TUN interface.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs`  
The Linux version creates a TUN device via `tun_tap` crate or `TUNSETIFF` ioctl.  
macOS uses `utun` (socket-based control channel with `SYSPROTO_CONTROL`).

**Tasks:**
- [x] Add `tun.rs` to `userspace_shared_macos/` with `MacosTunLifecycle` implementing
  the same `TunLifecycle` trait used by the Linux module (or a macOS-specific equivalent).
- [x] Bind a `utun` device by name (e.g. `utun9`) on macOS.
- [x] Support a test lifecycle that stubs the utun device for unit tests.
- [x] Add `cfg(target_os = "macos")` guards on any macOS-only syscall code.

**Dependency:** requires adding `utun` crate or direct `IOKit`/`socket` bindings.  
Candidate: `tun` crate with macOS support, or raw `libsocket`/`IOKit` ffi.

**Status (2026-05-21):** Implemented with direct Darwin `utun` control-socket
support in `third_party/rustynet-tun/src/lib.rs` and
`crates/rustynet-backend-wireguard/src/userspace_shared_macos/tun.rs`.

---

## Phase 3 — Authoritative UDP socket

**Goal:** Bind and own the UDP socket that carries peer traffic, STUN, and relay control.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs`  
`AuthoritativeSocket` wraps a `UdpSocket` and provides `AuthoritativeTransportIdentity`.

**Tasks:**
- [x] Add `socket.rs` to `userspace_shared_macos/` mirroring the Linux `AuthoritativeSocket`.
- [x] Implement `authoritative_transport_round_trip()` and `authoritative_transport_identity()`
  in `TunnelBackend for MacosUserspaceSharedBackend`.
- [x] Add test coverage for socket identity reporting.

**Status (2026-05-21):** Implemented `AuthoritativeSocket` in
`crates/rustynet-backend-wireguard/src/userspace_shared_macos/socket.rs` with a
macOS-specific transport label, generation counter, nonblocking bind, send, and
receive helpers. Backend trait methods now dispatch through the Phase 5
runtime.

---

## Phase 4 — boringtun engine wiring

**Goal:** Wire the boringtun WireGuard engine to the utun TUN device and UDP socket.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`

**Tasks:**
- [x] Expose/reuse `UserspaceEngine` wrapping `boringtun::noise::Tunn`.
- [x] Thread plaintext packets from the utun device through the engine and out the
  authoritative UDP socket, and vice versa.
- [x] Expose/reuse handshake freshness helpers.

**Status (2026-05-21):** The macOS userspace-shared path now reuses the
existing crate-visible boringtun `UserspaceEngine` and handshake telemetry from
the Linux shared backend instead of duplicating protocol logic. A macOS module
test proves private-key loading, peer configuration, and WireGuard handshake
initiation through the shared engine.

**Status (2026-05-21):** Packet threading now exists in the macOS runtime worker
added under Phase 5, and backend trait dispatch is wired.

---

## Phase 5 — Async runtime worker

**Goal:** Spin the engine in a background tokio task and expose `RuntimeControl` for  
peer management, route application, and stats queries.

**Reference:** `crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs`

**Tasks:**
- [x] Add `runtime.rs` to `userspace_shared_macos/` with `RunningUserspaceRuntime`
  and `RuntimeControl`.
- [x] Implement runtime recovery on worker exit (same pattern as Linux version).
- [x] Wire `MacosUserspaceSharedBackend::start()` to spawn the runtime worker.
- [x] Replace all `phase1_unimplemented()` returns in `TunnelBackend` with real dispatch.

**Status (2026-05-21):** Added
`crates/rustynet-backend-wireguard/src/userspace_shared_macos/runtime.rs` by
porting the Linux shared runtime shape to macOS socket/TUN types while reusing
the shared boringtun engine and handshake telemetry. Unit tests prove worker
identity reporting, backend start/shutdown, authoritative STUN-style round trip
on the worker-owned UDP socket, peer configuration/stats, peer handshake egress,
worker recovery scaffolding, and transport generation reuse. Production
`DirectMacosTunLifecycle` now reconciles non-default macOS routes through
argv-only `route` calls with rollback on failure. It also handles full-tunnel
exit mode by capturing the default route, installing exact peer endpoint bypass
host routes scoped to the underlay interface, moving the IPv4 default route to
the utun interface, refreshing bypass routes when peer endpoints change, and
restoring the original default route during exit-mode off or cleanup. Daemon
integration is wired in Phase 6.
Follow-up code hardening on 2026-05-21 tightened macOS route CIDR validation to
parse `IpAddr`/prefixes before argv construction, removed stale lifecycle
default "not implemented" methods, and made default-route/bypass cleanup state
retry-safe after route command failures.
Additional non-live parity coverage now proves macOS authoritative send uses the
worker-owned socket, round trips fail closed before start and after shutdown,
configured peer endpoints cannot be used as STUN/relay round-trip targets, and
backend restart gets a fresh transport generation.
The macOS backend test lifecycle now validates route CIDRs before recording a
route mutation, so invalid-route tests exercise the same fail-before-mutation
contract as the production direct route path. Backend-level tests also cover
duplicate peer configure, unconfigured peer update failure, handshake freshness
staying unchanged until engine activity, timeout cleanup for authoritative
round trips, route apply preserving transport identity, invalid route rejection
without state drift, exit-mode peer endpoint refresh, and shutdown clearing
exit-mode state.
Mac test lifecycle parity now includes route and exit-mode failure injection,
programmed route state, current exit-mode state, and worker-death recovery
coverage before peer configuration and route application.
Shared-transport parity coverage now also proves relay round-trip and relay
send use the same transport generation as peer ingress, relay control does not
advance peer handshake freshness, and an explicit macOS-to-macOS userspace
handshake uses the worker-owned authoritative sockets on both sides.
Security hardening now parses macOS command-backend and userspace-shared CIDRs
as `IpAddr` plus bounded prefix before accepting route, local-address, or peer
allowed-IP input. This rejects malformed addresses, extra separators, shell or
argv metacharacters, and invalid IPv4/IPv6 prefix lengths before backend state
mutation. macOS userspace-shared conformance tests now mirror the Debian shared
backend lifecycle, route/exit capability, and fail-before-mutation contracts.
Additional 2026-05-21 peer-mutation hardening made full-tunnel bypass refresh
transactional for peer add, endpoint update, and peer removal. If macOS bypass
route refresh fails after a peer mutation starts, runtime state rolls back to
the previous peer set/endpoint before returning the error, and tests prove the
operation can be retried from the retained state.
The userspace-shared macOS exit helper also now reconciles endpoint bypass
routes transactionally: stale bypass deletion is rolled back when adding the
new bypass host fails, and default-route-change failure reports bypass cleanup
failure instead of hiding leftover privileged route state.
The legacy command-only macOS backend was also hardened so it cannot drift
state silently while the shared backend is rolling out: non-default route
reconciliation now validates all CIDRs before mutation and rolls back on route
command failure; default-gateway parsing now requires a typed IPv4 address
instead of accepting arbitrary `route get default` text; and full-tunnel peer
add/update/remove refreshes endpoint bypass routes transactionally with wg
peer-state rollback on failure.
Follow-up command-backend cleanup hardening made exit-mode-off/default-route
restore fail closed too. Default-route restore failures and endpoint-bypass
delete failures now preserve retry state instead of clearing `default_gateway`
or bypass-host tracking, so a later retry can finish cleanup rather than losing
knowledge of installed privileged route state.
Additional 2026-05-22 runtime hardening bounds macOS userspace-shared
per-tick authoritative UDP datagram and TUN packet processing. This prevents a
peer-reachable UDP flood or local TUN packet flood from monopolizing the worker
loop and starving control/shutdown/recovery requests. Unit tests exercise both
budgets directly against the runtime state.
The same liveness, authoritative-transport recovery, and packet-budget contract
was then applied back to the Linux userspace-shared reference backend so macOS
and Debian/Linux shared backends remain behaviorally aligned.
Full-tunnel enable on the command backend now uses the command-runner capture
path for default-route discovery instead of an unmocked direct `/sbin/route`
spawn, and enable is transactional: bypass install failure restores pre-enable
state, default-route change failure deletes any newly installed bypass routes,
and tests assert `exit_mode` remains `Off` after failed enable.
`wireguard-go` cleanup PID discovery was tightened to parse `ps` output into
an exact two-token command shape whose executable basename is `wireguard-go`
and whose only argument is the managed utun interface. This avoids killing
unrelated processes whose command text merely ends with a similar suffix, and
malformed exact-match PID values fail closed.
Additional command-backend cleanup hardening now reports interface cleanup
failures during failed start instead of hiding them, treats missing macOS route
deletes as idempotent for stale route and bypass cleanup, preserves retry state
only for real delete failures, and ignores only clearly missing interfaces
during `ifconfig down` cleanup.
Additional userspace-shared hardening now treats zero-length utun reads and
test-injected empty TUN frames as no packet, preventing malformed plaintext
frames from driving worker churn. The authoritative UDP send path on both macOS
and the Linux shared reference now verifies `send_to` wrote the full datagram
length. macOS userspace-shared shutdown and worker-recovery cleanup failures
now leave an explicit retryable `cleanup_pending` state, preserve desired state
until cleanup succeeds, and allow a later `shutdown()` or `start()` attempt to
finish privileged route/exit cleanup instead of losing cleanup state.
Additional macOS backend validation now rejects runtime-context interface
drift before any backend mutation in both the userspace-shared and command-only
adapters. Both macOS adapters also reject invalid peer endpoints before
WireGuard mutation: zero ports, unspecified addresses, multicast addresses,
and IPv4 broadcast addresses fail closed without changing peer state.
Runtime-context CIDRs are now validated before start-side mutation too, so a
malformed mesh CIDR or non-IPv4 local CIDR cannot be retained as trusted
backend context or reach key/device setup on macOS while IPv6 local tunnel
parity is still unsupported.
The command-only adapter also renders IPv6 peer endpoints with WireGuard's
bracketed `[addr]:port` form instead of ambiguous colon joining.
The macOS userspace-shared adapter now also rejects IPv6 peer endpoints until
the backend owns an IPv6-capable authoritative socket; this prevents accepting
state that the current IPv4-only socket cannot send. STUN/relay authoritative
transport targets are validated before send/operation recording too: zero
ports, unspecified addresses, IPv6 targets, multicast targets, and IPv4
broadcast targets fail closed without socket mutation or retained test records.
The same IPv4-only peer endpoint boundary is enforced again inside the macOS
runtime worker, so crate-internal `RuntimeControl` calls cannot bypass the
public backend validation and poison engine peer state. The public backend and
runtime worker now share one Rust validator for this boundary, reducing drift
between the two enforcement points.
The macOS authoritative send path now rejects configured peer endpoints too,
matching the round-trip guard so relay/STUN control payloads cannot be sent as
arbitrary datagrams to the WireGuard peer data endpoint.
Direct macOS `utun` startup cleanup now reports cleanup failures alongside the
primary configure failure instead of hiding failed `ifconfig down`/route-state
cleanup during failed device bring-up.
Direct macOS backend cleanup now attempts default-route/bypass restoration and
`utun` interface-down cleanup even when the first cleanup step fails, and
combines both errors when both fail. This prevents a failed route restore from
silently skipping interface shutdown.
Both macOS adapters now keep route-delete idempotency narrow: real missing
routes (`not in table` / `No such process`) remain harmless, but `route` tool
spawn failures such as `No such file or directory` no longer get mistaken for
an absent route.
The command-only macOS backend now aggregates independent cleanup failures from
interface shutdown, default-route restoration, and `wireguard-go` termination,
so a first cleanup failure no longer hides later route or process cleanup
failures from operators.
Backend conformance now also covers macOS userspace-shared endpoint boundary
behavior: invalid peer endpoints fail before state mutation, and authoritative
relay/STUN sends cannot target a configured WireGuard peer endpoint.

---

## Phase 6 — Daemon integration

**Goal:** Allow the daemon to use `MacosWireguardUserspaceShared` backend mode on macOS.

**Tasks:**
- [x] Implement production macOS route reconciliation in `DirectMacosTunLifecycle`.
- [x] Implement production macOS exit-mode reconciliation in `DirectMacosTunLifecycle`.
- [x] Remove `userspace_shared_blocker()` return for `MacosWireguardUserspaceShared`
  in `crates/rustynetd/src/daemon.rs`.
- [x] Add macOS-specific `validate_daemon_config` path (private key, listen port).
- [x] Add `DaemonBackend::MacosWireguardUserspaceShared` variant wired to
  `MacosUserspaceSharedBackend`.
- [x] Update `validate_daemon_config_rejects_macos_userspace_shared_backend_with_precise_blocker`
  test to confirm the backend is now accepted rather than blocked.
- [x] Add `daemon_runtime_macos_userspace_shared_backend_reports_authoritative_transport_state`
  integration test mirroring the Linux authoritative transport state test.

**Status (2026-05-21):** Daemon config validation now accepts
`macos-wireguard-userspace-shared` with runtime WireGuard key material,
`DaemonBackend` has a macOS userspace-shared variant wired to
`MacosUserspaceSharedBackend`, interface-down operations fail closed with a
backend-shutdown instruction, and the macOS authoritative transport state test
proves daemon status/netcheck see `authoritative_backend_shared_transport`.
Follow-up daemon-side validator hardening on 2026-05-21 made macOS runtime ACL
and key-custody reports aggregate explicit drift reasons and fail closed on
empty report sets. Key custody now also treats a plaintext WireGuard
passphrase file at rest as forbidden. The reviewed launchd template and
bootstrap installer now target `macos-wireguard-userspace-shared`, include
runtime private-key/passphrase arguments required by the daemon, provision the
reviewed Keychain environment variables, and reject plist-unsafe node/path
inputs before rendering.
Additional non-live service hardening on 2026-05-21 parses and validates both
launchd `ProgramArguments` and `EnvironmentVariables`. The service report now
fails closed unless launchd pins the userspace-shared backend, supplies runtime
WireGuard key/passphrase arguments, and uses the reviewed Keychain service,
account shape, and fallback credential path. VM-lab bootstrap now maps the
orchestrator `exit` role to the daemon's `blind_exit` role before rendering the
macOS launchd service, with embedded-script tests covering backend selection,
Keychain env, plist input rejection, and role mapping.
Follow-up Keychain alignment fixed the daemon and CLI custody paths to use the
same reviewed WireGuard passphrase service as launchd
(`net.rustynet.wg-key-passphrase`) and the same account character boundary.
The macOS DNS fail-closed report now rejects empty nameserver snapshots and
missing loopback-resolver advertisement instead of treating unverifiable DNS
state as clean. macOS traffic adapter probes now require parsed IP targets,
reject CIDR/host/special-address inputs before shell embedding, and fail closed
when diagnostic tarball inspection cannot list archive contents.

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
- [x] TUN (utun) lifecycle — Phase 2
- [x] Authoritative UDP socket — Phase 3
- [x] boringtun engine — Phase 4
- [x] Async runtime worker — Phase 5
- [x] Daemon integration — Phase 6
- [x] Non-live cleanup retry, UDP send-length, and empty TUN-frame hardening (2026-05-21)
- [x] Non-live macOS context/interface and endpoint fail-before-mutation validation (2026-05-21)
- [x] Non-live macOS runtime CIDR validation and IPv6 peer endpoint rendering hardening (2026-05-21)
- [x] Non-live macOS IPv4-only authoritative socket boundary enforcement for peer endpoints and relay/STUN targets (2026-05-21)
- [x] Non-live macOS runtime-worker endpoint validation defense-in-depth (2026-05-21)
- [x] Non-live macOS authoritative-send peer-endpoint isolation (2026-05-21)
- [x] Non-live macOS direct-utun failed-start cleanup error reporting (2026-05-21)
- [x] Non-live macOS direct cleanup attempts route restore and interface down independently (2026-05-21)
- [x] Non-live macOS route-delete idempotency no longer hides route tool spawn failures (2026-05-21)
- [x] Non-live macOS command-backend cleanup reports multiple failed cleanup steps (2026-05-21)
- [x] Non-live macOS conformance coverage for endpoint fail-before-mutation and control-send isolation (2026-05-21)
- [x] Non-live macOS key-custody report drift aggregation and plaintext passphrase-at-rest rejection (2026-05-21)
- [x] Non-live macOS runtime ACL report drift aggregation and empty-report fail-closed behavior (2026-05-21)
- [x] Non-live macOS launchd template/installer moved to userspace-shared backend with keychain env and plist-input validation (2026-05-21)
- [x] Non-live macOS launchd service report validates ProgramArguments and Keychain environment variables (2026-05-21)
- [x] Non-live macOS VM bootstrap maps orchestrator `exit` role to daemon `blind_exit` and tests embedded scripts (2026-05-21)
- [x] Non-live macOS Keychain service/account contract aligned across launchd, daemon key loader, CLI custody ops, and doctor checks (2026-05-21)
- [x] Non-live macOS DNS fail-closed report rejects empty nameserver/unadvertised loopback resolver state (2026-05-21)
- [x] Non-live macOS traffic adapter rejects non-IP/special ping targets and unreadable diagnostic archives fail closed (2026-05-21)
- [x] Non-live daemon integration now reports macOS userspace-shared authoritative transport unavailable after fake runtime worker exit, and full-tunnel route activation is rejected before mutation when protected DNS is disabled (2026-05-22)
- [x] Non-live macOS parity now proves daemon authoritative transport recovery after fake worker death, backend conformance for identity hiding/recovery/rollback retryability, and macOS DNS assertion before full-tunnel commit (2026-05-22)
- [x] Non-live macOS route/DNS/PF parity now has full-tunnel route/DNS ordering coverage, exact PF rule snapshots, Linux+macOS daemon shared-transport recovery parity, and hidden fake-backend hooks gated behind explicit `test-harness` cargo features (2026-05-22)
- [ ] Live lab validation — Phase 7
