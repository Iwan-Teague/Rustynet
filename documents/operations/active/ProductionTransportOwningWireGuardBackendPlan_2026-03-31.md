# Rustynet Production Transport-Owning WireGuard Backend Plan
**Generated:** 2026-03-31  
**Repository Root:** `/Users/iwanteague/Desktop/Rustynet`  
**Status:** Active supporting implementation plan for the remaining pre-live-lab traversal/relay backend delta  
**Owning Ledger:** [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

## 0. Purpose And Document Relationship
This document exists to close the last meaningful non-live implementation gap before Rustynet can begin honest five-to-six-node simulated or live lab traversal testing:

- the repository already has truthfulness hardening,
- the repository already has fail-closed authoritative transport contracts,
- the repository already blocks dishonest second-socket STUN and relay bootstrap,
- but the repository still does **not** have a production backend that owns the same UDP socket used for:
  - peer ciphertext traffic,
  - STUN round trips,
  - relay hello/refresh round trips,
  - relay keepalive sends.

This plan is not a status ledger replacement. Status truth remains in:
- [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)
- [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)

This document is the implementation blueprint for the remaining code delta only.

## 1. Current Audited Baseline
The following repository state is already true and must not be regressed:

### 1.1 Backend Contract Already Exists
The backend API already exposes the required transport-agnostic contract in [crates/rustynet-backend-api/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/src/lib.rs):
- `AuthoritativeTransportIdentity`
- `AuthoritativeTransportResponse`
- `TunnelBackend::authoritative_transport_identity()`
- `TunnelBackend::authoritative_transport_round_trip(...)`
- `TunnelBackend::authoritative_transport_send(...)`
- `TunnelBackend::transport_socket_identity_blocker()`

### 1.2 Daemon Already Consumes That Contract Correctly
The daemon/runtime path already consumes the contract in:
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs)
- [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)

Truthfulness hardening that must remain unchanged:
- `direct_active` still requires fresh handshake proof.
- `relay_active` still requires fresh handshake proof plus authenticated relay-session consistency.
- command-only backends must still fail closed when authoritative shared transport is required.

### 1.3 Only The In-Memory Backend Proves Shared Transport Today
The only backend that currently satisfies the authoritative shared-transport contract is the in-memory/test backend inside [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs).

Current production backends remain command-only adapters:
- Linux backend: command runner over kernel WireGuard / `wg` / `ip`
- macOS backend: command runner over `wireguard-go`

Those adapters honestly report blocker strings because they do not own authoritative packet I/O.

### 1.4 Current WireGuard Backend Crate Now Contains Only A Partial Production Substrate
[crates/rustynet-backend-wireguard/Cargo.toml](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/Cargo.toml) now pins the released userspace-backend dependencies:
- `boringtun = "0.7.0"`
- `tun-rs = "2.8.2"`

The crate now contains:
- the split backend module tree,
- the Phase 2 Linux userspace-shared runtime skeleton,
- a real backend-owned authoritative UDP socket owner,
- a real backend-owned runtime worker boundary,
- a real `boringtun`-backed engine wrapper boundary,
- an owned handshake telemetry container.

The crate still does **not** contain the later production pieces required for live-lab truth:
- backend-owned STUN/relay round-trip/send operations on that socket,
- peer ciphertext datapath integration,
- backend-native authenticated handshake advancement,
- a real TUN datapath,
- daemon/install/start selection wiring for the new backend mode.

### 1.5 Backend Mode Plumbing Exists But Is Intentionally Blocked
The new non-default backend mode names are already wired and must be preserved:
- `linux-wireguard-userspace-shared`
- `macos-wireguard-userspace-shared`

Current behavior:
- parser/startup accepts the values,
- host-profile enforcement preserves them,
- daemon startup still rejects them fail-closed with precise blocker text until the later implementation phases wire the new backend mode end-to-end.

### 1.6 Current Gate Baseline
As of the audited 2026-03-31 tree:
- `./scripts/ci/phase10_hp2_gates.sh` passes
- `./scripts/ci/phase10_cross_network_exit_gates.sh` fails closed only on missing canonical live reports
- `./scripts/ci/phase10_gates.sh` fails closed only on stale fresh-install matrix evidence for current `HEAD`
- `./scripts/ci/membership_gates.sh` no longer dies on the earlier CLI/module-path regression; any remaining red path must not come from this transport-owning backend slice

This document must not soften those gates.

## 2. Definition Of “Ready To Start Live Lab”
This plan is complete enough to begin honest simulated or live lab runs only when all of the following are true:

1. `linux-wireguard-userspace-shared` exists as a real backend implementation.
2. That backend owns the authoritative peer UDP socket.
3. Peer ciphertext traffic uses that exact socket.
4. STUN round trips use that exact socket.
5. Relay hello/refresh round trips use that exact socket.
6. Relay keepalive sends use that exact socket.
7. Backend-native handshake telemetry comes from authenticated WireGuard engine evidence, not programmed state.
8. Non-live tests prove the same-socket invariant directly at the socket-instance or backend-owned transport-generation level, not merely by matching local port or local address text.
9. Regression and CI gates stay green except for separately documented live-artifact blockers.

This document does **not** include the live-lab evidence run itself. That begins only after the phases below are complete.

## 3. Approved Design Decisions
The following decisions are fixed for this implementation. Engineers are not being asked to redesign them.

### 3.1 WireGuard Engine Choice
Selected:
- direct Rust-native `boringtun` library integration from a released `crates.io` version

Rejected for this slice:
- `wireguard-go` subprocess ownership
- command-only kernel WireGuard ownership
- branch-tip git dependencies

Why this choice is fixed:
- Rustynet needs backend-owned packet I/O, not merely backend-configured transport.
- The backend must own the authoritative socket inside the Rust process.
- The daemon must not infer authority from a second socket.
- `boringtun` is the best fit for Rust-first, in-process ownership while keeping WireGuard as an adapter behind `TunnelBackend`.

Implementation rule:
- use a released crate version pinned in `Cargo.lock`
- do not use upstream branch tips
- vendor a fork only if a narrow backend-internal patch is required
- do not add git-branch dependencies for the shared-backend path
- if a dependency brings required `unsafe` internally, contain it inside backend adapter modules and add targeted tests around the resulting trust boundary rather than widening assumptions across crates

### 3.2 TUN / Interface Layer Choice
Selected:
- `tun-rs`

Rejected for this slice:
- a long-lived helper-owned datapath
- a large custom Linux `/dev/net/tun` implementation before first lab proof

Why this choice is fixed:
- the backend needs a real Linux TUN path now,
- the authoritative socket must stay inside the backend,
- `tun-rs` reduces implementation risk while keeping the backend authoritative.

Implementation rule:
- if helper-assisted TUN setup is required, long-lived TUN ownership must still transfer into the backend runtime immediately
- the helper must not remain in the packet path after setup completes

### 3.3 Privilege Model
Selected:
- helper-assisted host networking setup, backend-owned runtime transport

Required boundary:
- the privileged helper may create/configure host networking resources if needed,
- but it must never own:
  - the authoritative UDP socket,
  - the userspace WireGuard engine,
  - STUN round trips,
  - relay round trips,
  - relay keepalive sends,
  - transport identity authority.

Why this choice is fixed:
- it preserves the repository’s hardened privileged boundary,
- keeps long-lived transport authority inside the backend,
- avoids splitting trust or transport identity across processes.

### 3.4 Platform Scope
Selected:
- Linux production userspace-shared backend is mandatory in this slice.
- macOS userspace-shared backend is explicitly optional and may remain blocked.

Why this choice is fixed:
- the immediate live-lab target is Linux,
- widening to macOS now delays the only platform required for honest traversal/relay proof,
- README and ledgers must remain truthful if macOS remains blocked.

### 3.5 Shared Transport Runtime Model
Selected:
- one backend-owned authoritative UDP socket
- one backend-owned userspace WireGuard engine
- one backend-owned TUN datapath
- one backend-owned runtime worker that is the sole owner of transport state
- at most one outstanding authoritative generic round trip at a time

This is not negotiable because it is the only model that preserves unambiguous transport authority.

## 4. Non-Negotiable Security And Architecture Rules
The implementation must preserve all of these rules:

1. No daemon-owned side socket for STUN.
2. No daemon-owned side socket for relay.
3. No same-port second-socket tricks using `SO_REUSEADDR`, `SO_REUSEPORT`, or equivalent.
4. No `wireguard-go` subprocess for the new shared mode.
5. No kernel WireGuard transport for the new shared mode.
6. No helper-owned authoritative UDP socket.
7. No WireGuard engine types leaking into `rustynetd` policy/control layers.
8. No weakening of `direct_active` or `relay_active`.
9. No change to the relay protocol design.
10. No change to traversal signature/freshness authority.
11. No optimistic README or ledger claims before live evidence exists.
12. No silent fallback from `linux-wireguard-userspace-shared` to `linux-wireguard` on startup, privilege failure, dependency failure, or runtime error.

## 5. Current-To-Target Delta Matrix
| Area | Current State | Required State Before Live Lab | Exact Delta |
| --- | --- | --- | --- |
| Linux backend runtime | command-only adapter over OS-managed socket | Rust backend owns UDP socket and WG engine | add new production userspace runtime |
| STUN authority | daemon contract exists, production backends blocked | same socket as peer ciphertext | implement backend-owned round trip |
| Relay authority | daemon contract exists, production backends blocked | same socket as peer ciphertext | implement backend-owned round trip + send |
| Handshake telemetry | command backends use external status | userspace-shared backend must emit backend-native handshake timestamps | add authenticated per-peer telemetry in backend runtime |
| TUN datapath | command backend configures external interface | userspace-shared backend owns plaintext datapath lifecycle | add TUN creation/open/configuration path |
| Mode selection | mode names parse but are blocked | Linux shared mode constructs real backend | instantiate backend in daemon/start/install surfaces |
| Test proof | in-memory backend only | production backend same-socket proof | add backend, daemon, and simulated integration tests |
| Gate confidence | truthfulness gates hardened | new backend must not regress any gate | extend tests/gates without softening live-evidence failures |

## 6. Exact Target Runtime Architecture
The production target for `linux-wireguard-userspace-shared` is:

1. A backend object implementing `TunnelBackend`.
2. A dedicated backend runtime worker thread that owns all mutable transport state.
3. A single backend-owned authoritative UDP socket bound to the configured listen port.
4. A backend-owned userspace WireGuard engine for every configured peer.
5. A backend-owned TUN device or TUN handle for plaintext packets.
6. A synchronous command channel from `TunnelBackend` methods into the runtime worker.
7. A narrow reply path for:
   - lifecycle operations,
   - peer configuration,
   - endpoint updates,
   - authoritative round trips,
   - authoritative sends,
   - handshake timestamp queries,
   - stats,
   - shutdown.

### 6.1 Ownership Invariant
The local address returned from `authoritative_transport_identity()` must be the actual local address of the same UDP socket used for peer ciphertext traffic.

The same socket must be used for:
- peer handshake and data traffic,
- STUN round trips,
- relay hello/refresh round trips,
- relay keepalive sends.

### 6.1.1 Proof Invariant
For this plan, “same socket” does **not** mean:
- same local port only,
- same local address string only,
- same process only,
- same interface only.

It means:
- the same backend-owned socket instance, or
- the same backend-owned transport generation backed by exactly one authoritative socket instance for its lifetime.

Required implementation consequence:
- the userspace backend runtime must maintain an internal monotonic transport-generation identifier or equivalent socket-instance token,
- that token must change whenever the authoritative socket is recreated,
- test-only instrumentation must expose enough data to prove that:
  - peer ciphertext egress/ingress,
  - STUN round trips,
  - relay control round trips,
  - relay keepalive sends
  all used the same authoritative transport generation.

Local address equality is necessary but not sufficient proof.

### 6.2 Demultiplexing Invariant
Socket read behavior must follow this exact rule order:

1. If there is an active authoritative round trip and the source address exactly matches the expected remote address for that round trip, deliver the datagram to the waiting round-trip caller.
2. Otherwise, deliver the datagram to the userspace WireGuard engine as peer ciphertext input.
3. Do not add packet-content guessing for control-vs-peer authority.
4. Do not create any second socket for “clean” control traffic.

### 6.3 Round-Trip Concurrency Invariant
The backend must allow at most one outstanding authoritative generic round trip at a time.

Required behavior:
- if a second `authoritative_transport_round_trip(...)` arrives while one is in flight, return an explicit fail-closed backend error immediately
- do not queue round trips
- do not attempt ambiguous concurrent demultiplexing

### 6.3.1 Round-Trip Cleanup Invariant
Outstanding round-trip state must be cleared on all terminal paths:
- success
- timeout
- backend shutdown
- authoritative socket close
- transport-generation rollover

Required behavior:
- a timed-out or canceled round trip must not leave residual source attribution behind
- a later datagram from the old remote endpoint must not be delivered to a stale waiter
- transport-generation change must cancel any in-flight round trip fail-closed

### 6.4 Round-Trip Target Safety Invariant
`authoritative_transport_round_trip(...)` must reject a target address that currently matches any configured peer endpoint.

Reason:
- peer ciphertext datagrams must never be ambiguously mixed with generic backend round-trip traffic.

Exception:
- `authoritative_transport_send(...)` may target the selected relay endpoint because relay keepalive traffic legitimately shares the active relay path.

### 6.5 Handshake Telemetry Invariant
The userspace backend must implement `peer_latest_handshake_unix(...)` from authenticated engine evidence only.

It must **not** be updated from:
- programmed endpoints,
- STUN success,
- relay control success,
- optimistic state transitions.

### 6.6 Transport Regeneration Invariant
If the authoritative socket is lost, closed, or deliberately recreated:
- the backend must advance transport generation,
- clear any in-flight authoritative round-trip state,
- preserve no stale attribution from the old socket,
- force fresh post-change runtime proof before any new direct or relay-active claim can become live.

The implementation must not treat socket recreation as a transparent continuation of previously proven transport identity.

### 6.7 Privilege Invariant
Any helper interaction may assist only with:
- TUN/interface creation,
- address assignment,
- route setup or teardown if required by existing backend behavior,
- host integration operations already in scope for the helper.

The helper must never own runtime transport.

## 7. Required File And Module Layout
Current state:
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs) is too large to remain the sole implementation file once the userspace runtime lands.

Required target layout inside [crates/rustynet-backend-wireguard/src](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src):
- `lib.rs`
  - exports backend constructors and shared public types only
- `in_memory.rs`
  - existing in-memory/test backend moved out of `lib.rs`
- `linux_command.rs`
  - existing command-only Linux adapter
- `macos_command.rs`
  - existing command-only macOS adapter
- `userspace_shared/mod.rs`
  - Linux userspace-shared backend public glue
- `userspace_shared/runtime.rs`
  - backend runtime worker and command loop
- `userspace_shared/socket.rs`
  - authoritative UDP socket ownership, send, receive, and round-trip state
- `userspace_shared/engine.rs`
  - userspace WireGuard engine wrapper and per-peer state
- `userspace_shared/tun.rs`
  - TUN open/configure/read/write lifecycle
- `userspace_shared/handshake.rs`
  - authenticated handshake timestamp tracking

If the final module split differs slightly, the responsibilities above must still remain separated.

## 8. Phase 1: Crate Restructure And Dependency Introduction
### 8.1 Objective
Prepare the backend crate for a production userspace runtime without changing product claims yet.

### 8.2 Files To Touch
- [crates/rustynet-backend-wireguard/Cargo.toml](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/Cargo.toml)
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs)
- newly created files under [crates/rustynet-backend-wireguard/src](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src)

### 8.3 Exact Work
1. Split current `lib.rs` into the module layout in Section 7.
2. Keep the existing in-memory backend behavior unchanged.
3. Keep the existing command-only Linux and macOS adapters unchanged.
4. Add released, pinned dependencies for:
   - `boringtun`
   - `tun-rs`
5. Add only the minimum runtime and synchronization dependencies needed to implement a single-owner backend worker model.
6. Do not widen the public backend API unless a concrete missing capability is proven.
7. Update dependency governance in the same change:
   - no git branch dependencies for the shared-backend path
   - no hidden optional fallback dependency that silently switches implementation mode
   - keep new dependency usage contained to backend adapter modules unless an API expansion is explicitly justified

### 8.4 Deliverables
- backend crate still compiles
- existing in-memory and command-only tests still pass
- no status or README claims change yet

### 8.5 Mandatory Validation
- `cargo fmt --all -- --check`
- `cargo check -p rustynet-backend-wireguard`
- existing backend tests in [crates/rustynet-backend-wireguard/tests/conformance.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/tests/conformance.rs)

### 8.6 Status - 2026-03-31
Phase 1 is complete in the current tree.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs) now acts as a stable crate root with explicit module ownership boundaries and stable public re-exports for the existing in-memory and command-only backends.
- Existing in-memory backend logic was moved into [crates/rustynet-backend-wireguard/src/in_memory.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/in_memory.rs) without widening any claims or changing its authoritative shared-transport test behavior.
- Existing Linux command-only backend logic was moved into [crates/rustynet-backend-wireguard/src/linux_command.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/linux_command.rs) without changing its fail-closed blocker behavior.
- Existing macOS command-only backend logic was moved into [crates/rustynet-backend-wireguard/src/macos_command.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/macos_command.rs) without changing its fail-closed blocker behavior.
- The required `userspace_shared` module tree now exists under [crates/rustynet-backend-wireguard/src/userspace_shared](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared) as compileable Phase 1 boundary scaffolding only:
  - `mod.rs`
  - `runtime.rs`
  - `socket.rs`
  - `engine.rs`
  - `tun.rs`
  - `handshake.rs`
- [crates/rustynet-backend-wireguard/Cargo.toml](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/Cargo.toml) now pins released crate versions for:
  - `boringtun = "0.7.0"`
  - `tun-rs = "2.8.2"`
- [Cargo.lock](/Users/iwanteague/Desktop/Rustynet/Cargo.lock) now records the resolved Phase 1 dependency graph for those released versions.

Not completed in Phase 1:
- no production `linux-wireguard-userspace-shared` runtime exists yet
- no authoritative UDP socket ownership exists yet
- no TUN/runtime worker exists yet
- no daemon or live-lab selection behavior changed in this slice

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/in_memory.rs crates/rustynet-backend-wireguard/src/linux_command.rs crates/rustynet-backend-wireguard/src/macos_command.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/tests/conformance.rs`
- `cargo fmt --all -- --check`
- `cargo check -p rustynet-backend-wireguard`
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`

Historical status note:
- As of 2026-03-31, Phase 2 remained fully open.
- See Section 9.7 for the 2026-04-01 completion update.

## 9. Phase 2: Linux Userspace-Shared Runtime Skeleton
### 9.1 Objective
Create a real `linux-wireguard-userspace-shared` backend that owns its runtime resources but is not yet fully wired to daemon selection surfaces.

### 9.2 Files To Touch
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs)

### 9.3 Exact Work
1. Add a new backend type for `linux-wireguard-userspace-shared`.
2. On `start(...)`, create:
   - the authoritative UDP socket,
   - the runtime worker,
   - the userspace engine wrapper,
   - the internal command channel.
3. Bind the authoritative socket to the configured listen port.
4. Return `authoritative_transport_identity()` only after successful `start(...)`.
5. Make `shutdown()` deterministically stop the worker, close the socket, and clear state.
6. Keep the command-only Linux backend unchanged.
7. If startup fails after any partial resource acquisition, tear down all partially created resources and return a fail-closed error without falling back to command-only mode.

### 9.4 Required Worker Behavior
The runtime worker must be the sole owner of:
- UDP socket
- peer engine state
- endpoint table
- outstanding round-trip state
- handshake telemetry map

`TunnelBackend` method calls must talk to the worker through an internal request/reply interface. The public backend object must not duplicate transport ownership.

### 9.5 Deliverables
- backend starts and stops cleanly
- authoritative identity is absent before start and present after start
- command-only backends still report blockers unchanged

### 9.6 Mandatory Tests
Add tests proving:
- `authoritative_transport_identity()` is unavailable before start
- `authoritative_transport_identity()` returns the authoritative local address after start
- command-only Linux backend still reports blocker
- command-only macOS backend still reports blocker
- partial startup failure does not leave a live socket, worker, or hidden fallback backend behind

### 9.7 Status - 2026-04-01
Phase 2 is complete in the current backend crate.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) now defines a real `LinuxUserspaceSharedBackend` type with validated constructor inputs, runtime ownership state, authoritative identity reporting only after successful start, deterministic shutdown, and fail-closed later-phase method behavior.
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs) now implements a real single-owner runtime worker with explicit request/reply messages, worker-owned socket/peer-engine/endpoint/round-trip/handshake containers, ready-handshake startup, and shutdown that joins the worker deterministically.
- [crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs) now binds a real authoritative UDP socket to the configured listen port and reports its actual local address through `authoritative_transport_identity()`.
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs) now provides a real backend-internal `boringtun` key-material wrapper that reads the configured WireGuard private key, derives the static public key, and owns the future peer-engine container without leaking WireGuard engine types outside the backend crate.
- [crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs) now provides the owned handshake telemetry map required for later authenticated handshake advancement without fabricating freshness in Phase 2.
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs) now re-exports the new Linux userspace-shared backend type for backend-crate construction/testing only; no daemon or product-surface wiring changed in this phase.
- [crates/rustynet-backend-wireguard/tests/conformance.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/tests/conformance.rs) now covers the new backend lifecycle and confirms the command-only Linux/macOS blocker strings remain unchanged.

Validated in this slice:
- `authoritative_transport_identity()` is absent before start and present only after successful start.
- `start(...)` fails closed on repeated invocation.
- startup binds a real authoritative UDP socket to the configured listen port.
- startup failure after socket bind but before runtime completion rolls back cleanly and releases the port.
- `shutdown()` tears down the runtime, joins the worker, clears identity visibility, and releases the port deterministically.
- command-only Linux/macOS backends remain unchanged and still report their precise blocker strings.
- Phase 2 does not add STUN, relay round-trip/send, peer ciphertext, TUN datapath, or daemon wiring.

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/tests/conformance.rs`
- `cargo fmt --all -- --check`
  - Current result: fails on unrelated pre-existing formatting drift in [mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/vm_lab/mod.rs).
- `cargo check -p rustynet-backend-wireguard`
  - Current result: pass
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - Initial sandboxed run hit `EPERM` when the new socket-binding tests tried to bind a real UDP socket.
  - Unsandboxed rerun for the backend crate only:
    - `CARGO_TARGET_DIR=/tmp/rustynet-phase2-target-escalated cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
    - Result: pass
- Final compile recheck after the last cleanup:
  - `CARGO_TARGET_DIR=/tmp/rustynet-phase2-check cargo check -p rustynet-backend-wireguard`
  - Result: pass

Phase 2 completed:
- real Linux userspace-shared backend type
- real authoritative socket ownership on successful start
- real runtime worker ownership boundary
- real backend-internal engine wrapper boundary
- deterministic shutdown and partial-start rollback
- test-backed lifecycle and blocker preservation

What remains for Phase 3:
- implement `authoritative_transport_round_trip(...)`
- implement `authoritative_transport_send(...)`
- keep one outstanding generic round trip at a time
- reject configured peer endpoints for generic round trips
- begin same-socket STUN/relay control proof on the authoritative socket

Residual risks / blockers after Phase 2:
- Phase 2 does not yet provide STUN or relay operations on the authoritative socket; later-phase methods still fail closed with precise errors.
- Phase 2 does not yet provide peer ciphertext datapath, TUN lifecycle, or authenticated handshake advancement.
- Daemon/start/install selection surfaces still intentionally reject `linux-wireguard-userspace-shared`; that remains correct until later phases land.
- The backend crate still emits non-blocking dead-code warnings from the untouched Phase 1 [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) scaffold because the real TUN datapath is intentionally deferred to Phase 5.

## 10. Phase 3: Same-Socket STUN And Relay Control
### 10.1 Objective
Make the backend-owned authoritative socket perform the exact STUN and relay control operations the daemon already expects.

### 10.2 Files To Touch
- [crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs)

### 10.3 Exact Work
1. Implement `authoritative_transport_round_trip(...)`.
2. Implement `authoritative_transport_send(...)`.
3. Enforce one outstanding round trip at a time.
4. Enforce round-trip target rejection when the target matches a configured peer endpoint.
5. Route non-round-trip traffic into the userspace WireGuard engine.
6. Preserve exact authoritative transport generation across:
   - STUN round trip,
   - relay hello/refresh round trip,
   - relay keepalive send,
   - peer ciphertext traffic.

### 10.4 Required Failure Modes
All of the following must fail closed:
- concurrent authoritative round trip attempt
- round trip before backend start
- round trip after shutdown
- round trip to configured peer endpoint
- malformed command sequencing that would require a second authoritative socket

### 10.5 Mandatory Backend Tests
Add tests proving:
- STUN-style round trip records the same authoritative transport generation as peer traffic
- relay-style round trip records the same authoritative transport generation as peer traffic
- relay keepalive send records the same authoritative transport generation as peer traffic
- second concurrent authoritative round trip is rejected
- same-port-but-different-socket behavior is not treated as authoritative transport
- round trip to configured peer endpoint is rejected
- timeout or cancellation clears waiter state so stale later packets cannot satisfy an old round trip

### 10.6 Mandatory Daemon Compatibility Tests
Existing daemon tests around authoritative transport must still pass:
- authoritative STUN path
- authoritative relay establish path
- authoritative relay keepalive path
- blocked backend fail-closed path

### 10.7 Status - 2026-04-01
Phase 3 is complete in the current backend crate.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) now routes `authoritative_transport_round_trip(...)` and `authoritative_transport_send(...)` into the real userspace-shared runtime instead of the earlier fail-closed placeholder path, while keeping later-phase route/exit-mode work fail-closed.
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs) now owns authoritative round-trip/send execution, enforces one in-flight generic round trip at a time, rejects configured peer endpoints for generic round trips, demultiplexes matching response datagrams before routing all other datagrams into the userspace engine boundary, records authoritative transport generation for test proof, and clears waiter state on timeout, shutdown, and worker exit.
- [crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs) now assigns a monotonic authoritative transport-generation token to each real socket instance, exposes nonblocking same-socket receive/send helpers, and preserves backend-owned socket identity without introducing a second socket.
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs) now records peer ciphertext ingress at the engine boundary with the same authoritative transport generation used by STUN and relay control operations, which provides the Phase 3 same-socket proof without overclaiming Phase 4 datapath parity.

Validated in this slice:
- authoritative round trip fails closed before backend start and after shutdown
- second concurrent generic round trip is rejected fail-closed
- generic round trip to a configured peer endpoint is rejected fail-closed
- STUN-style round trip, relay-style round trip, relay keepalive send, and peer ciphertext ingress all record the same authoritative transport generation
- same local port after backend restart yields a new transport generation, proving that same-port identity alone is not authoritative transport identity
- round-trip timeout clears waiter state and routes a late datagram into peer-path accounting instead of satisfying a stale waiter
- command-only Linux/macOS blocker behavior remains unchanged
- existing daemon authoritative STUN/relay/blocker tests still pass unchanged

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
- `cargo fmt --all -- --check`
  - Result: pass
- `cargo check -p rustynet-backend-wireguard`
  - Result: pass
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - Result: pass
  - Backend crate unit tests: 30 passed
  - Backend crate conformance tests: 6 passed
  - Non-blocking warning only: untouched Phase 1 [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) scaffold still emits dead-code warnings because the real TUN phase remains open
- `cargo test -p rustynetd daemon_runtime_authoritative_stun_refresh_uses_backend_shared_transport_identity -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_relay_establish_and_keepalive_use_backend_shared_transport_identity -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_transport_socket_identity_blocker_fail_closes_relay_bootstrap -- --nocapture`
  - Result: pass

Phase 3 completed:
- backend-owned authoritative round-trip support on the Linux userspace-shared socket
- backend-owned authoritative one-way send support on that same socket
- strict one-round-trip-at-a-time enforcement
- fail-closed rejection of generic round trips that target configured peer endpoints
- same-transport-generation proof across STUN, relay control, relay keepalive, and peer ciphertext ingress accounting
- stale waiter cleanup on timeout and shutdown paths

What remains for Phase 4:
- integrate the userspace WireGuard engine beyond conservative ingress accounting so peer ciphertext and authenticated handshake evidence come from real engine activity
- drive `peer_latest_handshake_unix(...)` from authenticated engine evidence only
- keep `direct_active` and `relay_active` truthfulness semantics unchanged while replacing programmed state with authenticated userspace-engine evidence

Residual risks / blockers after Phase 3:
- Phase 3 proves same authoritative socket generation for STUN, relay control, keepalive, and peer-path ingress accounting, but it does not yet provide authenticated handshake truth, full peer ciphertext datapath parity, or TUN lifecycle ownership.
- Daemon/start/install selection surfaces still intentionally do not construct `linux-wireguard-userspace-shared`; that remains later work.
- The untouched Phase 1 [tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) scaffold still emits non-blocking dead-code warnings until the TUN phase lands.

## 11. Phase 4: Userspace Engine Integration And Handshake Telemetry
### 11.1 Objective
Turn the userspace-shared backend from “socket owner” into a true WireGuard transport owner with authenticated handshake telemetry.

### 11.2 Files To Touch
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs)
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs)

### 11.3 Exact Work
1. Maintain per-peer userspace engine state inside the backend runtime.
2. Feed inbound ciphertext from the authoritative socket into the correct peer engine state.
3. Feed outbound plaintext from TUN into the correct peer engine state for encryption and send.
4. Track latest authenticated handshake timestamps per peer from engine evidence only.
5. Implement:
   - `configure_peer(...)`
   - `update_peer_endpoint(...)`
   - `current_peer_endpoint(...)`
   - `peer_latest_handshake_unix(...)`
   - `remove_peer(...)`
   - `stats(...)`

### 11.4 Truthfulness Rule
`peer_latest_handshake_unix(...)` must not advance on:
- peer configuration only,
- endpoint programming only,
- relay control exchange only,
- STUN success only.

It may advance only when the userspace engine produces authenticated evidence.

Additional required behavior:
- handshake timestamps must be scoped to the currently active peer/runtime state
- transport-generation rollover must not preserve fake freshness
- peer removal must clear handshake state for that peer

### 11.5 Mandatory Tests
Add tests proving:
- handshake timestamp is absent until authenticated engine activity occurs
- handshake timestamp updates after authenticated engine evidence
- programmed state alone does not update handshake time
- relay control packets do not update handshake time
- STUN traffic does not update handshake time
- transport-generation rollover does not preserve stale handshake freshness
- peer removal clears handshake telemetry for that peer

### 11.6 Daemon Regression Requirement
The following semantics must remain unchanged in daemon tests:
- `direct_active` still requires fresh handshake proof
- `relay_active` still requires fresh handshake proof plus authenticated relay-session consistency
- relay session endpoint mismatch still blocks live `relay_active`

### 11.7 Status - 2026-04-01
Phase 4 is complete in the current backend crate.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs) now owns real per-peer `boringtun::noise::Tunn` state keyed by `NodeId`, keeps runtime-owned endpoint and allowed-IP state with each peer, routes inbound ciphertext to the matched peer engine by configured endpoint, drives outbound encryption from the current backend-internal plaintext test boundary, and derives authenticated handshake observations from userspace-engine evidence rather than programmed state.
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs) now keeps peer configuration, endpoint state, authoritative socket ownership, round-trip state, and handshake telemetry synchronized inside the single-owner worker, applies engine outcomes back onto the authoritative socket, and implements honest `configure_peer(...)`, `update_peer_endpoint(...)`, `current_peer_endpoint(...)`, `peer_latest_handshake_unix(...)`, `remove_peer(...)`, and `stats(...)` behavior for the Linux userspace-shared backend.
- [crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs) now records monotonic per-peer authenticated handshake timestamps only when the userspace engine reports authenticated evidence, and clears that state on peer replacement/removal.
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) now carries Phase 4 backend tests for authenticated handshake advancement, negative handshake cases, peer replacement/removal, honest endpoint reporting, and honest stats behavior without widening any daemon or product claim.

Validated in this slice:
- handshake timestamps are absent until authenticated userspace-engine activity occurs
- authenticated userspace-engine activity between two Linux userspace-shared backends advances handshake timestamps on both peers
- peer configuration and endpoint programming alone do not advance handshake freshness
- STUN round trips do not advance handshake freshness
- relay control sends do not advance handshake freshness
- backend restart and new authoritative transport generation do not preserve stale handshake freshness
- peer removal clears handshake telemetry and configured endpoint state for that peer
- duplicate peer configuration safely replaces runtime-owned peer state without inflating peer count
- unconfigured peer endpoint updates fail closed
- `current_peer_endpoint(...)` and `stats(...)` report runtime-owned state honestly without inventing relay/live-path facts
- daemon `direct_active` and `relay_active` truthfulness regressions continue to pass unchanged

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
- `cargo fmt --all -- --check`
  - Result: pass
- `cargo check -p rustynet-backend-wireguard`
  - Result: pass
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - Result: pass
  - Backend crate unit tests: 38 passed
  - Backend crate conformance tests: 6 passed
- `cargo test -p rustynetd daemon_runtime_relay_session_becomes_live_only_with_selected_endpoint_and_fresh_handshake -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_relay_session_endpoint_mismatch_is_not_live -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_health_uses_live_handshake_without_forced_reprobe -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_auto_tunnel_direct_liveness_expiry_falls_back_to_relay -- --nocapture`
  - Result: pass

Phase 4 completed:
- runtime-owned per-peer userspace WireGuard engine state for the Linux userspace-shared backend
- inbound ciphertext delivery from the authoritative socket into the matched peer engine state
- outbound plaintext encryption from the backend-internal test boundary into authoritative socket sends
- per-peer authenticated handshake telemetry sourced from engine evidence only
- honest peer/endpoint/handshake/stats backend methods without fake transport success

What remains for Phase 5:
- real host TUN lifecycle and helper-boundary integration
- explicit daemon/install/start selection-surface wiring for `linux-wireguard-userspace-shared`
- preserving truthful product claims while making the new mode selectable end-to-end

Residual risks / blockers after Phase 4:
- The current plaintext path is still the backend-internal test boundary, not the final host TUN lifecycle; host integration remains a later phase.
- Daemon/start/install selection surfaces still intentionally do not construct `linux-wireguard-userspace-shared`; end-to-end product behavior remains unchanged.
- macOS userspace-shared parity remains unimplemented and unclaimed.

## 12. Phase 5: TUN Lifecycle, Helper Boundary, And Selection Surfaces
### 12.1 Objective
Wire the new backend end-to-end into Linux runtime selection without changing defaults or widening unsupported claims.

### 12.2 Files To Touch
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs)
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/main.rs)
- [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh)
- [crates/rustynet-cli/src/ops_write_daemon_env.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_write_daemon_env.rs)
- [crates/rustynet-cli/src/ops_install_systemd.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_install_systemd.rs)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)
- [scripts/systemd/rustynetd.service](/Users/iwanteague/Desktop/Rustynet/scripts/systemd/rustynetd.service)
- [crates/rustynetd/src/privileged_helper.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs) only if helper-assisted TUN setup is required

### 12.3 Exact Work
1. Implement Linux TUN open/create/configure path for the userspace backend.
2. Keep helper involvement narrow and host-setup only.
3. Ensure the backend mode can be explicitly selected end-to-end.
4. Preserve default backend selection:
   - Linux default remains `linux-wireguard`
   - macOS default remains `macos-wireguard`
5. Preserve existing fail-closed command-only blocker behavior for command-only modes.
6. Keep `auto_port_forward_exit` and other capability claims truthful; do not widen them implicitly.
7. Ensure any helper-created TUN resource is either:
   - transferred immediately into backend ownership, or
   - torn down immediately on failure.

The helper must not remain a long-lived owner or packet forwarder.

### 12.4 Required Runtime Behavior
When `RUSTYNET_BACKEND=linux-wireguard-userspace-shared` is set:
- daemon must construct the real backend,
- backend must expose authoritative transport identity after start,
- daemon netcheck/status must report `transport_socket_identity_state=authoritative_backend_shared_transport`,
- no separate daemon-owned socket may appear in the runtime path.

### 12.5 Mandatory Tests
Add tests proving:
- userspace-shared mode constructs and reports authoritative transport state
- command-only modes still report blocked authoritative transport state
- explicit mode selection survives installer/env/start surfaces unchanged
- fail-closed behavior persists if TUN or helper setup fails
- userspace-shared startup failure does not silently downgrade to command-only mode

### 12.6 Status - 2026-04-01
Phase 5 is complete in the current tree for the Linux userspace-shared backend slice.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs) now provides a real Linux TUN lifecycle with two explicit ownership paths: direct backend-owned setup for local/runtime use and helper-assisted host setup that creates/configures the interface, transfers long-lived file-descriptor ownership immediately into the backend runtime, and tears the interface down on failure or shutdown.
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) now wires the Linux userspace-shared backend through the TUN lifecycle, fails closed on TUN or socket startup errors, preserves deterministic cleanup, and keeps test-only lifecycle injection available for backend-crate validation without widening any product claim.
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs) now treats the TUN device as runtime-owned state so the single-owner worker, not the daemon or helper, remains the long-lived owner of packet and transport resources.
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) now constructs `linux-wireguard-userspace-shared` on Linux, validates the required key/helper configuration honestly, preserves fail-closed behavior on unsupported hosts and blocked macOS userspace-shared mode, and reports `authoritative_backend_shared_transport` once the real backend has been started.
- [crates/rustynetd/src/privileged_helper.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs) now accepts the narrow `ip tuntap add dev <iface> mode tun user <uid> group <gid>` schema required for helper-assisted Linux TUN creation without widening the helper into a long-lived packet owner.
- [scripts/systemd/rustynetd.service](/Users/iwanteague/Desktop/Rustynet/scripts/systemd/rustynetd.service) and [crates/rustynet-cli/src/ops_install_systemd.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_install_systemd.rs) now preserve explicit backend mode selection while exposing `/dev/net/tun` to the daemon service template without changing the default backend away from `linux-wireguard`.
- [crates/rustynet-backend-wireguard/tests/conformance.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/tests/conformance.rs) and backend/daemon/CLI tests now cover TUN lifecycle cleanup, no-silent-downgrade startup failure, authoritative transport reporting for the real userspace-shared backend, and service-template preservation of backend mode plus TUN-device access.
- [crates/rustynetd/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/main.rs), [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh), [crates/rustynet-cli/src/ops_write_daemon_env.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_write_daemon_env.rs), and [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs) were re-audited and required no Phase 5 edits because they already preserved an explicit `linux-wireguard-userspace-shared` selection without rewriting it.

Validated in this slice:
- `linux-wireguard-userspace-shared` now has a real Linux TUN lifecycle path instead of a placeholder scaffold.
- Helper-assisted setup remains host-setup only; the helper never owns the authoritative UDP socket, userspace WireGuard engine, STUN/relay control traffic, or long-lived packet forwarding.
- Startup failure during TUN creation or later socket/runtime acquisition fails closed and does not silently downgrade to `linux-wireguard`.
- Explicit backend mode selection survives daemon config parsing, installer/systemd template generation, env handling, and `start.sh` host-profile enforcement without changing the Linux/macOS defaults.
- Command-only Linux/macOS backends remain unchanged and still report blocked authoritative transport state.
- `transport_socket_identity_state=authoritative_backend_shared_transport` is now reported for the real Linux userspace-shared backend once it has been started.
- Unsupported capability claims such as `auto_port_forward_exit` remain unchanged.

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/tests/conformance.rs crates/rustynetd/src/daemon.rs crates/rustynetd/src/privileged_helper.rs crates/rustynet-cli/src/ops_install_systemd.rs`
- `cargo fmt --all -- --check`
  - Result: pass
- `cargo check -p rustynet-backend-wireguard`
  - Result: pass
- `cargo check -p rustynetd`
  - Result: pass
- `cargo check -p rustynet-cli --bin rustynet-cli`
  - Result: pass
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - Result: pass
  - Backend crate unit tests: 40 passed
  - Backend crate conformance tests: 6 passed
- `cargo test -p rustynetd validate_daemon_config_accepts_linux_userspace_shared_backend -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_production_backend_transport_identity_blocker_disables_stun_worker -- --nocapture`
  - Result: pass
- `cargo test -p rustynetd daemon_runtime_linux_userspace_shared_backend_reports_authoritative_transport_state -- --nocapture`
  - Result: pass
- `cargo test -p rustynet-cli --bin rustynet-cli rustynetd_service_template_preserves_backend_env_and_tun_device_access -- --nocapture`
  - Result: pass

Phase 5 completed:
- real Linux TUN lifecycle support for the userspace-shared backend
- helper-boundary narrowing that keeps the helper in host-setup only and transfers long-lived TUN ownership into the backend runtime
- explicit `linux-wireguard-userspace-shared` selection through daemon/config/install/start/systemd surfaces without changing default backend selection
- no-silent-downgrade fail-closed behavior on TUN or startup failure
- truthful authoritative transport status reporting for the real Linux userspace-shared backend

What remains for Phase 6:
- simulated multi-peer proof that peer ciphertext, STUN, and relay control all use the same authoritative transport generation in the production Linux backend path
- additional negative simulated coverage for same-port-new-socket rejection, rollover cleanup, and stale-handshake invalidation at the integrated daemon/backend level
- later full regression, gate, and live-evidence work

Residual risks / blockers after Phase 5:
- The Linux userspace-shared backend is now selectable and owns the real TUN/socket/engine runtime resources, but the Phase 6 simulated-proof bundle still needs to demonstrate the full same-generation invariant end-to-end on the production path.
- macOS userspace-shared parity remains blocked and unclaimed.
- README and repo-level product claims remain intentionally conservative until later simulated proof, gate, and live-evidence phases complete.

## 13. Phase 6: Simulated Proof Tests And Pre-Lab Validation
### 13.1 Objective
Prove locally, without live evidence claims, that the production Linux backend now satisfies the same-socket transport invariants.

### 13.2 Required Test Surfaces
- [crates/rustynet-backend-wireguard/tests/conformance.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/tests/conformance.rs)
- backend unit tests under [crates/rustynet-backend-wireguard/src](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src)
- daemon tests in [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)

### 13.3 Mandatory New Simulated Integration Test
Add at least one local multi-peer simulated test that proves all of the following together:
- one userspace-shared backend instance sends peer ciphertext using authoritative transport generation `X`
- the same backend instance performs a STUN round trip using authoritative transport generation `X`
- the same backend instance performs a relay control exchange or keepalive using authoritative transport generation `X`
- there is no second daemon-owned or backend-owned authority socket in the path

Test-only instrumentation is acceptable. The proof matters more than elegance.
Local-address equality by itself is not sufficient for this proof; the test must assert the same socket-instance token or authoritative transport-generation token.

### 13.4 Mandatory Negative Coverage
Add tests for:
- same-port-but-different-socket rejection
- concurrent round-trip rejection
- round-trip-to-peer-endpoint rejection
- no authoritative identity before start
- no authoritative identity after shutdown
- transport-generation rollover invalidates stale round-trip state
- transport-generation rollover does not preserve stale handshake freshness
- no handshake timestamp from programmed state
- command-only backends remain blocked

### 13.5 Status - 2026-04-01
Phase 6 is complete in the current backend crate for the Linux userspace-shared simulated-proof slice.

Completed in this slice:
- [crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs) now records actual peer-ciphertext egress on the authoritative socket with the authoritative transport generation used for that send, so simulated proof can use the real production runtime path instead of inferring peer traffic from a receiving-side coincidence.
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) now carries the Phase 6 multi-peer simulated proof test that exercises one Linux userspace-shared backend instance across peer ciphertext, STUN round trip, relay round trip, and relay keepalive, asserts a single authoritative transport generation across all four path classes, and proves the invariant at generation level rather than by local-address equality alone.
- [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) also now carries the stronger restart/rollover regression proving that the same local port after restart is a new authoritative socket generation, that an in-flight round trip is canceled during shutdown, and that a late packet from the old socket generation becomes peer ingress on the new runtime instead of satisfying stale waiter state.

Validated in this slice:
- one Linux userspace-shared backend instance now has a local multi-peer simulated proof that peer ciphertext egress, STUN round trip, relay round trip, and relay keepalive all traverse the same authoritative transport generation on the production backend path
- the proof is generation-level, not local-address-only, and therefore does not treat same-port coincidence as authoritative identity
- the production-path late-packet rollover regression now proves stale round-trip state is invalidated across same-port restart with a new authoritative socket generation
- existing negative coverage for concurrent round-trip rejection, round-trip-to-peer-endpoint rejection, no authoritative identity before start, no authoritative identity after shutdown, no handshake from programmed state, and command-only backend blockers remains intact and green

Validation completed for this slice:
- `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
- `cargo fmt --all -- --check`
  - Result: pass
- `cargo check -p rustynet-backend-wireguard`
  - Result: pass
- `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
  - Result: pass
  - Backend crate unit tests: 42 passed
  - Backend crate conformance tests: 6 passed
- No targeted daemon validation was rerun in this slice because no daemon code changed and the required Phase 6 proof was satisfied entirely within backend-internal simulated tests.

Phase 6 completed:
- generation-level local simulated proof that one production Linux userspace-shared backend instance uses the same authoritative transport generation for peer ciphertext, STUN, relay round trip, and relay keepalive
- explicit negative proof that same-port-after-restart is a new authoritative socket generation, not reused authoritative identity
- explicit negative proof that transport-generation rollover cancels stale round-trip waiter state and does not let late packets satisfy the old exchange
- preservation of existing fail-closed negative coverage without widening any product/runtime claim

What remains for Phase 7:
- the broader regression stack for the full backend/daemon/workspace surface
- the CI and gate pass set defined in Phase 7
- live-evidence generation and artifact refresh after the full regression stack is clean

Residual risks / blockers after Phase 6:
- The production Linux userspace-shared backend now has local simulated proof, but Phase 7 still needs to prove the wider workspace and gate surface remains green.
- No live-lab evidence or canonical report regeneration was attempted in this phase, so README and repo-level completion claims must remain conservative.
- macOS userspace-shared parity remains blocked and unclaimed.

## 14. Phase 7: Gates And Regression Checks
This is the final phase before live-lab execution.

### 14.1 Required Validation Order
Run in this order:

1. `rustfmt --edition 2024` on touched Rust files
2. `cargo fmt --all -- --check`
3. `cargo check -p rustynet-backend-wireguard`
4. `cargo check -p rustynetd`
5. targeted backend tests
6. targeted daemon tests
7. `cargo check --workspace --all-targets --all-features`
8. `cargo test --workspace --all-targets --all-features`
9. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
10. `cargo audit --deny warnings`
11. `cargo deny check bans licenses sources advisories`
12. `./scripts/ci/phase10_hp2_gates.sh`
13. `./scripts/ci/membership_gates.sh`
14. `./scripts/ci/phase10_cross_network_exit_gates.sh`
15. `./scripts/ci/phase10_gates.sh`

### 14.2 Expected Outcomes Before Live Evidence
Acceptable outcomes:
- `phase10_hp2_gates.sh` passes
- `membership_gates.sh` passes
- `phase10_cross_network_exit_gates.sh` fails only because the six canonical live cross-network reports are still missing for current `HEAD`
- `phase10_gates.sh` fails only because `artifacts/phase10/fresh_install_os_matrix_report.json` is stale for current `HEAD`, unless that artifact is intentionally regenerated honestly

Unacceptable outcomes:
- any failure caused by the new userspace backend slice
- any regression in direct/relay proof semantics
- any regression that reintroduces second-socket authority
- any softening of validator or gate behavior

### 14.3 Regression Checklist
Before declaring this plan complete, confirm:
- command-only Linux backend still blocks authoritative shared transport
- command-only macOS backend still blocks authoritative shared transport
- userspace Linux backend owns peer socket, STUN, and relay control on same transport
- same-socket proof is instance-level or generation-level, not inferred from local address equality
- daemon netcheck/status truthfulness is unchanged or stricter
- `direct_active` semantics are unchanged
- `relay_active` semantics are unchanged
- existing live-evidence blockers remain fail-closed and are not patched around

### 14.4 2026-04-01 Execution Status
Phase 7 validation was executed in the required order against the current tree.

Phase 1 through Phase 6 audit result:
- complete in the current tree for the Linux userspace-shared backend slice
- Phase 6 proof is present and explicit in:
  - `crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs`
  - `linux_userspace_shared_backend_multi_peer_simulated_proof_uses_one_generation_for_peer_stun_and_relay_paths`
  - `linux_userspace_shared_backend_restart_cancels_stale_round_trip_and_same_port_new_socket_does_not_reuse_it`
  - `crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs`
  - `recorded_peer_ciphertext_egress_for_test`

Validation commands run:
1. `rustfmt --edition 2024 crates/rustynet-backend-wireguard/src/lib.rs crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs crates/rustynet-backend-wireguard/src/userspace_shared/runtime.rs crates/rustynet-backend-wireguard/src/userspace_shared/socket.rs crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs crates/rustynet-backend-wireguard/src/userspace_shared/handshake.rs crates/rustynet-backend-wireguard/src/userspace_shared/tun.rs crates/rustynet-backend-wireguard/tests/conformance.rs crates/rustynetd/src/daemon.rs crates/rustynetd/src/main.rs crates/rustynetd/src/privileged_helper.rs crates/rustynetd/src/stun_client.rs crates/rustynetd/src/relay_client.rs crates/rustynet-cli/src/main.rs crates/rustynet-cli/src/ops_write_daemon_env.rs crates/rustynet-cli/src/ops_install_systemd.rs`
2. `cargo fmt --all -- --check`
3. `cargo check -p rustynet-backend-wireguard`
4. `cargo check -p rustynetd`
5. `cargo test -p rustynet-backend-wireguard --tests -- --nocapture`
6. `cargo test -p rustynetd daemon_runtime_ -- --nocapture`
7. `cargo check --workspace --all-targets --all-features`
8. `cargo test --workspace --all-targets --all-features`
9. `cargo clippy --workspace --all-targets --all-features -- -D warnings`
10. `cargo audit --deny warnings`
11. `cargo deny check bans licenses sources advisories`
12. `./scripts/ci/phase10_hp2_gates.sh`
13. `./scripts/ci/membership_gates.sh`
14. `./scripts/ci/phase10_cross_network_exit_gates.sh`
15. `./scripts/ci/phase10_gates.sh`

Reruns performed:
- No code-regression reruns were required in this validation pass.
- The long-running `membership_gates.sh` process was allowed to run to completion so its final failure could be classified precisely rather than treated as a hidden backend regression.

Validation outcomes:
- Passed:
  - `cargo fmt --all -- --check`
  - `cargo check -p rustynet-backend-wireguard`
  - `cargo check -p rustynetd`
  - targeted backend tests
  - targeted daemon runtime tests
  - `cargo check --workspace --all-targets --all-features`
  - `cargo test --workspace --all-targets --all-features`
  - `cargo clippy --workspace --all-targets --all-features -- -D warnings`
  - `./scripts/ci/phase10_hp2_gates.sh`
- Blocked by dependency-policy regressions introduced by the Linux userspace-shared backend dependency chain:
  - `cargo audit --deny warnings` fails on `RUSTSEC-2024-0436` because `tun-rs 2.8.2` pulls `route_manager` and `netconfig-rs`, which pull `netlink-packet-core`, which still depends on unmaintained `paste 1.0.15`
  - `cargo deny check bans licenses sources advisories` fails on the same unmaintained `paste` advisory and also fails license policy because the new `boringtun` / `tun-rs` dependency chain introduces `BSD-2-Clause` and `ISC` licenses that are not currently allowed by the repository policy configuration; the rejecting crates observed in this run were `ip_network`, `ip_network_table`, `libloading`, `ring`, and `untrusted`
- Evidence gates remain fail-closed exactly as intended:
  - `./scripts/ci/phase10_cross_network_exit_gates.sh` fails only because the six canonical live cross-network reports are missing for current `HEAD`
  - `./scripts/ci/phase10_gates.sh` fails only because `artifacts/phase10/fresh_install_os_matrix_report.json` is stale for current `HEAD`; in this run the gate reported `report=c86a62a766b8af8382dfa57805aec8b4cad284ff expected=06e3e2ed745b4439505991bea775246cde8ed653`
  - `./scripts/ci/membership_gates.sh` does not expose a userspace-shared backend regression; it ultimately fails only because it delegates into the same stale fresh-install evidence gate already reported by `phase10_gates.sh`

Post-phase live-lab correction from 2026-04-02:
- Two reduced five-node helper reruns on committed `main` materially advanced the production Linux userspace-shared path:
  - [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs) now prepares and scrubs runtime WireGuard key material for `linux-wireguard-userspace-shared` exactly like the command-only Linux backend, which cleared the earlier startup failure on missing `/run/rustynet/wireguard.key`.
  - [scripts/systemd/rustynetd-privileged-helper.service](/Users/iwanteague/Desktop/Rustynet/scripts/systemd/rustynetd-privileged-helper.service) and [crates/rustynet-cli/src/ops_install_systemd.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_install_systemd.rs) now expose `/dev/net/tun` inside the privileged-helper private device namespace, which cleared the earlier helper failure on `ip tuntap add ...` returning `open: No such file or directory`.
- The current reduced-lab truth is now more precise than the earlier Phase 7 closeout:
  - the helper flow preserves `linux-wireguard-userspace-shared`
  - the daemon starts far enough to create the userspace-owned TUN on at least part of the five-node topology
  - the lab now gets through bootstrap, membership, assignments, and traversal issuance before failing in baseline runtime enforcement
- The remaining blocker is not a harness or policy artifact. It is still a real backend implementation gap:
  - the Linux userspace-shared backend continues to fail closed on route application and exit-mode work because [crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/userspace_shared/mod.rs) still routes `apply_routes(...)` and `set_exit_mode(...)` into later-phase fail-closed placeholders
  - on failing nodes, `rustynet status` now reports `last_reconcile_error=reconcile dataplane apply failed: backend error: Internal: linux userspace-shared backend does not yet implement route application; later production transport-owning phases remain open`
  - `rustynetd-managed-dns.service` failures are secondary symptoms of that fail-closed dataplane state, not the primary cause
- Therefore the previous “dependency-policy plus evidence only” blocker set was incomplete. Pre-live-lab readiness still also requires honest route application and exit-mode implementation for the Linux userspace-shared backend.

Security invariants re-verified:
- The Linux userspace-shared backend remains the sole owner of the authoritative UDP socket, userspace engine state, TUN runtime state, round-trip control state, and handshake telemetry.
- Command-only Linux/macOS backends remain unchanged and still fail closed on authoritative shared transport.
- Daemon truthfulness semantics remain unchanged:
  - `direct_active` still requires fresh handshake proof
  - `relay_active` still requires fresh handshake proof plus authenticated relay-session consistency
- No validation result indicated a second-socket authority regression, a silent downgrade from userspace-shared to command-only mode, or a weakening of authoritative transport proof.
- Evidence and report gates remain fail-closed on missing or stale artifacts.

Phase 7 status:
- Validation execution is complete.
- Phase 7 is not cleanly complete yet because the reduced five-node live-lab reruns proved an additional runtime implementation gap remains in the Linux userspace-shared backend: route application and exit-mode programming still fail closed under real baseline enforcement.
- The new userspace-shared dependency chain also still violates the repository's audit and license policy gates, and the fresh-install / live cross-network evidence set is still stale or missing for current `HEAD`.

Exact prerequisites before this plan can be declared pre-live-lab ready:
1. Implement honest Linux userspace-shared route application and exit-mode programming so the backend no longer fails closed when baseline runtime enforcement needs dataplane routes.
2. Re-run the reduced five-node helper lab until `enforce_baseline_runtime` succeeds on the full topology without managed-DNS fallout from missing dataplane state.
3. Replace or otherwise remove the `tun-rs 2.8.2` dependency path that introduces unmaintained `paste 1.0.15`, or prove a policy-approved secure alternative with code and validation.
4. Resolve the repository license-policy failures introduced by the `boringtun` / `tun-rs` dependency chain without weakening the deny gate.
5. Regenerate the fresh-install matrix evidence for current `HEAD`.
6. Run the live lab and regenerate the six canonical cross-network reports for current `HEAD`.

## 15. Exact File Map For Engineers
The following files must be treated as the primary implementation surface:

### 15.1 Backend API and WireGuard Backend
- [crates/rustynet-backend-api/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-api/src/lib.rs)
- [crates/rustynet-backend-wireguard/Cargo.toml](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/Cargo.toml)
- [crates/rustynet-backend-wireguard/src/lib.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/src/lib.rs)
- [crates/rustynet-backend-wireguard/tests/conformance.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-backend-wireguard/tests/conformance.rs)

### 15.2 Daemon Runtime
- [crates/rustynetd/src/daemon.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/daemon.rs)
- [crates/rustynetd/src/phase10.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/phase10.rs)
- [crates/rustynetd/src/stun_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/stun_client.rs)
- [crates/rustynetd/src/relay_client.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/relay_client.rs)
- [crates/rustynetd/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/main.rs)
- [crates/rustynetd/src/privileged_helper.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynetd/src/privileged_helper.rs) if helper-assisted TUN setup is necessary

### 15.3 Selection And Deployment Surfaces
- [start.sh](/Users/iwanteague/Desktop/Rustynet/start.sh)
- [crates/rustynet-cli/src/main.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/main.rs)
- [crates/rustynet-cli/src/ops_write_daemon_env.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_write_daemon_env.rs)
- [crates/rustynet-cli/src/ops_install_systemd.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_install_systemd.rs)
- [scripts/systemd/rustynetd.service](/Users/iwanteague/Desktop/Rustynet/scripts/systemd/rustynetd.service)

### 15.4 Gate And Evidence Surfaces
- [scripts/ci/phase10_hp2_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_hp2_gates.sh)
- [scripts/ci/membership_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/membership_gates.sh)
- [scripts/ci/phase10_cross_network_exit_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_cross_network_exit_gates.sh)
- [scripts/ci/phase10_gates.sh](/Users/iwanteague/Desktop/Rustynet/scripts/ci/phase10_gates.sh)
- [crates/rustynet-cli/src/ops_cross_network_reports.rs](/Users/iwanteague/Desktop/Rustynet/crates/rustynet-cli/src/ops_cross_network_reports.rs)

## 16. Stop Conditions
Stop and document the blocker instead of improvising if any of the following becomes true:

1. The implementation would require a daemon-owned second socket.
2. The implementation would require a helper-owned authoritative socket.
3. The implementation would require `wireguard-go` or kernel WireGuard to own the shared-mode transport.
4. The implementation cannot prove same-socket identity for peer traffic, STUN, and relay control.
5. The implementation can only prove same local address or same port, but not same socket instance or same authoritative transport generation.
6. The implementation can only report handshake liveness from programmed state.
7. The implementation would require softening `direct_active`, `relay_active`, or any CI/report gate.

## 17. What Happens After This Plan Is Complete
Once Phases 1 through 7 are complete and validated, the next work is:

1. run the live lab with `RUSTYNET_BACKEND=linux-wireguard-userspace-shared`
2. regenerate the six canonical cross-network reports for current `HEAD`
3. regenerate `artifacts/phase10/fresh_install_os_matrix_report.json` for current `HEAD`
4. re-run:
   - `./scripts/ci/phase10_cross_network_exit_gates.sh`
   - `./scripts/ci/phase10_gates.sh`
5. update:
   - [README.md](/Users/iwanteague/Desktop/Rustynet/README.md)
   - [PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md](./PlugAndPlayTraversalRelayDeltaPlan_2026-03-29.md)

That live-evidence step is intentionally out of scope for this pre-live-lab implementation document.
