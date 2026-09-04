# Mobile Client Rust Architecture — How Much of the Android and iOS Client Can Be Rust, and Can It Be 100%?

- **Date:** 2026-09-04
- **Status:** UNTRUSTED — architecture/feasibility study produced by a delegated edit agent. It has **not** been reviewed by the owner. Nothing here is a mandate; it is a grounded design proposal to be scrutinized line by line before anything is built. File:line citations were collected against the working tree and should be re-verified before implementation.
- **Scope:** Docs only. No code was changed. No mobile code exists anywhere in the repository today (grep for `ios`/`android`/`mobile` across `documents/Requirements.md` returns no requirement matches — mobile is greenfield).
- **Question:** How much of a Rustynet Android and iOS client can be Rust? Can the client be 100% Rust? Can the *core* be 100% Rust?

---

## 0) Executive summary

1. **The tunnel core can be ~100% Rust, shared with desktop, unchanged.** The vendored boringtun fork (`third_party/boringtun`) is already a *noise-only* library — its platform I/O (epoll/kqueue/tun device code, FFI, JNI) exists in-tree but is **not compiled in** (`third_party/boringtun/src/lib.rs:8` exposes only `pub mod noise`). Rustynet's own engine (`crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs:10`) drives `boringtun::noise::{Packet, Tunn, TunnResult}` directly from its own I/O loop, with no platform dependency beyond a UDP socket and a tun fd. Both of those exist on mobile: the OS hands the app a tun fd, and boringtun handles the rest.
2. **The external-fd injection path already exists on macOS** — `userspace_shared_macos/tun.rs:979` (`open_utun_device`) wraps an externally-created utun via `rustynet_tun::SyncDevice::from_raw_fd` (:997). An iOS PacketTunnelProvider hands the extension exactly such an fd. The same constructor pattern is what Android needs (~20 lines: a `from_raw_fd`-style constructor over a plain read/write fd with no header framing).
3. **The honest overall verdict is NO for "100% Rust app," YES for "≈100% Rust core,"** with an irreducible native shim per platform of roughly 5–12% of the client codebase (UI + VPN-service lifecycle + key-store plumbing + packaging). Numbers in §8.
4. **The key-custody seam for mobile key stores already exists:** `rustynet-crypto` defines `pub trait OsSecureStore` (`crates/rustynet-crypto/src/lib.rs:312`) and a generic `KeyCustodyManager<S: OsSecureStore>` (:381). iOS Keychain and Android Keystore adapters implement this trait; no core change is required. This directly satisfies SecurityMinimumBar §4 ("OS key store usage where available", `documents/SecurityMinimumBar.md:216-222`).
5. **Biggest architectural caution:** `rustynetd`'s `DaemonRuntime` (`crates/rustynetd/src/daemon.rs:4655`, 38,215 LOC file, 187 `cfg(target_os)` sites in that file alone) is *not* the thing to port. The mobile core should reuse the **domain layer + the backend abstraction + the userspace engine**, and build a new, small, mobile-native orchestrator on top — not shrink the desktop daemon. Detail in §2.4 and §7.
6. **Recommended FFI:** UniFFI for both platforms (one interface definition, Swift + Kotlin bindings generated, async-friendly, no C header management). swift-bridge/cxx are better only if the iOS side demands zero-copy Swift-native types at scale, which a control-plane API does not. Detail in §6.

---

## 0.1) Corrections and caveats from adversarial review (2026-09-04)

This study was adversarially reviewed in
`MobileClientRustArchitecture_AdversarialReview_2026-09-04.md`. Its findings are
folded in here. Three factual citations in the body were re-verified against the
working tree and corrected in place:

- boringtun's `pub mod noise` is at `third_party/boringtun/src/lib.rs:8`, not `:13`.
- `RolePreset` has **9** variants, not 8 — the original list omitted `BlindRelay`
  (Client/Admin/Exit/BlindExit/Relay/Anchor/Nas/Llm/**BlindRelay**;
  `crates/rustynet-control/src/role_presets.rs:41`).
- The compiled boringtun surface is **~2,700 LOC** (the `src/noise/` tree measures
  2,678), not ~3,600; the itemized file sizes already sum to ~2,655.

Three design-level caveats the body understates — none fatal, but each is real
work the "≈100% Rust core" headline must carry as an asterisk:

1. **Android has a native seam *in the dataplane*, not only in the lifecycle.**
   The WireGuard transport UDP socket the Rust engine opens must be excluded from
   the tunnel via `VpnService.protect(fd)`, or the app's own encrypted packets are
   routed back into the tun and loop. So "everything after the fd is Rust" needs a
   qualifier: the outbound transport socket's fd must round-trip through a
   one-call native `protect()` hook (per socket, and again on roam/rebind). This
   is small, but it is a native call on the packet path — §3.4 and the §0 summary
   should not imply the dataplane is native-free once the tun fd exists.
2. **The FFI must not hardcode `fn start_tunnel(fd: i32, …)`** (as sketched at §7).
   §3.2 and §9 already concede iOS may hand the extension an `NEPacketTunnelFlow`
   packet-array object rather than a raw fd; the entry point must therefore take
   an abstract packet-source handle (resolved by prototype P1), not an `i32`, or
   it contradicts the study's own device-seam plan.
3. **"No core change required" for custody is compile-true but security-false.**
   The `OsSecureStore` *trait* is reused unchanged, but each platform adapter
   (Secure-Enclave-wrapped storage on iOS; StrongBox/TEE with fail-loud fallback
   on Android; the `RequireOsSecureStore` posture; any key attestation) is **new
   security-bearing code** that must independently satisfy SecurityMinimumBar §4.
   The 5–12% shim figure (§8) counts lines of code, not security-review surface —
   the custody adapters deserve core-equivalent scrutiny, not "plumbing" scrutiny.

---

## 1) Grounding: what exists today that mobile would stand on

Every claim in this section is verifiable in the working tree. The architecture layering (CLI/UX → Domain → Daemon+Services → Backend Abstraction → Platform) is documented in `documents/CODE_MAP.md:7-36` and enforced by import rules in `documents/CODE_MAP.md:311-329`.

### 1.1 The backend abstraction — the contract mobile implements

`crates/rustynet-backend-api/src/lib.rs` (442 LOC, `#![forbid(unsafe_code)]` at :1) defines everything the mobile tunnel must satisfy:

- `NodeId` (:8-63) — validated, length-capped, rejects control/invisible-bidi characters.
- `SocketEndpoint` (:72-75), `Route` (:104-108) with `RouteKind` Mesh/ExitNodeLan/ExitNodeDefault (:97-101), `ExitMode` Off/FullTunnel (:91-94).
- `PeerConfig` (:111-122) — node_id, endpoint, raw 32-byte public key, allowed_ips, optional persistent keepalive (FIS-0015).
- `RuntimeContext` (:125-130) — local_node, interface_name, mesh_cidr, local_cidr.
- `BackendCapabilities` (:133-147) — supports_roaming, exit_nodes, exit_client, exit_serving, lan_routes, ipv6.
- Health/stats types: `TunnelStats` (:150-155), `PathHealth` (:163-167, FIS-0004), `PeerPathSample` (:173-183, FIS-0013).
- **`trait TunnelBackend: Send + Sync` (:237-358)** — notably *synchronous*, with `start(context)` (:242), `configure_peer` (:244), `update_peer_endpoint` (:246), `apply_routes` (:278), `set_exit_mode` (:280), `stats` (:282), `shutdown` (:357), and a fail-closed second-socket identity rule (`transport_socket_identity_blocker`, :353, rationale at :343-352).

This trait is the exact seam a mobile backend implements. A `MobileVpnBackend` would take the OS-provided tun fd at `start()` time instead of opening `/dev/net/tun` or a utun socket. Because the trait is sync and object-safe, it wraps cleanly behind an FFI boundary.

### 1.2 The WireGuard core — already decoupled from platform I/O

The vendored boringtun fork (`third_party/boringtun`, version 0.7.0, 7,586 LOC in-tree) is described in its own `Cargo.toml` as a *"Rustynet-local fork of boringtun with a noise-only dependency surface"*. Critically:

- `third_party/boringtun/src/lib.rs:8` exposes **only** `pub mod noise` (plus an `x25519` re-export at :19-25). The upstream platform code that exists in the tree — `device/mod.rs` (884 LOC), `epoll.rs` (416), `kqueue.rs` (337), `tun_darwin.rs` (256), `tun_linux.rs` (159), `ffi/mod.rs` (397), `jni.rs` (271) — is **not compiled**.
- Dependencies are pure crypto/utility: x25519-dalek 2.0.1, chacha20poly1305 0.10.0-pre.1, blake2, hmac, aead, rand_core, parking_lot, nix (time-only), tracing. **No tokio. No socket code.**
- The compiled surface (~2,700 LOC: `noise/handshake.rs` 950, `noise/mod.rs` 845 with `Tunn`/`TunnResult`/`Packet`, timers 335, session 330, rate_limiter 195) is *pure packet-processing state*: handshake state machine, session key derivation, encrypt/decrypt, timers, anti-replay rate limiting. Zero platform assumption.

This is the single most important fact in this document: **Rustynet already ships a userspace WireGuard core that is I/O-free**, and its own engine — not upstream's — drives it.

### 1.3 The userspace engine — Rustynet's own I/O loop around the noise core

`crates/rustynet-backend-wireguard/src/` (26,711 LOC total) contains two userspace engines:

- `userspace_shared/` (Linux-flavored): `engine.rs` 3,211 LOC — imports `boringtun::noise::{Packet, Tunn, TunnResult}` at :10 and drives the handshake/encrypt/decrypt loop itself; `runtime.rs` 1,911; `tun.rs` 1,548 with a **device seam** (`Real(SyncDevice)` enum at :146, constructor `fn real(device: SyncDevice)` at :25, and `SyncDevice::open(interface_name)` call sites at :302 and :439) so tests inject fake devices; `fair_drain.rs` 460.
- `userspace_shared_macos/`: `tun.rs` 2,600 LOC whose `open_utun_device` (:979) wraps an **externally supplied** utun fd via `rustynet_tun::SyncDevice::from_raw_fd(raw_fd)` at :997; `runtime.rs` 2,193; `mod.rs` 2,742.

The delegator crate `rustynet-backend-userspace` (`crates/rustynet-backend-userspace/src/lib.rs`, 228 LOC) selects between them by `cfg` (linux → `LinuxUserspaceSharedBackend`, macos → `MacosUserspaceSharedBackend`, imports at :21-25) and **fails closed at runtime** on any other platform — every operation returns `BackendError::internal("UserspaceBackend is only available on Linux and macOS")` (:69-75, helper `platform_unavailable` :80-82). That is exactly the pattern a mobile backend extends: add arms, never weaken the fail-closed default.

The tun layer itself, `third_party/rustynet-tun/src/lib.rs` (547 LOC, single file), is a `SyncDevice` with per-OS `cfg` arms: Linux `/dev/net/tun` + `TUNSETIFF` ioctl (:3-129), macOS utun with 4-byte header framing via readv/writev (:131-505, including `from_raw_fd` at :242-250, `AsRawFd`/`IntoRawFd` :264-276, Drop closes the fd :253-262), and a **fallback arm (:507-542) that returns `io::ErrorKind::Unsupported`** for anything else — fail-closed by construction. Both existing arms are plain blocking `read`/`write` over a file descriptor, which is precisely the semantics of Android's tun fd.

### 1.4 The domain layer — transport-agnostic and already import-safe anywhere

Per the import rules (`documents/CODE_MAP.md:311-329`), these crates may be used from any context, including a mobile app:

- **`rustynet-control`** (32,319 LOC) — membership bundles (`SignedMembershipUpdate`, `MembershipState`, Ed25519 `MembershipSignature`), replay watermarks (`MembershipWatermark` + `PerEpochReplayWatermark`), role system: 9-value `RolePreset` enum (Client/Admin/Exit/BlindExit/Relay/Anchor/Nas/Llm/BlindRelay) + `validate_transition()` in `crates/rustynet-control/src/role_presets.rs`, gossip, enrollment-token verification.
- **`rustynet-policy`** (3,194 LOC, single `src/lib.rs`) — default-deny `PolicySet`/`PolicyRule`/`AccessRequest` ACL evaluation.
- **`rustynet-dns-zone`** (1,664 LOC) — Magic DNS signed-zone schema.
- **`rustynet-crypto`** (4,973 LOC, single `src/lib.rs`) — keys, signing, custody (§5).
- **`rustynet-backend-api`** (442 LOC) — the abstraction itself (§1.1).

### 1.5 Useful portable non-domain pieces

- `PathMtuDiscovery` (`crates/rustynetd/src/path_mtu.rs`) — a **pure RFC 8899 DPLPMTUD state machine, no I/O**, 1280-byte floor, `SAFE_BRINGUP_TUNNEL_MTU` 1420. Directly reusable for the mobile tun MTU dance.
- `ReconnectPolicy` + `next_reconnect_delay_jittered_ms` (`crates/rustynetd/src/resilience.rs`, AWS Full Jitter, FIS-0016) — the reconnect/backoff model for mobile network churn.
- Killswitch *precedence model* (`crates/rustynetd/src/killswitch_precedence.rs`): shared `RuleDisposition`, `terminator_is_reachable`, `ContainedInterfaces`, and the fail-closed `Escapes` default. There is no single killswitch struct; each OS binds the model to its own enforcement (Linux nftables boot file, macOS PF, Windows WFP smoke). Mobile binds the same model to the platform's own primitives (§4.3).
- `EnrollmentToken` (`crates/rustynetd/src/enrollment_token.rs`) — one-time HMAC device-onboarding token; the mobile "join the mesh by scanning a code" flow consumes this unchanged.
- `rustynet-netns-probe` — a **std-only** Rust crate (no external deps, offline-buildable) that byte-pins the STUN wire format against `rustynetd`'s `stun_client.rs`. Evidence that std-only mobile-compatible Rust components are already an accepted pattern in this repo.

### 1.6 What does NOT port

`rustynetd` as a whole (152,403 LOC) is a desktop supervisor: `DaemonRuntime` (`daemon.rs:4655`) is a large struct of file-path-backed state stores, `cfg(target_os)` fields (187 in `daemon.rs` alone; 73 in `phase10.rs`), and OS-integration via `Command::new` on `nft` (5 sites), `/sbin/pfctl` (4), `tcpdump`, `dig`, `/sbin/route`, `systemctl`, `ping`, `ip`, `sysctl`, `getent`, `dscacheutil`, `ping6`, and even `/bin/sh`. `privileged_helper.rs` (6,399 LOC) assumes a separate privileged binary — a pattern mobile OSes forbid (no root helper processes in app sandboxes). The mobile client reuses the *ideas* (fail-closed helpers, residue markers, precedence models) and the *portable pieces* (§1.5), not the daemon process itself. See §2.4 and §7.

`rustynet-cli` (324,273 LOC) is the lab robot + operator CLI; nearly all of it is irrelevant to mobile (its `vm-lab` surface is already default-off in release builds, per RNQ-17 in `AGENTS.md §11.2`).

---

## 2) Reuse thesis: the shared mobile core

### 2.1 Layer map, desktop → mobile

| Desktop component | Mobile role | Change required |
| --- | --- | --- |
| `rustynet-control` membership/enrollment/roles | Identical: identity, membership verification, role gating, replay watermarks | None — pure domain |
| `rustynet-policy` default-deny ACL | Identical: on-device ACL evaluation for app/split-tunnel policy | None |
| `rustynet-dns-zone` | Identical: signed Magic DNS zone parsing/verification | None |
| `rustynet-crypto` keys + custody | Identical key logic; new `OsSecureStore` impls for Keychain/Keystore | New adapter per platform (§5) |
| `rustynet-backend-api` `TunnelBackend` | The contract the mobile backend implements | None |
| vendored `boringtun` noise core | The WireGuard implementation itself | None — already platform-free |
| `rustynet-tun::SyncDevice` | The tun fd wrapper | Add Android + iOS arms (§3.2) |
| `userspace_shared/engine.rs` + `runtime.rs` I/O loop | The packet loop inside the VPN process/extension | Generalize fd acquisition (§3.3) |
| `rustynetd` gossip/relay/stun *client logic* | Peer discovery, relay fallback, NAT discovery on mobile | Partial: extract client halves; drop server/egress halves (§2.3) |
| `DaemonRuntime` | **Not ported.** Mobile gets a new, small orchestrator (§2.4) | New code, shared where possible |
| `privileged_helper.rs` | Nothing — no privileged helpers in mobile sandboxes | Replaced by OS VPN-service permissions |
| `rustynet-cli`, lab robot, install wizards | Nothing | N/A |

### 2.2 What "100% Rust core" means concretely

The claim is: **every security-critical decision and every packet byte after the OS-provided fd is processed by the same Rust code that desktop runs.** That includes: handshake + session crypto (boringtun noise), peer/endpoint management (`TunnelBackend` methods), membership verification + replay protection (`rustynet-control`), ACL decisions (`rustynet-policy`), DNS zone verification (`rustynet-dns-zone`), key custody decisions (`rustynet-crypto` + `OsSecureStore`), reconnect policy, PMTU state machine, and the killswitch *precedence decision* (with platform-native enforcement, §4.3).

The native shim (§4) never touches packet bytes and never makes a trust decision. It does lifecycle, UI, entitlement plumbing, and store I/O.

### 2.3 Client halves of gossip/relay/STUN

`rustynetd` mixes client and infrastructure logic. For mobile:

- **STUN client** — portable as-is (std-only patterns already proven by `rustynet-netns-probe`, which byte-pins this wire format).
- **RelayClient** (`crates/rustynetd/src/relay_client.rs`, 2,609 LOC) — the mobile node is a relay *consumer*, never a server; the client half ports, though it will need a review pass for desktop assumptions (blocking I/O style vs the mobile extension's lifetime constraints).
- **Gossip runtime** (`gossip_runtime.rs`, 2,670 LOC) — the mobile node participates as a leaf; expect to consume rather than rebroadcast at full mesh duty. Ports with the same caveat.

This extraction is the largest genuinely *new* engineering item in the core (§9, P2) — but it is Rust-to-Rust refactoring inside existing crates, not platform work.

### 2.4 The mobile orchestrator (new, small, Rust)

Rather than shrinking `DaemonRuntime`, the study proposes a new thin crate — working name `rustynet-mobile-core` — that composes: backend-api types + a `MobileVpnBackend` + control/policy/dns-zone + crypto custody + the portable pieces of §1.5. Its state machine is *much* smaller than the daemon's because mobile deletes whole subsystems: no port mapping (uPnP/PCP/NAT-PMP, `port_mapper.rs` 4,666 LOC — phones are never servers), no privileged helper, no launchd/systemd integration, no NAS/LLM serving roles, no exit-*serving*. What remains is: enroll → verify membership → configure peers → run tunnel → observe health → reconnect/roam → apply policy → fail closed.

The initial mobile role set should be **Client only** (with Admin-capable viewing later). `is_supported_for_platform()` (`crates/rustynet-cli/src/vm_lab/orchestrator/role.rs`) already establishes the principle that roles are platform-gated; the mobile core should enforce the same gate fail-closed at `start()`.

---

## 3) WireGuard on mobile as Rust: the fd-handoff boundary

### 3.1 The boundary in one sentence

**The OS creates and owns the tun interface; it hands the app a file descriptor; everything on the far side of that descriptor — handshake, encryption, peers, keepalive, DNS logic, killswitch decisions — is the shared Rust core.**

### 3.2 iOS: NetworkExtension PacketTunnelProvider

On iOS the app ships a **Packet Tunnel Provider extension** (a separate binary embedded in the app bundle, declared in the app's entitlements with the NetworkExtension + VPN entitlements). At tunnel start, `NEPacketTunnelProvider.startTunnel(with:)` is invoked by the system; the provider calls `setTunnelNetworkSettings(_:)` to set addresses/routes/DNS/MTU, after which the system hands the extension its packet flows — classically via `NEPacketTunnelFlow` (packets as `NSArray<NSData>` with an IPC ring buffer to the kernel) or, at the POSIX level, via a tun fd accessible through the flow's underlying file descriptor.

The Rust side treats that fd exactly like the macOS utun fd: `rustynet-tun`'s macOS arm already implements `SyncDevice::from_raw_fd(fd)` (`third_party/rustynet-tun/src/lib.rs:242-250`) with the 4-byte utun header framing handled internally (:180-240), and the macOS userspace engine already wraps an externally-created utun this way (`userspace_shared_macos/tun.rs:979` → `from_raw_fd` at :997). The iOS path is the same device family — the shim's job is reduced to: receive the fd/flow object, hand it to the FFI, call `start`.

Two iOS specifics the design must respect:

1. **Memory pressure & lifetime:** the extension can be killed at any time; the Rust core must treat every start as cold-start from verified state (which fail-closed membership verification already mandates) — no assumption of warm persistence.
2. **Packet model mismatch:** if the integration uses `NEPacketTunnelFlow`'s read/write packet arrays instead of a raw fd, the engine's fd-read loop needs a thin packet-source trait. The existing device seam (`userspace_shared/tun.rs:25` `fn real(device: SyncDevice)`, `:146` `Real(SyncDevice)`) is the right place: add a `PacketFlow` variant of that enum rather than bypassing the seam. (Prototype P1, §9, resolves which model the target iOS version gives us.)

### 3.3 Android: VpnService.establish()

On Android the app extends `VpnService` (an Android *Service* component); the user grants VPN permission once via the system consent dialog; `Builder().addAddress().addRoute().addDnsServer().setMtu().establish()` returns a **plain tun fd** (`ParcelFileDescriptor`, dup-able to an int). Android's tun fd semantics are byte-stream read/write with no header framing — the *simplest* of all platforms.

Required work, all tiny: add an Android arm to `rustynet-tun` (~20 LOC: a `from_raw_fd`-style constructor performing plain reads/writes; the Linux arm's read/write loop at `third_party/rustynet-tun/src/lib.rs:67-93` is the template) and add a `cfg(target_os = "android")` arm in the userspace backend that constructs the engine over the injected fd, following the existing fail-closed `platform_unavailable` pattern in `crates/rustynet-backend-userspace/src/lib.rs:69-82` (i.e., an unknown platform still fails closed at runtime).

The VPN process on Android *is* the app process running the foreground service; the Rust engine runs in-process behind the FFI, reading the fd on a dedicated thread.

### 3.4 What stays identical across both platforms after the fd exists

Everything: `Tunn` handshake initiation and response handling, session key rotation timers, anti-replay rate limiting, packet encrypt/decrypt, peer endpoint updates (`update_peer_endpoint`, `TunnelBackend` :246), keepalives (`PeerConfig.persistent_keepalive_secs`, :111-122), health observation (`peer_path_health` :263 / `peer_path_sample` :269), stats (:282), and shutdown (:357). The engine's UDP socket for WireGuard transport is created *inside* Rust on both platforms (normal app sockets; no entitlement needed for the WG UDP transport itself — only the tun interface is OS-gated).

### 3.5 DNS and killswitch on mobile

- **DNS:** the desktop Magic-DNS loopback-resolver posture (macOS `DnsPosture` machinery, `phase10.rs`/`macos_dns_sc_protect.rs`) does not port — mobile cannot install a system resolver. Instead: route DNS into the tunnel via the OS API (`setTunnelNetworkSettings` DNS settings on iOS; `addDnsServer` on Android) and serve/verify the signed zone in the shared core. The three-state posture idea (FullyProtected / Scoped / Untouched) survives as a **status model** the app reports, verified against actual settings the OS confirmed — fail-closed: posture unknown ⇒ report unprotected.
- **Killswitch:** the shared precedence model (`killswitch_precedence.rs`) decides; enforcement binds to platform primitives — iOS: the tunnel settings' `includeAllNetworks`/`excludeLocalNetworks`-style tight routing plus immediate `cancelTunnelWithError` on verification failure (NetworkExtension provides no firewall primitive; "fail closed" = tunnel-down ⇒ no traffic by construction); Android: `addDisallowedApplication` for the app itself + lockdown-style route coverage, and dropping the fd (interface gone) as the enforced default. The invariant to preserve is the desktop one: **the default disposition is `Escapes` ⇒ treat as failure** (`killswitch_precedence.rs` fail-closed default), and a `ShutdownResidueMarker`-style record is written before any teardown so a killed extension leaves a visible "did not shut down cleanly" trace.

---

## 4) The minimal native shim — what must be non-Rust and why

Nothing in the security core. The shim exists because four things are OS-proprietary surfaces that no Rust crate can occupy:

### 4.1 iOS shim (Swift, in the app + PacketTunnelProvider extension)

1. **Entitlements & packaging:** NetworkExtension entitlement, app groups (shared container between app and extension), keychain-access-group; Xcode project, code signing, App Store metadata. (No alternative exists; Apple controls the format.)
2. **PacketTunnelProvider lifecycle:** the extension subclass that receives `startTunnel`/`stopTunnel`, calls `setTunnelNetworkSettings`, and forwards the fd/flow into the Rust core; the system may kill/restart it — Swift owns the IPC surface with the system.
3. **UI:** SwiftUI views (status, connect/disconnect, enrollment QR scan, settings, killswitch posture display). The *logic behind every screen* is Rust via FFI; only view code is Swift.
4. **Keychain bridging:** thin calls to `Security.framework` (SecItem) implementing the `OsSecureStore` adapter — but this adapter can itself be the Rust `security-framework`-style crate talking to Keychain directly, with Swift doing nothing; the irreducible part is the entitlement configuration, not the code. (§5.)
5. **System callbacks:** `NWPathMonitor` for network changes → forwarded to the Rust core (endpoint re-assertion, reconnect policy tick).

### 4.2 Android shim (Kotlin, in the app + VpnService)

1. **Manifest & packaging:** `VpnService` service declaration, `BIND_VPN_SERVICE` permission, FOREGROUND_SERVICE permissions, Gradle/APK/AAB build, Play listing.
2. **VpnService lifecycle:** the `VpnService` subclass; the consent dialog flow; `Builder().establish()`; forwarding the returned fd into the FFI; foreground-notification requirements.
3. **UI:** Jetpack Compose screens (same screen set as iOS). Logic via FFI.
4. **Keystore bridging:** `AndroidKeyStore` access (hardware-backed keys, StrongBox where available) implementing the `OsSecureStore` adapter (§5).
5. **System callbacks:** `ConnectivityManager.NetworkCallback` for network changes → FFI.

### 4.3 Why nothing else needs to be native

Reviewing the desktop native-integration surface: every `Command::new` external binary in `rustynetd` (§1.6 list) is desktop-OS integration (nftables, PF, systemd, route) that mobile either forbids (helpers) or replaces with the VPN-service primitives above. File-path-backed daemon state becomes app-sandbox storage via a small Rust storage trait. Diagnostics (`rustynet-sysinfo` observation pattern, `CommandRunner` allowlist seam) shrink to what mobile OSes expose. There is no remaining class of functionality that requires non-Rust implementation code — only non-Rust *declaration* (manifests, entitlements, storyboards/views) and *lifecycle hosts* (the two service classes).

---

## 5) Key custody on mobile

### 5.1 The seam already exists

`rustynet-crypto` defines `pub trait OsSecureStore` (`crates/rustynet-crypto/src/lib.rs:312`), consumed by the generic `KeyCustodyManager<S: OsSecureStore>` (:381) with `store_private_key` (:431) / `load_private_key` (:459) and a configurable `OsStoreFallbackPolicy` (:390 — whether a missing OS store may fall back to encrypted-at-rest). The crate already ships: AEAD envelope encryption of key material (`generate_key_custody_material` :1338, `encrypt_private_key_envelope` :1382, `aead_seal` :1518 / `aead_open` :1552, `write_encrypted_key_file` :1572 / `read_encrypted_key_file` :1681), zeroizing `SecretKey` (:43, `ct_eq` :50), `Ed25519SigningProvider` (:1148) with provider attestation (:1269-1290), and macOS Keychain helpers (`store_macos_generic_password` :573, `load` :763, `system_keychain_owned` :836/:888) as the reference `OsSecureStore` consumer.

### 5.2 iOS adapter

An `IosKeychainStore: OsSecureStore` backed by SecItem (kSecClassGenericPassword, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, **app-group/keychain-access-group** so the tunnel extension and the app see the same items — matching the desktop pattern of `rustynet.anchor_enrollment_secret` keyed access, `documents/SecurityMinimumBar.md:419-424`). The WireGuard private key additionally benefits from **Secure Enclave**-backed protection: secp256r1 P-256 is the hardware curve, *not* X25519, so the WG private key cannot be generated *inside* the Enclave; the correct pattern is Enclave-wrapped storage — generate an Enclave key-encryption-key, wrap the X25519 secret with it, store the wrapped blob (AEAD with the Enclave key via ECIES/`kSecAlgorithmECIESEncryption`-style flow or AES key derived from an Enclave ECDH). This is "OS key store usage where available" + "zeroization strategy" satisfied at once (SecurityMinimumBar `documents/SecurityMinimumBar.md:216-222`).

### 5.3 Android adapter

An `AndroidKeystoreStore: OsSecureStore` backed by `AndroidKeyStore`: generate an AES-GCM or ECDH key with `setIsStrongBoxBacked(true)` when available (fall back to TEE-backed, and **fail or degrade loudly** if neither — per the fallback policy semantics of `OsStoreFallbackPolicy` :390, and the strictest-secure-default rule in `AGENTS.md §2`). Hardware-backed wrapping of the X25519 WG secret as on iOS; in-memory zeroization is already the crate's behavior.

### 5.4 Mapping to the security bar

| SecurityMinimumBar control | Mobile satisfaction |
| --- | --- |
| OS key store where available (:216-222) | Keychain / Keystore adapters implementing `OsSecureStore` |
| Encrypted-at-rest fallback with strict permissions + startup checks (:218) | Existing `write_encrypted_key_file` (:1572) in app-sandbox storage; sandbox permissions replace Unix-mode bits; startup check = wrapped-blob presence + hardware binding verification before any tunnel start (fail closed) |
| Zeroization (:216-222) | Already inherent (`SecretKey` :43-50, `KeyCustodyManager::new_zeroizing` :411) |
| Signing state fails closed when corrupt (:216-222) | Existing membership/signature verification paths unchanged |
| Anchor/enrollment secret OS-secure custody (:419-424, plaintext rejected) | Enrollment token handling keeps HMAC secret in the OS store; never in prefs/plist/SharedPreferences |

---

## 6) FFI boundary

### 6.1 Recommendation: **UniFFI for both platforms.**

Rationale against the alternatives:

- **UniFFI (Mozilla)** — one UDL/procmacro interface definition generates Swift *and* Kotlin bindings; supports async methods, enums, records, error types, and object handles; the de-facto standard for Rust mobile cores (Mozilla VPN itself, Iroh, Bitwarden). Cost: a `uniffi` dependency and some scaffolding; exported types must be FFI-friendly (no generics across the boundary).
- **swift-bridge / cxx (iOS)** — tighter Swift-native types and lower per-call overhead, but Swift-only: Android still needs JNI separately, doubling the interface maintenance for a control-plane API whose call volume is tiny (start/stop/status/enroll — not per-packet). Per-packet data never crosses the FFI anyway (the engine reads the fd directly inside Rust), so the performance argument is moot.
- **Raw JNI (Android)** — what vendored boringtun's uncompiled `jni.rs` (271 LOC) sketches; verbose, unsafe-adjacent, no Swift reuse. Reject as primary; UniFFI generates its Kotlin via the same machinery regardless of JVM.

Given `#![forbid(unsafe_code)]` is the workspace posture (`crates/rustynet-backend-api/src/lib.rs:1`) and the repo has **zero existing FFI crates** (grep across all Cargo.tomls: no uniffi/cxx/swift-bridge/jni/ndk), UniFFI's generated (audited, boring) glue is the best fit for a security-first codebase. The generated layer is the only place raw pointers cross; keep it confined to a new `rustynet-mobile-ffi` crate so the boundary is greppable and gateable.

### 6.2 Sketched exported API (illustrative, not final)

```rust
// rustynet-mobile-ffi (proposed) — object facade per platform host
pub struct MobileClient { /* orchestrator + custody + backend handle */ }

#[uniffi::export]
impl MobileClient {
    // Lifecycle: fd handed over by PacketTunnelProvider / VpnService.establish()
    fn start_tunnel(fd: i32, settings: TunnelSettings) -> Result<TunnelStatus, MobileError>;
    fn stop_tunnel(reason: StopReason) -> Result<TunnelStatus, MobileError>;
    fn status(&self) -> TunnelStatus;                 // posture, peers, health, killswitch state
    // Onboarding
    fn enroll(token: EnrollmentTokenInput, device_name: String) -> Result<EnrollmentReceipt, MobileError>;
    // Control plane
    fn apply_membership_update(&self, bundle: SignedBundleBytes) -> Result<(), MobileError>;
    fn set_exit_mode(&self, mode: ExitModeInput) -> Result<(), MobileError>;
    // Key ops (custody lives in rustynet-crypto behind these)
    fn ensure_device_key(&self, require_hardware_backing: bool) -> Result<KeyReport, MobileError>;
    fn public_key(&self) -> Vec<u8>;                  // 32-byte X25519 public
    // System callbacks forwarded from the shim
    fn on_network_path_changed(&self, snapshot: NetworkSnapshot);
    fn on_memory_pressure(&self);
}
```

Design rules for the boundary: no packet bytes ever cross FFI; all trust decisions stay in Rust; every fallible call returns a typed error (fail-closed, mirroring `BackendError` semantics, `backend-api/src/lib.rs:186-235`); status is pull-based with a small push event channel for posture changes; the fd is passed as an integer and immediately wrapped via the `SyncDevice::from_raw_fd` path (:242-250) so Drop ownership (closes on drop, :253-262) stays in Rust.

---

## 7) What is deliberately NOT reused — and why that is correct

1. **`DaemonRuntime`** (`daemon.rs:4655`): its size (38k LOC file), its file-path state stores, and its 187 per-OS cfg sites in one file make it the wrong substrate for an extension process with a 50 MB-class memory envelope and arbitrary kill timing. The mobile orchestrator (§2.4) re-implements *orchestration*, not *subsystems*, by composing the same crates.
2. **Privileged helper architecture** (`privileged_helper.rs`, 6,399 LOC): no equivalent exists on mobile; the OS VPN consent + extension sandbox replaces it as the privilege boundary.
3. **Exit-serving / NAS / LLM / Relay-serving / Anchor roles** on phones: resource and policy reality; role gate fails closed (§2.4). Blind-exit irreversibility rules (`role_presets.rs::validate_transition`) are irrelevant on mobile for the same reason.
4. **Port mapping** (`port_mapper.rs`, PCP/NAT-PMP/uPnP): phones don't host; traversal for mobile = STUN + relay client + ICE candidates only.
5. **`rustynet-cli`** entirely, except as a code donor for the enrollment-token and status display logic.

This trimming is also what makes the honest percentage in §8 achievable: the mobile client is not "the daemon on a phone" — it is a new small host around the shared domain + tunnel core.

---

## 8) THE VERDICT — numbers

Component-by-component disposition (LOC from the audit; "core" = shared library code inside the tunnel process; "shim" = thin platform-host code; "native" = irreducible platform code):

| Component | Disposition | Notes |
| --- | --- | --- |
| boringtun noise core (~2,700 LOC compiled) | **Rust** | unchanged, vendored |
| userspace engine + runtime + fair_drain (~7,500 LOC) | **Rust** | generalize fd acquisition (Android arm) |
| rustynet-tun (547 LOC) | **Rust** | + ~20-40 LOC Android/iOS arms |
| backend-api (442 LOC) | **Rust** | unchanged |
| rustynet-control (32,319 LOC) | **Rust** | unchanged |
| rustynet-policy (3,194 LOC) | **Rust** | unchanged |
| rustynet-dns-zone (1,664 LOC) | **Rust** | unchanged |
| rustynet-crypto (4,973 LOC) | **Rust** | + 2 `OsSecureStore` adapters (~300-500 LOC each, themselves Rust) |
| relay/STUN/gossip client halves (~5,000-7,000 LOC extracted) | **Rust** | P2 extraction effort |
| Mobile orchestrator (new) | **Rust** | est. 2,000-4,000 LOC, small state machine |
| FFI crate (new) | **Rust** (generated glue) | UniFFI; only place pointers cross |
| VPN service classes (NE provider / VpnService) | **Native** (thin) | ~150-300 LOC each; lifecycle + fd handoff only |
| UI | **Native** | Swift/SwiftUI + Kotlin/Compose; logic in Rust; size dominated by views |
| Entitlements/manifests/packaging | **Native** (declarative) | no code |
| Keychain/Keystore plumbing | **Mostly Rust** (store crates) + native declarations | access-group / keystore config declarative |
| Network-change callbacks | **Native** (thin) | NWPathMonitor / NetworkCallback, forwarders only |

**Rough composition of a shipped mobile client:**

- **iOS:** ~85–92% of *logic and code* is Rust (tunnel core, domain, custody, orchestrator, FFI); the irreducible Swift surface is ~8–15% (extension lifecycle, views, project config). Packet-path and security-decision code: **100% Rust**.
- **Android:** ~85–93% Rust by the same measure (simpler fd model, no utun framing); Kotlin surface ~7–15%.

**Can the app be 100% Rust? No** — and the irreducible remainder is exactly: (a) the platform-mandated service lifecycle classes (Apple/Google provide no Rust entry point for `NEPacketTunnelProvider` subclassing or `VpnService` subclassing — the class must exist in the platform language to be recognized), (b) UI (no first-class supported Rust UI story on either platform worth betting a security product on), (c) declarative entitlement/packaging artifacts. **Can the core be ~100% Rust? Yes** — that is the existing architecture's own trajectory: the vendored fork already deleted the platform I/O from the tunnel; the domain crates are import-safe anywhere; the custody trait exists. The smallest honest statement of the answer: **100% of the security boundary is Rust; the OS keeps the door frame.**

**Smallest possible native shim** (if the owner wants to harden further): iOS — a PacketTunnelProvider subclass whose every method is one call into FFI, plus a SwiftUI shell that is a bound status view; Android — a VpnService subclass whose `onStartCommand`/`onRevoke`/`establish` are one-call FFI forwards, plus a Compose shell. Everything behind those one-call surfaces can be Rust, including (via UniFFI callbacks) reconnection policy, posture reporting, and settings storage.

---

## 9) Risks, unknowns, and what to prototype first

### 9.1 Risks

1. **App Store / Play VPN policy.** Apple requires the NetworkExtension entitlement (request it from Apple; provisioning time is a schedule risk, not a code risk) and review of VPN apps under App Review guideline 5.6-ish VPN disclosures (privacy policy, data collection disclosure). Play requires the VPN permission declaration form and a privacy policy; background VPN policy favors foreground-service usage. Neither store prohibits userspace WG or Rust-compiled extensions; Mozilla VPN and Tailscale are operating precedents for exactly this architecture (Rust core + boringtun-lineage + UniFFI). Risk is procedural, not architectural.
2. **iOS packet model uncertainty** (`NEPacketTunnelFlow` arrays vs raw fd): affects the engine's read loop plumbing (§3.2). Bounded: the device seam absorbs either model. **Prototype P1 resolves it.**
3. **boringtun mobile performance.** Desktop numbers do not transfer directly (older ARM cores, thermal ceilings, NE memory limits). Mitigation: the engine already does batched fair draining (`fair_drain.rs`); benchmark early on target hardware (P2). No reason to expect inadequacy — commercial VPNs ship this exact lineage on phones — but *measure, don't assume*.
4. **Background execution limits.** iOS extensions are kill-prone; Android foreground services are persistent-notification-bound. Design consequence adopted throughout: cold-start correctness (fail-closed verification on every start — already the house rule), jittered reconnect (`resilience.rs` policy), no warm-state assumptions.
5. **Extension memory ceilings** (iOS NE budget ~50 MB class): the full domain stack is small, but audit `rustynet-control` + engine allocations under load; the `rustynet-alloc-meter` vendored crate exists for exactly this kind of accounting.
6. **Key-store policy drift:** OS store APIs change (accessibility classes, StrongBox availability); the `OsSecureStore` seam isolates it.
7. **Requirements gap:** `documents/Requirements.md` has no mobile requirements today (§0). Before implementation, mobile belongs in Requirements (R-class entries: roles allowed on mobile, killswitch posture semantics, custody bar application) — this doc does not create requirements; it proposes them.

### 9.2 Prototype order (cheapest risk retirement first)

1. **P1 — iOS fd/flow probe:** PacketTunnelProvider skeleton + `SyncDevice::from_raw_fd`-wrapped engine doing an echo of packets from a local server; resolves the packet-model question and memory ceiling in one spike. (~1–2 weeks.)
2. **P2 — Android end-to-end:** VpnService + Android tun arm + engine over injected fd, handshaking against a real lab exit node (the UTM lab provides the counterpart node). Resolves perf + fd lifecycle. (~1–2 weeks, largely parallel with P1.)
3. **P3 — UniFFI surface + custody adapters:** enroll → key in Keychain/Keystore (hardware-wrapped) → status loop across both platforms; the full shim API from §6.2 exercised from Kotlin and Swift tests.
4. **P4 — killswitch/posture verification harness:** the precedence model bound to platform enforcement, verified by adversarial tests (tunnel kill mid-flow, network flap, store corruption) — the mobile analog of the desktop fail-closed gate suites.

---

## 10) Sources (primary file:line claims)

- `crates/rustynet-backend-api/src/lib.rs`:1 (forbid unsafe), :8-63, :91-147, :237-358 (TunnelBackend surface).
- `third_party/boringtun/src/lib.rs`:13, :19-25 (noise-only exposure); `third_party/boringtun/Cargo.toml` (noise-only fork description, deps).
- `crates/rustynet-backend-wireguard/src/userspace_shared/engine.rs`:10-11 (direct noise-core driving); `userspace_shared/tun.rs`:25, :146, :302, :439 (device seam); `userspace_shared_macos/tun.rs`:979, :997 (external-fd wrap); `fair_drain.rs` (batched draining).
- `third_party/rustynet-tun/src/lib.rs`:3-129 (Linux), :131-505 (macOS incl. :242-250 from_raw_fd, :253-262 Drop), :507-542 (fail-closed fallback).
- `crates/rustynet-backend-userspace/src/lib.rs`:21-25, :69-82 (runtime fail-closed platform gating).
- `crates/rustynet-crypto/src/lib.rs`:312 (OsSecureStore), :381-459 (KeyCustodyManager), :1338-1681 (envelope/encrypted-file primitives), :43-50 (zeroizing SecretKey), :573-888 (macOS keychain helpers), :1148 (Ed25519SigningProvider).
- `documents/SecurityMinimumBar.md`:216-222 (§4 secret/key handling), :419-424 (enrollment secret custody), :693 (encrypted-at-rest precedent).
- `documents/CODE_MAP.md`:7-36 (layers), :311-329 (import rules), :331-344 (where-to-add), :357-363 (fail-closed call sites, RN-03).
- `crates/rustynetd/src/daemon.rs`:4655 (DaemonRuntime); LOC and external-binary inventory from the 2026-09-04 audit (§1.6).
- `crates/rustynetd/src/` portable pieces: `path_mtu.rs` (RFC 8899 state machine), `resilience.rs` (FIS-0016), `killswitch_precedence.rs`, `shutdown_residue.rs`, `enrollment_token.rs`.
- LOC totals: direct `wc`-style audit of `src/**/*.rs` per crate, 2026-09-04 (values in §1/§8).

*End of study.*
