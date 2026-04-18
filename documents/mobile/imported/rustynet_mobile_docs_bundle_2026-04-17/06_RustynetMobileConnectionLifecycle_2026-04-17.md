# Rustynet Mobile Connection Lifecycle

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetMobileConnectionLifecycle_2026-04-17.md`  
**Status:** Proposed lifecycle and flow design  
**Audience:** Rust engineers, Android engineers, iOS engineers, QA, security reviewers

---

## 1. Purpose

This document explains how a Rustynet mobile client should move through its important runtime states:

1. install,
2. first launch,
3. enrollment,
4. tunnel setup,
5. steady-state operation,
6. peer / route updates,
7. network roam events,
8. suspend / resume,
9. shutdown or revocation.

It is written to answer a practical question:

**When the app connects, reconnects, roams, or fails, which file is responsible for what?**

---

## 2. Shared connection model assumptions

This lifecycle assumes the following:

- Rustynet continues using its signed trust/configuration model rather than creating a mobile-only trust shortcut.
- The mobile product is a client role first.
- The shared Rust engine owns session logic, peer state, verification, and packet logic.
- Android and iOS own VPN lifecycle, secure storage, and platform network APIs.
- The underlying tunnel model remains consistent with a WireGuard-style packet tunnel and peer cryptographic identity model.

---

## 3. Main actors

### 3.1 Shared Rust actors

- `rustynet-mobile-core::engine::MobileEngine`
- `rustynet-mobile-core::enrollment`
- `rustynet-mobile-core::assignment`
- `rustynet-mobile-core::session`
- `rustynet-mobile-core::routes`
- `rustynet-mobile-core::dns`
- `rustynet-mobile-core::diag`

### 3.2 Android actors

- `MainActivity.kt`
- `RustynetVpnController.kt`
- `RustynetVpnService.kt`
- `AndroidSecretStore.kt`
- `UnderlyingNetworkMonitor.kt`
- `RustynetNative.kt`

### 3.3 iOS actors

- `RustynetMobileApp.swift`
- `TunnelManager.swift`
- `IOSSecretStore.swift`
- `PacketTunnelProvider.swift`
- `AppGroupStateStore.swift`
- `RustynetFFI.swift`

---

## 4. Lifecycle states

Suggested shared high-level states:

- `Uninitialized`
- `AwaitingUserPermission`
- `Enrolling`
- `Provisioned`
- `Connecting`
- `Connected`
- `Rekeying`
- `Roaming`
- `Suspended`
- `Stopping`
- `Stopped`
- `Error`
- `Revoked`

These states should be owned by Rust and surfaced to Kotlin / Swift as read-only app state.

---

## 5. Flow 1: first launch and local initialization

### 5.1 Goal

Start the app with no enrollment and no active tunnel.

### 5.2 Native responsibilities

#### Android

- launch app UI,
- load non-secret UX state,
- initialize `AndroidSecretStore`,
- ask the Rust FFI layer to create a `MobileEngine`,
- show that VPN permission is not yet granted or enrollment is not complete.

#### iOS

- launch container app,
- initialize `TunnelManager` and `IOSSecretStore`,
- load any saved `NETunnelProviderManager` preferences,
- create the shared Rust engine handle,
- show the current provisioning / permission state.

### 5.3 Rust responsibilities

- create an empty engine state,
- report whether persisted state is present,
- request any secure storage material needed to determine if the device is provisioned,
- emit a state snapshot for the UI.

### 5.4 Files that own this

- Rust: `engine.rs`, `state.rs`, `events.rs`
- Android: `MainActivity.kt`, `RustynetVpnController.kt`, `AndroidSecretStore.kt`
- iOS: `RustynetMobileApp.swift`, `TunnelManager.swift`, `IOSSecretStore.swift`

---

## 6. Flow 2: enrollment / provisioning

### 6.1 Goal

Turn an unprovisioned app into a trusted Rustynet device without weakening the existing trust model.

### 6.2 Enrollment sequence

1. User enters or scans enrollment information.
2. Native UI sends a narrow request to Rust.
3. Rust validates the input shape.
4. Rust requests any secret generation or retrieval path required.
5. Native secure-storage layer creates or unwraps local secret material as needed.
6. Rust performs control-plane communication and signature verification.
7. Rust produces a provisioned local state and a signed assignment baseline.
8. Native stores only the allowed persistent outputs.
9. UI moves to `Provisioned`.

### 6.3 Security-critical rule

Enrollment must not leave a raw long-lived private key in plain app storage even for “just one step.” The secret path must move directly from generation/import into secure storage or a Rust secret wrapper.

### 6.4 Function inventory

#### Rust

- `MobileEngine::begin_enrollment(request)`
- `MobileEngine::complete_enrollment(response)`
- `MobileEngine::verify_signed_assignment(bundle)`
- `MobileEngine::export_persisted_state()`

#### Native

- Android `EnrollmentViewModel.submitEnrollment()`
- Android `AndroidSecretStore.storeWrappedTransportKey()`
- iOS `EnrollmentViewModel.submitEnrollment()`
- iOS `IOSSecretStore.storeTransportKey()`

### 6.5 Files that own this

- Rust: `enrollment.rs`, `membership.rs`, `assignment.rs`, `secrets.rs`
- Android: `EnrollmentViewModel.kt`, `AndroidSecretStore.kt`, `RustynetNative.kt`
- iOS: `EnrollmentViewModel.swift`, `IOSSecretStore.swift`, `RustynetFFI.swift`

---

## 7. Flow 3: request VPN permission and prepare the OS tunnel surface

### 7.1 Android

Official Android guidance requires the app to call `VpnService.prepare()`, obtain consent if necessary, protect the tunnel socket from VPN capture, and then establish the TUN interface using `VpnService.Builder`.

#### Sequence

1. UI asks to connect.
2. `RustynetVpnController` calls `VpnService.prepare()`.
3. If consent is required, UI completes the system prompt.
4. `RustynetVpnService` starts.
5. Service creates or receives the upstream transport socket.
6. Service calls `protect()` on the socket before tunnel activation.
7. Service uses `Builder` to create the TUN interface.
8. Native side informs Rust that OS tunnel surfaces are ready.
9. Rust moves from `Provisioned` to `Connecting`.

#### Files

- `RustynetVpnController.kt`
- `RustynetVpnService.kt`
- `UnderlyingNetworkMonitor.kt`
- `RustynetNative.kt`

### 7.2 iOS

On iOS the container app manages `NETunnelProviderManager` configuration, while the packet tunnel extension owns the active tunnel lifecycle.

#### Sequence

1. UI asks to connect.
2. `TunnelManager` loads or creates provider preferences.
3. The app requests the system to start the packet tunnel.
4. `PacketTunnelProvider.startTunnel(...)` runs inside the extension.
5. Extension loads secure state via Keychain access group / shared policy.
6. Extension initializes the Rust engine or attaches to the required state.
7. Extension applies network settings and starts packet processing.
8. Rust moves to `Connecting`.

#### Files

- `TunnelManager.swift`
- `PacketTunnelProvider.swift`
- `IOSSecretStore.swift`
- `RustynetFFI.swift`

---

## 8. Flow 4: build and apply the tunnel plan

### 8.1 Goal

Translate signed Rustynet state into an OS-applicable plan:

- local tunnel addresses,
- peer set,
- routes,
- DNS servers / search settings,
- exit-mode decisions,
- keepalive / path behavior.

### 8.2 Ownership split

#### Rust computes

- peer config set,
- route set,
- DNS plan,
- exit/split/full tunnel decisions,
- handshake / reconnection triggers,
- internal state transition to `Connecting` / `Connected`.

#### Native applies

- Android `VpnService.Builder` address, route, DNS, MTU, and interface setup
- iOS `NEPacketTunnelNetworkSettings` and related route/DNS application

### 8.3 Function inventory

#### Rust

- `MobileEngine::build_tunnel_plan()`
- `RoutePlanner::compute(...)`
- `DnsPlanner::compute(...)`
- `SessionManager::prepare_peers(...)`

#### Native

- Android `RustynetVpnService.applyTunnelPlan(...)`
- iOS `PacketTunnelProvider.applyTunnelSettings(...)`

### 8.4 Files that own this

- Rust: `routes.rs`, `dns.rs`, `session.rs`, `peer_set.rs`
- Android: `RustynetVpnService.kt`
- iOS: `PacketTunnelProvider.swift`

---

## 9. Flow 5: steady-state packet and transport loop

### 9.1 Goal

Move encrypted packet traffic between the OS TUN surface and the remote Rustynet peers while keeping session state and diagnostics accurate.

### 9.2 Android steady-state shape

- `RustynetVpnService` owns the TUN file descriptor and OS service lifecycle.
- The Rust engine receives packet bytes from the TUN path.
- Rust processes packet routing / tunnel logic and emits transport datagrams.
- Native networking code or a Rust-owned socket path transmits those datagrams using the protected transport socket.
- Incoming datagrams are handed back to Rust for decryption / decapsulation.
- Rust emits clear packets for reinjection into the TUN interface.

### 9.3 iOS steady-state shape

- `PacketTunnelProvider` reads packets from `packetFlow`.
- Packets are handed to Rust.
- Rust emits transport datagrams to be sent to remote peers.
- Incoming datagrams are delivered back to Rust.
- Rust emits decapsulated packets to be written to `packetFlow`.

### 9.4 Critical rule

The packet loop must remain a Rust-owned logic path. Kotlin and Swift are only adapters to OS packet APIs.

### 9.5 Files that own this

- Rust: `session.rs`, `events.rs`, backend adapters, `diag.rs`
- Android: `RustynetVpnService.kt`, JNI shim, `RustynetNative.kt`
- iOS: `PacketTunnelProvider.swift`, `PacketFlowBridge.swift`, `RustynetFFI.swift`

---

## 10. Flow 6: peer, route, or policy updates while connected

### 10.1 Goal

Apply control-plane changes without breaking the trust model or leaving the app in a partially updated state.

### 10.2 Sequence

1. Native app or extension receives a trigger to refresh state.
2. Rust fetches or accepts a new signed assignment bundle.
3. Rust verifies signature and version / freshness rules.
4. Rust computes the delta.
5. Rust emits updated route/DNS/peer plan events.
6. Native applies only the required platform changes.
7. Session transitions either stay `Connected` or briefly enter `Rekeying` / `Roaming`.

### 10.3 Important requirement

A failed verification must fail closed. The app must not apply unsigned or invalid state “temporarily” just to preserve connectivity.

### 10.4 Files that own this

- Rust: `assignment.rs`, `peer_set.rs`, `routes.rs`, `dns.rs`, `session.rs`
- Android: `RustynetVpnService.kt`, `TunnelStateRepository.kt`
- iOS: `PacketTunnelProvider.swift`, `TunnelManager.swift`

---

## 11. Flow 7: roaming and path changes

### 11.1 Goal

Handle Wi-Fi to cellular transitions, interface churn, captive portals, and path preference changes without exposing route leaks or breaking session correctness.

### 11.2 Android

Android’s `VpnService` docs also point to tracking underlying networks when the VPN explicitly binds its upstream communications. The app should surface path changes to Rust and keep route ownership explicit.

#### Sequence

1. `UnderlyingNetworkMonitor` reports path change.
2. Native informs Rust via `on_network_path_changed(...)`.
3. Rust decides whether to:
   - keep current path,
   - update peer endpoint,
   - trigger handshake,
   - rebuild route/DNS plan,
   - enter `Roaming`.
4. Native updates any Android-specific underlying-network metadata.

### 11.3 iOS

Path changes show up through extension lifecycle and network-path observation available to the packet tunnel provider.

#### Sequence

1. `PathObserver` reports change.
2. Provider informs Rust.
3. Rust reevaluates endpoint/path assumptions and handshake needs.
4. Provider applies any required network-setting change.

### 11.4 Files that own this

- Rust: `path.rs`, `session.rs`, `timers.rs`
- Android: `UnderlyingNetworkMonitor.kt`, `RustynetVpnService.kt`
- iOS: `PathObserver.swift`, `PacketTunnelProvider.swift`

---

## 12. Flow 8: suspend, background, wake, and service recreation

### 12.1 Goal

Keep session behavior correct across lifecycle interruptions without losing track of trust state or leaking secrets into the wrong storage tier.

### 12.2 Android

Expected cases:

- service restarted by system,
- process recreation,
- app UI gone while VPN service remains alive,
- network temporarily unavailable.

Rules:

- persist only the minimum restart-safe non-secret state outside secure storage,
- reconstruct the engine from persisted state and secure storage inputs,
- never rely on UI-layer objects for active tunnel correctness.

### 12.3 iOS

Expected cases:

- packet tunnel extension started independently of the container app,
- extension restarted or reloaded,
- app and extension coordinating through App Group state,
- device lock / unlock changing key availability.

Rules:

- extension must be able to rehydrate required non-secret state without container-app cooperation,
- secret access should come from Keychain access groups, not App Group files,
- accessibility class choices must match the intended lock-state behavior.

---

## 13. Flow 9: stop, revoke, and teardown

### 13.1 Goal

Shut down cleanly without leaving stale routes, packet loops, or lingering secret copies in memory.

### 13.2 Sequence

1. User disconnects, OS revokes permission, or a fatal security error occurs.
2. Native signals Rust to stop.
3. Rust transitions to `Stopping`.
4. Rust clears active session state and zeroizes secret working buffers.
5. Native tears down OS tunnel resources.
6. Rust transitions to `Stopped` or `Revoked`.
7. UI receives final state and diagnostics.

### 13.3 Files that own this

- Rust: `session.rs`, `state.rs`, `secrets.rs`, `diag.rs`
- Android: `RustynetVpnService.kt`
- iOS: `PacketTunnelProvider.swift`, `TunnelManager.swift`

---

## 14. Diagnostics lifecycle

Diagnostics should be captured at state transitions, not through ad hoc log scraping.

Suggested diagnostic checkpoints:

- enrollment start/failure/success,
- permission denied,
- tunnel plan generated,
- tunnel settings applied,
- session connected,
- peer update applied,
- roam event handled,
- disconnect reason,
- verification failure.

The authoritative diagnostic artifact should come from Rust as a redacted snapshot, with native layers only adding platform-specific metadata that does not increase secret exposure.

---

## 15. Failure cases that must be tested deliberately

- enrollment interrupted after secret generation but before state save,
- Android tunnel socket not protected before route activation,
- iOS extension started while container app is not running,
- signed assignment update fails verification mid-session,
- service / extension restart after network loss,
- device lock changes key accessibility,
- persisted non-secret state present but secure storage item missing,
- FFI panic during packet loop or settings application.

---

## 16. Bottom line

A mobile VPN app is not just “connect” and “disconnect.” It is a long sequence of state transitions across:

- trust state,
- secure storage,
- OS VPN lifecycle,
- route and DNS application,
- packet I/O,
- network roaming,
- extension or service restart.

If each step has a clear file owner and function owner, the mobile implementation remains understandable and testable.

---

## Sources

### Rustynet and Rust references

- Workspace root: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/Cargo.toml`
- Repository README: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/README.md`
- Backend API crate: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/crates/rustynet-backend-api/src/lib.rs`
- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`

### Android official documentation

- VPN guide: `https://developer.android.com/develop/connectivity/vpn`
- `VpnService` API reference: `https://developer.android.com/reference/android/net/VpnService`

### Apple official documentation

- Network Extension overview: `https://developer.apple.com/documentation/networkextension`
- Packet tunnel provider: `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- `NEPacketTunnelProvider`: `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- `NETunnelProviderManager`: `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`

### WireGuard / security references

- WireGuard protocol overview: `https://www.wireguard.com/`
- WireGuard whitepaper: `https://www.wireguard.com/papers/wireguard.pdf`
- OWASP MASVS: `https://mas.owasp.org/MASVS/`
