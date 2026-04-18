# Rustynet Mobile Architecture Design (Mid-Level)

**Date:** 2026-04-17  
**Status:** Proposed design document for future implementation work  
**Audience:** Rustynet maintainers and implementers planning Android and iOS client work  
**Scope:** Mid-level architectural design. This document sits below the mobile roadmap and above per-directory / per-file implementation specifications.

---

## 1. Why this document exists

The current Rustynet repository already contains a substantial Rust workspace with separate crates for daemon, CLI, control, crypto, policy, relay, DNS zone, backend API, backend wireguard integration, and backend stubs.[^repo-workspace] The active execution ledgers also say the project is **not** fully release-ready yet because fresh-install evidence for current `HEAD` and canonical cross-network evidence for current `HEAD` are still open.[^phase5-readiness]

That matters for mobile planning because the correct question is **not** “How do we port the current desktop/server runtime wholesale onto phones?” The correct question is:

1. Which existing Rust crates and invariants are worth preserving?
2. Which current runtime surfaces are host-specific and should **not** be copied into mobile?
3. What new crates, native wrappers, build surfaces, and security boundaries are required to make Android and iOS first-class Rustynet clients?

This document answers those questions at a concrete repository and architectural level.

---

## 2. Current repo truth that shapes the mobile design

### 2.1 Existing seams Rustynet can reuse

Rustynet already has a backend abstraction crate (`rustynet-backend-api`) and a current WireGuard-oriented backend crate (`rustynet-backend-wireguard`). The backend trait already models operations such as start, peer configuration, endpoint updates, route application, exit-mode changes, handshake initiation, transport identity queries, shared transport send/receive, and shutdown.[^backend-api-lib] This is the most important existing extension seam for mobile.

The current backend WireGuard crate exports Linux and macOS concrete backends plus a `LinuxUserspaceSharedBackend`; there is no current Android or iOS backend export surface in that crate.[^backend-wireguard-lib]

The repository also already has reusable Rust crates that are naturally applicable to mobile:

- `rustynet-control` for signed control/state processing and persistence-related logic[^control-cargo]
- `rustynet-policy` for policy logic[^repo-workspace]
- `rustynet-crypto` for cryptographic helpers and keystore-related support[^crypto-cargo]
- `rustynet-dns-zone` for Magic DNS / signed zone representation[^dns-zone-cargo]
- parts of `rustynet-relay` for transport protocol/client logic, where appropriate[^relay-cargo]

### 2.2 Existing surfaces that should not be ported directly

The current repository also has large host-oriented surfaces in `rustynetd` and `rustynet-cli`, including daemon lifecycle code, privileged helper flows, IPC, VM-lab operations, service-management assumptions, and platform-specific runtime scaffolding.[^rustynetd-files][^rustynet-cli-files]

Those are valid for desktop/server hosts, but they are the wrong architectural starting point for mobile. Android expects VPN apps to be built around `VpnService`, with explicit user consent, foreground-service behavior, and a TUN interface created through `VpnService.Builder`.[^android-vpn-guide][^android-vpn-api][^android-vpn-protect] iOS expects a containing app plus a Packet Tunnel Provider app extension built on `NEPacketTunnelProvider`, with entitlement-gated Network Extension APIs and a separate extension lifecycle.[^apple-packet-provider][^apple-nepacketprovider][^apple-networkextension]

**Conclusion:** mobile should reuse Rust logic, but replace the host lifecycle layer completely.

---

## 3. Design goals

### 3.1 Primary goals

1. **Keep Rust central.** The tunnel/control/security core remains in Rust as much as practical.
2. **Use thin native wrappers.** Kotlin/Android and Swift/iOS should own only the OS lifecycle, entitlements, UI, and packet/TUN integration that the operating systems require.
3. **Preserve Rustynet’s existing security bar.** Rustynet already requires proven crypto, OS keystore use where available, zeroization, fail-closed behavior, supply-chain controls, and explicit documentation hygiene.[^security-minimum-bar]
4. **Make mobile capability truth explicit.** Do not pretend mobile can do everything the desktop/server runtime can do.
5. **Avoid shell and service-manager assumptions.** No `systemd`, `launchd`, shell bootstrap, or privileged-helper model should be treated as a mobile baseline.

### 3.2 Explicit non-goals for v1

The first mobile implementation should **not** try to make phones act as:

- relay hosts
- authoritative control-plane hosts
- always-on administration consoles
- direct ports of the current CLI operational surface
- hosts for the current shell-driven setup and lab tooling

Those can be revisited later, but they would materially increase platform risk, battery risk, review risk, and security complexity.

---

## 4. Recommended repository structure

This section proposes **new** repository paths. These do **not** exist today unless explicitly stated.

### 4.1 Recommended new top-level directories

```text
Rustynet/
  mobile/
    android/
    ios/
  crates/
    rustynet-mobile-core/
    rustynet-mobile-ffi/
    rustynet-backend-android/
    rustynet-backend-ios/
  documents/
    mobile/
      README.md
      MobileArchitectureDesign_2026-04-17.md
      AndroidImplementationPlan_YYYY-MM-DD.md
      IOSImplementationPlan_YYYY-MM-DD.md
      MobileStorageAndKeyCustody_YYYY-MM-DD.md
      MobileFfiContract_YYYY-MM-DD.md
      MobileThreatModel_YYYY-MM-DD.md
      MobileTestAndVerificationPlan_YYYY-MM-DD.md
  scripts/
    mobile/
      build-android.sh
      build-ios.sh
      package-ios-xcframework.sh
      verify-mobile-artifacts.sh
      generate-mobile-bindings.sh
```

### 4.2 Why this structure is the right level of separation

- `crates/` keeps the shared implementation in Rust and consistent with the current workspace layout.[^repo-workspace]
- `mobile/android/` and `mobile/ios/` isolate native application and extension packaging concerns.
- `documents/mobile/` keeps the mobile planning set together and avoids scattering architectural material through `operations/active/`.
- `scripts/mobile/` provides deterministic, reviewable build entry points instead of ad hoc local steps.

### 4.3 Documentation hygiene requirement

If this structure is adopted, `documents/README.md` should also be updated, because the repo’s documentation rules explicitly say indexes and surrounding documentation must be updated when adding new docs.[^documents-readme]

### 4.4 Existing repository files that will likely need changes

The mobile program can add new directories cleanly, but a few existing repository files will almost certainly need deliberate edits:

- `Cargo.toml` at the repo root: add the new mobile crates to the workspace and keep them under the existing workspace lint policy, including the current `unsafe_code = "forbid"` rule.[^repo-workspace]
- `documents/README.md`: add the new `documents/mobile/` subtree and source-precedence guidance for mobile docs.[^documents-readme]
- `crates/rustynet-backend-api/src/lib.rs`: confirm whether the current backend trait is already sufficient for mobile or whether a narrow trait evolution is needed for packet-batch-oriented iOS integration or mobile capability reporting.[^backend-api-lib]
- `crates/rustynet-control/`: audit which modules are daemon-free and reusable on mobile versus which assumptions must be extracted or wrapped.[^control-cargo]
- `crates/rustynet-crypto/`: add mobile-safe keystore/keychain abstraction helpers only if the existing crypto crate is the right long-term home for them.[^crypto-cargo]
- build and CI configuration: add mobile build/test jobs, artifact verification, and release gating in the repository’s existing automation surface.

### 4.5 Existing repository files that should not be reused directly on mobile

The following existing areas are better treated as reference material than as direct mobile dependencies:

- `crates/rustynetd/src/daemon.rs` and adjacent runtime files[^rustynetd-files]
- `crates/rustynetd/src/privileged_helper.rs` and host-privilege assumptions[^rustynetd-files]
- `crates/rustynet-cli/src/ops.rs`, VM-lab support, and host orchestration code[^rustynet-cli-files]
- host service/bootstrap flows documented for desktop and server operations[^documents-readme]

The mobile implementation should consume shared Rust logic intentionally rather than importing host-runtime code out of convenience.

---

## 5. Proposed Rust crate design

## 5.1 `crates/rustynet-mobile-core/`

**Purpose:** shared Rust application core for mobile clients.

**What belongs here:**

- signed assignment / configuration ingestion
- local configuration validation
- state-machine logic for connect / reconnect / disconnect
- exit-node selection logic
- LAN toggle and routing-intent planning logic
- DNS / Magic DNS state handling that is platform-agnostic
- control-plane sync logic that does not depend on desktop daemons
- diagnostics generation and redaction
- replay protection / metadata freshness validation for signed control artifacts
- battery/network-aware retry policy logic (platform-neutral policy, not scheduling APIs)

**What does not belong here:**

- Android `VpnService`
- iOS `NEPacketTunnelProvider`
- Swift/Kotlin UI code
- platform keystore APIs directly
- packet-flow API ownership specific to either OS

**Reasoning:** this crate should be the shared “mobile brain.” It keeps the core behavior in Rust and drastically reduces duplication across Android and iOS.

### 5.2 `crates/rustynet-mobile-ffi/`

**Purpose:** stable exported interface used by Android and iOS wrapper code.

**Recommended approach:** use UniFFI for high-level control/config/status APIs, because UniFFI has first-class Kotlin and Swift bindings.[^uniffi-swift-kotlin]

**What belongs here:**

- exported Rust functions and data models for:
  - app initialization
  - loading signed config bundles
  - selecting profiles / exit modes
  - start / stop / resume tunnel requests
  - status snapshots
  - diagnostics summaries
  - log redaction controls
  - sync / refresh entry points
- explicit FFI-safe error types
- versioned FFI contract identifiers
- panic containment at the export boundary

**Boundary rule:** the FFI surface should be **narrow** and versioned. No native caller should depend on internal Rust types or module layouts.

### 5.3 `crates/rustynet-backend-android/`

**Purpose:** Android-specific implementation of the backend seam for the mobile environment.

**Expected responsibilities:**

- adapt Android VPN/TUN lifecycle into the existing backend model
- accept protected socket handles and TUN file descriptors from Kotlin/Java
- integrate packet I/O with the shared Rust core
- enforce Android-specific route semantics as delivered by `VpnService.Builder`
- expose Android-relevant stats and error states back upward

**Important note:** Android’s custom VPN model requires using `VpnService.prepare()` for consent, `VpnService.protect()` to keep the tunnel’s own transport socket outside the VPN, and `VpnService.Builder` to establish the VPN interface.[^android-vpn-protect][^android-vpn-guide] This backend should therefore assume that the native Android wrapper owns the consent flow and initial descriptor creation.

### 5.4 `crates/rustynet-backend-ios/`

**Purpose:** iOS-specific implementation of the backend seam for the Packet Tunnel Provider environment.

**Expected responsibilities:**

- adapt packet-tunnel extension lifecycle into the existing backend model
- receive packet batches from `NEPacketTunnelFlow`
- send encapsulated packets back through the provider’s packet flow APIs
- map iOS routing/dns/network settings decisions into the Rust control logic
- emit provider-safe diagnostics and state for the containing app

**Important note:** iOS packet tunnels are implemented with `NEPacketTunnelProvider`, and packet flow is exposed through `packetFlow` / `NEPacketTunnelFlow`, which reads and writes packet batches rather than handing out the same sort of raw TUN descriptor Android does.[^apple-nepacketprovider][^apple-nepackettunnelflow][^apple-readpackets][^apple-writepackets] That means the iOS backend must be designed around batch packet callbacks, not around reusing an Android-style fd ownership model.

### 5.5 Why separate Android and iOS backend crates are preferable

A single “mobile backend” crate sounds neat, but the packet I/O ownership model is genuinely different across the two platforms:

- Android gives a `ParcelFileDescriptor`-backed VPN interface and requires careful socket protection to avoid routing loops.[^android-vpn-protect][^android-pfd]
- iOS gives packet-flow APIs inside a separate app extension and requires extension-safe packaging, App Groups, and Network Extension entitlements.[^apple-nepacketprovider][^apple-app-extension-safe][^apple-app-groups]

The backend interface can stay common; the concrete backend implementations should not be forced into a fake lowest-common-denominator abstraction.

### 5.6 Proposed internal file scaffolding for the new Rust crates

The following file layout is a **recommended scaffold**, not current repo truth. It is intended to make responsibilities explicit before implementation begins.

```text
crates/rustynet-mobile-core/
  Cargo.toml
  src/
    lib.rs
    app/
      mod.rs
      runtime.rs
      session.rs
      lifecycle.rs
    config/
      mod.rs
      signed_bundle.rs
      validation.rs
      freshness.rs
    control/
      mod.rs
      assignments.rs
      peers.rs
      exit_mode.rs
    dns/
      mod.rs
      magic_dns.rs
      resolver_state.rs
    policy/
      mod.rs
      lan_visibility.rs
      route_intent.rs
    sync/
      mod.rs
      refresh.rs
      backoff.rs
    diagnostics/
      mod.rs
      report.rs
      redaction.rs
    platform/
      mod.rs
      capabilities.rs
    errors.rs

crates/rustynet-mobile-ffi/
  Cargo.toml
  src/
    lib.rs
    api.rs
    models.rs
    errors.rs
    callbacks.rs
    runtime_handle.rs
  uniffi/
    rustynet_mobile.udl   # if the UDL-based UniFFI style is chosen

crates/rustynet-backend-android/
  Cargo.toml
  src/
    lib.rs
    backend.rs
    tun_fd.rs
    protected_socket.rs
    packet_io.rs
    routes.rs
    dns.rs
    stats.rs
    errors.rs

crates/rustynet-backend-ios/
  Cargo.toml
  src/
    lib.rs
    backend.rs
    packet_flow.rs
    packet_codec.rs
    routes.rs
    dns.rs
    stats.rs
    errors.rs
```

### 5.7 Purpose of the major Rust files

- `rustynet-mobile-core/src/app/runtime.rs`: owns the top-level mobile runtime and long-lived state handles.
- `rustynet-mobile-core/src/app/session.rs`: owns connect/disconnect/reconnect session state transitions.
- `rustynet-mobile-core/src/config/signed_bundle.rs`: parses and verifies the mobile-consumed signed control/config bundle.
- `rustynet-mobile-core/src/config/freshness.rs`: enforces expiry, replay, and trust-anchor freshness rules.
- `rustynet-mobile-core/src/control/peers.rs`: derives effective peer state to hand to the backend layer.
- `rustynet-mobile-core/src/control/exit_mode.rs`: centralizes exit-node preference and current effective exit mode.
- `rustynet-mobile-core/src/dns/magic_dns.rs`: holds Magic DNS state derivation that is common across Android and iOS.
- `rustynet-mobile-core/src/policy/route_intent.rs`: computes desired routing intent before each platform wrapper applies its own APIs.
- `rustynet-mobile-core/src/sync/backoff.rs`: provides consistent retry policy while leaving actual scheduling to the native platform.
- `rustynet-mobile-core/src/diagnostics/redaction.rs`: ensures diagnostics export is safe before anything crosses into UI, logs, or support bundles.
- `rustynet-mobile-ffi/src/api.rs`: the canonical exported surface that Kotlin and Swift call.
- `rustynet-mobile-ffi/src/runtime_handle.rs`: opaque runtime/session handles exposed across FFI.
- `rustynet-backend-android/src/protected_socket.rs`: Android-only logic for transport socket protection requirements.
- `rustynet-backend-android/src/tun_fd.rs`: fd ownership and safety wrappers for the Android TUN descriptor.
- `rustynet-backend-ios/src/packet_flow.rs`: packet-batch bridge between `NEPacketTunnelFlow` and Rust packet processing.
- `rustynet-backend-ios/src/packet_codec.rs`: iOS-side packet framing/adaptation helpers if the provider bridge requires them.

### 5.8 Ownership map: what lives where

| Concern | Primary owner | Why |
|---|---|---|
| Signed config verification | Rust mobile core | Must be identical across platforms and security-critical. |
| Peer/exit/policy derivation | Rust mobile core | Cross-platform behavior should stay consistent. |
| VPN permission and consent | Native Android / native iOS app surfaces | Required by OS APIs. |
| Live TUN / packet interface ownership | Native Android service and iOS packet-tunnel extension | Required by platform lifecycle rules. |
| Packet processing backend | Rust Android/iOS backend crates | Keeps data path logic in Rust where practical. |
| Secret storage API calls | Native wrappers plus Rust policy | OS-specific storage APIs, Rust-owned security policy. |
| UI presentation | Kotlin / Swift | Native user experience and platform integration. |
| Diagnostics redaction policy | Rust mobile core | Security-sensitive and should remain consistent. |
| Deferred refresh scheduling | WorkManager / BGTaskScheduler or equivalent native schedulers | Platform-owned scheduling semantics. |

---

## 6. Proposed native project layout

## 6.1 Android project structure

```text
mobile/android/
  settings.gradle.kts
  build.gradle.kts
  app/
    build.gradle.kts
    src/main/AndroidManifest.xml
    src/main/java/com/rustynet/mobile/
      MainActivity.kt
      RustyNetApplication.kt
      ui/
        onboarding/
        tunnel/
        settings/
        diagnostics/
      vpn/
        RustyNetVpnService.kt
        TunnelController.kt
        TunnelNotificationManager.kt
        VpnPermissionLauncher.kt
      bridge/
        RustBridge.kt
        FfiModels.kt
        FfiErrorMapper.kt
      security/
        AndroidKeystoreFacade.kt
        KeyAttestationVerifier.kt
        SecretMaterialPolicy.kt
      storage/
        SecureConfigStore.kt
        SharedPrefsStore.kt
      sync/
        AssignmentRefreshWorker.kt
        TrustMaterialRefreshWorker.kt
      net/
        ConnectivityObserver.kt
        NetworkChangeCoordinator.kt
    src/androidTest/
    src/test/
```

### Purpose of the major Android files

- `RustyNetVpnService.kt`: owns the Android `VpnService` lifecycle, permission result handling, foreground-service requirements, and handoff to Rust.[^android-vpn-guide][^android-vpn-api]
- `TunnelController.kt`: mediates between UI state and the Rust core state machine.
- `RustBridge.kt`: the only Kotlin layer that directly speaks to the Rust FFI.
- `AndroidKeystoreFacade.kt`: wraps key generation / storage / retrieval policy through Android Keystore.[^android-keystore][^android-cryptography-guide]
- `KeyAttestationVerifier.kt`: verifies hardware-backed or policy-required attestation evidence where enforced.[^android-attestation]
- `AssignmentRefreshWorker.kt`: uses WorkManager for deferrable refresh and trust-material maintenance work, not for the live tunnel itself.[^android-workmanager][^android-background-overview]
- `TunnelNotificationManager.kt`: ensures the user-visible and policy-required foreground notification path is owned centrally.

### 6.2 iOS project structure

```text
mobile/ios/
  RustyNetMobile.xcodeproj/
  RustyNetMobile/
    App/
      RustyNetMobileApp.swift
      MainView.swift
      TunnelViewModel.swift
    Tunnel/
      TunnelManager.swift
      RustBridge.swift
    Security/
      KeychainStore.swift
      SharedAccessGroupPolicy.swift
      SecretMaterialPolicy.swift
    Storage/
      SharedContainerStore.swift
      PreferencesStore.swift
    Sync/
      AssignmentRefreshScheduler.swift
      TrustMaterialRefreshScheduler.swift
    Diagnostics/
      DiagnosticsExporter.swift
    Resources/
      Info.plist
      RustyNetMobile.entitlements
  RustyNetPacketTunnel/
    PacketTunnelProvider.swift
    PacketFlowBridge.swift
    ProviderStateStore.swift
    Info.plist
    RustyNetPacketTunnel.entitlements
  Frameworks/
    RustyNetMobile.xcframework
```

### Purpose of the major iOS files

- `TunnelManager.swift`: the containing app’s owner for `NETunnelProviderManager` configuration and control.[^apple-netunnelprovidermanager]
- `PacketTunnelProvider.swift`: subclass of `NEPacketTunnelProvider`; this is the entry point for the live tunnel extension.[^apple-nepacketprovider]
- `PacketFlowBridge.swift`: translates `NEPacketTunnelFlow` packet batches to and from the Rust backend boundary.[^apple-nepackettunnelflow]
- `KeychainStore.swift`: stores transport key material and sensitive credentials in Keychain; uses access groups where the app and extension must share them.[^apple-keychain-sharing][^apple-keychain-access-groups]
- `SharedContainerStore.swift`: stores non-secret app/extension shared state in an App Group container.[^apple-app-groups]
- `RustBridge.swift`: app- and extension-safe binding layer to the Rust XCFramework.
- `RustyNetPacketTunnel.entitlements`: contains Network Extension and any required App Group / shared access entitlements.

### Why a containing app and extension must both exist on iOS

The containing app uses `NETunnelProviderManager` to create, save, and control VPN configurations, while the live tunnel execution occurs inside the Packet Tunnel Provider extension.[^apple-netunnelprovidermanager][^apple-nepacketprovider] Those are separate packaging and lifecycle surfaces by design.

---

## 7. Runtime architecture

## 7.1 Shared architecture summary

At runtime, the mobile client should be split into three layers:

1. **Native application / extension layer**  
   Owns OS permissions, UI, app lifecycle, notifications, entitlements, packet/TUN creation, and keystore access.

2. **Rust FFI layer**  
   Owns a narrow, versioned exported contract used by Kotlin and Swift.

3. **Rust mobile core + platform backend layer**  
   Owns connect/reconnect state, signed config application, policy decisions, packet/tunnel orchestration, route intent, exit-mode state, diagnostics, and platform-agnostic security logic.

This gives the project a **Rust-first core** without fighting the operating systems.

### 7.2 Android runtime flow

1. UI requests connection.
2. App checks / requests VPN consent via `VpnService.prepare()`.[^android-vpn-protect]
3. `RustyNetVpnService` starts and promotes itself correctly as a foreground service where required.[^android-vpn-api]
4. Service opens or receives the transport socket and calls `VpnService.protect()` so the transport path does not loop back through the VPN.[^android-vpn-protect]
5. Service configures the VPN interface via `VpnService.Builder` and obtains the `ParcelFileDescriptor` for the TUN interface.[^android-vpn-guide][^android-vpn-builder]
6. Kotlin passes the necessary descriptors / handles to the Rust backend boundary.
7. Rust mobile core applies signed state, routing intent, DNS intent, and peer configuration.
8. Android backend runs packet/tunnel processing and reports status upward.
9. WorkManager handles deferred refresh tasks such as trust or assignment updates; it is not the live tunnel engine.[^android-workmanager][^android-background-overview]

### 7.3 iOS runtime flow

1. Containing app creates or updates a `NETunnelProviderManager` configuration.[^apple-netunnelprovidermanager]
2. User activates the VPN.
3. iOS launches the Packet Tunnel Provider extension.
4. `PacketTunnelProvider` loads its configuration and shared secrets from Keychain/App Group state.[^apple-keychain-sharing][^apple-app-groups]
5. Provider reads packets from `packetFlow` / `NEPacketTunnelFlow` and passes packet batches into the Rust backend boundary.[^apple-nepackettunnelflow][^apple-readpackets]
6. Rust mobile core applies signed state, routing intent, DNS intent, and peer configuration.
7. Backend sends tunnel output back through `NEPacketTunnelFlow.writePackets(...)`.[^apple-writepackets]
8. The containing app observes summarized state via shared storage or other approved coordination primitives.[^apple-app-groups]

### 7.4 Why the packet loop must be designed differently on iOS

On Android, a file-descriptor-oriented design is natural. On iOS, `NEPacketTunnelFlow` is packet-batch and callback oriented.[^apple-nepackettunnelflow] That means the architecture must avoid assuming a single packet engine integration shape across both platforms.

---

## 8. Rust/native boundary design

## 8.1 Boundary principles

The boundary between Rust and Kotlin/Swift should follow these rules:

1. No native code reaches into internal Rust modules directly.
2. All exported Rust operations are versioned and documented.
3. All panics are contained before they cross FFI.
4. All secrets are zeroized or lifetime-bounded on the Rust side where possible.[^security-minimum-bar]
5. Logging across the boundary is redacted by default.
6. Threading ownership is explicit; callbacks must not hide reentrancy assumptions.

### 8.2 Recommended API shape

**Good FFI candidates:**

- initialize / shutdown runtime
- load or replace signed configuration bundle
- apply UI-driven preference changes
- request connect / disconnect / reconnect
- get connection status snapshot
- export redacted diagnostics bundle
- fetch current route / DNS / exit summary
- request soft refresh of assignment or trust state

**Bad FFI candidates:**

- exposing internal Rust structs wholesale
- passing unbounded arbitrary JSON blobs through every layer
- putting secret material into verbose exception strings
- making the UI layer responsible for replay protection or signature verification

### 8.3 UniFFI versus narrow C ABI

Use UniFFI for the **control/config/status API** because Swift and Kotlin support is already available.[^uniffi-swift-kotlin] For the packet hot path, keep the design flexible:

- On Android, an fd-oriented integration can likely stay mostly on the Rust side after the descriptor handoff.
- On iOS, packet batching through `NEPacketTunnelFlow` may justify a thinner custom boundary for packet buffers if UniFFI overhead or ergonomics are not appropriate.

This is a design recommendation, not a statement that UniFFI cannot be used for packet flow. The goal is to avoid locking the highest-throughput path to a tool that was selected for ergonomic high-level bindings.

---

## 9. Security architecture

## 9.1 Storage and key custody

Rustynet’s current security minimum bar already says to use OS keystores where available and to provide encrypted-at-rest fallback only when that is unavoidable.[^security-minimum-bar]

### Android

Use Android Keystore for application key material or for wrapping sensitive transport/config secrets. Android’s official guidance is to use Android Keystore when applications require greater key security, and hardware-backed support can be strengthened with key attestation where policy requires that assurance.[^android-keystore][^android-cryptography-guide][^android-attestation]

**Recommended Android policy:**

- generate/store a wrapping or custody key in Android Keystore
- prefer hardware-backed / StrongBox-backed storage when available[^android-keystore]
- record capability truth instead of assuming uniform hardware support
- use attestation only where the trust model genuinely needs it
- keep secrets out of logs, intents, and plain shared preferences[^android-hardcoded-secrets]

### iOS

Use Keychain for sensitive transport key material and credentials. iOS apps and their Packet Tunnel Provider extensions can share Keychain items using access groups, while non-secret shared state can live in an App Group container.[^apple-keychain-sharing][^apple-keychain-access-groups][^apple-app-groups]

**Important design constraint:** WireGuard uses Curve25519-based keys.[^wireguard-protocol] Apple’s Secure Enclave APIs exposed through CryptoKit are centered on Secure Enclave-managed P-256 keys, not on directly storing arbitrary Curve25519 private keys inside Secure Enclave.[^apple-cryptokit-curve25519][^apple-secureenclave] Therefore, the mobile design should **not** assume that the tunnel transport private key itself can simply be moved into Secure Enclave. The correct baseline is **Keychain custody for transport keys**, with Secure Enclave reserved for separate keys only if a later design finds a justified use.

### Shared rule

App Group storage should be treated as **shared state**, not as a magic secure keystore. Secrets should live in Keychain / Keystore; the shared container should hold non-secret configuration, status, and coordination state.

## 9.2 Cryptography policy

Rustynet should continue to rely on well-known modern primitives. WireGuard’s protocol uses ChaCha20-Poly1305, Curve25519, BLAKE2s, SipHash24, and HKDF, and the project publicly documents substantial protocol analysis and formal verification work.[^wireguard-protocol][^wireguard-verification]

That supports the existing Rustynet security posture of preferring proven constructions over bespoke mobile-specific crypto.

## 9.3 Mobile hardening baseline

The mobile program should explicitly align with OWASP MASVS / MASTG for storage, cryptography, platform interaction, network communication, code quality, and testing discipline.[^owasp-masvs][^owasp-mastg]

Recommended baseline controls:

- no secrets in logs, analytics, screenshots, or crash reports
- secure wipe / zeroization of temporary secret buffers where possible[^security-minimum-bar]
- authenticated, replay-resistant signed control artifacts
- fail-closed behavior on signature, freshness, or trust-anchor failure[^security-minimum-bar]
- build-time prohibition of accidental debug leakage in release builds
- deterministic release build and dependency review gates

---

## 10. Build and packaging architecture

## 10.1 Android

Rust supports Android targets including `aarch64-linux-android` and other Android triples.[^rust-android-targets][^rust-platform-support] Android native code integration is officially supported through the NDK, and JNI guidance is documented by Android.[^android-ndk][^android-jni]

**Recommended Android packaging model:**

- build Rust mobile crates as Android-native libraries for target ABIs
- package them through the Android app module
- keep Kotlin as the ownership layer for `VpnService`, permission, notification, and WorkManager integration
- keep Rust as the owner of core connection logic, config verification, policy, and the bulk of tunnel orchestration

## 10.2 iOS

Apple supports distributing compiled cross-platform binary frameworks as XCFrameworks, which can bundle multiple slices and be consumed by Apple-platform projects or Swift Package Manager binary targets.[^apple-xcframework][^apple-spm-binary]

**Recommended iOS packaging model:**

- build Rust code into Apple-platform library slices
- package them into `RustyNetMobile.xcframework`
- embed that XCFramework into both the containing app and the Packet Tunnel Provider extension
- ensure all linked code is app-extension-safe where the extension is concerned[^apple-app-extension-safe][^apple-embed-frameworks]

### 10.3 Shared build scripts

Add script entry points under `scripts/mobile/` so CI and humans use the same top-level commands:

- `build-android.sh`
- `build-ios.sh`
- `package-ios-xcframework.sh`
- `verify-mobile-artifacts.sh`
- `generate-mobile-bindings.sh`

These scripts should emit explicit artifact manifests, hashes, and failure reasons.

---

## 11. Test and verification architecture

## 11.1 Test layers

### Rust layer

- unit tests for `rustynet-mobile-core`
- property or invariant tests for signed artifact parsing / validation
- route / policy tests
- replay/freshness validation tests
- secret redaction tests

### FFI layer

- contract tests for exported methods and data models
- compatibility tests when bumping the FFI version
- panic-containment tests
- threading / callback reentrancy tests

### Android layer

- unit tests for Kotlin wrappers
- instrumentation tests for VPN permission, keystore policy, and foreground-service transitions
- network-switch / connectivity-change tests
- tests ensuring tunnel transport sockets are protected from recursive routing[^android-vpn-protect]

### iOS layer

- unit tests for app-side manager code
- extension tests for Packet Tunnel Provider state transitions
- tests for App Group and Keychain sharing assumptions[^apple-app-groups][^apple-keychain-sharing]
- route / DNS configuration verification through Network Extension APIs[^apple-routing]

## 11.2 Security verification gates

The mobile path should inherit Rustynet’s current emphasis on audit gates and release readiness. The repo already has a release-readiness summary and a security minimum bar.[^phase5-readiness][^security-minimum-bar]

Recommended mobile-specific gates:

- `cargo fmt`, `cargo check`, `cargo clippy`, `cargo test`
- Android lint / instrumentation test pass
- iOS app + extension build/test pass
- SBOM generation for mobile artifacts
- dependency audit gates consistent with existing repo practice
- explicit release profile checks that debug logging and unsafe diagnostics are off
- MASVS-aligned verification checklist completion[^owasp-masvs]

---

## 12. Feature slicing for the first mobile implementation

## 12.1 Recommended v1 feature set

- sign in / enroll into an existing Rustynet environment
- receive and validate signed assignments/configuration
- start and stop the tunnel
- show connection state and peer/exit summary
- select or clear exit-node preference
- apply LAN-visibility preference if supported by policy
- show current DNS mode / Magic DNS state
- export a redacted diagnostics bundle
- refresh trust/config state safely on foreground and scheduled maintenance paths

## 12.2 Recommended deferred features

- running a relay on the phone
- running a production exit node on the phone
- full administrative control-plane tooling on-device
- mobile equivalents of current VM-lab and host-orchestration flows
- shell parity with desktop operations
- full desktop/server daemon parity

This is not because those are impossible in all cases. It is because the current repo shape and platform rules make them poor first-delivery choices.[^android-vpn-guide][^apple-networkextension][^rustynetd-files][^rustynet-cli-files]

---

## 13. Implementation sequence

### Phase A - foundation

1. Add `documents/mobile/` and index it.
2. Add new workspace crates:
   - `rustynet-mobile-core`
   - `rustynet-mobile-ffi`
   - `rustynet-backend-android`
   - `rustynet-backend-ios`
3. Define the first stable FFI contract.
4. Decide which existing crates are imported unchanged versus wrapped.

### Phase B - Android skeleton

1. Create `mobile/android/` Gradle project.
2. Implement `RustyNetVpnService.kt` skeleton.
3. Build Rust Android artifacts and load them from the app.
4. Prove descriptor handoff and a no-traffic connect/disconnect cycle.
5. Add Keystore-backed local custody.

### Phase C - iOS skeleton

1. Create containing app and Packet Tunnel Provider targets.
2. Package Rust as an XCFramework.
3. Implement `NETunnelProviderManager` and `PacketTunnelProvider` scaffolding.
4. Prove Keychain/App Group sharing.
5. Prove packet batch handoff from `NEPacketTunnelFlow` to Rust and back.

### Phase D - functional tunnel

1. Integrate signed config loading.
2. Integrate peer configuration.
3. Bring up real tunnel connectivity.
4. Add exit mode and DNS state handling.
5. Add diagnostics and recovery logic.

### Phase E - security and release hardening

1. Add attestation/capability truth on Android where required.
2. Add release logging restrictions.
3. Run MASVS-style verification.
4. Add CI artifact verification and readiness reporting.

---

## 14. Pitfalls and hidden questions that should be answered early

### 14.1 Android-specific pitfalls

- **Recursive routing:** if the tunnel’s own transport socket is not protected with `VpnService.protect()`, the connection can loop back into the VPN.[^android-vpn-protect]
- **Foreground-service behavior:** Android places operational requirements on VPN services; the app should not assume a background-only service model.[^android-vpn-api]
- **Wrong tool for background work:** WorkManager is for deferrable background maintenance, not for the active data path.[^android-workmanager][^android-background-overview]
- **Hardware-backed myth:** not every Android device offers the same Keystore guarantees; capability truth must be measured, not assumed.[^android-keystore][^android-attestation]

### 14.2 iOS-specific pitfalls

- **Extension-safe code only:** the packet tunnel extension must not link APIs that are not allowed in app extensions, or distribution will fail.[^apple-app-extension-safe]
- **Two-process assumption:** the containing app and provider extension are separate lifecycle surfaces; do not rely on shared in-memory state.
- **Wrong secret store:** App Groups are for sharing state, not for replacing Keychain.
- **Wrong key assumption:** Secure Enclave is not a generic storage target for WireGuard/Curve25519 transport keys.[^apple-secureenclave][^apple-cryptokit-curve25519][^wireguard-protocol]
- **Misusing Network Extension:** TN3120 defines expected use cases for packet tunnel providers; this should remain a VPN client design, not a vague generic packet interception project.[^apple-tn3120]

### 14.3 Rust / FFI pitfalls

- **Unbounded surface area:** if every internal type leaks through FFI, future refactors will stall.
- **Panic leakage:** any panic crossing FFI is a correctness and stability bug.
- **Callback reentrancy surprises:** packet and status callbacks need explicit threading contracts.
- **Logging leaks:** mobile crash and analytics pipelines can become a secret exfiltration path if redaction is not enforced.

### 14.4 Product / architecture questions to settle before code grows

1. Is mobile v1 strictly a client of an existing Rustynet deployment, or should it participate in enrollment/bootstrap flows directly?
2. Which signed artifacts must be cached offline, and what freshness / replay bounds are required?
3. Which diagnostics are allowed to cross from the Packet Tunnel Provider extension to the containing app?
4. Are per-app VPN and always-on variants in scope for either platform in v1, or are they deferred?
5. Which portions of the current `rustynet-control` persistence model are appropriate on mobile, and which should be re-scoped?
6. What is the minimum viable offline behavior when the control plane is temporarily unavailable?
7. Which Android device classes and iOS minimum versions will be supported in the first release?

These questions are worth answering now because they directly affect the crate boundaries and file layout proposed above.

---

## 15. What should be documented next

The next most useful documents after this one are:

1. **Android implementation plan**  
   exact class responsibilities, manifest/service requirements, descriptor handoff, foreground notification policy, and Keystore flows

2. **iOS implementation plan**  
   exact target layout, entitlement set, app-group model, packetFlow bridging model, XCFramework packaging, and key sharing rules

3. **Mobile storage and key custody spec**  
   transport keys, wrapping keys, cache encryption, replay/freshness metadata, zeroization policy, and backup/migration rules

4. **Mobile FFI contract spec**  
   exported API, versioning, threading model, panic policy, data model ownership, and error mapping

5. **Mobile threat model**  
   attacker classes, secret exposure paths, on-device compromise assumptions, logging/telemetry exposure, and rollback/replay concerns

6. **Mobile test and verification plan**  
   Rust tests, platform tests, MASVS mapping, release gates, and artifact provenance

---

## 16. Bottom line

The right way to make Rustynet work on Android and iOS is **not** to port the current host runtime intact. The correct shape is:

- keep the core trust, policy, configuration, and tunnel orchestration logic in Rust
- add a shared `rustynet-mobile-core`
- add separate Android and iOS backend adapters behind the existing backend seam
- add a narrow FFI crate for Kotlin and Swift integration
- let Android own `VpnService` and iOS own `NEPacketTunnelProvider`
- keep secrets in Keystore/Keychain, not in improvised shared storage
- make mobile capability truth explicit and release-gated

That gives Rustynet a mobile architecture that is consistent with the current workspace, consistent with Android and Apple platform rules, and consistent with the project’s existing Rust/security posture.

---

## Sources

### Rustynet repository and current docs

[^repo-workspace]: Rustynet workspace `Cargo.toml`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/Cargo.toml
[^phase5-readiness]: `documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md
[^documents-readme]: `documents/README.md`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/documents/README.md
[^security-minimum-bar]: `documents/SecurityMinimumBar.md`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/documents/SecurityMinimumBar.md
[^backend-api-lib]: `crates/rustynet-backend-api/src/lib.rs`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-backend-api/src/lib.rs
[^backend-wireguard-lib]: `crates/rustynet-backend-wireguard/src/lib.rs`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-backend-wireguard/src/lib.rs
[^control-cargo]: `crates/rustynet-control/Cargo.toml`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-control/Cargo.toml
[^crypto-cargo]: `crates/rustynet-crypto/Cargo.toml`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-crypto/Cargo.toml
[^dns-zone-cargo]: `crates/rustynet-dns-zone/Cargo.toml`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-dns-zone/Cargo.toml
[^relay-cargo]: `crates/rustynet-relay/Cargo.toml`, GitHub raw: https://raw.githubusercontent.com/Iwan-Teague/Rustynet/refs/heads/main/crates/rustynet-relay/Cargo.toml
[^rustynetd-files]: `crates/rustynetd/src/` repository listing, GitHub: https://github.com/Iwan-Teague/Rustynet/tree/main/crates/rustynetd/src
[^rustynet-cli-files]: `crates/rustynet-cli/src/` repository listing, GitHub: https://github.com/Iwan-Teague/Rustynet/tree/main/crates/rustynet-cli/src

### Android official sources

[^android-vpn-guide]: Android Developers, “VPN” guide: https://developer.android.com/develop/connectivity/vpn
[^android-vpn-api]: Android Developers, `VpnService` API reference: https://developer.android.com/reference/android/net/VpnService
[^android-vpn-builder]: Android Developers, `VpnService.Builder` API reference: https://developer.android.com/reference/android/net/VpnService.Builder
[^android-vpn-protect]: Android Developers, custom VPN implementation guidance including `prepare()`, `protect()`, and `Builder.establish()`: https://developer.android.com/develop/connectivity/vpn?hl=en
[^android-pfd]: Android Developers, `ParcelFileDescriptor` API reference: https://developer.android.com/reference/android/os/ParcelFileDescriptor
[^android-keystore]: Android Developers, Android Keystore system: https://developer.android.com/privacy-and-security/keystore
[^android-attestation]: Android Developers, key attestation: https://developer.android.com/privacy-and-security/security-key-attestation
[^android-cryptography-guide]: Android Developers, cryptography overview: https://developer.android.com/privacy-and-security/cryptography
[^android-hardcoded-secrets]: Android Developers, hardcoded cryptographic secrets risk guidance: https://developer.android.com/privacy-and-security/risks/hardcoded-cryptographic-secrets
[^android-workmanager]: Android Developers, WorkManager overview: https://developer.android.com/topic/libraries/architecture/workmanager
[^android-background-overview]: Android Developers, background tasks overview: https://developer.android.com/develop/background-work/background-tasks
[^android-ndk]: Android Developers, get started with the NDK: https://developer.android.com/ndk/guides
[^android-jni]: Android Developers, JNI tips: https://developer.android.com/training/articles/perf-jni

### Apple official sources

[^apple-networkextension]: Apple Developer, Network Extension overview: https://developer.apple.com/documentation/networkextension
[^apple-packet-provider]: Apple Developer, packet tunnel provider overview: https://developer.apple.com/documentation/networkextension/packet-tunnel-provider
[^apple-nepacketprovider]: Apple Developer, `NEPacketTunnelProvider`: https://developer.apple.com/documentation/networkextension/nepackettunnelprovider
[^apple-nepackettunnelflow]: Apple Developer, `NEPacketTunnelFlow`: https://developer.apple.com/documentation/networkextension/nepackettunnelflow
[^apple-readpackets]: Apple Developer, `readPackets(completionHandler:)`: https://developer.apple.com/documentation/networkextension/nepackettunnelflow/readpackets%28completionhandler%3A%29
[^apple-writepackets]: Apple Developer, `writePackets(_:withProtocols:)`: https://developer.apple.com/documentation/networkextension/nepackettunnelflow/writepackets%28_%3Awithprotocols%3A%29
[^apple-netunnelprovidermanager]: Apple Developer, `NETunnelProviderManager`: https://developer.apple.com/documentation/networkextension/netunnelprovidermanager
[^apple-routing]: Apple Developer, “Routing your VPN network traffic”: https://developer.apple.com/documentation/networkextension/routing-your-vpn-network-traffic
[^apple-tn3120]: Apple Developer, TN3120 “Expected use cases for Network Extension packet tunnel providers”: https://developer.apple.com/documentation/technotes/tn3120-expected-use-cases-for-network-extension-packet-tunnel-providers
[^apple-app-groups]: Apple Developer, Configuring App Groups: https://developer.apple.com/documentation/xcode/configuring-app-groups
[^apple-keychain-sharing]: Apple Developer, sharing access to keychain items among a collection of apps: https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps
[^apple-keychain-access-groups]: Apple Developer, keychain item access groups: https://developer.apple.com/documentation/security/keychain-services/keychain-items/sharing-access-to-keychain-items-among-a-collection-of-apps
[^apple-app-extension-safe]: Apple Developer, App Extension Programming Guide: https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html
[^apple-embed-frameworks]: Apple Developer, “Using an Embedded Framework to Share Code”: https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html
[^apple-cryptokit-curve25519]: Apple Developer, CryptoKit `Curve25519`: https://developer.apple.com/documentation/cryptokit/curve25519
[^apple-secureenclave]: Apple Developer, “Protecting keys with the Secure Enclave”: https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave
[^apple-xcframework]: Apple Developer, “Creating a multi-platform binary framework bundle”: https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle
[^apple-spm-binary]: Apple Developer, “Distributing binary frameworks as Swift packages”: https://developer.apple.com/documentation/xcode/distributing-binary-frameworks-as-swift-packages

### Rust and industry sources

[^rust-platform-support]: Rust documentation, platform support: https://doc.rust-lang.org/rustc/platform-support.html
[^rust-android-targets]: Rust documentation, Android targets: https://doc.rust-lang.org/rustc/platform-support/android.html
[^uniffi-swift-kotlin]: UniFFI user guide, Kotlin and Swift bindings: https://mozilla.github.io/uniffi-rs/latest/
[^wireguard-protocol]: WireGuard protocol and cryptography overview: https://www.wireguard.com/protocol/
[^wireguard-verification]: WireGuard formal verification page: https://www.wireguard.com/formal-verification/
[^owasp-masvs]: OWASP Mobile Application Security Verification Standard (MASVS): https://mas.owasp.org/MASVS/
[^owasp-mastg]: OWASP Mobile Application Security Testing Guide (MASTG): https://mas.owasp.org/MASTG/
