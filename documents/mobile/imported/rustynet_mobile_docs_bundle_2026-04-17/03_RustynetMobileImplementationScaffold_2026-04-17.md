# Rustynet Mobile Implementation Scaffold

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetMobileImplementationScaffold_2026-04-17.md`  
**Status:** Proposed lower-level implementation scaffold  
**Audience:** Rustynet maintainers, mobile engineers, Rust engineers, release engineers

---

## 1. Purpose

This document takes the mobile roadmap and architecture design one step lower.

It focuses on the concrete scaffold that a future implementation should create:

- new workspace crates,
- new Android and iOS project directories,
- the important files that should exist,
- the responsibility of each file or module,
- the major functions each layer should own,
- the existing Rustynet files that should change,
- the existing Rustynet files that should not be reused as mobile runtime surfaces.

This is not a line-by-line coding spec. It is a buildable repository and module plan.

---

## 2. Current repository facts that drive the scaffold

The current public workspace already contains the right *kind* of reusable Rust slices: control, crypto, DNS, policy, relay, backend API, and a backend WireGuard crate. The workspace root also currently sets `unsafe_code = "forbid"` in workspace lints, which is important because any mobile FFI layer will have to address that explicitly rather than quietly working around it.

The repository also does not currently contain Android application modules or iOS app / extension targets.

That makes the right first move clear:

- **preserve and reuse existing pure-Rust domain crates where possible,**
- **add mobile-specific Rust crates only where the current host runtime is not reusable,**
- **create native mobile shells beside the workspace, not inside `rustynetd`,**
- **do not treat `start.sh`, desktop bootstrap scripts, or VM-lab wrappers as the mobile runtime path.**

---

## 3. High-level scaffold recommendation

The repository should grow in three directions at once:

1. **Shared Rust mobile engine crates** for configuration, signed-state verification, connection orchestration, packet processing, diagnostics, and secure secret handling.
2. **Native platform projects** for Android and iOS packaging, UI, OS VPN APIs, lifecycle, secure storage adapters, and store deployment.
3. **A narrow FFI seam** between the shared Rust engine and the native shells.

---

## 4. Recommended repository structure

```text
Rustynet/
  Cargo.toml
  crates/
    rustynet-backend-api/
    rustynet-backend-wireguard/
    rustynet-control/
    rustynet-crypto/
    rustynet-dns-zone/
    rustynet-local-security/
    rustynet-policy/
    rustynet-relay/
    rustynet-cli/
    rustynetd/

    rustynet-mobile-core/
    rustynet-mobile-ffi/
    rustynet-backend-android/
    rustynet-backend-ios/
    rustynet-mobile-diag/

  mobile/
    android/
      app/
      gradle/
      build.gradle.kts
      settings.gradle.kts
      gradle.properties

    ios/
      RustynetMobile.xcodeproj/
      RustynetMobile/
      RustynetPacketTunnel/
      Shared/
      Scripts/

  documents/
    architecture/
      mobile/
        ... mobile docs ...
```

### 4.1 Why this structure

- The shared engine remains in the Rust workspace, where Rustynet’s real logic already lives.
- The mobile apps live under a dedicated `mobile/` directory because their build systems are native-platform specific.
- The split makes it obvious which code is reusable Rust logic and which code is packaging / platform glue.

---

## 5. New Rust crates that should exist

### 5.1 `crates/rustynet-mobile-core/`

This should be the main shared mobile engine crate.

#### Role

Own mobile-safe shared logic that is not tied to Android or iOS UI frameworks:

- enrollment orchestration,
- signed bundle verification,
- local device state machine,
- peer set management,
- route and DNS plan computation,
- transport session orchestration,
- tunnel lifecycle decisions,
- reconnection / roam logic,
- diagnostics snapshot generation,
- secret-type wrappers and zeroization helpers.

#### Internal file plan

```text
crates/rustynet-mobile-core/
  Cargo.toml
  src/
    lib.rs
    config.rs
    error.rs
    engine.rs
    enrollment.rs
    membership.rs
    assignment.rs
    session.rs
    peer_set.rs
    routes.rs
    dns.rs
    events.rs
    state.rs
    timers.rs
    path.rs
    secrets.rs
    zeroize_types.rs
    diag.rs
```

#### Core files and purpose

- `lib.rs`  
  Public crate exports and top-level feature gates.
- `config.rs`  
  Mobile config structs for local device configuration, transport preferences, DNS mode, split/full tunnel mode, and debug feature flags.
- `error.rs`  
  A mobile-engine-specific error model that cleanly crosses the FFI boundary.
- `engine.rs`  
  The central `MobileEngine` state machine.
- `enrollment.rs`  
  Enrollment/bootstrap flow orchestration against the existing Rustynet trust model.
- `membership.rs`  
  Local handling of mobile membership state and trust material.
- `assignment.rs`  
  Verification and application of signed configuration / assignment bundles.
- `session.rs`  
  Tunnel session lifecycle, handshake triggers, and steady-state connection bookkeeping.
- `peer_set.rs`  
  Active peer configuration and peer-update application logic.
- `routes.rs`  
  Route plan calculation for mesh, LAN, and exit-node flows.
- `dns.rs`  
  Managed DNS / Magic DNS mobile application logic and OS-facing DNS plan outputs.
- `events.rs`  
  Internal engine events and FFI-facing event payloads.
- `state.rs`  
  Persistable and non-persistable engine state representations.
- `timers.rs`  
  Reconnect backoff, keepalive scheduling, jitter windows, and timeout policy.
- `path.rs`  
  Network-path observations: Wi-Fi vs cellular, path changes, interface churn, metered hints.
- `secrets.rs`  
  Secret newtypes and parsing rules; no casual `String` or `Vec<u8>` use for long-lived secrets.
- `zeroize_types.rs`  
  `Zeroize` / `ZeroizeOnDrop` wrappers and helper constructors.
- `diag.rs`  
  Redacted diagnostic snapshots.

#### Important functions that should live here

- `MobileEngine::new(...)`
- `MobileEngine::begin_enrollment(...)`
- `MobileEngine::complete_enrollment(...)`
- `MobileEngine::load_persisted_state(...)`
- `MobileEngine::apply_signed_assignment(...)`
- `MobileEngine::build_tunnel_plan(...)`
- `MobileEngine::start_session(...)`
- `MobileEngine::stop_session(...)`
- `MobileEngine::on_network_path_changed(...)`
- `MobileEngine::on_peer_update(...)`
- `MobileEngine::export_redacted_diagnostics(...)`

### 5.2 `crates/rustynet-mobile-ffi/`

This should be the only Rust crate that directly exposes native-callable symbols.

#### Role

- expose a stable ABI to Android and iOS wrappers,
- translate native requests into `rustynet-mobile-core` operations,
- maintain opaque engine handles,
- convert Rust events and errors into FFI-safe forms,
- contain all unavoidable FFI-related unsafe code in one reviewable place.

A full design is in the separate FFI contract document.

### 5.3 `crates/rustynet-backend-android/`

#### Role

Provide Android-specific Rust-side abstractions for:

- packet I/O adaptation to Android TUN file descriptors,
- Android capability reporting,
- Android-specific route and DNS application metadata,
- platform constraint mapping back into `rustynet-mobile-core`.

This crate should **not** know about Android UI. It should only know about Android networking and tunnel constraints expressed as data and callbacks.

### 5.4 `crates/rustynet-backend-ios/`

#### Role

Provide iOS-specific Rust-side abstractions for:

- packet I/O adaptation to `NEPacketTunnelFlow` callback surfaces,
- iOS route / DNS capability reporting,
- iOS path, sleep, wake, and extension-lifecycle metadata,
- platform constraint mapping back into `rustynet-mobile-core`.

Like the Android backend crate, this is not where SwiftUI or UIKit logic belongs.

### 5.5 `crates/rustynet-mobile-diag/`

#### Role

A small shared crate for:

- redaction helpers,
- structured diagnostics schemas,
- support-bundle shaping,
- log-field filtering policy.

Keeping this separate makes it harder for ad hoc debug logic to creep into platform targets.

---

## 6. Existing workspace files that will need changes

### 6.1 Root `Cargo.toml`

It will need new workspace members for the mobile crates.

### 6.2 `crates/rustynet-backend-api/src/lib.rs`

The existing backend trait is a strong starting seam. It may need carefully reviewed additions for mobile capability reporting and event-driven packet/transport ownership, but the intent should remain the same: keep backend-specific behavior behind a narrow interface.

### 6.3 Documentation indexes

These should eventually be updated:

- `documents/README.md`
- `documents/operations/active/README.md` (only if mobile work becomes active execution)
- a new `documents/architecture/mobile/README.md` if the mobile doc set grows further

---

## 7. Existing files that should not be treated as mobile runtime surfaces

These remain important repository assets, but they should not become the mobile runtime model:

- `start.sh`
- `crates/rustynetd/...`
- `crates/rustynet-cli/...` as the primary mobile surface
- `scripts/bootstrap/...`
- `scripts/vm_lab/...`
- current systemd/service-manager oriented host paths

They may still be useful as sources of domain logic, validation rules, or test fixtures, but they should not be wrapped and shipped as a phone runtime.

---

## 8. Android project scaffold

```text
mobile/android/
  settings.gradle.kts
  build.gradle.kts
  gradle.properties
  app/
    build.gradle.kts
    proguard-rules.pro
    src/
      main/
        AndroidManifest.xml
        java/com/rustynet/mobile/
          MainActivity.kt
          app/App.kt
          ui/... 
          vpn/RustynetVpnService.kt
          vpn/RustynetVpnController.kt
          vpn/UnderlyingNetworkMonitor.kt
          storage/AndroidSecretStore.kt
          storage/EncryptedStateStore.kt
          ffi/RustynetNative.kt
          diag/RedactingLogger.kt
          tunnel/TunnelStateRepository.kt
          tunnel/TunnelNotificationController.kt
        cpp/
          CMakeLists.txt
          rustynet_bridge.cpp
```

### 8.1 Why a tiny `cpp/` directory is acceptable

A very small Android JNI shim is the cleanest way to keep Rust heavy while staying close to official Android NDK and JNI guidance. The rule should be that this shim is narrow, dumb, and security-reviewed; it does not contain product logic.

---

## 9. iOS project scaffold

```text
mobile/ios/
  RustynetMobile.xcodeproj/
  RustynetMobile/
    App/
      RustynetMobileApp.swift
      ContentView.swift
      EnrollmentViewModel.swift
      TunnelViewModel.swift
    Tunnel/
      TunnelManager.swift
      PreferencesStore.swift
    Security/
      IOSSecretStore.swift
      EnrollmentTokenStore.swift
    Diagnostics/
      RedactingLogger.swift
      SupportBundleBuilder.swift
    FFI/
      RustynetFFI.swift
      RustynetFFI.h
    Resources/
      RustynetMobile.entitlements

  RustynetPacketTunnel/
    PacketTunnelProvider.swift
    PacketFlowBridge.swift
    PathObserver.swift
    ExtensionStateStore.swift
    RustynetPacketTunnel.entitlements

  Shared/
    Models/
    IPC/
      AppGroupStateStore.swift
    Diagnostics/
      RedactionPolicy.swift

  Scripts/
    build_rust_apple.sh
    package_xcframework.sh
```

---

## 10. Ownership rules by layer

### 10.1 Rust owns

- protocol and packet logic,
- signed-state verification,
- peer and route computation,
- session state machine,
- reconnection logic,
- diagnostics shaping,
- secret-type wrappers and zeroization,
- policy and trust interpretation.

### 10.2 Kotlin owns

- Android UI,
- `VpnService` lifecycle,
- permission prompts,
- notifications,
- Android Keystore adapter,
- Android persistence adapter,
- network callbacks,
- JNI call sites.

### 10.3 Swift owns

- iOS UI,
- `NETunnelProviderManager` and app preference flows,
- `NEPacketTunnelProvider` lifecycle,
- Keychain adapter,
- App Group state sharing,
- extension-safe host integration,
- C/Swift bridge call sites.

---

## 11. File-level rules that should be binding from the start

- Secret-bearing logic must not live in UI-layer files.
- Packet processing must not live in Kotlin or Swift except for the minimum adapter code needed to bridge OS packet APIs to Rust.
- Native storage files may store encrypted state, IDs, and non-secret UX state, but not raw long-lived transport secrets in app files.
- Any file that touches FFI must have explicit memory ownership notes in comments.
- Any file that logs must route through a redacting logger abstraction, not direct ad hoc logging calls.

---

## 12. Build artifact plan

### 12.1 Android

Expected outputs:

- `librustynet_mobile_ffi.so` for each supported ABI,
- Android app APK / AAB,
- symbol files and mapping files for release builds,
- a small JNI bridge library if the Android side uses a C++ shim.

### 12.2 iOS

Expected outputs:

- Rust static library or packaged XCFramework,
- container app target,
- packet tunnel extension target,
- signed archive for TestFlight / App Store review.

---

## 13. What should be implemented first

The lowest-risk implementation order is:

1. add new docs and workspace placeholders,
2. add `rustynet-mobile-core` with pure Rust config/state models,
3. add `rustynet-mobile-ffi` with stub handles and panic containment,
4. build Android and iOS “hello tunnel shell” targets that start but do not yet pass live traffic,
5. add secret storage adapters,
6. add enrollment and signed-state verification,
7. add real packet/transport flow,
8. add reconnection and diagnostics,
9. add release gates and security review checks.

---

## 14. High-value pitfalls to avoid at scaffold time

### 14.1 Do not put mobile-only code into `rustynetd`

That would make the repository harder to reason about and blur host-runtime and phone-runtime responsibilities.

### 14.2 Do not let the FFI surface sprawl

Every extra FFI function increases review burden, panic handling risk, and memory-ownership ambiguity.

### 14.3 Do not use App Group files or Android preferences for raw private keys

Those are not the right custody surfaces for long-lived transport secrets.

### 14.4 Do not carry current shell automation assumptions into phones

Phones do not have systemd, unattended root shell flows, or the same startup semantics as host environments.

### 14.5 Do not assume that existing repo support for Linux/macOS host runtime tells you anything about mobile runtime viability

The mobile adaptation work is real product work, not packaging work.

---

## 15. Bottom line

The scaffold should make three things obvious in the repository:

1. **where the shared Rust engine lives,**
2. **where Android and iOS own platform-specific behavior,**
3. **where the security-critical boundaries are.**

If the repository layout makes those three things obvious, later implementation and review work becomes much easier.

---

## Sources

### Rustynet repository

- Workspace root: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/Cargo.toml`
- Repository README: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/README.md`
- Backend API crate: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/crates/rustynet-backend-api/src/lib.rs`
- Backend WireGuard crate: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/crates/rustynet-backend-wireguard/src/lib.rs`

### Official Rust documentation

- Cargo workspaces: `https://doc.rust-lang.org/cargo/reference/workspaces.html`
- Rust platform support: `https://doc.rust-lang.org/rustc/platform-support.html`
- Rust iOS targets: `https://doc.rust-lang.org/rustc/platform-support/apple-ios.html`
- Rust linkage / `staticlib` and `cdylib`: `https://doc.rust-lang.org/reference/linkage.html`
- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`

### Android official documentation

- VPN guide: `https://developer.android.com/develop/connectivity/vpn`
- `VpnService` API reference: `https://developer.android.com/reference/android/net/VpnService`
- Android NDK overview: `https://developer.android.com/ndk/guides`
- JNI guidance: `https://developer.android.com/training/articles/perf-jni`
- Android Keystore: `https://developer.android.com/privacy-and-security/keystore`

### Apple official documentation

- Network Extension overview: `https://developer.apple.com/documentation/networkextension`
- Packet tunnel provider: `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- `NEPacketTunnelProvider`: `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Configuring app groups: `https://developer.apple.com/documentation/xcode/configuring-app-groups`
- Keychain services: `https://developer.apple.com/documentation/security/keychain-services`
- App Extension Programming Guide: `https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html`

### WireGuard and security references

- WireGuard protocol: `https://www.wireguard.com/protocol/`
- WireGuard official repositories: `https://www.wireguard.com/repositories/`
- OWASP MASVS: `https://mas.owasp.org/MASVS/`
