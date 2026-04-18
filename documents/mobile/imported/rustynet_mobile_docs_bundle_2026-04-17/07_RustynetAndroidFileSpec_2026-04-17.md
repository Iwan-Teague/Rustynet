# Rustynet Android File Specification

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetAndroidFileSpec_2026-04-17.md`  
**Status:** Proposed Android file-by-file implementation plan  
**Audience:** Android engineers, Rust engineers, security reviewers

---

## 1. Purpose

This document describes the important Android-side files that should exist for Rustynet mobile, what each file should do, what functions it should own, and what security rules apply to it.

It assumes the Android product is a **real VPN client app** built on `VpnService`, backed by a shared Rust core.

The design goal is simple:

- Kotlin should own Android platform behavior.
- Rust should own tunnel logic, trust logic, and connection logic.
- Security-sensitive data should stay out of UI files and out of ordinary app storage.

---

## 2. Recommended Android project layout

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
          app/
            App.kt
          ui/
            MainActivity.kt
            enrollment/EnrollmentViewModel.kt
            tunnel/TunnelViewModel.kt
            settings/SettingsViewModel.kt
          vpn/
            RustynetVpnController.kt
            RustynetVpnService.kt
            UnderlyingNetworkMonitor.kt
            TunnelNotificationController.kt
          storage/
            AndroidSecretStore.kt
            EncryptedStateStore.kt
          ffi/
            RustynetNative.kt
            NativeModels.kt
          diag/
            RedactingLogger.kt
            SupportBundleBuilder.kt
          tunnel/
            TunnelStateRepository.kt
            TunnelPlanMapper.kt
        cpp/
          CMakeLists.txt
          rustynet_bridge.cpp
```

---

## 3. Root build files

### 3.1 `mobile/android/settings.gradle.kts`

#### Purpose

- define the Android modules in the mobile app,
- keep build boundaries clear if the project later adds test or sample modules.

#### Requirements

- keep the project small at first: one `app` module is enough,
- do not add dynamic feature modules until the core tunnel path is stable.

### 3.2 `mobile/android/build.gradle.kts`

#### Purpose

- shared Android build configuration,
- plugin versions,
- repository definitions.

#### Requirements

- keep release and debug behavior explicit,
- centralize NDK/CMake config if a JNI shim is used,
- do not hide security-significant build flags in local scripts.

### 3.3 `mobile/android/app/build.gradle.kts`

#### Purpose

- Android app module configuration,
- package name, SDK versions, signing / release config,
- NDK / CMake integration,
- packaging of the Rust FFI artifact.

#### Key responsibilities

- package `librustynet_mobile_ffi.so` for supported ABIs,
- enable R8 / release shrinking as appropriate,
- keep debug-only features out of release,
- make sure native symbols / mapping files are archived for crash triage.

#### Security notes

- release builds must not depend on debug logging defaults,
- test-only features must be guarded at compile time, not just hidden in UI,
- signing config must not be committed insecurely.

---

## 4. Android manifest and app bootstrap

### 4.1 `mobile/android/app/src/main/AndroidManifest.xml`

#### Purpose

Declare the Android app components, permissions, and the `VpnService` entrypoint.

#### Must include

- VPN service declaration with `android.permission.BIND_VPN_SERVICE`
- `android.net.VpnService` intent filter for the service
- explicit backup policy (`android:allowBackup` or scoped backup rules)
- any foreground-service or notification declarations actually required by the final implementation

#### Service declaration shape

The Android VPN guide shows the expected manifest shape for a custom VPN service:

```xml
<service
    android:name=".vpn.RustynetVpnService"
    android:permission="android.permission.BIND_VPN_SERVICE">
    <intent-filter>
        <action android:name="android.net.VpnService" />
    </intent-filter>
</service>
```

#### Security notes

- do not leave backup behavior implicit,
- do not add broad unrelated permissions “just in case,”
- do not expose any service that should remain internal.

### 4.2 `mobile/android/app/src/main/java/com/rustynet/mobile/app/App.kt`

#### Purpose

App-wide initialization.

#### Responsibilities

- initialize a strict redacting logger,
- initialize non-secret app state repositories,
- initialize dependency graph objects for UI, storage, and VPN control,
- avoid doing secret fetches here unless absolutely necessary.

#### Must not do

- start the VPN automatically on process start,
- read raw transport keys into process-global memory,
- initialize debug telemetry that can see secret-bearing state.

---

## 5. UI-layer files

### 5.1 `ui/MainActivity.kt`

#### Purpose

Container activity for app navigation.

#### Responsibilities

- host the enrollment and tunnel-control UI,
- request VPN consent flow when the user initiates connect,
- observe state from `TunnelStateRepository` or view models,
- never own transport logic.

#### Functions

- `onCreate(...)`
- `requestVpnPreparationIfNeeded()`
- `handleVpnPermissionResult(...)`

#### Security notes

- should not hold raw long-lived secrets,
- should not directly call the JNI shim for packet logic,
- should not log config payloads or errors verbosely.

### 5.2 `ui/enrollment/EnrollmentViewModel.kt`

#### Purpose

Manage user-driven enrollment UX.

#### Responsibilities

- accept enrollment input from UI,
- validate local form shape,
- call into `RustynetNative` or a controller abstraction,
- update UI state for success/failure.

#### Functions

- `submitEnrollment(request)`
- `cancelEnrollment()`
- `observeEnrollmentState()`

#### Security notes

- if an enrollment token must exist in memory, keep it brief and do not log it,
- do not store enrollment input in ordinary saved-state bundles unless explicitly scrubbed.

### 5.3 `ui/tunnel/TunnelViewModel.kt`

#### Purpose

Expose connect/disconnect state and redacted diagnostics to the UI.

#### Responsibilities

- call `RustynetVpnController.connect()` / `disconnect()`
- subscribe to tunnel state updates,
- present route/DNS mode, peer status, last error, and diagnostic summary

#### Must not do

- implement connection logic,
- inspect raw secret storage,
- interpret signed state directly.

### 5.4 `ui/settings/SettingsViewModel.kt`

#### Purpose

Expose user-safe settings such as diagnostics level, notifications, or optional path preferences.

#### Security notes

- do not surface dangerous debug toggles in release builds,
- do not let the UI disable verification or signature checks.

---

## 6. VPN lifecycle files

### 6.1 `vpn/RustynetVpnController.kt`

#### Purpose

High-level Android app controller for tunnel lifecycle.

#### Responsibilities

- coordinate UI requests with `VpnService.prepare()`,
- start and stop `RustynetVpnService`,
- bridge view-model actions into service actions,
- centralize Android-specific tunnel start/stop policy.

#### Functions

- `prepareForConnect(activity)`
- `connect()`
- `disconnect()`
- `onVpnPermissionGranted()`
- `onVpnPermissionDenied()`

#### Security notes

- only one place in the app should decide whether connect is allowed,
- this is a good place to require that provisioning and secure storage are ready before start.

### 6.2 `vpn/RustynetVpnService.kt`

#### Purpose

The most important Android runtime file.

This class is the Android-side owner of:

- the `VpnService` lifecycle,
- the local TUN interface creation,
- protected upstream socket preparation,
- service recreation and revoke handling,
- communication between Android OS networking and the Rust engine.

#### Responsibilities

- call `protect()` on upstream sockets before tunnel activation,
- use `VpnService.Builder` to configure addresses, routes, DNS, MTU, and interface session name,
- keep the TUN interface alive while the session runs,
- pass TUN packets to Rust and apply Rust-emitted tunnel events,
- handle `onRevoke()` correctly,
- update foreground notification state if the final design uses it.

#### Functions

- `onStartCommand(...)`
- `onDestroy()`
- `onRevoke()`
- `establishTun(tunnelPlan)`
- `openProtectedTransportSocket(...)`
- `startRustSession()`
- `stopRustSession(reason)`
- `pumpTunToRust()`
- `pumpRustToTun()`
- `applyTunnelPlan(tunnelPlan)`
- `applyUnderlyingNetworks(networks)`

#### Security-critical notes

- The upstream socket must be protected before the VPN starts routing tunnel traffic.
- This file must not read raw long-lived private keys from ordinary app files.
- Verification failures from Rust must fail closed: do not keep stale connectivity with invalid state.
- If the service is recreated, it must rebuild from secure storage + persisted non-secret state, not from UI-layer assumptions.

### 6.3 `vpn/UnderlyingNetworkMonitor.kt`

#### Purpose

Track Wi-Fi / cellular / path changes and inform the VPN service and Rust engine.

#### Responsibilities

- register a `ConnectivityManager.NetworkCallback`,
- observe network availability / loss / changes,
- tell `RustynetVpnService` which underlying networks are active,
- surface path changes to the Rust engine.

#### Functions

- `start()`
- `stop()`
- `onAvailable(network)`
- `onLost(network)`
- `onCapabilitiesChanged(network, caps)`

#### Security notes

- do not infer trust from network type,
- do not log full network details unnecessarily.

### 6.4 `vpn/TunnelNotificationController.kt`

#### Purpose

Own user-facing VPN status notification behavior if the final Android implementation uses foreground-service behavior.

#### Responsibilities

- show connected / connecting / error status,
- keep notification text redacted and boring,
- avoid exposing peer names or endpoints unless explicitly approved.

---

## 7. Storage files

### 7.1 `storage/AndroidSecretStore.kt`

#### Purpose

Android-side secure secret storage owner.

This file should be the only normal app file allowed to:

- create or access a Keystore wrapping key,
- wrap or unwrap long-lived transport secret material,
- broker secret access between Android and Rust.

#### Responsibilities

- `getOrCreateWrappingKey()`
- `wrapSecret(secretBytes)`
- `unwrapSecret(ciphertext)`
- `deleteSecret(alias)`
- `hasRequiredSecretMaterial()`

#### Security notes

- do not store raw transport private key bytes directly in preferences or plaintext files,
- if ciphertext is stored on disk, keep that file separate from ordinary app settings,
- prefer hardware-backed protection when available, but detect capability rather than assuming it.

### 7.2 `storage/EncryptedStateStore.kt`

#### Purpose

Persist non-secret or low-secret state that needs durability, such as:

- redacted device config,
- signed assignment blobs,
- last known tunnel mode,
- diagnostics counters,
- versioned app state.

#### Security notes

- this is not the primary home for raw private keys,
- backup policy for this store must be reviewed explicitly.

---

## 8. Rust bridge files

### 8.1 `ffi/RustynetNative.kt`

#### Purpose

Safe Kotlin wrapper over the native/JNI bridge.

#### Responsibilities

- expose Kotlin-friendly methods for engine lifecycle and command submission,
- translate native error codes into Kotlin result types,
- ensure buffer-free routines are called correctly,
- keep direct JNI exposure away from UI files.

#### Functions

- `createEngine()`
- `freeEngine(handle)`
- `initialize(handle, config)`
- `beginEnrollment(handle, request)`
- `startSession(handle)`
- `stopSession(handle, reason)`
- `pushTunPacket(handle, packet)`
- `pushTransportDatagram(handle, datagram, endpoint)`
- `pollEvent(handle)`
- `exportDiagnostics(handle)`

#### Security notes

- do not accept giant convenience objects when narrow buffers are enough,
- redact error strings before surfacing to UI or logs.

### 8.2 `ffi/NativeModels.kt`

#### Purpose

Define Kotlin-side models for FFI events and errors.

#### Examples

- `NativeEvent.StateChanged`
- `NativeEvent.ApplyTunnelPlan`
- `NativeEvent.WritePacketToTun`
- `NativeEvent.SendTransportDatagram`
- `NativeEvent.SecretRequired`
- `NativeError.VerificationFailed`

#### Security notes

- no secret payload fields unless unavoidable,
- prefer opaque IDs or handles over raw key-bearing strings.

### 8.3 `cpp/rustynet_bridge.cpp`

#### Purpose

Tiny JNI shim between Kotlin and the Rust C ABI.

#### Responsibilities

- translate `jbyteArray`, `jstring`, and primitive types to C ABI values,
- copy inputs into Rust-owned buffers or pass pointers only for call duration,
- call Rust free routines for Rust-owned outputs where appropriate,
- never implement product logic.

#### Security notes

- this file must remain intentionally small,
- pointer validation and ownership comments should be explicit,
- no caching of secret-bearing JNI strings.

### 8.4 `cpp/CMakeLists.txt`

#### Purpose

Build the JNI shim and link against the Rust-generated native library.

---

## 9. Diagnostics files

### 9.1 `diag/RedactingLogger.kt`

#### Purpose

Central logging API for the Android app.

#### Responsibilities

- define safe log categories,
- sanitize values before log emission,
- no-op or strip sensitive debug logging in release.

#### Functions

- `debug(tag, msg)`
- `info(tag, msg)`
- `warn(tag, msg)`
- `error(tag, redactedMsg, throwable?)`
- `redact(value)`

### 9.2 `diag/SupportBundleBuilder.kt`

#### Purpose

Build a support bundle from redacted diagnostics only.

#### Responsibilities

- request redacted diag snapshot from Rust,
- add Android version / device model / app version metadata if approved,
- exclude secret storage, logs with secrets, and raw packet traces.

---

## 10. Tunnel state repository files

### 10.1 `tunnel/TunnelStateRepository.kt`

#### Purpose

Single source of truth for UI-observable tunnel state.

#### Responsibilities

- publish `Disconnected`, `Connecting`, `Connected`, `Error`, `Revoked`, etc.
- merge native lifecycle state with Rust engine state,
- keep the UI reactive without duplicating session logic.

### 10.2 `tunnel/TunnelPlanMapper.kt`

#### Purpose

Translate Rust-emitted tunnel-plan data into Android-applicable structures for `VpnService.Builder`.

#### Responsibilities

- convert addresses, routes, DNS servers, and interface parameters into native types,
- reject malformed or unsupported plans early.

#### Security notes

- treat verification-complete plan data as authoritative,
- do not “repair” invalid security-critical values with silent defaults.

---

## 11. File ownership summary by concern

| Concern | Primary Android file |
|---|---|
| User connect / disconnect UX | `RustynetVpnController.kt` |
| Android VPN service lifecycle | `RustynetVpnService.kt` |
| Path / network changes | `UnderlyingNetworkMonitor.kt` |
| Long-lived secret custody | `AndroidSecretStore.kt` |
| Shared Rust bridge | `RustynetNative.kt` + `rustynet_bridge.cpp` |
| Tunnel status for UI | `TunnelStateRepository.kt` |
| Logging and redaction | `RedactingLogger.kt` |
| Support bundle generation | `SupportBundleBuilder.kt` |

---

## 12. Android-specific pitfalls to avoid

### 12.1 Forgetting to protect the upstream socket

Android explicitly documents this as necessary to avoid routing the tunnel’s own traffic back into the VPN.

### 12.2 Putting transport logic in the service class

`RustynetVpnService.kt` should adapt Android OS behavior, not grow into a second connection engine.

### 12.3 Using `String` everywhere for secret material

Use binary buffers for transient paths and hand secrets to Rust or secure storage quickly.

### 12.4 Leaving backup behavior implicit

The app must explicitly decide what can be backed up and what cannot.

### 12.5 Logging full errors from native / Rust without redaction

Those errors can accidentally contain sensitive values or too much operational detail.

---

## 13. Bottom line

The Android file layout should make it impossible to confuse roles:

- `RustynetVpnService.kt` owns Android VPN behavior,
- `AndroidSecretStore.kt` owns Android secure secret custody,
- `RustynetNative.kt` and the JNI shim own the Rust bridge,
- UI files own only UI state,
- Rust owns the actual networking and trust logic.

That separation is what keeps the Android app maintainable and safe.

---

## Sources

### Android official documentation

- VPN guide: `https://developer.android.com/develop/connectivity/vpn`
- `VpnService` API reference: `https://developer.android.com/reference/android/net/VpnService`
- Android Keystore system: `https://developer.android.com/privacy-and-security/keystore`
- Log info disclosure risk: `https://developer.android.com/privacy-and-security/risks/log-info-disclosure`
- Auto Backup for Apps: `https://developer.android.com/identity/data/autobackup`
- Android NDK guides: `https://developer.android.com/ndk/guides`
- JNI tips: `https://developer.android.com/training/articles/perf-jni`
- Play Integrity API: `https://developer.android.com/google/play/integrity`
- Play `VpnService` policy overview: `https://support.google.com/googleplay/android-developer/answer/12564964`

### Rust and security references

- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`
- WireGuard official overview: `https://www.wireguard.com/`
- WireGuard Android official project: `https://git.zx2c4.com/wireguard-android/about/`
- OWASP MASVS: `https://mas.owasp.org/MASVS/`
