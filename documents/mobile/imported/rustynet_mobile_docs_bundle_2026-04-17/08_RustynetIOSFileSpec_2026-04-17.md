# Rustynet iOS File Specification

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetIOSFileSpec_2026-04-17.md`  
**Status:** Proposed iOS file-by-file implementation plan  
**Audience:** iOS engineers, Rust engineers, security reviewers

---

## 1. Purpose

This document describes the important iOS-side files and targets that should exist for Rustynet mobile, what each file should do, what functions it should own, and what security rules apply to it.

It assumes the iOS product is built as:

- a **container app** for UI, preferences, and enrollment,
- a **Packet Tunnel Provider extension** for the live VPN runtime,
- a **shared Rust engine** for trust, connection, routing, DNS planning, and packet logic.

---

## 2. Recommended iOS project layout

```text
mobile/ios/
  RustynetMobile.xcodeproj/

  RustynetMobile/
    App/
      RustynetMobileApp.swift
      ContentView.swift
    Features/
      Enrollment/
        EnrollmentViewModel.swift
      Tunnel/
        TunnelViewModel.swift
      Settings/
        SettingsViewModel.swift
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
      TunnelStatus.swift
      TunnelPlan.swift
      DiagnosticsSnapshot.swift
    IPC/
      AppGroupStateStore.swift
    Diagnostics/
      RedactionPolicy.swift

  Scripts/
    build_rust_apple.sh
    package_xcframework.sh
```

---

## 3. Why the iOS split matters

Apple’s Network Extension model is not just “an app with background networking.” The app and the Packet Tunnel Provider extension have different roles and lifecycle rules.

That means the repository should make the split obvious:

- the **container app** owns UI and preferences,
- the **extension** owns active packet tunnel runtime,
- the **shared Rust core** owns connection logic,
- **shared secret custody** must use the right Apple mechanisms, not ad hoc file sharing.

---

## 4. Xcode project and build scripts

### 4.1 `mobile/ios/RustynetMobile.xcodeproj/`

#### Purpose

Own the app target, packet tunnel extension target, signing settings, capabilities, and build graph.

#### Requirements

- container app and extension must have distinct targets,
- entitlements must be explicit and reviewed,
- any shared embedded framework usage must remain extension-safe.

### 4.2 `mobile/ios/Scripts/build_rust_apple.sh`

#### Purpose

Build the Rust FFI artifact for Apple targets.

#### Responsibilities

- build for device and simulator targets,
- produce deterministic artifacts for Xcode consumption,
- keep the Rust build invocation visible and reviewable.

### 4.3 `mobile/ios/Scripts/package_xcframework.sh`

#### Purpose

Package the Rust artifact as an XCFramework if that is the chosen distribution shape.

#### Security notes

- do not hide symbol-stripping or release-vs-debug behavior in undocumented shell logic,
- ensure the archive process is reproducible and easy to inspect in CI.

---

## 5. Container app files

### 5.1 `RustynetMobile/App/RustynetMobileApp.swift`

#### Purpose

Entry point for the iOS container app.

#### Responsibilities

- initialize app-wide dependencies,
- create `TunnelManager`, `IOSSecretStore`, and view models,
- avoid packet-tunnel logic in the app target.

#### Must not do

- own the active tunnel runtime,
- directly process packets,
- hold raw long-lived private keys in process-global objects.

### 5.2 `RustynetMobile/App/ContentView.swift`

#### Purpose

Top-level shell view for the app.

#### Responsibilities

- route to enrollment, status, and settings views,
- show state from view models,
- keep the UI state separate from tunnel logic.

### 5.3 `Features/Enrollment/EnrollmentViewModel.swift`

#### Purpose

Own user enrollment UX state.

#### Responsibilities

- accept scanned or entered enrollment data,
- call the Rust bridge or `TunnelManager` for enrollment flow steps,
- surface success/failure to the UI.

#### Functions

- `submitEnrollment(_ request: EnrollmentRequest)`
- `cancelEnrollment()`
- `refreshProvisioningState()`

#### Security notes

- if an enrollment token is present, keep it short-lived,
- do not log or persist enrollment tokens casually,
- do not leave secret-bearing state in SwiftUI previews or debug helpers.

### 5.4 `Features/Tunnel/TunnelViewModel.swift`

#### Purpose

Present tunnel status, connect/disconnect actions, and redacted diagnostics.

#### Responsibilities

- call `TunnelManager.startTunnel()` / `stopTunnel()`
- observe state published by the tunnel manager or App Group state store,
- never implement real connection logic itself.

### 5.5 `Features/Settings/SettingsViewModel.swift`

#### Purpose

Own user-safe settings and feature flags approved for release.

#### Security notes

- no switch should bypass signature verification or secure storage,
- debug-only settings must not be available in production builds.

---

## 6. Tunnel manager files in the container app

### 6.1 `Tunnel/TunnelManager.swift`

#### Purpose

Primary iOS-side controller for managing packet tunnel preferences and start/stop requests.

#### Responsibilities

- load and save `NETunnelProviderManager` preferences,
- create or update provider configuration,
- request tunnel start/stop,
- observe tunnel status for the UI,
- coordinate with App Group shared state as needed.

#### Functions

- `loadManager()`
- `savePreferences()`
- `startTunnel()`
- `stopTunnel()`
- `reloadStatus()`

#### Security notes

- this file should treat provider configuration as integrity-sensitive,
- it should not become a second secret store,
- only approved configuration should flow into `NETunnelProviderManager`.

### 6.2 `Tunnel/PreferencesStore.swift`

#### Purpose

Persist non-secret user preferences.

#### Examples

- selected diagnostics level,
- chosen UX defaults,
- whether auto-connect is enabled if the product supports it.

#### Security notes

- do not store transport keys or sensitive control-plane credentials here,
- if settings can affect trust or path behavior, validate them strictly.

---

## 7. Security files in the container app

### 7.1 `Security/IOSSecretStore.swift`

#### Purpose

Primary owner of long-lived secret custody on iOS.

This file should be the single policy owner for:

- transport private key storage in Keychain,
- session credential storage in Keychain,
- access-group-based sharing with the packet tunnel extension,
- keychain accessibility class decisions.

#### Responsibilities

- `storeTransportKey(...)`
- `loadTransportKey()`
- `deleteTransportKey()`
- `storeSessionCredential(...)`
- `loadSessionCredential()`
- `hasRequiredSecrets()`

#### Security-critical notes

- long-lived secrets belong in Keychain, not App Group files,
- the team must explicitly choose accessibility classes per secret type,
- `ThisDeviceOnly` should be the default for transport identity unless there is a carefully justified reason not to use it.

#### Hidden question this file must answer

Can the extension reconnect when the device is locked if the chosen accessibility class is highly restrictive?

That choice affects whether the app uses:

- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`, or
- a less restrictive but still device-local accessibility class such as after-first-unlock local-only access.

This must be decided intentionally and documented.

### 7.2 `Security/EnrollmentTokenStore.swift`

#### Purpose

Short-lived storage for enrollment-only material if enrollment cannot complete in one uninterrupted session.

#### Security notes

- prefer memory-only handling when possible,
- delete enrollment-only material immediately once provisioning succeeds,
- do not let this become a second general secret store.

---

## 8. Diagnostics files in the container app

### 8.1 `Diagnostics/RedactingLogger.swift`

#### Purpose

Single logging abstraction for the app target.

#### Responsibilities

- centralize logging,
- require explicit privacy choices for interpolated values,
- keep sensitive information out of the unified logging system.

#### Functions

- `debug(_ message: StaticString, ...)`
- `info(...)`
- `warn(...)`
- `error(...)`
- `redact(_ value: Any) -> String`

#### Security notes

- use privacy/redaction features where appropriate,
- prefer omission over “clever masking” for secrets.

### 8.2 `Diagnostics/SupportBundleBuilder.swift`

#### Purpose

Generate a user-exportable support bundle from redacted diagnostics.

#### Responsibilities

- collect redacted diagnostics from Rust,
- collect app version / OS version / status metadata,
- exclude Keychain material, App Group secrets, and raw packet traces.

---

## 9. FFI files in the container app

### 9.1 `FFI/RustynetFFI.h`

#### Purpose

C-ABI declarations exposed to Swift / ObjC.

#### Responsibilities

- declare handle types,
- declare exported Rust functions,
- define owned-buffer and free-function signatures,
- keep the ABI surface narrow.

### 9.2 `FFI/RustynetFFI.swift`

#### Purpose

Safe Swift wrapper over the C ABI.

#### Responsibilities

- expose Swift-friendly calls,
- translate error codes to Swift results,
- free Rust-owned buffers correctly,
- avoid spreading raw C calls across app and extension code.

#### Functions

- `createEngine()`
- `freeEngine()`
- `beginEnrollment(...)`
- `startSession()`
- `stopSession(...)`
- `pollEvent()`
- `exportDiagnostics()`

#### Security notes

- do not return secret-bearing buffers to arbitrary UI code,
- keep secret crossings rare and explicit.

---

## 10. Entitlements files in the container app

### 10.1 `Resources/RustynetMobile.entitlements`

#### Purpose

Declare capabilities used by the container app.

#### Expected capabilities

- App Groups
- Keychain sharing / access groups as needed
- Network Extension capability on the app side where required for configuration and management

#### Security notes

- keep entitlements minimal,
- review every entitlement like a privilege grant.

---

## 11. Packet tunnel extension files

### 11.1 `RustynetPacketTunnel/PacketTunnelProvider.swift`

#### Purpose

The most important iOS runtime file.

This class owns the active VPN runtime inside Apple’s Packet Tunnel Provider model.

#### Responsibilities

- implement `startTunnel(...)` and `stopTunnel(...)`,
- load required secure state via Keychain access group policy,
- initialize or attach to the Rust engine,
- apply `NEPacketTunnelNetworkSettings`,
- read packets from `packetFlow`,
- hand packet bytes to Rust,
- write Rust-emitted clear packets back to `packetFlow`,
- handle sleep/wake/lifecycle events if needed by the final design.

#### Functions

- `startTunnel(options:completionHandler:)`
- `stopTunnel(with:completionHandler:)`
- `handleAppMessage(_:completionHandler:)`
- `applyTunnelSettings(_ plan: TunnelPlan)`
- `startPacketReadLoop()`
- `deliverInboundDatagramToRust(...)`
- `writeClearPacketsFromRust(...)`

#### Security-critical notes

- this target must remain extension-safe,
- it must not rely on the container app being alive,
- it must not read raw secrets from App Group files,
- verification failures must fail closed,
- it must avoid verbose logs because extension logs are still part of the platform logging system.

### 11.2 `RustynetPacketTunnel/PacketFlowBridge.swift`

#### Purpose

Small adapter layer between `NEPacketTunnelFlow` and the Rust engine.

#### Responsibilities

- convert packet arrays from `packetFlow` into Rust input calls,
- accept Rust-emitted clear packets and write them with the right protocol metadata,
- keep packet buffer ownership obvious.

#### Security notes

- do not perform protocol logic here,
- do not keep packet history buffers longer than necessary.

### 11.3 `RustynetPacketTunnel/PathObserver.swift`

#### Purpose

Track path or network changes visible to the extension and inform Rust.

#### Responsibilities

- surface path changes to the Rust engine,
- help trigger roam/reconnect decisions.

### 11.4 `RustynetPacketTunnel/ExtensionStateStore.swift`

#### Purpose

Persist only the minimum extension-local non-secret state needed for restart-safe behavior.

#### Security notes

- not a secret store,
- not the home for transport private key material.

### 11.5 `RustynetPacketTunnel/RustynetPacketTunnel.entitlements`

#### Purpose

Declare extension-side capabilities.

#### Expected capabilities

- Network Extension packet tunnel entitlement
- App Groups if shared non-secret state is required
- Keychain access group / sharing settings required for secret access

#### Security notes

- extension entitlements must be kept minimal and aligned with the container app’s signed capabilities,
- do not add unrelated network entitlements “just in case.”

---

## 12. Shared files used by both app and extension

### 12.1 `Shared/Models/TunnelStatus.swift`

#### Purpose

Simple state model shared by app and extension-safe code.

Examples:

- `.unprovisioned`
- `.connecting`
- `.connected`
- `.error(redactedCode)`
- `.revoked`

### 12.2 `Shared/Models/TunnelPlan.swift`

#### Purpose

Swift-side representation of an already-verified tunnel plan emitted by Rust.

#### Security notes

- this should not contain raw secrets,
- it should contain only the data needed to apply OS tunnel settings.

### 12.3 `Shared/Models/DiagnosticsSnapshot.swift`

#### Purpose

Redacted diagnostics model for support bundle generation and UI display.

### 12.4 `Shared/IPC/AppGroupStateStore.swift`

#### Purpose

Shared non-secret state store between the container app and packet tunnel extension.

#### Appropriate contents

- current connection status,
- last error code,
- redacted diagnostics summary,
- timestamp of last successful connect.

#### Must never contain

- transport private key,
- raw session credential,
- enrollment token,
- decrypted trust secrets.

### 12.5 `Shared/Diagnostics/RedactionPolicy.swift`

#### Purpose

Central redaction rules used by both app and extension.

#### Responsibilities

- define which fields are always omitted,
- define which fields may be hashed / shortened for support use,
- avoid divergence between app and extension logging behavior.

---

## 13. iOS-specific pitfalls to avoid

### 13.1 Storing secrets in App Group files

App Groups are for shared containers and IPC, not a substitute for Keychain custody of long-lived private keys.

### 13.2 Assuming Secure Enclave can directly hold WireGuard transport keys

Apple documents Secure Enclave restrictions around supported key types and creation behavior. Do not assume you can import or use arbitrary existing Curve25519 transport key material there.

### 13.3 Forgetting extension-safe API rules

Apple explicitly warns that app extensions must use extension-safe APIs and build settings. Shared code that is fine in the container app may be invalid for the extension.

### 13.4 Designing the extension as dependent on the UI app process

The packet tunnel extension must be able to operate correctly when the container app is not active.

### 13.5 Choosing the wrong Keychain accessibility class by accident

A too-restrictive class may break background reconnect behavior. A too-permissive class may weaken device-local secret protection. This must be a documented decision, not an implementation accident.

---

## 14. File ownership summary by concern

| Concern | Primary iOS file |
|---|---|
| UI entry and navigation | `RustynetMobileApp.swift` / `ContentView.swift` |
| Enrollment UX | `EnrollmentViewModel.swift` |
| Tunnel preference management | `TunnelManager.swift` |
| Long-lived secret custody | `IOSSecretStore.swift` |
| Active VPN runtime | `PacketTunnelProvider.swift` |
| Packet flow bridging | `PacketFlowBridge.swift` |
| Shared non-secret state | `AppGroupStateStore.swift` |
| Rust bridge | `RustynetFFI.swift` / `RustynetFFI.h` |
| Logging and redaction | `RedactingLogger.swift` / `RedactionPolicy.swift` |

---

## 15. Bottom line

The iOS file layout should make four facts impossible to miss:

1. the **container app** is not the active tunnel runtime,
2. the **packet tunnel extension** is not the home for ad hoc app logic,
3. the **Keychain** is the home for long-lived secret custody,
4. the **Rust engine** remains the owner of trust and connection behavior.

If those facts stay obvious in the repository, the iOS app will be much easier to implement and review correctly.

---

## Sources

### Apple official documentation

- Network Extension overview: `https://developer.apple.com/documentation/networkextension`
- Packet tunnel provider overview: `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- `NEPacketTunnelProvider`: `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- `NETunnelProviderManager`: `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- TN3134 Network Extension provider deployment: `https://developer.apple.com/documentation/technotes/tn3134-network-extension-provider-deployment`
- Configuring network extensions: `https://developers.apple.com/documentation/xcode/configuring-network-extensions`
- App Groups: `https://developer.apple.com/documentation/xcode/configuring-app-groups`
- App Groups entitlement: `https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.security.application-groups`
- Keychain services: `https://developer.apple.com/documentation/security/keychain-services`
- Sharing keychain items among apps: `https://developer.apple.com/documentation/security/sharing-access-to-keychain-items-among-a-collection-of-apps`
- Restricting keychain item accessibility: `https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility`
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: `https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly`
- App Extension Programming Guide: `https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html`
- Secure Enclave key restrictions: `https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave`
- OSLog privacy: `https://developer.apple.com/documentation/os/oslogprivacy`

### Rust and WireGuard references

- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`
- Rust linkage: `https://doc.rust-lang.org/reference/linkage.html`
- WireGuard official overview: `https://www.wireguard.com/`
- WireGuard Apple official project: `https://git.zx2c4.com/wireguard-apple/`

### Security references

- OWASP MASVS: `https://mas.owasp.org/MASVS/`
- Apple Platform Security guide entry on keychain data protection: `https://support.apple.com/en-gb/guide/security/secb0694df1a/web`
