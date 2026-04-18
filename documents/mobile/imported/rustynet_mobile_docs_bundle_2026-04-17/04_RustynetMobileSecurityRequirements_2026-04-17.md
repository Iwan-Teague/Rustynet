# Rustynet Mobile Security Requirements

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetMobileSecurityRequirements_2026-04-17.md`  
**Status:** Proposed security requirements and guardrails  
**Audience:** Rust engineers, mobile engineers, security reviewers, release engineers

---

## 1. Purpose

This document defines the security requirements that should be treated as binding for Android and iOS mobile work.

It is intentionally stricter than a typical feature spec. The mobile app is not just another front end. It will hold device identity, transport secrets, signed configuration, and potentially privileged control-plane access. That means a large part of the security posture is determined **before** the first production feature is finished.

This document answers the questions that normally show up too late:

- Where may a transport private key exist?
- Where must it never exist?
- What data can be logged?
- What data must never be logged?
- What memory patterns are acceptable for secret material?
- Which files own secret storage?
- How should backup, restore, extension sharing, and FFI affect the design?
- What roles or keys should be forbidden on mobile v1?

---

## 2. Security baseline

The mobile design should meet four simultaneous goals:

1. **Keep Rust as the high-assurance implementation core.**
2. **Use platform security services instead of inventing replacements.**
3. **Minimize the time, scope, and number of places where raw secrets exist in memory.**
4. **Make security review easy by keeping dangerous code narrow and obvious.**

The relevant external baselines are:

- Android VPN and Keystore guidance,
- Apple Network Extension, Keychain, and App Group rules,
- official Rust FFI and linkage guidance,
- WireGuard cryptographic requirements,
- OWASP MASVS / MASTG mobile security baselines.

---

## 3. Non-negotiable security invariants

These should be treated as architecture rules, not optional hardening ideas.

### 3.1 No raw long-lived transport secret in normal app files

The mobile transport private key must not be stored in:

- Android `SharedPreferences`,
- Android app-internal files in plaintext,
- iOS App Group shared files,
- iOS `UserDefaults`,
- imported JSON config files left on disk,
- debug exports, support bundles, screenshots, or logs.

### 3.2 No raw long-lived transport secret in non-redacted logs

Private keys, enrollment tokens, session tokens, signed membership blobs that embed secret material, peer auth material, and raw packet contents must never be emitted to logs.

### 3.3 No owner / admin signing authority on mobile v1

Mobile v1 should not store high-value operator signing material that can mutate the network’s authoritative control state. Phones are easier to lose, steal, coerce, and instrument than tightly managed administrative hosts.

This is one of the most important scope-control decisions in the whole mobile plan.

### 3.4 All secret-bearing Rust types must use explicit zeroization helpers

Rust does not automatically guarantee secure zeroization of arbitrary secret buffers. If a secret must exist in memory, the Rust side should hold it in explicit secret wrappers that zero memory on drop and avoid accidental formatting or cloning.

### 3.5 The FFI boundary must never be the “easy path” for secrets

The native wrappers should not become a casual side channel that moves secret values around as `String`, `NSString`, or convenience JSON.

### 3.6 Backup and restore behavior must be explicitly designed

If secret-bearing state is restorable when it should not be, the app can accidentally clone an identity or leak a transport key to a new device.

### 3.7 Packet transport sockets must not route back into the tunnel

On Android this means the tunnel socket must be protected from VPN routing before tunnel traffic starts. If not, the app can create a routing loop or self-capture its own transport path.

---

## 4. Secret classification

### 4.1 Tier 0: forbidden on mobile v1

These should not live on mobile devices at all in the first release:

- network-wide owner signing key,
- admin signing keys that can reassign peers or issue authoritative network changes,
- relay private keys used for shared infrastructure roles,
- exit-node server credentials,
- long-lived unattended automation credentials.

### 4.2 Tier 1: long-lived device secrets

These may exist on mobile, but only with strict custody:

- device transport private key,
- device enrollment key material if the enrollment design truly requires a device-local keypair,
- device-scoped refresh token or session credential,
- attestation keys or attest-related local state where platform services require them.

### 4.3 Tier 2: signed but non-secret trust state

These are sensitive but not secret in the same way:

- signed assignment bundles,
- peer public keys,
- route plans,
- DNS plans,
- membership metadata,
- tunnel status snapshots.

These still require integrity protection and careful logging, but they do not need the same custody model as a private key.

### 4.4 Tier 3: operational telemetry

This includes:

- last connect time,
- redacted error codes,
- backend capability labels,
- route/DNS application status,
- app version and build information.

This can be persisted more freely, but it still must be scrubbed of secrets and unnecessary personal data.

---

## 5. Where secrets should live at rest

### 5.1 Android

The most reliable mobile design is:

- create a Keystore-resident wrapping key,
- use that wrapping key to encrypt the raw WireGuard-style transport private key or other raw secret data,
- store only the wrapped ciphertext in app storage,
- prefer hardware-backed key protection when the device provides it,
- verify capabilities rather than assuming all devices provide the same hardware protection.

This approach avoids making false assumptions about direct platform support for every algorithm the app might use internally.

#### Files that should own this

- `mobile/android/app/src/main/java/com/rustynet/mobile/storage/AndroidSecretStore.kt`
- optionally a small Rust-facing storage adapter file in the FFI layer if reads/writes are brokered by native code

### 5.2 iOS

The transport private key and other long-lived mobile secrets should live in the **Keychain**, not in an App Group file.

Where the container app and packet tunnel extension both need access, use:

- Keychain access groups for shared secret access,
- App Groups only for non-secret shared state and small status snapshots.

#### Accessibility nuance that must be decided early

Apple’s accessibility classes matter here:

- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly` is highly restrictive and avoids sync/restore to a new device.
- But some tunnel behavior may need secret access while the device is in the background after first unlock.

That means the team must explicitly decide whether a given secret should use:

- **maximum local-only protection**, or
- **background availability after first unlock**.

This decision should be documented per secret type instead of hidden in implementation.

#### Files that should own this

- `mobile/ios/RustynetMobile/Security/IOSSecretStore.swift`
- `mobile/ios/RustynetPacketTunnel/PacketTunnelProvider.swift` only as a consumer, not as the long-term policy owner

---

## 6. Where secrets may exist in memory

### 6.1 Preferred rule

Secrets should spend almost all of their lifetime in one of two places only:

- the platform secure storage service (Keystore / Keychain), or
- a short-lived Rust secret wrapper in `rustynet-mobile-core`.

### 6.2 Memory-handling rules

#### In Rust

Use dedicated secret wrappers such as:

- fixed-size key newtypes for 32-byte key material,
- `Zeroize` / `ZeroizeOnDrop` wrappers,
- redaction-aware `Debug` / `Display` implementations that never print secret values,
- explicit helper functions that parse encoded key material into secret types exactly once.

#### In Kotlin / Java

Avoid long-lived secret values in `String` because Java strings are immutable. Use `ByteArray` for transient binary values, clear buffers when the app controls them, and push the long-lived secret into Keystore custody or back into Rust as quickly as possible.

#### In Swift

Avoid turning secret binary material into UI-facing strings unless the UX absolutely requires it. Prefer binary buffers (`Data` or dedicated wrappers) only for short-lived handoff paths, and overwrite temporary mutable buffers when the code owns them. The long-lived authoritative copy should live in Keychain or Rust secret wrappers, not in view models.

### 6.3 What mobile cannot promise

Even with zeroization, mobile apps should not pretend that secret data can never exist in RAM. The goal is narrower and realistic:

- reduce lifetime,
- reduce copying,
- reduce surface area,
- reduce accidental persistence,
- make forensic recovery meaningfully harder,
- keep high-value secrets out of easier-to-extract locations.

---

## 7. Secrets lifecycle table

| Secret / material | Mobile v1 allowed? | At-rest owner | In-memory owner | Notes |
|---|---:|---|---|---|
| Device transport private key | Yes | Keystore-wrapped ciphertext (Android) / Keychain item (iOS) | Rust secret wrapper during active use | Never in logs or app files |
| Enrollment token | Yes, short-lived | Secure storage if it must survive restarts; otherwise memory only | Rust or native setup flow briefly | Delete after enrollment if possible |
| Session / refresh token | Yes | Platform secure storage | Rust or native auth layer briefly | Rotate and revoke server-side |
| Signed assignment bundle | Yes | Encrypted app state if needed | Rust parsed state | Treat as integrity-sensitive |
| Peer public keys | Yes | App state | Rust runtime | Public, but still avoid noisy logs |
| Owner/admin signing key | No | N/A | N/A | Keep off mobile v1 |
| Support bundle redaction rules | Yes | App resources / code | Rust/native helpers | Non-secret |

---

## 8. Logging requirements

### 8.1 Android

Android guidance explicitly warns against leaking sensitive data to logcat. Production logging must be sanitized, and sensitive values must be omitted rather than “masked later.”

#### Rules

- No tokens, private keys, signed secret blobs, endpoint auth material, or packet bodies in logs.
- No raw exception messages from secure storage or FFI errors if they may include secrets.
- Release builds should strip or sharply reduce debug logs.
- Use one redacting logger abstraction instead of direct scattered `Log.d` / `Log.e` usage.

#### File ownership

- `mobile/android/app/src/main/java/com/rustynet/mobile/diag/RedactingLogger.kt`

### 8.2 iOS

Apple’s unified logging system supports privacy controls, but that is not permission to log sensitive values. Use privacy annotations where a value truly must appear in a structured log statement, and prefer omission for secret-bearing fields.

#### Rules

- Never log private keys, tokens, raw configuration payloads, or packet content.
- Prefer static messages plus redacted identifiers.
- Use `.sensitive` / privacy redaction for interpolated values that are allowed but still sensitive.

#### File ownership

- `mobile/ios/RustynetMobile/Diagnostics/RedactingLogger.swift`
- `mobile/ios/Shared/Diagnostics/RedactionPolicy.swift`

---

## 9. Backup, restore, sync, and device migration rules

### 9.1 Android

Android Auto Backup can back up app data unless it is explicitly disabled or controlled.

For Rustynet mobile:

- the app must explicitly set a backup policy,
- secret-bearing files should be excluded from backup,
- transport identity must not silently clone to a new device through backup/restore,
- if the product ever supports backup of non-secret configuration, that split must be explicit.

### 9.2 iOS

Keychain item accessibility decisions control whether items are eligible for device migration or iCloud keychain behavior.

For Rustynet mobile:

- transport identity should default to a `ThisDeviceOnly` class unless there is a very strong product reason otherwise,
- App Group shared files must not be used as a workaround for keychain restrictions,
- extension sharing should use keychain access groups for secrets and App Groups for non-secret state.

---

## 10. Control-plane and trust requirements

### 10.1 Reuse Rustynet trust semantics, do not invent a mobile trust shortcut

The mobile app should use the same signed-assignment / signed-membership trust model Rustynet already uses. Mobile must not create a weaker “temporary mobile mode” that bypasses authoritative signatures or reduces verification.

### 10.2 TLS and pinning decisions must be explicit

If the control plane uses TLS, the team must explicitly decide whether:

- system trust roots are enough,
- a pinned certificate or SPKI policy is required,
- mTLS or device-bound authentication is required for enrollment or sensitive control actions.

This should be a design decision, not a future TODO buried in HTTP client code.

### 10.3 Optional hardening: app and device attestation

For higher-assurance environments, enrollment and privileged control-plane calls can optionally require:

- Android Play Integrity validation,
- Apple App Attest / DeviceCheck validation.

These should be treated as **supplementary hardening**. They do not replace Rustynet’s own cryptographic identity or signed-state verification.

---

## 11. FFI security requirements

### 11.1 Unsafe-code containment

The current workspace forbids unsafe code globally. A mobile FFI crate will almost certainly need a small, reviewable unsafe surface.

The recommended rule is:

- keep `rustynet-mobile-core` and the domain crates safe Rust only,
- confine unavoidable unsafe to `rustynet-mobile-ffi`,
- document every unsafe block with a safety contract,
- require line-by-line review for FFI changes.

### 11.2 No secret-rich JSON convenience interfaces

The FFI layer should not accept or return giant convenience payloads that casually include secrets. Keep secret transfer narrow and explicit.

### 11.3 No panic across the boundary

Rust panics must never unwind across foreign-language boundaries. The FFI layer should catch and convert panics into structured error results.

### 11.4 Explicit memory ownership

Every exported FFI function should document:

- who allocates,
- who frees,
- whether Rust copies input,
- whether the native side may retain a pointer,
- whether the returned buffer can contain sensitive data.

---

## 12. Platform-specific network security requirements

### 12.1 Android

- Call `VpnService.prepare()` before tunnel activation.
- Protect the tunnel socket with `VpnService.protect()` before routing traffic through the VPN.
- Use `VpnService.Builder` to establish the TUN interface only after the upstream socket is safely outside the VPN.
- Keep underlying network changes visible to the VPN service if multiple upstream networks are used.

### 12.2 iOS

- Use a Packet Tunnel Provider for the custom packet tunnel path.
- Keep packet-flow logic inside `NEPacketTunnelProvider` and `NEPacketTunnelFlow` usage, not ad hoc background tasks.
- Respect extension-safe API rules for any shared frameworks or code reused by the extension.
- Keep shared secret custody in Keychain access groups, not only in App Group files.

---

## 13. Release and review gates that should exist before launch

### 13.1 Static / build-time gates

- `cargo fmt`, `cargo clippy`, and workspace test gates
- `cargo audit` / dependency vulnerability review
- `cargo deny` or equivalent policy for licenses / duplicate unsafe dependencies
- explicit review for any crate that contains unsafe code
- release-build checks that strip debug logging and test-only flags

### 13.2 Mobile security test gates

- secret-in-logs checks
- backup / restore secret-leak checks
- storage inspection checks on rooted / jailbroken test devices or equivalent labs
- FFI panic-containment tests
- extension/container cross-access checks on iOS
- tunnel socket recursion regression tests on Android
- signed-assignment tamper tests

### 13.3 Threat-model gate

Before public beta, the project should have a mobile-specific threat model that covers:

- device theft,
- malware on device,
- backup / restore cloning,
- rooted / jailbroken devices,
- network-path interception,
- tampered app binaries,
- extension/container secret sharing,
- support-bundle and telemetry leakage.

---

## 14. Anti-patterns that should be called out by name

These should be treated as design failures:

- storing the transport private key in `SharedPreferences`, `UserDefaults`, or App Group files,
- using plaintext JSON import/export as the normal key path,
- leaving enrollment tokens on disk indefinitely,
- logging full config payloads on connect failure,
- keeping secret-bearing values in UI view models longer than necessary,
- copying keys through `String` for convenience when a binary path exists,
- putting packet processing or crypto policy in Kotlin/Swift “just for speed of implementation,”
- allowing panics or unchecked pointer lifetimes in the FFI layer,
- placing admin signing authority on phones in v1.

---

## 15. Bottom line

The security posture of Rustynet mobile will not be determined by one crypto library choice. It will be determined by dozens of file-level custody decisions:

- where secrets are stored,
- where they are copied,
- where they are logged,
- which layers are allowed to see them,
- how the FFI seam is constrained,
- how much privilege is allowed onto the device in the first place.

If these rules are baked into the file layout and the review checklist from the start, the mobile implementation has a much better chance of staying aligned with Rustynet’s existing security bar.

---

## Sources

### Android official documentation

- Android Keystore system: `https://developer.android.com/privacy-and-security/keystore`
- Key attestation: `https://developer.android.com/privacy-and-security/security-key-attestation`
- VPN guide: `https://developer.android.com/develop/connectivity/vpn`
- `VpnService` API reference: `https://developer.android.com/reference/android/net/VpnService`
- Log info disclosure risk: `https://developer.android.com/privacy-and-security/risks/log-info-disclosure`
- Auto Backup: `https://developer.android.com/identity/data/autobackup`
- Play Integrity API: `https://developer.android.com/google/play/integrity`

### Apple official documentation

- Network Extension overview: `https://developer.apple.com/documentation/networkextension`
- Packet tunnel provider: `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- `NEPacketTunnelProvider`: `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Keychain services: `https://developer.apple.com/documentation/security/keychain-services`
- Restricting keychain accessibility: `https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility`
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`: `https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly`
- Accessing keychain items with Face ID or Touch ID: `https://developer.apple.com/documentation/LocalAuthentication/accessing-keychain-items-with-face-id-or-touch-id`
- Keychain data protection (Apple Platform Security): `https://support.apple.com/en-gb/guide/security/secb0694df1a/web`
- App Groups: `https://developer.apple.com/documentation/xcode/configuring-app-groups`
- App Attest / DeviceCheck: `https://developer.apple.com/documentation/devicecheck`
- Preparing to use App Attest: `https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service`
- Secure Enclave key restrictions: `https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave`
- OSLog privacy: `https://developer.apple.com/documentation/os/oslogprivacy`
- `.sensitive` privacy option: `https://developer.apple.com/documentation/os/oslogprivacy/sensitive`

### Rust and WireGuard references

- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`
- Rust linkage: `https://doc.rust-lang.org/reference/linkage.html`
- WireGuard cryptography / protocol: `https://www.wireguard.com/`
- WireGuard whitepaper: `https://www.wireguard.com/papers/wireguard.pdf`
- `zeroize` crate docs: `https://docs.rs/zeroize/latest/zeroize/`

### Mobile security standards

- OWASP MASVS: `https://mas.owasp.org/MASVS/`
- OWASP mobile project overview: `https://owasp.org/www-project-mobile-app-security/`
- OWASP backup guidance: `https://mas.owasp.org/MASTG/knowledge/android/MASVS-STORAGE/MASTG-KNOW-0050/`
- OWASP mobile application security cheat sheet: `https://cheatsheetseries.owasp.org/cheatsheets/Mobile_Application_Security_Cheat_Sheet.html`
