# Rustynet Mobile FFI Contract

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetMobileFfiContract_2026-04-17.md`  
**Status:** Proposed FFI and ABI contract  
**Audience:** Rust engineers, Android engineers, iOS engineers, security reviewers

---

## 1. Why this document exists

The single easiest way to lose the benefits of a Rust-first mobile design is to let the native/Rust boundary become vague.

If the FFI layer is too large, unclear, or convenience-driven, several bad things happen at once:

- secret material gets copied into more languages than necessary,
- memory ownership becomes ambiguous,
- panic behavior becomes unsafe,
- platform-specific hacks leak into shared logic,
- Kotlin/Swift start becoming alternate implementations of core logic,
- the codebase becomes harder to review.

This document defines the intended contract so that the Rust/native seam stays narrow, explicit, and security-reviewable.

---

## 2. Design goals

The FFI contract should optimize for:

1. **Rust-heavy implementation**  
   Shared logic stays in Rust.
2. **Small native shims**  
   Kotlin and Swift remain platform wrappers, not protocol engines.
3. **Stable ownership**  
   Every call documents who owns memory and when buffers can be freed.
4. **Secret minimization**  
   Secret data should cross the FFI boundary as rarely as possible.
5. **Reviewable unsafe code**  
   Any unsafe Rust should be tightly contained and documented.
6. **Predictable errors**  
   No unwinding across FFI, no opaque crash-only failure modes.

---

## 3. Current repo constraint that matters most

Rustynet’s current workspace lints forbid unsafe code at the workspace level. A realistic FFI layer almost always needs a very small amount of unsafe code to:

- validate raw pointers,
- copy foreign buffers into owned Rust memory,
- manage opaque handles,
- export C-ABI entry points.

That means the project must make an explicit decision instead of drifting into accidental exceptions.

### 3.1 Recommended decision

- keep `rustynet-mobile-core` safe Rust only,
- keep existing domain crates safe Rust only,
- allow a tightly scoped, heavily documented exception in `rustynet-mobile-ffi`,
- require explicit code review for every unsafe block.

This is cleaner and safer than smearing unsafe logic across many crates.

---

## 4. Why use a C ABI as the lowest common layer

For a cross-platform mobile app, the most durable base contract is a small C ABI.

### 4.1 Why not make Kotlin or Swift call deep Rust internals directly

Because that would couple the mobile apps to Rust implementation details and make the boundary larger than necessary.

### 4.2 Why not depend the whole design on a higher-level binding generator

A higher-level binding tool may still be useful later, but the architecture should not require one to explain the trust boundary. A small C ABI is easy to reason about using official Rust, Android NDK, and Apple platform documentation.

### 4.3 Recommended platform adaptation

- **Android:** Kotlin -> JNI shim -> Rust C ABI
- **iOS:** Swift / ObjC shim -> Rust C ABI

The shims should remain minimal translators, not homes for business logic.

---

## 5. Crate and file layout

```text
crates/rustynet-mobile-ffi/
  Cargo.toml
  src/
    lib.rs
    api.rs
    engine_handle.rs
    error.rs
    buffer.rs
    event.rs
    panic_boundary.rs
    callbacks.rs
    android.rs
    apple.rs
```

### 5.1 File purposes

- `lib.rs`  
  crate exports and symbol visibility.
- `api.rs`  
  exported ABI functions.
- `engine_handle.rs`  
  opaque handle allocation and lifecycle.
- `error.rs`  
  FFI-safe error codes and last-error buffer helpers.
- `buffer.rs`  
  FFI-safe owned buffer representation and free routines.
- `event.rs`  
  event enums and serialization helpers.
- `panic_boundary.rs`  
  catch-unwind wrapper logic.
- `callbacks.rs`  
  native callback structs or registration helpers.
- `android.rs`  
  Android-specific FFI adapters if needed.
- `apple.rs`  
  Apple-specific FFI adapters if needed.

---

## 6. What the FFI layer should and should not do

### 6.1 It should do

- translate native calls into `rustynet-mobile-core` operations,
- convert Rust errors into stable numeric / string error results,
- manage opaque engine handles,
- move packet buffers between native code and the Rust engine,
- expose structured events for UI and lifecycle integration,
- keep panic behavior contained.

### 6.2 It should not do

- define product logic,
- parse OS-specific configuration files,
- talk directly to Android UI or SwiftUI view state,
- own long-lived secret storage policy,
- become a second business-logic layer,
- expose debug shortcuts that bypass verification or trust checks.

---

## 7. Recommended ABI model

### 7.1 Opaque engine handle

The native side should not hold a pointer to internal Rust structs directly. Instead, it should hold an opaque engine handle.

Suggested public concept:

- `RustynetMobileEngineHandle`

Rust owns the real engine object; the native side only stores a handle token.

### 7.2 Native-side interaction model

The simplest reviewable model is:

1. native creates an engine,
2. native submits commands and input buffers,
3. Rust emits events and output buffers,
4. native applies OS-specific side effects.

That keeps OS VPN APIs on the native side and shared logic on the Rust side.

### 7.3 Why an event-driven model is preferable

An event queue is easier to reason about than a large callback jungle.

Examples of Rust-emitted events:

- `StateChanged`
- `ApplyTunnelSettings`
- `WriteTunPacket`
- `SendTransportDatagram`
- `PersistWrappedSecret`
- `RequestWrappedSecret`
- `DiagnosticsAvailable`
- `ErrorRaised`

Examples of native-to-Rust inputs:

- `TunnelSettingsApplied`
- `TunPacketReceived`
- `TransportDatagramReceived`
- `WrappedSecretLoaded`
- `NetworkPathChanged`
- `VpnPermissionGranted`
- `ExtensionWoke` / `ServiceRecreated`

---

## 8. Suggested exported functions

The exact final ABI can change, but the first implementation should stay within a family like this.

### 8.1 Lifecycle

- `rustynet_mobile_engine_new(...) -> Handle`
- `rustynet_mobile_engine_free(handle)`
- `rustynet_mobile_engine_initialize(handle, config_json, config_len)`
- `rustynet_mobile_engine_shutdown(handle)`

### 8.2 Enrollment and trust state

- `rustynet_mobile_engine_begin_enrollment(handle, request_json, len)`
- `rustynet_mobile_engine_complete_enrollment(handle, response_json, len)`
- `rustynet_mobile_engine_apply_signed_assignment(handle, blob_ptr, blob_len)`
- `rustynet_mobile_engine_load_persisted_state(handle, blob_ptr, blob_len)`
- `rustynet_mobile_engine_export_persisted_state(handle) -> OwnedBuffer`

### 8.3 Session / tunnel control

- `rustynet_mobile_engine_start_session(handle)`
- `rustynet_mobile_engine_stop_session(handle, reason_code)`
- `rustynet_mobile_engine_on_network_path_changed(handle, path_json, len)`
- `rustynet_mobile_engine_on_visibility_changed(handle, visible)`

### 8.4 Packet / transport I/O

- `rustynet_mobile_engine_push_tun_packet(handle, packet_ptr, packet_len, family)`
- `rustynet_mobile_engine_push_transport_datagram(handle, buf_ptr, buf_len, addr_json, addr_len)`
- `rustynet_mobile_engine_poll_event(handle) -> Event`
- `rustynet_mobile_engine_take_buffer(handle, buffer_id) -> OwnedBuffer`

### 8.5 Diagnostics and errors

- `rustynet_mobile_engine_export_redacted_diagnostics(handle) -> OwnedBuffer`
- `rustynet_mobile_last_error_code() -> i32`
- `rustynet_mobile_last_error_message() -> OwnedBuffer`
- `rustynet_mobile_buffer_free(buffer_ptr, buffer_len)`

---

## 9. Memory ownership rules

These rules should be written into code comments and test cases.

### 9.1 General rule

The native side may pass raw pointers only for the duration of the call. Rust must copy input it needs to keep.

### 9.2 Inputs from native to Rust

- Native allocates input buffers.
- Rust validates pointer + length.
- Rust copies input into owned memory before the call returns if the data must survive.
- Rust must never retain borrowed foreign pointers after return.

### 9.3 Outputs from Rust to native

- Rust allocates owned output buffers.
- Native receives pointer + length.
- Native must call the designated free function.
- Any output buffer that may contain sensitive data should be clearly labelled in code comments and should be zeroized before free where possible.

### 9.4 Opaque handles

- Rust allocates and frees engine objects.
- Native never dereferences internal Rust pointers.
- Double-free and use-after-free must be tested explicitly.

---

## 10. Error model

### 10.1 Use stable error codes

The native side should not have to parse arbitrary Rust strings to understand failure classes.

Suggested error categories:

- `INVALID_ARGUMENT`
- `NOT_INITIALIZED`
- `ALREADY_RUNNING`
- `NOT_RUNNING`
- `SECRET_UNAVAILABLE`
- `VERIFICATION_FAILED`
- `PERSISTENCE_FAILED`
- `INTERNAL_ERROR`
- `PANIC_CAUGHT`

### 10.2 Last-error buffer

For diagnostics, the FFI layer can expose a thread-local or handle-local last-error message buffer. This must be redacted and must not include secrets.

### 10.3 No panic across the ABI

Every exported function should run behind a `catch_unwind` boundary and return a structured error when a panic occurs.

---

## 11. Secret-handling rules at the boundary

### 11.1 Default rule: do not export secret values back to native code

The native side should ask Rust to perform operations, not ask Rust to hand back long-lived private keys.

### 11.2 Exceptions must be narrow and documented

Examples of acceptable temporary crossings:

- import of a user-provided enrollment token,
- import of wrapped secret ciphertext from secure storage,
- export of wrapped ciphertext back to secure storage,
- user-visible display of a one-time device code or fingerprint.

### 11.3 Do not use giant convenience JSON blobs for secret paths

Secret import/export should use binary or narrow structured payloads, not “dump the whole config as JSON and fish the secret out later.”

---

## 12. Android-specific boundary notes

### 12.1 JNI shim responsibilities

The Android shim should:

- convert JNI strings / byte arrays into C-ABI calls,
- map Java/Kotlin exceptions into app-layer failures,
- never perform protocol logic,
- never store raw long-lived secrets except for the duration of a single call.

### 12.2 Tunnel socket and TUN ownership

The Android native side owns:

- `VpnService` permission and lifecycle,
- tunnel socket protection before tunnel activation,
- `VpnService.Builder` use and local TUN creation.

Rust owns:

- the logical session state machine,
- packet processing,
- peer update logic,
- route/DNS plan computation as data.

### 12.3 Recommended file pair

- `mobile/android/app/src/main/cpp/rustynet_bridge.cpp`
- `mobile/android/app/src/main/java/com/rustynet/mobile/ffi/RustynetNative.kt`

---

## 13. iOS-specific boundary notes

### 13.1 Swift / C shim responsibilities

The Apple-side shim should:

- translate Swift / ObjC values into C-ABI calls,
- pass packet buffers between `NEPacketTunnelFlow` and Rust,
- keep extension-safe behavior explicit,
- avoid keeping secret data in Swift view models or convenience wrappers.

### 13.2 Packet flow ownership

The iOS native side owns:

- `NEPacketTunnelProvider` lifecycle,
- `NETunnelProviderManager` preference save/load flows,
- route and DNS application via Network Extension APIs,
- extension/container coordination.

Rust owns:

- session logic,
- signed-state verification,
- route/DNS planning as data,
- packet transformation / protocol logic.

### 13.3 Recommended file pair

- `mobile/ios/RustynetMobile/FFI/RustynetFFI.swift`
- `mobile/ios/RustynetMobile/FFI/RustynetFFI.h`

---

## 14. Review checklist for any FFI change

Every FFI change should answer these questions in the PR description:

1. Does this add any new unsafe block in Rust?
2. Why is the unsafe block necessary?
3. What is the exact safety contract?
4. Does the call move secret data across the boundary?
5. Could the same goal be achieved with an event or handle instead of a raw pointer?
6. Who owns the buffer before and after the call?
7. What happens if the native side passes a null pointer or zero length?
8. What happens if Rust panics?
9. Is the returned error message redacted?
10. Are there tests for double-free, invalid input, and panic containment?

---

## 15. Anti-patterns to reject

Reject the following immediately:

- exposing deep Rust structs directly to native code,
- retaining foreign pointers after return,
- returning borrowed Rust memory to native code,
- letting panics unwind into Kotlin/Swift,
- using the FFI layer as a shortcut to reach internal debug state,
- sending secrets over JSON because “it is easier,”
- building separate Kotlin and Swift implementations of core connection logic.

---

## 16. Bottom line

The FFI layer should be a **thin membrane**, not a second application architecture.

If it stays narrow, explicit, and boring, Rust remains the implementation center of gravity and the mobile apps remain small platform wrappers.

That is exactly the shape Rustynet wants.

---

## Sources

### Official Rust documentation

- Rustonomicon FFI: `https://doc.rust-lang.org/nomicon/ffi.html`
- Rust linkage: `https://doc.rust-lang.org/reference/linkage.html`
- Cargo workspaces: `https://doc.rust-lang.org/cargo/reference/workspaces.html`

### Android official documentation

- Android NDK guides: `https://developer.android.com/ndk/guides`
- JNI tips: `https://developer.android.com/training/articles/perf-jni`
- VPN guide: `https://developer.android.com/develop/connectivity/vpn`
- `VpnService` API reference: `https://developer.android.com/reference/android/net/VpnService`

### Apple official documentation

- Network Extension overview: `https://developer.apple.com/documentation/networkextension`
- `NEPacketTunnelProvider`: `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- Packet tunnel provider overview: `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- App extension safety guidance: `https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html`
- Creating a multi-platform binary framework bundle: `https://developer.apple.com/documentation/xcode/creating-a-multi-platform-binary-framework-bundle`

### Rustynet repository and security references

- Workspace root: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/Cargo.toml`
- Backend API crate: `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/crates/rustynet-backend-api/src/lib.rs`
- OWASP MASVS: `https://mas.owasp.org/MASVS/`
