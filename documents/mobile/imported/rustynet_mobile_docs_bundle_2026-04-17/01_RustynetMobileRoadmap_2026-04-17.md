# Rustynet Mobile Platform Roadmap (Android + iOS)

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/RustynetMobileRoadmap_2026-04-17.md`  
**Status:** Proposed roadmap and design plan  
**Audience:** Rustynet maintainers, mobile engineers, security reviewers, release engineers

---

## 1. Purpose

This document lays out a practical, security-first, Rust-first plan for bringing Rustynet to **Android** and **iOS** as real mobile apps, without diluting the project’s current engineering standards.

It is intended to answer five questions in one place:

1. **What should the mobile products actually be?**
2. **What parts of Rustynet can be reused, and what must be replaced?**
3. **How do we keep the implementation centered in Rust instead of re-writing core logic in Kotlin and Swift?**
4. **How do we maintain strong security on mobile without making false assumptions about platform capabilities?**
5. **What decisions and pitfalls need to be handled early so the project does not discover them during beta or store review?**

This is a roadmap, not a promise that every item should be shipped in the first mobile release. It intentionally separates **v1 essentials**, **hard requirements for production**, and **deferred capabilities**.

---

## 2. Executive summary

### 2.1 The right goal

Rustynet on mobile should be built as:

- a **first-class client app** on Android and iOS,
- powered by a **shared Rust core**,
- wrapped by **small native platform shells** for UI, lifecycle, VPN APIs, key storage, notifications, and store packaging.

### 2.2 The wrong goal

Rustynet on mobile should **not** be approached as:

- “port `start.sh` to phones,”
- “run the current daemon as-is in the background,”
- “make Android and iOS behave like tiny Linux hosts,”
- “copy security logic into Kotlin and Swift for convenience,” or
- “ship every desktop/server role on day one.”

### 2.3 What the first mobile product should be

The recommended v1 product is a **secure mobile Rustynet client** that can:

- enroll a device into an existing Rustynet deployment,
- establish and maintain a tunnel,
- apply policy-controlled full-tunnel or split-tunnel routing,
- use managed DNS / Magic DNS where supported by the Rustynet control plane,
- support remote-exit usage when the server-side path is ready,
- survive normal mobile lifecycle events and network changes,
- expose operator-friendly but safe diagnostics.

### 2.4 What v1 should not do

The recommended v1 should **not** try to make phones into:

- general-purpose relay nodes,
- general-purpose exit nodes,
- unattended provisioning hosts,
- mobile replacements for the live-lab / VM-lab tooling,
- holders of high-value administrative or signing authority.

### 2.5 One-sentence architecture recommendation

**Keep protocol, policy, crypto, state machine, routing decisions, enrollment logic, and tunnel orchestration in Rust; keep Kotlin and Swift limited to platform lifecycle, system VPN APIs, secure storage adapters, notifications, and UI.**

---

## 3. Current state of Rustynet, and what it means for mobile

### 3.1 What Rustynet already has

Rustynet already has the shape of a project that can support mobile work, because the repository is a Rust workspace split into multiple crates instead of one monolith. The existing crate layout strongly suggests that a mobile design should preserve shared Rust logic rather than reimplementing behavior per platform.

Relevant existing crates include:

- `crates/rustynet-backend-api`
- `crates/rustynet-backend-wireguard`
- `crates/rustynet-control`
- `crates/rustynet-crypto`
- `crates/rustynet-dns-zone`
- `crates/rustynet-local-security`
- `crates/rustynet-policy`
- `crates/rustynet-relay`
- `crates/rustynetd`
- `crates/rustynet-cli`

This is important because it means mobile does **not** need a fresh architecture from zero. It needs a **platform adaptation layer**.

### 3.2 What Rustynet does not yet appear to have

From the current repository structure and active documentation, Rustynet does **not** yet appear to have:

- Android application modules,
- iOS application or extension targets,
- JNI / Swift binding layers,
- a mobile-specific backend implementation,
- a mobile-safe secure storage abstraction,
- a mobile capability model,
- a mobile release and validation pipeline.

### 3.3 What the current repo status implies

Rustynet is not “done” even before mobile work. The current active readiness docs indicate that the branch still has **top-level evidence and release-readiness blockers**, especially around fresh-install proof and canonical cross-network proof for the current `HEAD`.

That matters for mobile in two ways:

1. **Mobile work can still begin now** in the areas of crate extraction, API design, platform spikes, and security architecture.
2. **Mobile beta should not ship against unstable server-side assumptions** if the underlying traversal/relay/control-plane truth is still being finalized.

### 3.4 The central mobile conclusion from the repo state

Rustynet today is best understood as having:

- a **promising Rust core**,
- a **host-oriented operational shell**, and
- **unfinished current-branch validation**.

The mobile plan should therefore be:

- **reuse the core**,
- **replace the host shell**, and
- **avoid binding mobile product decisions to unstable server-side or evidence-related gaps**.

---

## 4. Product scope: what the mobile apps should and should not be

### 4.1 Recommended v1 scope

The first Android and iOS releases should support:

- device enrollment into an existing Rustynet control plane,
- sign-in / bootstrap using a controlled enrollment flow,
- tunnel connect / disconnect,
- policy-controlled full-tunnel mode,
- policy-controlled split-tunnel mode,
- managed DNS and Magic DNS where available,
- remote-exit use where the server side already supports it,
- network change recovery,
- bounded diagnostics and exportable support bundles,
- remote revocation and re-key flows.

### 4.2 Deferred scope

The following should be explicitly **deferred** unless there is a hard product requirement:

- mobile as relay host,
- mobile as exit node,
- mobile blind-exit host,
- full admin/operator surface on-device,
- live-lab / VM-lab features,
- local shell/bootstrap orchestration,
- unmanaged sideload-only enterprise feature branches,
- broad plugin or scripting support.

### 4.3 Why this scope is correct

Mobile operating systems provide **VPN client APIs**, not “turn your phone into a general-purpose Linux network appliance” APIs. Even when something is technically possible, it may conflict with battery management, background execution policy, entitlement boundaries, store review, or the user’s expectations.

A secure v1 should therefore optimize for:

- **client correctness**,
- **security clarity**,
- **reliable lifecycle handling**, and
- **minimum privileged complexity**.

---

## 5. Platform realities that the design must respect

## 5.1 Android reality

Android provides `VpnService` for custom VPN implementations. The app establishes a virtual interface and reads/writes packets through the file descriptor returned by the VPN setup path. Routes, DNS servers, MTU-related behavior, bypass rules, and allowed address families are configured through `VpnService.Builder`.

This means the Android mobile client should be designed around:

- one Android app module,
- one `VpnService` implementation,
- a native/Rust tunnel engine that owns the packet processing path,
- a minimal Kotlin layer that manages Android-specific lifecycle and user interactions.

Important Android consequences:

- **The Android VPN is a real system-level network feature**, not just an in-app socket proxy.
- **DNS must be set deliberately** when Rustynet expects managed DNS behavior; otherwise the platform can use the default network’s DNS.
- **Play distribution has policy obligations** for apps using `VpnService`.
- **Background behavior and battery management matter**; the design has to survive Doze, App Standby, and device-specific behavior.
- **Always-on and per-app VPN are possible**, but should be treated as separate product-policy decisions, not assumed defaults.

## 5.2 iOS reality

iOS uses **Network Extension**, specifically a **Packet Tunnel Provider app extension**, for custom VPN clients. The provider gets a virtual packet interface through `packetFlow`, while interface configuration is applied using `NEPacketTunnelNetworkSettings`. The containing app manages configurations through `NETunnelProviderManager` and controls active sessions through `NETunnelProviderSession`.

This means the iOS product is not one simple binary. It is at least:

- a containing app,
- a packet tunnel extension,
- a shared data mechanism between them,
- and a Rust core linked into the appropriate targets.

Important iOS consequences:

- **The tunnel provider is an app extension with entitlement requirements.**
- **The app and extension are separate processes.** They do not share normal app state automatically.
- **App Groups are required** for shared storage between the app and the extension.
- **Only extension-safe APIs may be linked by the extension target.**
- **Always-on / supervised-device style deployments should be treated as enterprise scope**, not a default consumer assumption.

## 5.3 Shared mobile reality

Both mobile platforms force the same high-level conclusion:

- the OS owns lifecycle and tunnel entry points,
- the app must integrate with a system VPN framework,
- secrets and configuration must be handled using platform storage models,
- background behavior is constrained,
- routing and DNS must be configured explicitly,
- store and entitlement policy are part of engineering, not postscript paperwork.

---

## 6. The recommended target architecture

### 6.1 Core principle

Rust should remain the **center of gravity**.

That means:

- protocol logic stays in Rust,
- policy evaluation stays in Rust,
- key lifecycle logic stays in Rust,
- config parsing and validation stay in Rust,
- tunnel orchestration state stays in Rust,
- route and DNS intent stay in Rust,
- logging schemas and redaction rules stay in Rust.

Kotlin and Swift should own only what they must own:

- user interface,
- platform permission flows,
- app/extension/service lifecycle,
- platform VPN API entry points,
- secure-storage primitives,
- notifications,
- store packaging.

### 6.2 Proposed architecture diagram

```text
                       +------------------------------+
                       |      Rustynet Control Plane  |
                       |  enrollment / policy / auth  |
                       +---------------+--------------+
                                       |
                                       |
                        shared protocol and config model
                                       |
                 +---------------------+---------------------+
                 |                                           |
                 v                                           v
      +---------------------------+              +---------------------------+
      |   Android app + service   |              |  iOS app + tunnel ext.   |
      |  Kotlin UI / VpnService   |              | Swift UI / NEPacketTunnel|
      +-------------+-------------+              +-------------+-------------+
                    |                                            |
                    | native lifecycle + secure storage adapters |
                    v                                            v
             +------+--------------------------------------------+------+
             |                 Rust mobile shared core                  |
             | control / crypto / policy / config / state machine      |
             | DNS intent / session logic / route intent / redaction   |
             +----------------------+----------------+------------------+
                                    |                |
                                    |                |
                                    v                v
                       +-------------------+  +-------------------+
                       | Android backend   |  | Apple backend     |
                       | packet IO adapter |  | packetFlow adapter|
                       +-------------------+  +-------------------+
```

### 6.3 Proposed workspace additions

The cleanest path is to add mobile-specific crates and directories rather than forcing mobile code into desktop/server crates.

Recommended additions:

```text
crates/
  rustynet-mobile-core/
  rustynet-mobile-ffi/
  rustynet-secure-storage/
  rustynet-backend-android/
  rustynet-backend-apple/
  rustynet-mobile-observability/

mobile/
  android/
    app/
    build-logic/
  ios/
    RustynetApp/
    RustynetPacketTunnelExtension/
    Rustynet.xcodeproj or workspace/
```

### 6.4 What each new crate should do

#### `crates/rustynet-mobile-core`
The platform-neutral mobile client core.

Owns:

- enrollment state machine,
- profile/config validation,
- mobile capability model,
- tunnel orchestration state machine,
- route intent model,
- DNS intent model,
- reconnect/backoff policy,
- policy enforcement,
- diagnostic/event schema,
- versioned config migrations.

#### `crates/rustynet-mobile-ffi`
The supported FFI surface for Kotlin and Swift.

Owns:

- stable API types for foreign callers,
- serialization-safe DTOs,
- lifecycle commands,
- error mapping,
- panic containment at the boundary,
- generated bindings support.

#### `crates/rustynet-secure-storage`
A Rust trait layer around platform storage.

Owns:

- `SecureStorage` trait,
- item labels / versioning,
- key wrapping semantics,
- migration helpers,
- platform capability reporting.

Implementations are provided by Android and Apple wrappers.

#### `crates/rustynet-backend-android`
Android-specific tunnel backend adapter.

Owns:

- packet FD handoff into Rust,
- Android packet loop integration,
- route/DNS intent translation into `VpnService.Builder` inputs,
- network change hooks,
- tunnel stats extraction.

#### `crates/rustynet-backend-apple`
Apple-specific tunnel backend adapter.

Owns:

- `packetFlow` bridging,
- `NEPacketTunnelNetworkSettings` translation,
- app-group coordination helpers,
- provider message helpers,
- extension-safe linking boundaries.

#### `crates/rustynet-mobile-observability`
Mobile-safe logging and diagnostics.

Owns:

- structured events,
- redaction rules,
- bounded ring buffers,
- support bundle schema,
- privacy-preserving counters.

---

## 7. Reuse, refactor, replace: mapping the current repo to mobile

### 7.1 Likely direct reuse candidates

These are the parts most likely to be reusable with limited changes:

- `rustynet-crypto`
- `rustynet-policy`
- `rustynet-control` client-facing protocol and config logic
- parts of `rustynet-dns-zone`
- parts of `rustynet-relay` that are genuinely client-side and platform-neutral
- core types and concepts from `rustynet-backend-api`

### 7.2 Likely refactor candidates

These likely need extraction or reshaping before mobile can use them cleanly:

- `rustynetd` logic that is currently too daemon-shaped,
- config loading that assumes host filesystem layouts,
- code that assumes desktop/server service managers,
- CLI-owned flows that should become library-owned flows,
- backend APIs that do not yet model mobile lifecycle events,
- logs and diagnostics that assume host file outputs.

### 7.3 Likely replace candidates

These are not good mobile building blocks and should be treated as desktop/server-only:

- `start.sh`
- shell bootstrap flows
- VM-lab wrappers
- Linux systemd orchestration assumptions
- macOS launch/host assumptions that do not apply to iOS
- command-based backend control surfaces that expect host shell access

### 7.4 Practical rule

If a component assumes one of these, it should not be considered mobile-ready:

- shell access,
- persistent unrestricted background execution,
- host-managed filesystems,
- admin/operator interactivity,
- arbitrary long-running services,
- direct use of host networking configuration tools.

---

## 8. How to keep the project truly Rust-first

### 8.1 Non-negotiable rule

For mobile, Kotlin and Swift are **wrappers**, not alternate implementations.

### 8.2 What must stay in Rust

The following should remain in Rust unless there is a platform-enforced reason not to:

- protocol message definitions,
- peer/config parsing,
- validation logic,
- cryptography orchestration,
- tunnel state machine,
- routing intent computation,
- DNS intent computation,
- enrollment protocol logic,
- session recovery logic,
- log schemas,
- redaction,
- capability modeling,
- policy evaluation.

### 8.3 What should live in native code

Android and iOS native code should be limited to:

- UI flows,
- platform VPN service entry points,
- keychain/keystore access bridges,
- app lifecycle wiring,
- notifications,
- platform-specific permission UX,
- distribution/build packaging.

### 8.4 FFI recommendation

Use **two FFI layers**, not one:

1. **A stable high-level binding layer** for app-facing operations such as enrollment, connect/disconnect, state queries, diagnostics, and profile management.
2. **A lower-level adapter layer** for hot-path packet I/O and OS handle transfer.

This is important because packet tunnels are performance-sensitive. The design should **not** push every packet through a heavy, allocation-rich foreign-language binding API.

### 8.5 Tooling recommendation

A strong default is:

- use **UniFFI** or an equivalent generated binding path for high-level Kotlin/Swift APIs,
- use a **thin C ABI / JNI / Swift bridge** for packet-path and handle-path integration where needed,
- keep ownership, lifetimes, and failure semantics explicit.

### 8.6 Rust governance rules for mobile

Add repository rules such as:

- no duplicated protocol or policy logic in native code,
- all new mobile security logic lands in Rust first,
- `unsafe` remains forbidden in shared crates,
- any unavoidable `unsafe` is isolated in tiny audited modules,
- no unwinding across FFI boundaries,
- all public FFI structs are versioned and documented,
- native wrappers may not parse security-sensitive config independently.

---

## 9. The biggest design question: how the current Rustynet environment becomes a mobile environment

### 9.1 What “the current working environment” means today

Rustynet today includes:

- host-oriented operational flows,
- CLI and daemon surfaces,
- shell-based setup paths,
- current backend implementations that are Linux/macOS oriented,
- evidence/runbook discipline,
- control-plane and policy logic in Rust.

### 9.2 What the mobile equivalent must become

On mobile, the equivalents are:

| Current desktop/server idea | Mobile equivalent |
|---|---|
| `start.sh` / operator menu | app onboarding and settings UI |
| daemon process | OS-owned VPN service or packet tunnel extension |
| host filesystem state | app storage + secure storage + app group container |
| system route setup commands | `VpnService.Builder` / `NEPacketTunnelNetworkSettings` |
| long-lived host service manager | mobile lifecycle callbacks and reconnect logic |
| report directories | bounded support bundles and exportable diagnostics |
| host keys and shell trust files | platform secret stores + server trust policy |

### 9.3 The key migration idea

Do **not** port the environment. **Re-express it.**

The goal is not “make Android look like Rustynet’s Linux runtime.” The goal is “make Rustynet’s client semantics work correctly inside Android and iOS’s VPN models.”

### 9.4 What needs to be extracted first

Before serious app work, extract the parts of Rustynet that should become platform-neutral libraries:

- config schema and validation,
- enrollment logic,
- policy resolution,
- route/DNS intent resolution,
- session state machine,
- reconnect and fail-closed behavior,
- diagnostics schema,
- secure storage API surface.

### 9.5 What needs to be replaced entirely

Replace these with mobile-native equivalents:

- bootstrap shell flows,
- direct service-manager assumptions,
- host inventory/lab assumptions,
- report-directory-centric UX,
- daemon startup semantics.

---

## 10. Security architecture for mobile Rustynet

## 10.1 Security goals

The mobile apps should preserve Rustynet’s security posture by default:

- fail closed,
- minimize trusted code surface,
- keep cryptographic material off logs and debug paths,
- avoid privilege creep,
- make platform trust boundaries explicit,
- treat local compromise and backup/restore behavior as design questions,
- maintain supply-chain visibility.

## 10.2 Threat model assumptions

The roadmap should assume at least these threat classes:

- passive network attackers,
- active MITM against control-plane endpoints,
- local malicious apps on the device,
- rooted / jailbroken / developer-modified environments,
- stolen unlocked or previously-unlocked devices,
- reverse engineering and API abuse,
- store build tampering or repackaging attempts,
- accidental log leakage,
- schema drift between platform wrappers and Rust core.

## 10.3 Key separation model

Do not treat “the mobile key” as one thing.

Use at least three conceptual layers:

1. **Tunnel transport key** — the key that identifies the tunnel peer.
2. **Device identity / enrollment credential** — used for control-plane trust and revocation logic.
3. **Storage protection key** — the platform-backed key used to wrap or protect at-rest secret material.

This separation makes remote revocation, re-enrollment, and incident response far cleaner.

## 10.4 iOS key storage reality

One of the most important mobile design facts is that **Secure Enclave is not a generic home for arbitrary VPN private keys**. Apple’s Secure Enclave APIs and key support are not a drop-in storage target for WireGuard-style Curve25519 private keys. As a result, the mobile design should **not** assume “we will store the Rustynet/WireGuard private key directly in Secure Enclave.”

Recommended iOS strategy:

- store the Rustynet transport private key in the **Keychain**,
- use a **device-bound accessibility class** for items that should not migrate to a new device,
- choose the accessibility class intentionally based on reconnect requirements,
- optionally use Secure Enclave-backed keys for **wrapping, gating, or attestation-related purposes**, not as a naïve replacement for the transport key.

### 10.4.1 The first-unlock question that must be decided early

This is a question teams often discover too late:

**Should the VPN be able to reconnect after reboot before the user unlocks the phone once?**

If yes, choose a Keychain accessibility class that allows background access after first unlock on that device. If no, choose a stricter class. This is a genuine product/security tradeoff and should be documented, not left implicit.

## 10.5 Android key storage reality

Android Keystore can protect key material from extraction and can be hardware-backed depending on device capabilities. However, support and enforcement characteristics vary by device and by algorithm. The design therefore should not overclaim “all Android phones will hardware-store the exact Rustynet tunnel key type.”

Recommended Android strategy:

- use a **Keystore-protected wrapping key** when available,
- generate or derive the tunnel key within Rust or controlled code,
- encrypt the transport key at rest using the wrapping key,
- record whether the storage protection is software-backed, hardware-backed, or stronger hardware-backed where supported,
- expose that capability truth to the control plane and diagnostics.

### 10.5.1 Why the wrapping model is safer than wishful thinking

The wrapping model avoids tying correctness to fragile assumptions about device-specific algorithm support. It lets Rustynet preserve a consistent key lifecycle while still benefiting from hardware-backed secret protection where the platform actually provides it.

## 10.6 Network trust and TLS policy

The mobile apps should enforce strong network defaults:

- HTTPS/TLS for control-plane communication,
- App Transport Security on Apple platforms,
- Network Security Configuration on Android,
- no blanket cleartext exceptions,
- certificate pinning only where there is a clear threat-model reason and an operational rotation plan.

### 10.6.1 Pinning policy recommendation

Pinning should not be adopted just because it “sounds more secure.” Apple explicitly cautions that pinning is not required and should be used carefully. The right Rustynet policy is:

- default to strong standard TLS validation,
- pin only high-value fixed endpoints if justified,
- use backup pins / rotation planning,
- document emergency recovery procedures,
- never build a pinning scheme that locks out legitimate rotation under incident response.

## 10.7 Attestation and anti-abuse

Attestation should be treated as an **optional hardening layer**, not the primary security foundation.

Recommended approach:

- on Android, consider **Play Integrity** for high-value enrollment or session actions,
- on Apple platforms, consider **App Attest** for similar high-value flows,
- verify attestation on the server,
- design graceful degradation if the attestation provider is unavailable,
- never make app availability depend on brittle client-only attestation logic.

## 10.8 Logging and observability

Mobile diagnostics are useful, but they are also a common leak path.

Rules:

- no secrets in logs,
- no raw key material in panic paths,
- no full control-plane tokens in log messages,
- IP and peer details redacted according to support mode,
- bounded ring buffer storage,
- explicit “export support bundle” action,
- per-event privacy classification,
- crash-safe but privacy-safe logging.

## 10.9 Memory safety and unsafe code policy

Rustynet already uses `#![forbid(unsafe_code)]` in security-relevant areas. Keep that standard for shared mobile crates. If `unsafe` becomes necessary for FFI glue or platform interop, confine it to very small modules that are:

- separately reviewed,
- documented with invariants,
- tested under sanitizers or targeted harnesses where possible,
- never mixed into business logic.

## 10.10 MASVS / MASTG alignment

Use OWASP MASVS and MASTG as the external security reference frame for the mobile program. Rustynet’s mobile release gates should explicitly map to the areas that matter most here:

- storage of secrets,
- cryptography,
- authentication and session control,
- network communication,
- platform interaction,
- code quality and build integrity,
- resilience and abuse resistance,
- privacy.

---

## 11. Networking model: routing, DNS, traversal, relay, and exit behavior on phones

## 11.1 Routing model

The Rust core should compute **routing intent** as a portable model:

- full tunnel,
- split tunnel,
- included routes,
- excluded routes,
- local-LAN policy,
- DNS scope,
- exit-node preference.

The platform backends should then translate that intent into:

- Android `VpnService.Builder` configuration,
- iOS `NEPacketTunnelNetworkSettings` and route settings.

This avoids two dangerous outcomes:

- route logic being duplicated in native code,
- mobile behavior drifting from desktop/server behavior.

## 11.2 DNS model

DNS needs its own explicit design, not an afterthought.

Requirements:

- managed DNS intent must be versioned in Rust,
- mobile backends must apply DNS settings deliberately,
- split-tunnel and excluded-route behavior must be tested for DNS leak scenarios,
- Magic DNS behavior must be modeled as policy, not inferred by UI state.

### 11.2.1 A hidden question teams often miss

**What happens when the tunnel is down but the user still expects managed-name behavior?**

Decide early whether the app should:

- fail closed and surface “name resolution unavailable,”
- fall back to public/default DNS,
- or preserve a limited local cache.

There is no free answer. The decision affects privacy, user expectations, and support burden.

## 11.3 Traversal and relay on mobile

Mobile clients should be treated as **dial-out-first endpoints**.

That means:

- traversal and relay support is still valuable,
- but the design should assume the phone is more often a client behind changing networks than a stable network host,
- path changes must trigger deliberate re-evaluation,
- battery cost must be considered when tuning keepalive and reassertion behavior.

## 11.4 Exit behavior on mobile

Using a remote exit from a phone is reasonable. Making the phone itself a general exit node is not a good v1 goal.

Reasons:

- background constraints,
- battery drain,
- mobile radio variability,
- inbound/reachability assumptions,
- store-policy and UX complications,
- poor incident-response characteristics if a phone is lost or wiped.

---

## 12. Apple-specific architecture plan

## 12.1 Product shape

The Apple mobile product should consist of:

- a Swift containing app,
- a Packet Tunnel Provider extension,
- a shared app-group container,
- Rust static or dynamic library targets linked appropriately.

## 12.2 Containing app responsibilities

The containing app should own:

- onboarding and account/device enrollment UI,
- local settings,
- device posture presentation,
- non-sensitive diagnostics presentation,
- configuration creation through `NETunnelProviderManager`,
- start/stop requests to `NETunnelProviderSession`,
- secure but limited support bundle export.

## 12.3 Packet tunnel extension responsibilities

The extension should own:

- packet ingress/egress via `packetFlow`,
- tunnel session startup/shutdown,
- applying `NEPacketTunnelNetworkSettings`,
- live packet-path state,
- reconnect and path-change handling,
- interaction with the Rust tunnel engine.

## 12.4 App group design

Use an App Group for:

- non-secret shared config metadata,
- limited state needed by both app and extension,
- log ring buffers,
- migration markers,
- message handoff files if needed.

Do **not** assume the app and extension can share arbitrary in-memory state. They cannot.

## 12.5 Extension-safe API rule

The iOS extension target must be kept clean of APIs that are not extension-safe. This must influence both:

- the Swift code linked into the extension,
- and any Rust-to-native bridge code that introduces platform dependencies.

## 12.6 Recommended iOS build structure

Recommended split:

- `mobile/ios/RustynetApp` — containing app
- `mobile/ios/RustynetPacketTunnelExtension` — packet tunnel extension
- `crates/rustynet-mobile-core` — shared engine
- `crates/rustynet-backend-apple` — Apple packet adapter
- `crates/rustynet-mobile-ffi` — Swift-callable surface

### 12.6.1 Optional refinement

If extension-safe concerns become sharp, split the Apple FFI into:

- `rustynet-apple-app-ffi`
- `rustynet-apple-extension-ffi`

Both can call the same shared Rust core while keeping linkage and capability boundaries explicit.

---

## 13. Android-specific architecture plan

## 13.1 Product shape

The Android product should consist of:

- a Kotlin app,
- a `VpnService` implementation,
- a Rust native library,
- a secure storage bridge to Android Keystore,
- native/JNI glue for FD handoff and lifecycle bridging.

## 13.2 App responsibilities

The app should own:

- onboarding and enrollment UI,
- settings and user-visible policy state,
- state presentation,
- diagnostics UI,
- notification UX,
- opt-in flows for VPN permissions and policy surfaces,
- start/stop control for the service.

## 13.3 `VpnService` responsibilities

The Android `VpnService` should own:

- requesting and maintaining the VPN session,
- building the virtual interface settings,
- passing packet FDs into Rust,
- receiving state updates from Rust,
- reflecting tunnel state to the Android UI and notification surface,
- reacting to revoke or lifecycle events.

## 13.4 Recommended Android build structure

Recommended split:

- `mobile/android/app` — app + service + UI
- `crates/rustynet-mobile-core` — shared engine
- `crates/rustynet-backend-android` — Android packet adapter
- `crates/rustynet-mobile-ffi` — high-level app-facing bindings

## 13.5 Foreground/background behavior

The app must be engineered with realistic expectations about Android background execution and battery policy. The service design should prioritize:

- resilient reconnect logic,
- correct reaction to revoke/shutdown events,
- explicit testing in Doze/App Standby conditions,
- device-matrix testing beyond only emulator and Pixel devices.

## 13.6 Android policy and publishing

Plan for Google Play compliance from the start:

- complete the `VpnService` declaration requirements,
- make user disclosure and consent flows clear,
- keep privacy disclosures aligned with actual traffic handling and diagnostics,
- avoid surprising or hidden data collection in support features.

---

## 14. The backend API changes Rustynet will likely need

The current `rustynet-backend-api` crate is a strong starting seam, but mobile likely needs additional abstractions.

Recommended additions:

### 14.1 `PacketIo` abstraction

A portable abstraction for:

- receiving IP packets from the platform VPN interface,
- sending packets back to the platform VPN interface,
- explicit close/revoke semantics,
- backpressure/error signaling.

### 14.2 `RouteIntent` and `DnsIntent`

Move platform-neutral desired network behavior into Rust-owned types, for example:

- included routes,
- excluded routes,
- DNS servers,
- search domains,
- local network policy,
- metered or restricted-network hints where appropriate.

### 14.3 `SecureStorage` trait

A platform capability abstraction for:

- store secret,
- load secret,
- delete secret,
- report storage protection level,
- migrate secret format,
- indicate backup/migration semantics.

### 14.4 `NetworkEnvironment` hooks

A small model for network environment events:

- network changed,
- path degraded,
- metered status changed,
- app moved background/foreground,
- device reboot / first-unlock status where applicable,
- platform revoked tunnel.

### 14.5 `CapabilityProfile`

A typed, explicit capability model that includes things like:

- `supports_exit_host = false`
- `supports_relay_host = false`
- `supports_always_on = platform-dependent`
- `secure_storage = software_wrapped | hardware_wrapped | attested_hardware_wrapped`
- `background_reconnect = yes/no/limited`

This solves two problems:

1. The control plane learns the truth about the client platform.
2. The UI can stop pretending all Rustynet nodes are interchangeable.

---

## 15. Release engineering and supply-chain plan

## 15.1 Build outputs

The mobile build pipeline should produce:

- Android application artifacts with embedded Rust libraries,
- iOS app + extension builds linked against Rust artifacts,
- SBOMs for Rust and native dependencies,
- signed release artifacts,
- provenance records tied to source and dependency resolution.

## 15.2 Rust target support

Rust officially supports both Android and iOS targets, so a Rust-first mobile plan is realistic. Cross-compilation must still be engineered properly:

- Android requires the Android NDK and target-specific linker setup,
- iOS builds require Apple SDK/Xcode toolchains.

## 15.3 Supply-chain controls

Apply the same or stricter controls than the desktop/server pipeline:

- `cargo audit`
- `cargo deny`
- dependency review for native packages and Apple/Android build dependencies
- SBOM generation
- signed release builds
- provenance capture aligned with SLSA-style practices
- explicit version pinning and upgrade policy for binding generators and native SDK dependencies

## 15.4 Signing and store trust

Distribution security is part of the product:

- Android must use modern Play signing/distribution practices where relevant,
- Apple distribution must respect entitlements, signing identities, and extension packaging,
- no self-update mechanisms should bypass store distribution norms.

---

## 16. Testing strategy and hard release gates

## 16.1 Rust-level testing

Before platform UI polish, build strong Rust-side testing for:

- config parsing and migration,
- policy evaluation,
- route intent generation,
- DNS intent generation,
- reconnect state machine behavior,
- key lifecycle behavior,
- redaction rules,
- FFI DTO serialization contracts.

## 16.2 Fuzzing and parser hardening

Any parser, config decoder, enrollment message parser, or support-bundle reader that reaches mobile should be fuzzed or otherwise hardened. Mobile apps are especially painful to fix once a parsing bug is in the field.

## 16.3 Android testing

Need at least:

- unit tests,
- instrumentation tests,
- service lifecycle tests,
- network change tests,
- Doze / App Standby tests,
- emulator plus real-device coverage,
- upgrade/migration tests,
- VPN revoke tests.

## 16.4 iOS testing

Need at least:

- unit tests for Swift wrappers,
- integration tests for app + extension state flow,
- packet tunnel start/stop tests,
- app-group state migration tests,
- upgrade/migration tests,
- reboot/first-unlock behavioral tests,
- entitlement/configuration validation.

## 16.5 Security testing

Every mobile release should pass an explicit security validation plan that includes:

- MASVS/MASTG-aligned checks,
- secure storage verification,
- network trust verification,
- reverse-engineering sanity checks,
- jailbreak/root posture behavior review,
- log leakage review,
- crash dump content review,
- attestation failure-mode review if attestation is enabled.

## 16.6 Field behavior testing

A VPN product that only passes lab tests is not ready.

Add scenario tests for:

- Wi-Fi to cellular switch,
- captive network transitions,
- airplane mode cycles,
- app update while configured,
- device reboot,
- stale enrollment or revoked device,
- server pin rotation,
- DNS fallback decisions,
- tunnel failure while app is backgrounded.

## 16.7 Suggested mobile release gates

A mobile build should not be called release-ready unless it has:

- passed Rust core tests,
- passed Android/iOS lifecycle integration tests,
- passed secret-storage validation,
- shown no secret leakage in logs or support bundles,
- passed network trust tests,
- passed route/DNS leak tests,
- passed upgrade/migration tests,
- produced signed artifacts with dependency/provenance records.

---

## 17. Phased roadmap

## Phase 0 — Decision capture and feasibility spikes

### Goal
Remove the unknowns that can sink the whole effort later.

### Deliverables

- written mobile product scope and non-goals,
- written decision on v1 client-only scope,
- iOS key-storage feasibility note,
- Android key-storage feasibility note,
- FFI choice decision memo,
- first draft mobile capability model,
- control-plane compatibility review,
- store/distribution constraints checklist.

### Required spikes

1. **iOS key storage spike**  
   Prove the exact storage pattern for transport keys, enrollment credentials, and background reconnect expectations.

2. **Android key wrapping spike**  
   Prove a hardware-backed wrapping path where available, with software-backed fallback behavior.

3. **Packet path spike on both platforms**  
   Prove that the proposed packet I/O bridge can move packets into a Rust engine without pathological copying or lifecycle breakage.

4. **Binding strategy spike**  
   Validate UniFFI or alternative high-level bindings for non-hot-path APIs.

### Exit criteria

- no unresolved “can the platform even do this?” questions remain for v1,
- storage and FFI decisions are documented,
- mobile capability truth has a draft schema.

## Phase 1 — Workspace refactor for mobile reuse

### Goal
Turn Rustynet’s reusable logic into clean mobile-consumable crates.

### Deliverables

- `rustynet-mobile-core`
- `rustynet-mobile-ffi`
- `rustynet-secure-storage`
- backend API extensions for mobile lifecycle
- versioned config and migration support
- mobile-safe diagnostics schema

### Work items

- extract app/daemon-independent logic from CLI/daemon-owned code,
- centralize route/DNS intent in Rust,
- centralize redaction policy in Rust,
- centralize enrollment/session logic in Rust,
- define capability profile types,
- define FFI-safe DTOs and error model,
- add shared CI for mobile-target builds.

### Exit criteria

- the shared mobile Rust layer builds for Android and iOS targets,
- native wrappers can call a stable high-level API,
- no security-sensitive parsing is duplicated outside Rust.

## Phase 2 — Android MVP

### Goal
Ship the first functional Android client against the shared Rust core.

### Deliverables

- Android app shell,
- Android `VpnService`,
- Rust packet adapter for Android,
- secure storage integration,
- enrollment flow,
- connect/disconnect,
- full tunnel and basic split tunnel,
- diagnostics ring buffer,
- Google Play policy readiness package.

### Work items

- implement `rustynet-backend-android`,
- pass packet FD into Rust engine,
- translate Rust route/DNS intent into `VpnService.Builder`,
- implement service notifications and revoke behavior,
- add migration-safe storage for profiles and secrets,
- add state sync between service and UI,
- build support bundle export with redaction.

### Exit criteria

- Android client can enroll, connect, reconnect, and disconnect reliably,
- no DNS leak or routing drift in defined test matrix,
- store disclosure and policy requirements are prepared,
- secrets remain protected at rest and absent from logs.

## Phase 3 — iOS MVP

### Goal
Ship the first functional iOS client against the same shared Rust core.

### Deliverables

- containing app,
- packet tunnel extension,
- App Group shared state design,
- Apple secure storage integration,
- enrollment flow,
- connect/disconnect,
- full tunnel and basic split tunnel,
- diagnostics and support bundle workflow.

### Work items

- implement `rustynet-backend-apple`,
- bridge `packetFlow` into Rust engine,
- translate route/DNS intent into `NEPacketTunnelNetworkSettings`,
- implement app/extension coordination,
- implement provider-message-based control where needed,
- implement keychain strategy and migration,
- validate extension-safe linkage.

### Exit criteria

- iOS client can enroll, connect, reconnect, and disconnect reliably,
- app and extension state is coherent,
- reboot/first-unlock behavior is intentional and documented,
- secrets remain protected and non-migratory where policy requires it.

## Phase 4 — Security hardening and parity expansion

### Goal
Move from “works” to “production-safe.”

### Deliverables

- attestation-backed high-value flows if adopted,
- advanced split-tunnel controls,
- remote revocation and re-key support,
- stronger diagnostics redaction and support tooling,
- battery/performance tuning,
- expanded test matrix,
- hardened store-review narratives and privacy docs.

### Work items

- implement remote wipe/revoke/re-enroll semantics,
- add certificate/pin rotation procedures if pinning is used,
- refine reconnect/backoff on bad networks,
- improve policy visibility to the user,
- add platform-specific resilience handling,
- perform MASTG-style review passes.

### Exit criteria

- mobile builds satisfy the project’s explicit security release gates,
- support burden is manageable,
- lifecycle edge cases are documented and tested.

## Phase 5 — Enterprise and advanced capabilities

### Goal
Add the features that are useful, but not essential to the first secure release.

### Candidate items

- managed-device / enterprise always-on behavior,
- per-app VPN where appropriate,
- stronger posture integration,
- more advanced support bundle workflows,
- deeper device-trust signals,
- policy-driven LAN exceptions or local-service behavior.

### Explicit caution

Do not begin this phase until the v1 security and lifecycle model is stable. Advanced VPN features are expensive if the basics are still drifting.

---

## 18. Recommended sequencing relative to the current Rustynet backlog

Not all current Rustynet work should block mobile equally.

### 18.1 Work that should not block mobile architecture work

These can proceed in parallel with mobile design:

- workspace refactors,
- storage abstractions,
- FFI definition,
- Android/iOS packet-path spikes,
- capability model design,
- mobile CI scaffolding.

### 18.2 Work that should block mobile beta confidence

These should be substantially stable before a serious external beta:

- authoritative current control-plane/config truth,
- current server-side traversal/relay behavior for supported client flows,
- current-HEAD evidence discipline for the underlying product path,
- canonical handling of managed DNS / remote exit semantics.

### 18.3 Work that mobile should consume, not solve

The mobile team should use the server-side traversal/relay/control-plane truth. It should not try to redesign those systems while also bringing up two mobile platforms.

---

## 19. Questions that usually go unasked until late

These should be decided early and written down.

### 19.1 Can the VPN reconnect after device reboot before the user unlocks once?
This is a key-storage accessibility decision, not just a UX question.

### 19.2 Do secrets migrate to a new device restore?
If not, is re-enrollment smooth enough?

### 19.3 Is attestation optional, required, or risk-based?
What happens when App Attest or Play Integrity is unavailable?

### 19.4 Are mobile devices first-class peers or constrained peers?
The recommended answer is: constrained peers with an explicit capability model.

### 19.5 Can policy assume the phone will accept inbound connectivity?
The recommended answer is no, not as a default design assumption.

### 19.6 What exactly may appear in a support bundle?
This must be designed before the first support incident, not after it.

### 19.7 Who owns route truth?
Rust should own route intent. Native code should apply it.

### 19.8 Who owns DNS truth?
Rust should own DNS intent. Native code should apply it.

### 19.9 Will the app hold high-value admin authority?
Recommended answer: no for v1.

### 19.10 How are lost or stolen phones revoked?
Remote revocation and re-key must be part of the design, not an afterthought.

### 19.11 What happens if the OS kills the service/extension repeatedly?
Need crash-loop detection, bounded retries, and user-visible recovery guidance.

### 19.12 What is the fallback when secure hardware capability is absent?
Capability truth must be recorded and policy-aware.

### 19.13 Can the native wrappers drift from Rust core schema?
Only if the project allows it. The roadmap should forbid it.

---

## 20. Major pitfalls to avoid

### 20.1 Re-implementing logic in native code
This creates drift, bugs, and inconsistent security fixes.

### 20.2 Assuming Secure Enclave can directly store the transport key
This is one of the easiest wrong assumptions in iOS VPN design.

### 20.3 Assuming Android hardware-backed storage is uniform
It is not. Design for capability detection and fallback.

### 20.4 Sending packets through a high-level binding layer
This is likely to be slow and fragile. Keep the packet path close to Rust.

### 20.5 Treating mobile as a tiny Linux host
The lifecycle, storage, networking, and policy models are different.

### 20.6 Forgetting that iOS app and extension are separate processes
This breaks state sharing, logging, and secret access if ignored.

### 20.7 Letting DNS defaults leak behavior
Especially on Android, unmanaged DNS behavior can appear if not configured explicitly.

### 20.8 Building pinning with no rotation plan
This turns a security mechanism into an outage mechanism.

### 20.9 Logging too much during bring-up
Mobile debug logs have a habit of becoming production logs.

### 20.10 Testing only on ideal devices and stable Wi-Fi
Real mobile failures happen during path churn, reboots, throttling, and weak networks.

### 20.11 Shipping a client with no capability truth
This encourages control-plane assumptions that are false on mobile.

### 20.12 Holding admin-grade secrets on consumer devices
This makes incident response much worse than it needs to be.

---

## 21. Recommended engineering rules for the mobile program

1. **Client-only first.**  
   Do not broaden the mobile role before the client role is solid.

2. **Rust owns truth.**  
   Native code wraps platform APIs; it does not define policy or protocol.

3. **Capability model is explicit.**  
   The control plane must know what a mobile client can and cannot do.

4. **No secret-bearing logs.**  
   Debug convenience is not a valid reason to leak sensitive state.

5. **No silent security downgrades.**  
   Fallback from stronger storage or trust must be visible and policy-aware.

6. **No packet-by-packet high-level FFI.**  
   Keep hot data paths tight.

7. **No unsupported platform assumptions.**  
   Especially around key storage, always-on behavior, and background execution.

8. **Store policy is part of engineering.**  
   VPN distribution requirements must be handled during build-out, not at release week.

---

## 22. Concrete first actions

If work begins immediately, the first actions should be:

### Week-0 / first-sprint actions

- create this roadmap in the repo,
- approve the v1 client-only scope,
- create `rustynet-mobile-core`,
- create `rustynet-mobile-ffi`,
- define `CapabilityProfile`, `RouteIntent`, `DnsIntent`, and `SecureStorage`,
- write iOS and Android storage decision notes,
- run packet-path feasibility spikes on both platforms,
- define the support-bundle redaction schema,
- decide whether the first beta requires attestation or only supports it optionally.

### Immediate code-level objectives

- move reusable tunnel/session logic out of daemon-centric code,
- make route and DNS intent library-owned,
- create testable FFI DTOs,
- make mobile target builds green in CI,
- prove a minimal “enroll + connect” slice on one platform before broad UI work.

### Recommended order

1. shared Rust extraction,
2. Android MVP,
3. iOS MVP,
4. hardening and parity,
5. enterprise/advanced features.

Android first is not because iOS is unimportant. It is because Android’s `VpnService` path usually provides a slightly faster path to proving the Rust core and packet adapter design before the iOS app-extension boundary is introduced.

---

## 23. Final recommendation

Rustynet should absolutely be able to become a strong Android and iOS product **if** the project treats mobile as a **Rust-first client platform adaptation effort**, not as a thin UI over existing host scripts.

The best path is:

- preserve the current Rust core direction,
- extract more shared logic from daemon/CLI ownership,
- build dedicated Android and Apple backends,
- keep the native wrappers narrow,
- design storage and capability truth explicitly,
- and gate release on real lifecycle, trust, and leak testing.

The most important thing not to get wrong is this:

**The success of Rustynet mobile will depend less on “can Rust compile for phones?” and more on whether the team preserves one source of security truth in Rust while honestly respecting Android and iOS platform boundaries.**

---

## 24. Reference checklist for implementation owners

### Architecture owners

- [ ] Approve client-only v1 scope
- [ ] Approve capability model
- [ ] Approve FFI strategy
- [ ] Approve route/DNS intent ownership in Rust

### Security owners

- [ ] Approve iOS keychain strategy
- [ ] Approve Android keystore wrapping strategy
- [ ] Approve log redaction policy
- [ ] Approve attestation posture
- [ ] Approve backup/restore and re-enrollment semantics

### Platform owners

- [ ] Android packet-path spike completed
- [ ] iOS packet tunnel spike completed
- [ ] App Group model completed
- [ ] Play/App Store packaging constraints recorded

### Release owners

- [ ] Mobile CI targets green
- [ ] SBOM/provenance pipeline defined
- [ ] store disclosure requirements drafted
- [ ] upgrade/migration tests defined

---

## 25. Sources and verification references

### Rustynet repository state

- Rustynet repository root and workspace layout:  
  `https://github.com/Iwan-Teague/Rustynet`
- Rustynet README:  
  `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/README.md`
- Phase 5 release readiness summary:  
  `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md`
- Master work plan:  
  `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/documents/operations/active/MasterWorkPlan_2026-03-22.md`
- Active operations index:  
  `https://raw.githubusercontent.com/Iwan-Teague/Rustynet/main/documents/operations/active/README.md`

### Android official references

- Android VPN guide:  
  `https://developer.android.com/develop/connectivity/vpn`
- `VpnService.Builder` reference:  
  `https://developer.android.com/reference/android/net/VpnService.Builder`
- Android Keystore system:  
  `https://developer.android.com/privacy-and-security/keystore`
- Network Security Configuration:  
  `https://developer.android.com/privacy-and-security/security-config`
- Security with network protocols:  
  `https://developer.android.com/privacy-and-security/security-ssl`
- Play Integrity API:  
  `https://developer.android.com/google/play/integrity`
- Google Play `VpnService` policy guidance:  
  `https://support.google.com/googleplay/android-developer/answer/12564964`
- Doze and App Standby:  
  `https://developer.android.com/training/monitoring-device-state/doze-standby`
- App Standby Buckets:  
  `https://developer.android.com/topic/performance/appstandby`
- Hardware-backed Keystore / AOSP security background:  
  `https://source.android.com/docs/security/features/keystore`
- Android Rust introduction (AOSP):  
  `https://source.android.com/docs/setup/build/rust/building-rust-modules/overview`

### Apple official references

- Packet tunnel provider overview:  
  `https://developer.apple.com/documentation/networkextension/packet-tunnel-provider`
- `NEPacketTunnelProvider`:  
  `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider`
- `packetFlow`:  
  `https://developer.apple.com/documentation/networkextension/nepackettunnelprovider/packetflow`
- `NEPacketTunnelNetworkSettings`:  
  `https://developer.apple.com/documentation/networkextension/nepackettunnelnetworksettings`
- `NETunnelProviderManager`:  
  `https://developer.apple.com/documentation/networkextension/netunnelprovidermanager`
- `NETunnelProviderSession`:  
  `https://developer.apple.com/documentation/networkextension/netunnelprovidersession`
- Configuring network extensions:  
  `https://developer.apple.com/documentation/xcode/configuring-network-extensions`
- Network Extension overview:  
  `https://developer.apple.com/documentation/networkextension`
- Keychain Services:  
  `https://developer.apple.com/documentation/security/keychain-services`
- Storing keys in the Keychain:  
  `https://developer.apple.com/documentation/security/storing-keys-in-the-keychain`
- Restricting keychain item accessibility:  
  `https://developer.apple.com/documentation/security/restricting-keychain-item-accessibility`
- `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`:  
  `https://developer.apple.com/documentation/security/ksecattraccessibleafterfirstunlockthisdeviceonly`
- `kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly`:  
  `https://developer.apple.com/documentation/security/ksecattraccessiblewhenpasscodesetthisdeviceonly`
- App Transport Security / preventing insecure connections:  
  `https://developer.apple.com/documentation/security/preventing-insecure-network-connections`
- ATS configuration:  
  `https://developer.apple.com/documentation/bundleresources/information-property-list/nsapptransportsecurity`
- App Groups:  
  `https://developer.apple.com/documentation/xcode/configuring-app-groups`
- App extension guidance:  
  `https://developer.apple.com/library/archive/documentation/General/Conceptual/ExtensibilityPG/ExtensionScenarios.html`
- App Attest:  
  `https://developer.apple.com/documentation/devicecheck/preparing-to-use-the-app-attest-service`
  and  
  `https://developer.apple.com/documentation/devicecheck/establishing-your-app-s-integrity`

### Rust official references

- Rust platform support:  
  `https://doc.rust-lang.org/nightly/rustc/platform-support.html`
- Rust cross-compilation:  
  `https://rust-lang.github.io/rustup/cross-compilation.html`
- Rust linkage / `staticlib` and `cdylib`:  
  `https://doc.rust-lang.org/reference/linkage.html`

### Rust/mobile binding reference

- UniFFI user guide:  
  `https://mozilla.github.io/uniffi-rs/latest/`

### WireGuard protocol references

- WireGuard protocol and cryptography:  
  `https://www.wireguard.com/protocol/`
- WireGuard official repositories overview:  
  `https://www.wireguard.com/repositories/`
- WireGuard Android project README:  
  `https://github.com/WireGuard/wireguard-android/blob/master/README.md`
- WireGuard Apple project README/about:  
  `https://git.zx2c4.com/wireguard-apple/about/`

### Security verification references

- OWASP MASVS:  
  `https://mas.owasp.org/MASVS/`
- OWASP MAS project overview:  
  `https://owasp.org/www-project-mobile-app-security/`
- OWASP MASTG:  
  `https://github.com/OWASP/mastg`

### Supply-chain references

- SLSA:  
  `https://slsa.dev/`
- CISA SBOM overview:  
  `https://www.cisa.gov/sbom`

---

## 26. Suggested follow-on documents

After this roadmap is added, the next useful documents would be:

1. `documents/architecture/mobile/MobileCapabilityModel.md`
2. `documents/architecture/mobile/MobileSecureStorageDecision.md`
3. `documents/architecture/mobile/MobileFfiStrategy.md`
4. `documents/architecture/mobile/AndroidBackendPlan.md`
5. `documents/architecture/mobile/AppleBackendPlan.md`
6. `documents/architecture/mobile/MobileReleaseGates.md`
7. `documents/architecture/mobile/MobileThreatModel.md`

