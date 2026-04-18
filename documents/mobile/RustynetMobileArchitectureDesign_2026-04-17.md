# Rustynet Mobile Architecture Design

Status: proposed architecture reference
Date: 2026-04-17

## Purpose

This document preserves the useful mobile architecture research that was living
in Downloads and makes it part of the repository docs tree.

It is intentionally scoped as a design reference for future Android and iOS
client work. It does not change current active priorities.

## Core Design Conclusion

Rustynet on mobile should be built as:

- a first-class Android client
- a first-class iOS client
- both powered by a shared Rust core
- both wrapped by thin native platform shells

The wrong approach is to port the current host-oriented daemon and shell
surfaces wholesale onto phones.

## Current Repo Truth That Shapes Mobile Design

Useful reusable seams already exist:

- `crates/rustynet-backend-api`
- `crates/rustynet-backend-wireguard`
- `crates/rustynet-control`
- `crates/rustynet-crypto`
- `crates/rustynet-dns-zone`
- `crates/rustynet-policy`
- `crates/rustynet-relay`

Host-oriented surfaces should not be treated as the mobile baseline:

- `crates/rustynetd`
- `crates/rustynet-cli`
- shell/bootstrap/service-manager flows
- VM-lab/live-lab orchestration

Conclusion:

- reuse the Rust core
- replace the host lifecycle layer
- do not copy Linux/macOS/Windows host assumptions into mobile

## Recommended Repository Structure

```text
documents/mobile/
mobile/android/
mobile/ios/
crates/rustynet-mobile-core/
crates/rustynet-mobile-ffi/
crates/rustynet-backend-android/
crates/rustynet-backend-ios/
scripts/mobile/
```

Why:

- shared Rust logic stays in `crates/`
- native Android/iOS packaging stays under `mobile/`
- mobile planning stays in one docs subtree instead of being scattered through
  active operations ledgers

## Proposed Rust Crate Split

### `rustynet-mobile-core`

Should own:

- signed config ingestion
- local config validation
- connect / reconnect / disconnect state logic
- exit-mode and routing-intent logic
- DNS / Magic DNS state handling that is platform-agnostic
- diagnostics generation and redaction

Should not own:

- Android `VpnService`
- iOS `NEPacketTunnelProvider`
- Kotlin/Swift UI
- direct native keystore/keychain APIs

### `rustynet-mobile-ffi`

Should expose a narrow, versioned FFI surface for:

- initialization
- loading signed config bundles
- start / stop / resume requests
- status snapshots
- diagnostics summaries
- explicit FFI-safe error types

High-level recommendation:

- use a narrow stable FFI contract
- keep internal Rust types out of native callers

### `rustynet-backend-android`

Should adapt Android VPN lifecycle and TUN handling to the backend abstraction.

Native Kotlin/Java should own:

- user consent flow
- `VpnService` lifecycle
- app notifications / foreground-service behavior
- platform secure storage plumbing

### `rustynet-backend-ios`

Should adapt Packet Tunnel Provider lifecycle and packet-flow handling to the
backend abstraction.

Native Swift/ObjC should own:

- `NETunnelProviderManager`
- `NEPacketTunnelProvider`
- app-extension lifecycle
- App Group storage plumbing
- entitlement-managed platform behavior

## Platform Reality Constraints

### Android

Design around:

- `VpnService`
- TUN file descriptor ownership
- route / DNS configuration through the Android VPN builder path
- battery and background execution constraints

### iOS

Design around:

- Packet Tunnel Provider
- app + extension separation
- App Groups for shared state
- entitlement-gated Network Extension APIs

### Shared conclusion

Both platforms imply the same architecture rule:

- OS lifecycle and VPN API ownership stay native
- policy, protocol, crypto, control sync, and tunnel orchestration stay as
  centralized in Rust as practical

## Security Rules For Mobile

Mobile work must keep the current Rustynet bar:

- Rust-first shared logic
- proven crypto only
- OS-secure storage where available
- fail-closed behavior on missing or stale trust/config state
- no shell/bootstrap assumptions
- no host-service-manager assumptions
- narrow native wrappers

Additional mobile-specific expectations:

- explicit handling of background/lifecycle interruption
- strong separation between client app and privileged tunnel entry points
- bounded diagnostics with secret redaction

## Suggested Implementation Phases

### Phase 1

- mobile crate extraction plan
- FFI contract design
- backend capability design for mobile

### Phase 2

- Android wrapper spike
- iOS wrapper spike
- secure storage abstraction design

### Phase 3

- mobile connect/disconnect baseline
- config ingestion
- DNS and routing-intent path

### Phase 4

- policy and exit-mode behavior
- reconnect and network-change handling
- diagnostics and support bundle path

### Phase 5

- CI/build/release pipeline
- mobile validation matrix
- store-distribution and entitlement readiness

## Non-Goals For Early Mobile Work

Do not start by making phones into:

- relay nodes
- exit nodes
- control-plane hosts
- mobile replacements for VM-lab/live-lab tools
- full admin consoles

The first correct mobile product is a secure mobile client.
