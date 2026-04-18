# Rustynet Mobile Platform Roadmap

Status: proposed roadmap reference
Date: 2026-04-17

## Purpose

This document preserves the useful mobile roadmap research that was living in
Downloads and makes it part of the repository docs tree.

It is a roadmap, not a promise of immediate implementation.

## Executive Summary

The right v1 mobile goal is:

- a secure Android client
- a secure iOS client
- backed by a shared Rust core
- wrapped by small native shells for lifecycle, VPN APIs, secure storage, and
  UI

The wrong goal is:

- port the current daemon/service/bootstrap shell surfaces directly
- make mobile devices behave like miniature Linux hosts
- re-implement core security logic in Kotlin and Swift out of convenience

## Recommended v1 Product Scope

The first mobile release should focus on:

- device enrollment into an existing Rustynet deployment
- connect / disconnect
- policy-controlled full-tunnel or split-tunnel routing
- managed DNS / Magic DNS where supported by the control plane
- remote-exit use where the server-side path is already ready
- reconnect after network changes
- bounded diagnostics and support bundles

## Deferred Scope

The following should be deferred unless there is a hard product requirement:

- mobile as relay host
- mobile as exit node
- mobile as blind-exit host
- full administrator console on-device
- VM-lab/live-lab features
- shell/bootstrap orchestration on-device

## Why The Scope Must Stay Tight

Mobile operating systems provide VPN client APIs, not general-purpose homelab
host APIs.

A secure first release should optimize for:

- client correctness
- security clarity
- lifecycle reliability
- minimum privileged complexity

## Product Milestones

### M0: design and extraction

- define mobile crate split
- define FFI contract
- define secure storage boundary
- define capability model for mobile

### M1: Android proof of concept

- Android app shell
- `VpnService` integration
- Rust core bootstrap and connect/disconnect baseline

### M2: iOS proof of concept

- containing app + packet tunnel extension
- Rust core integration
- connect/disconnect baseline

### M3: shared client capability baseline

- enrollment
- signed config ingestion
- split/full tunnel policy application
- DNS behavior
- diagnostics baseline

### M4: hardening

- reconnect and roaming behavior
- secure storage review
- support bundle redaction
- lifecycle and battery behavior validation

### M5: release readiness

- mobile build and artifact verification
- CI coverage
- platform validation matrix
- app-store / entitlement readiness

## Engineering Rules For Mobile

1. keep shared logic in Rust
2. keep native wrappers thin
3. do not import host-runtime assumptions from `rustynetd` and `rustynet-cli`
4. do not weaken the repository security bar for mobile convenience
5. do not promise mobile roles the platform is not ready to support

## Dependencies On The Core Project

Mobile planning can begin now, but mobile release work should not outrun core
project truth.

In particular:

- unfinished server/runtime evidence on desktop/server hosts should be treated
  as a dependency risk
- mobile should reuse stable core seams, not unstable convenience paths

## Mobile-Specific Risk Areas

- Android battery/background execution behavior
- iOS entitlement and extension lifecycle complexity
- native secure storage integration
- FFI contract stability
- DNS behavior differences between platforms
- app-store review and distribution constraints

## Success Criteria For A Real Mobile v1

Mobile v1 is only honestly ready when:

- enrollment is reliable
- tunnel connect/disconnect is reliable
- routing and DNS behavior are correct
- reconnect after normal network changes works
- diagnostics are actionable and redacted
- CI/build/release flow exists
- platform-specific packaging and entitlement requirements are satisfied

Until then, mobile planning should stay documented as future architecture and
roadmap work.
