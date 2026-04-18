# Rustynet Mobile Documentation Bundle Index

**Date:** 2026-04-17  
**Suggested repo path:** `documents/architecture/mobile/BundleIndex_2026-04-17.md`  
**Status:** Working bundle index for Android + iOS mobile planning  
**Audience:** Rustynet maintainers, mobile engineers, security reviewers, release engineers

---

## 1. What this bundle is

This bundle is a companion set of documents for planning and implementing Rustynet as a mobile client on **Android** and **iOS**.

It is intentionally layered:

1. a product and delivery roadmap,
2. a mid-level architecture design,
3. lower-level implementation and file-layout documents,
4. security requirements that remain binding across all files,
5. per-platform file maps and function inventories.

The goal is to give a future implementation effort enough grounded detail that work can begin without inventing a new architecture on the fly.

---

## 2. Current repository truth this bundle assumes

At the time this bundle was prepared, the public Rustynet repository shows:

- a Rust workspace with crates for control, crypto, DNS zone, policy, relay, daemon, CLI, backend API, backend WireGuard, and a backend stub,
- a current project focus on production traversal/relay transport plus fresh release evidence,
- no Android application modules,
- no iOS application or extension targets,
- no mobile-specific backend or FFI crate in the workspace yet.

That means mobile work should be treated as a **new platform adaptation layer on top of existing Rust crates**, not a small patch to the existing daemon or shell-wrapper environment.

---

## 3. Recommended reading order

Read these in this order:

1. `01_RustynetMobileRoadmap_2026-04-17.md`  
   What the mobile product should be, what to ship first, and what not to ship first.
2. `02_RustynetMobileArchitectureDesign_2026-04-17.md`  
   The shared architecture, crate boundaries, native wrapper model, and top-level repository structure.
3. `03_RustynetMobileImplementationScaffold_2026-04-17.md`  
   The proposed repository tree, important files, crate/module ownership, and concrete scaffolding.
4. `04_RustynetMobileSecurityRequirements_2026-04-17.md`  
   The non-negotiable security rules that every file and feature must follow.
5. `05_RustynetMobileFfiContract_2026-04-17.md`  
   The Rust/native boundary, exported functions, handle model, memory ownership, and unsafe-code containment.
6. `06_RustynetMobileConnectionLifecycle_2026-04-17.md`  
   How a mobile device enrolls, connects, roams, updates peer state, and shuts down safely.
7. `07_RustynetAndroidFileSpec_2026-04-17.md`  
   Android-specific files, classes, functions, and platform-security requirements.
8. `08_RustynetIOSFileSpec_2026-04-17.md`  
   iOS-specific files, targets, functions, extension rules, and platform-security requirements.
9. `09_OpenWorkIndex_2026-04-17.md`  
   The separate cross-repo index of open Rustynet work outside the mobile effort.

---

## 4. What is new in this bundle

The roadmap and architecture documents already describe the product and system shape at a high-to-mid level.

This bundle adds five lower-level documents that answer the next set of implementation questions:

- **What new crates and directories should exist?**
- **What exact files should live under Android and iOS?**
- **Which functions belong in Rust versus Kotlin/Swift?**
- **How should secrets move through the app, and where must they never appear?**
- **How should the Rust/native FFI boundary be shaped so that Rust remains the core implementation language?**
- **How should enrollment, tunnel setup, routing, DNS, peer updates, roaming, and shutdown be divided across files?**

---

## 5. Design assumptions that remain consistent across the bundle

These documents all assume the following:

- **Rust remains the implementation center of gravity.** Shared protocol, policy, crypto, state-machine, signed-state verification, and connection orchestration stay in Rust.
- **Android and iOS own only platform surfaces.** Kotlin and Swift own UI, lifecycle, permission prompts, OS VPN APIs, notifications, secure storage adapters, and packaging.
- **Mobile v1 is a client product, not a full host role.** Phones are not v1 relay nodes, exit nodes, or signing authorities.
- **The current repo’s host runtime is not directly portable.** `rustynetd`, `start.sh`, VM-lab wrappers, and desktop/server bootstrap flows are not the mobile runtime model.
- **Security rules outrank convenience.** Secret handling, logging limits, backup exclusion, and FFI review constraints must be treated as first-class architecture requirements.

---

## 6. Key hidden questions this bundle is designed to surface early

This bundle is also meant to force early decisions on issues that otherwise become late blockers:

- How will mobile fit into a workspace that currently forbids `unsafe_code`, when a real FFI layer usually needs a tiny amount of reviewed unsafe code?
- Which secrets must be available while the device is locked, and which must be `ThisDeviceOnly` / non-restorable?
- How will Android tunnel sockets be protected from VPN recursion before Rust begins transport work?
- How will iOS packet-tunnel extension-safe rules shape shared code and frameworks?
- Which existing Rustynet trust artifacts can be reused directly, and which require a mobile-safe transport or storage adapter?
- Which server-side features must be stable before mobile beta is credible?

---

## 7. Suggested repository placement

If added to the repo, the documents fit cleanly under:

```text
documents/
  architecture/
    mobile/
      BundleIndex_2026-04-17.md
      RustynetMobileRoadmap_2026-04-17.md
      RustynetMobileArchitectureDesign_2026-04-17.md
      RustynetMobileImplementationScaffold_2026-04-17.md
      RustynetMobileSecurityRequirements_2026-04-17.md
      RustynetMobileFfiContract_2026-04-17.md
      RustynetMobileConnectionLifecycle_2026-04-17.md
      RustynetAndroidFileSpec_2026-04-17.md
      RustynetIOSFileSpec_2026-04-17.md
```

---

## 8. Source hierarchy used for this bundle

When there is tension between sources, use them in this order:

1. **Current Rustynet repository truth** (workspace layout, README, active ledgers, current crate seams)
2. **Official platform documentation** from Google / Android Developers and Apple Developer
3. **Official Rust documentation** (`rustc`, Cargo, Rust Reference, Rustonomicon)
4. **Official WireGuard documentation and official project repositories**
5. **OWASP MASVS / MASTG** for mobile security verification and testing baselines

---

## 9. Bottom line

The roadmap and architecture documents explain *why* mobile Rustynet should be built a certain way.

The lower-level documents in this bundle are meant to answer *how* that work should be broken down into crates, targets, files, functions, security rules, and platform-specific responsibilities.

They are detailed enough to support design review, task planning, and early implementation, while still stopping short of pretending that the exact final code has already been written.
