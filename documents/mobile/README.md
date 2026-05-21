# Mobile Docs Index

This folder holds future-facing Rustynet mobile planning material.

Classification:

- these documents are architecture and roadmap references
- they are not current release-blocking ledgers
- they do not override the current active implementation priorities for the
  desktop/server runtime

Current documents:

- [RustynetMobileArchitectureDesign_2026-04-17.md](./RustynetMobileArchitectureDesign_2026-04-17.md)
- [RustynetMobileRoadmap_2026-04-17.md](./RustynetMobileRoadmap_2026-04-17.md)

Imported bundle preserved intact:

- [rustynet_mobile_docs_bundle_2026-04-17/00_BundleIndex_2026-04-17.md](./imported/rustynet_mobile_docs_bundle_2026-04-17/00_BundleIndex_2026-04-17.md)

Bundle notes:

- the imported bundle is preserved as-is under `documents/mobile/imported/`
- it contains lower-level implementation scaffold, security, FFI, lifecycle,
  Android, iOS, and open-work files in the original numeric bundle order
- the imported bundle is reference material; current repo source-of-truth rules
  still apply

Rules:

- keep mobile docs Rust-first and security-first
- do not let mobile planning weaken current repository source-of-truth rules
- if mobile work becomes active implementation work, add the owning plan to the
  appropriate active-ledger index

## Anchor Node Role (iOS and Android are bootstrap-clients only)

The anchor node role
([`operations/active/AnchorNodeRoleDesign_2026-05-21.md`](../operations/active/AnchorNodeRoleDesign_2026-05-21.md))
is a host-side runtime role for always-on peers that publish a stable
bootstrap target on the LAN. iOS and Android **cannot host** any
anchor capability:

- `NEPacketTunnelProvider` (iOS) and Android `VpnService` lifecycles
  do not provide reliable 24/7 background residency
- mobile addresses change too frequently to anchor (Wi-Fi/cellular
  handoff, NAT churn)
- mobile sandboxing prevents LAN-exposed listener bind on arbitrary
  ports

Mobile clients **consume** anchor services:

- `rustynet-mobile-core` carries an `anchor_bundle_pull_client`
  module that performs the same single-use-token bundle-pull as the
  `rustynet anchor pull-bundle` CLI verb
- the FFI surface stays narrow: callable from iOS Swift and Android
  Kotlin shells; signed-bundle verification is identical to the
  desktop path
- mobile UI surfaces anchor metadata read-only so the operator can
  pick a sensible first-contact target

See the architecture and roadmap files in this folder for how this
fits into the broader mobile crate split (`rustynet-mobile-core`,
`rustynet-mobile-ffi`).
