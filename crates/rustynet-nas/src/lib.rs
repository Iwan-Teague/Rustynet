#![forbid(unsafe_code)]

//! `rustynet-nas` — the NAS sibling service for the `nas`
//! service-hosting role (D13.c).
//!
//! Canonical design:
//! `documents/operations/active/NasNodeRoleDesign_2026-06-11.md`.
//!
//! This crate is deliberately a **thin, hardened wrapper**: it owns
//! the content-addressed backup protocol ([`protocol`]), the
//! AEAD-encrypted per-peer object store ([`store`]), and health
//! reporting ([`health`]). It does NOT authenticate peers (the
//! daemon hands it verified identities — see
//! `rustynetd::service_exposure`), does NOT terminate TLS (the
//! tunnel is the secure channel), does NOT implement a filesystem
//! or replication, and never opens a LAN/public listener.
//!
//! Fail-closed posture: missing/insecure data root, unavailable
//! at-rest key, malformed wire input, quota breach, and
//! cross-namespace access all refuse — never degrade.

pub mod health;
pub mod protocol;
pub mod store;

/// Default NAS service port on the tunnel interface (NAS design §4;
/// configurable, but the listener address is always tunnel-only).
pub const DEFAULT_NAS_PORT: u16 = 51823;
