#![forbid(unsafe_code)]

//! `rustynet-llm-gateway` — the inference gateway for the `llm`
//! service-hosting role (D13.d).
//!
//! Canonical design:
//! `documents/operations/active/LlmNodeRoleDesign_2026-06-11.md`.
//!
//! Topology (LLM design §3.1): the gateway is the only mesh-facing
//! process, bound to the tunnel address; the inference engine runs
//! behind a process boundary on host loopback only and is never
//! reachable from the tunnel or the LAN. The gateway:
//!
//! - takes the caller identity ONLY from the daemon's verified
//!   handoff (`rustynetd::service_exposure::VerifiedPeerIdentity`) —
//!   client-supplied identity headers and API keys are ignored;
//!   there is no API key anywhere in this contract;
//! - admits a stream only under a `Decision::Allow` from signed
//!   policy for `TrafficContext::LlmService` (default-deny);
//! - enforces the admin's per-peer model allow-list, token quota,
//!   and request rate ([`enforce`], scoped by
//!   `rustynet_policy::LlmAccessScope` — restrictions on a grant,
//!   never a grant source);
//! - may issue a short-lived, single-audience, node-signed session
//!   token ([`session`]) as defence-in-depth; the token is
//!   re-checked against current signed policy on every use and can
//!   never exceed what policy allows;
//! - streams completion tokens over a persistent, length-bounded
//!   binary framing ([`protocol`]) as plaintext **inside** the
//!   WireGuard tunnel — the tunnel is the crypto; no second TLS
//!   layer, no per-request handshake.
//!
//! Logs and audit events carry ids, thumbprints, and counts only —
//! never prompts, completions, uploaded context, or tokens.

pub mod enforce;
pub mod engine;
pub mod health;
pub mod protocol;
pub mod session;

/// Default LLM gateway port on the tunnel interface (configurable;
/// the listener address is always tunnel-only).
pub const DEFAULT_LLM_GATEWAY_PORT: u16 = 51824;
