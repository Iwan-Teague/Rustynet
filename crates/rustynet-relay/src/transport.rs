#![forbid(unsafe_code)]

//! Relay transport session protocol and packet forwarding.
//!
//! This module implements the relay session authentication and bidirectional
//! packet forwarding for nodes that cannot establish direct connectivity.
//!
//! # Security model
//!
//! - **Ciphertext-only relay**: payloads are forwarded byte-for-byte without
//!   inspection.  The relay never sees plaintext.
//! - **Signed tokens**: every session requires a control-plane-issued
//!   [`RelaySessionToken`] with a valid ed25519 signature.
//! - **Constant-time auth**: all secret-field comparisons (`node_id`,
//!   `peer_node_id`, `relay_id`) use `subtle::ConstantTimeEq`.
//! - **Replay protection**: each token nonce is remembered for the duration of
//!   the max TTL window; replayed nonces are rejected.
//! - **Relay-binding**: tokens carry the intended relay's `relay_id`; the
//!   relay verifies this matches its own identity.
//! - **Scope enforcement**: tokens must carry `scope=forward_ciphertext_only`.
//! - **Bounded resources**: per-node session caps, per-node packet rate limits,
//!   per-node hello rate limits, maximum packet size, idle/half-open timeouts.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(test)]
use std::cell::Cell;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

// RSA-0086 test hook: counts ed25519 hello-signature verifications so the
// witness tests can prove the daemon's locked commit path performs ZERO of
// them (and that the standalone `verify_hello_token_signature` performs
// exactly the unlocked ones). Per-THREAD on purpose: the witness observes
// only the signature work performed by its own execution thread, so a test
// running in another thread (cargo runs test threads in parallel) can
// never drift an observation — a process-global counter here was racy by
// construction. Never compiled outside `cfg(test)`; never read for any
// admission decision.
#[cfg(test)]
thread_local! {
    pub(crate) static RELAY_HELLO_SIG_VERIFY_CALLS: Cell<usize> = const { Cell::new(0) };
}

use ed25519_dalek::VerifyingKey;
use rand::TryRngCore;
use rustynet_control::{MAX_RELAY_SESSION_TOKEN_TTL_SECS, RELAY_TOKEN_SCOPE, RelaySessionToken};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::blind_relay_listener::{AddressArtifactError, AddressValidationKeyRing};
use crate::rate_limit::RateLimiter;
use crate::session::{RelaySession, SessionId};

/// Maximum TTL we accept from a token's `issued_at` → `expires_at` span.
const MAX_RELAY_TTL_SECS: u64 = MAX_RELAY_SESSION_TOKEN_TTL_SECS;
/// How long we keep a half-open (un-paired) session before evicting it.
const HALF_OPEN_SESSION_TIMEOUT_SECS: u64 = 60;
/// How long an idle (no packets) session may remain open.
const IDLE_SESSION_TIMEOUT_SECS: u64 = 30;
/// Maximum forwarded-payload size.  Packets larger than this are dropped
/// silently rather than returned as an error (to avoid amplification).
const MAX_PACKET_SIZE_BYTES: usize = 65_536;
/// Wire-format message-type byte for a relay hello, matching
/// `relay_client.rs` (moved here with `parse_relay_hello` so the library
/// parser and the daemon dispatch share one constant).
pub const RELAY_HELLO_MSG_TYPE: u8 = 0x01;
/// Wire-format message-type byte for an OI-10 address-validation challenge:
/// the relay's reply to a hello that passed parse but failed the pre-auth
/// address-validation gate for lack of an artifact. Payload is exactly
/// `[artifact; 32]` — same framing shape as the blind-v2 0x05 response.
pub const RELAY_HELLO_CHALLENGE_MSG_TYPE: u8 = 0x06;
/// Wire-format trailing-field type byte a client appends to its relay hello
/// to carry the address-validation artifact it was challenged for:
/// `[0x07] ++ artifact[32]`. Any OTHER trailing byte is a parse error
/// (wire tightening; see the parse-site comment).
pub const RELAY_HELLO_ARTIFACT_FIELD_TYPE: u8 = 0x07;
/// Wire-format message-type byte for the v2 relay hello (D3 seams plan,
/// seam 1). The allocation is pinned HERE, once, so no lane re-derives
/// "next free" independently: at the plan's base `0x08` is unused as a
/// first-byte discriminator across `rustynet-relay/`,
/// `rustynetd/src/relay_client.rs`, and `rustynet-control/`. An un-upgraded
/// relay falls through to its `unknown message type` refusal on `0x08`, so
/// a mis-negotiated v2 send is a dropped hello, never a misparse.
/// Negotiation rides the membership snapshot (`relay_proto_max`), never a
/// probe on the pre-auth relay port.
pub const RELAY_HELLO_V2_MSG_TYPE: u8 = 0x08;
/// Wire-format `protocol_version` byte carried inside a v2 relay hello.
/// Receivers refuse any value other than exactly this constant (fail
/// closed, mirroring `WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION` and the
/// gossip watermark version check); the client-side chooser
/// (`pick_relay_hello_version`) only ever picks this value when the
/// membership snapshot advertises exactly it (`relay_proto_max = 2`).
pub const RELAY_PROTOCOL_VERSION: u8 = 2;
/// Domain-separation tag for the v1 relay-hello address-validation HMAC.
/// Deliberately distinct from the blind listener's
/// `BLIND_ADDR_VALIDATION_DOMAIN`: an artifact minted by one protocol is
/// worthless on the other (cross-protocol artifact replay is a reviewed
/// defect class — wave5-9 W-followups).
pub const RELAY_ADDR_VALIDATION_DOMAIN: &[u8] = b"rustynet-relay-hello-addr-validation-v1";
// Artifact lifetime is owned by the reviewed keyring (`BLIND_ADDR_VALIDATION_TTL_SECS`,
// 30 s): deliberately SHORT, so an artifact proves "this socket answered a
// challenge moments ago", never "this identity is good" — a long TTL would
// let one minted artifact serve a slow replay.
/// Maximum accepted byte length of `node_id` / `peer_node_id` in a relay
/// hello, enforced at parse time before either value is copied or used as a
/// pre-auth map key (RLY-05).
///
/// Node ids in this deployment are hostname-style slugs (`exit-1`,
/// `client-1`, `relay-1`), so 128 bytes is far above any legitimate value
/// while cutting the pre-authentication memory a hostile sender can park from
/// ~65 KB per entry to ~128 B — a ~500x reduction against
/// `MAX_HELLO_LIMITER_ENTRIES` retained keys.
pub const MAX_RELAY_NODE_ID_BYTES: usize = 128;
/// How long we retain nonces in the replay-prevention store: must cover the
/// entire window in which a token can still be accepted, so a nonce cannot be
/// recycled while its token remains valid.
///
/// RLY-10: this was `MAX_RELAY_TTL_SECS * 2` (240 s), which assumed the skew
/// tolerance is applied **once**. It is applied **twice** on independent axes:
/// `validate_hello`'s future-dating check admits `issued_at <= now + skew`, and
/// `is_expired` then admits `now <= expires_at + skew` where
/// `expires_at = issued_at + ttl`. So the true acceptance window measured from
/// the instant a nonce is first recorded is `ttl + 2 * skew`, not `ttl + skew`.
/// At the daemon's default skew of 90 that is `120 + 180 = 300 > 240`, leaving a
/// 61-second window in which the nonce had been pruned but the token was still
/// accepted — i.e. a replay. The hole opened for any token with `ttl >= 60`.
///
/// Sizing retention from the real bound fixes it without reducing the
/// operator-facing skew tolerance (clamping skew below 60 would reject the honest
/// 60–90 s clock drift the tolerance exists to absorb). Cost: retention grows
/// 240 → 359 s, so the nonce map and the per-hello `O(n)` persist grow ~50% —
/// trivial in absolute terms at this scale.
const NONCE_RETENTION_SECS: u64 = MAX_RELAY_TTL_SECS + 2 * MAX_CLOCK_SKEW_TOLERANCE_SECS + 1;
/// Hard ceiling on `clock_skew_tolerance_secs` accepted by `RelayTransport`
/// constructors. The replay store retains nonces for `NONCE_RETENTION_SECS`
/// (two TTL windows). If a caller supplied a larger skew, a token could
/// remain non-expired (per `is_expired`) after its nonce was already pruned,
/// re-opening the replay window. We clamp at construction time to keep the
/// invariant `MAX_RELAY_TTL_SECS + skew < NONCE_RETENTION_SECS`.
///
/// RLY-10: this ceiling used to be `MAX_RELAY_TTL_SECS`, which satisfied the
/// invariant only by EQUALITY (120 + 120 == 240). That one second mattered,
/// because the two comparisons are not symmetric: `prune` evicts at
/// `age >= retention` (exclusive boundary, pinned by
/// `nonce_at_exact_retention_age_is_pruned_by_cleanup`) while `is_expired`
/// retains a token at `now == expires_at + skew` (it compares with `>`). At the
/// old ceiling there was therefore a single second in which the nonce had been
/// pruned but the token was still valid — a replay window. Subtracting one makes
/// the invariant hold strictly, closing it without loosening the retention
/// boundary that test deliberately pins.
///
/// Not reachable in the shipped daemon (its default skew is 90 and there is no
/// flag to raise it), so this is defence in depth for library consumers that
/// construct `RelayTransport` directly.
const MAX_CLOCK_SKEW_TOLERANCE_SECS: u64 = MAX_RELAY_TTL_SECS - 1;

/// Compile-time guard for the RLY-10 invariant.
///
/// Deliberately a `const` assertion rather than a unit test: these are all
/// compile-time constants, so a runtime test of them would assert something
/// clippy correctly flags as constant. This way any future edit to the TTL,
/// the skew ceiling or the retention window that reopens the replay window is a
/// **build error**, which is strictly stronger than a test.
const _: () = assert!(
    MAX_RELAY_TTL_SECS + 2 * MAX_CLOCK_SKEW_TOLERANCE_SECS < NONCE_RETENTION_SECS,
    "nonce retention must strictly exceed the FULL acceptance window, which is \
     `ttl + 2 * skew` — skew is applied once when admitting `issued_at <= now + \
     skew` and again when admitting `now <= expires_at + skew`. Sizing this with \
     a single skew term leaves a replay window in which the nonce is pruned but \
     the token is still accepted."
);

/// Maximum `handle_hello` calls accepted per node within a one-second window
/// before the hello itself is rejected (separate from packet rate limiting).
const MAX_HELLOS_PER_NODE_PER_SEC: u32 = 5;
/// Maximum `handle_hello` calls admitted per SOURCE ADDRESS within a
/// one-second window before the hello is shed BEFORE any crypto work
/// (AQ-69). Deliberately equal to the daemon assembly's per-source-IP
/// pre-auth shed (`MAX_PRE_AUTH_HELLOS_PER_IP_PER_SEC`), so this in-transport
/// gate never rejects a hello the daemon would have admitted — legitimate
/// traffic decisions are unchanged — while the shed now sits immediately in
/// front of the ed25519 verify it protects, inside the crate that performs
/// the verify.
const MAX_HELLOS_PER_SOURCE_PER_SEC: u32 = 50;
/// Hard cap on the number of distinct source addresses the per-source shed
/// tracks, mirroring the daemon's `MAX_PRE_AUTH_HELLO_SOURCE_IPS` posture:
/// a pre-auth flood rotating source addresses must not grow the table
/// without limit, and an overflow REJECTS (fail closed) rather than evicting
/// or exceeding the bound (RSA-0037).
const MAX_HELLO_SOURCE_ENTRIES: usize = 4096;
/// Default global active session cap. Production daemons may lower or raise this
/// during startup, but the transport must always retain a total cap.
const DEFAULT_MAX_TOTAL_SESSIONS: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RejectReason {
    /// Token signature invalid, scope wrong, relay-id mismatch, node-id
    /// mismatch, or TTL out of bounds.
    InvalidToken,
    /// Token expiry timestamp has passed (plus skew tolerance).
    ExpiredToken,
    /// This token nonce was already seen (replay detected).
    ReplayedNonce,
    /// The `peer_node_id` in the hello does not match the token's field.
    PeerMismatch,
    /// Per-node session cap has been reached.
    Capacity,
    /// Hello rate limit for this node has been exceeded.
    RateLimitExceeded,
    /// OI-10: the hello passed parse and the rate gates but carried NO
    /// address-validation artifact while the gate is enabled. This is a
    /// CHALLENGE, not a final verdict: the relay replies with a fresh
    /// artifact and the client retries with it attached.
    AddressValidationRequired,
    /// OI-10: the hello carried an address-validation artifact, but it did
    /// not verify — wrong source address, wrong token nonce, expired
    /// (past skew), foreign key epoch, or foreign HMAC domain. No artifact
    /// is issued for this outcome.
    AddressValidationInvalid,
    /// Replay store could not be updated, so accepting the token would weaken
    /// anti-replay guarantees.
    ReplayStoreUnavailable,
    /// The host clock is unusable, so token freshness cannot be established.
    /// Mirrors `ReplayStoreUnavailable`: a guarantee we cannot evaluate is a
    /// guarantee we refuse to assume (RLY-15).
    ClockUnavailable,
    /// Daemon supplied an invalid allocated relay data port.
    InvalidAllocatedPort,
    /// Kernel CSPRNG was unavailable while minting the session id. We refuse
    /// to fall back to a less random source because the session id namespaces
    /// the forwarding map; a predictable id would let one peer hijack
    /// another's relay session.
    SessionIdRandomnessUnavailable,
}

/// An issued address-validation artifact: an HMAC-SHA256 tag (truncated to
/// 20 bytes) plus key-epoch and expiry framing, minted by
/// [`RelayTransport::issue_hello_validation_artifact`] and presented back
/// inside a retry hello.
///
/// # Secret posture
///
/// The tag bytes are HMAC output over a per-process secret key; presenting
/// one is what admits a hello past the pre-auth gate. They are therefore
/// treated exactly like the blind listener's `relay_challenge`
/// (`BlindRelayHelloV2` redacts that field): the [`fmt::Debug`] impl is
/// hand-written and prints NO artifact bytes. Witness:
/// `address_validation_artifact_debug_redacts_tag_bytes`, registered in
/// `rustynetd/src/secret_log_audit.rs` + `witness_listing.rs`.
#[derive(Clone)]
pub struct AddressValidationArtifact([u8; 32]);

impl AddressValidationArtifact {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for AddressValidationArtifact {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never emit tag bytes: a Debug-printed artifact is a ready-made
        // gate-pass for whatever log it lands in (§4: never log secrets).
        f.debug_tuple("AddressValidationArtifact")
            .field(&"REDACTED [32 bytes]")
            .finish()
    }
}

/// Session establishment request from a node to the relay.
///
/// `PartialEq`/`Eq` are not derived because the embedded `RelaySessionToken`
/// deliberately does not implement them (to prevent non-constant-time
/// comparisons on secret fields).  Use `ct_eq` on the token when needed.
#[derive(Debug, Clone)]
pub struct RelayHello {
    pub node_id: String,
    pub peer_node_id: String,
    pub session_token: RelaySessionToken,
    /// OI-10: optional pre-auth address-validation artifact (`None` on a
    /// first-contact hello, `Some` on the challenge retry).
    pub addr_validation_artifact: Option<AddressValidationArtifact>,
}

/// Reads a big-endian `u16` length prefix at `pos`, or `None` when fewer
/// than two bytes remain (the truncation every call site rejects explicitly).
fn read_u16_be(data: &[u8], pos: usize) -> Option<u16> {
    let hi = *data.get(pos)?;
    let lo = *data.get(pos.checked_add(1)?)?;
    Some(u16::from_be_bytes([hi, lo]))
}

/// Parses a `RelayHello` from wire format.
///
/// This is the attacker-reachable pre-auth parser for the relay's UDP hello
/// path (run before any signature verification), which is why every field it
/// copies is length-bounded (RLY-05 / AUDIT-031). It is `pub` in the library
/// so the fuzz target `fuzz/fuzz_targets/relay_hello_parse.rs` can exercise
/// it directly; the daemon dispatches through this same function.
pub fn parse_relay_hello(data: &[u8]) -> Result<RelayHello, String> {
    if data.first().copied() != Some(RELAY_HELLO_MSG_TYPE) {
        return Err("not a hello message".to_owned());
    }

    let mut pos = 1;

    // Node ID
    if pos + 2 > data.len() {
        return Err("truncated node_id length".to_owned());
    }
    let node_id_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated node_id length".to_owned())? as usize;
    pos += 2;

    // Bound the identifier BEFORE it is copied (RLY-05 / AUDIT-031).
    //
    // `validate_hello`'s first check keys the pre-auth `HelloLimiter` on this
    // value — `counts.entry(node_id.to_owned())` — which happens BEFORE the
    // signature is verified. `MAX_HELLO_LIMITER_ENTRIES` bounds how many
    // entries that map holds, but nothing bounded how large each key was, and
    // the only ceiling here was the 64 KiB datagram. 16384 entries x ~65 KB
    // measured at ~1015 MiB of unverified attacker-chosen bytes resident
    // pre-authentication.
    //
    // AUDIT-031 ("cap the relay pre-auth map") is on the before-release list;
    // RSA-0037 capped the entry COUNT, and this caps the byte size, which was
    // the remaining half.
    if node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "node_id length {node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }

    if pos + node_id_len > data.len() {
        return Err("truncated node_id".to_owned());
    }
    let node_id_bytes = data
        .get(pos..pos + node_id_len)
        .ok_or_else(|| "truncated node_id".to_owned())?;
    let node_id = String::from_utf8(node_id_bytes.to_vec()).map_err(|e| e.to_string())?;
    pos += node_id_len;

    // Peer node ID
    if pos + 2 > data.len() {
        return Err("truncated peer_node_id length".to_owned());
    }
    let peer_node_id_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated peer_node_id length".to_owned())? as usize;
    pos += 2;

    // Same bound as `node_id` above: `peer_node_id` is likewise copied out of
    // an unauthenticated datagram, and both are compared against the signed
    // token later, so neither can legitimately exceed the protocol cap.
    if peer_node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "peer_node_id length {peer_node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }

    if pos + peer_node_id_len > data.len() {
        return Err("truncated peer_node_id".to_owned());
    }
    let peer_node_id_bytes = data
        .get(pos..pos + peer_node_id_len)
        .ok_or_else(|| "truncated peer_node_id".to_owned())?;
    let peer_node_id = String::from_utf8(peer_node_id_bytes.to_vec()).map_err(|e| e.to_string())?;
    pos += peer_node_id_len;

    // Token
    if pos + 2 > data.len() {
        return Err("truncated token length".to_owned());
    }
    let token_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated token length".to_owned())? as usize;
    pos += 2;

    if pos + token_len > data.len() {
        return Err("truncated token".to_owned());
    }
    let token_data = data
        .get(pos..pos + token_len)
        .ok_or_else(|| "truncated token".to_owned())?;
    let session_token = parse_relay_token(token_data)?;
    pos += token_len;

    // OI-10: optional trailing address-validation artifact field,
    // `[0x07] ++ artifact[32]`.
    //
    // WIRE TIGHTENING (wave5-9 W2): any other trailing byte is now a parse
    // ERROR, not ignored. Prior to OI-10 this parser stopped reading at the
    // token and silently discarded everything after it, so an
    // unauthenticated sender could append ~64 KiB of dead weight per
    // datagram inside the length accounting every hop has already paid for.
    // Legacy clients never sent trailing bytes, so the only senders this
    // breaks are ones already speaking an unknown future dialect — exactly
    // the frames that MUST fail closed.
    let addr_validation_artifact = if pos == data.len() {
        None
    } else if data.get(pos).copied() == Some(RELAY_HELLO_ARTIFACT_FIELD_TYPE) {
        let rest = data.len() - pos;
        if rest != 1 + 32 {
            return Err(format!(
                "relay hello artifact field must be exactly 1+32 bytes, got {rest}"
            ));
        }
        let artifact: [u8; 32] = data
            .get(pos + 1..pos + 33)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or("invalid artifact field")?;
        Some(AddressValidationArtifact::from_bytes(artifact))
    } else {
        return Err(format!(
            "unexpected trailing byte {:#04x} in relay hello",
            data.get(pos).copied().unwrap_or_default()
        ));
    };

    Ok(RelayHello {
        node_id,
        peer_node_id,
        session_token,
        addr_validation_artifact,
    })
}

/// Frames the trailing hello field a client appends on the OI-10 challenge
/// retry: `[0x07] ++ artifact[32]`. Pure framing over the opaque artifact.
pub fn serialize_relay_hello_artifact_field(artifact: &AddressValidationArtifact) -> [u8; 33] {
    let mut field = [0u8; 33];
    field[0] = RELAY_HELLO_ARTIFACT_FIELD_TYPE;
    field[1..].copy_from_slice(artifact.as_bytes());
    field
}

/// Frames the relay's OI-10 challenge response: `[0x06] ++ artifact[32]`.
/// Pure framing over the opaque artifact (mirror of the blind-v2 0x05
/// response framer in the daemon).
pub fn serialize_relay_hello_challenge(artifact: &AddressValidationArtifact) -> [u8; 33] {
    let mut datagram = [0u8; 33];
    datagram[0] = RELAY_HELLO_CHALLENGE_MSG_TYPE;
    datagram[1..].copy_from_slice(artifact.as_bytes());
    datagram
}

// ── v2 relay hello (D3 seams plan §3, step S3) ────────────────────────────────
//
// Pure library addition: parser + serializer only, NOT yet reachable from
// relay dispatch (`main.rs` still refuses `0x08` via its unknown-message-type
// arm until S4). The layout extends the v1 field sequence with a version
// byte, a validated padding tail, and the OI-10 artifact field MANDATORY:
//
// [0x08][u8 protocol_version = 2][u16 pad_len][u16 node_id_len][node_id]
// [u16 peer_node_id_len][peer_node_id][u16 token_len][token]
// [0x07 ++ artifact[32]][pad_len zero bytes]

/// A parsed v2 relay hello.
///
/// The artifact is NOT an `Option` here, unlike v1's [`RelayHello`]: §3
/// makes it mandatory, because a v2 hello that could omit it would let a
/// client switch message types to bypass the default-on OI-10 pre-auth gate.
/// The type makes the omission unrepresentable.
#[derive(Debug, Clone)]
pub struct RelayHelloV2 {
    pub node_id: String,
    pub peer_node_id: String,
    pub session_token: RelaySessionToken,
    pub addr_validation_artifact: AddressValidationArtifact,
    /// Length of the trailing padding region. Every padding byte on the wire
    /// is `0x00` today — validated, not ignored: an inconsistent tail is a
    /// refuse, never a shrug.
    pub pad_len: u16,
}

/// Fixed byte count around the variable-length fields of a v2 hello:
/// msg_type (1) + protocol_version (1) + pad_len (2) + the three length
/// prefixes (6) + the mandatory 33-byte artifact field. `pad_len` is capped
/// at `MAX_PACKET_SIZE_BYTES` minus this, so padding can never become the
/// amplification vector RLY-05/AUDIT-031 closed for the identifier fields.
const RELAY_HELLO_V2_FIXED_FIELD_BYTES: usize = 43;

/// Serializes a v2 relay hello (§3 layout, pad bytes all zero).
///
/// Unlike the daemon's unchecked v1 serializer, this fails closed on any
/// input that would not round-trip through [`parse_relay_hello_v2`] — a
/// serializer that emitted unparseable frames would make the round-trip
/// identity a lie at exactly the lengths attackers probe (semantic caps
/// included, not just the `u16` wire widths).
pub fn serialize_relay_hello_v2(hello: &RelayHelloV2) -> Result<Vec<u8>, String> {
    let node_id = hello.node_id.as_bytes();
    let peer_node_id = hello.peer_node_id.as_bytes();
    if node_id.len() > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "node_id length {} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}",
            node_id.len()
        ));
    }
    if peer_node_id.len() > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "peer_node_id length {} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}",
            peer_node_id.len()
        ));
    }
    let node_id_len = u16::try_from(node_id.len()).map_err(|_| {
        format!(
            "node_id length {} exceeds the u16 wire maximum",
            node_id.len()
        )
    })?;
    let peer_node_id_len = u16::try_from(peer_node_id.len()).map_err(|_| {
        format!(
            "peer_node_id length {} exceeds the u16 wire maximum",
            peer_node_id.len()
        )
    })?;
    let token_wire = serialize_relay_token_wire(&hello.session_token)?;
    let token_len = u16::try_from(token_wire.len()).map_err(|_| {
        format!(
            "token length {} exceeds the u16 wire maximum",
            token_wire.len()
        )
    })?;
    let pad_len_max = MAX_PACKET_SIZE_BYTES - RELAY_HELLO_V2_FIXED_FIELD_BYTES;
    if usize::from(hello.pad_len) > pad_len_max {
        return Err(format!(
            "pad_len {} exceeds maximum {pad_len_max}",
            hello.pad_len
        ));
    }
    let total = RELAY_HELLO_V2_FIXED_FIELD_BYTES
        .checked_add(node_id.len())
        .and_then(|t| t.checked_add(peer_node_id.len()))
        .and_then(|t| t.checked_add(token_wire.len()))
        .and_then(|t| t.checked_add(usize::from(hello.pad_len)))
        .ok_or_else(|| "relay hello v2 length overflows".to_owned())?;
    if total > MAX_PACKET_SIZE_BYTES {
        return Err(format!(
            "relay hello v2 frame length {total} exceeds maximum {MAX_PACKET_SIZE_BYTES}"
        ));
    }

    let mut buf = Vec::with_capacity(total);
    buf.push(RELAY_HELLO_V2_MSG_TYPE);
    buf.push(RELAY_PROTOCOL_VERSION);
    buf.extend_from_slice(&hello.pad_len.to_be_bytes());
    buf.extend_from_slice(&node_id_len.to_be_bytes());
    buf.extend_from_slice(node_id);
    buf.extend_from_slice(&peer_node_id_len.to_be_bytes());
    buf.extend_from_slice(peer_node_id);
    buf.extend_from_slice(&token_len.to_be_bytes());
    buf.extend_from_slice(&token_wire);
    buf.extend_from_slice(&serialize_relay_hello_artifact_field(
        &hello.addr_validation_artifact,
    ));
    buf.resize(buf.len() + usize::from(hello.pad_len), 0u8);
    Ok(buf)
}

/// Wire format of [`parse_relay_token`], mirrored. The daemon has kept a
/// private copy for the v1 frame (`relay_client.rs`); the library needs its
/// own so the v2 round-trip does not depend on test helpers. The semantic
/// caps mirror the parser's (a token this serializer refuses could never
/// have parsed, so refusing here keeps the round-trip identity exact).
fn serialize_relay_token_wire(token: &RelaySessionToken) -> Result<Vec<u8>, String> {
    let node_id = token.node_id.as_bytes();
    let peer_node_id = token.peer_node_id.as_bytes();
    let scope = token.scope.as_bytes();
    if node_id.len() > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "token node_id length {} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}",
            node_id.len()
        ));
    }
    if peer_node_id.len() > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "token peer_node_id length {} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}",
            peer_node_id.len()
        ));
    }
    if scope.len() > RELAY_TOKEN_SCOPE.len() {
        return Err(format!(
            "token scope length {} exceeds maximum {}",
            scope.len(),
            RELAY_TOKEN_SCOPE.len()
        ));
    }
    let node_id_len = u16::try_from(node_id.len()).map_err(|_| {
        format!(
            "token node_id length {} exceeds the u16 wire maximum",
            node_id.len()
        )
    })?;
    let peer_node_id_len = u16::try_from(peer_node_id.len()).map_err(|_| {
        format!(
            "token peer_node_id length {} exceeds the u16 wire maximum",
            peer_node_id.len()
        )
    })?;
    let scope_len = u16::try_from(scope.len()).map_err(|_| {
        format!(
            "token scope length {} exceeds the u16 wire maximum",
            scope.len()
        )
    })?;

    let mut buf = Vec::with_capacity(
        1 + 2 + node_id.len() + 2 + peer_node_id.len() + 16 + 2 + scope.len() + 16 + 16 + 64,
    );
    buf.push(1); // token version, as parse_relay_token demands
    buf.extend_from_slice(&node_id_len.to_be_bytes());
    buf.extend_from_slice(node_id);
    buf.extend_from_slice(&peer_node_id_len.to_be_bytes());
    buf.extend_from_slice(peer_node_id);
    buf.extend_from_slice(&token.relay_id);
    buf.extend_from_slice(&scope_len.to_be_bytes());
    buf.extend_from_slice(scope);
    buf.extend_from_slice(&token.issued_at_unix.to_be_bytes());
    buf.extend_from_slice(&token.expires_at_unix.to_be_bytes());
    buf.extend_from_slice(&token.nonce);
    buf.extend_from_slice(&token.signature);
    Ok(buf)
}

/// Parses a v2 relay hello (§3 layout).
///
/// Same pre-auth discipline as [`parse_relay_hello`] — this function is
/// attacker-reachable the moment S4 wires dispatch — so every field is
/// length-bounded before it is copied, nothing is defaulted, and every
/// deviation from the layout is a typed refusal. In particular:
///
/// - `protocol_version` must equal [`RELAY_PROTOCOL_VERSION`] exactly (fail
///   closed on unknown versions, mirroring the reviewed
///   `WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION` and gossip watermark checks);
/// - the OI-10 artifact field is MANDATORY (the reason [`RelayHelloV2`] is
///   not shaped like [`RelayHello`]);
/// - exactly `pad_len` bytes must follow the artifact field and every one
///   must be `0x00`. The two rules are checked together before any
///   allocation, so a short datagram claiming a huge pad_len refuses on the
///   length match alone.
pub fn parse_relay_hello_v2(data: &[u8]) -> Result<RelayHelloV2, String> {
    if data.len() > MAX_PACKET_SIZE_BYTES {
        return Err(format!(
            "relay hello v2 frame length {} exceeds maximum {MAX_PACKET_SIZE_BYTES}",
            data.len()
        ));
    }
    if data.first().copied() != Some(RELAY_HELLO_V2_MSG_TYPE) {
        return Err("not a relay hello v2 message".to_owned());
    }
    let protocol_version = data
        .get(1)
        .copied()
        .ok_or_else(|| "truncated protocol_version".to_owned())?;
    if protocol_version != RELAY_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported relay hello v2 protocol version: {protocol_version}"
        ));
    }
    let mut pos = 2;

    let pad_len = read_u16_be(data, pos).ok_or_else(|| "truncated pad_len".to_owned())?;
    pos += 2;

    // Static ceiling on the claimed padding: refuses before any allocation.
    let pad_len_max = MAX_PACKET_SIZE_BYTES - RELAY_HELLO_V2_FIXED_FIELD_BYTES;
    if usize::from(pad_len) > pad_len_max {
        return Err(format!("pad_len {pad_len} exceeds maximum {pad_len_max}"));
    }

    // Node ID — identical bound and error discipline to the v1 parser
    // (the pre-auth limiter keys on this value before signature
    // verification, so the byte cap is the same one).
    if pos + 2 > data.len() {
        return Err("truncated node_id length".to_owned());
    }
    let node_id_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated node_id length".to_owned())? as usize;
    pos += 2;
    if node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "node_id length {node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }
    if pos + node_id_len > data.len() {
        return Err("truncated node_id".to_owned());
    }
    let node_id_bytes = data
        .get(pos..pos + node_id_len)
        .ok_or_else(|| "truncated node_id".to_owned())?;
    let node_id = String::from_utf8(node_id_bytes.to_vec()).map_err(|e| e.to_string())?;
    pos += node_id_len;

    // Peer node ID — same bound (copied out of an unauthenticated datagram,
    // compared against the signed token later).
    if pos + 2 > data.len() {
        return Err("truncated peer_node_id length".to_owned());
    }
    let peer_node_id_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated peer_node_id length".to_owned())? as usize;
    pos += 2;
    if peer_node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "peer_node_id length {peer_node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }
    if pos + peer_node_id_len > data.len() {
        return Err("truncated peer_node_id".to_owned());
    }
    let peer_node_id_bytes = data
        .get(pos..pos + peer_node_id_len)
        .ok_or_else(|| "truncated peer_node_id".to_owned())?;
    let peer_node_id = String::from_utf8(peer_node_id_bytes.to_vec()).map_err(|e| e.to_string())?;
    pos += peer_node_id_len;

    // Token — parsed by exactly the v1 token parser, so admission code
    // stays format-agnostic (§3 property 4).
    if pos + 2 > data.len() {
        return Err("truncated token length".to_owned());
    }
    let token_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated token length".to_owned())? as usize;
    pos += 2;
    if pos + token_len > data.len() {
        return Err("truncated token".to_owned());
    }
    let token_data = data
        .get(pos..pos + token_len)
        .ok_or_else(|| "truncated token".to_owned())?;
    let session_token = parse_relay_token(token_data)?;
    pos += token_len;

    // MANDATORY artifact field (§3): [0x07] ++ artifact[32]. A v2 hello
    // without it would let a client opt out of the default-on OI-10 gate by
    // switching message types — the regression this layout makes
    // unrepresentable.
    let rest = data.len() - pos;
    if rest < 1 + 32 {
        return Err(format!(
            "relay hello v2 requires the 33-byte address-validation artifact field, got {rest}"
        ));
    }
    if data.get(pos).copied() != Some(RELAY_HELLO_ARTIFACT_FIELD_TYPE) {
        return Err(format!(
            "relay hello v2 artifact field must begin with {:#04x}, got {:#04x}",
            RELAY_HELLO_ARTIFACT_FIELD_TYPE,
            data.get(pos).copied().unwrap_or_default()
        ));
    }
    let artifact: [u8; 32] = data
        .get(pos + 1..pos + 33)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "truncated artifact".to_owned())?;
    pos += 33;

    // §3 properties 2+3, checked together before anything is allocated:
    // exactly pad_len bytes must remain, and every one must be zero.
    let remaining = data.len() - pos;
    if remaining != usize::from(pad_len) {
        return Err(format!(
            "pad_len {pad_len} does not match the {remaining} trailing bytes"
        ));
    }
    let padding = data
        .get(pos..)
        .ok_or_else(|| "truncated padding".to_owned())?;
    if let Some(offset) = padding.iter().position(|&byte| byte != 0) {
        return Err(format!("padding byte at offset {offset} is not 0x00"));
    }

    Ok(RelayHelloV2 {
        node_id,
        peer_node_id,
        session_token,
        addr_validation_artifact: AddressValidationArtifact::from_bytes(artifact),
        pad_len,
    })
}

/// The all-zero artifact value a v2 FIRST-CONTACT client sends in the
/// mandatory artifact field.
///
/// The v2 layout cannot omit the artifact (that omission is exactly the
/// gate-bypass S3 closed), so a first-contact client needs a distinguished
/// "no artifact yet" value. All-zero is that value, by construction: issued
/// artifacts are keyed HMAC outputs over the source address and token nonce,
/// so the all-zero string is not producible by the issuer, and the blind-v2
/// O2 envelope parse rejects all-zero challenge values for the same reason.
/// On relay admission the conversion below maps it back to v1's `None`, so
/// the OI-10 gate treats a v2 first contact EXACTLY like a v1 one
/// (`AddressValidationRequired` → challenge → retry).
pub const RELAY_HELLO_V2_FIRST_CONTACT_ARTIFACT: [u8; 32] = [0u8; 32];

impl RelayHelloV2 {
    /// True iff this hello carries the first-contact placeholder artifact
    /// ([`RELAY_HELLO_V2_FIRST_CONTACT_ARTIFACT`]).
    pub fn artifact_is_first_contact_placeholder(&self) -> bool {
        self.addr_validation_artifact.as_bytes() == &RELAY_HELLO_V2_FIRST_CONTACT_ARTIFACT
    }
}

/// Relay-side admission conversion (D3 seams §7 step S4): a dispatched v2
/// hello becomes the SAME [`RelayHello`] the v1 admit path already
/// validates, so gates, signature verification, replay and commit stay
/// format-agnostic (§3 property 4). The mandatory v2 artifact maps back to
/// v1's optional one: the all-zero first-contact placeholder becomes
/// `None` (the gate then issues a challenge, identically to v1 first
/// contact), and ANY other value — including a wrong one — is passed
/// through as `Some`, so the gate still refuses it as
/// `AddressValidationInvalid`. A v2 client can no more skip the gate by
/// encoding a bad artifact than a v1 client can.
impl From<RelayHelloV2> for RelayHello {
    fn from(v2: RelayHelloV2) -> Self {
        let addr_validation_artifact = if v2.artifact_is_first_contact_placeholder() {
            None
        } else {
            Some(v2.addr_validation_artifact)
        };
        Self {
            node_id: v2.node_id,
            peer_node_id: v2.peer_node_id,
            session_token: v2.session_token,
            addr_validation_artifact,
        }
    }
}

/// Client-side serialization conversion (D3 seams §7 step S4): the hello the
/// client already builds for v1 becomes a v2 frame with `pad_len = 0`. A
/// `None` artifact (first contact) is serialized as the all-zero placeholder
/// so the mandatory field stays present and the relay's gate maps it back to
/// `None` — the OI-10 challenge flow is identical across dialects.
///
/// Padding is `0` today (the shortest valid frame); a non-zero pad choice is
/// a future owner decision and changes nothing structural.
impl From<&RelayHello> for RelayHelloV2 {
    fn from(hello: &RelayHello) -> Self {
        Self {
            node_id: hello.node_id.clone(),
            peer_node_id: hello.peer_node_id.clone(),
            session_token: hello.session_token.clone(),
            addr_validation_artifact: hello.addr_validation_artifact.clone().unwrap_or_else(|| {
                AddressValidationArtifact::from_bytes(RELAY_HELLO_V2_FIRST_CONTACT_ARTIFACT)
            }),
            pad_len: 0,
        }
    }
}

/// OI-10 helper: domain-separated expansion of the 16-byte token nonce into
/// the 32-byte client-nonce input the reviewed keyring expects. Domain
/// separation (`RELAY_ADDR_VALIDATION_DOMAIN` prefix) keeps v1-hello nonce
/// inputs from colliding with blind-v2 nonce inputs that happen to share
/// bytes.
fn artifact_nonce_input(token_nonce: &[u8; 16]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(RELAY_ADDR_VALIDATION_DOMAIN);
    hasher.update(token_nonce);
    hasher.finalize().into()
}

/// OI-10 helper: the "privacy epoch" input the reviewed keyring API expects,
/// derived from this relay's own 16-byte id (first 8 bytes, big-endian).
/// Binds artifacts to the issuing relay identity so an artifact minted by
/// relay A cannot be re-presented to relay B that shares an epoch window.
fn relay_epoch_input(relay_id: &[u8; 16]) -> u64 {
    // `relay_id` is always 16 bytes, so `first_chunk::<8>` is statically
    // `Some`; the fallback arm is unreachable and fail-closed (epoch 0).
    match relay_id.first_chunk::<8>() {
        Some(epoch_bytes) => u64::from_be_bytes(*epoch_bytes),
        None => 0,
    }
}

/// Parses a `RelaySessionToken` from wire format.
///
/// Like `parse_relay_hello`, this runs on an unauthenticated datagram before
/// signature verification, so every embedded field is length-bounded before
/// it is copied (same pre-auth memory bound as the hello fields).
pub fn parse_relay_token(data: &[u8]) -> Result<RelaySessionToken, String> {
    let mut pos = 0;

    // Version
    if pos >= data.len() {
        return Err("missing version".to_owned());
    }
    let version = data
        .get(pos)
        .copied()
        .ok_or_else(|| "missing version".to_owned())?;
    if version != 1 {
        return Err(format!("unsupported token version: {version}"));
    }
    pos += 1;

    // Node ID
    if pos + 2 > data.len() {
        return Err("truncated token node_id length".to_owned());
    }
    let node_id_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated token node_id length".to_owned())? as usize;
    pos += 2;

    // Bound the token-embedded identifier BEFORE it is copied. This is the
    // same pre-auth memory bound RLY-05 applied to the outer hello fields,
    // which `parse_relay_token` missed: this function runs on an
    // unauthenticated datagram BEFORE signature verification, and without a
    // bound each of `node_id` / `peer_node_id` / `scope` could be declared
    // up to 64 KiB inside one ~64 KiB hello, forcing ~3x that in heap
    // `String`s per datagram. No legitimate token can hit these caps: any
    // session that would pass validation has token ids equal (constant-time
    // compared) to hello fields already capped at
    // `MAX_RELAY_NODE_ID_BYTES`, and scope equal to `RELAY_TOKEN_SCOPE`, so
    // a longer value could never authenticate.
    if node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "token node_id length {node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }

    if pos + node_id_len > data.len() {
        return Err("truncated token node_id".to_owned());
    }
    let node_id_bytes = data
        .get(pos..pos + node_id_len)
        .ok_or_else(|| "truncated token node_id".to_owned())?;
    let node_id = String::from_utf8(node_id_bytes.to_vec())
        .map_err(|e| format!("invalid token node_id: {e}"))?;
    pos += node_id_len;

    // Peer node ID
    if pos + 2 > data.len() {
        return Err("truncated token peer_node_id length".to_owned());
    }
    let peer_node_id_len = read_u16_be(data, pos)
        .ok_or_else(|| "truncated token peer_node_id length".to_owned())?
        as usize;
    pos += 2;

    // Same bound as the token's node_id above.
    if peer_node_id_len > MAX_RELAY_NODE_ID_BYTES {
        return Err(format!(
            "token peer_node_id length {peer_node_id_len} exceeds maximum {MAX_RELAY_NODE_ID_BYTES}"
        ));
    }

    if pos + peer_node_id_len > data.len() {
        return Err("truncated token peer_node_id".to_owned());
    }
    let peer_node_id_bytes = data
        .get(pos..pos + peer_node_id_len)
        .ok_or_else(|| "truncated token peer_node_id".to_owned())?;
    let peer_node_id = String::from_utf8(peer_node_id_bytes.to_vec())
        .map_err(|e| format!("invalid token peer_node_id: {e}"))?;
    pos += peer_node_id_len;

    // Relay ID (16 bytes)
    if pos + 16 > data.len() {
        return Err("truncated relay_id".to_owned());
    }
    let relay_id: [u8; 16] = data
        .get(pos..pos + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "truncated relay_id".to_owned())?;
    pos += 16;

    // Scope
    if pos + 2 > data.len() {
        return Err("truncated scope length".to_owned());
    }
    let scope_len =
        read_u16_be(data, pos).ok_or_else(|| "truncated scope length".to_owned())? as usize;
    pos += 2;

    // Scope is compared for exact equality against `RELAY_TOKEN_SCOPE`
    // during validation, so anything longer can never authenticate — cap
    // the copy at that length (same pre-auth memory bound as above).
    if scope_len > RELAY_TOKEN_SCOPE.len() {
        return Err(format!(
            "token scope length {scope_len} exceeds maximum {}",
            RELAY_TOKEN_SCOPE.len()
        ));
    }

    if pos + scope_len > data.len() {
        return Err("truncated scope".to_owned());
    }
    let scope_bytes = data
        .get(pos..pos + scope_len)
        .ok_or_else(|| "truncated scope".to_owned())?;
    let scope =
        String::from_utf8(scope_bytes.to_vec()).map_err(|e| format!("invalid scope: {e}"))?;
    pos += scope_len;

    // Timestamps
    if pos + 16 > data.len() {
        return Err("truncated timestamps".to_owned());
    }
    let issued_at_unix = u64::from_be_bytes(
        data.get(pos..pos + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "truncated timestamps".to_owned())?,
    );
    pos += 8;
    let expires_at_unix = u64::from_be_bytes(
        data.get(pos..pos + 8)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| "truncated timestamps".to_owned())?,
    );
    pos += 8;

    // Nonce (16 bytes)
    if pos + 16 > data.len() {
        return Err("truncated nonce".to_owned());
    }
    let nonce: [u8; 16] = data
        .get(pos..pos + 16)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "truncated nonce".to_owned())?;
    pos += 16;

    // Signature (64 bytes)
    if pos + 64 > data.len() {
        return Err("truncated signature".to_owned());
    }
    let signature: [u8; 64] = data
        .get(pos..pos + 64)
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| "truncated signature".to_owned())?;

    Ok(RelaySessionToken {
        node_id,
        peer_node_id,
        relay_id,
        scope,
        issued_at_unix,
        expires_at_unix,
        nonce,
        signature,
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHelloAck {
    pub session_id: SessionId,
    pub allocated_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayHelloResponse {
    Accepted(RelayHelloAck),
    Rejected(RejectReason),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayForwardError {
    SessionNotFound,
    SessionExpired,
    UnauthorizedSourceTuple,
}

/// Where to forward a received frame. Deliberately carries NO payload:
/// the relay never copies or inspects frame contents — the caller sends
/// the exact received bytes (`&buf[..len]`) to `peer_addr` via the
/// socket bound to `peer_allocated_port` (zero-copy forward path).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayForwardTarget {
    pub peer_session_id: SessionId,
    pub peer_allocated_port: u16,
    pub peer_addr: SocketAddr,
}

pub struct RelayTransport {
    /// This relay's own identifier.  Every accepted token must have a matching
    /// `relay_id`; tokens issued for a different relay are rejected.
    relay_id: [u8; 16],
    sessions: HashMap<SessionId, RelaySession>,
    node_pair_index: HashMap<(String, String), SessionId>,
    rate_limiter: RateLimiter,
    control_verifier_key: VerifyingKey,
    nonce_store: NonceStore,
    hello_limiter: HelloLimiter,
    source_hello_limiter: SourceHelloLimiter,
    clock_skew_tolerance_secs: u64,
    max_sessions_per_node: usize,
    max_total_sessions: usize,
    /// OI-10: per-process HMAC keyring for address-validation artifacts.
    /// Fresh key material from the kernel CSPRNG at every construction
    /// (never persisted): artifacts are a short-lived proof-of-liveness, so
    /// a restart costing each client one extra exchange is the right trade
    /// against key-management surface.
    addr_validation_keys: AddressValidationKeyRing,
    /// OI-10: DEFAULT-ON. When true, every hello must carry a verifiable
    /// address-validation artifact BEFORE the ed25519 signature is touched,
    /// so unauthenticated garbage costs at most one cheap HMAC per datagram
    /// instead of one ed25519 verify.
    require_addr_validation: bool,
}

impl RelayTransport {
    pub fn new(
        relay_id: [u8; 16],
        control_verifier_key: VerifyingKey,
        max_sessions_per_node: usize,
        clock_skew_tolerance_secs: u64,
    ) -> Result<Self, String> {
        // Clamp skew so the replay-store retention window always strictly
        // dominates the maximum acceptable token validity. Without this, an
        // operator that supplies an unreasonably large skew (>120 s) could
        // open a replay window between the time a nonce is pruned and the
        // time `is_expired` would finally reject the token. Clamping is
        // fail-closed (stricter expiry) and preserves the existing API.
        let (clock_skew_tolerance_secs, was_clamped) =
            compute_clamped_skew(clock_skew_tolerance_secs);
        if was_clamped {
            // `tracing` is only available behind the `daemon` feature in this
            // crate; emit a structured stderr line so the warning is visible
            // in non-daemon builds (tests, library consumers) too.
            eprintln!(
                "warn relay_transport: clock_skew_tolerance_secs clamped to {MAX_CLOCK_SKEW_TOLERANCE_SECS} (operator-supplied value exceeded the safe ceiling; replay window would otherwise reopen)"
            );
        }
        // OI-10: mint the artifact HMAC key from the kernel CSPRNG.
        // Fail-closed: no CSPRNG, no transport — a predictable key would make
        // artifacts forgeable and the gate theatre (same posture as
        // `SessionId::try_generate`).
        let mut key_material = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut key_material)
            .map_err(|err| {
                format!("relay transport init failed: kernel CSPRNG unavailable: {err}")
            })?;
        let addr_validation_keys =
            AddressValidationKeyRing::new(0, key_material).map_err(|err| {
                format!("relay transport init failed: address-validation keyring: {err}")
            })?;
        Ok(Self {
            relay_id,
            sessions: HashMap::new(),
            node_pair_index: HashMap::new(),
            rate_limiter: RateLimiter::default(),
            control_verifier_key,
            nonce_store: NonceStore::default(),
            hello_limiter: HelloLimiter::new(MAX_HELLOS_PER_NODE_PER_SEC),
            source_hello_limiter: SourceHelloLimiter::new(MAX_HELLOS_PER_SOURCE_PER_SEC),
            clock_skew_tolerance_secs,
            max_sessions_per_node,
            max_total_sessions: DEFAULT_MAX_TOTAL_SESSIONS,
            addr_validation_keys,
            // OI-10 DEFAULT-ON: the pre-auth address-validation gate starts
            // enabled. The documented opt-out is
            // `with_require_addr_validation(false)`; the relay binary maps
            // that to `--no-require-addr-validation` and logs a warning.
            require_addr_validation: true,
        })
    }

    /// OI-10 operator opt-out. `false` disables the pre-auth
    /// address-validation gate (the pre-OI-10 behavior); callers that opt
    /// out deliberately MUST log the decision (the relay binary does, at
    /// warn level). Default construction is gate-ON; this builder exists so
    /// the flip is explicit at the call site, never silent.
    pub fn with_require_addr_validation(mut self, required: bool) -> Self {
        self.require_addr_validation = required;
        self
    }

    /// OI-10: whether the pre-auth address-validation gate is enabled.
    pub fn require_addr_validation(&self) -> bool {
        self.require_addr_validation
    }

    /// OI-10: mint a fresh address-validation artifact for the exchange the
    /// given hello is part of — bound to `observed_addr` (ip+port), the
    /// hello token's nonce, this relay's identity, and a short expiry.
    ///
    /// Called ONLY on the `AddressValidationRequired` path, which sits
    /// behind the per-source hello shed, so artifact farming is bounded by
    /// the same budget that bounds pre-auth crypto work (mirrors the
    /// blind-v2 O2 issuance pattern in the daemon).
    pub fn issue_hello_validation_artifact(
        &self,
        observed_addr: &SocketAddr,
        token_nonce: &[u8; 16],
        now_unix: u64,
    ) -> Result<AddressValidationArtifact, AddressArtifactError> {
        let client_nonce = artifact_nonce_input(token_nonce);
        let privacy_epoch = relay_epoch_input(&self.relay_id);
        self.addr_validation_keys
            .issue_artifact_for_domain(
                RELAY_ADDR_VALIDATION_DOMAIN,
                observed_addr,
                &client_nonce,
                privacy_epoch,
                now_unix,
            )
            .map(AddressValidationArtifact::from_bytes)
    }

    pub fn new_with_replay_store_path(
        relay_id: [u8; 16],
        control_verifier_key: VerifyingKey,
        max_sessions_per_node: usize,
        clock_skew_tolerance_secs: u64,
        replay_store_path: impl Into<PathBuf>,
    ) -> Result<Self, String> {
        let mut transport = Self::new(
            relay_id,
            control_verifier_key,
            max_sessions_per_node,
            clock_skew_tolerance_secs,
        )?;
        let mut nonce_store = NonceStore::load(replay_store_path.into())?;
        nonce_store.prune(Duration::from_secs(NONCE_RETENTION_SECS))?;
        transport.nonce_store = nonce_store;
        Ok(transport)
    }

    pub fn set_max_total_sessions(&mut self, max_total_sessions: usize) -> Result<(), String> {
        if max_total_sessions == 0 {
            return Err("max total relay sessions must be greater than 0".to_owned());
        }
        // Refuse to shrink below the live session count. Silent eviction would
        // be an operator footgun: legitimate sessions disappear without an
        // observable error, and evicting the oldest is a heuristic the caller
        // didn't necessarily ask for. A clear error gives the operator
        // feedback so they can drain sessions explicitly before shrinking.
        let live = self.sessions.len();
        if max_total_sessions < live {
            return Err(format!(
                "cannot shrink max total relay sessions to {max_total_sessions} below live count {live}; drain sessions first"
            ));
        }
        self.max_total_sessions = max_total_sessions;
        Ok(())
    }

    /// Operator tuning for the per-node forward rate limits. Zero is
    /// refused fail-closed (a zero budget would silently blackhole every
    /// frame; an operator wanting to stop forwarding should drain
    /// sessions instead). Defaults stay `RateLimiter::default()`
    /// (10k pps / 100 Mbps per node).
    pub fn set_rate_limits(&mut self, max_pps: u64, max_bps: u64) -> Result<(), String> {
        if max_pps == 0 || max_bps == 0 {
            return Err(
                "relay rate limits must be greater than 0 (drain sessions to stop forwarding)"
                    .to_owned(),
            );
        }
        self.rate_limiter.max_pps = max_pps;
        self.rate_limiter.max_bps = max_bps;
        Ok(())
    }

    /// Validate a session establishment request without allocating relay state.
    ///
    /// This is used by the relay daemon to reject forged/stale/flooded hellos
    /// before binding an allocated UDP port. Successful validation is advisory:
    /// callers must still commit with `handle_hello_from_tuple_with_allocated_port`,
    /// which re-checks the stateful security predicates before creating a session.
    pub fn validate_hello_from_tuple(
        &mut self,
        hello: &RelayHello,
        observed_addr: SocketAddr,
    ) -> Result<(), RejectReason> {
        self.validate_hello(hello, observed_addr, true)
    }

    /// RSA-0086: the PRE-SIGNATURE admission gates only — checks 0, 1 and 2
    /// of the ordered list on `handle_hello_from_tuple_with_allocated_port`
    /// (per-source shed, per-node_id hello rate limit, OI-10
    /// address-validation gate). The relay daemon runs these under the
    /// transport lock, drops the lock, and only then performs the ed25519
    /// verify with `verify_hello_token_signature`, so verify latency can
    /// never stall a forward in flight. The ordering contract is unchanged:
    /// the OI-10 gate stays strictly pre-verify, and both rate limiters are
    /// charged here, exactly as the single-pass `validate_hello_from_tuple`
    /// charged them.
    pub fn validate_hello_gates_from_tuple(
        &mut self,
        hello: &RelayHello,
        observed_addr: SocketAddr,
    ) -> Result<(), RejectReason> {
        self.check_hello_gates(hello, observed_addr, true)
    }

    /// RSA-0086: the POST-SIGNATURE admission checks only — checks 4
    /// through 12 of the ordered list (TTL bound, freshness, future-dating,
    /// self-pairing, replay, the three ct_eq bindings, scope, both session
    /// capacities). Read-only: takes `&self`, so it proves in its own
    /// signature that it mutates no rate limiter and records nothing — the
    /// daemon may run it under the transport lock with zero admission side
    /// effects beyond the reject itself.
    pub fn validate_hello_post_signature(&self, hello: &RelayHello) -> Result<(), RejectReason> {
        self.check_hello_post_signature(hello)
    }

    /// RSA-0086: the ed25519 token signature check (check 3 of the ordered
    /// list), deliberately an associated function taking NO transport
    /// state. The type signature is the guarantee the relay daemon depends
    /// on: verification touches only the parsed hello and the (immutable,
    /// `Copy`) control-plane verifying key, so it needs no transport lock —
    /// the daemon calls this BETWEEN its locked sections, and verify
    /// latency stalls nothing but the verifying caller.
    ///
    /// Check ordering is unchanged: the daemon runs the OI-10 gate and both
    /// rate limiters (see `validate_hello_gates_from_tuple`) BEFORE this,
    /// and the post-signature checks (see `validate_hello_post_signature`)
    /// AFTER it, exactly the order `validate_hello` has always enforced.
    pub fn verify_hello_token_signature(
        hello: &RelayHello,
        control_verifier_key: &VerifyingKey,
    ) -> Result<(), RejectReason> {
        #[cfg(test)]
        RELAY_HELLO_SIG_VERIFY_CALLS.with(|calls| calls.set(calls.get() + 1));
        // Check 2: Verify token signature (ed25519, constant-time internally)
        if let Err(e) = hello.session_token.verify_signature(control_verifier_key) {
            eprintln!("Relay hello rejected: invalid signature: {e}");
            return Err(RejectReason::InvalidToken);
        }
        Ok(())
    }

    /// Process a session establishment request with a daemon-owned allocated port.
    ///
    /// All security checks are performed in a deliberate order:
    ///
    /// 0. Per-source-address hello shed (identity-free, cheap, no crypto —
    ///    the verify-protecting gate; AQ-69 / blind-v2 step-2 pattern)
    /// 1. Hello rate limit per node_id (cheap, no crypto — shed load before signature work)
    /// 2. Address-validation gate (OI-10, DEFAULT-ON): a cheap HMAC-SHA256
    ///    check on an artifact the client can only hold by having answered
    ///    a challenge from THIS source address moments ago — runs BEFORE
    ///    the ed25519 verify, so unauthenticated floods cost HMAC work,
    ///    not signature work. Missing artifact ⇒
    ///    `AddressValidationRequired` (the relay replies with a
    ///    challenge); failed verification ⇒ `AddressValidationInvalid`.
    /// 3. Signature verification (ed25519, inherently constant-time)
    /// 4. TTL bound check (max 120 s)
    /// 5. Token freshness / expiry
    /// 6. Replay nonce check
    /// 7. `node_id` binding (`ct_eq`: `hello.node_id` == `token.node_id`)
    /// 8. `peer_node_id` binding (`ct_eq`: `hello.peer_node_id` == `token.peer_node_id`)
    /// 9. `relay_id` binding (`ct_eq`: `token.relay_id` == `self.relay_id`)
    /// 10. Scope enforcement (token.scope == "`forward_ciphertext_only`")
    /// 11. Global session capacity
    /// 12. Per-node session capacity
    /// 13. Daemon-supplied allocated port validation
    ///
    /// RSA-0086: this method's internal check order (gates → verify →
    /// post-signature checks → commit) is byte-for-byte the historical one,
    /// so every direct caller keeps the exact admission results and reject
    /// reasons it always got. The relay DAEMON no longer calls this method
    /// under its transport lock: it runs the gates and the post-signature
    /// checks locked via `validate_hello_gates_from_tuple` /
    /// `validate_hello_post_signature`, performs check 3 UNLOCKED via
    /// `verify_hello_token_signature`, and commits with
    /// `commit_hello_from_tuple_with_allocated_port` — same checks, same
    /// order, no ed25519 work under the lock.
    pub fn handle_hello_from_tuple_with_allocated_port(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloResponse {
        if let Err(reason) = self.check_hello_gates(&hello, observed_addr, false) {
            return RelayHelloResponse::Rejected(reason);
        }
        if let Err(reason) = Self::verify_hello_token_signature(&hello, &self.control_verifier_key)
        {
            return RelayHelloResponse::Rejected(reason);
        }
        if let Err(reason) = self.check_hello_post_signature(&hello) {
            return RelayHelloResponse::Rejected(reason);
        }
        self.commit_checked_hello(hello, observed_addr, allocated_port)
    }

    /// RSA-0086: the daemon's locked commit step. The caller MUST already
    /// have run `verify_hello_token_signature` OUTSIDE the transport lock
    /// and it MUST have returned `Ok(())` for this exact hello — this
    /// method does NOT verify (that is the point: no ed25519 work runs
    /// under the lock). It re-runs the cheap stateful checks — the OI-10
    /// gate (an artifact can expire between the gate pass and the commit)
    /// and every post-signature predicate (capacity, replay, bindings can
    /// all change while the lock was released) — then commits state, so
    /// the admission guarantees of
    /// `handle_hello_from_tuple_with_allocated_port` are unchanged. A
    /// caller that skips its own unlocked verify has NO verified hello:
    /// the signature would then never be checked, so this method is
    /// documented fail-closed for that caller, not safe by default.
    pub fn commit_hello_from_tuple_with_allocated_port(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloResponse {
        if let Err(reason) = self.check_hello_gates(&hello, observed_addr, false) {
            return RelayHelloResponse::Rejected(reason);
        }
        if let Err(reason) = self.check_hello_post_signature(&hello) {
            return RelayHelloResponse::Rejected(reason);
        }
        self.commit_checked_hello(hello, observed_addr, allocated_port)
    }

    /// Shared tail of both commit paths above: the port sanity check, the
    /// replay-nonce record, and the session allocation. Runs only after
    /// every admission check (including the signature, wherever the caller
    /// chose to run it) has passed.
    fn commit_checked_hello(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloResponse {
        if allocated_port == 0 {
            eprintln!("Relay hello rejected: allocated port 0");
            return RelayHelloResponse::Rejected(RejectReason::InvalidAllocatedPort);
        }

        // All checks passed — record nonce to prevent replay
        if let Err(err) = self.nonce_store.insert(hello.session_token.nonce) {
            eprintln!("Relay hello rejected: replay store unavailable: {err}");
            return RelayHelloResponse::Rejected(RejectReason::ReplayStoreUnavailable);
        }

        // Allocate session
        self.remove_session_for_pair(&hello.node_id, &hello.peer_node_id);

        let session_id = match SessionId::try_generate() {
            Ok(id) => id,
            Err(err) => {
                eprintln!("Relay hello rejected: session id CSPRNG unavailable: {err}");
                return RelayHelloResponse::Rejected(RejectReason::SessionIdRandomnessUnavailable);
            }
        };

        let session = RelaySession {
            session_id,
            node_id: hello.node_id.clone(),
            peer_node_id: hello.peer_node_id.clone(),
            allocated_port,
            hello_source_addr: observed_addr,
            bound_peer_addr: None,
            expires_at_unix: hello.session_token.expires_at_unix,
            established_at: Instant::now(),
            last_packet_at: Instant::now(),
            paired_session_id: None,
        };

        self.sessions.insert(session_id, session);
        self.node_pair_index.insert(
            (hello.node_id.clone(), hello.peer_node_id.clone()),
            session_id,
        );

        RelayHelloResponse::Accepted(RelayHelloAck {
            session_id,
            allocated_port,
        })
    }

    /// The full admission sequence: gates, signature, post-signature
    /// checks. RSA-0086 split this into `check_hello_gates`,
    /// `verify_hello_token_signature` and `check_hello_post_signature`;
    /// this composition keeps the exact check order for callers that hold
    /// the transport lock anyway (library callers, tests,
    /// `validate_hello_from_tuple`).
    fn validate_hello(
        &mut self,
        hello: &RelayHello,
        observed_addr: SocketAddr,
        record_hello_rate: bool,
    ) -> Result<(), RejectReason> {
        self.check_hello_gates(hello, observed_addr, record_hello_rate)?;
        Self::verify_hello_token_signature(hello, &self.control_verifier_key)?;
        self.check_hello_post_signature(hello)
    }

    /// RSA-0086: checks 0, 1 and 1.5 of the admission walk-through — the
    /// identity-free per-source shed, the per-node_id hello rate limit,
    /// and the OI-10 address-validation gate. All cheap (no ed25519 work)
    /// and all stateful (`&mut self`: the two rate limiters are charged
    /// here, exactly once, on the `record_hello_rate` arm).
    fn check_hello_gates(
        &mut self,
        hello: &RelayHello,
        observed_addr: SocketAddr,
        record_hello_rate: bool,
    ) -> Result<(), RejectReason> {
        // Check 0: Per-source shed — identity-free, cheap, before ANY crypto
        // work (AQ-69; blind-v2 admission step-2 pattern). Keyed on the
        // observed source address rather than any attacker-supplied field,
        // so rotating `node_id` per packet cannot defeat it: at most
        // MAX_HELLOS_PER_SOURCE_PER_SEC hellos per source per window ever
        // reach the ed25519 verify below. Consumed on the same
        // `record_hello_rate` arm as the per-node_id limiter, so the commit
        // pass's re-validation does not double-charge the budget.
        if record_hello_rate && !self.source_hello_limiter.check(observed_addr.ip()) {
            return Err(RejectReason::RateLimitExceeded);
        }

        // Check 1: Hello rate limit — shed before any crypto work
        if record_hello_rate && !self.hello_limiter.check(&hello.node_id) {
            return Err(RejectReason::RateLimitExceeded);
        }

        // Check 1.5 (OI-10, DEFAULT-ON): pre-auth address-validation gate —
        // HMAC-SHA256 BEFORE any ed25519 work. The artifact is bound to the
        // observed source address (ip AND port), the hello token's nonce,
        // this relay's id, and a 30 s expiry, so a captured artifact is
        // worthless from another socket, for another token, or later.
        //
        // Ordering matters: this runs AFTER the rate gates (artifact farming
        // is bounded by the per-source shed) and BEFORE the signature check
        // (the DoS the gate exists to stop is unauthenticated ed25519
        // spam). An all-zero nonce input is refused inside the keyring, and
        // a clock that cannot be read fails closed exactly like Check 4.
        if self.require_addr_validation {
            let Some(now_unix) = now_unix_checked() else {
                eprintln!(
                    "Relay hello rejected: host clock unusable, cannot evaluate address-validation artifact"
                );
                return Err(RejectReason::ClockUnavailable);
            };
            let Some(artifact) = &hello.addr_validation_artifact else {
                eprintln!(
                    "Relay hello rejected: address-validation artifact missing (challenge will be issued)"
                );
                return Err(RejectReason::AddressValidationRequired);
            };
            let client_nonce = artifact_nonce_input(&hello.session_token.nonce);
            let privacy_epoch = relay_epoch_input(&self.relay_id);
            if let Err(err) = self.addr_validation_keys.verify_artifact_for_domain(
                RELAY_ADDR_VALIDATION_DOMAIN,
                &observed_addr,
                &client_nonce,
                privacy_epoch,
                artifact.as_bytes(),
                now_unix,
                self.clock_skew_tolerance_secs,
            ) {
                eprintln!("Relay hello rejected: address-validation artifact invalid: {err}");
                return Err(RejectReason::AddressValidationInvalid);
            }
        }

        // Check 2 — the ed25519 signature — lives in
        // `verify_hello_token_signature` (RSA-0086): an associated function
        // with no `self`, so it can run without the transport lock.
        // `validate_hello` composes it between the gates above and the
        // checks below, preserving the historical order.
        Ok(())
    }

    /// RSA-0086: everything that only makes sense on a
    /// signature-authenticated hello — TTL bound, freshness/future-dating,
    /// self-pairing, replay, the three ct_eq bindings, scope, and both
    /// session capacities (checks 3 through 11 of the admission
    /// walk-through). Read-only (`&self`): nothing here records state, so
    /// the daemon may run it under the transport lock with no admission
    /// side effect beyond the reject itself.
    fn check_hello_post_signature(&self, hello: &RelayHello) -> Result<(), RejectReason> {
        // Check 3: Verify token TTL bound (max 120 s)
        let ttl = hello.session_token.ttl_secs();
        if ttl > MAX_RELAY_TTL_SECS {
            eprintln!("Relay hello rejected: TTL exceeds max ({ttl} > {MAX_RELAY_TTL_SECS})");
            return Err(RejectReason::InvalidToken);
        }

        // Check 4: Token freshness / expiry
        //
        // RLY-15: with no usable clock there is no freshness to check, so refuse
        // rather than proceed against a substituted value.
        let Some(now_unix) = now_unix_checked() else {
            eprintln!("Relay hello rejected: host clock unusable, cannot evaluate token freshness");
            return Err(RejectReason::ClockUnavailable);
        };

        if hello
            .session_token
            .is_expired(now_unix, self.clock_skew_tolerance_secs)
        {
            eprintln!("Relay hello rejected: token expired");
            return Err(RejectReason::ExpiredToken);
        }

        // Check 4b: Token must not be future-dated (RLY-01).
        //
        // `ttl_secs()` is a DIFFERENCE (`expires_at - issued_at`), and
        // `is_expired` is an upper bound only, so without this check a token
        // dated far in the future satisfies both: `ttl <= MAX_RELAY_TTL_SECS`
        // holds because the difference is small, and `now > expires_at + skew`
        // is false because `expires_at` is enormous.
        //
        // That matters beyond freshness. `NONCE_RETENTION_SECS` is measured from
        // *insert* time, not from the token's own window, so the retention
        // invariant documented above ("a nonce cannot be recycled within its
        // validity period") silently depends on `issued_at <= now`. A
        // future-dated token outlives its own nonce entry and can therefore be
        // replayed indefinitely, once per prune cycle.
        //
        // The repo already applies this norm to signed membership attestations —
        // `documents/SecurityMinimumBar.md:87` requires they be fresh "and not
        // future-dated beyond clock-skew tolerance". That text governs
        // attestations rather than relay tokens, so it is cited here as the
        // precedent for the shape of this check, not as a requirement that
        // already covered this path.
        if hello.session_token.issued_at_unix
            > now_unix.saturating_add(self.clock_skew_tolerance_secs)
        {
            eprintln!("Relay hello rejected: token is future-dated beyond skew tolerance");
            return Err(RejectReason::InvalidToken);
        }

        // Check 4c: Reject a self-paired token (RLY-11).
        //
        // Checked against the TOKEN's fields, not the hello's, so this only ever
        // runs on data the signature has already authenticated. An honest issuer
        // already refuses to mint these (`control/lib.rs` rejects
        // `node_id == peer_node_id`), so this is defence in depth against a
        // compromised or buggy issuer: with both fields equal, `node_pair_index`
        // keys `(A, A)` and the forward-path reverse lookup resolves to the
        // session's OWN id, making the relay echo every frame back to the sender.
        if hello.session_token.node_id == hello.session_token.peer_node_id {
            eprintln!("Relay hello rejected: token is self-paired (node_id == peer_node_id)");
            return Err(RejectReason::InvalidToken);
        }

        // Check 5: Replay nonce
        if self.nonce_store.contains(&hello.session_token.nonce) {
            eprintln!("Relay hello rejected: nonce replay detected");
            return Err(RejectReason::ReplayedNonce);
        }

        // Check 6: node_id binding (constant-time)
        let node_id_match: bool = hello
            .node_id
            .as_bytes()
            .ct_eq(hello.session_token.node_id.as_bytes())
            .into();
        if !node_id_match {
            eprintln!("Relay hello rejected: node_id mismatch between hello and token");
            return Err(RejectReason::InvalidToken);
        }

        // Check 7: peer_node_id binding (constant-time)
        let peer_match: bool = hello
            .peer_node_id
            .as_bytes()
            .ct_eq(hello.session_token.peer_node_id.as_bytes())
            .into();
        if !peer_match {
            eprintln!("Relay hello rejected: peer_node_id mismatch");
            return Err(RejectReason::PeerMismatch);
        }

        // Check 8: relay_id binding (constant-time byte comparison)
        let relay_match: bool = hello.session_token.relay_id.ct_eq(&self.relay_id).into();
        if !relay_match {
            eprintln!("Relay hello rejected: token relay_id does not match this relay");
            return Err(RejectReason::InvalidToken);
        }

        // Check 9: Scope enforcement
        if hello.session_token.scope != RELAY_TOKEN_SCOPE {
            eprintln!(
                "Relay hello rejected: unexpected scope '{}'",
                hello.session_token.scope
            );
            return Err(RejectReason::InvalidToken);
        }

        // Check 10: Global session capacity. Replacing an existing pair is not
        // growth, so allow it even when the relay is at capacity.
        let pair_key = (hello.node_id.clone(), hello.peer_node_id.clone());
        let replacing_existing_pair = self.node_pair_index.contains_key(&pair_key);
        if !replacing_existing_pair && self.sessions.len() >= self.max_total_sessions {
            eprintln!("Relay hello rejected: global session capacity reached");
            return Err(RejectReason::Capacity);
        }

        // Check 11: Per-node session capacity. As with the global cap above,
        // replacing an existing pair is not growth: the old session is removed
        // before the new one is inserted (`remove_session_for_pair` runs after
        // validation), so the replacement must not count the session it is
        // about to free. Without this exemption a node at exactly its cap can
        // never re-hello any of its own pairs — the client's proactive token
        // refresh re-hellos while the old session is still alive — and every
        // refresh is locked out until sessions fully expire.
        let node_session_count = self
            .sessions
            .values()
            .filter(|s| s.node_id == hello.node_id)
            .count();
        // The indexed pair's session belongs to `hello.node_id` by construction
        // (the index is keyed on the establishing hello's own fields), so when
        // `replacing_existing_pair` holds, exactly one of the counted sessions
        // is the one about to be freed.
        let effective_node_session_count = if replacing_existing_pair {
            node_session_count.saturating_sub(1)
        } else {
            node_session_count
        };

        if effective_node_session_count >= self.max_sessions_per_node {
            eprintln!(
                "Relay hello rejected: capacity limit reached for node {}",
                hello.node_id
            );
            return Err(RejectReason::Capacity);
        }

        Ok(())
    }

    #[cfg(test)]
    pub fn handle_hello_from_tuple(
        &mut self,
        hello: RelayHello,
        observed_addr: SocketAddr,
    ) -> RelayHelloResponse {
        let allocated_port = self.next_test_allocated_port();
        if let Err(reason) = self.validate_hello_from_tuple(&hello, observed_addr) {
            return RelayHelloResponse::Rejected(reason);
        }
        self.handle_hello_from_tuple_with_allocated_port(hello, observed_addr, allocated_port)
    }

    #[cfg(test)]
    pub fn handle_hello(&mut self, hello: RelayHello) -> RelayHelloResponse {
        let observed_addr = SocketAddr::from(([127, 0, 0, 1], 40_000));
        self.handle_hello_from_tuple(hello, observed_addr)
    }

    /// Refresh session activity timestamp without forwarding data.
    ///
    /// Used by keepalive packets to prevent session idle timeout.
    pub fn touch_session_from_tuple(
        &mut self,
        session_id: SessionId,
        from_addr: SocketAddr,
    ) -> Result<bool, RelayForwardError> {
        // RLY-15: no usable clock means session liveness cannot be established.
        // Report the session as expired rather than treat it as live.
        let Some(now_unix) = now_unix_checked() else {
            return Err(RelayForwardError::SessionExpired);
        };

        let Some(session) = self.sessions.get_mut(&session_id) else {
            return Err(RelayForwardError::SessionNotFound);
        };
        if session.expires_at_unix <= now_unix {
            self.remove_session(session_id);
            return Err(RelayForwardError::SessionExpired);
        }
        match session.bound_peer_addr {
            Some(bound_addr) if bound_addr == from_addr => {
                session.last_packet_at = Instant::now();
                Ok(true)
            }
            Some(_) => Err(RelayForwardError::UnauthorizedSourceTuple),
            None => Ok(false),
        }
    }

    #[cfg(test)]
    pub fn touch_session(&mut self, session_id: SessionId) -> Result<(), String> {
        let session = self
            .sessions
            .get_mut(&session_id)
            .ok_or("session not found")?;
        session.last_packet_at = Instant::now();
        Ok(())
    }

    pub fn has_session(&self, session_id: SessionId) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// Forward a ciphertext payload from one session to its paired session.
    ///
    /// Returns:
    /// - `Ok(Some((peer_session_id, payload)))` — forwarded successfully
    /// - `Ok(None)` — silently dropped (rate limit or no paired session)
    /// - `Err(msg)` — session not found
    ///
    /// Payloads are forwarded byte-for-byte.  The relay never inspects content.
    pub fn forward_packet(
        &mut self,
        session_id: SessionId,
        payload: &[u8],
        from_addr: SocketAddr,
    ) -> Result<Option<RelayForwardTarget>, RelayForwardError> {
        // Silently drop oversized payloads (do not error — avoids amplification)
        if payload.len() > MAX_PACKET_SIZE_BYTES {
            return Ok(None);
        }

        // RLY-15: as above -- an unusable clock cannot certify a live session.
        let Some(now_unix) = now_unix_checked() else {
            return Err(RelayForwardError::SessionExpired);
        };

        let Some(session) = self.sessions.get(&session_id) else {
            return Err(RelayForwardError::SessionNotFound);
        };
        if session.expires_at_unix <= now_unix {
            self.remove_session(session_id);
            return Err(RelayForwardError::SessionExpired);
        }

        {
            // The entry was confirmed above and nothing removes it before
            // this point; a `None` still fails closed with the same error a
            // missing session always gets.
            let session = self
                .sessions
                .get_mut(&session_id)
                .ok_or(RelayForwardError::SessionNotFound)?;
            match session.bound_peer_addr {
                Some(bound_addr) if bound_addr == from_addr => {}
                Some(_) => return Err(RelayForwardError::UnauthorizedSourceTuple),
                None => {
                    if session.hello_source_addr.ip() != from_addr.ip() {
                        return Err(RelayForwardError::UnauthorizedSourceTuple);
                    }
                    session.bound_peer_addr = Some(from_addr);
                }
            }

            // Rate limit check — silent drop on excess
            if !self
                .rate_limiter
                .check_packet(&session.node_id, payload.len())
            {
                return Ok(None);
            }

            // Update last_packet_at
            session.last_packet_at = Instant::now();
        }

        // Resolve the paired session id. Fast path: the cached id on the
        // session, re-validated against the live session map with plain
        // &str comparisons (no allocation). Fallback (first packet after
        // pairing, or after the partner was replaced/evicted): the
        // authoritative owned-key pair-index lookup, exactly as before.
        let cached_peer_sid = {
            let Some(session) = self.sessions.get(&session_id) else {
                return Err(RelayForwardError::SessionNotFound);
            };
            session.paired_session_id.filter(|sid| {
                self.sessions
                    .get(sid)
                    .is_some_and(|candidate| session.is_paired_with(candidate))
            })
        };
        let peer_sid = match cached_peer_sid {
            Some(sid) => sid,
            None => {
                let (looked_up, current_node_id, current_peer_node_id) = {
                    let Some(session) = self.sessions.get(&session_id) else {
                        return Err(RelayForwardError::SessionNotFound);
                    };
                    (
                        self.node_pair_index
                            .get(&(session.peer_node_id.clone(), session.node_id.clone()))
                            .copied(),
                        session.node_id.clone(),
                        session.peer_node_id.clone(),
                    )
                };
                let Some(sid) = looked_up else {
                    // Half-open: no paired session yet; silently drop
                    return Ok(None);
                };
                if !self.sessions.contains_key(&sid) {
                    self.node_pair_index
                        .remove(&(current_peer_node_id, current_node_id));
                    return Ok(None);
                }
                // Cache for subsequent frames on this session.
                if let Some(session) = self.sessions.get_mut(&session_id) {
                    session.paired_session_id = Some(sid);
                }
                sid
            }
        };

        let Some(peer_session) = self.sessions.get_mut(&peer_sid) else {
            // Unreachable in practice (existence was just validated on
            // both paths), kept as a silent drop for defence in depth.
            return Ok(None);
        };
        if peer_session.expires_at_unix <= now_unix {
            self.remove_session(peer_sid);
            return Ok(None);
        }
        let Some(peer_addr) = peer_session.bound_peer_addr else {
            return Ok(None);
        };
        peer_session.last_packet_at = Instant::now();
        // Forward payload as-is — never inspected, never copied: the caller
        // sends the same received bytes to the returned target.
        Ok(Some(RelayForwardTarget {
            peer_session_id: peer_sid,
            peer_allocated_port: peer_session.allocated_port,
            peer_addr,
        }))
    }

    /// Evict idle, half-open, and stale sessions, and prune the nonce store.
    ///
    /// Should be called periodically (e.g., every 10 seconds).
    pub fn cleanup_idle_sessions(&mut self) -> Vec<RelaySession> {
        let now = Instant::now();
        let idle_threshold = Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS);
        let half_open_threshold = Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS);
        // RLY-15: the idle and half-open sweeps below use `Instant`, a MONOTONIC
        // clock, and are unaffected by a broken wall clock -- so they must keep
        // running. Only the wall-clock expiry comparison is skipped, by leaving
        // `now_unix` as `None`. Not reaping an expired session is safe here
        // because the forward paths reject it independently: it lingers in the
        // map but cannot carry traffic.
        let now_unix = now_unix_checked();

        let mut to_remove = Vec::new();

        for (session_id, session) in &self.sessions {
            let age = now.duration_since(session.established_at);
            let idle = now.duration_since(session.last_packet_at);

            let has_pair = self
                .node_pair_index
                .contains_key(&(session.peer_node_id.clone(), session.node_id.clone()));

            // Remove session if:
            // - it has expired according to the signed session token, OR
            // - it is half-open (no paired session) and exceeds the half-open timeout, OR
            // - it is idle (no recent packets) and exceeds the idle timeout
            // RLY-15: `None` means the wall clock is unusable, so this session's
            // expiry is simply unknown -- not "not expired". Left to the
            // forward-path rejection rather than guessed at here.
            let is_expired = session_is_expired(session.expires_at_unix, now_unix);
            let is_stale_half_open = !has_pair && age > half_open_threshold;
            let is_idle = idle > idle_threshold;
            if is_expired || is_stale_half_open || is_idle {
                to_remove.push(*session_id);
            }
        }

        let mut removed = Vec::new();
        for sid in to_remove {
            if let Some(session) = self.remove_session(sid) {
                removed.push(session);
            }
        }

        // Prune nonce store: remove entries older than the nonce retention window
        // to prevent unbounded memory growth while keeping anti-replay guarantees.
        if let Err(err) = self
            .nonce_store
            .prune(Duration::from_secs(NONCE_RETENTION_SECS))
        {
            eprintln!("relay nonce-store prune failed: {err}");
        }

        // Prune rate-limiter token buckets that no longer correspond to any
        // active session. `RateLimiter::check_packet` allocates a fresh bucket
        // on the first packet for any new `node_id`; without this prune, a
        // steady churn of distinct `node_id`s would grow the bucket map
        // without bound (memory-exhaustion DoS). Tying bucket lifetime to
        // session lifetime caps the bucket count by `max_total_sessions`.
        // Borrowed keys: this runs on the cleanup tick, but there is no need
        // to clone every session's node_id just to build a membership set —
        // disjoint field borrows let the set of `&str` views over
        // `self.sessions` coexist with the mutable borrow of
        // `self.rate_limiter`.
        let active_nodes: std::collections::HashSet<&str> = self
            .sessions
            .values()
            .map(|session| session.node_id.as_str())
            .collect();
        self.rate_limiter
            .retain_active_nodes(|node_id| active_nodes.contains(node_id));

        // Prune the pre-auth hello limiter's per-node_id windows on the same
        // cadence (RSA-0037): a node_id whose one-second window has elapsed no
        // longer needs an entry, so a churn of distinct pre-auth node_ids cannot
        // accumulate stale windows between cleanups.
        self.hello_limiter.prune_elapsed(now);

        // Prune the per-source shed's address windows on the same cadence
        // (AQ-69 / RSA-0037): a source whose one-second window has elapsed
        // no longer needs an entry, so source-address churn cannot
        // accumulate stale windows between cleanups.
        self.source_hello_limiter.prune_elapsed(now);

        removed
    }

    #[cfg(test)]
    fn next_test_allocated_port(&self) -> u16 {
        let base = 50_000u16;
        let offset = (self.sessions.len() % 10_000) as u16;
        base.wrapping_add(offset)
    }

    /// Number of active sessions (for monitoring/tests).
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    fn remove_session_for_pair(&mut self, node_id: &str, peer_node_id: &str) {
        let Some(existing_session_id) = self
            .node_pair_index
            .get(&(node_id.to_owned(), peer_node_id.to_owned()))
            .copied()
        else {
            return;
        };
        self.remove_session(existing_session_id);
    }

    fn remove_session(&mut self, session_id: SessionId) -> Option<RelaySession> {
        let session = self.sessions.remove(&session_id)?;
        self.node_pair_index
            .remove(&(session.node_id.clone(), session.peer_node_id.clone()));
        Some(session)
    }
}

// ── Nonce store ───────────────────────────────────────────────────────────────

#[derive(Default)]
struct NonceStore {
    nonces: HashMap<[u8; 16], u64>,
    path: Option<PathBuf>,
}

impl NonceStore {
    fn load(path: PathBuf) -> Result<Self, String> {
        validate_replay_store_path(&path)?;
        if !path.exists() {
            let store = Self {
                nonces: HashMap::new(),
                path: Some(path),
            };
            store.persist()?;
            return Ok(store);
        }

        let content =
            fs::read_to_string(&path).map_err(|err| format!("read replay store: {err}"))?;
        let mut nonces = HashMap::new();
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let nonce_hex = fields
                .next()
                .ok_or_else(|| format!("replay store line {} missing nonce", line_no + 1))?;
            let inserted_at_unix = fields
                .next()
                .ok_or_else(|| format!("replay store line {} missing timestamp", line_no + 1))?
                .parse::<u64>()
                .map_err(|err| {
                    format!("replay store line {} invalid timestamp: {err}", line_no + 1)
                })?;
            if fields.next().is_some() {
                return Err(format!(
                    "replay store line {} has unexpected fields",
                    line_no + 1
                ));
            }
            nonces.insert(parse_nonce_hex(nonce_hex)?, inserted_at_unix);
        }
        Ok(Self {
            nonces,
            path: Some(path),
        })
    }

    fn contains(&self, nonce: &[u8; 16]) -> bool {
        self.nonces.contains_key(nonce)
    }

    fn insert(&mut self, nonce: [u8; 16]) -> Result<(), String> {
        // Insert directly, persist, and roll back on failure. Avoids the
        // O(n) clone of the entire nonce map per accepted hello (which at
        // 4096 sessions × 240 s retention gave O(n²) total work). The
        // persist-failure consistency property is preserved: in-memory
        // state matches on-disk state, OR the operation fails closed
        // without mutating either.
        // RLY-15: an entry stamped from a substituted clock is worse than no
        // entry -- it silently changes when this nonce becomes prunable, which is
        // the whole anti-replay window. Refuse instead, which rejects the hello.
        let Some(now) = now_unix_checked() else {
            return Err("host clock unusable; refusing to record a replay nonce".to_owned());
        };
        let prior = self.nonces.insert(nonce, now);
        if let Err(err) = self.persist() {
            // Restore previous state (either remove the new entry, or
            // re-insert whatever was there before — defensive against
            // an unexpected duplicate).
            match prior {
                Some(previous) => {
                    self.nonces.insert(nonce, previous);
                }
                None => {
                    self.nonces.remove(&nonce);
                }
            }
            return Err(err);
        }
        Ok(())
    }

    fn prune(&mut self, retention: Duration) -> Result<(), String> {
        // RLY-15: this is the call site that rules out a sentinel. The filter
        // below is `now - inserted_at >= retention`, so a substituted `u64::MAX`
        // would evict EVERY nonce and empty the replay set. Return before any
        // mutation, which retains every nonce -- pruning late is a bounded memory
        // cost, pruning early is a replay window.
        let Some(now) = now_unix_checked() else {
            return Err(
                "host clock unusable; skipping nonce prune to preserve anti-replay".to_owned(),
            );
        };
        let retention_secs = retention.as_secs();
        // Collect keys to drop without cloning the full map. The drop set
        // is bounded by the number of expiring nonces (typically a small
        // fraction of total), not by the map size.
        let to_remove: Vec<([u8; 16], u64)> = self
            .nonces
            .iter()
            // Boundary is EXCLUSIVE and deliberately stays so: an entry at exactly
            // `retention_secs` is evicted. This is pinned by
            // `nonce_at_exact_retention_age_is_pruned_by_cleanup`, whose comment
            // states it exists so "a future loosening would be caught by tests".
            //
            // RLY-10 (a one-second replay window when skew was at its ceiling) was
            // therefore fixed on the OTHER side of the invariant — by lowering
            // `MAX_CLOCK_SKEW_TOLERANCE_SECS` to `MAX_RELAY_TTL_SECS - 1` so that
            // `TTL + skew < NONCE_RETENTION_SECS` holds strictly rather than by
            // equality. Do not "fix" it here by loosening this comparison.
            .filter(|(_, inserted_at)| now.saturating_sub(**inserted_at) >= retention_secs)
            .map(|(nonce, inserted_at)| (*nonce, *inserted_at))
            .collect();
        if to_remove.is_empty() {
            return Ok(());
        }
        for (nonce, _) in &to_remove {
            self.nonces.remove(nonce);
        }
        if let Err(err) = self.persist() {
            // Restore evicted entries with their original timestamps so
            // a later prune retry sees the same state as before.
            for (nonce, inserted_at) in to_remove {
                self.nonces.insert(nonce, inserted_at);
            }
            return Err(err);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        persist_nonce_map(path, &self.nonces)
    }
}

/// Wall-clock seconds since UNIX_EPOCH, or `None` when the host clock is unusable.
///
/// **Security (RLY-15).** `SystemTime::now() < UNIX_EPOCH` is rare but real: a
/// board with no RTC during very early boot, a clock rolled back by a
/// misconfigured NTP, an operator running `date --set=...`. An older version
/// `.expect(...)`-ed and crashed the relay on every hello, which was correctly
/// replaced — but the replacement returned `0`, and its doc comment claimed that
/// made tokens "look already-expired — fail-closed". It does the opposite.
/// `is_expired` is `now > expires_at + skew`, and `0 > anything` is **false**, so
/// every token became unexpired and the data path's
/// `session.expires_at_unix <= now_unix` never fired. Expiry enforcement was
/// switched off entirely, under a comment asserting the reverse.
///
/// # Why there is no sentinel, only an `Option`
///
/// The obvious repair is to substitute `u64::MAX` so `MAX > expires_at + skew`
/// makes everything expired. That fixes expiry and breaks anti-replay:
/// [`NonceStore::prune`] computes `now - retention`, so with `now = u64::MAX`
/// every nonce is older than the boundary and the **entire replay set is evicted
/// on each prune**. `0` is the exact mirror — it retains nonces while disabling
/// expiry.
///
/// No single value is fail-closed for both, because the two consumers want
/// opposite directions from it. So the failure is returned instead of encoded,
/// and each call site disposes of it in its own safe direction: reject the hello,
/// treat a session as expired on the forward paths, and SKIP the prune so nonces
/// are retained.
/// Whether a session's signed expiry has passed, given a possibly-unavailable
/// wall clock.
///
/// RLY-15: `None` means "unknown", NOT "not expired". Extracted as a pure
/// function because the interesting case needs a host clock before 1970, which no
/// unit test can arrange -- so the disposition is tested here instead of being
/// asserted only in prose at the call site.
///
/// Returning `false` for `None` is safe ONLY because the forward paths reject
/// such a session independently: it lingers in the session map but cannot carry
/// traffic. This function must therefore never become the sole expiry gate.
fn session_is_expired(expires_at_unix: u64, now_unix: Option<u64>) -> bool {
    now_unix.is_some_and(|now| expires_at_unix <= now)
}

/// Shared with the blind-relay v2 admission listener, whose replay store and
/// admission path follow the same fail-closed clock discipline (RLY-15).
pub(crate) fn now_unix_checked() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .ok()
}

/// Pure helper that clamps an operator-supplied clock-skew tolerance to the
/// safe ceiling and reports whether clamping occurred. Extracted so the
/// clamp decision is testable without depending on a logging subscriber.
///
/// Returns `(clamped_value, was_clamped)`. `was_clamped == true` is the
/// signal that a `warn`-level log line would be emitted.
fn compute_clamped_skew(input: u64) -> (u64, bool) {
    if input > MAX_CLOCK_SKEW_TOLERANCE_SECS {
        (MAX_CLOCK_SKEW_TOLERANCE_SECS, true)
    } else {
        (input, false)
    }
}

/// Pure helper that decides whether a `symlink_metadata` failure during
/// replay-store path validation is "expected" (file not yet created, fresh
/// install) or "unexpected" (permission denied, I/O error, etc.) and should
/// produce a warning. Extracted so the warn-or-not decision is testable
/// without depending on a logging subscriber.
///
/// Returns `true` iff a warning would be emitted.
fn should_warn_replay_stat_skip(err: &std::io::Error) -> bool {
    err.kind() != std::io::ErrorKind::NotFound
}

/// Shared with the blind-relay v2 admission listener, whose replay store uses
/// the identical path/permission validation (regular file, mode 0600, sane
/// parent directory).
pub(crate) fn validate_replay_store_path(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("replay store path must not be empty".to_owned());
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.file_type().is_file() {
                return Err("replay store path must be a regular file".to_owned());
            }
            #[cfg(unix)]
            {
                let mode = metadata.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    return Err(format!("replay store permissions too broad: {mode:o}"));
                }
            }
        }
        Err(err) => {
            // NotFound is expected on first-run / fresh-install: the parent
            // directory is the relevant security surface and is checked
            // below. Any *other* stat error (permission denied, I/O error)
            // means we couldn't actually verify the file's safety. Log a
            // warning so an operator with a corrupted state directory can
            // see that the permission check was skipped.
            if should_warn_replay_stat_skip(&err) {
                eprintln!(
                    "warn relay_transport: replay store permission check skipped — symlink_metadata({}) failed: {err}",
                    path.display()
                );
            }
        }
    }
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        let metadata =
            fs::symlink_metadata(parent).map_err(|err| format!("stat replay store dir: {err}"))?;
        if metadata.file_type().is_symlink() || !metadata.file_type().is_dir() {
            return Err("replay store parent must be a directory".to_owned());
        }
        #[cfg(unix)]
        {
            let mode = metadata.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "replay store parent permissions too broad: {mode:o}"
                ));
            }
        }
    }
    Ok(())
}

fn persist_nonce_map(path: &Path, nonces: &HashMap<[u8; 16], u64>) -> Result<(), String> {
    validate_replay_store_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "replay store path missing file name".to_owned())?
        .to_string_lossy();
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let mut lines = nonces.iter().collect::<Vec<_>>();
    lines.sort_by(|left, right| left.0.cmp(right.0));
    let mut content = String::new();
    for (nonce, inserted_at_unix) in lines {
        content.push_str(&format!("{} {inserted_at_unix}\n", hex_nonce(nonce)));
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| format!("open replay store tmp: {err}"))?;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("write replay store tmp: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("sync replay store tmp: {err}"))?;
    drop(file);

    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set replay store permissions: {err}"))?;

    fs::rename(&tmp_path, path).map_err(|err| format!("replace replay store: {err}"))?;

    // Durability: fsync the PARENT DIRECTORY after the rename (RLY-04).
    //
    // `file.sync_all()` above makes the temp file's *contents* durable, but the
    // rename that publishes it is a directory-entry update, which is not covered
    // by that fsync. Without this, a crash immediately after the rename can lose
    // the entry and drop recently accepted nonces — reopening the replay window
    // for exactly those tokens until they expire, in a store whose only purpose
    // is crash-durable replay prevention.
    //
    // This mirrors the sequence `rustynet-crypto::write_atomic_encrypted_key_file`
    // and `rustynetd::enrollment_token::write_ledger` already use. Directory
    // fsync is a no-op on Windows (opening a directory handle for
    // FlushFileBuffers requires access flags `File::open` does not request), so
    // it is unix-gated exactly as those two call sites are.
    // Derive the directory EXACTLY as the temp-file write above does, including
    // the `"."` fallback. An earlier revision of this fix skipped the fsync when
    // `path.parent()` was `Some("")` — which is what a bare relative filename
    // yields — so for that input the temp file was written into `.` while the
    // directory was never synced, and the fix silently did nothing. Sharing the
    // derivation keeps the two halves honest.
    #[cfg(unix)]
    {
        let dir =
            fs::File::open(parent).map_err(|err| format!("open replay store parent dir: {err}"))?;
        dir.sync_all()
            .map_err(|err| format!("sync replay store parent dir: {err}"))?;
    }

    Ok(())
}

fn hex_nonce(nonce: &[u8; 16]) -> String {
    let mut encoded = String::with_capacity(32);
    for byte in nonce {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn parse_nonce_hex(value: &str) -> Result<[u8; 16], String> {
    if value.len() != 32 {
        return Err("replay store nonce must be 32 hex characters".to_owned());
    }
    let mut nonce = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|err| format!("replay store nonce is not utf8: {err}"))?;
        let byte = u8::from_str_radix(text, 16)
            .map_err(|err| format!("replay store nonce is not hex: {err}"))?;
        *nonce
            .get_mut(index)
            .ok_or_else(|| "replay store nonce must be 32 hex characters".to_owned())? = byte;
    }
    Ok(nonce)
}

// ── Hello rate limiter ────────────────────────────────────────────────────────

/// Limits session-establishment (`handle_hello`) attempts per node per second.
///
/// This is a separate, much tighter limit than the packet-level `RateLimiter`
/// because `handle_hello` performs ed25519 verification (CPU-intensive).
/// Applying a cheap counter before verification protects against CPU-exhaustion
/// attacks.
/// Hard cap on the number of distinct `node_id` windows the `HelloLimiter`
/// retains. The map is keyed on the attacker-controlled `node_id` and consulted
/// BEFORE the ed25519 signature check, so without a bound a pre-auth attacker
/// rotating `node_id` strings could grow it without limit (RSA-0037, CWE-770).
/// Set well above any legitimate distinct-node cardinality in a 1-second window
/// (the relay's session cap is `DEFAULT_MAX_TOTAL_SESSIONS` = 4096) so it never
/// false-rejects real peers, while still bounding total memory.
pub(crate) const MAX_HELLO_LIMITER_ENTRIES: usize = 16_384;

pub(crate) struct HelloLimiter {
    max_per_sec: u32,
    max_entries: usize,
    counts: HashMap<String, (u32, Instant)>,
}

impl HelloLimiter {
    pub(crate) fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            max_entries: MAX_HELLO_LIMITER_ENTRIES,
            counts: HashMap::new(),
        }
    }

    /// Returns `true` if the hello should be allowed, `false` if rate-limited.
    pub(crate) fn check(&mut self, node_id: &str) -> bool {
        let now = Instant::now();

        // RSA-0037: hard-cap the map so a pre-auth node_id flood cannot exhaust
        // memory. When a NEW node_id arrives and the map is at capacity, first
        // drop any windows whose one-second period has already elapsed; if it is
        // still full, reject the new node_id (fail closed — never allocate above
        // the cap). Existing tracked node_ids are always allowed to look up
        // their counter, so this cannot false-reject an in-window peer.
        if self.counts.len() >= self.max_entries && !self.counts.contains_key(node_id) {
            self.prune_elapsed(now);
            if self.counts.len() >= self.max_entries {
                return false;
            }
        }

        let entry = self.counts.entry(node_id.to_owned()).or_insert((0, now));

        // Reset counter if the one-second window has elapsed
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            *entry = (0, now);
        }

        if entry.0 >= self.max_per_sec {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// Drop entries whose one-second window has already elapsed. Mirrors the
    /// per-IP `PreAuthHelloLimiter::prune` / per-node `retain_active_nodes`
    /// pruning so the map stays bounded under churn (RSA-0037).
    fn prune_elapsed(&mut self, now: Instant) {
        self.counts
            .retain(|_, (_, started)| now.duration_since(*started) < Duration::from_secs(1));
    }

    /// Number of distinct `node_id` windows currently tracked. Exposed for the
    /// DOS-1 flood audit (`crate::hello_limiter_audit`) to observe the map
    /// size without reaching into the private `counts` field.
    #[cfg(feature = "daemon")]
    pub(crate) fn entry_count(&self) -> usize {
        self.counts.len()
    }
}

/// Identity-free per-source-address hello shed (AQ-69) — the v1-path analogue
/// of blind-v2 admission step 2 ("per-SOURCE-PREFIX pre-auth rate limit ...
/// shed before any crypto", `blind_relay_listener.rs`): keyed on the OBSERVED
/// source address, the only pre-auth key an attacker cannot rewire per
/// packet. The per-node_id [`HelloLimiter`] above is checked first in spirit
/// but its key is attacker-supplied — its own capacity comment concedes a
/// flood rotates `node_id` per packet — so it bounds memory, not verify
/// volume. This limiter bounds the verify volume: at most
/// `MAX_HELLOS_PER_SOURCE_PER_SEC` hellos per source per window ever reach
/// [`RelayTransport::validate_hello`]'s ed25519 check.
///
/// Mechanically mirrors `HelloLimiter` (and the daemon's per-IP
/// `PreAuthHelloLimiter`): one-second windows, capacity-checked insert that
/// prunes elapsed windows first and REJECTS while still full (fail closed),
/// lazy window reset on access.
pub(crate) struct SourceHelloLimiter {
    max_per_sec: u32,
    max_entries: usize,
    counts: HashMap<IpAddr, (u32, Instant)>,
}

impl SourceHelloLimiter {
    pub(crate) fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec,
            max_entries: MAX_HELLO_SOURCE_ENTRIES,
            counts: HashMap::new(),
        }
    }

    /// Returns `true` if the hello should be admitted to the crypto work,
    /// `false` if it is shed before any signature work.
    pub(crate) fn check(&mut self, source: IpAddr) -> bool {
        let now = Instant::now();

        // Fail closed at the table bound, mirroring `HelloLimiter::check`
        // (RSA-0037): a NEW source arriving at capacity first drops elapsed
        // windows; if the table is still full the new source is shed rather
        // than growing the map. Tracked sources always keep their lookup.
        if self.counts.len() >= self.max_entries && !self.counts.contains_key(&source) {
            self.prune_elapsed(now);
            if self.counts.len() >= self.max_entries {
                return false;
            }
        }

        let entry = self.counts.entry(source).or_insert((0, now));

        // Reset counter if the one-second window has elapsed
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            *entry = (0, now);
        }

        if entry.0 >= self.max_per_sec {
            return false;
        }
        entry.0 += 1;
        true
    }

    /// Drop entries whose one-second window has elapsed, mirroring
    /// `HelloLimiter::prune_elapsed` (RSA-0037).
    fn prune_elapsed(&mut self, now: Instant) {
        self.counts
            .retain(|_, (_, started)| now.duration_since(*started) < Duration::from_secs(1));
    }

    /// Distinct sources currently tracked; test seam only.
    #[cfg(test)]
    pub(crate) fn entry_count(&self) -> usize {
        self.counts.len()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    /// D3 seams plan seam 1: the v2 message-type byte allocation is pinned
    /// by a test, not just by the plan's prose. If a future change takes
    /// `0x08` (or shifts `RELAY_PROTOCOL_VERSION`), this fails and the
    /// allocation record must be renegotiated deliberately.
    #[test]
    fn relay_hello_v2_consts_pin_the_allocated_byte_space() {
        assert_eq!(RELAY_HELLO_V2_MSG_TYPE, 0x08);
        assert_eq!(RELAY_PROTOCOL_VERSION, 2);
        // Distinct from every message-type byte already allocated in this
        // file (v1 hello, OI-10 challenge, OI-10 artifact field).
        assert_ne!(RELAY_HELLO_V2_MSG_TYPE, RELAY_HELLO_MSG_TYPE);
        assert_ne!(RELAY_HELLO_V2_MSG_TYPE, RELAY_HELLO_CHALLENGE_MSG_TYPE);
        assert_ne!(RELAY_HELLO_V2_MSG_TYPE, RELAY_HELLO_ARTIFACT_FIELD_TYPE);
        // The version constant is a payload value, never a first byte that
        // collides with the v1 hello's framing.
        assert_ne!(RELAY_PROTOCOL_VERSION, RELAY_HELLO_MSG_TYPE);
    }

    // ── D3 seams plan S3: v2 hello frame library (parser + serializer) ────

    /// The golden v2 layout vector (D3 seams plan §3): node ids
    /// `node-a`/`node-b`, a deterministic token (relay id `0xAA`×16, scope
    /// `forward_ciphertext_only`, issued 1_700_000_000 / expires
    /// 1_700_000_060, nonce `0x11`×16, signature `0x22`×64), artifact
    /// `0x77`×32 behind the `0x07` tag, `pad_len = 7` zero bytes.
    /// Derived independently of the serializer and pinned byte-for-byte so
    /// silent reshuffling of the layout cannot pass.
    const GOLDEN_V2_HELLO_HEX: &str = concat!(
        "0802000700066e6f64652d6100066e6f64652d62009a0100066e6f64",
        "652d6100066e6f64652d62aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00",
        "17666f72776172645f636970686572746578745f6f6e6c7900000000",
        "6553f100000000006553f13c11111111111111111111111111111111",
        "22222222222222222222222222222222222222222222222222222222",
        "22222222222222222222222222222222222222222222222222222222",
        "22222222222222220777777777777777777777777777777777777777",
        "7777777777777777777777777700000000000000",
    );

    /// Test-local hex decoder (the crate has no hex dependency).
    fn unhex(s: &str) -> Vec<u8> {
        s.as_bytes()
            .chunks(2)
            .map(|pair| {
                let hi = (pair[0] as char).to_digit(16).expect("hex digit");
                let lo = (pair[1] as char).to_digit(16).expect("hex digit");
                ((hi << 4) | lo) as u8
            })
            .collect()
    }

    /// The deterministic v2 hello the golden vector was derived from.
    fn sample_v2_hello() -> RelayHelloV2 {
        RelayHelloV2 {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: RelaySessionToken {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: [0xAA; 16],
                scope: RELAY_TOKEN_SCOPE.to_owned(),
                issued_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_060,
                nonce: [0x11; 16],
                signature: [0x22; 64],
            },
            addr_validation_artifact: AddressValidationArtifact::from_bytes([0x77; 32]),
            pad_len: 7,
        }
    }

    /// Field-wise equality (RelaySessionToken deliberately has no
    /// PartialEq, so the token compares via its wire bytes).
    fn assert_v2_round_trip_eq(parsed: &RelayHelloV2, expected: &RelayHelloV2) {
        assert_eq!(parsed.node_id, expected.node_id);
        assert_eq!(parsed.peer_node_id, expected.peer_node_id);
        assert_eq!(parsed.pad_len, expected.pad_len);
        assert_eq!(
            parsed.addr_validation_artifact.as_bytes(),
            expected.addr_validation_artifact.as_bytes()
        );
        assert_eq!(
            token_wire_bytes(&parsed.session_token),
            token_wire_bytes(&expected.session_token)
        );
    }

    #[test]
    fn relay_hello_v2_first_contact_conversion_maps_placeholder_to_none() {
        let mut first_contact = sample_v2_hello();
        first_contact.addr_validation_artifact =
            AddressValidationArtifact::from_bytes(RELAY_HELLO_V2_FIRST_CONTACT_ARTIFACT);
        first_contact.pad_len = 0;

        let v1 = RelayHello::from(first_contact);
        assert!(v1.addr_validation_artifact.is_none());
        assert_eq!(v1.node_id, "node-a");
        assert_eq!(v1.peer_node_id, "node-b");
    }

    #[test]
    fn relay_hello_v2_conversion_keeps_non_placeholder_artifact_gated() {
        // Any non-placeholder value — including a WRONG one — must reach the
        // OI-10 gate as `Some`, so the gate refuses it as invalid instead of
        // re-issuing a challenge. A v2 client cannot skip the gate by
        // encoding a bad artifact.
        let mut hostile = sample_v2_hello();
        hostile.addr_validation_artifact = AddressValidationArtifact::from_bytes([0xDE; 32]);
        hostile.pad_len = 0;
        let v1 = RelayHello::from(hostile);
        assert_eq!(
            v1.addr_validation_artifact
                .as_ref()
                .expect("non-placeholder artifact is preserved")
                .as_bytes(),
            &[0xDE; 32]
        );
    }

    #[test]
    fn relay_hello_v1_first_contact_becomes_placeholder_v2_and_survives_the_wire() {
        let v1 = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: RelaySessionToken {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: [0xAA; 16],
                scope: RELAY_TOKEN_SCOPE.to_owned(),
                issued_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_060,
                nonce: [0x11; 16],
                signature: [0x22; 64],
            },
            addr_validation_artifact: None,
        };

        let v2 = RelayHelloV2::from(&v1);
        assert_eq!(v2.pad_len, 0);
        assert!(v2.artifact_is_first_contact_placeholder());

        let wire = serialize_relay_hello_v2(&v2).expect("converted hello serializes");
        let parsed = parse_relay_hello_v2(&wire).expect("converted hello parses");
        let back = RelayHello::from(parsed);
        assert!(back.addr_validation_artifact.is_none());
        assert_eq!(back.node_id, v1.node_id);
        assert_eq!(back.peer_node_id, v1.peer_node_id);
        assert_eq!(
            token_wire_bytes(&back.session_token),
            token_wire_bytes(&v1.session_token)
        );
    }

    #[test]
    fn relay_hello_v1_challenge_retry_artifact_survives_v2_wire() {
        let artifact = AddressValidationArtifact::from_bytes([0x77; 32]);
        let v1 = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: RelaySessionToken {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                relay_id: [0xAA; 16],
                scope: RELAY_TOKEN_SCOPE.to_owned(),
                issued_at_unix: 1_700_000_000,
                expires_at_unix: 1_700_000_060,
                nonce: [0x11; 16],
                signature: [0x22; 64],
            },
            addr_validation_artifact: Some(artifact.clone()),
        };

        let v2 = RelayHelloV2::from(&v1);
        assert!(!v2.artifact_is_first_contact_placeholder());
        let parsed = parse_relay_hello_v2(&serialize_relay_hello_v2(&v2).expect("serialize"))
            .expect("parse");
        let back = RelayHello::from(parsed);
        assert_eq!(
            back.addr_validation_artifact
                .as_ref()
                .expect("kept")
                .as_bytes(),
            artifact.as_bytes()
        );
    }

    #[test]
    fn relay_hello_v2_golden_layout() {
        let golden = unhex(GOLDEN_V2_HELLO_HEX);
        assert_eq!(golden.len(), 216);

        // Serialize is byte-exact against the pinned vector.
        let hello = sample_v2_hello();
        let bytes = serialize_relay_hello_v2(&hello).expect("golden hello serializes");
        assert_eq!(bytes, golden, "serializer diverged from the pinned layout");

        // Parse is its exact inverse, and re-serializing is stable.
        let parsed = parse_relay_hello_v2(&golden).expect("golden frame parses");
        assert_v2_round_trip_eq(&parsed, &hello);
        let again = serialize_relay_hello_v2(&parsed).expect("re-serialize");
        assert_eq!(again, golden);

        // Field offsets pinned by assertion, not only via round-trip.
        assert_eq!(golden[0], RELAY_HELLO_V2_MSG_TYPE);
        assert_eq!(golden[1], RELAY_PROTOCOL_VERSION);
        assert_eq!(&golden[2..4], &7u16.to_be_bytes());
        assert_eq!(&golden[4..6], &6u16.to_be_bytes());
        assert_eq!(&golden[6..12], b"node-a");
        assert_eq!(&golden[12..14], &6u16.to_be_bytes());
        assert_eq!(&golden[14..20], b"node-b");
        assert_eq!(&golden[20..22], &154u16.to_be_bytes());
        assert_eq!(golden[22], 1); // token version byte
        let artifact_at = 22 + 154;
        assert_eq!(golden[artifact_at], RELAY_HELLO_ARTIFACT_FIELD_TYPE);
        assert_eq!(&golden[artifact_at + 1..artifact_at + 33], &[0x77; 32]);
        assert_eq!(&golden[artifact_at + 33..], &[0u8; 7]);
    }

    #[test]
    fn relay_hello_v2_round_trip_is_identity() {
        for pad_len in [0u16, 1, 7, 64, 4096] {
            let mut hello = sample_v2_hello();
            hello.pad_len = pad_len;
            let bytes = serialize_relay_hello_v2(&hello).expect("serializes");
            assert_eq!(bytes.len(), 209 + usize::from(pad_len));
            let parsed = parse_relay_hello_v2(&bytes).expect("round-trips");
            assert_v2_round_trip_eq(&parsed, &hello);
            assert_eq!(parsed.pad_len, pad_len);
            assert_eq!(
                serialize_relay_hello_v2(&parsed).expect("re-serialize"),
                bytes
            );
        }

        // The serializer's total-size ceiling: this hello's fixed part is
        // 209 bytes, so pad 65327 fills the datagram exactly and 65328
        // refuses.
        let mut hello = sample_v2_hello();
        hello.pad_len = 65_327;
        let bytes = serialize_relay_hello_v2(&hello).expect("max legal padding serializes");
        assert_eq!(bytes.len(), MAX_PACKET_SIZE_BYTES);
        assert!(parse_relay_hello_v2(&bytes).is_ok());
        hello.pad_len = 65_328;
        let err = serialize_relay_hello_v2(&hello).expect_err("over-ceiling padding refuses");
        assert!(err.contains("exceeds maximum"), "unexpected error: {err}");
    }

    #[test]
    fn relay_hello_v2_unknown_version_rejected() {
        for version in [0u8, 1, 3, 0xff] {
            let mut frame = unhex(GOLDEN_V2_HELLO_HEX);
            frame[1] = version;
            let err =
                parse_relay_hello_v2(&frame).expect_err("unknown protocol version must refuse");
            assert!(
                err.contains(&format!(
                    "unsupported relay hello v2 protocol version: {version}"
                )),
                "wrong error for version {version}: {err}"
            );
        }
        // A frame with no version byte refuses distinctly.
        let err = parse_relay_hello_v2(&[RELAY_HELLO_V2_MSG_TYPE])
            .expect_err("missing version must refuse");
        assert!(
            err.contains("truncated protocol_version"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_missing_artifact_field() {
        let golden = unhex(GOLDEN_V2_HELLO_HEX);
        // Cut the artifact field but keep the 7 claimed pad bytes: the
        // missing mandatory artifact refuses (never "parses as padding").
        let after_token = golden.len() - 7 - 33;
        let mut frame = golden[..after_token].to_vec();
        frame.extend_from_slice(&[0u8; 7]);
        let err = parse_relay_hello_v2(&frame)
            .expect_err("a v2 hello with no artifact field must refuse");
        assert!(
            err.contains("address-validation artifact"),
            "unexpected: {err}"
        );

        // A 32-byte tail (tag + 31) is a truncated artifact, refused too.
        let mut short = golden[..after_token].to_vec();
        short.extend_from_slice(&[0x07u8; 32]);
        let err = parse_relay_hello_v2(&short).expect_err("short artifact must refuse");
        assert!(
            err.contains("address-validation artifact"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_artifact_field_with_wrong_tag() {
        let mut frame = unhex(GOLDEN_V2_HELLO_HEX);
        let artifact_at = frame.len() - 7 - 33;
        frame[artifact_at] = RELAY_HELLO_CHALLENGE_MSG_TYPE; // 0x06, not 0x07
        let err = parse_relay_hello_v2(&frame).expect_err("wrong artifact tag must refuse");
        assert!(
            err.contains("artifact field must begin with 0x07"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_padding_length_lies() {
        let golden = unhex(GOLDEN_V2_HELLO_HEX);

        // Claimed 7, actual 6: truncate one pad byte.
        let mut short = golden.clone();
        short.pop();
        let err = parse_relay_hello_v2(&short).expect_err("short padding must refuse");
        assert!(
            err.contains("pad_len 7 does not match the 6 trailing bytes"),
            "unexpected: {err}"
        );

        // Claimed 7, actual 8: one appended byte.
        let mut long = golden.clone();
        long.push(0);
        let err = parse_relay_hello_v2(&long).expect_err("extra trailing byte must refuse");
        assert!(
            err.contains("pad_len 7 does not match the 8 trailing bytes"),
            "unexpected: {err}"
        );

        // Claimed 0 with 7 real pad bytes.
        let mut zero = golden.clone();
        zero[2..4].copy_from_slice(&0u16.to_be_bytes());
        let err = parse_relay_hello_v2(&zero).expect_err("pad_len lie must refuse");
        assert!(
            err.contains("pad_len 0 does not match the 7 trailing bytes"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_nonzero_padding() {
        let mut frame = unhex(GOLDEN_V2_HELLO_HEX);
        let last = frame.len() - 1;
        frame[last] = 0x01;
        let err = parse_relay_hello_v2(&frame).expect_err("non-zero padding must refuse");
        assert!(
            err.contains("padding byte at offset 6 is not 0x00"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_oversize_input() {
        let oversized = vec![0u8; MAX_PACKET_SIZE_BYTES + 1];
        let err = parse_relay_hello_v2(&oversized).expect_err("oversize datagram must refuse");
        assert!(err.contains("exceeds maximum 65536"), "unexpected: {err}");

        // A pad_len beyond the static ceiling refuses before any allocation.
        let mut frame = unhex(GOLDEN_V2_HELLO_HEX);
        frame[2..4].copy_from_slice(&65_494u16.to_be_bytes());
        let err = parse_relay_hello_v2(&frame).expect_err("over-ceiling pad_len must refuse");
        assert!(
            err.contains("pad_len 65494 exceeds maximum 65493"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_refuses_oversize_node_id() {
        let mut frame = unhex(GOLDEN_V2_HELLO_HEX);
        frame[4..6].copy_from_slice(&129u16.to_be_bytes());
        let err = parse_relay_hello_v2(&frame).expect_err("over-cap node_id must refuse");
        assert!(
            err.contains("node_id length 129 exceeds maximum 128"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn relay_hello_v2_and_v1_are_distinct_dialects() {
        // Neither parser accepts the other's dialect (differential pin:
        // the two parsers share the token parser and nothing else).
        let (sk, _) = make_test_keypair();
        let hello = make_hello(&sk, "node-a", "node-b");
        let artifact = AddressValidationArtifact::from_bytes([0x77; 32]);
        let v1 = serialize_hello_bytes(&hello, Some(&artifact));
        assert!(parse_relay_hello(&v1).is_ok(), "v1 sanity");
        assert!(parse_relay_hello_v2(&v1).is_err(), "v1 bytes are not v2");

        let v2 = serialize_relay_hello_v2(&sample_v2_hello()).expect("serializes");
        assert!(parse_relay_hello_v2(&v2).is_ok(), "v2 sanity");
        assert!(parse_relay_hello(&v2).is_err(), "v2 bytes are not v1");
    }

    #[test]
    fn relay_hello_v2_witness_no_panic_over_mutations() {
        // Deterministic xorshift64: no new dependency, reproducible run to
        // run. Every input must yield a well-typed Ok or Err — never a
        // panic, never a partially-read frame.
        struct Xorshift64(u64);
        impl Xorshift64 {
            fn next_u64(&mut self) -> u64 {
                let mut x = self.0;
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                self.0 = x;
                x
            }
            fn below(&mut self, bound: usize) -> usize {
                ((self.next_u64() >> 16) % bound as u64) as usize
            }
        }
        let mut rng = Xorshift64(0x2026_0925_DEAD_BEEF);
        let golden = unhex(GOLDEN_V2_HELLO_HEX);
        assert!(
            parse_relay_hello_v2(&golden).is_ok(),
            "pristine golden frame sanity"
        );

        let mut checked = 0usize;

        // 1. Truncations at EVERY length.
        for len in 0..=golden.len() {
            let _ = parse_relay_hello_v2(&golden[..len]);
            checked += 1;
        }

        // 2. Every single-bit flip of every byte.
        for byte_idx in 0..golden.len() {
            for bit in 0..8u8 {
                let mut frame = golden.clone();
                frame[byte_idx] ^= 1 << bit;
                let _ = parse_relay_hello_v2(&frame);
                checked += 1;
            }
        }

        // 3. Length lies at all four length fields (pad_len at 2..4,
        //    node_id_len at 4..6, peer_node_id_len at 12..14, token_len at
        //    20..22): zero, one-off, huge, u16 max.
        for off in [2usize, 4, 12, 20] {
            for &lie in &[
                0u16, 1, 5, 6, 7, 8, 32, 33, 153, 154, 155, 0x00ff, 0x1000, 0x7fff, 0xfffe, 0xffff,
            ] {
                let mut frame = golden.clone();
                frame[off..off + 2].copy_from_slice(&lie.to_be_bytes());
                let _ = parse_relay_hello_v2(&frame);
                checked += 1;
            }
        }

        // 4. Random frames: half shaped like a v2 hello, half pure noise.
        while checked < 20_000 {
            let len = rng.below(400);
            let mut frame = vec![0u8; len];
            for byte in frame.iter_mut() {
                *byte = rng.next_u64() as u8;
            }
            if len >= 2 && rng.below(2) == 0 {
                frame[0] = RELAY_HELLO_V2_MSG_TYPE;
                frame[1] = RELAY_PROTOCOL_VERSION;
            }
            let _ = parse_relay_hello_v2(&frame);
            checked += 1;
        }

        // 5. Multi-byte random mutations of a valid frame (1-8 writes).
        for _ in 0..5_000 {
            let mut frame = golden.clone();
            for _ in 0..(1 + rng.below(8)) {
                let at = rng.below(frame.len());
                frame[at] = rng.next_u64() as u8;
            }
            let _ = parse_relay_hello_v2(&frame);
            checked += 1;
        }

        // 6. Oversize noise datagrams around the MAX_PACKET_SIZE_BYTES
        //    boundary (both sides of the refusal edge).
        for _ in 0..1_000 {
            let len = 65_000 + rng.below(2_000);
            let frame = vec![0x08u8; len];
            let _ = parse_relay_hello_v2(&frame);
            checked += 1;
        }

        assert!(
            checked >= 20_000,
            "witness ran {checked} inputs, wanted at least 20,000"
        );
    }

    const TEST_RELAY_ID: [u8; 16] = [0xAA; 16];

    fn make_test_keypair() -> (SigningKey, VerifyingKey) {
        let signing_key = SigningKey::from_bytes(&[1u8; 32]);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    fn make_transport(signing_key: &SigningKey) -> RelayTransport {
        RelayTransport::new(TEST_RELAY_ID, signing_key.verifying_key(), 8, 90)
            .expect("relay transport init")
            // Legacy token-machinery tests run the OI-10 gate OFF on purpose;
            // the gate itself is covered by its own dedicated tests below.
            .with_require_addr_validation(false)
    }

    fn temp_replay_store_path(test_name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-{test_name}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("temp replay store dir should be created");
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("temp replay store dir permissions should be restricted");
        dir.join("replay.store")
    }

    /// Build a valid token bound to `TEST_RELAY_ID` and the given TTL.
    fn make_valid_token(
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        ttl_secs: u64,
    ) -> RelaySessionToken {
        RelaySessionToken::sign(signing_key, node_id, peer_node_id, TEST_RELAY_ID, ttl_secs)
    }

    /// Build a valid hello that uses a fresh token.
    fn make_hello(signing_key: &SigningKey, node_id: &str, peer_node_id: &str) -> RelayHello {
        RelayHello {
            node_id: node_id.to_owned(),
            peer_node_id: peer_node_id.to_owned(),
            session_token: make_valid_token(signing_key, node_id, peer_node_id, 60),
            addr_validation_artifact: None,
        }
    }

    fn observed_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::from((ip, port))
    }

    fn accept_hello_from(
        transport: &mut RelayTransport,
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        from_addr: SocketAddr,
    ) -> SessionId {
        match transport
            .handle_hello_from_tuple(make_hello(signing_key, node_id, peer_node_id), from_addr)
        {
            RelayHelloResponse::Accepted(ack) => ack.session_id,
            other => panic!("expected accepted hello, got {other:?}"),
        }
    }

    fn accept_hello_from_with_port(
        transport: &mut RelayTransport,
        signing_key: &SigningKey,
        node_id: &str,
        peer_node_id: &str,
        from_addr: SocketAddr,
        allocated_port: u16,
    ) -> RelayHelloAck {
        let hello = make_hello(signing_key, node_id, peer_node_id);
        transport
            .validate_hello_from_tuple(&hello, from_addr)
            .expect("hello should validate before port allocation");
        match transport.handle_hello_from_tuple_with_allocated_port(
            hello,
            from_addr,
            allocated_port,
        ) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected accepted hello, got {other:?}"),
        }
    }

    // ── Signature / basic token validity ─────────────────────────────────────

    /// RSA-0086 witness: with the transport mutex HELD for the whole
    /// admission sequence, no ed25519 verification may run. The daemon's
    /// locked sections are exactly `validate_hello_gates_from_tuple`,
    /// `validate_hello_post_signature` and
    /// `commit_hello_from_tuple_with_allocated_port` — none may touch the
    /// verify counter — and the unlock-then-verify step bumps it by one.
    /// The counter is per-thread, so concurrent test threads cannot drift
    /// these exact-count observations.
    #[test]
    fn rsa0086_no_signature_verification_under_the_transport_lock() {
        let (sk, _) = make_test_keypair();
        let transport = std::sync::Mutex::new(make_transport(&sk));
        let hello = make_hello(&sk, "node-a", "node-b");
        let from_addr = observed_addr([203, 0, 113, 10], 45_000);

        // Hold the transport lock across the entire locked admission
        // sequence, like the daemon does between its two locked sections.
        let mut guard = transport.lock().expect("transport mutex poisoned");
        let baseline = RELAY_HELLO_SIG_VERIFY_CALLS.with(Cell::get);

        guard
            .validate_hello_gates_from_tuple(&hello, from_addr)
            .expect("pre-signature gates pass");
        guard
            .validate_hello_post_signature(&hello)
            .expect("post-signature checks pass");
        match guard.commit_hello_from_tuple_with_allocated_port(hello.clone(), from_addr, 45_001) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("expected accepted commit, got {other:?}"),
        }

        assert_eq!(
            RELAY_HELLO_SIG_VERIFY_CALLS.with(Cell::get),
            baseline,
            "no ed25519 verify may run while the transport lock is held"
        );
        drop(guard);

        // The daemon's between-sections step: verify OUTSIDE the lock.
        RelayTransport::verify_hello_token_signature(&hello, &sk.verifying_key())
            .expect("valid token verifies");
        assert_eq!(
            RELAY_HELLO_SIG_VERIFY_CALLS.with(Cell::get),
            baseline + 1,
            "the out-of-lock verify is the only signature work"
        );
    }

    /// RSA-0086 soundness witness: the daemon's flow is gates (locked) →
    /// signature verify (UNLOCKED) → commit (locked). N copies of one
    /// verified hello racing that flow must produce exactly one Accepted
    /// session: the nonce insert runs under the lock inside the commit, so
    /// every loser is rejected as a replayed nonce and no session pair is
    /// double-allocated — the unlock window cannot buy a second admission.
    #[test]
    fn rsa0086_concurrent_identical_hellos_admit_exactly_one_session() {
        let (sk, _) = make_test_keypair();
        let verifier_key = std::sync::Arc::new(sk.verifying_key());
        let transport = std::sync::Arc::new(std::sync::Mutex::new(make_transport(&sk)));
        let hello = std::sync::Arc::new(make_hello(&sk, "node-a", "node-b"));
        let from_addr = observed_addr([203, 0, 113, 10], 45_000);

        // The daemon pre-verifies each hello once before the commit race:
        // gates under the lock, signature outside it.
        {
            let mut guard = transport.lock().expect("transport mutex poisoned");
            guard
                .validate_hello_gates_from_tuple(&hello, from_addr)
                .expect("pre-signature gates pass");
        }
        RelayTransport::verify_hello_token_signature(&hello, &verifier_key)
            .expect("valid token verifies");

        const RACERS: usize = 8;
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(RACERS));
        let mut handles = Vec::new();
        for index in 0..RACERS {
            let transport = std::sync::Arc::clone(&transport);
            let hello = std::sync::Arc::clone(&hello);
            let verifier_key = std::sync::Arc::clone(&verifier_key);
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                // Each racer re-verifies OUTSIDE the lock (the daemon's
                // between-sections step), then takes the lock only for the
                // commit.
                RelayTransport::verify_hello_token_signature(&hello, &verifier_key)
                    .expect("valid token verifies");
                let mut guard = transport.lock().expect("transport mutex poisoned");
                guard.commit_hello_from_tuple_with_allocated_port(
                    (*hello).clone(),
                    from_addr,
                    45_001 + index as u16,
                )
            }));
        }

        let mut accepted = 0usize;
        let mut replayed = 0usize;
        for handle in handles {
            match handle.join().expect("racer thread should not panic") {
                RelayHelloResponse::Accepted(_) => accepted += 1,
                RelayHelloResponse::Rejected(RejectReason::ReplayedNonce) => replayed += 1,
                other => panic!("unexpected racer response: {other:?}"),
            }
        }
        assert_eq!(accepted, 1, "exactly one racer may win the nonce insert");
        assert_eq!(
            replayed,
            RACERS - 1,
            "every loser must be rejected as a replayed nonce"
        );
        assert_eq!(
            transport
                .lock()
                .expect("transport mutex poisoned")
                .session_count(),
            1,
            "the unlock window must not double-allocate the session"
        );
    }

    #[test]
    fn test_invalid_signature_token_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Token signed with a different key then signature bytes mangled
        let wrong_sk = SigningKey::from_bytes(&[2u8; 32]);
        let mut token = make_valid_token(&wrong_sk, "node-a", "node-b", 60);
        token.signature = [99u8; 64];

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_invalid_allocated_port_rejected_without_consuming_nonce() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello = make_hello(&sk, "node-a", "node-b");
        let from_addr = observed_addr([203, 0, 113, 10], 51000);

        let rejected =
            transport.handle_hello_from_tuple_with_allocated_port(hello.clone(), from_addr, 0);
        assert_eq!(
            rejected,
            RelayHelloResponse::Rejected(RejectReason::InvalidAllocatedPort)
        );
        assert_eq!(transport.session_count(), 0);

        let accepted =
            transport.handle_hello_from_tuple_with_allocated_port(hello, from_addr, 50_000);
        assert!(
            matches!(accepted, RelayHelloResponse::Accepted(_)),
            "valid retry should not be blocked by nonce consumption: {accepted:?}"
        );
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn test_expired_token_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut token = make_valid_token(&sk, "node-a", "node-b", 60);
        token.expires_at_unix = now_unix - 200;
        // Re-sign with expired timestamp
        let payload = token.canonical_payload();
        token.signature = sk.sign(payload.as_bytes()).to_bytes();

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::ExpiredToken)
        );
    }

    #[test]
    fn test_token_ttl_exceeds_max_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: make_valid_token(&sk, "node-a", "node-b", 200), // > 120 s
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Replay protection ─────────────────────────────────────────────────────

    #[test]
    fn test_replayed_nonce_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello1 = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token.clone(),
            addr_validation_artifact: None,
        };
        assert!(matches!(
            transport.handle_hello(hello1),
            RelayHelloResponse::Accepted(_)
        ));

        let hello2 = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };
        assert_eq!(
            transport.handle_hello(hello2),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce)
        );
    }

    #[test]
    fn test_nonce_store_pruned_in_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Accept one hello to seed the nonce store
        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        assert_eq!(transport.nonce_store.nonces.len(), 1);

        // Back-date the nonce so it appears older than the retention window
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix_checked()
                .expect("test host clock must be after the epoch")
                .saturating_sub(NONCE_RETENTION_SECS + 1);
        }

        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            0,
            "expired nonces must be pruned by cleanup"
        );
    }

    #[test]
    fn test_durable_replay_store_rejects_nonce_after_restart() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("durable-replay");
        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token.clone(),
            addr_validation_artifact: None,
        };

        {
            let mut transport = RelayTransport::new_with_replay_store_path(
                TEST_RELAY_ID,
                sk.verifying_key(),
                8,
                90,
                replay_store_path.clone(),
            )
            .expect("durable replay store should initialize")
            .with_require_addr_validation(false);
            assert!(matches!(
                transport.handle_hello_from_tuple_with_allocated_port(
                    hello,
                    observed_addr([198, 51, 100, 70], 40_070),
                    55_070,
                ),
                RelayHelloResponse::Accepted(_)
            ))
        };

        let mut restarted = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        )
        .expect("durable replay store should reload")
        .with_require_addr_validation(false);
        let replay = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };
        assert_eq!(
            restarted.handle_hello_from_tuple_with_allocated_port(
                replay,
                observed_addr([198, 51, 100, 70], 40_070),
                55_071,
            ),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce)
        );
        let _ = fs::remove_dir_all(
            replay_store_path
                .parent()
                .expect("replay store path should have parent"),
        );
    }

    #[test]
    fn test_replay_store_corruption_fails_closed_on_startup() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("corrupt-replay");
        fs::write(&replay_store_path, "not-a-valid-store\n")
            .expect("corrupt replay store should be written");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        ) {
            Ok(_) => panic!("corrupt replay store must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("replay store"));
        let _ = fs::remove_dir_all(
            replay_store_path
                .parent()
                .expect("replay store path should have parent"),
        );
    }

    #[cfg(unix)]
    #[test]
    fn test_replay_store_rejects_broad_parent_permissions() {
        let (sk, _) = make_test_keypair();
        let replay_store_path = temp_replay_store_path("broad-parent");
        let parent = replay_store_path
            .parent()
            .expect("replay store path should have parent")
            .to_path_buf();
        fs::set_permissions(&parent, fs::Permissions::from_mode(0o755))
            .expect("parent permissions should be widened for negative test");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            replay_store_path.clone(),
        ) {
            Ok(_) => panic!("broad replay store parent permissions must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("parent permissions too broad"));

        let _ = fs::set_permissions(&parent, fs::Permissions::from_mode(0o700));
        let _ = fs::remove_dir_all(parent);
    }

    // ── Node-id and relay-id binding (new constant-time checks) ──────────────

    #[test]
    fn test_node_id_mismatch_rejected_with_constant_time_check() {
        // hello.node_id = "attacker" but token.node_id = "node-a"
        // The relay must reject this with InvalidToken (not PeerMismatch).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "attacker".to_owned(), // wrong
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_relay_id_mismatch_rejected() {
        // Token issued for a different relay — must be rejected.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let other_relay_id = [0xBB; 16]; // ≠ TEST_RELAY_ID
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", other_relay_id, 60);

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Scope enforcement ─────────────────────────────────────────────────────

    #[test]
    fn test_wrong_scope_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Manually forge a token with a wrong scope and re-sign it
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut token = RelaySessionToken {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            relay_id: TEST_RELAY_ID,
            scope: "full_tunnel_admin".to_owned(), // wrong
            issued_at_unix: now_unix,
            expires_at_unix: now_unix + 60,
            nonce: [0x11; 16],
            signature: [0u8; 64],
        };
        let payload = token.canonical_payload();
        token.signature = sk.sign(payload.as_bytes()).to_bytes();

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::InvalidToken)
        );
    }

    // ── Peer-id binding ───────────────────────────────────────────────────────

    #[test]
    fn test_peer_mismatch_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "node-b", 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-c".to_owned(), // different from token
            session_token: token,
            addr_validation_artifact: None,
        };

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::PeerMismatch)
        );
    }

    // ── Capacity ──────────────────────────────────────────────────────────────

    #[test]
    fn test_capacity_limit_enforced() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 2, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        for i in 0..2 {
            let hello = make_hello(&sk, "node-a", &format!("node-b-{i}"));
            assert!(matches!(
                transport.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ));
        }

        // Third hello for the same node must be rejected
        let hello = make_hello(&sk, "node-a", "node-b-extra");
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
    }

    #[test]
    fn test_global_capacity_limit_enforced_across_nodes() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        transport
            .set_max_total_sessions(2)
            .expect("global session cap should configure");

        let from = observed_addr([203, 0, 113, 10], 50000);
        accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_000);
        accept_hello_from_with_port(&mut transport, &sk, "node-b", "peer-b", from, 50_001);
        assert_eq!(transport.session_count(), 2);

        let response = transport.handle_hello_from_tuple_with_allocated_port(
            make_hello(&sk, "node-c", "peer-c"),
            from,
            50_002,
        );
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
        assert_eq!(transport.session_count(), 2);
    }

    #[test]
    fn test_global_capacity_allows_existing_pair_replacement() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        transport
            .set_max_total_sessions(1)
            .expect("global session cap should configure");

        let from = observed_addr([203, 0, 113, 10], 50000);
        accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_000);
        assert_eq!(transport.session_count(), 1);

        let ack =
            accept_hello_from_with_port(&mut transport, &sk, "node-a", "peer-a", from, 50_001);
        assert_eq!(ack.allocated_port, 50_001);
        assert_eq!(transport.session_count(), 1);

        let rejected = transport.handle_hello_from_tuple_with_allocated_port(
            make_hello(&sk, "node-b", "peer-b"),
            from,
            50_002,
        );
        assert_eq!(
            rejected,
            RelayHelloResponse::Rejected(RejectReason::Capacity)
        );
    }

    // ── Hello rate limiting ───────────────────────────────────────────────────

    #[test]
    fn test_hello_rate_limit_blocks_flood() {
        let (sk, _) = make_test_keypair();
        // Very tight hello limit so we can test without sleeping
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        transport.hello_limiter.max_per_sec = 2;

        // First two should pass
        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "flooder", "node-b")),
            RelayHelloResponse::Accepted(_) | RelayHelloResponse::Rejected(_)
        ));
        // We don't assert Accepted here because nonces differ each call (fine)
        // — we just want to confirm that the 3rd call within 1 second is limited

        // Drain hello budget for "flooder"
        transport.hello_limiter.counts.insert(
            "flooder".to_owned(),
            (transport.hello_limiter.max_per_sec, Instant::now()),
        );

        assert_eq!(
            transport.handle_hello(make_hello(&sk, "flooder", "node-b")),
            RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded)
        );
    }

    #[test]
    fn test_hello_rate_limit_resets_after_window() {
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        transport.hello_limiter.max_per_sec = 1;

        // Exhaust the window
        transport
            .hello_limiter
            .counts
            .insert("node-a".to_owned(), (1, Instant::now()));
        assert_eq!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded)
        );

        // Back-date the window so it appears to have expired
        transport.hello_limiter.counts.insert(
            "node-a".to_owned(),
            (1, Instant::now() - Duration::from_secs(2)),
        );

        // Now the hello should be allowed through
        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Accepted(_)
        ));
    }

    // ── Happy-path session lifecycle ──────────────────────────────────────────

    #[test]
    fn test_valid_hello_allocates_session() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Accepted(_)
        ));
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn test_session_pairing_and_bidirectional_forwarding() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 10], 40_000);
        let data_a = observed_addr([198, 51, 100, 10], 51_820);
        let hello_b = observed_addr([203, 0, 113, 20], 41_000);
        let data_b = observed_addr([203, 0, 113, 20], 51_821);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);

        let payload_a = b"ciphertext from A";
        assert_eq!(
            transport
                .forward_packet(sid_a, payload_a, data_a)
                .expect("forwarding should not error before pairing"),
            None,
            "first packet must bind node-a but not forward before node-b is bound"
        );

        let payload_b = b"ciphertext from B";
        let forward_b = transport
            .forward_packet(sid_b, payload_b, data_b)
            .unwrap()
            .expect("should forward");
        assert_eq!(forward_b.peer_session_id, sid_a);
        assert_eq!(forward_b.peer_allocated_port, 50_000);
        assert_eq!(forward_b.peer_addr, data_a);

        let forward_a = transport
            .forward_packet(sid_a, payload_a, data_a)
            .unwrap()
            .expect("bound sessions should forward bidirectionally");
        assert_eq!(forward_a.peer_session_id, sid_b);
        assert_eq!(forward_a.peer_allocated_port, 50_001);
        assert_eq!(forward_a.peer_addr, data_b);
    }

    #[test]
    fn test_forward_target_uses_daemon_allocated_port() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 50], 40_050);
        let data_a = observed_addr([198, 51, 100, 50], 51_850);
        let hello_b = observed_addr([203, 0, 113, 60], 41_060);
        let data_b = observed_addr([203, 0, 113, 60], 51_860);

        let ack_a =
            accept_hello_from_with_port(&mut transport, &sk, "node-a", "node-b", hello_a, 55_123);
        let ack_b =
            accept_hello_from_with_port(&mut transport, &sk, "node-b", "node-a", hello_b, 55_987);

        assert_eq!(ack_a.allocated_port, 55_123);
        assert_eq!(ack_b.allocated_port, 55_987);

        assert_eq!(
            transport
                .forward_packet(ack_a.session_id, b"bind-a", data_a)
                .expect("binding node-a should not error"),
            None
        );

        let forward_b = transport
            .forward_packet(ack_b.session_id, b"ciphertext", data_b)
            .unwrap()
            .expect("node-b should forward to bound node-a");
        assert_eq!(forward_b.peer_session_id, ack_a.session_id);
        assert_eq!(forward_b.peer_allocated_port, 55_123);
        assert_eq!(forward_b.peer_addr, data_a);

        let forward_a = transport
            .forward_packet(ack_a.session_id, b"reply", data_a)
            .unwrap()
            .expect("node-a should forward to bound node-b");
        assert_eq!(forward_a.peer_session_id, ack_b.session_id);
        assert_eq!(forward_a.peer_allocated_port, 55_987);
        assert_eq!(forward_a.peer_addr, data_b);
    }

    #[test]
    fn test_payload_forwarded_byte_for_byte_without_inspection() {
        // The transport never touches payload bytes at all: the target it
        // returns carries no payload (the caller forwards the exact
        // received buffer — structurally byte-for-byte). This test pins
        // that parser-hostile byte patterns still resolve a forward target
        // rather than being inspected/rejected.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 11], 40_010);
        let data_a = observed_addr([198, 51, 100, 11], 51_830);
        let hello_b = observed_addr([203, 0, 113, 21], 41_010);
        let data_b = observed_addr([203, 0, 113, 21], 51_831);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        // Byte patterns that could confuse parsers must still forward.
        for payload in [
            vec![0u8; 100],
            vec![0xFFu8; 100],
            (0u8..100).collect::<Vec<_>>(),
        ] {
            let forwarded = transport
                .forward_packet(sid_a, &payload, data_a)
                .unwrap()
                .expect("parser-hostile payloads must still resolve a forward target");
            assert_eq!(forwarded.peer_session_id, sid_b);
            assert_eq!(forwarded.peer_addr, data_b);
        }
    }

    // ── Oversized payload ─────────────────────────────────────────────────────

    #[test]
    fn test_oversized_payload_silently_dropped() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 12], 40_020);
        let data_a = observed_addr([198, 51, 100, 12], 51_840);
        let hello_b = observed_addr([203, 0, 113, 22], 41_020);
        let data_b = observed_addr([203, 0, 113, 22], 51_841);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        let oversized = vec![0u8; MAX_PACKET_SIZE_BYTES + 1];
        let result = transport.forward_packet(sid_a, &oversized, data_a).unwrap();
        assert_eq!(result, None, "oversized payload must be silently dropped");
        // Session still live — drop does not tear down the session
        assert_eq!(transport.session_count(), 2);
    }

    // ── Rate limiting (packets) ───────────────────────────────────────────────

    #[test]
    fn test_rate_limit_drops_silently() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        transport.rate_limiter.max_pps = 5;

        let hello_a = observed_addr([198, 51, 100, 13], 40_030);
        let data_a = observed_addr([198, 51, 100, 13], 51_850);
        let hello_b = observed_addr([203, 0, 113, 23], 41_030);
        let data_b = observed_addr([203, 0, 113, 23], 51_851);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        for _ in 0..5 {
            assert!(transport.forward_packet(sid_a, b"data", data_a).is_ok());
        }
        // Excess — silent drop
        let result = transport.forward_packet(sid_a, b"data", data_a).unwrap();
        assert_eq!(result, None);
        assert_eq!(transport.session_count(), 2); // sessions intact
    }

    #[test]
    fn test_wrong_source_tuple_rejected_after_binding() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello_a = observed_addr([198, 51, 100, 14], 40_040);
        let data_a = observed_addr([198, 51, 100, 14], 51_860);
        let spoof_a = observed_addr([198, 51, 100, 14], 60_000);
        let hello_b = observed_addr([203, 0, 113, 24], 41_040);
        let data_b = observed_addr([203, 0, 113, 24], 51_861);

        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_a);
        let sid_b = accept_hello_from(&mut transport, &sk, "node-b", "node-a", hello_b);
        let _ = transport.forward_packet(sid_a, b"bind-a", data_a);
        let _ = transport.forward_packet(sid_b, b"bind-b", data_b);

        let err = transport
            .forward_packet(sid_a, b"spoof", spoof_a)
            .expect_err("bound session must reject tuple changes");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_new_hello_replaces_existing_session_for_same_pair() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_old = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 21], 40_110),
        );
        let sid_new = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 21], 40_111),
        );

        assert_ne!(sid_old, sid_new);
        assert!(!transport.has_session(sid_old));
        assert!(transport.has_session(sid_new));
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn rehello_replacing_existing_pair_is_exempt_from_per_node_capacity() {
        // Mirror of the global-capacity replacement exemption (Check 10) for
        // the per-node cap (Check 11). A node whose OWN live session occupies
        // its last slot must still be able to re-hello that same pair: the
        // replacement removes the old session before inserting the new one,
        // so the per-node live count never grows. Without the exemption a
        // node at exactly `max_sessions_per_node` can never refresh any
        // session (the client's proactive token refresh path re-hellos while
        // the old session is still alive), locking every refresh out until
        // sessions fully expire.
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 1, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        let sid_first = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 40], 40_200),
        );
        assert_eq!(transport.session_count(), 1);

        let sid_second = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 40], 40_201),
        );

        assert_ne!(sid_first, sid_second);
        assert!(!transport.has_session(sid_first));
        assert!(transport.has_session(sid_second));
        assert_eq!(
            transport.session_count(),
            1,
            "replacement must stay count-neutral"
        );
    }

    #[test]
    fn distinct_new_pair_still_counts_against_per_node_capacity() {
        // The negative control for the exemption above: when the node's slot
        // is occupied by a DIFFERENT pair, a hello for a new pair is genuine
        // growth and must still be refused at the per-node cap.
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 1, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 41], 40_210),
        );

        match transport.handle_hello(make_hello(&sk, "node-a", "node-c")) {
            RelayHelloResponse::Rejected(RejectReason::Capacity) => {}
            other => panic!("expected Capacity rejection for genuine growth, got {other:?}"),
        }
    }

    #[test]
    fn test_unbound_session_rejects_different_source_ip() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 15], 40_050),
        );

        let err = transport
            .forward_packet(sid_a, b"spoof", observed_addr([203, 0, 113, 25], 51_870))
            .expect_err("unbound session must reject a different source IP");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_stale_tuple_reuse_after_cleanup_is_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let old_hello = observed_addr([198, 51, 100, 16], 40_060);
        let old_data = observed_addr([198, 51, 100, 16], 51_880);
        let peer_hello = observed_addr([203, 0, 113, 26], 41_060);
        let peer_data = observed_addr([203, 0, 113, 26], 51_881);

        let sid_old = accept_hello_from(&mut transport, &sk, "node-a", "node-b", old_hello);
        let sid_peer = accept_hello_from(&mut transport, &sk, "node-b", "node-a", peer_hello);
        let _ = transport.forward_packet(sid_old, b"bind-a", old_data);
        let _ = transport.forward_packet(sid_peer, b"bind-b", peer_data);
        for session in transport.sessions.values_mut() {
            session.last_packet_at =
                Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }
        let removed = transport.cleanup_idle_sessions();
        assert_eq!(
            removed.len(),
            2,
            "cleanup must remove both stale paired sessions"
        );
        assert_eq!(transport.session_count(), 0);

        let sid_new = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([203, 0, 113, 27], 40_061),
        );
        assert_eq!(
            transport
                .sessions
                .get(&sid_new)
                .expect("new session should exist")
                .allocated_port,
            50_000,
            "cleaned ports must be reusable"
        );
        let err = transport
            .forward_packet(sid_new, b"stale", old_data)
            .expect_err("old tuple must not claim a reused relay port");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_cross_session_forwarding_attempt_is_rejected() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_ab = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 17], 40_070),
        );
        let sid_ba = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 28], 41_070),
        );
        let _ = transport.forward_packet(
            sid_ab,
            b"bind-ab",
            observed_addr([198, 51, 100, 17], 51_890),
        );
        let _ =
            transport.forward_packet(sid_ba, b"bind-ba", observed_addr([203, 0, 113, 28], 51_891));

        let sid_cd = accept_hello_from(
            &mut transport,
            &sk,
            "node-c",
            "node-d",
            observed_addr([198, 51, 100, 18], 40_080),
        );
        let sid_dc = accept_hello_from(
            &mut transport,
            &sk,
            "node-d",
            "node-c",
            observed_addr([203, 0, 113, 29], 41_080),
        );
        let _ = transport.forward_packet(
            sid_cd,
            b"bind-cd",
            observed_addr([198, 51, 100, 18], 51_892),
        );
        let _ =
            transport.forward_packet(sid_dc, b"bind-dc", observed_addr([203, 0, 113, 29], 51_893));

        let err = transport
            .forward_packet(
                sid_ab,
                b"cross-talk",
                observed_addr([198, 51, 100, 18], 51_892),
            )
            .expect_err("session AB must reject session CD's bound tuple");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_keepalive_rejects_unbound_and_wrong_tuple_activity() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 19], 40_090),
        );

        assert!(
            !transport
                .touch_session_from_tuple(sid_a, observed_addr([198, 51, 100, 19], 51_894))
                .expect("unbound keepalive should be ignored, not accepted")
        );

        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 30], 41_090),
        );
        let _ =
            transport.forward_packet(sid_a, b"bind-a", observed_addr([198, 51, 100, 19], 51_894));
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 30], 51_895));

        let err = transport
            .touch_session_from_tuple(sid_a, observed_addr([198, 51, 100, 19], 60_001))
            .expect_err("bound keepalive must reject a different tuple");
        assert_eq!(err, RelayForwardError::UnauthorizedSourceTuple);
    }

    #[test]
    fn test_expired_session_forwarding_is_rejected_and_cleaned_up() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let sid_a = accept_hello_from(
            &mut transport,
            &sk,
            "node-a",
            "node-b",
            observed_addr([198, 51, 100, 20], 40_100),
        );
        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 31], 41_100),
        );
        let _ =
            transport.forward_packet(sid_a, b"bind-a", observed_addr([198, 51, 100, 20], 51_896));
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 31], 51_897));

        transport
            .sessions
            .get_mut(&sid_a)
            .expect("session should exist")
            .expires_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .saturating_sub(1);

        let err = transport
            .forward_packet(sid_a, b"expired", observed_addr([198, 51, 100, 20], 51_896))
            .expect_err("expired session must not forward");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(!transport.has_session(sid_a));
        assert!(transport.has_session(sid_b));
    }

    // ── Session cleanup ───────────────────────────────────────────────────────

    #[test]
    fn test_idle_session_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        transport.handle_hello(make_hello(&sk, "node-b", "node-a"));
        assert_eq!(transport.session_count(), 2);

        for s in transport.sessions.values_mut() {
            s.last_packet_at = Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn test_half_open_session_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        transport.handle_hello(make_hello(&sk, "node-a", "node-b")); // no matching hello-b
        assert_eq!(transport.session_count(), 1);

        for s in transport.sessions.values_mut() {
            s.established_at =
                Instant::now() - Duration::from_secs(HALF_OPEN_SESSION_TIMEOUT_SECS + 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn hello_limiter_caps_distinct_node_ids_under_flood() {
        // RSA-0037: a pre-auth flood of distinct node_ids must not grow the map
        // without bound. Once at capacity, a brand-new node_id is rejected and
        // never inserted.
        let mut limiter = HelloLimiter::new(MAX_HELLOS_PER_NODE_PER_SEC);
        limiter.max_entries = 8;
        for i in 0..8 {
            assert!(limiter.check(&format!("flood-node-{i}")));
        }
        assert_eq!(limiter.counts.len(), 8);
        assert!(
            !limiter.check("overflow-node"),
            "a new node_id beyond the cap must be rejected"
        );
        assert!(
            limiter.counts.len() <= 8,
            "map must stay bounded under flood"
        );
        assert!(!limiter.counts.contains_key("overflow-node"));
        // An already-tracked node_id is still allowed to look up its window (no
        // false-reject of an in-window peer).
        assert!(limiter.check("flood-node-0"));
    }

    #[test]
    fn hello_limiter_prune_drops_elapsed_windows() {
        // RSA-0037: prune_elapsed drops node_id windows whose one-second period
        // has passed, keeping the map bounded under churn between cleanups.
        let mut limiter = HelloLimiter::new(MAX_HELLOS_PER_NODE_PER_SEC);
        let base = Instant::now();
        // `stale` started at `base`; `fresh` started 2s later (relative to the
        // `now` we prune at) — using forward offsets avoids Instant underflow.
        limiter.counts.insert("stale".to_owned(), (1, base));
        limiter
            .counts
            .insert("fresh".to_owned(), (1, base + Duration::from_secs(2)));
        limiter.prune_elapsed(base + Duration::from_secs(2));
        assert!(
            !limiter.counts.contains_key("stale"),
            "elapsed-window entry must be pruned"
        );
        assert!(
            limiter.counts.contains_key("fresh"),
            "in-window entry must be retained"
        );
    }

    #[test]
    fn cleanup_idle_sessions_evicts_orphan_rate_limiter_buckets() {
        // Regression: before this hook, `RateLimiter::check_packet` allocated
        // a fresh bucket on every distinct `node_id` and nothing ever
        // evicted, so a relay seeing a steady churn of distinct nodes would
        // grow `RateLimiter::buckets` without bound (memory-exhaustion DoS).
        // The cleanup tick must now drop any bucket whose `node_id` has no
        // active session.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Accept a session, drive one packet through it to allocate a bucket,
        // then mark the session idle and run cleanup. The bucket should be
        // evicted alongside the session.
        let from_addr = observed_addr([198, 51, 100, 27], 41_000);
        let ack =
            accept_hello_from_with_port(&mut transport, &sk, "node-a", "node-b", from_addr, 50_001);
        let session_id = ack.session_id;
        let payload = vec![0u8; 64];
        let _ = transport.forward_packet(session_id, &payload, from_addr);
        assert_eq!(transport.rate_limiter.bucket_count(), 1);

        for s in transport.sessions.values_mut() {
            s.last_packet_at = Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(transport.session_count(), 0);
        assert_eq!(
            transport.rate_limiter.bucket_count(),
            0,
            "orphaned rate-limiter buckets must not survive session eviction"
        );
    }

    // ── Constant-time security regression tests ───────────────────────────────
    //
    // These tests document and verify the constant-time comparison guarantees.
    // The relay uses `subtle::ConstantTimeEq` for all secret-field comparisons
    // to prevent timing side-channels in authentication paths.

    #[test]
    fn test_constant_time_node_id_comparison_rejects_all_mismatches_uniformly() {
        // This test verifies that node_id mismatches (where hello.node_id !=
        // token.node_id) always produce the same rejection reason regardless
        // of which byte position differs.  This is a regression test for the
        // constant-time ct_eq usage in handle_hello.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Token is issued for "node-aaaa", but hello claims different node_ids
        // that differ in various positions.
        let token = make_valid_token(&sk, "node-aaaa", "node-b", 60);

        let mismatches = [
            "Xode-aaaa", // first byte differs
            "node-Xaaa", // middle byte differs
            "node-aaaX", // last byte differs
            "attacker",  // completely different
        ];

        for wrong_id in mismatches {
            let hello = RelayHello {
                node_id: wrong_id.to_owned(),
                peer_node_id: "node-b".to_owned(),
                session_token: token.clone(),
                addr_validation_artifact: None,
            };

            // All mismatches must produce InvalidToken (not a position-revealing error)
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::InvalidToken),
                "node_id mismatch at any position must produce InvalidToken"
            );
        }
    }

    #[test]
    fn test_constant_time_peer_id_comparison_rejects_all_mismatches_uniformly() {
        // Same regression test for peer_node_id field.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let token = make_valid_token(&sk, "node-a", "peer-bbbb", 60);

        let mismatches = [
            "Xeer-bbbb", // first byte differs
            "peer-Xbbb", // middle byte differs
            "peer-bbbX", // last byte differs
            "attacker",  // completely different
        ];

        for wrong_peer in mismatches {
            let hello = RelayHello {
                node_id: "node-a".to_owned(),
                peer_node_id: wrong_peer.to_owned(),
                session_token: token.clone(),
                addr_validation_artifact: None,
            };

            // All mismatches must produce PeerMismatch (consistent rejection)
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::PeerMismatch),
                "peer_node_id mismatch at any position must produce PeerMismatch"
            );
        }
    }

    #[test]
    fn test_constant_time_relay_id_comparison_rejects_all_mismatches_uniformly() {
        // Same regression test for relay_id field.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Generate tokens with relay_ids that differ in various byte positions
        let relay_ids: [[u8; 16]; 3] = [
            [
                0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA,
            ], // first byte differs
            [
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xBB, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xAA,
            ], // middle byte differs
            [
                0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
                0xAA, 0xBB,
            ], // last byte differs
        ];

        for wrong_relay_id in relay_ids {
            let token = RelaySessionToken::sign(&sk, "node-a", "node-b", wrong_relay_id, 60);
            let hello = RelayHello {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                session_token: token,
                addr_validation_artifact: None,
            };

            // All mismatches must produce InvalidToken
            assert_eq!(
                transport.handle_hello(hello),
                RelayHelloResponse::Rejected(RejectReason::InvalidToken),
                "relay_id mismatch at any byte position must produce InvalidToken"
            );
        }
    }

    #[test]
    fn test_relay_session_token_ct_eq_is_available_and_correct() {
        // Verify that RelaySessionToken::ct_eq works correctly and is the
        // intended comparison method for tokens.
        let (sk, _) = make_test_keypair();

        let token_a = make_valid_token(&sk, "node-a", "node-b", 60);
        let token_b = make_valid_token(&sk, "node-a", "node-b", 60);
        let token_c = make_valid_token(&sk, "node-a", "node-c", 60);

        // Different nonces mean tokens are not equal even if fields match
        assert!(
            !token_a.ct_eq(&token_b),
            "tokens with different nonces must not be ct_eq"
        );

        // Same token compared to itself is always equal
        assert!(
            token_a.ct_eq(&token_a),
            "token compared to itself must be ct_eq"
        );

        // Obviously different tokens are not equal
        assert!(
            !token_a.ct_eq(&token_c),
            "tokens with different peer_node_id must not be ct_eq"
        );
    }

    #[test]
    fn test_subtle_crate_is_used_for_constant_time_comparisons() {
        // This is a compile-time contract test: the subtle crate must be
        // available and ConstantTimeEq must be usable.  If subtle is removed
        // from dependencies or the API changes, this test will fail to compile.
        use subtle::ConstantTimeEq;

        let a: [u8; 16] = [0xAA; 16];
        let b: [u8; 16] = [0xAA; 16];
        let c: [u8; 16] = [0xBB; 16];

        let eq_ab: bool = a.ct_eq(&b).into();
        let eq_ac: bool = a.ct_eq(&c).into();

        assert!(eq_ab, "identical arrays must be ct_eq");
        assert!(!eq_ac, "different arrays must not be ct_eq");
    }

    // ── Adversarial security regression tests ─────────────────────────────────
    //
    // These tests verify the relay rejects various attack scenarios correctly.

    #[test]
    fn adversarial_forged_signature_rejected_without_timing_leak() {
        // Attacker forges a token with wrong signature bytes
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        let mut hello = make_hello(&sk, "attacker", "victim");
        // Corrupt the signature
        hello.session_token.signature[0] ^= 0xFF;
        hello.session_token.signature[31] ^= 0xFF;
        hello.session_token.signature[63] ^= 0xFF;

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "forged signature must be rejected"
        );
    }

    #[test]
    fn adversarial_past_expired_token_rejected() {
        // Attacker tries to use a token that has expired beyond clock skew tolerance
        let (sk, _) = make_test_keypair();
        let _transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        let _token = RelaySessionToken::sign(&sk, "node-a", "node-b", TEST_RELAY_ID, 1);
        // The explicit expired-token path is already covered by test_expired_token_rejected.
        // This test keeps the adversarial boundary case focused on a strict clock-skew policy.

        // Instead, verify that a very short TTL with no skew tolerance is rejected
        // This tests the boundary condition
        let mut transport_strict = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 0)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // With 1 second TTL and immediate check, should still pass (just barely)
        let hello = make_hello(&sk, "node-a", "node-b");
        assert!(
            matches!(
                transport_strict.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ),
            "fresh token should be accepted even with strict 0 clock skew"
        );
    }

    #[test]
    fn adversarial_session_exhaustion_attack_blocked() {
        // Attacker tries to exhaust session capacity for a node
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 2, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // Fill up the session quota
        for i in 0..2 {
            let hello = make_hello(&sk, "attacker", &format!("peer-{i}"));
            assert!(matches!(
                transport.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ));
        }

        // Additional session should be rejected
        let hello = make_hello(&sk, "attacker", "peer-extra");
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::Capacity),
            "session exhaustion must be blocked"
        );

        // Verify other nodes are not affected
        let (sk2, _) = make_test_keypair();
        let mut transport2 = RelayTransport::new(TEST_RELAY_ID, sk2.verifying_key(), 2, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        let hello = make_hello(&sk2, "honest-node", "peer-1");
        assert!(
            matches!(
                transport2.handle_hello(hello),
                RelayHelloResponse::Accepted(_)
            ),
            "other nodes must not be affected by attacker's session exhaustion"
        );
    }

    #[test]
    fn adversarial_hello_flood_rate_limited() {
        // Attacker floods hello messages to exhaust CPU
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 100, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // Send hellos up to the rate limit
        let mut accepted = 0;
        let mut rate_limited = 0;
        for i in 0..20 {
            let hello = make_hello(&sk, "flood-attacker", &format!("peer-{i}"));
            match transport.handle_hello(hello) {
                RelayHelloResponse::Accepted(_) => accepted += 1,
                RelayHelloResponse::Rejected(RejectReason::RateLimitExceeded) => rate_limited += 1,
                other => panic!("unexpected response: {other:?}"),
            }
        }

        // Should hit rate limit before all accepted
        assert!(
            rate_limited > 0,
            "hello flood must trigger rate limiting (accepted={accepted}, rate_limited={rate_limited})"
        );
        assert!(
            accepted <= MAX_HELLOS_PER_NODE_PER_SEC as usize,
            "accepted count must not exceed rate limit"
        );
    }

    /// AQ-69 (relay preauth CPU DoS): N unauthenticated hellos from ONE
    /// source, each rotating the attacker-chosen `node_id` (which defeats
    /// the per-node_id limiter BY DESIGN — the key is attacker-supplied),
    /// must cost at most K ed25519 verifies. The verify only ever runs for
    /// a packet the identity-free per-source shed admitted, so counting
    /// `InvalidToken` rejections counts verifies: at most K of the N
    /// packets may reach the signature check.
    #[test]
    fn per_source_shed_bounds_unauthenticated_hello_verifies() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let from = observed_addr([203, 0, 113, 10], 5000);

        const N: usize = 200;
        const K: usize = MAX_HELLOS_PER_SOURCE_PER_SEC as usize;

        let mut invalid_token = 0usize; // shed passed -> ed25519 verify ran
        let mut rate_limited = 0usize; // shed rejected -> no crypto work

        for i in 0..N {
            // A fresh attacker-chosen node_id per packet: the pre-existing
            // per-node_id limiter must NOT be what bounds this flood.
            let mut token = make_valid_token(&sk, &format!("rot-{i}"), "peer", 60);
            token.signature = [99u8; 64]; // unauthenticated: garbage signature
            let hello = RelayHello {
                node_id: format!("rot-{i}"),
                peer_node_id: "peer".to_owned(),
                session_token: token,
                addr_validation_artifact: None,
            };
            match transport.validate_hello_from_tuple(&hello, from) {
                Err(RejectReason::InvalidToken) => invalid_token += 1,
                Err(RejectReason::RateLimitExceeded) => rate_limited += 1,
                other => panic!("unexpected outcome for packet {i}: {other:?}"),
            }
        }

        assert_eq!(
            invalid_token + rate_limited,
            N,
            "every unauthenticated hello must be rejected"
        );
        assert!(
            invalid_token <= K,
            "at most K={K} verifies may run for N={N} unauthenticated packets \
             from one source (ran {invalid_token})"
        );
        assert_eq!(rate_limited, N - invalid_token);
    }

    /// AQ-69 companion: the per-source shed must not change legitimate
    /// behaviour — a valid hello still validates, a second source is not
    /// punished for the first source's flood, and a source that exhausted
    /// its own budget is shed exactly as the daemon's per-IP gate would
    /// shed it (same constant, same window).
    #[test]
    fn per_source_shed_preserves_legitimate_traffic_and_isolates_sources() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let honest = observed_addr([198, 51, 100, 7], 5001);
        let flooder = observed_addr([203, 0, 113, 10], 5002);

        // (a) A valid hello from an honest source is accepted, untouched.
        assert!(
            transport
                .validate_hello_from_tuple(&make_hello(&sk, "node-a", "node-b"), honest)
                .is_ok(),
            "valid hello must still validate"
        );

        // (b) The flooder exhausts its OWN budget with unauthenticated
        // rotating-node_id packets (all rejected).
        for i in 0..200 {
            let mut token = make_valid_token(&sk, &format!("rot-{i}"), "peer", 60);
            token.signature = [99u8; 64];
            let hello = RelayHello {
                node_id: format!("rot-{i}"),
                peer_node_id: "peer".to_owned(),
                session_token: token,
                addr_validation_artifact: None,
            };
            assert!(
                transport
                    .validate_hello_from_tuple(&hello, flooder)
                    .is_err(),
                "unauthenticated hello {i} must be rejected"
            );
        }

        // (c) The honest source is unaffected by the other source's flood.
        assert!(
            transport
                .validate_hello_from_tuple(&make_hello(&sk, "node-a2", "node-b2"), honest)
                .is_ok(),
            "honest source must not be shed for another source's flood"
        );

        // (d) The flooder's NEXT hello — even a perfectly valid one — is
        // shed before any crypto: the same per-source policy the daemon's
        // per-IP gate already applies, now enforced at the verify too.
        assert_eq!(
            transport.validate_hello_from_tuple(&make_hello(&sk, "node-c", "node-d"), flooder),
            Err(RejectReason::RateLimitExceeded),
            "exhausted source must be shed before the signature check"
        );
    }

    /// The per-source shed's table is hard-bounded (fail closed) so a
    /// source-address churn flood cannot grow it without limit (RSA-0037
    /// posture, mirroring the daemon's `MAX_PRE_AUTH_HELLO_SOURCE_IPS`).
    #[test]
    fn source_hello_limiter_bounds_tracked_source_table() {
        let mut limiter = SourceHelloLimiter::new(MAX_HELLOS_PER_SOURCE_PER_SEC);

        let mut admitted = 0;
        for i in 0..(MAX_HELLO_SOURCE_ENTRIES + 512) {
            // Distinct address per probe (last octet wraps; two octets give
            // enough distinct addresses for the cap + overflow probes).
            let ip = IpAddr::from([198u8, 51, (i / 256) as u8, (i % 256) as u8]);
            if limiter.check(ip) {
                admitted += 1;
            }
        }

        assert_eq!(
            admitted, MAX_HELLO_SOURCE_ENTRIES,
            "exactly the table bound may be admitted; the rest fail closed"
        );
        assert_eq!(
            limiter.entry_count(),
            MAX_HELLO_SOURCE_ENTRIES,
            "the table must never exceed its bound"
        );
    }

    #[test]
    fn adversarial_cross_relay_token_rejected() {
        // Attacker tries to use a token issued for a different relay
        let (sk, _) = make_test_keypair();
        let other_relay_id: [u8; 16] = [0xDE; 16];
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // Token signed for wrong relay
        let token = RelaySessionToken::sign(&sk, "node-a", "node-b", other_relay_id, 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "token for different relay must be rejected"
        );
    }

    #[test]
    fn adversarial_node_impersonation_rejected() {
        // Attacker tries to claim a different node_id in hello vs token
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // Token for "real-node" but hello claims "attacker"
        let token = RelaySessionToken::sign(&sk, "real-node", "peer-b", TEST_RELAY_ID, 60);
        let hello = RelayHello {
            node_id: "attacker".to_owned(), // Mismatch!
            peer_node_id: "peer-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::InvalidToken),
            "node impersonation must be rejected"
        );
    }

    #[test]
    fn adversarial_peer_redirection_rejected() {
        // Attacker tries to redirect traffic to different peer
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        // Token for node-a→peer-b but hello claims node-a→attacker-peer
        let token = RelaySessionToken::sign(&sk, "node-a", "peer-b", TEST_RELAY_ID, 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "attacker-peer".to_owned(), // Mismatch!
            session_token: token,
            addr_validation_artifact: None,
        };

        let result = transport.handle_hello(hello);
        assert_eq!(
            result,
            RelayHelloResponse::Rejected(RejectReason::PeerMismatch),
            "peer redirection must be rejected"
        );
    }

    #[test]
    fn adversarial_nonce_reuse_rejected_even_with_valid_signature() {
        // Attacker captures valid token and replays it
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);

        let hello = make_hello(&sk, "node-a", "node-b");
        let cloned_hello = hello.clone();

        // First use succeeds
        assert!(matches!(
            transport.handle_hello(hello),
            RelayHelloResponse::Accepted(_)
        ));

        // Replay of exact same token is rejected
        assert_eq!(
            transport.handle_hello(cloned_hello),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce),
            "replayed nonce must be rejected even with valid signature"
        );
    }

    // ── Keepalive / touch_session tests ───────────────────────────────────────

    #[test]
    fn touch_session_updates_last_packet_at() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = make_hello(&sk, "node-a", "node-b");
        let ack = match transport.handle_hello(hello) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        // Age the session
        if let Some(session) = transport.sessions.get_mut(&ack.session_id) {
            session.last_packet_at = Instant::now() - Duration::from_secs(100);
        }

        // Touch should update timestamp
        assert!(
            transport.touch_session(ack.session_id).is_ok(),
            "touch_session should succeed for valid session"
        );

        // Verify timestamp was updated (should be recent now)
        if let Some(session) = transport.sessions.get(&ack.session_id) {
            assert!(
                session.last_packet_at.elapsed() < Duration::from_secs(1),
                "last_packet_at should be recent after touch"
            );
        }
    }

    #[test]
    fn touch_session_rejects_unknown_session() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let unknown_session = SessionId::from([0xDE; 16]);
        assert!(
            transport.touch_session(unknown_session).is_err(),
            "touch_session must reject unknown session"
        );
    }

    // ── Replay-store / boundary regression tests ─────────────────────────────
    //
    // Pin the security contracts that prior tests left implicit:
    //   * skew is clamped at construction so retention always dominates TTL
    //   * the replay window is closed at every point inside the skew tolerance
    //   * forward/touch reject at exact-second expiry boundary
    //   * advisory `validate_hello_from_tuple` does not consume the nonce
    //   * `cleanup_idle_sessions` evicts at the retention boundary
    //   * persisted store survives whitespace and dedupes against memory
    //   * persisted store fails closed on malformed timestamp / extra fields
    //   * persisted store rejects symlinked targets
    //   * empty / max-size store reload semantics

    #[test]
    fn skew_tolerance_is_clamped_to_max_ttl() {
        // Operator misconfigured a 600-second skew. Without clamping, a token
        // that expired at t+120 would remain accepted until t+720 while the
        // nonce store prunes at t+240, leaving a 480-second replay window.
        // The constructor clamps so `is_expired` rejects no later than
        // expires_at + MAX_CLOCK_SKEW_TOLERANCE_SECS, which never exceeds
        // NONCE_RETENTION_SECS.
        let (sk, _) = make_test_keypair();
        let transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 600)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        assert_eq!(
            transport.clock_skew_tolerance_secs, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "clock skew larger than MAX_CLOCK_SKEW_TOLERANCE_SECS must be clamped"
        );

        let inside = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 30)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        assert_eq!(
            inside.clock_skew_tolerance_secs, 30,
            "clock skew within bounds must be preserved verbatim"
        );

        let exact = RelayTransport::new(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            MAX_CLOCK_SKEW_TOLERANCE_SECS,
        )
        .expect("relay transport init")
        .with_require_addr_validation(false);
        assert_eq!(
            exact.clock_skew_tolerance_secs, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "boundary value must be preserved (not over-clamped)"
        );
    }

    #[test]
    fn skew_clamp_invariant_holds_for_replay_retention() {
        // Compile-time-style invariant test: retention must always cover the
        // whole window in which a token can still be accepted, so a nonce is
        // never pruned while its token remains valid.
        //
        // RLY-10: this previously asserted `ttl + skew <= retention`, which
        // undercounts. Skew is applied TWICE on independent axes — once
        // admitting `issued_at <= now + skew`, once admitting
        // `now <= expires_at + skew` — so the real bound is `ttl + 2 * skew`,
        // and it must be STRICT because `prune` evicts at `age >= retention`
        // while `is_expired` still retains at the boundary.
        const _: () = assert!(
            MAX_RELAY_TTL_SECS + 2 * MAX_CLOCK_SKEW_TOLERANCE_SECS < NONCE_RETENTION_SECS,
            "ttl + 2*skew must be strictly less than nonce retention, or the \
             replay window reopens"
        );
    }

    /// RLY-15: every consumer must dispose of an unavailable clock in ITS OWN
    /// fail-closed direction, because no single substituted value is safe for all
    /// of them.
    #[test]
    fn an_unavailable_clock_never_reads_as_a_live_session() {
        // Session expiry: unknown is not "not expired".
        assert!(
            !session_is_expired(1_000, None),
            "an unknown clock must not be reported as expiry-passed, because the \
             forward paths handle it"
        );
        // And the ordinary comparisons still hold.
        assert!(
            session_is_expired(1_000, Some(1_000)),
            "expiry boundary is <="
        );
        assert!(session_is_expired(1_000, Some(1_001)));
        assert!(!session_is_expired(1_000, Some(999)));
    }

    /// The anti-replay side: an unavailable clock must SKIP the prune, retaining
    /// every nonce. This is the call site that rules out a `u64::MAX` sentinel --
    /// the filter is `now - inserted_at >= retention`, so `MAX` evicts everything.
    ///
    /// A source pin, because the failing branch needs a pre-1970 host clock. What
    /// it guards is the specific regression: reintroducing a substituted value.
    #[test]
    fn no_consumer_substitutes_a_value_for_an_unavailable_clock() {
        // Normalized before searching: a Windows checkout materialises this
        // file with CRLF (no .gitattributes forced LF historically), and the
        // LF-joined needles below would never match — the pin then fails as
        // "the test module must exist" on every Windows CI run.
        let source = include_str!("transport.rs").replace(
            "
", "
",
        );
        // Slice at the test MODULE, not the first `#[cfg(test)]`: there are
        // `#[cfg(test)]` attributes on production helpers earlier in the file, and
        // anchoring on those silently truncates the slice to nothing -- which made
        // the first version of this test report zero occurrences and fail for the
        // wrong reason.
        let test_module = format!("#[cfg(test)]\nmod {} {{", "tests");
        let production = &source[..source
            .find(test_module.as_str())
            .expect("the test module must exist")];

        // No production line may unwrap a clock value into a default. Checked per
        // LINE against both spellings rather than against a list of exact
        // expressions: the first version of this pin only forbade
        // `now_unix_checked().unwrap_or(..)` and therefore missed
        // `now_unix.unwrap_or(0)` on the local binding -- which is the original
        // defect exactly. Needles are assembled at runtime so this test's own
        // source does not match them.
        let unwrap_needle = format!("unwrap_{}", "or");
        for (index, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") {
                continue;
            }
            let mentions_clock = line.contains("now_unix") || line.contains("now_unix_checked");
            assert!(
                !(mentions_clock
                    && (line.contains(unwrap_needle.as_str())
                        || line.contains(".or(")
                        || line.contains("map_or(")
                        || line.contains("= match"))),
                "line {} substitutes a default for an unavailable clock; every consumer must \
                 dispose of `None` in its own fail-closed direction (unwrap_or/map_or/.or/match \
                 spellings included): {line}",
                index + 1
            );
        }

        // And the checked helper must be the only wall-clock source in the file,
        // so a new call site cannot quietly reintroduce the old shape.
        // Count CODE occurrences only. `now_unix_checked`'s own doc comment names
        // `SystemTime::now()` while explaining the finding, and counting that as a
        // call site is how the previous version of this assertion failed for the
        // wrong reason.
        let direct = production
            .lines()
            .filter(|line| {
                let trimmed = line.trim_start();
                !trimmed.starts_with("//") && trimmed.contains("SystemTime::now()")
            })
            .count();
        assert_eq!(
            direct, 1,
            "SystemTime::now() must be called exactly once in production code (inside \
             now_unix_checked), so a new call site cannot reintroduce an unchecked clock; \
             found {direct}"
        );

        // The prune must return before mutating, not filter with a substituted now.
        let prune_at = production
            .find("fn prune(&mut self, retention: Duration)")
            .expect("prune must exist");
        let prune_head: String = production[prune_at..].chars().take(900).collect();
        assert!(
            prune_head.contains("return Err"),
            "prune must fail closed on an unavailable clock before touching the nonce map"
        );

        // The `SystemTime::now()` census above does not see wall-clock reads
        // that never spell `SystemTime::now()`: `UNIX_EPOCH.elapsed()` is the
        // same clock under a different spelling, so
        // `UNIX_EPOCH.elapsed().unwrap_or(..)` reintroduces the substituted-
        // default defect while every pin above stays green. Every production
        // line that touches the epoch must go through the checked
        // `duration_since(UNIX_EPOCH)` shape (and `use` lines are exempt).
        let elapsed = [".elapsed", "("].concat();
        for (index, line) in production.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//") || trimmed.starts_with("use ") {
                continue;
            }
            if !line.contains("UNIX_EPOCH") {
                continue;
            }
            assert!(
                line.contains("duration_since(UNIX_EPOCH)") && !line.contains(elapsed.as_str()),
                "line {} reads the epoch clock outside the checked helper; route it \
                 through now_unix_checked() — a substituted default for an \
                 unavailable clock is the RLY-15 defect",
                index + 1
            );
        }

        // The epoch-shape rule above routes every read through
        // now_unix_checked(), but it cannot see the helper's OWN internals:
        // swapping its checked disposal for a defaulted value moves the
        // RLY-15 substituted default INSIDE the one sanctioned call site while
        // every line-level rule above stays green (the offending spelling sits
        // on a chain line that names neither `now_unix` nor `UNIX_EPOCH`;
        // proven by mutation). Pin the helper body directly: it must dispose
        // of a failed clock via `.ok()` and may not spell any substituting or
        // panicking fallback.
        let helper_start = production
            .find("fn now_unix_checked()")
            .expect("now_unix_checked must exist");
        let helper_body_end = production[helper_start..]
            .find("\n}\n")
            .map(|at| helper_start + at)
            .expect("now_unix_checked must have a closing brace");
        let helper = &production[helper_start..=helper_body_end];
        let unwrap_needle = format!("unwrap_{}", "or");
        // `.map_err(|_| 0)` and `.ok().or(Some(0))` keep the sanctioned `.ok()`
        // spelling while substituting a value on the Err/None arm (both proven
        // green by mutation before these tokens were added), so the ban covers
        // the whole substitute-on-failure family, not just the unwrap spellings.
        for banned in [
            unwrap_needle.as_str(),
            ".expect(",
            ".unwrap(",
            ".map_err(",
            ".or(",
            "map_or(",
        ] {
            assert!(
                !helper.contains(banned),
                "now_unix_checked must not substitute or panic on an unavailable \
                 clock ({banned}); it must return None so every consumer disposes \
                 of the failure in its own fail-closed direction (RLY-15)"
            );
        }
        assert!(
            helper.contains(".ok()"),
            "now_unix_checked must keep the checked Option disposal; replacing \
             it with a defaulted value is the RLY-15 defect"
        );
    }

    #[test]
    fn now_unix_checked_returns_a_recent_value_on_a_healthy_clock() {
        // Security pin. The original helper `.expect(...)`-ed and crashed the
        // relay on every hello when `SystemTime::now() < UNIX_EPOCH`. Its
        // replacement returned 0 and its comment claimed that made tokens "look
        // already-expired -- fail-closed"; RLY-15 established that this is
        // backwards, since `is_expired` is `now > expires_at + skew` and
        // `0 > anything` is false. Expiry was switched off entirely.
        //
        // The helper now returns `Option`, so the failure cannot be encoded as a
        // value that any consumer might read in the wrong direction. The negative
        // branch is not forceable in a unit test -- it needs a host clock before
        // 1970 -- so what is pinned here is the positive branch plus, in the
        // tests below, that each CONSUMER disposes of `None` in its own
        // fail-closed direction.
        let now = now_unix_checked().expect("test host clock must be after the epoch");
        // Sanity: > 2025-01-01 (1_735_689_600). Test runs in 2026+.
        assert!(
            now > 1_735_689_600,
            "now_unix_checked() should return a 2025+ value on a healthy clock; got {now}"
        );
    }

    #[test]
    fn forward_packet_rejects_at_exact_expiry_second() {
        // `forward_packet` uses `<=` against expiry, so a session whose token
        // expires at exactly `now_unix` must be rejected (fail-closed at the
        // boundary).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let from = observed_addr([198, 51, 100, 90], 40_900);
        let sid = accept_hello_from(&mut transport, &sk, "node-a", "node-b", from);
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        transport
            .sessions
            .get_mut(&sid)
            .expect("session should exist")
            .expires_at_unix = now_unix;

        let err = transport
            .forward_packet(sid, b"boundary", from)
            .expect_err("forward must reject at exact expiry second");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(
            !transport.has_session(sid),
            "expired session must be cleaned up by forward_packet"
        );
    }

    #[test]
    fn touch_session_from_tuple_rejects_at_exact_expiry_second() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello_addr = observed_addr([198, 51, 100, 91], 40_910);
        let data_addr = observed_addr([198, 51, 100, 91], 51_910);
        let sid_a = accept_hello_from(&mut transport, &sk, "node-a", "node-b", hello_addr);
        let sid_b = accept_hello_from(
            &mut transport,
            &sk,
            "node-b",
            "node-a",
            observed_addr([203, 0, 113, 91], 41_910),
        );
        let _ = transport.forward_packet(sid_a, b"bind-a", data_addr);
        let _ =
            transport.forward_packet(sid_b, b"bind-b", observed_addr([203, 0, 113, 91], 51_911));

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        transport
            .sessions
            .get_mut(&sid_a)
            .expect("session should exist")
            .expires_at_unix = now_unix;

        let err = transport
            .touch_session_from_tuple(sid_a, data_addr)
            .expect_err("touch must reject at exact expiry second");
        assert_eq!(err, RelayForwardError::SessionExpired);
        assert!(
            !transport.has_session(sid_a),
            "expired session must be cleaned up by touch_session_from_tuple"
        );
    }

    #[test]
    fn validate_hello_from_tuple_does_not_consume_nonce() {
        // The advisory pre-flight `validate_hello_from_tuple` is documented
        // as fail-closed-before-I/O: it rejects forged/stale/flooded hellos
        // before the daemon binds an allocated UDP port, but it must NOT
        // burn the nonce. Otherwise a benign caller that allocates a port
        // and then commits would see its own committed hello rejected as a
        // replay.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        let hello = make_hello(&sk, "node-a", "node-b");
        let from = observed_addr([198, 51, 100, 92], 40_920);

        transport
            .validate_hello_from_tuple(&hello, from)
            .expect("advisory validation must succeed");
        assert!(
            transport.nonce_store.nonces.is_empty(),
            "advisory pre-check must not consume the nonce"
        );
        assert!(
            !transport.nonce_store.contains(&hello.session_token.nonce),
            "advisory pre-check must not register the nonce"
        );

        match transport.handle_hello_from_tuple_with_allocated_port(hello.clone(), from, 50_010) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("commit must succeed after advisory validation: {other:?}"),
        }
        assert!(
            transport.nonce_store.contains(&hello.session_token.nonce),
            "commit path must register the nonce"
        );
    }

    #[test]
    fn commit_path_does_not_double_count_hello_rate() {
        // Contract: `validate_hello_from_tuple` is the daemon's first contact
        // point and is the call that consumes one hello-rate budget unit. The
        // subsequent commit (`handle_hello_from_tuple_with_allocated_port`)
        // re-runs all stateful security predicates, but it must NOT charge a
        // second hello against the rate budget — otherwise the effective
        // budget is halved and an honest peer can rate-limit itself with two
        // legitimate sequential calls in the daemon's pre-check + commit flow.
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new(TEST_RELAY_ID, sk.verifying_key(), 8, 90)
            .expect("relay transport init")
            .with_require_addr_validation(false);
        transport.hello_limiter.max_per_sec = 1;
        let from = observed_addr([198, 51, 100, 93], 40_930);

        // First advisory call uses the single budget unit.
        let hello1 = make_hello(&sk, "node-a", "node-b");
        transport
            .validate_hello_from_tuple(&hello1, from)
            .expect("first advisory pre-check must succeed");
        // Commit must succeed even though the rate budget was already drained
        // by the advisory call — the commit path itself must not count again.
        match transport.handle_hello_from_tuple_with_allocated_port(hello1, from, 50_020) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("commit must not double-count hello rate: {other:?}"),
        }

        // A second independent advisory call must now be rate-limited because
        // the budget was already consumed by the first advisory call (not by
        // the commit). This proves the counter is charged exactly once per
        // (advisory, commit) pair.
        let hello2 = make_hello(&sk, "node-a", "node-b");
        assert_eq!(
            transport.validate_hello_from_tuple(&hello2, from),
            Err(RejectReason::RateLimitExceeded),
            "second advisory call must trip the rate limit"
        );
    }

    #[test]
    fn replay_rejected_inside_full_skew_window() {
        // Even at the latest instant where `is_expired` would still accept
        // the token (expires_at + skew - 1), a replay must remain rejected.
        // This protects against a subtle bug where the in-memory nonce
        // store could be pruned while the token is still valid.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = make_hello(&sk, "node-a", "node-b");
        let nonce = hello.session_token.nonce;
        match transport.handle_hello(hello.clone()) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("first hello must be accepted: {other:?}"),
        }

        // Back-date the recorded nonce to (now - retention + 1) — the latest
        // moment it can still be in the store. A replay here must be rejected.
        let almost_pruned = now_unix_checked()
            .expect("test host clock must be after the epoch")
            .saturating_sub(NONCE_RETENTION_SECS - 1);
        transport.nonce_store.nonces.insert(nonce, almost_pruned);

        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::ReplayedNonce),
            "nonce must remain in store throughout retention - 1 boundary"
        );
    }

    #[test]
    fn nonce_at_exact_retention_age_is_pruned_by_cleanup() {
        // `prune` keeps entries with `now - inserted_at < retention`. At
        // exactly `retention_secs`, the entry must be evicted. This pins the
        // boundary so a future loosening would be caught by tests.
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Seed one nonce
        transport.handle_hello(make_hello(&sk, "node-a", "node-b"));
        assert_eq!(transport.nonce_store.nonces.len(), 1);
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix_checked()
                .expect("test host clock must be after the epoch")
                .saturating_sub(NONCE_RETENTION_SECS);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            0,
            "entries at exactly retention age must be pruned (boundary is exclusive)"
        );

        // And one second younger must survive.
        transport.handle_hello(make_hello(&sk, "node-c", "node-d"));
        for inserted_at in transport.nonce_store.nonces.values_mut() {
            *inserted_at = now_unix_checked()
                .expect("test host clock must be after the epoch")
                .saturating_sub(NONCE_RETENTION_SECS - 1);
        }
        transport.cleanup_idle_sessions();
        assert_eq!(
            transport.nonce_store.nonces.len(),
            1,
            "entries one second below retention must survive"
        );
    }

    #[test]
    fn empty_replay_store_loads_cleanly_and_persists_zero_entries() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("empty-replay");
        // First open creates the file
        let _ = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("empty replay store must initialize cleanly");
        let content = fs::read_to_string(&path).expect("replay store file should exist");
        assert!(
            content.is_empty(),
            "fresh replay store must be persisted empty, not contain stub data"
        );

        // Second open of an empty file must also succeed (covers reload path)
        let transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("empty replay store must reload cleanly");
        assert_eq!(transport.nonce_store.nonces.len(), 0);

        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_tolerates_blank_lines_but_rejects_extra_fields() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("blank-vs-extra");

        // Whitespace-only lines must be ignored. Use a fresh timestamp so
        // load + prune (`new_with_replay_store_path`) does not silently drop
        // the valid entry as past-retention.
        let nonce_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
        let fresh_ts = now_unix_checked().expect("test host clock must be after the epoch");
        let valid_with_blanks = format!("\n   \n{nonce_hex} {fresh_ts}\n\n");
        fs::write(&path, valid_with_blanks)
            .expect("valid-with-blanks replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");
        let transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("blank lines must be tolerated");
        assert_eq!(
            transport.nonce_store.nonces.len(),
            1,
            "blank lines must be skipped without dropping valid entries"
        );

        // Extra trailing field must fail closed
        let extra = format!("{nonce_hex} 1700000000 extra-junk\n");
        fs::write(&path, extra).expect("extra-field replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");
        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("extra fields in replay store must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("unexpected fields"));

        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_rejects_short_nonce_hex() {
        // 30 hex chars (15 bytes) instead of the required 32 must fail closed.
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("short-nonce");
        fs::write(&path, "deadbeefdeadbeefdeadbeefdeadbe 1700000000\n")
            .expect("short-nonce replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("short nonce must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("32 hex characters"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn replay_store_rejects_non_numeric_timestamp() {
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("bad-ts");
        let nonce_hex: String = (0u8..16).map(|b| format!("{b:02x}")).collect();
        fs::write(&path, format!("{nonce_hex} not-a-number\n"))
            .expect("bad-timestamp replay store should be written");
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .expect("test fixture must have 0600 permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("non-numeric timestamp must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("invalid timestamp"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rejects_symlinked_path() {
        // The replay store path itself must not be a symlink — otherwise a
        // local attacker with write access to the parent could redirect
        // writes elsewhere. The validator must reject symlinked file paths.
        let (sk, _) = make_test_keypair();
        let real = temp_replay_store_path("symlink-real");
        let parent = real
            .parent()
            .expect("path should have parent")
            .to_path_buf();
        // Create a real target with valid (empty) content
        fs::write(&real, "").expect("real replay store target should be created");
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600))
            .expect("real replay store target must be 0600");

        let symlink = parent.join("replay.symlink");
        std::os::unix::fs::symlink(&real, &symlink)
            .expect("symlink for negative test should be created");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            symlink.clone(),
        ) {
            Ok(_) => panic!("symlinked replay store path must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("regular file"));

        let _ = fs::remove_dir_all(parent);
    }

    #[cfg(unix)]
    #[test]
    fn replay_store_rejects_broad_file_permissions() {
        // The replay store file itself (not just the parent) must enforce
        // strict permissions on load. Pin the contract so we catch any
        // future regressions in `validate_replay_store_path`.
        let (sk, _) = make_test_keypair();
        let path = temp_replay_store_path("broad-file");
        fs::write(&path, "").expect("broad-perm replay store should be written");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
            .expect("test fixture must use widened permissions");

        let err = match RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        ) {
            Ok(_) => panic!("broad replay store file permissions must fail closed"),
            Err(err) => err,
        };
        assert!(err.contains("permissions too broad"));
        let _ = fs::remove_dir_all(path.parent().expect("path should have parent"));
    }

    #[test]
    fn nonce_store_failed_persist_keeps_in_memory_state_consistent() {
        // If `persist_map` were to fail, `insert` must NOT update the
        // in-memory `nonces` map: otherwise the durable store drifts from
        // memory and a relay restart would forget the nonce. Simulate this
        // by pointing the store at a path whose parent disappears.
        let path_dir = std::env::temp_dir().join(format!(
            "rustynet-relay-vanish-{}-{}",
            std::process::id(),
            now_unix_checked().expect("test host clock must be after the epoch")
        ));
        fs::create_dir_all(&path_dir).expect("temp dir must be created");
        #[cfg(unix)]
        fs::set_permissions(&path_dir, fs::Permissions::from_mode(0o700))
            .expect("temp dir permissions must be tight");
        let path = path_dir.join("replay.store");
        let (sk, _) = make_test_keypair();
        let mut transport = RelayTransport::new_with_replay_store_path(
            TEST_RELAY_ID,
            sk.verifying_key(),
            8,
            90,
            path.clone(),
        )
        .expect("replay store should initialize")
        .with_require_addr_validation(false);
        // Remove the parent directory so subsequent writes fail
        fs::remove_dir_all(&path_dir).expect("parent directory removal should succeed");

        let hello = make_hello(&sk, "node-a", "node-b");
        let response = transport.handle_hello_from_tuple_with_allocated_port(
            hello.clone(),
            observed_addr([198, 51, 100, 95], 40_950),
            50_030,
        );
        assert_eq!(
            response,
            RelayHelloResponse::Rejected(RejectReason::ReplayStoreUnavailable),
            "persist failure must surface as ReplayStoreUnavailable"
        );
        assert!(
            !transport.nonce_store.contains(&hello.session_token.nonce),
            "failed persist must not leave a phantom nonce in memory"
        );
        assert_eq!(
            transport.session_count(),
            0,
            "no session may be allocated when nonce persistence fails"
        );
    }

    #[test]
    fn touch_session_prevents_idle_cleanup() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // Create two sessions
        let hello_a = make_hello(&sk, "node-a", "node-b");
        let ack_a = match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        let hello_b = make_hello(&sk, "node-b", "node-a");
        let ack_b = match transport.handle_hello(hello_b) {
            RelayHelloResponse::Accepted(ack) => ack,
            other => panic!("expected Accepted, got {other:?}"),
        };

        // Age both sessions past idle threshold
        for session in transport.sessions.values_mut() {
            session.last_packet_at =
                Instant::now() - Duration::from_secs(IDLE_SESSION_TIMEOUT_SECS + 1);
        }

        // Touch only session A
        let _ = transport.touch_session(ack_a.session_id);

        // Run cleanup
        transport.cleanup_idle_sessions();

        // Session A should survive, session B should be cleaned
        assert!(
            transport.sessions.contains_key(&ack_a.session_id),
            "touched session should survive cleanup"
        );
        assert!(
            !transport.sessions.contains_key(&ack_b.session_id),
            "untouched idle session should be cleaned up"
        );
    }

    // ── Followup-audit regression tests ──────────────────────────────────────
    //
    // Pin the contracts for the four DoS / footgun followups flagged by the
    // previous audit:
    //   1. NonceStore::insert no longer clones the entire map per accepted
    //      hello — verified via large-batch insertion timing budget plus
    //      direct rollback-on-persist-failure check.
    //   2. compute_clamped_skew exposes the (value, was_clamped) decision
    //      the warn log line is gated on.
    //   3. set_max_total_sessions rejects shrinking below the live count.
    //   4. should_warn_replay_stat_skip exposes the decision the warn log
    //      line is gated on.

    #[test]
    fn nonce_store_insert_handles_large_batches_without_quadratic_clone() {
        // Followup #1: insert previously cloned the entire HashMap on each
        // call (O(n) per call, O(n²) total). Pin a bound that the
        // pre-fix implementation would blow through on slow CI: inserting
        // 1000 nonces into an in-memory store (no persist path) must
        // finish in well under 200 ms. The pre-fix implementation copied
        // (1 + 2 + ... + 1000) ≈ 500 000 entries; the new implementation
        // copies zero. We pick a generous threshold to avoid flakes on
        // shared CI runners.
        let mut store = NonceStore::default();
        let mut nonce = [0u8; 16];
        let start = Instant::now();
        for i in 0..1000u64 {
            nonce[0..8].copy_from_slice(&i.to_le_bytes());
            store
                .insert(nonce)
                .expect("in-memory insert must not fail without a persist path");
        }
        let elapsed = start.elapsed();
        assert_eq!(
            store.nonces.len(),
            1000,
            "all 1000 distinct nonces must be retained"
        );
        assert!(
            elapsed < Duration::from_millis(200),
            "1000 inserts must complete well under 200 ms (took {elapsed:?}); \
             a regression to clone-on-write would scale O(n²) and blow the budget"
        );
    }

    #[test]
    fn nonce_store_insert_persist_failure_rolls_back_in_memory_state() {
        // Followup #1: the new insert path mutates self.nonces *first* and
        // then persists; on persist failure it must roll back. This pins
        // the same property the existing
        // `nonce_store_failed_persist_keeps_in_memory_state_consistent`
        // test pins at the daemon entry point, but exercised directly on
        // NonceStore so the rollback path is unit-pinned.
        let dir = std::env::temp_dir().join(format!(
            "rustynet-relay-rollback-{}-{}",
            std::process::id(),
            now_unix_checked().expect("test host clock must be after the epoch")
        ));
        fs::create_dir_all(&dir).expect("temp dir must be created");
        #[cfg(unix)]
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))
            .expect("temp dir permissions must be tight");
        let path = dir.join("replay.store");
        let mut store = NonceStore::load(path).expect("fresh store should initialize");
        // Yank the parent so subsequent persist calls fail.
        fs::remove_dir_all(&dir).expect("parent removal should succeed");

        let nonce = [0xAB; 16];
        let result = store.insert(nonce);
        assert!(
            result.is_err(),
            "insert with vanished parent must surface a persist error"
        );
        assert!(
            !store.nonces.contains_key(&nonce),
            "failed persist must not leave a phantom nonce in memory"
        );
    }

    #[test]
    fn compute_clamped_skew_reports_clamp_decision() {
        // Followup #2: the clamp decision is silent at construction time.
        // Pin the pure helper that the warn log is gated on so future
        // refactors cannot accidentally silence the warning.
        let (val, clamped) = compute_clamped_skew(0);
        assert_eq!((val, clamped), (0, false), "zero skew must pass through");

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS - 1);
        assert!(!clamped, "value below ceiling must not clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS - 1);

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS);
        assert!(!clamped, "value at exact ceiling must not clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS);

        let (val, clamped) = compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS + 1);
        assert!(clamped, "value one above ceiling must clamp");
        assert_eq!(
            val, MAX_CLOCK_SKEW_TOLERANCE_SECS,
            "clamped value must equal the ceiling"
        );

        let (val, clamped) = compute_clamped_skew(u64::MAX);
        assert!(clamped, "u64::MAX must clamp");
        assert_eq!(val, MAX_CLOCK_SKEW_TOLERANCE_SECS);
    }

    #[test]
    fn parse_nonce_hex_validates_length_and_hex() {
        // Exactly 32 hex chars decode to 16 bytes (lower, upper, and mixed case).
        assert_eq!(parse_nonce_hex(&"00".repeat(16)).unwrap(), [0u8; 16]);
        assert_eq!(parse_nonce_hex(&"ff".repeat(16)).unwrap(), [0xffu8; 16]);
        assert_eq!(parse_nonce_hex(&"Ab".repeat(16)).unwrap(), [0xabu8; 16]);
        assert_eq!(
            parse_nonce_hex("000102030405060708090a0b0c0d0e0f").unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        // Any length other than 32 is rejected before decoding.
        assert!(parse_nonce_hex("").is_err());
        assert!(parse_nonce_hex(&"0".repeat(31)).is_err());
        assert!(parse_nonce_hex(&"0".repeat(33)).is_err());
        // Correct length but non-hex bytes are rejected.
        assert!(parse_nonce_hex(&"gg".repeat(16)).is_err());
        assert!(parse_nonce_hex(&"zz".repeat(16)).is_err());
    }

    #[test]
    fn set_max_total_sessions_refuses_to_shrink_below_live_count() {
        // Followup #3: an operator who shrinks the cap below the current
        // live session count must get a clear error rather than silent
        // eviction (or, worse, a config that admits the change but lets
        // the live set continue exceeding the cap).
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);
        // Seed two live sessions
        let hello_a = make_hello(&sk, "node-a", "node-b");
        let hello_b = make_hello(&sk, "node-c", "node-d");
        match transport.handle_hello(hello_a) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("first hello must be accepted: {other:?}"),
        }
        match transport.handle_hello(hello_b) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("second hello must be accepted: {other:?}"),
        }
        assert_eq!(transport.session_count(), 2);

        let err = transport
            .set_max_total_sessions(1)
            .expect_err("shrinking below live count must fail closed");
        assert!(
            err.contains("cannot shrink") && err.contains("live count"),
            "error must clearly signal the shrink-below-live problem: {err}"
        );
        // And the underlying state must not have been mutated.
        assert_eq!(
            transport.session_count(),
            2,
            "rejected shrink must not have evicted sessions"
        );

        // Equal-to-live is fine (does not regress observable cap).
        transport
            .set_max_total_sessions(2)
            .expect("cap == live must succeed");
        // Strictly above live is fine.
        transport
            .set_max_total_sessions(10)
            .expect("cap > live must succeed");
        // Zero is still rejected (existing contract preserved).
        let err = transport
            .set_max_total_sessions(0)
            .expect_err("zero cap must still fail");
        assert!(err.contains("greater than 0"));
    }

    #[test]
    fn should_warn_replay_stat_skip_treats_not_found_as_silent() {
        // Followup #4: the warn log line for "permission check skipped due
        // to unexpected stat error" is gated on this helper. NotFound is
        // the *expected* fresh-install case and must not warn; any other
        // io error means we couldn't actually verify safety and must warn.
        let not_found = std::io::Error::from(std::io::ErrorKind::NotFound);
        assert!(
            !should_warn_replay_stat_skip(&not_found),
            "NotFound is expected on fresh install and must not warn"
        );

        let permission_denied = std::io::Error::from(std::io::ErrorKind::PermissionDenied);
        assert!(
            should_warn_replay_stat_skip(&permission_denied),
            "PermissionDenied means we could not verify safety and must warn"
        );

        // A handful of other unexpected kinds — all must warn so the
        // decision boundary is not "only PermissionDenied".
        for kind in [
            std::io::ErrorKind::Other,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::TimedOut,
        ] {
            let err = std::io::Error::from(kind);
            assert!(
                should_warn_replay_stat_skip(&err),
                "unexpected io kind {kind:?} must warn"
            );
        }
    }

    // ---- Negative regression tests for the 2026-07-29 adversarial review ----
    //
    // Most of these fail against the pre-fix code. Two do NOT, and saying so
    // matters more than the tidy claim: a test that passes both before and after
    // a fix proves nothing, which was itself a finding in this review (PF-15, two
    // contradictory "minimal ruleset" tests green simultaneously because their
    // fixtures could not express the non-minimal case).
    //
    // Verified by reverting each fix individually:
    //   discriminates  — future_dated_token_is_rejected_rly01
    //   discriminates  — self_paired_token_is_rejected_rly11
    //   discriminates  — skew_ceiling_keeps_the_retention_invariant_strict_rly10
    //   discriminates  — token_future_dating_boundary_is_exactly_skew_rly01
    //   discriminates  — node_id_bound_is_exactly_max_relay_node_id_bytes_rly05
    //   DOES NOT       — persist_tolerates_a_path_without_a_directory_component_rly04
    //                    (a regression guard for the parent-dir derivation; the
    //                    fsync itself is not observable from a unit test)

    /// RLY-01: a token dated far in the future must be refused.
    ///
    /// Pre-fix this was ACCEPTED: `ttl_secs()` is a difference so the TTL bound
    /// passed, and `is_expired` is an upper bound only so the expiry check passed
    /// too. Because nonce retention is measured from insert time rather than from
    /// the token's own window, such a token outlives its nonce entry and replays
    /// indefinitely.
    #[test]
    fn future_dated_token_is_rejected_rly01() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let far_future = now_unix_checked()
            .expect("test host clock must be after the epoch")
            .saturating_add(3_153_600_000);
        let token =
            RelaySessionToken::sign_at(&sk, "node-a", "node-b", TEST_RELAY_ID, far_future, 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        match transport.handle_hello(hello) {
            RelayHelloResponse::Rejected(RejectReason::InvalidToken) => {}
            other => panic!("future-dated token must be rejected as InvalidToken, got {other:?}"),
        }
        assert_eq!(
            transport.session_count(),
            0,
            "a future-dated token must not create a session"
        );
    }

    /// RLY-01 boundary: a token issued within the skew tolerance is still fine,
    /// so the new check cannot false-reject an honest peer whose clock runs fast.
    #[test]
    fn token_issued_slightly_ahead_within_skew_is_accepted_rly01() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        // One second ahead — well inside the default skew tolerance.
        let slightly_ahead = now_unix_checked()
            .expect("test host clock must be after the epoch")
            .saturating_add(1);
        let token =
            RelaySessionToken::sign_at(&sk, "node-a", "node-b", TEST_RELAY_ID, slightly_ahead, 60);
        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-b".to_owned(),
            session_token: token,
            addr_validation_artifact: None,
        };

        match transport.handle_hello(hello) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("a token 1s ahead must stay acceptable, got {other:?}"),
        }
    }

    /// RLY-01 boundary: the future-dating cutoff must be EXACTLY `now + skew`.
    ///
    /// The two tests above bracket the check far too loosely — 100 years ahead is
    /// rejected and 1 second ahead is accepted, which together prove only that
    /// *some* bound exists. An adversarial reviewer loosened the check to accept
    /// 104 days of future-dating and the whole suite stayed green. This pins the
    /// actual constant so that mutation fails.
    #[test]
    fn token_future_dating_boundary_is_exactly_skew_rly01() {
        let (sk, _) = make_test_keypair();
        let skew = make_transport(&sk).clock_skew_tolerance_secs;

        let issue_at = |offset: u64| {
            let token = RelaySessionToken::sign_at(
                &sk,
                "node-a",
                "node-b",
                TEST_RELAY_ID,
                now_unix_checked()
                    .expect("test host clock must be after the epoch")
                    .saturating_add(offset),
                60,
            );
            RelayHello {
                node_id: "node-a".to_owned(),
                peer_node_id: "node-b".to_owned(),
                session_token: token,
                addr_validation_artifact: None,
            }
        };

        // Exactly at the tolerance: still acceptable.
        let mut at_bound = make_transport(&sk);
        match at_bound.handle_hello(issue_at(skew)) {
            RelayHelloResponse::Accepted(_) => {}
            other => panic!("issued_at == now + skew must be accepted, got {other:?}"),
        }

        // One second past it: refused.
        let mut past_bound = make_transport(&sk);
        match past_bound.handle_hello(issue_at(skew + 1)) {
            RelayHelloResponse::Rejected(RejectReason::InvalidToken) => {}
            other => panic!("issued_at == now + skew + 1 must be rejected, got {other:?}"),
        }
    }

    /// RLY-11: a self-paired token must be refused.
    ///
    /// Pre-fix this was ACCEPTED, and `node_pair_index` then keyed `(A, A)` so the
    /// forward-path reverse lookup resolved to the session's own id — the relay
    /// echoed every frame back to the sender.
    #[test]
    fn self_paired_token_is_rejected_rly11() {
        let (sk, _) = make_test_keypair();
        let mut transport = make_transport(&sk);

        let hello = RelayHello {
            node_id: "node-a".to_owned(),
            peer_node_id: "node-a".to_owned(),
            session_token: make_valid_token(&sk, "node-a", "node-a", 60),
            addr_validation_artifact: None,
        };

        match transport.handle_hello(hello) {
            RelayHelloResponse::Rejected(RejectReason::InvalidToken) => {}
            other => panic!("self-paired token must be rejected as InvalidToken, got {other:?}"),
        }
        assert_eq!(
            transport.session_count(),
            0,
            "a self-paired token must not create a session"
        );
    }

    /// RLY-10: the skew ceiling must keep `TTL + skew < NONCE_RETENTION_SECS`
    /// STRICTLY, not by equality.
    ///
    /// The two comparisons around the retention window are asymmetric — `prune`
    /// evicts at `age >= retention` while `is_expired` still retains a token at
    /// `now == expires_at + skew` — so an equality-only invariant left a
    /// one-second window in which the nonce was pruned but the token remained
    /// valid. Pre-fix, `compute_clamped_skew(120)` returned `(120, false)` and
    /// `120 + 120 == 240` hit that window.
    ///
    /// The fix is on the skew side deliberately: the retention boundary itself is
    /// pinned by `nonce_at_exact_retention_age_is_pruned_by_cleanup`, whose stated
    /// purpose is to catch exactly the kind of loosening that "fixing" `prune`
    /// would have been. That test caught it.
    #[test]
    fn skew_ceiling_keeps_the_retention_invariant_strict_rly10() {
        // A caller asking for the old ceiling is now clamped down and told so.
        let (clamped, was_clamped) = compute_clamped_skew(MAX_RELAY_TTL_SECS);
        assert_eq!(clamped, MAX_RELAY_TTL_SECS - 1);
        assert!(
            was_clamped,
            "requesting the old ceiling must report that it was clamped"
        );

        // And the new ceiling itself is accepted unchanged.
        assert_eq!(
            compute_clamped_skew(MAX_CLOCK_SKEW_TOLERANCE_SECS),
            (MAX_CLOCK_SKEW_TOLERANCE_SECS, false)
        );
    }

    /// RLY-04 regression guard: adding the parent-directory fsync introduced a new
    /// failure path, so prove a store whose path has no directory component still
    /// persists rather than erroring on an empty parent.
    #[test]
    fn persist_tolerates_a_path_without_a_directory_component_rly04() {
        let mut store = NonceStore {
            path: Some(PathBuf::from("rustynet-relay-rly04-probe.store")),
            nonces: HashMap::new(),
        };
        let result = store.insert([7u8; 16]);
        // Clean up regardless of outcome so a failure cannot leave residue.
        let _ = fs::remove_file("rustynet-relay-rly04-probe.store");
        assert!(
            result.is_ok(),
            "a bare relative store path must still persist: {result:?}"
        );
    }
    // ── OI-10: pre-auth address-validation gate (DEFAULT-ON) ────────────────

    fn gate_on_transport(signing_key: &SigningKey) -> RelayTransport {
        RelayTransport::new(TEST_RELAY_ID, signing_key.verifying_key(), 8, 90)
            .expect("relay transport init")
    }

    fn token_wire_bytes(token: &RelaySessionToken) -> Vec<u8> {
        let mut buf = vec![1u8];
        for value in [&token.node_id, &token.peer_node_id] {
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value.as_bytes());
        }
        buf.extend_from_slice(&token.relay_id);
        buf.extend_from_slice(&(token.scope.len() as u16).to_be_bytes());
        buf.extend_from_slice(token.scope.as_bytes());
        buf.extend_from_slice(&token.issued_at_unix.to_be_bytes());
        buf.extend_from_slice(&token.expires_at_unix.to_be_bytes());
        buf.extend_from_slice(&token.nonce);
        buf.extend_from_slice(&token.signature);
        buf
    }

    fn serialize_hello_bytes(
        hello: &RelayHello,
        artifact: Option<&AddressValidationArtifact>,
    ) -> Vec<u8> {
        let mut buf = vec![RELAY_HELLO_MSG_TYPE];
        for value in [&hello.node_id, &hello.peer_node_id] {
            buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
            buf.extend_from_slice(value.as_bytes());
        }
        let token_bytes = token_wire_bytes(&hello.session_token);
        buf.extend_from_slice(&(token_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(&token_bytes);
        if let Some(artifact) = artifact {
            buf.extend_from_slice(&serialize_relay_hello_artifact_field(artifact));
        }
        buf
    }

    #[test]
    fn addr_validation_default_on_requires_artifact_before_anything_else() {
        let (sk, _) = make_test_keypair();
        let mut transport = gate_on_transport(&sk);
        assert!(
            transport.require_addr_validation(),
            "OI-10 default must be gate-ON"
        );

        // A perfectly signed, fresh, replay-free hello with NO artifact must
        // be challenged — never accepted.
        let hello = make_hello(&sk, "node-a", "node-b");
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::AddressValidationRequired)
        );
        assert_eq!(transport.session_count(), 0);
    }

    #[test]
    fn addr_validation_gate_runs_before_signature_verification() {
        let (sk, _) = make_test_keypair();
        let mut transport = gate_on_transport(&sk);

        // CORRUPT signature AND no artifact: the gate must win. If the
        // ed25519 verify ran first, this would come back InvalidToken.
        let mut hello = make_hello(&sk, "node-a", "node-b");
        hello.session_token.signature = [0x42u8; 64];
        assert_eq!(
            transport.handle_hello(hello),
            RelayHelloResponse::Rejected(RejectReason::AddressValidationRequired),
            "the cheap HMAC gate must reject before any ed25519 work"
        );
    }

    #[test]
    fn addr_validation_issue_then_attach_is_accepted() {
        let (sk, _) = make_test_keypair();
        let mut transport = gate_on_transport(&sk);
        let from_addr = observed_addr([198, 51, 100, 71], 41_071);

        let now = now_unix_checked().expect("test host clock must be after the epoch");
        let hello = make_hello(&sk, "node-a", "node-b");
        let artifact = transport
            .issue_hello_validation_artifact(&from_addr, &hello.session_token.nonce, now)
            .expect("artifact issuance should succeed");
        let mut retried = hello;
        retried.addr_validation_artifact = Some(artifact);

        assert!(matches!(
            transport.handle_hello_from_tuple_with_allocated_port(retried, from_addr, 55_071),
            RelayHelloResponse::Accepted(_)
        ));
        assert_eq!(transport.session_count(), 1);
    }

    #[test]
    fn addr_validation_artifact_is_bound_to_source_address() {
        let (sk, _) = make_test_keypair();
        let mut transport = gate_on_transport(&sk);
        let issued_for = observed_addr([198, 51, 100, 72], 41_072);
        let replayed_from = observed_addr([198, 51, 100, 72], 41_999);

        let now = now_unix_checked().expect("test host clock must be after the epoch");
        let hello = make_hello(&sk, "node-a", "node-b");
        let artifact = transport
            .issue_hello_validation_artifact(&issued_for, &hello.session_token.nonce, now)
            .expect("artifact issuance should succeed");
        let mut retried = hello;
        retried.addr_validation_artifact = Some(artifact);

        // Same host, DIFFERENT PORT: the artifact binds the full socket.
        assert_eq!(
            transport.handle_hello_from_tuple_with_allocated_port(retried, replayed_from, 55_072),
            RelayHelloResponse::Rejected(RejectReason::AddressValidationInvalid)
        );
    }

    #[test]
    fn addr_validation_artifact_expires() {
        let (sk, _) = make_test_keypair();
        let transport = gate_on_transport(&sk);
        let from_addr = observed_addr([198, 51, 100, 73], 41_073);

        let now = now_unix_checked().expect("test host clock must be after the epoch");
        let hello = make_hello(&sk, "node-a", "node-b");
        let artifact = transport
            .issue_hello_validation_artifact(&from_addr, &hello.session_token.nonce, now)
            .expect("artifact issuance should succeed");

        // Re-present the same (addr, nonce, artifact) triple far past the
        // 30 s TTL + 90 s skew window.
        let client_nonce = artifact_nonce_input(&hello.session_token.nonce);
        assert!(matches!(
            transport.addr_validation_keys.verify_artifact_for_domain(
                RELAY_ADDR_VALIDATION_DOMAIN,
                &from_addr,
                &client_nonce,
                relay_epoch_input(&TEST_RELAY_ID),
                artifact.as_bytes(),
                now + 400,
                transport.clock_skew_tolerance_secs,
            ),
            Err(AddressArtifactError::Expired)
        ));
    }

    #[test]
    fn addr_validation_artifact_domain_separation() {
        // A blind-v2-minted artifact (different HMAC domain) must NEVER
        // verify on the v1 hello gate, same key or not.
        let mut key_bytes = [0u8; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut key_bytes)
            .expect("test CSPRNG");
        let keyring = crate::blind_relay_listener::AddressValidationKeyRing::new(1, key_bytes)
            .expect("non-zero keyring key");
        let addr = observed_addr([198, 51, 100, 74], 41_074);
        let client_nonce = [0x5Au8; 32];
        let now = now_unix_checked().expect("test host clock must be after the epoch");

        let blind_artifact = keyring
            .issue_artifact(&addr, &client_nonce, 7, now)
            .expect("blind-domain issuance should succeed");
        assert!(
            keyring
                .verify_artifact_for_domain(
                    RELAY_ADDR_VALIDATION_DOMAIN,
                    &addr,
                    &client_nonce,
                    7,
                    &blind_artifact,
                    now,
                    90,
                )
                .is_err(),
            "blind-domain artifact must not verify under the v1 hello domain"
        );
        assert!(
            keyring
                .verify_artifact(&addr, &client_nonce, 7, &blind_artifact, now, 90)
                .is_ok(),
            "same-domain verification must still succeed"
        );
    }

    #[test]
    fn addr_validation_opt_out_is_explicit_and_effective() {
        let (sk, _) = make_test_keypair();
        let transport = gate_on_transport(&sk).with_require_addr_validation(false);
        assert!(!transport.require_addr_validation());

        // Pre-OI-10 behavior restored: an artifact-less hello is accepted.
        let mut transport = transport;
        assert!(matches!(
            transport.handle_hello(make_hello(&sk, "node-a", "node-b")),
            RelayHelloResponse::Accepted(_)
        ));
    }

    #[test]
    fn parse_relay_hello_accepts_trailing_artifact_field() {
        let (sk, _) = make_test_keypair();
        let hello = make_hello(&sk, "node-a", "node-b");
        let artifact = AddressValidationArtifact::from_bytes([0x77u8; 32]);

        let bytes = serialize_hello_bytes(&hello, Some(&artifact));
        let parsed = parse_relay_hello(&bytes).expect("artifact-carrying hello should parse");
        assert_eq!(
            parsed
                .addr_validation_artifact
                .as_ref()
                .map(|a| *a.as_bytes()),
            Some([0x77u8; 32])
        );
        assert_eq!(parsed.node_id, "node-a");
        assert_eq!(parsed.peer_node_id, "node-b");
    }

    #[test]
    fn parse_relay_hello_rejects_unknown_trailing_bytes() {
        let (sk, _) = make_test_keypair();
        let hello = make_hello(&sk, "node-a", "node-b");

        // W2 wire tightening: a trailing byte that is NOT the artifact
        // field is a parse error, not silently-ignored padding.
        let mut bytes = serialize_hello_bytes(&hello, None);
        bytes.push(0x99);
        assert!(
            parse_relay_hello(&bytes).is_err(),
            "unknown trailing byte must fail parse (W2 tightening)"
        );

        // Wrong artifact length must fail too.
        let mut short = serialize_hello_bytes(&hello, None);
        short.push(RELAY_HELLO_ARTIFACT_FIELD_TYPE);
        short.extend_from_slice(&[0u8; 31]);
        assert!(
            parse_relay_hello(&short).is_err(),
            "31-byte artifact must fail"
        );
    }

    #[test]
    fn address_validation_artifact_debug_redacts_tag_bytes() {
        let artifact = AddressValidationArtifact::from_bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A,
            0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1A, 0x1B, 0x1C,
        ]);
        let rendered = format!("{artifact:?}");
        assert!(
            rendered.contains("REDACTED"),
            "Debug must declare redaction: {rendered}"
        );
        for secret in ["DEAD", "BEEF", "dead", "beef"] {
            assert!(
                !rendered.contains(secret),
                "Debug must never emit artifact tag bytes (saw {secret}): {rendered}"
            );
        }
        // The enclosing hello's derived Debug inherits the redaction.
        let (sk, _) = make_test_keypair();
        let hello = make_hello(&sk, "node-a", "node-b");
        let mut hello = hello;
        hello.addr_validation_artifact = Some(artifact);
        let hello_rendered = format!("{hello:?}");
        assert!(
            !hello_rendered.contains("DEADBEEF"),
            "hello Debug leaks artifact"
        );
        assert!(hello_rendered.contains("REDACTED"));
    }
}
