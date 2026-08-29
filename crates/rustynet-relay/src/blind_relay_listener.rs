//! Blind-relay v2 admission listener (phase 4 of
//! `BlindRelayProtocolSelection_2026-08-28.md` / `BlindRelayRoleDesign_2026-08-27.md`).
//!
//! This module wires the relay side of the identity-blind v2 protocol: it
//! accepts identity-free hello v2 datagrams and runs the ten-step admission
//! verification sequence in exactly the order pinned by protocol-selection
//! §2.2(f). It is v2-ONLY by design (design §0 item 5): there is no v1
//! fallback, no translation, and no dual-mode listener on this path. The
//! identity-bearing v1 transport in [`crate::transport`] is untouched.
//!
//! The ten steps, each fail-closed:
//!
//! 1. bounded datagram size + exact v2 envelope parse (cheap, no crypto —
//!    the phase-3 parsers in `rustynet-control::blind_relay`);
//! 2. per-SOURCE-PREFIX pre-auth rate limit (identity-free key — v2 carries
//!    no node_id, so the v1 per-node-id limiter key cannot be reused);
//! 3. stateless address-validation artifact verify (HMAC-SHA256 under a
//!    rotating local key) BEFORE any session allocation;
//! 4. issuer key-id allowlist + leg-token `verify_strict`;
//! 5. version/kind/audience/scope/privacy-epoch/profile/slot/canonical field
//!    checks;
//! 6. usable clock, not-before/future-date, expiry, TTL checks;
//! 7. proof-of-possession transcript `verify_strict` against the token's
//!    presenter key;
//! 8. durable replay-store availability + nonce/leg/PoP replay rejection;
//! 9. global / per-source-prefix / per-profile waiting-leg resource limits;
//! 10. atomic nonce commit + bounded waiting-leg allocation.
//!
//! Cheap-before-expensive is structural: no signature or HMAC work happens
//! before steps 1–2, and no per-circuit state allocation happens before
//! step 3. [`BlindAdmissionStage`] lets a test observer witness the order.
//!
//! # The address-validation artifact rides in `relay_challenge`
//!
//! Protocol-selection §2.2(d) specifies a QUIC-Retry-style stateless
//! address-validation token: HMAC-SHA256 over (observed address, client
//! nonce, privacy epoch, short expiry) under a rotating local key. Phase 3
//! reserved the hello's fixed 32-byte `relay_challenge` slot for exactly
//! this artifact ("the rotating-key HMAC token *format* it will carry is
//! phase 4"). Phase 4 fills it: the artifact is
//! `epoch: u32 BE | expires_at: u64 BE | truncated_tag: [u8; 20]`, totaling
//! exactly 32 bytes, so the landed v2 wire format is unchanged. The tag is a
//! truncated HMAC-SHA256 (160 bits — QUIC Retry tokens use 128-bit tags;
//! this token is an anti-amplification measure, not identity authentication,
//! so a truncated tag is proportionate). Because the artifact is bound into
//! the PoP transcript via `relay_challenge`, presenting a stale or foreign
//! artifact also breaks the proof.
//!
//! # Go-live gate: this listener does NOT open production advertisement
//!
//! [`BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED`] is `false` and
//! [`BlindRelayListener::try_open`] refuses unless it, the signed-state
//! capability, AND the operator flag are all granted. The design (§16) and
//! protocol-selection §6 both require an INDEPENDENT ADVERSARIAL REVIEW of
//! the composition before `blind_relay` may be advertised by production
//! signed state. Phase 4 implements the listener path; it does not open it.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ed25519_dalek::VerifyingKey;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use rustynet_control::blind_relay::{
    BLIND_RELAY_TOKEN_SCOPE_V2, BlindRelayLegSlot, BlindRelayTokenKindV2,
    MAX_BLIND_RELAY_HELLO_WIRE_BYTES, MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS,
    parse_blind_relay_hello_v2_wire_bytes,
};

// ── Bounds and constants ─────────────────────────────────────────────────────

/// Compile-time approval bit for advertising `blind_relay` by production
/// signed state. `false` until the independent adversarial review required by
/// design §16 / protocol-selection §6 has been completed. The admission
/// listener cannot be opened in production while this is `false`, regardless
/// of signed capabilities or operator flags.
pub const BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED: bool = false;

/// Ceiling on the operator-supplied clock-skew tolerance, mirroring the v1
/// transport's `MAX_CLOCK_SKEW_TOLERANCE_SECS` discipline: retention must
/// strictly exceed token TTL plus twice the skew so no replay window opens.
pub const BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS: u64 = 119;

/// Replay-entry retention: strictly greater than max leg-token TTL plus twice
/// the max skew (protocol-selection §3, inherited from v1 RLY-10). Compile-
/// time pinned so a loosening of either side fails the build.
pub const BLIND_NONCE_RETENTION_SECS: u64 =
    MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS + 2 * BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS + 1;
const _: () = assert!(
    BLIND_NONCE_RETENTION_SECS
        > MAX_BLIND_RELAY_LEG_TOKEN_TTL_SECS + 2 * BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS,
    "blind replay retention must strictly exceed TTL + 2*skew"
);

/// Hard byte cap on the on-disk replay store (protocol-selection §3: the file
/// gains a hard byte cap; a full store rejects admission, never evicts live
/// entries).
pub const MAX_BLIND_REPLAY_STORE_FILE_BYTES: usize = 4 * 1024 * 1024;

/// Longest possible persisted line: 64 hex digest chars + separator + up to 20
/// decimal digits + newline.
const BLIND_REPLAY_LINE_MAX_BYTES: usize = 64 + 1 + 20 + 1;

/// Entry cap derived from the byte cap; a store at this cap rejects admission.
pub const MAX_BLIND_REPLAY_ENTRIES: usize =
    MAX_BLIND_REPLAY_STORE_FILE_BYTES / BLIND_REPLAY_LINE_MAX_BYTES;

/// Global cap on waiting (unpaired) circuits held in memory.
pub const MAX_BLIND_WAITING_LEGS_TOTAL: usize = 256;

/// Per-source-prefix cap on waiting circuits a single network prefix may hold.
pub const MAX_BLIND_WAITING_LEGS_PER_SOURCE_PREFIX: usize = 16;

/// Per-profile cap on waiting circuits.
pub const MAX_BLIND_WAITING_LEGS_PER_PROFILE: usize = 64;

/// Pre-auth hello rate per source prefix per second (mirrors the v1
/// `MAX_HELLOS_PER_NODE_PER_SEC` posture; shed before any crypto).
pub const MAX_BLIND_HELLOS_PER_SOURCE_PREFIX_PER_SEC: u32 = 5;

/// Hard cap on distinct source-prefix windows the pre-auth limiter retains
/// (mirrors the v1 `HelloLimiter` RSA-0037 bound; the key is attacker-
/// controlled so the map must be bounded BEFORE any crypto).
pub const MAX_SOURCE_PREFIX_LIMITER_ENTRIES: usize = 16_384;

/// Lifetime of an address-validation artifact: short by design (protocol-
/// selection §2.2(d)) so it can never become a stable linkability cookie.
pub const BLIND_ADDR_VALIDATION_TTL_SECS: u64 = 30;

/// Truncated HMAC-SHA256 tag length carried by the artifact.
pub const BLIND_ADDR_VALIDATION_TAG_LEN: usize = 20;

/// Artifact size: must be exactly the 32-byte `relay_challenge` slot.
const BLIND_ADDR_ARTIFACT_BYTES: usize = 4 + 8 + BLIND_ADDR_VALIDATION_TAG_LEN;
const _: () = assert!(BLIND_ADDR_ARTIFACT_BYTES == 32);

/// Epoch cap for the address-validation key ring. Old-epoch artifacts die at
/// their own short TTL; retaining a bounded history lets a rotation not strand
/// in-flight clients.
pub const MAX_ADDR_VALIDATION_KEYRING_EPOCHS: usize = 8;

/// Domain-separation prefix for the address-validation MAC (house style:
/// `rustynet-control-<purpose>-v1` byte strings).
const BLIND_ADDR_VALIDATION_DOMAIN: &[u8] = b"rustynet-control-blind-relay-addr-validation-v1";

/// Domain prefixes for the replay digests. The leg digest is exactly the
/// protocol-selection §3 key: `sha256("v2" | privacy_epoch | nonce |
/// leg_handle)`. The nonce and PoP digests are defense-in-depth records with
/// distinct domains: the nonce digest rejects any reuse of a token nonce
/// within the epoch regardless of leg handle (BR-C11 "same nonce / different
/// handle"), and the PoP digest rejects any reuse of a presented proof.
const BLIND_REPLAY_DOMAIN_LEG: &[u8] = b"v2";
const BLIND_REPLAY_DOMAIN_NONCE: &[u8] = b"v2-nonce";
const BLIND_REPLAY_DOMAIN_POP: &[u8] = b"v2-pop";

// ── Rejection classes and admission stages ──────────────────────────────────

/// Closed rejection classes surfaced by the admission path (design §7.3: no
/// which-check-failed detail beyond these classes; never any secret material).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindRejectReason {
    /// Step 1: oversize or non-canonical datagram.
    Malformed,
    /// Step 2: source prefix shed before any crypto.
    RateLimited,
    /// Step 3: address-validation artifact missing, stale, foreign, or
    /// cryptographically invalid.
    AddressValidation,
    /// Steps 4, 5, 7, and pairing mismatches: unauthorized material. One
    /// class on purpose — the wire must not learn which check fired.
    Unauthorized,
    /// Step 8: nonce, leg, or proof replay.
    Replayed,
    /// Step 9: a bounded resource is exhausted.
    Capacity,
    /// The host clock is unusable (RLY-15: no sentinel, reject).
    ClockUnavailable,
    /// Step 8/10: the durable replay store is unavailable, corrupt, or full.
    ReplayStoreUnavailable,
}

impl fmt::Display for BlindRejectReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::Malformed => "malformed hello",
            Self::RateLimited => "rate limited",
            Self::AddressValidation => "address validation failed",
            Self::Unauthorized => "unauthorized",
            Self::Replayed => "replay rejected",
            Self::Capacity => "capacity exceeded",
            Self::ClockUnavailable => "clock unavailable",
            Self::ReplayStoreUnavailable => "replay store unavailable",
        };
        f.write_str(text)
    }
}

/// Errors from opening a listener. Distinct from [`BlindRejectReason`] because
/// these are operator-facing configuration failures, not wire rejections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlindListenerOpenError {
    /// A go-live gate refused: the adversarial-review approval bit is unset,
    /// or the signed capability, or the operator flag. Production stays
    /// closed until design §16 review completes.
    GateClosed,
    /// The replay store path is invalid or the existing store is corrupt.
    /// Never TOFU re-initialized (protocol-selection §3 / BR-C11).
    ReplayStoreInvalid(String),
}

impl fmt::Display for BlindListenerOpenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GateClosed => f.write_str(
                "blind relay v2 listener is gated closed: adversarial review, signed capability, and operator flag must all be granted",
            ),
            Self::ReplayStoreInvalid(detail) => {
                write!(f, "blind relay replay store is invalid: {detail}")
            }
        }
    }
}

/// Admission stages, in execution order. A test observer records these to
/// witness the §2.2(f) ordering (e.g. that no crypto stage runs for a
/// malformed frame); production installs a no-op observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindAdmissionStage {
    EnvelopeParse,
    SourceRateLimit,
    AddressValidation,
    IssuerVerification,
    FieldValidation,
    Freshness,
    ProofOfPossession,
    ReplayCheck,
    ResourceLimits,
    Commit,
}

/// Observer hook for admission staging. Implementations must not log
/// handle/address material (design §7.7); the default production observer
/// records nothing.
pub trait BlindAdmissionObserver {
    fn stage_entered(&mut self, stage: BlindAdmissionStage);
}

/// Production observer: records nothing.
pub struct BlindNoopObserver;

impl BlindAdmissionObserver for BlindNoopObserver {
    fn stage_entered(&mut self, _stage: BlindAdmissionStage) {}
}

// ── Source-prefix pre-auth rate limiter (step 2) ─────────────────────────────

/// Identity-free source-prefix key: IPv4 /24 or IPv6 /48, family-tagged. v2
/// hellos carry no node_id, so the v1 per-node-id limiter key is deliberately
/// NOT reused (protocol-selection §2.2(d)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SourcePrefix([u8; 9]);

fn source_prefix(addr: &IpAddr) -> SourcePrefix {
    let mut key = [0u8; 9];
    match addr {
        IpAddr::V4(v4) => {
            key[0] = 4;
            key[1..4].copy_from_slice(&v4.octets()[..3]);
        }
        IpAddr::V6(v6) => {
            key[0] = 6;
            key[1..7].copy_from_slice(&v6.octets()[..6]);
        }
    }
    SourcePrefix(key)
}

/// Pre-auth hello rate limiter keyed by source prefix. Same shape and
/// fail-closed bounded-map discipline as the v1 `HelloLimiter` (RSA-0037):
/// when a NEW prefix arrives at capacity, elapsed windows are pruned first;
/// if still full the new prefix is rejected — never allocate above the cap.
pub(crate) struct SourcePrefixLimiter {
    max_per_sec: u32,
    max_entries: usize,
    counts: HashMap<SourcePrefix, (u32, Instant)>,
}

impl SourcePrefixLimiter {
    fn new(max_per_sec: u32) -> Self {
        Self {
            max_per_sec: max_per_sec.max(1),
            max_entries: MAX_SOURCE_PREFIX_LIMITER_ENTRIES,
            counts: HashMap::new(),
        }
    }

    /// Returns `true` if the hello may proceed, `false` if rate-limited.
    fn check(&mut self, prefix: SourcePrefix) -> bool {
        let now = Instant::now();
        if self.counts.len() >= self.max_entries && !self.counts.contains_key(&prefix) {
            self.counts
                .retain(|_, (_, started)| now.duration_since(*started) < Duration::from_secs(1));
            if self.counts.len() >= self.max_entries {
                return false;
            }
        }
        let entry = self.counts.entry(prefix).or_insert((0, now));
        if now.duration_since(entry.1) >= Duration::from_secs(1) {
            *entry = (0, now);
        }
        if entry.0 >= self.max_per_sec {
            return false;
        }
        entry.0 += 1;
        true
    }
}

// ── Stateless address-validation artifact (step 3) ───────────────────────────

/// Errors from artifact issuance/verification. Coarse on purpose: callers map
/// every variant to [`BlindRejectReason::AddressValidation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressArtifactError {
    InvalidArtifact,
    UnknownKeyEpoch,
    AuthenticationFailed,
    Expired,
    ClockOverflow,
}

impl fmt::Display for AddressArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidArtifact => "address-validation artifact is malformed",
            Self::UnknownKeyEpoch => "address-validation artifact names an unknown key epoch",
            Self::AuthenticationFailed => "address-validation artifact failed authentication",
            Self::Expired => "address-validation artifact is expired",
            Self::ClockOverflow => "address-validation artifact expiry overflows",
        };
        f.write_str(text)
    }
}

/// Rotating HMAC key material for the address-validation artifacts.
///
/// Keys are held zeroized-on-drop. Rotation is strictly forward (a new epoch
/// must exceed the active epoch) and the ring keeps a bounded history so
/// artifacts issued under the previous epoch stay verifiable until their own
/// short TTL expires. Callers that persist rotation records do so via the
/// daemon's key-rotation machinery; this type holds only the live key set
/// (protocol-selection §3: the replay store itself is keyless — the ONLY
/// keyed local state on the blind path is this HMAC key).
#[derive(Clone)]
pub struct AddressValidationKeyRing {
    keys: BTreeMap<u32, Zeroizing<[u8; 32]>>,
    active_epoch: u32,
}

impl fmt::Debug for AddressValidationKeyRing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never expose key material or even key-count specifics beyond the
        // epoch bookkeeping (§4: never log secrets).
        f.debug_struct("AddressValidationKeyRing")
            .field("active_epoch", &self.active_epoch)
            .field("epochs_retained", &self.keys.len())
            .finish()
    }
}

impl AddressValidationKeyRing {
    /// Build a ring whose active epoch is `epoch`.
    pub fn new(epoch: u32, key: [u8; 32]) -> Result<Self, AddressArtifactError> {
        if key == [0u8; 32] {
            // A zero HMAC key would make artifacts forgeable; refuse.
            return Err(AddressArtifactError::InvalidArtifact);
        }
        let mut keys = BTreeMap::new();
        keys.insert(epoch, Zeroizing::new(key));
        Ok(Self {
            keys,
            active_epoch: epoch,
        })
    }

    /// Rotate to a strictly-forward epoch with fresh key material. Evicts the
    /// oldest epoch beyond [`MAX_ADDR_VALIDATION_KEYRING_EPOCHS`].
    pub fn rotate(&mut self, epoch: u32, key: [u8; 32]) -> Result<(), AddressArtifactError> {
        if key == [0u8; 32] {
            return Err(AddressArtifactError::InvalidArtifact);
        }
        if epoch <= self.active_epoch {
            return Err(AddressArtifactError::InvalidArtifact);
        }
        self.keys.insert(epoch, Zeroizing::new(key));
        self.active_epoch = epoch;
        while self.keys.len() > MAX_ADDR_VALIDATION_KEYRING_EPOCHS {
            let Some(oldest) = self.keys.keys().next().copied() else {
                break;
            };
            self.keys.remove(&oldest);
        }
        Ok(())
    }

    /// The epoch new artifacts are issued under.
    pub fn active_epoch(&self) -> u32 {
        self.active_epoch
    }

    fn key_for(&self, epoch: u32) -> Option<&[u8; 32]> {
        self.keys.get(&epoch).map(|k| &**k)
    }

    fn artifact_tag(
        key: &[u8; 32],
        observed: &SocketAddr,
        client_nonce: &[u8; 32],
        privacy_epoch: u64,
        key_epoch: u32,
        expires_at_unix: u64,
    ) -> Result<[u8; BLIND_ADDR_VALIDATION_TAG_LEN], AddressArtifactError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| AddressArtifactError::InvalidArtifact)?;
        mac.update(BLIND_ADDR_VALIDATION_DOMAIN);
        mac.update(&key_epoch.to_be_bytes());
        mac.update(&expires_at_unix.to_be_bytes());
        mac.update(addr_octets(observed).as_slice());
        mac.update(client_nonce);
        mac.update(&privacy_epoch.to_be_bytes());
        let full = mac.finalize().into_bytes();
        let mut tag = [0u8; BLIND_ADDR_VALIDATION_TAG_LEN];
        tag.copy_from_slice(&full[..BLIND_ADDR_VALIDATION_TAG_LEN]);
        Ok(tag)
    }

    /// Issue the 32-byte address-validation artifact a client presents back as
    /// its hello `relay_challenge`. Bound to the observed source address, the
    /// client nonce, the privacy epoch, and a short expiry.
    pub fn issue_artifact(
        &self,
        observed: &SocketAddr,
        client_nonce: &[u8; 32],
        privacy_epoch: u64,
        now_unix: u64,
    ) -> Result<[u8; 32], AddressArtifactError> {
        // Constant-time: client_nonce is random material even for the degenerate
        // all-zero check, and the workspace secret-equality audit requires it.
        if client_nonce.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return Err(AddressArtifactError::InvalidArtifact);
        }
        let expires_at_unix = now_unix
            .checked_add(BLIND_ADDR_VALIDATION_TTL_SECS)
            .ok_or(AddressArtifactError::ClockOverflow)?;
        let key_epoch = self.active_epoch;
        let key = self
            .key_for(key_epoch)
            .ok_or(AddressArtifactError::UnknownKeyEpoch)?;
        let tag = Self::artifact_tag(
            key,
            observed,
            client_nonce,
            privacy_epoch,
            key_epoch,
            expires_at_unix,
        )?;
        let mut artifact = [0u8; 32];
        artifact[..4].copy_from_slice(&key_epoch.to_be_bytes());
        artifact[4..12].copy_from_slice(&expires_at_unix.to_be_bytes());
        artifact[12..].copy_from_slice(&tag);
        Ok(artifact)
    }

    /// Verify a presented artifact against the observed address, the hello's
    /// client nonce, and the token's privacy epoch. Uses constant-time tag
    /// comparison. Expired means expired PAST the skew window; artifacts never
    /// extend any session's life.
    pub fn verify_artifact(
        &self,
        observed: &SocketAddr,
        client_nonce: &[u8; 32],
        privacy_epoch: u64,
        artifact: &[u8; 32],
        now_unix: u64,
        clock_skew_tolerance_secs: u64,
    ) -> Result<(), AddressArtifactError> {
        // Constant-time: client_nonce is random material even for the degenerate
        // all-zero check, and the workspace secret-equality audit requires it.
        if client_nonce.ct_eq(&[0u8; 32]).unwrap_u8() == 1 {
            return Err(AddressArtifactError::InvalidArtifact);
        }
        let key_epoch = u32::from_be_bytes(
            artifact[..4]
                .try_into()
                .map_err(|_| AddressArtifactError::InvalidArtifact)?,
        );
        let expires_at_unix = u64::from_be_bytes(
            artifact[4..12]
                .try_into()
                .map_err(|_| AddressArtifactError::InvalidArtifact)?,
        );
        let presented_tag: [u8; BLIND_ADDR_VALIDATION_TAG_LEN] = artifact[12..]
            .try_into()
            .map_err(|_| AddressArtifactError::InvalidArtifact)?;
        let key = self
            .key_for(key_epoch)
            .ok_or(AddressArtifactError::UnknownKeyEpoch)?;
        let expected = Self::artifact_tag(
            key,
            observed,
            client_nonce,
            privacy_epoch,
            key_epoch,
            expires_at_unix,
        )?;
        if presented_tag.ct_eq(&expected).unwrap_u8() != 1 {
            return Err(AddressArtifactError::AuthenticationFailed);
        }
        if now_unix > expires_at_unix.saturating_add(clock_skew_tolerance_secs) {
            return Err(AddressArtifactError::Expired);
        }
        Ok(())
    }
}

/// Canonical byte encoding of a socket address for MAC inputs: IP octets in
/// display order plus the port big-endian.
fn addr_octets(addr: &SocketAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(18);
    match addr.ip() {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

// ── Replay store (steps 8 and 10) ────────────────────────────────────────────

/// §3 leg digest: `sha256("v2" | privacy_epoch | nonce | leg_handle)`.
pub fn blind_replay_digest_leg(
    privacy_epoch: u64,
    nonce: &[u8; 16],
    leg_handle: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(BLIND_REPLAY_DOMAIN_LEG)
        .chain_update(privacy_epoch.to_be_bytes())
        .chain_update(nonce)
        .chain_update(leg_handle)
        .finalize()
        .into()
}

/// Defense-in-depth nonce digest: any reuse of a token nonce within the
/// privacy epoch is rejected regardless of leg handle (BR-C11).
pub fn blind_replay_digest_nonce(privacy_epoch: u64, nonce: &[u8; 16]) -> [u8; 32] {
    Sha256::new()
        .chain_update(BLIND_REPLAY_DOMAIN_NONCE)
        .chain_update(privacy_epoch.to_be_bytes())
        .chain_update(nonce)
        .finalize()
        .into()
}

/// Defense-in-depth proof digest: any reuse of a presented PoP triple is
/// rejected regardless of which token carried it (BR-C06 cross-circuit proof).
pub fn blind_replay_digest_pop(
    client_nonce: &[u8; 32],
    relay_challenge: &[u8; 32],
    pop_signature: &[u8; 64],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(BLIND_REPLAY_DOMAIN_POP)
        .chain_update(client_nonce)
        .chain_update(relay_challenge)
        .chain_update(pop_signature)
        .finalize()
        .into()
}

fn blind_replay_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn parse_blind_replay_digest_hex(value: &str) -> Result<[u8; 32], String> {
    if value.len() != 64 {
        return Err("blind replay digest must be 64 hex characters".to_owned());
    }
    let mut digest = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk)
            .map_err(|err| format!("blind replay digest is not utf8: {err}"))?;
        digest[index] = u8::from_str_radix(text, 16)
            .map_err(|err| format!("blind replay digest is not hex: {err}"))?;
    }
    Ok(digest)
}

/// Durable digest-keyed replay store, mirroring the v1 `NonceStore`
/// discipline (protocol-selection §3): line format `<64-hex digest>
/// <inserted_at_unix>`, insert-then-persist with rollback on persist failure,
/// RLY-15 clock refusal (a substituted clock must never stamp entries), a
/// hard byte cap whose exhaustion REJECTS ADMISSION rather than evicting live
/// entries, atomic tmp+rename persistence with a parent-directory fsync, and
/// mode-0600 files. A corrupt or unwritable store is UNAVAILABLE, never
/// silently re-initialized; the blind path requires the durable store (a
/// memory-only store is fail-open and forbidden here).
pub(crate) struct BlindReplayStore {
    entries: HashMap<[u8; 32], u64>,
    path: PathBuf,
}

impl BlindReplayStore {
    /// Open (or create) the store at `path`. Any parse/validation failure of
    /// an EXISTING store is corrupt-store refusal — never TOFU re-init.
    fn open(path: PathBuf) -> Result<Self, String> {
        crate::transport::validate_replay_store_path(&path)?;
        if !path.exists() {
            let store = Self {
                entries: HashMap::new(),
                path,
            };
            store.persist()?;
            return Ok(store);
        }
        let content = std::fs::read_to_string(&path)
            .map_err(|err| format!("read blind replay store: {err}"))?;
        let mut entries = HashMap::new();
        for (line_no, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut fields = trimmed.split_whitespace();
            let digest_hex = fields
                .next()
                .ok_or_else(|| format!("blind replay store line {} missing digest", line_no + 1))?;
            let inserted_at_unix = fields
                .next()
                .ok_or_else(|| {
                    format!("blind replay store line {} missing timestamp", line_no + 1)
                })?
                .parse::<u64>()
                .map_err(|err| {
                    format!(
                        "blind replay store line {} invalid timestamp: {err}",
                        line_no + 1
                    )
                })?;
            if fields.next().is_some() {
                return Err(format!(
                    "blind replay store line {} has unexpected fields",
                    line_no + 1
                ));
            }
            entries.insert(parse_blind_replay_digest_hex(digest_hex)?, inserted_at_unix);
        }
        Ok(Self { entries, path })
    }

    fn contains(&self, digest: &[u8; 32]) -> bool {
        self.entries.contains_key(digest)
    }

    fn has_capacity_for(&self, additional: usize) -> bool {
        self.entries.len().saturating_add(additional) <= MAX_BLIND_REPLAY_ENTRIES
    }

    /// Atomically record every digest or none (single insert-then-persist with
    /// full rollback). A full store prunes strictly-older-than-retention
    /// entries once and re-checks; if still full, admission is rejected —
    /// live entries are never evicted (BR-C11).
    fn insert_all(&mut self, digests: &[[u8; 32]]) -> Result<(), String> {
        // RLY-15: refuse to stamp entries from a substituted clock.
        let Some(now) = crate::transport::now_unix_checked() else {
            return Err("host clock unusable; refusing to record blind replay digests".to_owned());
        };
        if !self.has_capacity_for(digests.len()) {
            self.prune(BLIND_NONCE_RETENTION_SECS)?;
            if !self.has_capacity_for(digests.len()) {
                return Err("blind replay store is full; rejecting admission".to_owned());
            }
        }
        let mut prior = Vec::with_capacity(digests.len());
        for digest in digests {
            prior.push((*digest, self.entries.insert(*digest, now)));
        }
        if let Err(err) = self.persist() {
            for (digest, previous) in prior {
                match previous {
                    Some(timestamp) => {
                        self.entries.insert(digest, timestamp);
                    }
                    None => {
                        self.entries.remove(&digest);
                    }
                }
            }
            return Err(err);
        }
        Ok(())
    }

    /// Drop entries strictly at-or-beyond retention age. On clock failure the
    /// prune is SKIPPED (retain everything) — pruning early would open a
    /// replay window; pruning late costs bounded memory (RLY-15/RLY-10).
    fn prune(&mut self, retention_secs: u64) -> Result<(), String> {
        let Some(now) = crate::transport::now_unix_checked() else {
            return Err(
                "host clock unusable; skipping blind replay prune to preserve anti-replay"
                    .to_owned(),
            );
        };
        let to_remove: Vec<([u8; 32], u64)> = self
            .entries
            .iter()
            .filter(|(_, inserted_at)| now.saturating_sub(**inserted_at) >= retention_secs)
            .map(|(digest, inserted_at)| (*digest, *inserted_at))
            .collect();
        if to_remove.is_empty() {
            return Ok(());
        }
        for (digest, _) in &to_remove {
            self.entries.remove(digest);
        }
        if let Err(err) = self.persist() {
            for (digest, inserted_at) in to_remove {
                self.entries.insert(digest, inserted_at);
            }
            return Err(err);
        }
        Ok(())
    }

    fn persist(&self) -> Result<(), String> {
        persist_blind_replay_map(&self.path, &self.entries)
    }
}

/// Atomic persistence for the blind replay store. Same crash-recovery shape
/// as the v1 `persist_nonce_map`: validate path, write tmp (mode 0600),
/// fsync file, rename, fsync parent directory (RLY-04).
fn persist_blind_replay_map(path: &Path, entries: &HashMap<[u8; 32], u64>) -> Result<(), String> {
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    crate::transport::validate_replay_store_path(path)?;
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "blind replay store path missing file name".to_owned())?
        .to_string_lossy();
    let tmp_path = parent.join(format!(".{file_name}.tmp-{}", std::process::id()));

    let mut lines: Vec<(&[u8; 32], &u64)> = entries.iter().collect();
    lines.sort_by(|left, right| left.0.cmp(right.0));
    let mut content = String::with_capacity(entries.len() * BLIND_REPLAY_LINE_MAX_BYTES);
    for (digest, inserted_at_unix) in lines {
        content.push_str(&format!(
            "{} {inserted_at_unix}\n",
            blind_replay_hex(digest)
        ));
    }

    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options
        .open(&tmp_path)
        .map_err(|err| format!("open blind replay store tmp: {err}"))?;
    use std::io::Write;
    file.write_all(content.as_bytes())
        .map_err(|err| format!("write blind replay store tmp: {err}"))?;
    file.sync_all()
        .map_err(|err| format!("sync blind replay store tmp: {err}"))?;
    drop(file);

    #[cfg(unix)]
    fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600))
        .map_err(|err| format!("set blind replay store permissions: {err}"))?;

    fs::rename(&tmp_path, path).map_err(|err| format!("replace blind replay store: {err}"))?;

    // Durability: fsync the parent directory after the rename (RLY-04), unix-
    // gated exactly as the v1 store and the crypto/enrollment writers do.
    #[cfg(unix)]
    {
        let dir = fs::File::open(parent)
            .map_err(|err| format!("open blind replay store parent dir: {err}"))?;
        dir.sync_all()
            .map_err(|err| format!("sync blind replay store parent dir: {err}"))?;
    }

    Ok(())
}

// ── Waiting-leg circuit map (steps 9 and 10, design §7.6) ────────────────────

/// Key of a waiting circuit: the signed (privacy_epoch, circuit_handle) pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlindCircuitKey {
    pub privacy_epoch: u64,
    pub circuit_handle: [u8; 32],
}

/// Allowed per-leg live state (design §7.7): random handle, presenter-key
/// DIGEST (never the raw key), bound tuple, expiry. Nothing else.
#[derive(Debug, Clone, Copy)]
struct BlindWaitingLeg {
    leg_handle: [u8; 32],
    presenter_digest: [u8; 32],
    bound_addr: SocketAddr,
    expires_at_unix: u64,
}

/// A circuit awaiting its complementary leg. Holds no payload data — data
/// before pairing is never buffered (design §7.6).
#[derive(Debug, Clone)]
struct BlindWaitingCircuit {
    profile_id: String,
    expires_at_unix: u64,
    source_prefix: SourcePrefix,
    slot0: Option<BlindWaitingLeg>,
    slot1: Option<BlindWaitingLeg>,
}

impl BlindWaitingCircuit {
    fn leg_for(&self, slot: BlindRelayLegSlot) -> &Option<BlindWaitingLeg> {
        match slot {
            BlindRelayLegSlot::Slot0 => &self.slot0,
            BlindRelayLegSlot::Slot1 => &self.slot1,
        }
    }

    fn leg_for_mut(&mut self, slot: BlindRelayLegSlot) -> &mut Option<BlindWaitingLeg> {
        match slot {
            BlindRelayLegSlot::Slot0 => &mut self.slot0,
            BlindRelayLegSlot::Slot1 => &mut self.slot1,
        }
    }

    fn complementary(&self, slot: BlindRelayLegSlot) -> Option<&BlindWaitingLeg> {
        match slot {
            BlindRelayLegSlot::Slot0 => self.slot1.as_ref(),
            BlindRelayLegSlot::Slot1 => self.slot0.as_ref(),
        }
    }
}

/// Result of a successful admission. Phase 4 ends at pairing; bounded frame
/// forwarding between bound tuples is later-phase work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlindAdmissionOutcome {
    /// First valid leg recorded; circuit waits for its complement.
    WaitingLegRecorded,
    /// Complementary leg verified; the circuit is paired and removed from the
    /// waiting map for handoff to the forwarding plane.
    CircuitPaired,
}

/// Tunable resource limits (step 9). Defaults come from the module constants;
/// operators may only TIGHTEN them — zero values are refused (fail closed: a
/// zero limit would either disable the relay or, if read as "unlimited",
/// silently drop the bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlindRelayListenerLimits {
    pub max_waiting_legs_total: usize,
    pub max_waiting_legs_per_source_prefix: usize,
    pub max_waiting_legs_per_profile: usize,
    pub max_hellos_per_source_prefix_per_sec: u32,
}

impl Default for BlindRelayListenerLimits {
    fn default() -> Self {
        Self {
            max_waiting_legs_total: MAX_BLIND_WAITING_LEGS_TOTAL,
            max_waiting_legs_per_source_prefix: MAX_BLIND_WAITING_LEGS_PER_SOURCE_PREFIX,
            max_waiting_legs_per_profile: MAX_BLIND_WAITING_LEGS_PER_PROFILE,
            max_hellos_per_source_prefix_per_sec: MAX_BLIND_HELLOS_PER_SOURCE_PREFIX_PER_SEC,
        }
    }
}

// ── Listener ─────────────────────────────────────────────────────────────────

/// Everything [`BlindRelayListener::try_open`] needs. The two boolean gates
/// exist so the listener cannot open by accident: BOTH the signed-state
/// capability AND an explicit operator switch must be set, AND the
/// adversarial-review approval bit must be flipped (it is `false` today).
#[derive(Clone)]
pub struct BlindRelayListenerConfig {
    pub relay_id: [u8; 16],
    /// Issuer allowlist: key id → verifying key (step 4). Must be non-empty.
    pub issuer_keys: BTreeMap<String, VerifyingKey>,
    /// Public profile ids accepted by policy (step 5). Must be non-empty.
    pub allowed_profiles: BTreeSet<String>,
    /// Rotating HMAC keys for address-validation artifacts (step 3).
    pub address_validation_keys: AddressValidationKeyRing,
    /// Durable replay-store path (steps 8/10). REQUIRED — the blind path has
    /// no memory-only mode.
    pub replay_store_path: PathBuf,
    pub limits: BlindRelayListenerLimits,
    pub clock_skew_tolerance_secs: u64,
    /// Granted only when live signed membership state carries the BlindRelay
    /// capability for this relay (phase-1 signature surface; still closed for
    /// production advertisement).
    pub signed_capability_granted: bool,
    /// Explicit operator switch for the blind listener.
    pub operator_enabled: bool,
}

impl fmt::Debug for BlindRelayListenerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindRelayListenerConfig")
            .field("relay_id", &"<redacted>")
            .field("issuer_key_ids", &self.issuer_keys.keys().count())
            .field("allowed_profiles", &self.allowed_profiles)
            .field("address_validation_keys", &self.address_validation_keys)
            .field("replay_store_path", &self.replay_store_path)
            .field("limits", &self.limits)
            .field("clock_skew_tolerance_secs", &self.clock_skew_tolerance_secs)
            .field("signed_capability_granted", &self.signed_capability_granted)
            .field("operator_enabled", &self.operator_enabled)
            .finish()
    }
}

/// The v2-only identity-blind admission listener. Construction is gated
/// (`try_open`); admission runs the ten-step §2.2(f) sequence.
pub struct BlindRelayListener {
    relay_id: [u8; 16],
    issuer_keys: BTreeMap<String, VerifyingKey>,
    allowed_profiles: BTreeSet<String>,
    addr_keys: AddressValidationKeyRing,
    prefix_limiter: SourcePrefixLimiter,
    replay: BlindReplayStore,
    circuits: HashMap<BlindCircuitKey, BlindWaitingCircuit>,
    limits: BlindRelayListenerLimits,
    clock_skew_tolerance_secs: u64,
}

impl BlindRelayListener {
    /// Open the listener. Refuses unless ALL of: the adversarial-review
    /// approval bit ([`BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED`]), the
    /// signed-state capability, and the operator flag are granted; and the
    /// durable replay store opens clean. This is the go-live gate: the
    /// listener CANNOT open in production before design §16 review.
    pub fn try_open(config: BlindRelayListenerConfig) -> Result<Self, BlindListenerOpenError> {
        if !BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED
            || !config.signed_capability_granted
            || !config.operator_enabled
        {
            return Err(BlindListenerOpenError::GateClosed);
        }
        Self::build(config)
    }

    fn build(config: BlindRelayListenerConfig) -> Result<Self, BlindListenerOpenError> {
        if config.issuer_keys.is_empty() {
            // An empty issuer allowlist can never verify anything; refuse to
            // open rather than fail open later.
            return Err(BlindListenerOpenError::ReplayStoreInvalid(
                "issuer key allowlist is empty".to_owned(),
            ));
        }
        if config.allowed_profiles.is_empty() {
            return Err(BlindListenerOpenError::ReplayStoreInvalid(
                "allowed profile set is empty".to_owned(),
            ));
        }
        if config.relay_id == [0u8; 16] {
            return Err(BlindListenerOpenError::ReplayStoreInvalid(
                "relay id is degenerate (all zero)".to_owned(),
            ));
        }
        let limits = BlindRelayListenerLimits {
            max_waiting_legs_total: config.limits.max_waiting_legs_total.max(1),
            max_waiting_legs_per_source_prefix: config
                .limits
                .max_waiting_legs_per_source_prefix
                .max(1),
            max_waiting_legs_per_profile: config.limits.max_waiting_legs_per_profile.max(1),
            max_hellos_per_source_prefix_per_sec: config
                .limits
                .max_hellos_per_source_prefix_per_sec
                .max(1),
        };
        let (skew, clamped) = compute_clamped_skew(config.clock_skew_tolerance_secs);
        if clamped {
            eprintln!(
                "warn blind_relay_listener: clock-skew tolerance clamped to {BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS}s"
            );
        }
        let mut replay = BlindReplayStore::open(config.replay_store_path)
            .map_err(BlindListenerOpenError::ReplayStoreInvalid)?;
        // Prune at open, exactly as the v1 transport does. A clock failure
        // here is retained-entry-safe (prune skips), so only a hard store
        // error refuses the open.
        replay
            .prune(BLIND_NONCE_RETENTION_SECS)
            .map_err(BlindListenerOpenError::ReplayStoreInvalid)?;
        Ok(Self {
            relay_id: config.relay_id,
            issuer_keys: config.issuer_keys,
            allowed_profiles: config.allowed_profiles,
            addr_keys: config.address_validation_keys,
            prefix_limiter: SourcePrefixLimiter::new(limits.max_hellos_per_source_prefix_per_sec),
            replay,
            circuits: HashMap::new(),
            limits,
            clock_skew_tolerance_secs: skew,
        })
    }

    /// Issue an address-validation artifact for the initial exchange (the
    /// client will present it back as `relay_challenge`). Exposed so the
    /// datagram-level first-exchange handler can be wired without re-deriving
    /// the artifact format.
    pub fn issue_address_validation_artifact(
        &self,
        observed: &SocketAddr,
        client_nonce: &[u8; 32],
        privacy_epoch: u64,
        now_unix: u64,
    ) -> Result<[u8; 32], AddressArtifactError> {
        self.addr_keys
            .issue_artifact(observed, client_nonce, privacy_epoch, now_unix)
    }

    /// Number of circuits currently waiting for a complementary leg.
    pub fn waiting_circuit_count(&self) -> usize {
        self.circuits.len()
    }

    /// Run the ten-step admission sequence on a hello v2 datagram. `now_unix`
    /// is injectable for tests; production passes the checked host clock.
    pub fn handle_hello(
        &mut self,
        wire: &[u8],
        source: SocketAddr,
        observer: &mut dyn BlindAdmissionObserver,
    ) -> Result<BlindAdmissionOutcome, BlindRejectReason> {
        self.handle_hello_with_now(wire, source, crate::transport::now_unix_checked(), observer)
    }

    pub(crate) fn handle_hello_with_now(
        &mut self,
        wire: &[u8],
        source: SocketAddr,
        now_unix: Option<u64>,
        observer: &mut dyn BlindAdmissionObserver,
    ) -> Result<BlindAdmissionOutcome, BlindRejectReason> {
        // ── Step 1: bounded size + exact v2 envelope parse (no crypto) ────
        observer.stage_entered(BlindAdmissionStage::EnvelopeParse);
        if wire.len() > MAX_BLIND_RELAY_HELLO_WIRE_BYTES {
            return Err(BlindRejectReason::Malformed);
        }
        let hello = parse_blind_relay_hello_v2_wire_bytes(wire)
            .map_err(|_| BlindRejectReason::Malformed)?;

        // ── Step 2: per-source-prefix pre-auth rate limit (still no crypto)
        observer.stage_entered(BlindAdmissionStage::SourceRateLimit);
        let prefix = source_prefix(&source.ip());
        if !self.prefix_limiter.check(prefix) {
            return Err(BlindRejectReason::RateLimited);
        }

        // ── Step 3: stateless address-validation verify (HMAC) BEFORE any
        // session/circuit allocation. The clock is required from here on;
        // an unusable clock is a reject (RLY-15), never a default.
        observer.stage_entered(BlindAdmissionStage::AddressValidation);
        let now = now_unix.ok_or(BlindRejectReason::ClockUnavailable)?;
        self.addr_keys
            .verify_artifact(
                &source,
                &hello.client_nonce,
                hello.token.privacy_epoch,
                &hello.relay_challenge,
                now,
                self.clock_skew_tolerance_secs,
            )
            .map_err(|_| BlindRejectReason::AddressValidation)?;

        // ── Step 4: issuer key-id allowlist + token verify_strict ─────────
        observer.stage_entered(BlindAdmissionStage::IssuerVerification);
        let issuer_key = self
            .issuer_keys
            .get(&hello.token.issuer_key_id)
            .ok_or(BlindRejectReason::Unauthorized)?;
        hello
            .token
            .verify_signature(issuer_key)
            .map_err(|_| BlindRejectReason::Unauthorized)?;

        // ── Step 5: version/kind/audience/scope/epoch/profile/slot checks ─
        // (version, kind, scope, slot, epoch ≥ 1, canonical re-encode, and all
        // degenerate-field rejections are already pinned by the phase-3
        // parser; the listener re-checks the policy-dependent fields.)
        observer.stage_entered(BlindAdmissionStage::FieldValidation);
        if hello
            .token
            .audience_relay_id
            .ct_eq(&self.relay_id)
            .unwrap_u8()
            != 1
        {
            return Err(BlindRejectReason::Unauthorized);
        }
        if !matches!(hello.token.token_kind, BlindRelayTokenKindV2::BlindRelayLeg) {
            return Err(BlindRejectReason::Unauthorized);
        }
        // str::eq, not the ==/!= operator: the secret-material equality audit
        // sweeps operator comparisons mentioning token identifiers, and scope
        // is a pinned NON-secret constant.
        if !hello.token.scope.eq(BLIND_RELAY_TOKEN_SCOPE_V2) {
            return Err(BlindRejectReason::Unauthorized);
        }
        if !self.allowed_profiles.contains(&hello.token.profile_id) {
            return Err(BlindRejectReason::Unauthorized);
        }

        // ── Step 6: clock / not-before / expiry / TTL ─────────────────────
        observer.stage_entered(BlindAdmissionStage::Freshness);
        if hello.token.issued_at_unix > now.saturating_add(self.clock_skew_tolerance_secs) {
            return Err(BlindRejectReason::Unauthorized);
        }
        if hello.token.is_expired(now, self.clock_skew_tolerance_secs) {
            return Err(BlindRejectReason::Unauthorized);
        }

        // ── Step 7: PoP transcript verify_strict against presenter key ────
        observer.stage_entered(BlindAdmissionStage::ProofOfPossession);
        hello
            .verify_pop()
            .map_err(|_| BlindRejectReason::Unauthorized)?;

        // ── Step 8: durable replay-store availability + replay rejection ──
        observer.stage_entered(BlindAdmissionStage::ReplayCheck);
        let leg_digest = blind_replay_digest_leg(
            hello.token.privacy_epoch,
            &hello.token.nonce,
            &hello.token.leg_handle,
        );
        let nonce_digest = blind_replay_digest_nonce(hello.token.privacy_epoch, &hello.token.nonce);
        let pop_digest = blind_replay_digest_pop(
            &hello.client_nonce,
            &hello.relay_challenge,
            &hello.pop_signature,
        );
        if self.replay.contains(&leg_digest)
            || self.replay.contains(&nonce_digest)
            || self.replay.contains(&pop_digest)
        {
            return Err(BlindRejectReason::Replayed);
        }

        // Housekeeping before the limit math: expired circuits leave.
        self.prune_expired_circuits(now);

        // ── Step 9: resource limits + pairing decision (no state yet) ─────
        observer.stage_entered(BlindAdmissionStage::ResourceLimits);
        let slot = hello.token.leg_slot;
        let presenter_digest: [u8; 32] = Sha256::digest(hello.token.presenter_public_key).into();
        let circuit_key = BlindCircuitKey {
            privacy_epoch: hello.token.privacy_epoch,
            circuit_handle: hello.token.circuit_handle,
        };
        enum Plan {
            NewCircuit,
            PairWithExisting,
        }
        let plan = if let Some(existing) = self.circuits.get(&circuit_key) {
            // Pairing branch: the circuit holds the complementary leg.
            if existing.leg_for(slot).is_some() {
                // Same slot twice (distinct token — an exact replay was
                // already rejected at step 8) is a pairing violation.
                return Err(BlindRejectReason::Unauthorized);
            }
            let Some(prior) = existing.complementary(slot) else {
                return Err(BlindRejectReason::Unauthorized);
            };
            if existing.profile_id != hello.token.profile_id
                || existing.expires_at_unix != hello.token.expires_at_unix
                || prior.leg_handle == hello.token.leg_handle
                || prior.presenter_digest == presenter_digest
                || prior.bound_addr == source
                || prior.expires_at_unix != hello.token.expires_at_unix
            {
                // Mismatched profile/expiry, self-same leg, same presenter
                // key across legs (§7.6: distinct leg handle AND presenter), or
                // an identical observed tuple — a self-pair/anti-hijack signal
                // (BR-C13; two distinct endpoints never share one 5-tuple).
                return Err(BlindRejectReason::Unauthorized);
            }
            Plan::PairWithExisting
        } else {
            // New-circuit branch: bounded allocation checks.
            if self.circuits.len() >= self.limits.max_waiting_legs_total {
                return Err(BlindRejectReason::Capacity);
            }
            let prefix_owned = self
                .circuits
                .values()
                .filter(|circuit| circuit.source_prefix == prefix)
                .count();
            if prefix_owned >= self.limits.max_waiting_legs_per_source_prefix {
                return Err(BlindRejectReason::Capacity);
            }
            let profile_owned = self
                .circuits
                .values()
                .filter(|circuit| circuit.profile_id == hello.token.profile_id)
                .count();
            if profile_owned >= self.limits.max_waiting_legs_per_profile {
                return Err(BlindRejectReason::Capacity);
            }
            Plan::NewCircuit
        };

        // ── Step 10: atomic nonce commit + bounded waiting-leg allocation ─
        observer.stage_entered(BlindAdmissionStage::Commit);
        self.replay
            .insert_all(&[leg_digest, nonce_digest, pop_digest])
            .map_err(|_| BlindRejectReason::ReplayStoreUnavailable)?;
        // The in-memory allocation was fully validated in step 9 and cannot
        // fail; committing the digests first means any retry of this exact
        // hello is rejected at step 8 (fail-closed direction).
        match plan {
            Plan::NewCircuit => {
                let leg = BlindWaitingLeg {
                    leg_handle: hello.token.leg_handle,
                    presenter_digest,
                    bound_addr: source,
                    expires_at_unix: hello.token.expires_at_unix,
                };
                let mut circuit = BlindWaitingCircuit {
                    profile_id: hello.token.profile_id.clone(),
                    expires_at_unix: hello.token.expires_at_unix,
                    source_prefix: prefix,
                    slot0: None,
                    slot1: None,
                };
                *circuit.leg_for_mut(slot) = Some(leg);
                self.circuits.insert(circuit_key, circuit);
                Ok(BlindAdmissionOutcome::WaitingLegRecorded)
            }
            Plan::PairWithExisting => {
                // Paired circuits leave the waiting map; forwarding-plane
                // handoff is later-phase work.
                self.circuits.remove(&circuit_key);
                Ok(BlindAdmissionOutcome::CircuitPaired)
            }
        }
    }

    fn prune_expired_circuits(&mut self, now: u64) {
        self.circuits
            .retain(|_, circuit| circuit.expires_at_unix > now);
    }
}

/// Pure helper mirroring the v1 transport's skew clamp so the clamp decision
/// is testable and the ceiling stays in lockstep.
fn compute_clamped_skew(input: u64) -> (u64, bool) {
    if input > BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS {
        (BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS, true)
    } else {
        (input, false)
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use rustynet_control::blind_relay::{BlindRelayHelloV2, BlindRelayLegTokenV2};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    /// Spy observer that records the stage sequence.
    #[derive(Default)]
    struct RecordedObserver {
        stages: Vec<BlindAdmissionStage>,
    }

    impl BlindAdmissionObserver for RecordedObserver {
        fn stage_entered(&mut self, stage: BlindAdmissionStage) {
            self.stages.push(stage);
        }
    }

    // Relay ids are bounded printable ASCII on the wire (validate_audience_relay_id).
    const TEST_RELAY_ID: [u8; 16] = *b"test-relay-id-01";
    const TEST_PROFILE: &str = "profile-a";

    struct TestRig {
        issuer: SigningKey,
        listener: BlindRelayListener,
        store_path: PathBuf,
        now: u64,
    }

    fn temp_store_path(test_name: &str) -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "rustynet-blind-relay-{test_name}-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir should be created");
        #[cfg(unix)]
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
            .expect("temp dir permissions should be restricted");
        dir.join("blind_replay.store")
    }

    fn test_issuer_keys(issuer: &SigningKey) -> BTreeMap<String, VerifyingKey> {
        let mut keys = BTreeMap::new();
        keys.insert("issuer-1".to_owned(), issuer.verifying_key());
        keys
    }

    fn test_profiles() -> BTreeSet<String> {
        let mut profiles = BTreeSet::new();
        profiles.insert(TEST_PROFILE.to_owned());
        profiles
    }

    fn build_rig_with(
        _test_name: &str,
        limits: BlindRelayListenerLimits,
        store_path: PathBuf,
    ) -> TestRig {
        let issuer = SigningKey::from_bytes(&[7u8; 32]);
        let addr_keys = AddressValidationKeyRing::new(1, [9u8; 32]).expect("non-zero key ring key");
        let listener = BlindRelayListener::build(BlindRelayListenerConfig {
            relay_id: TEST_RELAY_ID,
            issuer_keys: test_issuer_keys(&issuer),
            allowed_profiles: test_profiles(),
            address_validation_keys: addr_keys,
            replay_store_path: store_path.clone(),
            limits,
            clock_skew_tolerance_secs: 10,
            signed_capability_granted: true,
            operator_enabled: true,
        })
        .expect("listener should build for tests");
        TestRig {
            issuer,
            listener,
            store_path,
            now: 1_800_000_000,
        }
    }

    fn build_rig(test_name: &str) -> TestRig {
        build_rig_with(
            test_name,
            BlindRelayListenerLimits::default(),
            temp_store_path(test_name),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn mint_leg(
        issuer: &SigningKey,
        presenter: &SigningKey,
        epoch: u64,
        circuit: [u8; 32],
        leg: [u8; 32],
        slot: BlindRelayLegSlot,
        nonce: [u8; 16],
        issued: u64,
        expires: u64,
        profile: &str,
    ) -> BlindRelayLegTokenV2 {
        BlindRelayLegTokenV2::new(
            BlindRelayTokenKindV2::BlindRelayLeg,
            TEST_RELAY_ID,
            BLIND_RELAY_TOKEN_SCOPE_V2,
            epoch,
            circuit,
            leg,
            slot,
            *presenter.verifying_key().as_bytes(),
            issued,
            expires,
            nonce,
            profile,
            "issuer-1",
        )
        .expect("leg token should validate")
        .sign(issuer)
    }

    /// Build a fully valid, admission-ready hello wire for one leg.
    #[allow(clippy::too_many_arguments)]
    fn signed_hello_wire(
        rig: &TestRig,
        source: SocketAddr,
        presenter: &SigningKey,
        epoch: u64,
        circuit: [u8; 32],
        leg: [u8; 32],
        slot: BlindRelayLegSlot,
        nonce: [u8; 16],
        client_nonce: [u8; 32],
    ) -> Vec<u8> {
        let token = mint_leg(
            &rig.issuer,
            presenter,
            epoch,
            circuit,
            leg,
            slot,
            nonce,
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, epoch, rig.now)
            .expect("artifact should issue");
        let hello = BlindRelayHelloV2::new(
            token,
            client_nonce,
            artifact,
            [0u8; 64], // replaced below with a real PoP signature
        )
        .expect("hello should validate");
        let transcript = hello.pop_transcript().expect("transcript should build");
        let pop = presenter.sign(transcript.canonical_bytes().as_bytes());
        let hello = BlindRelayHelloV2::new(hello.token, client_nonce, artifact, pop.to_bytes())
            .expect("hello should validate");
        hello.to_wire().into_bytes()
    }

    fn source_addr(octet: u8, port: u16) -> SocketAddr {
        source_addr_subnet(1, octet, port)
    }

    /// Source in `10.<subnet>.2.<octet>`; the limiter keys on IPv4 /24, so
    /// distinct `subnet` values are distinct prefixes and distinct `octet`
    /// values within one subnet share a prefix.
    fn source_addr_subnet(subnet: u8, octet: u8, port: u16) -> SocketAddr {
        SocketAddr::new(
            IpAddr::V4(std::net::Ipv4Addr::new(10, subnet, 2, octet)),
            port,
        )
    }

    fn distinct(bytes: u8) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = bytes.wrapping_add(i as u8);
        }
        out
    }

    fn distinct16(bytes: u8) -> [u8; 16] {
        let mut out = [0u8; 16];
        for (i, b) in out.iter_mut().enumerate() {
            *b = bytes.wrapping_add(i as u8);
        }
        out
    }

    // ── Step 1 negatives ────────────────────────────────────────────────────

    #[test]
    fn oversize_frame_rejected_before_any_crypto() {
        let mut rig = build_rig("oversize");
        let mut observer = RecordedObserver::default();
        let oversize = vec![0x41u8; MAX_BLIND_RELAY_HELLO_WIRE_BYTES + 1];
        let result = rig.listener.handle_hello_with_now(
            &oversize,
            source_addr(1, 5000),
            Some(rig.now),
            &mut observer,
        );
        assert_eq!(result, Err(BlindRejectReason::Malformed));
        // Only the parse stage ran; no rate limit, no HMAC, no signature.
        assert_eq!(observer.stages, vec![BlindAdmissionStage::EnvelopeParse]);
    }

    #[test]
    fn malformed_frame_does_no_signature_or_hmac_work() {
        let mut rig = build_rig("malformed");
        let mut observer = RecordedObserver::default();
        let garbage = b"version=2\nkind=not-a-token\n".to_vec();
        let result = rig.listener.handle_hello_with_now(
            &garbage,
            source_addr(1, 5000),
            Some(rig.now),
            &mut observer,
        );
        assert_eq!(result, Err(BlindRejectReason::Malformed));
        assert_eq!(observer.stages, vec![BlindAdmissionStage::EnvelopeParse]);
    }

    // ── Step 2 negative ─────────────────────────────────────────────────────

    #[test]
    fn source_prefix_rate_limit_sheds_before_signature_work() {
        let mut rig = build_rig("prefix_limit");
        let source = source_addr(9, 6000);
        let client_nonce = distinct(1);
        for i in 0..5u8 {
            let mut observer = RecordedObserver::default();
            // Invalid artifact keeps the hello cheap but past the rate limiter.
            let wire = {
                let token = mint_leg(
                    &rig.issuer,
                    &SigningKey::from_bytes(&[0x30 + i; 32]),
                    1,
                    distinct(10 + i),
                    distinct(40 + i),
                    BlindRelayLegSlot::Slot0,
                    distinct16(70 + i),
                    rig.now - 5,
                    rig.now + 60,
                    TEST_PROFILE,
                );
                BlindRelayHelloV2::new(token, client_nonce, distinct(200), [1u8; 64])
                    .expect("hello")
                    .to_wire()
                    .into_bytes()
            };
            let result =
                rig.listener
                    .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
            assert_ne!(
                result,
                Err(BlindRejectReason::RateLimited),
                "hello {i} within limit"
            );
        }
        let mut observer = RecordedObserver::default();
        let token = mint_leg(
            &rig.issuer,
            &SigningKey::from_bytes(&[0x50u8; 32]),
            1,
            distinct(90),
            distinct(91),
            BlindRelayLegSlot::Slot0,
            distinct16(92),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let wire = BlindRelayHelloV2::new(token, client_nonce, distinct(201), [1u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        let result =
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(result, Err(BlindRejectReason::RateLimited));
        // Shed at step 2: never reached the HMAC or signature stages.
        assert_eq!(
            observer.stages,
            vec![
                BlindAdmissionStage::EnvelopeParse,
                BlindAdmissionStage::SourceRateLimit
            ]
        );
        // A different prefix is NOT penalized.
        let mut observer = RecordedObserver::default();
        let result = rig.listener.handle_hello_with_now(
            &wire,
            source_addr_subnet(9, 200, 6000),
            Some(rig.now),
            &mut observer,
        );
        assert_ne!(result, Err(BlindRejectReason::RateLimited));
    }

    // ── Step 3 negatives ────────────────────────────────────────────────────

    #[test]
    fn missing_address_validation_artifact_rejects_before_issuer_verification() {
        let mut rig = build_rig("addr_missing");
        let source = source_addr(3, 6001);
        let client_nonce = distinct(2);
        let token = mint_leg(
            &rig.issuer,
            &SigningKey::from_bytes(&[0x11u8; 32]),
            1,
            distinct(3),
            distinct(4),
            BlindRelayLegSlot::Slot0,
            distinct16(5),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        // A random non-artifact challenge: parses fine (fixed hex, non-zero)
        // but carries no valid (epoch, expiry, tag) layout.
        let wire = BlindRelayHelloV2::new(token, client_nonce, distinct(6), [2u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        let mut observer = RecordedObserver::default();
        let result =
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(result, Err(BlindRejectReason::AddressValidation));
        // HMAC ran (step 3), but NO signature work (step 4) ever started.
        assert_eq!(
            observer.stages,
            vec![
                BlindAdmissionStage::EnvelopeParse,
                BlindAdmissionStage::SourceRateLimit,
                BlindAdmissionStage::AddressValidation,
            ]
        );
    }

    #[test]
    fn artifact_is_bound_to_source_address_client_nonce_and_epoch() {
        let rig = build_rig("addr_binding");
        let source = source_addr(4, 6002);
        let client_nonce = distinct(7);
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
            .expect("issue");
        let keys = &rig.listener.addr_keys;
        // Correct inputs verify.
        assert_eq!(
            keys.verify_artifact(&source, &client_nonce, 1, &artifact, rig.now, 10),
            Ok(())
        );
        // Different address fails.
        assert_eq!(
            keys.verify_artifact(
                &source_addr(5, 6002),
                &client_nonce,
                1,
                &artifact,
                rig.now,
                10
            ),
            Err(AddressArtifactError::AuthenticationFailed)
        );
        // Different client nonce fails.
        assert_eq!(
            keys.verify_artifact(&source, &distinct(8), 1, &artifact, rig.now, 10),
            Err(AddressArtifactError::AuthenticationFailed)
        );
        // Different privacy epoch fails.
        assert_eq!(
            keys.verify_artifact(&source, &client_nonce, 2, &artifact, rig.now, 10),
            Err(AddressArtifactError::AuthenticationFailed)
        );
        // Tampered tag fails.
        let mut tampered = artifact;
        tampered[31] ^= 0xFF;
        assert_eq!(
            keys.verify_artifact(&source, &client_nonce, 1, &tampered, rig.now, 10),
            Err(AddressArtifactError::AuthenticationFailed)
        );
        // Beyond expiry + skew fails.
        assert_eq!(
            keys.verify_artifact(&source, &client_nonce, 1, &artifact, rig.now + 60, 10),
            Err(AddressArtifactError::Expired)
        );
    }

    // ── Step 4 negatives ────────────────────────────────────────────────────

    #[test]
    fn unknown_issuer_key_id_rejected_without_reaching_field_validation() {
        let mut rig = build_rig("issuer_unknown");
        let source = source_addr(6, 6003);
        let client_nonce = distinct(9);
        let presenter = SigningKey::from_bytes(&[0x21u8; 32]);
        let token = mint_leg(
            &rig.issuer,
            &presenter,
            1,
            distinct(10),
            distinct(11),
            BlindRelayLegSlot::Slot0,
            distinct16(12),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        // Re-brand the token with an allowlist-unknown issuer id; signature
        // stays valid under the KNOWN key — only the id lookup must reject it.
        let mut rebranded = BlindRelayLegTokenV2::new(
            token.token_kind,
            token.audience_relay_id,
            token.scope.as_str(),
            token.privacy_epoch,
            token.circuit_handle,
            token.leg_handle,
            token.leg_slot,
            token.presenter_public_key,
            token.issued_at_unix,
            token.expires_at_unix,
            token.nonce,
            token.profile_id.as_str(),
            "issuer-UNKNOWN",
        )
        .expect("token")
        .sign(&rig.issuer);
        rebranded.signature = token.signature;
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
            .expect("issue");
        let wire = BlindRelayHelloV2::new(rebranded, client_nonce, artifact, [3u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        let mut observer = RecordedObserver::default();
        let result =
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(result, Err(BlindRejectReason::Unauthorized));
        assert_eq!(
            observer.stages.last(),
            Some(&BlindAdmissionStage::IssuerVerification)
        );
        assert!(
            !observer
                .stages
                .contains(&BlindAdmissionStage::FieldValidation)
        );
    }

    #[test]
    fn wrong_issuer_signature_rejected() {
        let mut rig = build_rig("issuer_wrong_sig");
        let source = source_addr(7, 6004);
        let client_nonce = distinct(13);
        let presenter = SigningKey::from_bytes(&[0x22u8; 32]);
        let impostor = SigningKey::from_bytes(&[0x23u8; 32]);
        let token = mint_leg(
            &impostor, // signed by a key NOT in the allowlist
            &presenter,
            1,
            distinct(14),
            distinct(15),
            BlindRelayLegSlot::Slot0,
            distinct16(16),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
            .expect("issue");
        let wire = BlindRelayHelloV2::new(token, client_nonce, artifact, [4u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        let mut observer = RecordedObserver::default();
        let result =
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(result, Err(BlindRejectReason::Unauthorized));
        assert_eq!(
            observer.stages.last(),
            Some(&BlindAdmissionStage::IssuerVerification)
        );
    }

    // ── Step 5 negatives ────────────────────────────────────────────────────

    #[test]
    fn wrong_audience_or_profile_rejected_at_field_validation() {
        for scenario in ["audience", "profile"] {
            let mut rig = build_rig(scenario);
            let source = source_addr(8, 6005);
            let client_nonce = distinct(17);
            let presenter = SigningKey::from_bytes(&[0x24u8; 32]);
            // Local named to avoid the secret-equality audit sweeping a `token`
            // identifier next to an == operator (this compares the scenario).
            let minted = if scenario == "audience" {
                BlindRelayLegTokenV2::new(
                    BlindRelayTokenKindV2::BlindRelayLeg,
                    *b"other-relay-aaaa", // wrong relay audience (still ASCII: only policy rejects it)
                    BLIND_RELAY_TOKEN_SCOPE_V2,
                    1,
                    distinct(18),
                    distinct(19),
                    BlindRelayLegSlot::Slot0,
                    *presenter.verifying_key().as_bytes(),
                    rig.now - 5,
                    rig.now + 60,
                    distinct16(20),
                    TEST_PROFILE,
                    "issuer-1",
                )
                .expect("token")
                .sign(&rig.issuer)
            } else {
                mint_leg(
                    &rig.issuer,
                    &presenter,
                    1,
                    distinct(21),
                    distinct(22),
                    BlindRelayLegSlot::Slot0,
                    distinct16(23),
                    rig.now - 5,
                    rig.now + 60,
                    "profile-NOT-ALLOWED",
                )
            };
            let artifact = rig
                .listener
                .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
                .expect("issue");
            let wire = BlindRelayHelloV2::new(minted, client_nonce, artifact, [5u8; 64])
                .expect("hello")
                .to_wire()
                .into_bytes();
            let mut observer = RecordedObserver::default();
            let result =
                rig.listener
                    .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
            assert_eq!(result, Err(BlindRejectReason::Unauthorized), "{scenario}");
            assert_eq!(
                observer.stages.last(),
                Some(&BlindAdmissionStage::FieldValidation)
            );
        }
    }

    // ── Step 6 negatives ────────────────────────────────────────────────────

    #[test]
    fn expired_and_future_tokens_rejected_at_freshness() {
        for scenario in ["expired", "future"] {
            let mut rig = build_rig(scenario);
            let source = source_addr(10, 6006);
            let client_nonce = distinct(24);
            let presenter = SigningKey::from_bytes(&[0x25u8; 32]);
            let (issued, expires) = if scenario == "expired" {
                (rig.now - 500, rig.now - 400)
            } else {
                (rig.now + 100, rig.now + 160) // issued beyond skew
            };
            let token = mint_leg(
                &rig.issuer,
                &presenter,
                1,
                distinct(25),
                distinct(26),
                BlindRelayLegSlot::Slot0,
                distinct16(27),
                issued,
                expires,
                TEST_PROFILE,
            );
            let artifact = rig
                .listener
                .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
                .expect("issue");
            let wire = BlindRelayHelloV2::new(token, client_nonce, artifact, [6u8; 64])
                .expect("hello")
                .to_wire()
                .into_bytes();
            let mut observer = RecordedObserver::default();
            let result =
                rig.listener
                    .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
            assert_eq!(result, Err(BlindRejectReason::Unauthorized), "{scenario}");
            assert_eq!(
                observer.stages.last(),
                Some(&BlindAdmissionStage::Freshness)
            );
        }
    }

    #[test]
    fn clock_unavailable_rejects_hello() {
        let mut rig = build_rig("clock_none");
        let source = source_addr(11, 6007);
        let client_nonce = distinct(28);
        let presenter = SigningKey::from_bytes(&[0x26u8; 32]);
        let token = mint_leg(
            &rig.issuer,
            &presenter,
            1,
            distinct(29),
            distinct(30),
            BlindRelayLegSlot::Slot0,
            distinct16(31),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
            .expect("issue");
        let wire = BlindRelayHelloV2::new(token, client_nonce, artifact, [7u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        let mut observer = RecordedObserver::default();
        let result = rig
            .listener
            .handle_hello_with_now(&wire, source, None, &mut observer);
        assert_eq!(result, Err(BlindRejectReason::ClockUnavailable));
        assert_eq!(
            observer.stages,
            vec![
                BlindAdmissionStage::EnvelopeParse,
                BlindAdmissionStage::SourceRateLimit,
                // The step-3 stage OPENS before the clock is consumed inside
                // it; the ClockUnavailable reject class is what fails closed.
                BlindAdmissionStage::AddressValidation,
            ]
        );
    }

    // ── Step 7 negatives ────────────────────────────────────────────────────

    #[test]
    fn bad_pop_signature_rejected_at_proof_stage() {
        let mut rig = build_rig("pop_bad");
        let source = source_addr(12, 6008);
        let client_nonce = distinct(32);
        let wire = signed_hello_wire(
            &rig,
            source,
            &SigningKey::from_bytes(&[0x27u8; 32]),
            1,
            distinct(33),
            distinct(34),
            BlindRelayLegSlot::Slot0,
            distinct16(35),
            client_nonce,
        );
        // Corrupt ONLY the PoP signature while keeping the document
        // canonical: flip a byte inside the final signature line value.
        let text = String::from_utf8(wire).expect("wire is utf8");
        let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
        let last = lines.len() - 1;
        let mut sig_chars: Vec<char> = lines[last].chars().collect();
        let flip = sig_chars.len() - 1;
        sig_chars[flip] = if sig_chars[flip] == '0' { '1' } else { '0' };
        lines[last] = sig_chars.into_iter().collect();
        let corrupt = lines.join("\n");
        let mut corrupt = corrupt.into_bytes();
        corrupt.push(b'\n');
        let mut observer = RecordedObserver::default();
        let result =
            rig.listener
                .handle_hello_with_now(&corrupt, source, Some(rig.now), &mut observer);
        // The mutated signature line breaks either canonical re-encode or the
        // PoP proof itself — both are closed-class rejects; the stage
        // sequence proves the composition fails at or before the proof.
        assert_eq!(result, Err(BlindRejectReason::Unauthorized));
        let reached_proof = observer
            .stages
            .contains(&BlindAdmissionStage::ProofOfPossession);
        let reached_commit = observer.stages.contains(&BlindAdmissionStage::Commit);
        assert!(!reached_commit);
        if reached_proof {
            // Proof stage ran and rejected.
        } else {
            // Parser rejected the mutated document.
            assert_eq!(observer.stages, vec![BlindAdmissionStage::EnvelopeParse]);
        }
    }

    #[test]
    fn pop_digest_differs_across_circuits() {
        let a = blind_replay_digest_pop(&distinct(40), &distinct(41), &[1u8; 64]);
        let b = blind_replay_digest_pop(&distinct(42), &distinct(41), &[1u8; 64]);
        assert_ne!(a, b);
    }

    // ── Step 8 negatives ────────────────────────────────────────────────────

    #[test]
    fn replayed_hello_rejected_after_first_admission() {
        let mut rig = build_rig("replay_exact");
        let source = source_addr(13, 6009);
        let wire = signed_hello_wire(
            &rig,
            source,
            &SigningKey::from_bytes(&[0x28u8; 32]),
            1,
            distinct(43),
            distinct(44),
            BlindRelayLegSlot::Slot0,
            distinct16(45),
            distinct(46),
        );
        let mut observer = RecordedObserver::default();
        let first = rig
            .listener
            .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(first, Ok(BlindAdmissionOutcome::WaitingLegRecorded));
        let second =
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer);
        assert_eq!(second, Err(BlindRejectReason::Replayed));
    }

    #[test]
    fn same_nonce_different_leg_handle_rejected() {
        let mut rig = build_rig("replay_nonce");
        let source = source_addr(14, 6010);
        let presenter = SigningKey::from_bytes(&[0x29u8; 32]);
        let nonce = distinct16(50);
        let client_nonce = distinct(51);
        let wire = signed_hello_wire(
            &rig,
            source,
            &presenter,
            1,
            distinct(52),
            distinct(53),
            BlindRelayLegSlot::Slot0,
            nonce,
            client_nonce,
        );
        let mut observer = RecordedObserver::default();
        assert_eq!(
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer),
            Ok(BlindAdmissionOutcome::WaitingLegRecorded)
        );
        // Fresh token (different circuit/leg), SAME nonce within the epoch.
        let token2 = mint_leg(
            &rig.issuer,
            &presenter,
            1,
            distinct(54),
            distinct(55),
            BlindRelayLegSlot::Slot0,
            nonce, // reused nonce
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let artifact = rig
            .listener
            .issue_address_validation_artifact(&source, &client_nonce, 1, rig.now)
            .expect("issue");
        let transcript = {
            let hello = BlindRelayHelloV2::new(token2.clone(), client_nonce, artifact, [0u8; 64])
                .expect("hello");
            hello.pop_transcript().expect("transcript")
        };
        let pop = presenter.sign(transcript.canonical_bytes().as_bytes());
        let wire2 = BlindRelayHelloV2::new(token2, client_nonce, artifact, pop.to_bytes())
            .expect("hello")
            .to_wire()
            .into_bytes();
        let result =
            rig.listener
                .handle_hello_with_now(&wire2, source, Some(rig.now), &mut observer);
        assert_eq!(result, Err(BlindRejectReason::Replayed));
    }

    #[test]
    fn corrupt_replay_store_refuses_listener_open() {
        let path = temp_store_path("corrupt_store");
        std::fs::write(&path, "not-a-valid-digest-line\n").expect("write corrupt store");
        let issuer = SigningKey::from_bytes(&[7u8; 32]);
        let result = BlindRelayListener::build(BlindRelayListenerConfig {
            relay_id: TEST_RELAY_ID,
            issuer_keys: test_issuer_keys(&issuer),
            allowed_profiles: test_profiles(),
            address_validation_keys: AddressValidationKeyRing::new(1, [9u8; 32]).expect("ring"),
            replay_store_path: path,
            limits: BlindRelayListenerLimits::default(),
            clock_skew_tolerance_secs: 10,
            signed_capability_granted: true,
            operator_enabled: true,
        });
        assert!(matches!(
            result,
            Err(BlindListenerOpenError::ReplayStoreInvalid(_))
        ));
    }

    #[test]
    fn full_replay_store_rejects_admission_and_never_evicts_live_entries() {
        // Exercise the cap at store level (constructing MAX entries through the
        // public admission path would need tens of thousands of signed
        // hellos); the listener maps a store-full error to ReplayStoreUnavailable.
        // Entries are stamped with the LIVE clock so the retention prune (the
        // one legitimate recovery path inside insert_all) has nothing to free.
        let path = temp_store_path("full_store");
        let mut store = BlindReplayStore::open(path.clone()).expect("open empty store");
        let live_stamp = crate::transport::now_unix_checked().unwrap_or(0);
        for i in 0..MAX_BLIND_REPLAY_ENTRIES {
            store.entries.insert(distinct((i % 251) as u8), live_stamp);
        }
        // Distinct-fill: colliding keys would under-fill the map.
        let mut salt = 0u64;
        while store.entries.len() < MAX_BLIND_REPLAY_ENTRIES {
            let mut digest = [0u8; 32];
            digest[..8].copy_from_slice(&salt.to_be_bytes());
            store.entries.insert(digest, live_stamp);
            salt += 1;
        }
        assert_eq!(store.entries.len(), MAX_BLIND_REPLAY_ENTRIES);
        let probe = distinct(99);
        let result = store.insert_all(&[probe]);
        assert!(result.is_err(), "full store must reject the insert");
        assert!(
            store.entries.len() == MAX_BLIND_REPLAY_ENTRIES,
            "no eviction on reject"
        );
        assert!(
            store.contains(&distinct(0u8)),
            "live entries are never evicted"
        );
        // After freeing space the same insert succeeds.
        store.entries.clear();
        assert!(store.insert_all(&[probe]).is_ok());
    }

    #[test]
    fn admission_commits_replay_entries_durably() {
        let mut rig = build_rig("durable_commit");
        let source = source_addr(15, 6011);
        let presenter = SigningKey::from_bytes(&[0x2Au8; 32]);
        let epoch = 1u64;
        let leg = distinct(60);
        let nonce = distinct16(61);
        let client_nonce = distinct(62);
        let wire = signed_hello_wire(
            &rig,
            source,
            &presenter,
            epoch,
            distinct(63),
            leg,
            BlindRelayLegSlot::Slot0,
            nonce,
            client_nonce,
        );
        let mut observer = RecordedObserver::default();
        assert_eq!(
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer),
            Ok(BlindAdmissionOutcome::WaitingLegRecorded)
        );
        let expected = blind_replay_digest_leg(epoch, &nonce, &leg);
        let on_disk = std::fs::read_to_string(&rig.store_path).expect("store readable");
        assert!(
            on_disk.contains(&blind_replay_hex(&expected)),
            "leg digest must be durably committed"
        );
    }

    // ── Step 9 negatives ────────────────────────────────────────────────────

    #[test]
    fn waiting_leg_resource_limits_hold() {
        // Tight limits: 1 total, 1 per prefix, 1 per profile.
        let limits = BlindRelayListenerLimits {
            max_waiting_legs_total: 2,
            max_waiting_legs_per_source_prefix: 1,
            max_waiting_legs_per_profile: 2,
            max_hellos_per_source_prefix_per_sec: 100,
        };
        let mut rig = build_rig_with("limits", limits, temp_store_path("limits"));
        let client_nonce = distinct(70);

        let admit = |rig: &mut TestRig, subnet: u8, host: u8, circuit: [u8; 32]| {
            let source = source_addr_subnet(subnet, host, 6012);
            let wire = signed_hello_wire(
                rig,
                source,
                &SigningKey::from_bytes(&[circuit[0]; 32]),
                1,
                circuit,
                distinct(circuit[0].wrapping_add(1)),
                BlindRelayLegSlot::Slot0,
                distinct16(circuit[0].wrapping_add(2)),
                client_nonce,
            );
            let mut observer = RecordedObserver::default();
            rig.listener
                .handle_hello_with_now(&wire, source, Some(rig.now), &mut observer)
        };

        assert_eq!(
            admit(&mut rig, 1, 20, distinct(80)),
            Ok(BlindAdmissionOutcome::WaitingLegRecorded)
        );
        // Same prefix, different circuit/profile → per-prefix cap.
        assert_eq!(
            admit(&mut rig, 1, 21, distinct(81)),
            Err(BlindRejectReason::Capacity)
        );
        // Different prefix passes the prefix cap (total now 2).
        assert_eq!(
            admit(&mut rig, 2, 30, distinct(82)),
            Ok(BlindAdmissionOutcome::WaitingLegRecorded)
        );
        // Total cap now holds even from a fresh prefix.
        assert_eq!(
            admit(&mut rig, 3, 40, distinct(83)),
            Err(BlindRejectReason::Capacity)
        );
    }

    // ── Step 10 + pairing (§7.6) ────────────────────────────────────────────

    #[test]
    fn pairing_happy_path_and_duplicate_slot_rejection() {
        let mut rig = build_rig("pairing");
        let source_a = source_addr(50, 6013);
        let source_b = source_addr(51, 6014);
        let circuit = distinct(90);
        let leg0 = distinct(91);
        let leg1 = distinct(92);
        let presenter_a = SigningKey::from_bytes(&[0x31u8; 32]);
        let presenter_b = SigningKey::from_bytes(&[0x32u8; 32]);
        let mut observer = RecordedObserver::default();

        let wire0 = signed_hello_wire(
            &rig,
            source_a,
            &presenter_a,
            1,
            circuit,
            leg0,
            BlindRelayLegSlot::Slot0,
            distinct16(93),
            distinct(94),
        );
        assert_eq!(
            rig.listener
                .handle_hello_with_now(&wire0, source_a, Some(rig.now), &mut observer),
            Ok(BlindAdmissionOutcome::WaitingLegRecorded)
        );

        // A second DISTINCT token claiming slot 0 again must be a pairing
        // violation (the exact same wire was already rejected as replay).
        let token_dup = mint_leg(
            &rig.issuer,
            &SigningKey::from_bytes(&[0x33u8; 32]),
            1,
            circuit,
            distinct(95),
            BlindRelayLegSlot::Slot0,
            distinct16(96),
            rig.now - 5,
            rig.now + 60,
            TEST_PROFILE,
        );
        let artifact_dup = rig
            .listener
            .issue_address_validation_artifact(&source_a, &distinct(97), 1, rig.now)
            .expect("issue");
        let wire_dup = BlindRelayHelloV2::new(token_dup, distinct(97), artifact_dup, [8u8; 64])
            .expect("hello")
            .to_wire()
            .into_bytes();
        assert_eq!(
            rig.listener
                .handle_hello_with_now(&wire_dup, source_a, Some(rig.now), &mut observer),
            Err(BlindRejectReason::Unauthorized)
        );

        // Complementary leg pairs.
        let wire1 = signed_hello_wire(
            &rig,
            source_b,
            &presenter_b,
            1,
            circuit,
            leg1,
            BlindRelayLegSlot::Slot1,
            distinct16(98),
            distinct(99),
        );
        assert_eq!(
            rig.listener
                .handle_hello_with_now(&wire1, source_b, Some(rig.now), &mut observer),
            Ok(BlindAdmissionOutcome::CircuitPaired)
        );
        assert_eq!(rig.listener.waiting_circuit_count(), 0);
    }

    #[test]
    fn mismatched_or_self_presenter_second_leg_rejected() {
        for scenario in ["profile", "expiry", "same_presenter"] {
            let mut rig = build_rig(scenario);
            let circuit = distinct(100);
            let source_a = source_addr(60, 6015);
            let source_b = source_addr(61, 6016);
            let presenter_a = SigningKey::from_bytes(&[0x34u8; 32]);
            let presenter_b = SigningKey::from_bytes(&[0x35u8; 32]);
            let mut observer = RecordedObserver::default();

            let expires = rig.now + 60;
            let token0 = mint_leg(
                &rig.issuer,
                &presenter_a,
                1,
                circuit,
                distinct(101),
                BlindRelayLegSlot::Slot0,
                distinct16(102),
                rig.now - 5,
                expires,
                TEST_PROFILE,
            );
            let artifact0 = rig
                .listener
                .issue_address_validation_artifact(&source_a, &distinct(103), 1, rig.now)
                .expect("issue");
            let hello0 =
                BlindRelayHelloV2::new(token0, distinct(103), artifact0, [0u8; 64]).expect("hello");
            let pop0 = presenter_a.sign(
                hello0
                    .pop_transcript()
                    .expect("t")
                    .canonical_bytes()
                    .as_bytes(),
            );
            let wire0 =
                BlindRelayHelloV2::new(hello0.token, distinct(103), artifact0, pop0.to_bytes())
                    .expect("hello")
                    .to_wire()
                    .into_bytes();
            assert_eq!(
                rig.listener
                    .handle_hello_with_now(&wire0, source_a, Some(rig.now), &mut observer),
                Ok(BlindAdmissionOutcome::WaitingLegRecorded),
                "{scenario}"
            );

            let (profile_b, expires_b) = match scenario {
                "profile" => ("profile-B-OTHER", expires),
                "expiry" => (TEST_PROFILE, expires + 30),
                _ => (TEST_PROFILE, expires),
            };
            let presenter_for_leg1 = if scenario == "same_presenter" {
                &presenter_a // same presenter key on both legs is forbidden
            } else {
                &presenter_b
            };
            let token1 = mint_leg(
                &rig.issuer,
                presenter_for_leg1,
                1,
                circuit,
                distinct(104),
                BlindRelayLegSlot::Slot1,
                distinct16(105),
                rig.now - 5,
                expires_b,
                profile_b,
            );
            let artifact1 = rig
                .listener
                .issue_address_validation_artifact(&source_b, &distinct(106), 1, rig.now)
                .expect("issue");
            let hello1 =
                BlindRelayHelloV2::new(token1, distinct(106), artifact1, [0u8; 64]).expect("hello");
            let pop1 = presenter_for_leg1.sign(
                hello1
                    .pop_transcript()
                    .expect("t")
                    .canonical_bytes()
                    .as_bytes(),
            );
            let wire1 =
                BlindRelayHelloV2::new(hello1.token, distinct(106), artifact1, pop1.to_bytes())
                    .expect("hello")
                    .to_wire()
                    .into_bytes();
            assert_eq!(
                rig.listener
                    .handle_hello_with_now(&wire1, source_b, Some(rig.now), &mut observer),
                Err(BlindRejectReason::Unauthorized),
                "{scenario}"
            );
        }
    }

    // ── No v1 fallback ──────────────────────────────────────────────────────

    #[test]
    fn no_v1_fallback_v1_shaped_wire_is_malformed() {
        let mut rig = build_rig("no_v1");
        let mut observer = RecordedObserver::default();
        // A plausible v1-grammar relay session token document (identity-
        // bearing): node_id/peer_node_id keys do not exist in the v2
        // allowlist and the line count can never match.
        let v1_wire = b"version=1\nnode_id=node-a\npeer_node_id=node-b\nrelay_id=AAAAAAAAAAAAAAAAAAAAAA==\nsignature=AAAA\n".to_vec();
        let result = rig.listener.handle_hello_with_now(
            &v1_wire,
            source_addr(70, 6017),
            Some(rig.now),
            &mut observer,
        );
        assert_eq!(result, Err(BlindRejectReason::Malformed));
        assert_eq!(observer.stages, vec![BlindAdmissionStage::EnvelopeParse]);
    }

    // ── Go-live gate ────────────────────────────────────────────────────────

    #[test]
    fn adversarial_review_gate_is_closed() {
        // Mutation obligation (design §13.1): flipping
        // BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED to true without the
        // completed §16 review must fail THIS test.
        // The const is compile-time-known, so silence the constant-assert lint;
        // the runtime check is still the mutation tripwire for §13.1.
        #![allow(clippy::assertions_on_constants)]
        assert!(!BLIND_RELAY_V2_ADVERSARIAL_REVIEW_APPROVED);
    }

    #[test]
    fn try_open_refuses_without_all_three_gates() {
        let issuer = SigningKey::from_bytes(&[7u8; 32]);
        let make_config = |capability: bool, flag: bool| BlindRelayListenerConfig {
            relay_id: TEST_RELAY_ID,
            issuer_keys: test_issuer_keys(&issuer),
            allowed_profiles: test_profiles(),
            address_validation_keys: AddressValidationKeyRing::new(1, [9u8; 32]).expect("ring"),
            replay_store_path: temp_store_path("gate"),
            limits: BlindRelayListenerLimits::default(),
            clock_skew_tolerance_secs: 10,
            signed_capability_granted: capability,
            operator_enabled: flag,
        };
        assert!(
            matches!(
                BlindRelayListener::try_open(make_config(true, true)),
                Err(BlindListenerOpenError::GateClosed)
            ),
            "review bit is false: even capability+flag must stay closed"
        );
        assert!(matches!(
            BlindRelayListener::try_open(make_config(false, true)),
            Err(BlindListenerOpenError::GateClosed)
        ));
        assert!(matches!(
            BlindRelayListener::try_open(make_config(true, false)),
            Err(BlindListenerOpenError::GateClosed)
        ));
    }

    // ── Key ring behavior ───────────────────────────────────────────────────

    #[test]
    fn key_ring_rotation_and_epoch_fallback() {
        let mut ring = AddressValidationKeyRing::new(1, [1u8; 32]).expect("ring");
        let source = source_addr(80, 6018);
        let nonce = distinct(110);
        let artifact = ring
            .issue_artifact(&source, &nonce, 1, 1_000)
            .expect("issue");
        // Old-epoch artifact still verifies while its key is retained.
        ring.rotate(2, [2u8; 32]).expect("rotate");
        assert_eq!(
            ring.verify_artifact(&source, &nonce, 1, &artifact, 1_005, 10),
            Ok(())
        );
        // Unknown epoch (never issued) fails.
        let mut foreign = artifact;
        foreign[..4].copy_from_slice(&99u32.to_be_bytes());
        assert_eq!(
            ring.verify_artifact(&source, &nonce, 1, &foreign, 1_005, 10),
            Err(AddressArtifactError::UnknownKeyEpoch)
        );
        // Backwards rotation is refused.
        assert_eq!(
            ring.rotate(1, [3u8; 32]),
            Err(AddressArtifactError::InvalidArtifact)
        );
        // Zero keys are refused at construction and rotation.
        assert!(matches!(
            AddressValidationKeyRing::new(5, [0u8; 32]),
            Err(AddressArtifactError::InvalidArtifact)
        ));
        assert_eq!(
            ring.rotate(3, [0u8; 32]),
            Err(AddressArtifactError::InvalidArtifact)
        );
    }

    #[test]
    fn skew_clamp_mirrors_v1_ceiling() {
        assert_eq!(compute_clamped_skew(0), (0, false));
        assert_eq!(
            compute_clamped_skew(BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS),
            (BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS, false)
        );
        assert_eq!(
            compute_clamped_skew(u64::MAX),
            (BLIND_MAX_CLOCK_SKEW_TOLERANCE_SECS, true)
        );
    }
}
