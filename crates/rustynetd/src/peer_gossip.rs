#![forbid(unsafe_code)]

//! D2.5 — Peer-distributed signed-bundle gossip.
//!
//! Per the dataplane execution plan §D2.5, each peer mints a signed
//! bundle that carries:
//!
//! * its node ID (Ed25519 verifying-key fingerprint),
//! * a strictly-increasing sequence number (per-source anti-replay),
//! * a Unix timestamp (drift-bounded freshness),
//! * the minter's VERIFIED membership epoch (I2 — binds the bundle to
//!   the signed-membership timeline so revocation is reinforced: once
//!   the mesh advances past the epoch a revoked peer last saw, that
//!   peer's self-signed bundles fall out of the acceptance window;
//!   freshness alone cannot expire them because the revoked peer
//!   itself is the signer and can keep re-stamping timestamps),
//! * its full [`CandidateSet`] (v4/v6 host + srflx endpoints from
//!   [`crate::dataplane_candidates`]),
//! * an Ed25519 signature over the canonical pre-image of all of the
//!   above.
//!
//! Peers exchange these bundles over the existing WG-encrypted control
//! channel (so there's no extra ingress and the channel is already
//! authenticated at the WG layer). A receiving peer accepts a bundle
//! only if:
//!
//! 1. The signature verifies under the bundle's claimed source node's
//!    known verifying key (from the membership snapshot). If the
//!    source is unknown to us, reject.
//! 2. The sequence number is strictly greater than the largest
//!    sequence we've previously accepted from that source.
//! 3. The timestamp is within the allowed freshness window relative to
//!    our local clock — both past (no stale replay of long-old
//!    bundles) and future (no clock-skew injection).
//!
//! Security framing:
//!
//! * The signature is the only authority. We do NOT trust the bundle's
//!   declared source node ID alone; the verifying key for that source
//!   must come from a separate trust artifact (the signed membership
//!   snapshot). A bundle signed by an unknown key is dropped.
//! * Anti-replay is per-source. A separate [`SeenSequenceState`]
//!   tracks the highest accepted sequence per source. This makes the
//!   protocol stateful but the state is bounded in size (one entry
//!   per known peer) and persists across daemon restarts via the
//!   existing watermark spool pattern.
//! * Freshness alone does not stop replay (an attacker can replay a
//!   fresh bundle if it's still inside the window), but combined with
//!   strict-monotonic sequence numbers it does — replaying is no-op
//!   because the sequence has already been seen.
//! * We canonicalise the pre-image before signing so two
//!   bit-identical bundles always produce the same signature; small
//!   serialisation drift would otherwise produce different signatures
//!   for the same logical bundle and break verification.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::dataplane_candidates::CandidateSet;

/// Wire-format version byte for [`serialise_bundle`] / [`deserialise_bundle`].
/// A bundle whose first byte does not equal this constant is rejected hard;
/// future protocol changes must bump this byte and add a new branch.
///
/// Version history:
/// * 1 — initial D2.5 layout (source, sequence, timestamp, counts,
///   candidates, signature).
/// * 2 — I2 epoch binding: a `u64` membership epoch inserted between the
///   timestamp and the candidate counts, covered by the signature. v1
///   bundles are rejected hard (no downgrade branch), and the signing
///   domain prefix was bumped in lockstep so a v1 signature can never
///   verify against a v2 pre-image even if the raw bytes were
///   reinterpreted.
pub const GOSSIP_BUNDLE_WIRE_VERSION: u8 = 2;

/// Hard cap on a single gossip datagram (header + candidates +
/// signature). With the strictest layout this fits comfortably in a
/// single UDP datagram (no IP fragmentation under normal MTU) and
/// covers the worst case of [`MAX_CANDIDATES_PER_BUNDLE`] candidates.
/// Datagrams larger than this are dropped on both send and receive.
pub const MAX_GOSSIP_DATAGRAM_BYTES: usize = 4 * 1024;

/// Fixed-layout wire constants used by `serialise_bundle` /
/// `deserialise_bundle`. Centralised so any future drift between
/// encoder and decoder is impossible.
const WIRE_VERSION_OFFSET: usize = 0;
const WIRE_SOURCE_OFFSET: usize = 1;
const WIRE_SEQUENCE_OFFSET: usize = 33;
const WIRE_TIMESTAMP_OFFSET: usize = 41;
const WIRE_EPOCH_OFFSET: usize = 49;
const WIRE_COUNTS_OFFSET: usize = 57;
const WIRE_CANDIDATES_OFFSET: usize = 73;
const WIRE_CANDIDATE_STRIDE: usize = 18;
const WIRE_SIGNATURE_LEN: usize = 64;

/// Magic prefix mixed into the signing pre-image. Domain separation:
/// guarantees that a signature on a gossip bundle cannot be replayed
/// as a signature on some other Ed25519-signed artifact (relay
/// session token, traversal bundle, etc.).
///
/// Bumped `v1` → `v2` together with [`GOSSIP_BUNDLE_WIRE_VERSION`]
/// when the I2 epoch field entered the pre-image: with a distinct
/// domain string, a signature minted over the v1 pre-image layout can
/// NEVER verify against a v2 pre-image, even for a hypothetical byte
/// string that parses under both layouts. Cross-version signature
/// confusion is thereby excluded categorically instead of relying on
/// the decoder's structural checks alone.
pub const GOSSIP_BUNDLE_DOMAIN: &[u8] = b"rustynet:peer_gossip:v2";

/// Bundle freshness window. A bundle whose timestamp is more than this
/// many seconds in the past OR future relative to the receiver's
/// local clock is dropped. The plan's recommendation is "a few
/// minutes": we use 5 minutes (300 s) which is generous for clock
/// drift but tight enough that an attacker cannot replay a stale
/// bundle indefinitely if they somehow obtained one with a
/// fresh-enough timestamp.
pub const DEFAULT_FRESHNESS_WINDOW_SECS: u64 = 300;

/// Maximum number of endpoints serialised per bundle. Hard cap to keep
/// pre-image generation bounded; a peer claiming hundreds of
/// candidates is either misconfigured or attempting to exhaust
/// verifier memory.
pub const MAX_CANDIDATES_PER_BUNDLE: usize = 32;

/// I2 — how many membership epochs a bundle's signed epoch may lag
/// BEHIND the receiver's verified epoch before the bundle is rejected.
///
/// Why a window instead of `bundle.epoch >= local_epoch`: the
/// membership epoch increments by exactly 1 on EVERY membership update
/// (`rustynet-control::membership` — join, capability change,
/// revocation, all of them), not only on revocations. A strict
/// equality/monotonic rule would therefore blackhole every peer's
/// still-fresh prior-epoch bundle on ANY benign membership change —
/// a mesh-wide fail-closed churn cliff each time an admin touches
/// membership. The window tolerates the propagation lag of a few
/// updates while still guaranteeing the property I2 exists for: a
/// REVOKED peer stops receiving membership updates, so the epoch it
/// can truthfully stamp freezes, and once the mesh advances more than
/// this many epochs past it, its self-signed bundles fall outside the
/// window everywhere — revocation is reinforced even where the
/// explicit revoked-source set has not propagated. Staleness within
/// the window is independently bounded by the signed-timestamp
/// freshness check ([`DEFAULT_FRESHNESS_WINDOW_SECS`]).
pub const GOSSIP_EPOCH_SKEW_WINDOW: u64 = 2;

/// I2 — how many membership epochs a bundle's signed epoch may run
/// AHEAD of the receiver's verified epoch before the bundle is
/// rejected as implausible.
///
/// A modestly-ahead epoch is legitimate: the minter may simply have
/// verified a newer membership snapshot than we have (we are the ones
/// lagging). But the tolerance must stay SMALL, because every epoch of
/// forward tolerance extends the revocation-aging horizon by one: a
/// still-keyed attacker who pre-stamps `local + F` keeps that bundle
/// inside receivers' behind-window for `F + GOSSIP_EPOCH_SKEW_WINDOW`
/// further mesh epochs. A wildly-future epoch has no honest
/// explanation (epochs only advance by 1 per verified update) and is
/// rejected outright.
pub const GOSSIP_EPOCH_FUTURE_TOLERANCE: u64 = 2;

/// A signed peer-endpoint gossip bundle. This is the on-wire shape
/// (serialised via [`serialise_bundle`]) plus the verifying signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipBundle {
    pub source_node_id: [u8; 32],
    pub sequence: u64,
    pub timestamp_unix: u64,
    /// I2 — the minter's VERIFIED membership epoch at mint time.
    /// Covered by the signature (part of [`signing_preimage`]), so a
    /// forwarding peer cannot rewrite it. The accept path enforces a
    /// bounded skew window around the receiver's own verified epoch;
    /// see `accept_bundle_with_now` for the exact semantics.
    pub epoch: u64,
    pub candidates: CandidateSet,
    pub signature: Signature,
}

/// Errors surfaced by the gossip mint / verify / accept paths.
#[derive(Debug)]
pub enum GossipError {
    /// The bundle's claimed source is not in our known-peer set.
    UnknownSource,
    /// GM-1 / RSA-0034: the bundle's claimed source IS a known peer, but
    /// signed membership currently marks it Revoked/Quarantined. Distinct
    /// from `UnknownSource` (which means "we've never heard of this peer")
    /// so the rejection reason is precise and separately counted —
    /// defense-in-depth alongside the dataplane ACL revocation check
    /// (DD-03/RSA-0007): a revoked node must not be able to re-advertise
    /// itself and be re-admitted via gossip alone.
    RevokedSource,
    /// The Ed25519 signature failed verification under the claimed
    /// source's verifying key.
    SignatureInvalid,
    /// The bundle's timestamp falls outside the freshness window.
    /// Carries the receiver's view of the drift in seconds (positive
    /// = bundle from the future, negative = bundle from the past).
    TimestampOutsideWindow { drift_secs: i64 },
    /// The bundle's sequence number is not strictly greater than the
    /// largest sequence already accepted from this source.
    SequenceNotMonotonic { last_seen: u64, presented: u64 },
    /// I2: the bundle's signed membership epoch falls outside the
    /// acceptance window around the receiver's verified epoch — more
    /// than [`GOSSIP_EPOCH_SKEW_WINDOW`] behind (stale trust view; the
    /// signature is valid but was minted against a membership timeline
    /// the mesh has moved past — the property that ages out a revoked
    /// peer's self-signed bundles) or more than
    /// [`GOSSIP_EPOCH_FUTURE_TOLERANCE`] ahead (implausible; epochs
    /// only advance by 1 per verified membership update).
    EpochOutsideWindow {
        local_epoch: u64,
        presented_epoch: u64,
    },
    /// Too many candidates packed into a single bundle.
    TooManyCandidates { presented: usize, max: usize },
    /// One or more candidate endpoints have non-gossip-worthy scope
    /// (loopback, link-local, multicast, broadcast, unspecified, or
    /// the IPv6 documentation prefix). A peer claiming such addresses
    /// as its own reachability is either misconfigured or trying to
    /// redirect our connect-attempt traffic to a local service or
    /// multicast group. Fail closed.
    UnreachableCandidate { addr: String },
    /// Couldn't compute the current Unix timestamp (clock before
    /// UNIX_EPOCH). Should never happen on a healthy host.
    TimestampUnavailable,
    /// Bundle's wire-format version byte did not equal
    /// [`GOSSIP_BUNDLE_WIRE_VERSION`]. A future protocol bump must add
    /// a new branch; the current decoder rejects unknown versions
    /// hard so a downgrade attack cannot trick us into accepting a
    /// weaker layout.
    WireVersionMismatch { expected: u8, presented: u8 },
    /// Bundle bytes ended before all fixed-layout fields could be
    /// read. Distinct from `WireMalformed` so the diagnostic names
    /// the actual condition.
    WireTruncated { needed: usize, available: usize },
    /// Bundle bytes were structurally malformed (e.g. a v4 lane
    /// carried 16 bytes that were not in the v4-mapped-IPv6 prefix
    /// form). Carries a fixed-vocabulary diagnostic so logging stays
    /// safe.
    WireMalformed(&'static str),
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipError::UnknownSource => write!(f, "gossip bundle source is not a known peer"),
            GossipError::RevokedSource => {
                write!(f, "gossip bundle source is revoked in signed membership")
            }
            GossipError::SignatureInvalid => {
                write!(f, "gossip bundle signature verification failed")
            }
            GossipError::TimestampOutsideWindow { drift_secs } => write!(
                f,
                "gossip bundle timestamp is outside the freshness window (drift {drift_secs}s)"
            ),
            GossipError::SequenceNotMonotonic {
                last_seen,
                presented,
            } => write!(
                f,
                "gossip bundle sequence not monotonic (last seen {last_seen}, presented {presented})"
            ),
            GossipError::EpochOutsideWindow {
                local_epoch,
                presented_epoch,
            } => write!(
                f,
                "gossip bundle membership epoch outside acceptance window (local {local_epoch}, presented {presented_epoch})"
            ),
            GossipError::TooManyCandidates { presented, max } => write!(
                f,
                "gossip bundle carries too many candidates ({presented}; max {max})"
            ),
            GossipError::UnreachableCandidate { addr } => write!(
                f,
                "gossip bundle carries a non-gossip-worthy candidate address {addr}"
            ),
            GossipError::TimestampUnavailable => write!(
                f,
                "local clock is before UNIX_EPOCH; cannot compute timestamp"
            ),
            GossipError::WireVersionMismatch {
                expected,
                presented,
            } => write!(
                f,
                "gossip bundle wire version mismatch (expected {expected}, presented {presented})"
            ),
            GossipError::WireTruncated { needed, available } => write!(
                f,
                "gossip bundle wire truncated (needed {needed}, available {available})"
            ),
            GossipError::WireMalformed(reason) => {
                write!(f, "gossip bundle wire malformed: {reason}")
            }
        }
    }
}

impl std::error::Error for GossipError {}

/// Per-source highest-accepted sequence. Lives in the daemon's state
/// directory (mirroring the watermark pattern used by the membership
/// and trust subsystems) and is consulted on every inbound bundle.
#[derive(Debug, Default, Clone)]
pub struct SeenSequenceState {
    inner: HashMap<[u8; 32], u64>,
}

impl SeenSequenceState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the highest sequence accepted from `source`, or None
    /// if we've never accepted a bundle from them.
    pub fn highest_accepted(&self, source: &[u8; 32]) -> Option<u64> {
        self.inner.get(source).copied()
    }

    /// Record that we've accepted `sequence` from `source`. Idempotent
    /// and safe to call with a sequence equal to or lower than the
    /// existing record (it keeps the maximum).
    pub fn record(&mut self, source: [u8; 32], sequence: u64) {
        self.inner
            .entry(source)
            .and_modify(|cur| {
                if sequence > *cur {
                    *cur = sequence;
                }
            })
            .or_insert(sequence);
    }

    /// Number of distinct sources we've ever accepted a bundle from.
    pub fn source_count(&self) -> usize {
        self.inner.len()
    }

    /// Iterate `(source_id, highest_accepted_sequence)` pairs. Used
    /// by the gossip watermark spool to serialise the per-source
    /// ledger. The order is unspecified — callers that need a
    /// deterministic spool layout should sort the result.
    pub fn iter_pairs_for_spool(&self) -> impl Iterator<Item = (&[u8; 32], &u64)> {
        self.inner.iter()
    }
}

/// Wall-clock now in seconds since UNIX_EPOCH. Defined here so tests
/// can mock it via the `*_with_now` variants.
pub fn current_unix_seconds() -> Result<u64, GossipError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| GossipError::TimestampUnavailable)
}

/// Canonical serialisation of the bundle's signed fields. Used both
/// by mint (to feed the signer) and by verify (to recompute the
/// pre-image). Deterministic: identical inputs always produce
/// identical bytes.
///
/// Wire layout (big-endian everywhere):
///
/// * `[..16]` magic prefix `b"rustynet:peer_gossip:v1"` truncated
///   to 16 bytes? No — full prefix length-prefixed.
/// * Domain prefix length (u16 BE) + prefix bytes.
/// * Source node ID (32 bytes).
/// * Sequence (u64 BE).
/// * Timestamp Unix seconds (u64 BE).
/// * Membership epoch (u64 BE) — I2; MUST be inside the pre-image so
///   the signature covers it (an unsigned epoch would be trivially
///   forgeable by any forwarding peer).
/// * Candidate count u32 BE for each of v4_host, v6_host,
///   v4_srflx, v6_srflx (4 lengths total).
/// * Candidates in canonical order: v4_host[..], v6_host[..],
///   v4_srflx[..], v6_srflx[..].
///   - hosts: 16 bytes (v4-mapped IPv6 for v4; native for v6) +
///     2 bytes port=0 padding.
///   - srflx: 16 bytes addr + 2 bytes port BE.
pub fn signing_preimage(
    source_node_id: &[u8; 32],
    sequence: u64,
    timestamp_unix: u64,
    epoch: u64,
    candidates: &CandidateSet,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        2 + GOSSIP_BUNDLE_DOMAIN.len()
            + 32
            + 8
            + 8
            + 8
            + 16
            + (candidates.v4_host.len()
                + candidates.v6_host.len()
                + candidates.v4_srflx.len()
                + candidates.v6_srflx.len())
                * 18,
    );
    out.extend_from_slice(&(GOSSIP_BUNDLE_DOMAIN.len() as u16).to_be_bytes());
    out.extend_from_slice(GOSSIP_BUNDLE_DOMAIN);
    out.extend_from_slice(source_node_id);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&timestamp_unix.to_be_bytes());
    out.extend_from_slice(&epoch.to_be_bytes());
    out.extend_from_slice(&(candidates.v4_host.len() as u32).to_be_bytes());
    out.extend_from_slice(&(candidates.v6_host.len() as u32).to_be_bytes());
    out.extend_from_slice(&(candidates.v4_srflx.len() as u32).to_be_bytes());
    out.extend_from_slice(&(candidates.v6_srflx.len() as u32).to_be_bytes());
    for ip in &candidates.v4_host {
        out.extend_from_slice(&ip_to_v6_octets(*ip));
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    for ip in &candidates.v6_host {
        out.extend_from_slice(&ip_to_v6_octets(*ip));
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    for sa in &candidates.v4_srflx {
        out.extend_from_slice(&ip_to_v6_octets(sa.ip()));
        out.extend_from_slice(&sa.port().to_be_bytes());
    }
    for sa in &candidates.v6_srflx {
        out.extend_from_slice(&ip_to_v6_octets(sa.ip()));
        out.extend_from_slice(&sa.port().to_be_bytes());
    }
    out
}

fn ip_to_v6_octets(ip: IpAddr) -> [u8; 16] {
    match ip {
        IpAddr::V6(v6) => v6.octets(),
        IpAddr::V4(v4) => {
            let mut out = [0u8; 16];
            out[10] = 0xff;
            out[11] = 0xff;
            out[12..16].copy_from_slice(&v4.octets());
            out
        }
    }
}

/// Mint a signed gossip bundle from local state. The caller supplies
/// the signing key (the WG-identity key, exposed via
/// `rustynet-crypto`), the next sequence number (caller is responsible
/// for monotonicity), the local VERIFIED membership epoch (I2 — must
/// come from a verified membership snapshot, never from the wire),
/// and the freshly-gathered [`CandidateSet`].
pub fn mint_bundle(
    signing_key: &SigningKey,
    sequence: u64,
    epoch: u64,
    candidates: CandidateSet,
) -> Result<GossipBundle, GossipError> {
    let timestamp_unix = current_unix_seconds()?;
    mint_bundle_with_timestamp(signing_key, sequence, timestamp_unix, epoch, candidates)
}

/// Test-friendly variant taking an explicit timestamp. Production
/// callers use [`mint_bundle`].
pub fn mint_bundle_with_timestamp(
    signing_key: &SigningKey,
    sequence: u64,
    timestamp_unix: u64,
    epoch: u64,
    candidates: CandidateSet,
) -> Result<GossipBundle, GossipError> {
    let candidate_count = candidates.v4_host.len()
        + candidates.v6_host.len()
        + candidates.v4_srflx.len()
        + candidates.v6_srflx.len();
    if candidate_count > MAX_CANDIDATES_PER_BUNDLE {
        return Err(GossipError::TooManyCandidates {
            presented: candidate_count,
            max: MAX_CANDIDATES_PER_BUNDLE,
        });
    }
    let source_node_id = signing_key.verifying_key().to_bytes();
    let preimage = signing_preimage(
        &source_node_id,
        sequence,
        timestamp_unix,
        epoch,
        &candidates,
    );
    let signature = signing_key.sign(&preimage);
    Ok(GossipBundle {
        source_node_id,
        sequence,
        timestamp_unix,
        epoch,
        candidates,
        signature,
    })
}

/// Verify a bundle against a known peer's verifying key. Does NOT
/// consult [`SeenSequenceState`] — call [`accept_bundle`] for the
/// full acceptance check (signature + freshness + monotonic
/// sequence).
pub fn verify_signature(
    bundle: &GossipBundle,
    verifying_key: &VerifyingKey,
) -> Result<(), GossipError> {
    let preimage = signing_preimage(
        &bundle.source_node_id,
        bundle.sequence,
        bundle.timestamp_unix,
        bundle.epoch,
        &bundle.candidates,
    );
    verifying_key
        .verify_strict(&preimage, &bundle.signature)
        .map_err(|_| GossipError::SignatureInvalid)
}

/// Full inbound acceptance check. Returns `Ok(())` if the bundle is
/// fresh, epoch-plausible, monotonic, and validly signed under a known
/// peer's key. Updates `state` to record the new highest sequence on
/// success.
///
/// `known_peers` is a map from node-id (the verifying key bytes) to
/// the verifying key itself; typically loaded from the signed
/// membership snapshot. `local_epoch` is the receiver's VERIFIED
/// membership epoch (I2) — the reference point for the epoch-skew
/// window; it must come from a verified snapshot, never from the wire.
#[allow(clippy::too_many_arguments)]
pub fn accept_bundle(
    bundle: &GossipBundle,
    known_peers: &HashMap<[u8; 32], VerifyingKey>,
    state: &mut SeenSequenceState,
    freshness_window_secs: u64,
    local_epoch: u64,
) -> Result<(), GossipError> {
    let now = current_unix_seconds()?;
    accept_bundle_with_now(
        bundle,
        known_peers,
        state,
        freshness_window_secs,
        local_epoch,
        now,
    )
}

/// Reject a gossip bundle whose candidate set includes any address
/// the receiver should not even attempt to connect to. The signature
/// check above proves the candidates came from the claimed peer, but
/// a compromised peer (or an honest peer with a broken candidate
/// gatherer) shouldn't be able to redirect our connect-attempt
/// traffic to localhost services, multicast groups, or other
/// non-public destinations.
///
/// Accepted scopes: Global and Private (RFC 1918 / RFC 4193 ULA).
/// Rejected scopes: Loopback, LinkLocal, Multicast, Broadcast,
/// Unspecified, and the IPv6 documentation prefix (folded into
/// Unspecified by `classify_ipv6`).
fn reject_unreachable_candidates(candidates: &CandidateSet) -> Result<(), GossipError> {
    use crate::dataplane_candidates::{AddressScope, classify_ip};
    let all_addrs = candidates
        .v4_host
        .iter()
        .chain(candidates.v6_host.iter())
        .copied()
        .chain(candidates.v4_srflx.iter().map(std::net::SocketAddr::ip))
        .chain(candidates.v6_srflx.iter().map(std::net::SocketAddr::ip));
    for ip in all_addrs {
        match classify_ip(ip) {
            AddressScope::Global | AddressScope::Private => {}
            scope => {
                return Err(GossipError::UnreachableCandidate {
                    addr: format!("{ip} (scope: {scope:?})"),
                });
            }
        }
    }
    Ok(())
}

/// Test-friendly variant taking an explicit "now". Production
/// callers use [`accept_bundle`].
pub fn accept_bundle_with_now(
    bundle: &GossipBundle,
    known_peers: &HashMap<[u8; 32], VerifyingKey>,
    state: &mut SeenSequenceState,
    freshness_window_secs: u64,
    local_epoch: u64,
    now_unix: u64,
) -> Result<(), GossipError> {
    let candidate_count = bundle.candidates.v4_host.len()
        + bundle.candidates.v6_host.len()
        + bundle.candidates.v4_srflx.len()
        + bundle.candidates.v6_srflx.len();
    if candidate_count > MAX_CANDIDATES_PER_BUNDLE {
        return Err(GossipError::TooManyCandidates {
            presented: candidate_count,
            max: MAX_CANDIDATES_PER_BUNDLE,
        });
    }
    let verifying_key = known_peers
        .get(&bundle.source_node_id)
        .ok_or(GossipError::UnknownSource)?;
    verify_signature(bundle, verifying_key)?;
    // Defense-in-depth: every candidate IP must be a scope we'd
    // willingly connect to. A malicious peer cannot bypass this
    // because the signature is verified above — but if a peer is
    // compromised, the gossip is constrained to advertising
    // public-style addresses. Specifically: reject loopback,
    // link-local, multicast, broadcast, unspecified, and the IPv6
    // documentation prefix. Private (RFC 1918 / RFC 4193 ULA) is
    // allowed because same-LAN peer reachability is a legitimate
    // case.
    reject_unreachable_candidates(&bundle.candidates)?;
    let drift = bundle.timestamp_unix as i128 - now_unix as i128;
    if drift.unsigned_abs() > freshness_window_secs as u128 {
        // Saturating-cast i128 → i64 so a pathological skew (timestamp
        // close to u64::MAX) reports a clamped sentinel rather than a
        // wrapped negative value. Cosmetic — the rejection itself is
        // correct either way.
        let drift_secs = drift.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        return Err(GossipError::TimestampOutsideWindow { drift_secs });
    }
    // I2 — membership-epoch skew window. Runs AFTER signature
    // verification (the epoch is a signed field; an unverified bundle
    // never reaches policy) and BEFORE the monotonic-sequence record
    // (a rejected epoch must not advance the per-source anti-replay
    // watermark).
    //
    // Exact semantics — accept iff
    //   local_epoch - GOSSIP_EPOCH_SKEW_WINDOW
    //     <= bundle.epoch
    //     <= local_epoch + GOSSIP_EPOCH_FUTURE_TOLERANCE
    // (both bounds inclusive, saturating at 0 / u64::MAX):
    //
    // * behind by more than the window (e.g. local 10, presented 7
    //   with window 2) → REJECT: the minter's trust view is a
    //   membership timeline the mesh has moved past. This is the arm
    //   that ages out a revoked peer's self-signed bundles — a revoked
    //   peer stops receiving membership updates, so the newest epoch
    //   it truthfully saw freezes while the mesh advances.
    // * equal, or behind within the window → ACCEPT: benign membership
    //   updates (joins, capability changes) bump the epoch mesh-wide by
    //   1 each, and bundle re-mints lag by up to the 30 s heartbeat, so
    //   a small skew is normal operation, not an attack (rejecting it
    //   would be a mesh-wide churn cliff on every membership change).
    // * ahead within the tolerance → ACCEPT: the minter verified a
    //   newer membership snapshot before we did; we are the laggard.
    // * ahead by more than the tolerance → REJECT as implausible:
    //   epochs advance by exactly 1 per verified membership update, so
    //   no honest propagation gap explains a wildly-future stamp, and
    //   unbounded forward acceptance would let a still-keyed attacker
    //   pre-stamp far-future epochs to outlive the behind-window.
    //
    // The saturating bounds mean: at local epochs <= the window the
    // floor is 0 (nothing spuriously rejected at genesis), and within
    // GOSSIP_EPOCH_FUTURE_TOLERANCE of u64::MAX the ceiling pins at
    // MAX (unreachable in practice; +1 per membership update).
    let epoch_floor = local_epoch.saturating_sub(GOSSIP_EPOCH_SKEW_WINDOW);
    let epoch_ceiling = local_epoch.saturating_add(GOSSIP_EPOCH_FUTURE_TOLERANCE);
    if bundle.epoch < epoch_floor || bundle.epoch > epoch_ceiling {
        return Err(GossipError::EpochOutsideWindow {
            local_epoch,
            presented_epoch: bundle.epoch,
        });
    }
    if let Some(last) = state.highest_accepted(&bundle.source_node_id)
        && bundle.sequence <= last
    {
        return Err(GossipError::SequenceNotMonotonic {
            last_seen: last,
            presented: bundle.sequence,
        });
    }
    state.record(bundle.source_node_id, bundle.sequence);
    Ok(())
}

/// Serialise a [`GossipBundle`] into a fixed-layout wire form. The
/// version byte at offset 0 is [`GOSSIP_BUNDLE_WIRE_VERSION`]; an
/// unknown version causes [`deserialise_bundle`] to reject hard
/// (no silent downgrade).
///
/// Layout (big-endian numbers):
///
/// * `[0]` — version byte (=2)
/// * `[1..33]` — source node id (32 bytes)
/// * `[33..41]` — sequence (u64)
/// * `[41..49]` — timestamp unix seconds (u64)
/// * `[49..57]` — membership epoch (u64) — I2
/// * `[57..61]` — v4_host count (u32)
/// * `[61..65]` — v6_host count (u32)
/// * `[65..69]` — v4_srflx count (u32)
/// * `[69..73]` — v6_srflx count (u32)
/// * `[73..]` — candidate slots, 18 bytes each: 16-byte v6-mapped
///   octets + 2-byte port (BE). For host slots the port field is
///   always zero; for srflx slots it carries the observed port.
/// * `[end-64..end]` — 64-byte Ed25519 signature (separated from the
///   signing pre-image: the pre-image uses the canonical form defined
///   in [`signing_preimage`], the wire trailer is the raw signature).
///
/// Pre-condition: the bundle's total candidate count must already
/// satisfy [`MAX_CANDIDATES_PER_BUNDLE`]; bundles that violate it
/// cannot have been produced by [`mint_bundle`] and the deserialiser
/// rejects them on read.
pub fn serialise_bundle(bundle: &GossipBundle) -> Vec<u8> {
    let count = bundle.candidates.v4_host.len()
        + bundle.candidates.v6_host.len()
        + bundle.candidates.v4_srflx.len()
        + bundle.candidates.v6_srflx.len();
    let mut out = Vec::with_capacity(
        WIRE_CANDIDATES_OFFSET + count * WIRE_CANDIDATE_STRIDE + WIRE_SIGNATURE_LEN,
    );
    out.push(GOSSIP_BUNDLE_WIRE_VERSION);
    out.extend_from_slice(&bundle.source_node_id);
    out.extend_from_slice(&bundle.sequence.to_be_bytes());
    out.extend_from_slice(&bundle.timestamp_unix.to_be_bytes());
    out.extend_from_slice(&bundle.epoch.to_be_bytes());
    out.extend_from_slice(&(bundle.candidates.v4_host.len() as u32).to_be_bytes());
    out.extend_from_slice(&(bundle.candidates.v6_host.len() as u32).to_be_bytes());
    out.extend_from_slice(&(bundle.candidates.v4_srflx.len() as u32).to_be_bytes());
    out.extend_from_slice(&(bundle.candidates.v6_srflx.len() as u32).to_be_bytes());
    for ip in &bundle.candidates.v4_host {
        out.extend_from_slice(&ip_to_v6_octets(*ip));
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    for ip in &bundle.candidates.v6_host {
        out.extend_from_slice(&ip_to_v6_octets(*ip));
        out.extend_from_slice(&0u16.to_be_bytes());
    }
    for sa in &bundle.candidates.v4_srflx {
        out.extend_from_slice(&ip_to_v6_octets(sa.ip()));
        out.extend_from_slice(&sa.port().to_be_bytes());
    }
    for sa in &bundle.candidates.v6_srflx {
        out.extend_from_slice(&ip_to_v6_octets(sa.ip()));
        out.extend_from_slice(&sa.port().to_be_bytes());
    }
    out.extend_from_slice(&bundle.signature.to_bytes());
    out
}

/// Inverse of [`serialise_bundle`]. Strictly version-gated, length-
/// checked, and family-checked. Does NOT verify the signature or the
/// freshness window — that is [`accept_bundle`]'s job. Returns one of
/// the `Wire*` `GossipError` variants on malformed input.
pub fn deserialise_bundle(bytes: &[u8]) -> Result<GossipBundle, GossipError> {
    if bytes.len() > MAX_GOSSIP_DATAGRAM_BYTES {
        return Err(GossipError::WireMalformed(
            "datagram exceeds MAX_GOSSIP_DATAGRAM_BYTES",
        ));
    }
    if bytes.len() < WIRE_CANDIDATES_OFFSET + WIRE_SIGNATURE_LEN {
        return Err(GossipError::WireTruncated {
            needed: WIRE_CANDIDATES_OFFSET + WIRE_SIGNATURE_LEN,
            available: bytes.len(),
        });
    }
    let presented_version = bytes[WIRE_VERSION_OFFSET];
    if presented_version != GOSSIP_BUNDLE_WIRE_VERSION {
        return Err(GossipError::WireVersionMismatch {
            expected: GOSSIP_BUNDLE_WIRE_VERSION,
            presented: presented_version,
        });
    }
    let mut source_node_id = [0u8; 32];
    source_node_id.copy_from_slice(&bytes[WIRE_SOURCE_OFFSET..WIRE_SOURCE_OFFSET + 32]);
    let sequence = u64::from_be_bytes(
        bytes[WIRE_SEQUENCE_OFFSET..WIRE_SEQUENCE_OFFSET + 8]
            .try_into()
            .expect("slice length is 8"),
    );
    let timestamp_unix = u64::from_be_bytes(
        bytes[WIRE_TIMESTAMP_OFFSET..WIRE_TIMESTAMP_OFFSET + 8]
            .try_into()
            .expect("slice length is 8"),
    );
    let epoch = u64::from_be_bytes(
        bytes[WIRE_EPOCH_OFFSET..WIRE_EPOCH_OFFSET + 8]
            .try_into()
            .expect("slice length is 8"),
    );
    let v4_host_count = u32::from_be_bytes(
        bytes[WIRE_COUNTS_OFFSET..WIRE_COUNTS_OFFSET + 4]
            .try_into()
            .expect("slice length is 4"),
    ) as usize;
    let v6_host_count = u32::from_be_bytes(
        bytes[WIRE_COUNTS_OFFSET + 4..WIRE_COUNTS_OFFSET + 8]
            .try_into()
            .expect("slice length is 4"),
    ) as usize;
    let v4_srflx_count = u32::from_be_bytes(
        bytes[WIRE_COUNTS_OFFSET + 8..WIRE_COUNTS_OFFSET + 12]
            .try_into()
            .expect("slice length is 4"),
    ) as usize;
    let v6_srflx_count = u32::from_be_bytes(
        bytes[WIRE_COUNTS_OFFSET + 12..WIRE_COUNTS_OFFSET + 16]
            .try_into()
            .expect("slice length is 4"),
    ) as usize;
    let total_count = v4_host_count
        .checked_add(v6_host_count)
        .and_then(|s| s.checked_add(v4_srflx_count))
        .and_then(|s| s.checked_add(v6_srflx_count))
        .ok_or(GossipError::WireMalformed("candidate count overflow"))?;
    if total_count > MAX_CANDIDATES_PER_BUNDLE {
        return Err(GossipError::TooManyCandidates {
            presented: total_count,
            max: MAX_CANDIDATES_PER_BUNDLE,
        });
    }
    let body_end = WIRE_CANDIDATES_OFFSET
        .checked_add(
            total_count
                .checked_mul(WIRE_CANDIDATE_STRIDE)
                .ok_or(GossipError::WireMalformed("candidate length overflow"))?,
        )
        .ok_or(GossipError::WireMalformed("candidate offset overflow"))?;
    let needed = body_end
        .checked_add(WIRE_SIGNATURE_LEN)
        .ok_or(GossipError::WireMalformed("wire size overflow"))?;
    if bytes.len() != needed {
        return Err(GossipError::WireTruncated {
            needed,
            available: bytes.len(),
        });
    }
    let mut cursor = WIRE_CANDIDATES_OFFSET;
    let mut v4_host = Vec::with_capacity(v4_host_count);
    for _ in 0..v4_host_count {
        let ip = read_v4_lane_octets(&bytes[cursor..cursor + 16])?;
        v4_host.push(IpAddr::V4(ip));
        cursor += WIRE_CANDIDATE_STRIDE;
    }
    let mut v6_host = Vec::with_capacity(v6_host_count);
    for _ in 0..v6_host_count {
        let ip = read_v6_lane_octets(&bytes[cursor..cursor + 16])?;
        v6_host.push(IpAddr::V6(ip));
        cursor += WIRE_CANDIDATE_STRIDE;
    }
    let mut v4_srflx = Vec::with_capacity(v4_srflx_count);
    for _ in 0..v4_srflx_count {
        let ip = read_v4_lane_octets(&bytes[cursor..cursor + 16])?;
        let port = u16::from_be_bytes([bytes[cursor + 16], bytes[cursor + 17]]);
        v4_srflx.push(SocketAddr::new(IpAddr::V4(ip), port));
        cursor += WIRE_CANDIDATE_STRIDE;
    }
    let mut v6_srflx = Vec::with_capacity(v6_srflx_count);
    for _ in 0..v6_srflx_count {
        let ip = read_v6_lane_octets(&bytes[cursor..cursor + 16])?;
        let port = u16::from_be_bytes([bytes[cursor + 16], bytes[cursor + 17]]);
        v6_srflx.push(SocketAddr::new(IpAddr::V6(ip), port));
        cursor += WIRE_CANDIDATE_STRIDE;
    }
    let mut signature_bytes = [0u8; WIRE_SIGNATURE_LEN];
    signature_bytes.copy_from_slice(&bytes[body_end..body_end + WIRE_SIGNATURE_LEN]);
    let signature = Signature::from_bytes(&signature_bytes);
    Ok(GossipBundle {
        source_node_id,
        sequence,
        timestamp_unix,
        epoch,
        candidates: CandidateSet {
            v4_host,
            v6_host,
            v4_srflx,
            v6_srflx,
        },
        signature,
    })
}

/// Read a v4 lane's 16-byte octets and reconstruct the embedded
/// [`Ipv4Addr`]. Rejects octets that aren't in the v4-mapped IPv6
/// prefix shape (`::ffff:X.X.X.X`) so a malformed wire can't sneak an
/// arbitrary v6 address into a v4 lane.
fn read_v4_lane_octets(octets: &[u8]) -> Result<Ipv4Addr, GossipError> {
    if octets.len() != 16 {
        return Err(GossipError::WireMalformed("v4 lane octets wrong length"));
    }
    if octets[0..10] != [0u8; 10] || octets[10] != 0xff || octets[11] != 0xff {
        return Err(GossipError::WireMalformed(
            "v4 lane is not v4-mapped IPv6 prefix",
        ));
    }
    Ok(Ipv4Addr::new(
        octets[12], octets[13], octets[14], octets[15],
    ))
}

/// Read a v6 lane's 16-byte octets and return an [`Ipv6Addr`].
/// Rejects octets that happen to be in the v4-mapped prefix form
/// (`::ffff:X.X.X.X`) so a malformed wire can't sneak a v4 address
/// into a v6 lane.
fn read_v6_lane_octets(octets: &[u8]) -> Result<Ipv6Addr, GossipError> {
    if octets.len() != 16 {
        return Err(GossipError::WireMalformed("v6 lane octets wrong length"));
    }
    if octets[0..10] == [0u8; 10] && octets[10] == 0xff && octets[11] == 0xff {
        return Err(GossipError::WireMalformed(
            "v6 lane carries v4-mapped IPv6 prefix",
        ));
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(octets);
    Ok(Ipv6Addr::from(buf))
}

/// Pure helper: extract every endpoint (host + srflx, v4 + v6) from a
/// bundle as a flat `Vec<SocketAddr>`. Host candidates use port 0
/// because the bundle doesn't carry per-host ports — the connect path
/// pairs them with the well-known WG listen port when establishing
/// a session.
pub fn flatten_endpoints(bundle: &GossipBundle) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for ip in &bundle.candidates.v4_host {
        out.push(SocketAddr::new(*ip, 0));
    }
    for ip in &bundle.candidates.v6_host {
        out.push(SocketAddr::new(*ip, 0));
    }
    out.extend(bundle.candidates.v4_srflx.iter().copied());
    out.extend(bundle.candidates.v6_srflx.iter().copied());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::net::Ipv4Addr;
    use std::net::Ipv6Addr;

    /// Membership epoch stamped into test bundles. Arbitrary but fixed;
    /// the epoch-window tests derive their local/presented epochs from it
    /// so boundary assertions stay readable.
    const TEST_EPOCH: u64 = 7;

    fn deterministic_signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn sample_candidates() -> CandidateSet {
        CandidateSet {
            v4_host: vec![IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))],
            v6_host: vec![IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))],
            v4_srflx: vec![SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5)),
                51820,
            )],
            v6_srflx: vec![SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 1)),
                51820,
            )],
        }
    }

    #[test]
    fn signing_preimage_is_deterministic_for_same_inputs() {
        let candidates = sample_candidates();
        let source = [7u8; 32];
        let p1 = signing_preimage(&source, 42, 1_700_000_000, TEST_EPOCH, &candidates);
        let p2 = signing_preimage(&source, 42, 1_700_000_000, TEST_EPOCH, &candidates);
        assert_eq!(p1, p2, "pre-image must be deterministic");
    }

    #[test]
    fn signing_preimage_carries_domain_separation_prefix() {
        let candidates = sample_candidates();
        let source = [7u8; 32];
        let preimage = signing_preimage(&source, 0, 0, TEST_EPOCH, &candidates);
        // Length-prefixed domain prefix.
        assert_eq!(
            u16::from_be_bytes([preimage[0], preimage[1]]),
            GOSSIP_BUNDLE_DOMAIN.len() as u16
        );
        assert_eq!(
            &preimage[2..2 + GOSSIP_BUNDLE_DOMAIN.len()],
            GOSSIP_BUNDLE_DOMAIN
        );
    }

    #[test]
    fn signing_preimage_binds_the_epoch() {
        // I2: two pre-images identical except for the epoch must
        // differ — the epoch is covered by the signature. An unsigned
        // epoch would be trivially rewritable by any forwarding peer.
        let candidates = sample_candidates();
        let source = [7u8; 32];
        let p1 = signing_preimage(&source, 42, 1_700_000_000, TEST_EPOCH, &candidates);
        let p2 = signing_preimage(&source, 42, 1_700_000_000, TEST_EPOCH + 1, &candidates);
        assert_ne!(p1, p2, "epoch must be part of the signed pre-image");
    }

    #[test]
    fn verify_signature_rejects_tampered_epoch() {
        // I2: flipping the epoch after signing must fail signature
        // verification — the epoch-window accept rule is meaningless
        // if a man-in-the-epidemic can restamp the epoch.
        let signing_key = deterministic_signing_key(40);
        let verifying_key = signing_key.verifying_key();
        let mut bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        bundle.epoch = bundle.epoch.wrapping_add(1);
        let err = verify_signature(&bundle, &verifying_key)
            .expect_err("tampered epoch must invalidate the signature");
        assert!(matches!(err, GossipError::SignatureInvalid));
    }

    #[test]
    fn mint_and_verify_round_trip_against_known_peer_key() {
        let signing_key = deterministic_signing_key(1);
        let verifying_key = signing_key.verifying_key();
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        verify_signature(&bundle, &verifying_key).expect("signature verifies under signer's key");
    }

    #[test]
    fn verify_signature_fails_under_wrong_key() {
        let signing_key = deterministic_signing_key(2);
        let other = deterministic_signing_key(3);
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        let err = verify_signature(&bundle, &other.verifying_key())
            .expect_err("must reject under wrong verifying key");
        assert!(matches!(err, GossipError::SignatureInvalid));
    }

    #[test]
    fn accept_bundle_records_sequence_and_advances_monotonically() {
        let signing_key = deterministic_signing_key(4);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let bundle1 = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&bundle1, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
            .expect("ok");
        assert_eq!(state.highest_accepted(&verifying_key.to_bytes()), Some(1));

        let bundle2 = mint_bundle_with_timestamp(
            &signing_key,
            2,
            1_700_000_100,
            TEST_EPOCH,
            CandidateSet::default(),
        )
        .unwrap();
        accept_bundle_with_now(&bundle2, &known, &mut state, 300, TEST_EPOCH, 1_700_000_100)
            .expect("strictly larger sequence accepted");
        assert_eq!(state.highest_accepted(&verifying_key.to_bytes()), Some(2));
    }

    #[test]
    fn accept_bundle_rejects_sequence_wraparound_at_u64_max() {
        // Anti-replay must hold at the integer boundary: once u64::MAX is
        // accepted, an attacker cannot "wrap" the per-source counter back to 0
        // or 1 to replay — every later sequence is <= the high-water mark and
        // is rejected as non-monotonic.
        let signing_key = deterministic_signing_key(9);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let max_bundle = mint_bundle_with_timestamp(
            &signing_key,
            u64::MAX,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(
            &max_bundle,
            &known,
            &mut state,
            300,
            TEST_EPOCH,
            1_700_000_000,
        )
        .expect("u64::MAX sequence accepted once");
        assert_eq!(
            state.highest_accepted(&verifying_key.to_bytes()),
            Some(u64::MAX)
        );

        for wrapped in [0u64, 1u64] {
            let bundle = mint_bundle_with_timestamp(
                &signing_key,
                wrapped,
                1_700_000_050,
                TEST_EPOCH,
                CandidateSet::default(),
            )
            .unwrap();
            let err =
                accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_050)
                    .expect_err("post-MAX wraparound must be rejected");
            assert!(
                matches!(
                    err,
                    GossipError::SequenceNotMonotonic { last_seen, presented }
                        if last_seen == u64::MAX && presented == wrapped
                ),
                "expected SequenceNotMonotonic for {wrapped}, got {err:?}"
            );
        }
        // The high-water mark is unchanged by the rejected wraparound attempts.
        assert_eq!(
            state.highest_accepted(&verifying_key.to_bytes()),
            Some(u64::MAX)
        );
    }

    #[test]
    fn accept_bundle_rejects_replay_of_same_sequence() {
        let signing_key = deterministic_signing_key(5);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            7,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
            .expect("ok");
        // Same bundle replayed must be rejected.
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("replay must be rejected");
        match err {
            GossipError::SequenceNotMonotonic {
                last_seen,
                presented,
            } => {
                assert_eq!(last_seen, 7);
                assert_eq!(presented, 7);
            }
            other => panic!("expected SequenceNotMonotonic, got {other:?}"),
        }
    }

    #[test]
    fn accept_bundle_rejects_lower_sequence_after_higher_seen() {
        let signing_key = deterministic_signing_key(6);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let high = mint_bundle_with_timestamp(
            &signing_key,
            100,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&high, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
            .expect("ok");
        let low = mint_bundle_with_timestamp(
            &signing_key,
            50,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        let err = accept_bundle_with_now(&low, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
            .expect_err("rewind must be rejected");
        assert!(matches!(err, GossipError::SequenceNotMonotonic { .. }));
    }

    #[test]
    fn accept_bundle_rejects_timestamp_too_far_in_the_past() {
        let signing_key = deterministic_signing_key(7);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        // 1000s in the past, window is 300s.
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_001_000)
                .expect_err("stale timestamp must be rejected");
        match err {
            GossipError::TimestampOutsideWindow { drift_secs } => {
                assert_eq!(drift_secs, -1000);
            }
            other => panic!("expected TimestampOutsideWindow, got {other:?}"),
        }
    }

    #[test]
    fn accept_bundle_rejects_timestamp_too_far_in_the_future() {
        let signing_key = deterministic_signing_key(8);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        // 1000s in the future, window is 300s.
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_001_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("future timestamp must be rejected");
        match err {
            GossipError::TimestampOutsideWindow { drift_secs } => {
                assert_eq!(drift_secs, 1000);
            }
            other => panic!("expected TimestampOutsideWindow, got {other:?}"),
        }
    }

    #[test]
    fn accept_bundle_epoch_window_boundaries_behind_and_ahead() {
        // I2 exact-boundary matrix around local epoch L with
        // GOSSIP_EPOCH_SKEW_WINDOW = 2 (behind, inclusive) and
        // GOSSIP_EPOCH_FUTURE_TOLERANCE = 2 (ahead, inclusive):
        //   L-3 reject | L-2 .. L+2 accept | L+3 reject.
        let signing_key = deterministic_signing_key(50);
        let verifying_key = signing_key.verifying_key();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);
        let local = TEST_EPOCH + 10; // comfortably away from the 0 floor
        let cases = [
            (local - GOSSIP_EPOCH_SKEW_WINDOW - 1, false),
            (local - GOSSIP_EPOCH_SKEW_WINDOW, true),
            (local - 1, true),
            (local, true),
            (local + 1, true),
            (local + GOSSIP_EPOCH_FUTURE_TOLERANCE, true),
            (local + GOSSIP_EPOCH_FUTURE_TOLERANCE + 1, false),
        ];
        for (presented, expect_ok) in cases {
            // Fresh sequence state per case so the anti-replay check
            // never interferes with the epoch assertion.
            let mut state = SeenSequenceState::new();
            let bundle = mint_bundle_with_timestamp(
                &signing_key,
                1,
                1_700_000_000,
                presented,
                sample_candidates(),
            )
            .expect("mint succeeds");
            let res =
                accept_bundle_with_now(&bundle, &known, &mut state, 300, local, 1_700_000_000);
            if expect_ok {
                res.unwrap_or_else(|err| {
                    panic!("epoch {presented} (local {local}) must be accepted, got {err:?}")
                });
            } else {
                match res.expect_err("epoch outside window must be rejected") {
                    GossipError::EpochOutsideWindow {
                        local_epoch,
                        presented_epoch,
                    } => {
                        assert_eq!(local_epoch, local);
                        assert_eq!(presented_epoch, presented);
                    }
                    other => panic!("expected EpochOutsideWindow, got {other:?}"),
                }
            }
        }
    }

    #[test]
    fn accept_bundle_epoch_floor_saturates_at_genesis() {
        // Local epoch 1 with window 2: the behind-floor saturates to 0,
        // so epoch-0 and epoch-1 bundles are accepted (no spurious
        // rejects at genesis) while the ahead-ceiling (1 + 2 = 3) still
        // rejects epoch 4.
        let signing_key = deterministic_signing_key(51);
        let verifying_key = signing_key.verifying_key();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);
        for (presented, expect_ok) in [(0u64, true), (1, true), (3, true), (4, false)] {
            let mut state = SeenSequenceState::new();
            let bundle = mint_bundle_with_timestamp(
                &signing_key,
                1,
                1_700_000_000,
                presented,
                sample_candidates(),
            )
            .expect("mint succeeds");
            let res = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1, 1_700_000_000);
            assert_eq!(
                res.is_ok(),
                expect_ok,
                "presented epoch {presented} against local 1: got {res:?}"
            );
        }
    }

    #[test]
    fn rejected_epoch_does_not_advance_sequence_watermark() {
        // An epoch-window rejection must leave the per-source
        // anti-replay ledger untouched: the same sequence number must
        // still be acceptable later from a bundle whose epoch is valid
        // (otherwise an attacker could burn a victim's sequence space
        // with out-of-window bundles).
        let signing_key = deterministic_signing_key(52);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);
        let local = TEST_EPOCH + 10;

        let stale = mint_bundle_with_timestamp(
            &signing_key,
            5,
            1_700_000_000,
            local - GOSSIP_EPOCH_SKEW_WINDOW - 1,
            sample_candidates(),
        )
        .expect("mint stale-epoch bundle");
        let err = accept_bundle_with_now(&stale, &known, &mut state, 300, local, 1_700_000_000)
            .expect_err("stale epoch must be rejected");
        assert!(matches!(err, GossipError::EpochOutsideWindow { .. }));
        assert_eq!(
            state.highest_accepted(&verifying_key.to_bytes()),
            None,
            "epoch rejection must not record the sequence"
        );

        let fresh =
            mint_bundle_with_timestamp(&signing_key, 5, 1_700_000_000, local, sample_candidates())
                .expect("mint valid-epoch bundle");
        accept_bundle_with_now(&fresh, &known, &mut state, 300, local, 1_700_000_000)
            .expect("same sequence must still be acceptable with a valid epoch");
        assert_eq!(
            state.highest_accepted(&verifying_key.to_bytes()),
            Some(5),
            "valid bundle records the sequence normally"
        );
    }

    #[test]
    fn accept_bundle_rejects_unknown_source() {
        let signing_key = deterministic_signing_key(9);
        let mut state = SeenSequenceState::new();
        let known: HashMap<[u8; 32], VerifyingKey> = HashMap::new();
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("unknown source must be rejected");
        assert!(matches!(err, GossipError::UnknownSource));
    }

    #[test]
    fn accept_bundle_rejects_tampered_candidates() {
        // Modify the candidates after signing — the signature won't
        // verify against the modified pre-image.
        let signing_key = deterministic_signing_key(10);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let mut bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        // Tamper: inject an attacker-controlled endpoint.
        bundle.candidates.v4_srflx.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            51820,
        ));
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("tampered candidates must trip signature mismatch");
        assert!(matches!(err, GossipError::SignatureInvalid));
    }

    #[test]
    fn mint_bundle_rejects_too_many_candidates() {
        let signing_key = deterministic_signing_key(11);
        let mut candidates = CandidateSet::default();
        for i in 0..(MAX_CANDIDATES_PER_BUNDLE as u32 + 1) {
            candidates.v4_host.push(IpAddr::V4(Ipv4Addr::from(i)));
        }
        let err =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, TEST_EPOCH, candidates)
                .expect_err("too many candidates");
        match err {
            GossipError::TooManyCandidates { presented, max } => {
                assert_eq!(presented, MAX_CANDIDATES_PER_BUNDLE + 1);
                assert_eq!(max, MAX_CANDIDATES_PER_BUNDLE);
            }
            other => panic!("expected TooManyCandidates, got {other:?}"),
        }
    }

    #[test]
    fn flatten_endpoints_returns_all_kinds_in_canonical_order() {
        let signing_key = deterministic_signing_key(12);
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        let flat = flatten_endpoints(&bundle);
        assert_eq!(flat.len(), 4);
        // v4_host first
        assert_eq!(flat[0].ip(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(flat[0].port(), 0);
        // v6_host
        assert!(matches!(flat[1].ip(), IpAddr::V6(_)));
        // v4_srflx
        assert_eq!(flat[2].port(), 51820);
        // v6_srflx
        assert!(matches!(flat[3].ip(), IpAddr::V6(_)));
    }

    #[test]
    fn seen_sequence_state_keeps_maximum_under_out_of_order_record() {
        let mut state = SeenSequenceState::new();
        let key = [42u8; 32];
        state.record(key, 5);
        state.record(key, 3);
        state.record(key, 7);
        state.record(key, 2);
        assert_eq!(state.highest_accepted(&key), Some(7));
        assert_eq!(state.source_count(), 1);
    }

    #[test]
    fn accept_bundle_rejects_loopback_candidate() {
        // Security pin: a malicious peer (or one whose candidate
        // gatherer is buggy) could gossip 127.0.0.1:51820 as a
        // reachable endpoint. Accepting it would redirect our
        // connect-attempt traffic to localhost. Reject.
        let signing_key = deterministic_signing_key(20);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let mut candidates = CandidateSet::default();
        candidates.v4_srflx.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            51820,
        ));
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, TEST_EPOCH, candidates)
                .unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("loopback srflx must be rejected");
        match err {
            GossipError::UnreachableCandidate { addr } => {
                assert!(
                    addr.contains("127.0.0.1"),
                    "error should name the offending address; got: {addr}"
                );
            }
            other => panic!("expected UnreachableCandidate, got: {other:?}"),
        }
    }

    #[test]
    fn accept_bundle_rejects_link_local_and_multicast_candidates() {
        let signing_key = deterministic_signing_key(21);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        // Multicast srflx: an attacker advertising 224.0.0.1 could
        // weaponise our connect-attempt traffic into a multicast
        // flood. Reject.
        let mut multi = CandidateSet::default();
        multi.v4_srflx.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            5353,
        ));
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, TEST_EPOCH, multi).unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("multicast must be rejected");
        assert!(matches!(err, GossipError::UnreachableCandidate { .. }));

        // Link-local v4 host candidate (169.254/16) — useless to a
        // remote peer and could leak interface naming.
        let mut ll = CandidateSet::default();
        ll.v4_host.push(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)));
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 2, 1_700_000_000, TEST_EPOCH, ll).unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("link-local must be rejected");
        assert!(matches!(err, GossipError::UnreachableCandidate { .. }));

        // Link-local v6 (fe80::/10) too.
        let mut ll6 = CandidateSet::default();
        ll6.v6_host
            .push(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 3, 1_700_000_000, TEST_EPOCH, ll6).unwrap();
        let err =
            accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
                .expect_err("v6 link-local must be rejected");
        assert!(matches!(err, GossipError::UnreachableCandidate { .. }));
    }

    #[test]
    fn accept_bundle_allows_private_and_global_candidates() {
        // The complement of the rejection tests: legitimate Private
        // (RFC 1918 / RFC 4193 ULA) and Global candidates must be
        // accepted. Same-LAN peer reachability is a legitimate case.
        let signing_key = deterministic_signing_key(22);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&bundle, &known, &mut state, 300, TEST_EPOCH, 1_700_000_000)
            .expect("sample (private + global) candidates accepted");
    }

    #[test]
    fn boundary_timestamps_at_exact_window_edge_are_accepted() {
        // A bundle exactly `freshness_window_secs` away (either
        // direction) is on the boundary; the implementation uses
        // strict `> window`, so equality is accepted.
        let signing_key = deterministic_signing_key(13);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let past = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&past, &known, &mut state, 300, TEST_EPOCH, 1_700_000_300)
            .expect("boundary past timestamp accepted");

        let future = mint_bundle_with_timestamp(
            &signing_key,
            2,
            1_700_000_600,
            TEST_EPOCH,
            sample_candidates(),
        )
        .unwrap();
        accept_bundle_with_now(&future, &known, &mut state, 300, TEST_EPOCH, 1_700_000_300)
            .expect("boundary future timestamp accepted");
    }

    #[test]
    fn serialise_then_deserialise_round_trips_round_trips_a_random_bundle() {
        // Round-trip pin: every signed field must survive
        // serialise/deserialise unchanged, and the signature trailer
        // must survive byte-for-byte (so verify_signature still
        // succeeds after the round trip).
        let signing_key = deterministic_signing_key(30);
        let verifying_key = signing_key.verifying_key();
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            42,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        let wire = serialise_bundle(&bundle);
        assert_eq!(
            wire[WIRE_VERSION_OFFSET], GOSSIP_BUNDLE_WIRE_VERSION,
            "wire version byte must be at offset 0"
        );
        let decoded = deserialise_bundle(&wire).expect("deserialise succeeds");
        assert_eq!(decoded.source_node_id, bundle.source_node_id);
        assert_eq!(decoded.sequence, bundle.sequence);
        assert_eq!(decoded.timestamp_unix, bundle.timestamp_unix);
        assert_eq!(decoded.epoch, bundle.epoch, "I2: epoch survives the wire");
        assert_eq!(decoded.candidates, bundle.candidates);
        assert_eq!(decoded.signature.to_bytes(), bundle.signature.to_bytes());
        // Defense-in-depth: a round-tripped bundle must still pass
        // signature verification under the originator's key.
        verify_signature(&decoded, &verifying_key)
            .expect("signature must verify after wire round-trip");
    }

    #[test]
    fn deserialise_rejects_wrong_version_byte() {
        let signing_key = deterministic_signing_key(31);
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        let mut wire = serialise_bundle(&bundle);
        wire[WIRE_VERSION_OFFSET] = GOSSIP_BUNDLE_WIRE_VERSION.wrapping_add(1);
        let err = deserialise_bundle(&wire).expect_err("must reject unknown version");
        match err {
            GossipError::WireVersionMismatch {
                expected,
                presented,
            } => {
                assert_eq!(expected, GOSSIP_BUNDLE_WIRE_VERSION);
                assert_eq!(presented, GOSSIP_BUNDLE_WIRE_VERSION.wrapping_add(1));
            }
            other => panic!("expected WireVersionMismatch, got {other:?}"),
        }
    }

    #[test]
    fn deserialise_rejects_truncated_bundle() {
        let signing_key = deterministic_signing_key(32);
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint succeeds");
        let wire = serialise_bundle(&bundle);
        // Lop off the last byte of the signature — must report a
        // strictly-typed truncation error, not panic.
        let truncated = &wire[..wire.len() - 1];
        let err = deserialise_bundle(truncated).expect_err("must reject truncated wire");
        assert!(
            matches!(err, GossipError::WireTruncated { .. }),
            "expected WireTruncated, got {err:?}"
        );
        // Also: bytes shorter than the fixed header must report
        // WireTruncated, not WireMalformed (the header-size pre-check
        // is the only sane place for the early exit).
        let header_only = &wire[..WIRE_CANDIDATES_OFFSET - 1];
        let err = deserialise_bundle(header_only).expect_err("header-truncated must reject");
        assert!(
            matches!(err, GossipError::WireTruncated { .. }),
            "expected WireTruncated for header-only truncation, got {err:?}"
        );
    }

    #[test]
    fn serialise_size_is_bounded_by_max_candidates_per_bundle() {
        // A maximally-packed legal bundle must fit inside the
        // MAX_GOSSIP_DATAGRAM_BYTES envelope. This pins the math: any
        // future bump of MAX_CANDIDATES_PER_BUNDLE that would push us
        // past the datagram cap fails this test.
        let signing_key = deterministic_signing_key(33);
        let mut candidates = CandidateSet::default();
        for i in 0..MAX_CANDIDATES_PER_BUNDLE as u32 {
            // Use distinct private-range v4 addresses so all
            // candidates pass the scope filter.
            let a = ((i / 256) % 256) as u8;
            let b = (i % 256) as u8;
            candidates
                .v4_host
                .push(IpAddr::V4(Ipv4Addr::new(10, 0, a, b)));
        }
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, TEST_EPOCH, candidates)
                .expect("mint");
        let wire = serialise_bundle(&bundle);
        assert!(
            wire.len() <= MAX_GOSSIP_DATAGRAM_BYTES,
            "max-packed bundle ({} bytes) exceeds MAX_GOSSIP_DATAGRAM_BYTES ({})",
            wire.len(),
            MAX_GOSSIP_DATAGRAM_BYTES
        );
        let expected = WIRE_CANDIDATES_OFFSET
            + MAX_CANDIDATES_PER_BUNDLE * WIRE_CANDIDATE_STRIDE
            + WIRE_SIGNATURE_LEN;
        assert_eq!(
            wire.len(),
            expected,
            "wire size must equal fixed header + N*stride + signature"
        );
    }

    #[test]
    fn deserialise_rejects_oversized_datagram() {
        // A datagram larger than MAX_GOSSIP_DATAGRAM_BYTES must be
        // rejected without panic — the receive path enforces the same
        // cap so a malicious peer cannot exhaust verifier memory.
        let blob = vec![0u8; MAX_GOSSIP_DATAGRAM_BYTES + 1];
        let err = deserialise_bundle(&blob).expect_err("oversized datagram must reject");
        assert!(
            matches!(err, GossipError::WireMalformed(_)),
            "expected WireMalformed for oversized datagram, got {err:?}"
        );
    }

    #[test]
    fn deserialise_rejects_v4_lane_with_non_mapped_octets() {
        // A wire whose v4 lane carries 16 bytes that are NOT in the
        // v4-mapped IPv6 prefix form is malformed. Without this
        // strict check a producer could sneak an arbitrary v6 address
        // into a v4 slot and bypass downstream family-typed logic.
        let signing_key = deterministic_signing_key(34);
        let bundle = mint_bundle_with_timestamp(
            &signing_key,
            1,
            1_700_000_000,
            TEST_EPOCH,
            sample_candidates(),
        )
        .expect("mint");
        let mut wire = serialise_bundle(&bundle);
        // sample_candidates() puts one v4_host first; corrupt its
        // octets so the v4-mapped prefix bytes are wrong.
        wire[WIRE_CANDIDATES_OFFSET] = 0xab;
        let err = deserialise_bundle(&wire).expect_err("must reject malformed v4 lane");
        assert!(
            matches!(err, GossipError::WireMalformed(_)),
            "expected WireMalformed, got {err:?}"
        );
    }

    #[test]
    fn deserialise_bundle_never_panics_on_truncations_and_arbitrary_bytes() {
        // Parser-never-panics invariant (the property a fuzzer would assert):
        // `deserialise_bundle` runs on untrusted UDP datagrams, so on any byte
        // string — truncated mid-field, oversized, bit-flipped, or random — it
        // must return Err, never panic (a panic here is a remote DoS). Any
        // panic propagates and fails the test.
        let signing_key = deterministic_signing_key(11);
        let valid = serialise_bundle(
            &mint_bundle_with_timestamp(
                &signing_key,
                5,
                1_700_000_000,
                TEST_EPOCH,
                sample_candidates(),
            )
            .unwrap(),
        );

        // Every prefix of a valid wire — catches index/slice panics when a
        // datagram is cut off inside a length or count field.
        for len in 0..=valid.len() {
            let _ = deserialise_bundle(&valid[..len]);
        }

        // Single-byte corruption at every offset of an otherwise-valid wire.
        for i in 0..valid.len() {
            let mut corrupted = valid.clone();
            corrupted[i] ^= 0xFF;
            let _ = deserialise_bundle(&corrupted);
        }

        // Pathological uniform fills across a range of lengths.
        for len in [0usize, 1, 7, 64, 256, 4096, MAX_GOSSIP_DATAGRAM_BYTES + 1] {
            let _ = deserialise_bundle(&vec![0u8; len]);
            let _ = deserialise_bundle(&vec![0xFFu8; len]);
        }

        // Deterministic pseudo-random byte strings of every length 0..512
        // (an LCG keeps the test reproducible without a rng dependency).
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..512usize {
            let mut bytes = Vec::with_capacity(len);
            for _ in 0..len {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                bytes.push((seed >> 33) as u8);
            }
            let _ = deserialise_bundle(&bytes);
        }
    }
}
