#![forbid(unsafe_code)]

//! D2.5 — Peer-distributed signed-bundle gossip.
//!
//! Per the dataplane execution plan §D2.5, each peer mints a signed
//! bundle that carries:
//!
//! * its node ID (Ed25519 verifying-key fingerprint),
//! * a strictly-increasing sequence number (per-source anti-replay),
//! * a Unix timestamp (drift-bounded freshness),
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
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::dataplane_candidates::CandidateSet;

/// Magic prefix mixed into the signing pre-image. Domain separation:
/// guarantees that a signature on a gossip bundle cannot be replayed
/// as a signature on some other Ed25519-signed artifact (relay
/// session token, traversal bundle, etc.).
pub const GOSSIP_BUNDLE_DOMAIN: &[u8] = b"rustynet:peer_gossip:v1";

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

/// A signed peer-endpoint gossip bundle. This is the on-wire shape
/// (serialised via [`serialise_bundle`]) plus the verifying signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GossipBundle {
    pub source_node_id: [u8; 32],
    pub sequence: u64,
    pub timestamp_unix: u64,
    pub candidates: CandidateSet,
    pub signature: Signature,
}

/// Errors surfaced by the gossip mint / verify / accept paths.
#[derive(Debug)]
pub enum GossipError {
    /// The bundle's claimed source is not in our known-peer set.
    UnknownSource,
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
    /// Too many candidates packed into a single bundle.
    TooManyCandidates { presented: usize, max: usize },
    /// Couldn't compute the current Unix timestamp (clock before
    /// UNIX_EPOCH). Should never happen on a healthy host.
    TimestampUnavailable,
}

impl std::fmt::Display for GossipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipError::UnknownSource => write!(f, "gossip bundle source is not a known peer"),
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
            GossipError::TooManyCandidates { presented, max } => write!(
                f,
                "gossip bundle carries too many candidates ({presented}; max {max})"
            ),
            GossipError::TimestampUnavailable => write!(
                f,
                "local clock is before UNIX_EPOCH; cannot compute timestamp"
            ),
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
    candidates: &CandidateSet,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        2 + GOSSIP_BUNDLE_DOMAIN.len()
            + 32
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
/// for monotonicity), and the freshly-gathered [`CandidateSet`].
pub fn mint_bundle(
    signing_key: &SigningKey,
    sequence: u64,
    candidates: CandidateSet,
) -> Result<GossipBundle, GossipError> {
    let timestamp_unix = current_unix_seconds()?;
    mint_bundle_with_timestamp(signing_key, sequence, timestamp_unix, candidates)
}

/// Test-friendly variant taking an explicit timestamp. Production
/// callers use [`mint_bundle`].
pub fn mint_bundle_with_timestamp(
    signing_key: &SigningKey,
    sequence: u64,
    timestamp_unix: u64,
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
    let preimage = signing_preimage(&source_node_id, sequence, timestamp_unix, &candidates);
    let signature = signing_key.sign(&preimage);
    Ok(GossipBundle {
        source_node_id,
        sequence,
        timestamp_unix,
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
        &bundle.candidates,
    );
    verifying_key
        .verify(&preimage, &bundle.signature)
        .map_err(|_| GossipError::SignatureInvalid)
}

/// Full inbound acceptance check. Returns `Ok(())` if the bundle is
/// fresh, monotonic, and validly signed under a known peer's key.
/// Updates `state` to record the new highest sequence on success.
///
/// `known_peers` is a map from node-id (the verifying key bytes) to
/// the verifying key itself; typically loaded from the signed
/// membership snapshot.
#[allow(clippy::too_many_arguments)]
pub fn accept_bundle(
    bundle: &GossipBundle,
    known_peers: &HashMap<[u8; 32], VerifyingKey>,
    state: &mut SeenSequenceState,
    freshness_window_secs: u64,
) -> Result<(), GossipError> {
    let now = current_unix_seconds()?;
    accept_bundle_with_now(bundle, known_peers, state, freshness_window_secs, now)
}

/// Test-friendly variant taking an explicit "now". Production
/// callers use [`accept_bundle`].
pub fn accept_bundle_with_now(
    bundle: &GossipBundle,
    known_peers: &HashMap<[u8; 32], VerifyingKey>,
    state: &mut SeenSequenceState,
    freshness_window_secs: u64,
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
    let drift = bundle.timestamp_unix as i128 - now_unix as i128;
    if drift.unsigned_abs() > freshness_window_secs as u128 {
        // Saturating-cast i128 → i64 so a pathological skew (timestamp
        // close to u64::MAX) reports a clamped sentinel rather than a
        // wrapped negative value. Cosmetic — the rejection itself is
        // correct either way.
        let drift_secs = drift.clamp(i64::MIN as i128, i64::MAX as i128) as i64;
        return Err(GossipError::TimestampOutsideWindow { drift_secs });
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
        let p1 = signing_preimage(&source, 42, 1_700_000_000, &candidates);
        let p2 = signing_preimage(&source, 42, 1_700_000_000, &candidates);
        assert_eq!(p1, p2, "pre-image must be deterministic");
    }

    #[test]
    fn signing_preimage_carries_domain_separation_prefix() {
        let candidates = sample_candidates();
        let source = [7u8; 32];
        let preimage = signing_preimage(&source, 0, 0, &candidates);
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
    fn mint_and_verify_round_trip_against_known_peer_key() {
        let signing_key = deterministic_signing_key(1);
        let verifying_key = signing_key.verifying_key();
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
                .expect("mint succeeds");
        verify_signature(&bundle, &verifying_key).expect("signature verifies under signer's key");
    }

    #[test]
    fn verify_signature_fails_under_wrong_key() {
        let signing_key = deterministic_signing_key(2);
        let other = deterministic_signing_key(3);
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
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

        let bundle1 =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
                .unwrap();
        accept_bundle_with_now(&bundle1, &known, &mut state, 300, 1_700_000_000).expect("ok");
        assert_eq!(state.highest_accepted(&verifying_key.to_bytes()), Some(1));

        let bundle2 =
            mint_bundle_with_timestamp(&signing_key, 2, 1_700_000_100, CandidateSet::default())
                .unwrap();
        accept_bundle_with_now(&bundle2, &known, &mut state, 300, 1_700_000_100)
            .expect("strictly larger sequence accepted");
        assert_eq!(state.highest_accepted(&verifying_key.to_bytes()), Some(2));
    }

    #[test]
    fn accept_bundle_rejects_replay_of_same_sequence() {
        let signing_key = deterministic_signing_key(5);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let bundle =
            mint_bundle_with_timestamp(&signing_key, 7, 1_700_000_000, sample_candidates())
                .unwrap();
        accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_000_000).expect("ok");
        // Same bundle replayed must be rejected.
        let err = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_000_000)
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

        let high =
            mint_bundle_with_timestamp(&signing_key, 100, 1_700_000_000, sample_candidates())
                .unwrap();
        accept_bundle_with_now(&high, &known, &mut state, 300, 1_700_000_000).expect("ok");
        let low = mint_bundle_with_timestamp(&signing_key, 50, 1_700_000_000, sample_candidates())
            .unwrap();
        let err = accept_bundle_with_now(&low, &known, &mut state, 300, 1_700_000_000)
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
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
                .unwrap();
        let err = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_001_000)
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
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_001_000, sample_candidates())
                .unwrap();
        let err = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_000_000)
            .expect_err("future timestamp must be rejected");
        match err {
            GossipError::TimestampOutsideWindow { drift_secs } => {
                assert_eq!(drift_secs, 1000);
            }
            other => panic!("expected TimestampOutsideWindow, got {other:?}"),
        }
    }

    #[test]
    fn accept_bundle_rejects_unknown_source() {
        let signing_key = deterministic_signing_key(9);
        let mut state = SeenSequenceState::new();
        let known: HashMap<[u8; 32], VerifyingKey> = HashMap::new();
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
                .unwrap();
        let err = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_000_000)
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

        let mut bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
                .unwrap();
        // Tamper: inject an attacker-controlled endpoint.
        bundle.candidates.v4_srflx.push(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            51820,
        ));
        let err = accept_bundle_with_now(&bundle, &known, &mut state, 300, 1_700_000_000)
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
        let err = mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, candidates)
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
        let bundle =
            mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
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
    fn boundary_timestamps_at_exact_window_edge_are_accepted() {
        // A bundle exactly `freshness_window_secs` away (either
        // direction) is on the boundary; the implementation uses
        // strict `> window`, so equality is accepted.
        let signing_key = deterministic_signing_key(13);
        let verifying_key = signing_key.verifying_key();
        let mut state = SeenSequenceState::new();
        let mut known = HashMap::new();
        known.insert(verifying_key.to_bytes(), verifying_key);

        let past = mint_bundle_with_timestamp(&signing_key, 1, 1_700_000_000, sample_candidates())
            .unwrap();
        accept_bundle_with_now(&past, &known, &mut state, 300, 1_700_000_300)
            .expect("boundary past timestamp accepted");

        let future =
            mint_bundle_with_timestamp(&signing_key, 2, 1_700_000_600, sample_candidates())
                .unwrap();
        accept_bundle_with_now(&future, &known, &mut state, 300, 1_700_000_300)
            .expect("boundary future timestamp accepted");
    }
}
