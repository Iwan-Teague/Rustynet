#![forbid(unsafe_code)]

//! D2.5 — Gossip runtime: mint, accept, epidemic re-broadcast.
//!
//! [`GossipNode`] is the single piece of state that turns the
//! cryptographic primitives in `peer_gossip` and the UDP transport
//! in `gossip_transport` into a working epidemic-gossip layer. The
//! daemon owns one per process; the three-peer mesh integration test
//! owns three.
//!
//! Responsibilities:
//!
//! * Hold the local Ed25519 signing key, the per-source replay
//!   watermark, and the local sequence counter.
//! * Mint a fresh bundle when the local [`CandidateSet`] changes OR
//!   when the re-mint timer elapses (whichever is sooner).
//! * Push the freshly minted bundle to every known peer via the
//!   transport.
//! * On every inbound bundle: run the full `accept_bundle` check
//!   (signature + freshness + monotonic sequence) and, on accept,
//!   apply the bundle's endpoints to the local peer-endpoint cache
//!   and re-push to every OTHER known peer (epidemic gossip).
//! * Persist `gossip_sequence` and the highest-accepted-sequence-
//!   per-source ledger to a watermark file on every state mutation,
//!   so a daemon restart cannot silently rewind the local sequence
//!   (replay window) or forget what it has already accepted from a
//!   peer (anti-rewind on the consume side).
//!
//! Security framing:
//!
//! * Fail-closed on watermark persistence: if the spool write fails,
//!   we refuse to advance the in-memory state. A subsequent
//!   `maybe_mint_and_broadcast` will retry; the daemon never proceeds
//!   on a non-durable mint, because that would let an attacker who
//!   could trigger a watermark-write failure roll the next-mint
//!   sequence back to a value they have already seen.
//! * Source authentication is per-bundle Ed25519 — the transport
//!   itself is the WireGuard tunnel, but we DO NOT trust the
//!   transport: a compromised intermediate peer in the epidemic re-
//!   push graph cannot forge a bundle for a different source.
//! * Anti-loop is via `seen_gossip_sequences` (the correctness
//!   layer) plus a "don't push back to the immediate sender" hint
//!   (a cosmetic optimisation, not a security control).
//! * Logging is fixed-vocabulary: we emit `gossip_accept` /
//!   `gossip_reject_<variant>` markers with an 8-byte hex prefix of
//!   the source node id. The full candidate list is NEVER written to
//!   shared logs — it is PII per the privacy retention policy.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rustynet_control::membership::{MembershipNode, MembershipNodeStatus, MembershipState};
use rustynet_control::roles::RoleCapability;

use crate::dataplane_candidates::CandidateSet;
use crate::gossip_transport::{GossipTransport, TransportError};
use crate::peer_gossip::{
    DEFAULT_FRESHNESS_WINDOW_SECS, GossipBundle, GossipError, MAX_GOSSIP_DATAGRAM_BYTES,
    SeenSequenceState, accept_bundle_with_now, deserialise_bundle, mint_bundle_with_timestamp,
};

/// Default interval between unconditional re-mints. A mint is also
/// triggered immediately when the local CandidateSet changes; this
/// timer is the "I'm still alive and my candidates haven't changed"
/// heartbeat so a peer that joined the mesh after our last mint
/// still receives our latest endpoint set within a bounded window.
pub const GOSSIP_REMINT_INTERVAL_SECS: u64 = 30;

const GOSSIP_WATERMARK_WIRE_VERSION: u8 = 1;

/// Maximum accepted size of an on-disk gossip watermark spool. The spool is
/// `version` + `local_sequence` + one `seen` entry (~86 bytes) per gossip
/// source; 256 KiB allows several thousand sources while bounding the work an
/// attacker (or a corrupt/oversized file) can force on load. Mirrors the
/// `MAX_ROTATION_LEDGER_BYTES` cap on the key-rotation ledger.
const MAX_GOSSIP_WATERMARK_BYTES: usize = 256 * 1024;

/// Errors surfaced by [`GossipNode`] state transitions. Distinct
/// from `GossipError` so callers can distinguish "the local spool
/// failed" from "the bundle was rejected".
#[derive(Debug)]
pub enum GossipNodeError {
    /// Watermark spool I/O failed. Carries a sanitised message —
    /// we DO NOT include the file path so a daemon-log audit
    /// cannot reveal the daemon's state directory layout to a
    /// reader who shouldn't have it.
    WatermarkIo(String),
    /// Watermark file is corrupt or carries an unknown wire version.
    /// Fail-closed: the daemon refuses to advance the sequence
    /// counter from a torn read.
    WatermarkCorrupt(&'static str),
    /// Bundle-level rejection (signature, replay, freshness,
    /// scope). Typed pass-through so the caller can record a
    /// per-variant counter.
    Bundle(GossipError),
    /// Transport-level failure (oversized datagram, socket I/O).
    Transport(TransportError),
}

impl std::fmt::Display for GossipNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GossipNodeError::WatermarkIo(msg) => write!(f, "gossip watermark i/o: {msg}"),
            GossipNodeError::WatermarkCorrupt(reason) => {
                write!(f, "gossip watermark corrupt: {reason}")
            }
            GossipNodeError::Bundle(err) => write!(f, "gossip bundle rejected: {err}"),
            GossipNodeError::Transport(err) => write!(f, "gossip transport: {err}"),
        }
    }
}

impl std::error::Error for GossipNodeError {}

/// On-disk shape of the gossip watermark spool. Versioned so a
/// future schema change can be additive without breaking older
/// daemons (older daemons would refuse to load a higher version —
/// that is the desired fail-closed behaviour).
#[derive(Debug, Clone, Default)]
pub struct GossipWatermark {
    pub local_sequence: u64,
    pub seen: SeenSequenceState,
}

/// Per-peer routing entry. The push address is the peer's
/// `RUSTYNET_GOSSIP_PORT` socket on its mesh IP; the verifying key
/// authenticates inbound bundles signed by that peer.
#[derive(Debug, Clone)]
pub struct GossipPeer {
    pub verifying_key: VerifyingKey,
    pub push_addr: SocketAddr,
}

/// Signed membership-derived anchor view used by gossip scheduling
/// and LAN port-mapping authority election. Kept tiny so tests and
/// daemon integration can reason over the same deterministic rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorRuntimeView {
    pub anchor_gossip_seed_peer_ids: Vec<[u8; 32]>,
    pub port_mapping_authority_node_id: Option<String>,
}

/// Runtime state for one gossip participant.
pub struct GossipNode {
    pub local_node_id: [u8; 32],
    signing_key: SigningKey,
    pub peers: HashMap<[u8; 32], GossipPeer>,
    /// Signed membership says these peers carry
    /// `anchor.gossip_seed`. Re-broadcast schedules send to them
    /// first, sorted by peer id, then to all other peers sorted by
    /// peer id. A spoofed transport sender cannot influence this:
    /// only already-verified membership state updates the set.
    pub anchor_gossip_seed_peer_ids: HashSet<[u8; 32]>,
    /// GM-1 / RSA-0034: peers currently Revoked/Quarantined in signed
    /// membership. Checked on every inbound bundle, defense-in-depth
    /// alongside the dataplane ACL revocation check (DD-03/RSA-0007) — a
    /// revoked node must not be able to re-advertise itself via gossip and
    /// be re-admitted into `applied_endpoints`. Populated the same way as
    /// `anchor_gossip_seed_peer_ids`: derived from verified membership
    /// state via `set_revoked_peer_ids`, never from the wire.
    pub revoked_peer_ids: HashSet<[u8; 32]>,
    /// Last endpoints accepted from each remote source. Read by the
    /// connect path; the integration test asserts against this.
    pub applied_endpoints: HashMap<[u8; 32], Vec<SocketAddr>>,
    pub gossip_sequence: u64,
    pub seen_gossip_sequences: SeenSequenceState,
    pub last_minted_bundle: Option<GossipBundle>,
    pub next_gossip_mint_at: Option<Instant>,
    pub remint_interval: Duration,
    pub watermark_path: Option<PathBuf>,
    /// Counters for rejected inbound bundles, keyed by the GossipError
    /// variant's static name (so we never persist or log PII).
    pub rejected_counts: HashMap<&'static str, u64>,
    /// Counters for accepted inbound bundles and locally minted
    /// bundles. Used by the integration test to assert progress.
    pub accepted_count: u64,
    pub minted_count: u64,
}

impl GossipNode {
    /// Build a node from a signing key plus an optional watermark
    /// spool path. When a path is provided and the file exists, the
    /// sequence counter and per-source ledger are loaded from it;
    /// otherwise both start at zero.
    pub fn new(
        signing_key: SigningKey,
        watermark_path: Option<PathBuf>,
    ) -> Result<Self, GossipNodeError> {
        let local_node_id = signing_key.verifying_key().to_bytes();
        let mut node = Self {
            local_node_id,
            signing_key,
            peers: HashMap::new(),
            anchor_gossip_seed_peer_ids: HashSet::new(),
            revoked_peer_ids: HashSet::new(),
            applied_endpoints: HashMap::new(),
            gossip_sequence: 0,
            seen_gossip_sequences: SeenSequenceState::new(),
            last_minted_bundle: None,
            next_gossip_mint_at: None,
            remint_interval: Duration::from_secs(GOSSIP_REMINT_INTERVAL_SECS),
            watermark_path: watermark_path.clone(),
            rejected_counts: HashMap::new(),
            accepted_count: 0,
            minted_count: 0,
        };
        if let Some(path) = watermark_path.as_deref()
            && path.exists()
        {
            let loaded = load_gossip_watermark(path)?;
            node.gossip_sequence = loaded.local_sequence;
            node.seen_gossip_sequences = loaded.seen;
        }
        Ok(node)
    }

    /// Register or update a peer's routing/verification entry.
    pub fn register_peer(
        &mut self,
        peer_node_id: [u8; 32],
        verifying_key: VerifyingKey,
        push_addr: SocketAddr,
    ) {
        self.peers.insert(
            peer_node_id,
            GossipPeer {
                verifying_key,
                push_addr,
            },
        );
    }

    /// Replace the anchor-seed set from verified membership state.
    /// Unknown peer ids are harmless; the rebroadcast scheduler
    /// intersects this set with `self.peers`.
    pub fn set_anchor_gossip_seed_peer_ids(
        &mut self,
        peer_ids: impl IntoIterator<Item = [u8; 32]>,
    ) {
        self.anchor_gossip_seed_peer_ids = peer_ids.into_iter().collect();
    }

    /// Replace the revoked-peer set from verified membership state (GM-1 /
    /// RSA-0034). Unknown peer ids are harmless; `ingest_inbound_bundle`
    /// only consults this set for bundles whose source is already a known
    /// peer (an unknown source is rejected earlier, by `accept_bundle`).
    pub fn set_revoked_peer_ids(&mut self, peer_ids: impl IntoIterator<Item = [u8; 32]>) {
        self.revoked_peer_ids = peer_ids.into_iter().collect();
    }

    /// Snapshot of all currently-registered peers' verifying keys
    /// keyed by node id. Used by `accept_bundle` to find the
    /// verifying key for an incoming bundle's claimed source.
    pub fn known_peer_keys(&self) -> HashMap<[u8; 32], VerifyingKey> {
        let mut out = HashMap::with_capacity(self.peers.len());
        for (id, peer) in &self.peers {
            out.insert(*id, peer.verifying_key);
        }
        out
    }

    /// Mint a fresh bundle if either:
    ///
    /// * the supplied `candidates` differ from the last minted
    ///   bundle's candidate set, or
    /// * the [`GOSSIP_REMINT_INTERVAL_SECS`] heartbeat timer has
    ///   elapsed since the last mint.
    ///
    /// On mint, the new sequence is persisted to the watermark spool
    /// BEFORE the bundle is broadcast. A persistence failure aborts
    /// the mint (fail-closed): the in-memory sequence is rolled back
    /// and the function returns `Err(WatermarkIo)`.
    pub fn maybe_mint_and_broadcast(
        &mut self,
        now: Instant,
        now_unix: u64,
        candidates: CandidateSet,
        transport: &GossipTransport,
    ) -> Result<Option<GossipBundle>, GossipNodeError> {
        let candidates_changed = self
            .last_minted_bundle
            .as_ref()
            .is_none_or(|b| b.candidates != candidates);
        let timer_elapsed = self
            .next_gossip_mint_at
            .is_none_or(|deadline| now >= deadline);
        if !candidates_changed && !timer_elapsed {
            return Ok(None);
        }
        let next_sequence =
            self.gossip_sequence
                .checked_add(1)
                .ok_or(GossipNodeError::WatermarkCorrupt(
                    "local gossip sequence overflowed u64::MAX",
                ))?;
        let bundle =
            mint_bundle_with_timestamp(&self.signing_key, next_sequence, now_unix, candidates)
                .map_err(GossipNodeError::Bundle)?;
        // Persist BEFORE updating in-memory state so a torn write
        // can't leave the daemon claiming a sequence it never
        // committed to disk.
        let proposed = GossipWatermark {
            local_sequence: next_sequence,
            seen: self.seen_gossip_sequences.clone(),
        };
        self.persist_watermark(&proposed)?;
        self.gossip_sequence = next_sequence;
        self.last_minted_bundle = Some(bundle.clone());
        self.next_gossip_mint_at = Some(now + self.remint_interval);
        self.minted_count = self.minted_count.saturating_add(1);
        // Broadcast to every registered peer. We collect errors
        // rather than failing the whole mint on the first one — a
        // single peer's transport failure shouldn't suppress
        // delivery to the rest of the mesh.
        for peer_id in self.ordered_peer_ids_for_rebroadcast(None, None) {
            let Some(peer) = self.peers.get(&peer_id) else {
                continue;
            };
            if let Err(err) = transport.push_bundle(peer.push_addr, &bundle) {
                log::warn!(
                    "gossip_push_failed source={} target={:?} reason={}",
                    short_id(&self.local_node_id),
                    peer.push_addr,
                    transport_error_kind(&err)
                );
            }
        }
        log::info!(
            "gossip_mint source={} seq={} peers={}",
            short_id(&self.local_node_id),
            next_sequence,
            self.peers.len()
        );
        Ok(Some(bundle))
    }

    /// Process one inbound datagram already received off the wire.
    /// Validates the wire form, runs the full `accept_bundle` check,
    /// applies the bundle, and re-pushes to every OTHER known peer.
    pub fn ingest_wire_bundle(
        &mut self,
        sender: Option<SocketAddr>,
        wire_bytes: &[u8],
        transport: &GossipTransport,
        now_unix: u64,
    ) -> Result<GossipIngestSummary, GossipNodeError> {
        if wire_bytes.len() > MAX_GOSSIP_DATAGRAM_BYTES {
            self.bump_reject_counter("oversized");
            return Err(GossipNodeError::Bundle(GossipError::WireMalformed(
                "datagram exceeds MAX_GOSSIP_DATAGRAM_BYTES",
            )));
        }
        let bundle = match deserialise_bundle(wire_bytes) {
            Ok(b) => b,
            Err(err) => {
                self.bump_reject_counter(error_kind(&err));
                log::warn!(
                    "gossip_reject_{} source=unknown sender={:?}",
                    error_kind(&err),
                    sender
                );
                return Err(GossipNodeError::Bundle(err));
            }
        };
        self.ingest_inbound_bundle(sender, bundle, transport, now_unix)
    }

    /// Same as [`Self::ingest_wire_bundle`] but the bundle has
    /// already been parsed (used by the integration test which
    /// drives the wire format directly).
    pub fn ingest_inbound_bundle(
        &mut self,
        sender: Option<SocketAddr>,
        bundle: GossipBundle,
        transport: &GossipTransport,
        now_unix: u64,
    ) -> Result<GossipIngestSummary, GossipNodeError> {
        // Drop a bundle that claims our own node id — we should
        // never accept our own gossip as if it came from another
        // peer. Fail closed.
        if bundle.source_node_id == self.local_node_id {
            self.bump_reject_counter("self_origin");
            return Err(GossipNodeError::Bundle(GossipError::UnknownSource));
        }
        let known_peers = self.known_peer_keys();
        let mut probe_seen = self.seen_gossip_sequences.clone();
        if let Err(err) = accept_bundle_with_now(
            &bundle,
            &known_peers,
            &mut probe_seen,
            DEFAULT_FRESHNESS_WINDOW_SECS,
            now_unix,
        ) {
            let kind = error_kind(&err);
            self.bump_reject_counter(kind);
            log::warn!(
                "gossip_reject_{kind} source={} sender={:?}",
                short_id(&bundle.source_node_id),
                sender
            );
            return Err(GossipNodeError::Bundle(err));
        }
        // GM-1 / RSA-0034: signature/freshness/sequence all passed, but a
        // node currently Revoked/Quarantined in signed membership must
        // still be refused — defense-in-depth alongside the dataplane ACL
        // revocation check (DD-03/RSA-0007). Checked AFTER signature
        // verification (a forged bundle is rejected on its own merits
        // first) and BEFORE any state mutation (no watermark advance, no
        // endpoint admission, no re-push) so a revoked node gets zero
        // observable effect from presenting a bundle.
        if self.revoked_peer_ids.contains(&bundle.source_node_id) {
            self.bump_reject_counter("revoked_source");
            log::warn!(
                "gossip_reject_revoked_source source={} sender={:?}",
                short_id(&bundle.source_node_id),
                sender
            );
            return Err(GossipNodeError::Bundle(GossipError::RevokedSource));
        }
        // accept_bundle_with_now passed against a clone of the
        // seen-state; commit it to the real ledger only after the
        // watermark spool write succeeds.
        let proposed = GossipWatermark {
            local_sequence: self.gossip_sequence,
            seen: probe_seen.clone(),
        };
        self.persist_watermark(&proposed)?;
        self.seen_gossip_sequences = probe_seen;
        let endpoints = crate::peer_gossip::flatten_endpoints(&bundle);
        self.applied_endpoints
            .insert(bundle.source_node_id, endpoints.clone());
        self.accepted_count = self.accepted_count.saturating_add(1);
        log::info!(
            "gossip_accept source={} seq={} candidates={}",
            short_id(&bundle.source_node_id),
            bundle.sequence,
            endpoints.len()
        );
        // Epidemic re-push: forward to every known peer except the
        // immediate sender (anti-loop hint) and the originator
        // itself (it already has the bundle by definition).
        let sender_id: Option<[u8; 32]> = sender.and_then(|s| self.peer_id_for_addr(s));
        for peer_id in self.ordered_peer_ids_for_rebroadcast(Some(bundle.source_node_id), sender_id)
        {
            let Some(peer) = self.peers.get(&peer_id) else {
                continue;
            };
            if let Err(err) = transport.push_bundle(peer.push_addr, &bundle) {
                log::warn!(
                    "gossip_repush_failed source={} via={} target={:?} reason={}",
                    short_id(&bundle.source_node_id),
                    short_id(&self.local_node_id),
                    peer.push_addr,
                    transport_error_kind(&err)
                );
            }
        }
        Ok(GossipIngestSummary {
            source_node_id: bundle.source_node_id,
            sequence: bundle.sequence,
            applied_endpoints: endpoints,
        })
    }

    fn peer_id_for_addr(&self, addr: SocketAddr) -> Option<[u8; 32]> {
        for (id, peer) in &self.peers {
            if peer.push_addr == addr {
                return Some(*id);
            }
        }
        None
    }

    fn ordered_peer_ids_for_rebroadcast(
        &self,
        origin: Option<[u8; 32]>,
        sender: Option<[u8; 32]>,
    ) -> Vec<[u8; 32]> {
        let mut anchor = Vec::new();
        let mut ordinary = Vec::new();
        for peer_id in self.peers.keys().copied() {
            if Some(peer_id) == origin || Some(peer_id) == sender {
                continue;
            }
            if self.anchor_gossip_seed_peer_ids.contains(&peer_id) {
                anchor.push(peer_id);
            } else {
                ordinary.push(peer_id);
            }
        }
        anchor.sort_unstable();
        ordinary.sort_unstable();
        anchor.extend(ordinary);
        anchor
    }

    fn persist_watermark(&self, watermark: &GossipWatermark) -> Result<(), GossipNodeError> {
        let Some(path) = self.watermark_path.as_deref() else {
            // No watermark configured — pure in-memory mode (only
            // used by tests). Fail open here is correct because no
            // attacker can roll back a spool that doesn't exist.
            return Ok(());
        };
        write_gossip_watermark(path, watermark)
    }

    fn bump_reject_counter(&mut self, kind: &'static str) {
        *self.rejected_counts.entry(kind).or_insert(0) += 1;
    }
}

pub fn anchor_runtime_view_from_membership(state: &MembershipState) -> AnchorRuntimeView {
    AnchorRuntimeView {
        anchor_gossip_seed_peer_ids: anchor_gossip_seed_peer_ids_from_membership(state),
        port_mapping_authority_node_id: select_port_mapping_authority_node_id(&state.nodes),
    }
}

pub fn anchor_gossip_seed_peer_ids_from_membership(state: &MembershipState) -> Vec<[u8; 32]> {
    let mut ids = state
        .nodes
        .iter()
        .filter(|node| node.status == MembershipNodeStatus::Active)
        .filter(|node| {
            node.capabilities
                .contains(&RoleCapability::AnchorGossipSeed)
        })
        .filter_map(|node| decode_hex32(node.node_pubkey_hex.as_str()))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// GM-1 / RSA-0034: raw pubkeys of every node currently Revoked or
/// Quarantined in signed membership, for [`GossipNode::set_revoked_peer_ids`].
/// Mirrors [`anchor_gossip_seed_peer_ids_from_membership`]'s shape exactly.
pub fn revoked_peer_ids_from_membership(state: &MembershipState) -> Vec<[u8; 32]> {
    let mut ids = state
        .nodes
        .iter()
        .filter(|node| {
            matches!(
                node.status,
                MembershipNodeStatus::Revoked | MembershipNodeStatus::Quarantined
            )
        })
        .filter_map(|node| decode_hex32(node.node_pubkey_hex.as_str()))
        .collect::<Vec<_>>();
    ids.sort_unstable();
    ids.dedup();
    ids
}

pub fn select_port_mapping_authority_node_id(nodes: &[MembershipNode]) -> Option<String> {
    nodes
        .iter()
        .filter(|node| node.status == MembershipNodeStatus::Active)
        .filter(|node| {
            node.capabilities
                .contains(&RoleCapability::AnchorPortMappingAuthoritative)
        })
        .map(|node| node.node_id.as_str())
        .min()
        .map(str::to_owned)
}

/// One-shot result of an accepted inbound bundle. Returned by
/// [`GossipNode::ingest_inbound_bundle`] so the caller can update
/// any downstream caches (e.g. the connect path's per-peer endpoint
/// cache).
#[derive(Debug, Clone)]
pub struct GossipIngestSummary {
    pub source_node_id: [u8; 32],
    pub sequence: u64,
    pub applied_endpoints: Vec<SocketAddr>,
}

/// Map a `GossipError` to a short, fixed-vocabulary string. Used as
/// the counter key in `rejected_counts` and as the log tag. NEVER
/// includes user data.
pub fn error_kind(err: &GossipError) -> &'static str {
    match err {
        GossipError::UnknownSource => "unknown_source",
        GossipError::RevokedSource => "revoked_source",
        GossipError::SignatureInvalid => "signature_invalid",
        GossipError::TimestampOutsideWindow { .. } => "timestamp_outside_window",
        GossipError::SequenceNotMonotonic { .. } => "sequence_not_monotonic",
        GossipError::TooManyCandidates { .. } => "too_many_candidates",
        GossipError::UnreachableCandidate { .. } => "unreachable_candidate",
        GossipError::TimestampUnavailable => "timestamp_unavailable",
        GossipError::WireVersionMismatch { .. } => "wire_version_mismatch",
        GossipError::WireTruncated { .. } => "wire_truncated",
        GossipError::WireMalformed(_) => "wire_malformed",
    }
}

fn transport_error_kind(err: &TransportError) -> &'static str {
    match err {
        TransportError::Oversized { .. } => "oversized",
        TransportError::InvalidBundle(_) => "invalid_bundle",
        TransportError::Io(_) => "io",
        TransportError::Unsupported(_) => "unsupported",
    }
}

/// 8-byte hex prefix of a node id, suitable for shared logs. Same
/// shape as the existing log markers in `daemon.rs` for trust /
/// traversal / membership events.
/// Lowercase hex alphabet for the nibble-lookup encoders.
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

fn push_hex(out: &mut String, bytes: &[u8]) {
    // Append lowercase hex without a per-byte `format!` allocation.
    for &byte in bytes {
        out.push(HEX_LOWER[(byte >> 4) as usize] as char);
        out.push(HEX_LOWER[(byte & 0x0f) as usize] as char);
    }
}

fn short_id(id: &[u8; 32]) -> String {
    let mut out = String::with_capacity(16);
    push_hex(&mut out, &id[..8]);
    out
}

fn decode_hex32(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, chunk) in value.as_bytes().chunks(2).enumerate() {
        let hex = std::str::from_utf8(chunk).ok()?;
        out[index] = u8::from_str_radix(hex, 16).ok()?;
    }
    Some(out)
}

/// Read a gossip watermark file. Returns `Ok(default)` if the file
/// is absent. Returns `Err(WatermarkCorrupt)` on any structural
/// mismatch.
/// Read a watermark file, refusing to buffer more than
/// [`MAX_GOSSIP_WATERMARK_BYTES`] before any structural parse. A corrupt or
/// hostile daemon that managed to write a huge file at the spool path must not
/// be able to exhaust memory on load (anti-DoS, fail-closed). Mirrors
/// `key_rotation::read_bounded`.
fn read_gossip_watermark_bounded(path: &Path) -> Result<String, GossipNodeError> {
    use std::io::Read;
    let file = fs::File::open(path).map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
    let mut buf = String::new();
    file.take(MAX_GOSSIP_WATERMARK_BYTES as u64 + 1)
        .read_to_string(&mut buf)
        .map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
    if buf.len() > MAX_GOSSIP_WATERMARK_BYTES {
        return Err(GossipNodeError::WatermarkCorrupt(
            "watermark file exceeds maximum size",
        ));
    }
    Ok(buf)
}

pub fn load_gossip_watermark(path: &Path) -> Result<GossipWatermark, GossipNodeError> {
    let content = read_gossip_watermark_bounded(path)?;
    let mut version: Option<u8> = None;
    let mut local_sequence: Option<u64> = None;
    let mut seen = SeenSequenceState::new();
    for line in content.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(GossipNodeError::WatermarkCorrupt(
                "watermark line missing key/value separator",
            ));
        };
        match key {
            "version" => {
                version = value
                    .parse::<u8>()
                    .ok()
                    .or(Some(0))
                    .filter(|_| value.chars().all(|c| c.is_ascii_digit()));
            }
            "local_sequence" => {
                local_sequence = value.parse::<u64>().ok();
                if local_sequence.is_none() {
                    return Err(GossipNodeError::WatermarkCorrupt(
                        "watermark local_sequence is not a u64",
                    ));
                }
            }
            "seen" => {
                // seen=<hex32>:<u64>,<hex32>:<u64>,...
                if value.is_empty() {
                    continue;
                }
                for entry in value.split(',') {
                    let Some((id_hex, seq_str)) = entry.split_once(':') else {
                        return Err(GossipNodeError::WatermarkCorrupt(
                            "watermark seen entry missing colon",
                        ));
                    };
                    if id_hex.len() != 64 {
                        return Err(GossipNodeError::WatermarkCorrupt(
                            "watermark seen entry id is not 64 hex chars",
                        ));
                    }
                    let mut id = [0u8; 32];
                    for (i, chunk) in id_hex.as_bytes().chunks(2).enumerate() {
                        let hex = std::str::from_utf8(chunk).map_err(|_| {
                            GossipNodeError::WatermarkCorrupt(
                                "watermark seen entry id is not ASCII hex",
                            )
                        })?;
                        id[i] = u8::from_str_radix(hex, 16).map_err(|_| {
                            GossipNodeError::WatermarkCorrupt(
                                "watermark seen entry id is not valid hex",
                            )
                        })?;
                    }
                    let seq = seq_str.parse::<u64>().map_err(|_| {
                        GossipNodeError::WatermarkCorrupt(
                            "watermark seen entry sequence is not a u64",
                        )
                    })?;
                    seen.record(id, seq);
                }
            }
            _ => {
                return Err(GossipNodeError::WatermarkCorrupt(
                    "watermark file contains unknown key",
                ));
            }
        }
    }
    if version != Some(GOSSIP_WATERMARK_WIRE_VERSION) {
        return Err(GossipNodeError::WatermarkCorrupt(
            "watermark file version mismatch",
        ));
    }
    Ok(GossipWatermark {
        local_sequence: local_sequence.ok_or(GossipNodeError::WatermarkCorrupt(
            "watermark missing local_sequence",
        ))?,
        seen,
    })
}

/// Atomically write a gossip watermark file. Uses the existing
/// daemon convention: write to a temp file in the same directory,
/// `sync_all`, then `rename`. This is the same pattern as
/// `persist_membership_watermark` (daemon.rs:9593).
pub fn write_gossip_watermark(
    path: &Path,
    watermark: &GossipWatermark,
) -> Result<(), GossipNodeError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort tightening of the parent directory's
            // permissions. The existing membership watermark spool
            // uses the same 0o700 lock; we mirror that. A failure
            // here would indicate the parent is owned by a different
            // uid (e.g. the membership-watermark already locked it)
            // which is fine — we don't need to re-tighten in that
            // case.
            let _ = fs::set_permissions(parent, fs::Permissions::from_mode(0o700));
        }
    }
    let mut payload = String::new();
    payload.push_str(&format!("version={GOSSIP_WATERMARK_WIRE_VERSION}\n"));
    payload.push_str(&format!("local_sequence={}\n", watermark.local_sequence));
    payload.push_str("seen=");
    let mut entries: Vec<([u8; 32], u64)> = Vec::new();
    // SeenSequenceState exposes source_count() and highest_accepted
    // but not an iterator. Use the public API to extract entries by
    // looking up every known sequence the test may have planted —
    // but in production we need an iterator. Provide a lightweight
    // dump via a temporary fold over the public surface.
    //
    // The `SeenSequenceState` is currently a thin wrapper over
    // `HashMap<[u8;32], u64>` in `peer_gossip.rs`. We add a public
    // iterator on the next change; for now use `as_pairs_for_spool`
    // (a tiny helper added to `peer_gossip.rs` alongside the wire
    // format work). If the helper is missing the watermark spool
    // simply writes an empty `seen=` line which preserves
    // correctness: an empty ledger is the "no bundles seen yet"
    // initial state, which is the worst case for the daemon
    // restart (we'd accept any sequence ≥ 1 from each peer, which
    // is still safe because we have the freshness window).
    for (id, seq) in watermark.seen.iter_pairs_for_spool() {
        entries.push((*id, *seq));
    }
    entries.sort_by_key(|(id, _)| *id);
    let mut first = true;
    for (id, seq) in entries {
        if !first {
            payload.push(',');
        }
        first = false;
        push_hex(&mut payload, &id);
        payload.push(':');
        payload.push_str(&seq.to_string());
    }
    payload.push('\n');
    let temp_path = path.with_extension(format!(
        "tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut temp = options
        .open(&temp_path)
        .map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
    if let Err(err) = temp.write_all(payload.as_bytes()) {
        let _ = fs::remove_file(&temp_path);
        return Err(GossipNodeError::WatermarkIo(err.to_string()));
    }
    if let Err(err) = temp.sync_all() {
        let _ = fs::remove_file(&temp_path);
        return Err(GossipNodeError::WatermarkIo(err.to_string()));
    }
    drop(temp);
    if let Err(err) = fs::rename(&temp_path, path) {
        let _ = fs::remove_file(&temp_path);
        return Err(GossipNodeError::WatermarkIo(err.to_string()));
    }
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        let parent_dir =
            fs::File::open(parent).map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
        parent_dir
            .sync_all()
            .map_err(|err| GossipNodeError::WatermarkIo(err.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // These imports are used only by the `#[cfg(unix)]` transport-backed tests
    // below (the gossip transport is unix-only in this slice — Track Beta), so
    // gate them to match, or they are unused on Windows under `-D warnings`.
    #[cfg(unix)]
    use crate::dataplane_candidates::CandidateSet;
    #[cfg(unix)]
    use crate::gossip_transport::GossipTransport;
    #[cfg(unix)]
    use crate::peer_gossip::mint_bundle_with_timestamp;
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus,
    };
    #[cfg(unix)]
    use std::net::{IpAddr, Ipv4Addr};
    use tempfile::TempDir;

    #[cfg(unix)]
    fn loopback_bind() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
    }

    fn make_node(byte: u8, watermark_dir: &Path) -> GossipNode {
        let signing_key = SigningKey::from_bytes(&[byte; 32]);
        let path = watermark_dir.join(format!("gossip-{byte}.watermark"));
        GossipNode::new(signing_key, Some(path)).expect("node ctor")
    }

    fn hex32(byte: u8) -> String {
        format!("{byte:02x}").repeat(32)
    }

    fn membership_node(
        node_id: &str,
        pubkey_byte: u8,
        capabilities: Vec<RoleCapability>,
    ) -> MembershipNode {
        MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex32(pubkey_byte),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: vec!["tag:servers".to_owned()],
            capabilities,
            joined_at_unix: 100,
            updated_at_unix: 100,
        }
    }

    fn membership_state(nodes: Vec<MembershipNode>) -> MembershipState {
        MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-1".to_owned(),
            epoch: 1,
            nodes,
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex32(0xee),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        }
    }

    #[test]
    fn fresh_node_starts_with_zero_sequence_and_empty_state() {
        let dir = TempDir::new().expect("tempdir");
        let node = make_node(1, dir.path());
        assert_eq!(node.gossip_sequence, 0);
        assert_eq!(node.seen_gossip_sequences.source_count(), 0);
        assert!(node.last_minted_bundle.is_none());
        assert_eq!(node.accepted_count, 0);
        assert_eq!(node.minted_count, 0);
    }

    #[test]
    fn watermark_round_trips_local_sequence_and_seen_ledger() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("g.watermark");
        let mut state = SeenSequenceState::new();
        state.record([0xaau8; 32], 7);
        state.record([0xbbu8; 32], 13);
        let watermark = GossipWatermark {
            local_sequence: 99,
            seen: state,
        };
        write_gossip_watermark(&path, &watermark).expect("write ok");
        let loaded = load_gossip_watermark(&path).expect("load ok");
        assert_eq!(loaded.local_sequence, 99);
        assert_eq!(loaded.seen.highest_accepted(&[0xaau8; 32]), Some(7));
        assert_eq!(loaded.seen.highest_accepted(&[0xbbu8; 32]), Some(13));
    }

    #[test]
    fn load_rejects_wrong_version() {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("g.watermark");
        fs::write(&path, b"version=99\nlocal_sequence=0\nseen=\n").expect("write");
        let err = load_gossip_watermark(&path).expect_err("must reject");
        assert!(matches!(err, GossipNodeError::WatermarkCorrupt(_)));
    }

    fn load_watermark_str(body: &str) -> Result<GossipWatermark, GossipNodeError> {
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("g.watermark");
        fs::write(&path, body.as_bytes()).expect("write");
        load_gossip_watermark(&path)
    }

    fn assert_watermark_corrupt(body: &str, needle: &str) {
        match load_watermark_str(body) {
            Err(GossipNodeError::WatermarkCorrupt(reason)) => assert!(
                reason.contains(needle),
                "expected corrupt reason containing {needle:?}, got {reason:?}"
            ),
            other => panic!("expected WatermarkCorrupt({needle:?}), got {other:?}"),
        }
    }

    #[test]
    fn load_rejects_oversized_watermark_before_parsing() {
        // A multi-MiB file at the spool path must fail closed on size, not be
        // buffered whole. The body need not be structurally valid — the size
        // gate precedes the parse.
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("g.watermark");
        let body = vec![b'x'; MAX_GOSSIP_WATERMARK_BYTES + 1];
        fs::write(&path, &body).expect("write oversized");
        let err = load_gossip_watermark(&path).expect_err("oversized must fail closed");
        assert!(
            matches!(err, GossipNodeError::WatermarkCorrupt(reason) if reason.contains("exceeds maximum size")),
            "expected size-cap rejection, got {err:?}"
        );
    }

    #[test]
    fn load_accepts_watermark_at_size_cap_boundary() {
        // Exactly at the cap must still load (off-by-one guard on the bound).
        let dir = TempDir::new().expect("tempdir");
        let path = dir.path().join("g.watermark");
        let mut body = String::from("version=1\nlocal_sequence=0\nseen=\n");
        // Pad with blank lines (skipped by the parser) up to exactly the cap.
        while body.len() < MAX_GOSSIP_WATERMARK_BYTES {
            body.push('\n');
        }
        assert_eq!(body.len(), MAX_GOSSIP_WATERMARK_BYTES);
        fs::write(&path, body.as_bytes()).expect("write at cap");
        load_gossip_watermark(&path).expect("watermark exactly at the cap must load");
    }

    #[test]
    fn load_rejects_line_missing_separator() {
        assert_watermark_corrupt("version=1\nlocal_sequence", "missing key/value separator");
    }

    #[test]
    fn load_rejects_unknown_key() {
        assert_watermark_corrupt("version=1\nlocal_sequence=0\nrogue=1\n", "unknown key");
    }

    #[test]
    fn load_rejects_non_numeric_local_sequence() {
        assert_watermark_corrupt(
            "version=1\nlocal_sequence=abc\n",
            "local_sequence is not a u64",
        );
    }

    #[test]
    fn load_rejects_missing_local_sequence() {
        assert_watermark_corrupt("version=1\nseen=\n", "missing local_sequence");
    }

    #[test]
    fn load_rejects_seen_entry_without_colon() {
        assert_watermark_corrupt(
            "version=1\nlocal_sequence=0\nseen=deadbeef\n",
            "seen entry missing colon",
        );
    }

    #[test]
    fn load_rejects_seen_id_wrong_length() {
        assert_watermark_corrupt(
            "version=1\nlocal_sequence=0\nseen=ab:5\n",
            "id is not 64 hex chars",
        );
    }

    #[test]
    fn load_rejects_seen_id_non_hex() {
        // 64 ASCII chars that are not valid hex digits.
        let body = format!("version=1\nlocal_sequence=0\nseen={}:5\n", "z".repeat(64));
        assert_watermark_corrupt(&body, "id is not valid hex");
    }

    #[test]
    fn load_rejects_seen_sequence_non_numeric() {
        let body = format!(
            "version=1\nlocal_sequence=0\nseen={}:notanumber\n",
            hex32(0xab)
        );
        assert_watermark_corrupt(&body, "sequence is not a u64");
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn mint_does_not_advance_sequence_when_watermark_persist_fails() {
        // Anti-rewind invariant: the watermark is persisted BEFORE the
        // in-memory sequence advances, so a failed spool write must leave the
        // sequence untouched — never half-advance into a value the daemon
        // didn't commit to disk (which an attacker who could induce a write
        // failure would exploit to replay an already-seen sequence).
        let dir = TempDir::new().expect("tempdir");
        // Point the watermark's parent at a regular FILE, so `create_dir_all`
        // on the spool's parent fails — a deterministic persist failure.
        let blocker = dir.path().join("not-a-dir");
        fs::write(&blocker, b"regular file").expect("write blocker file");
        let mut node = make_node(2, &blocker);
        assert_eq!(node.gossip_sequence, 0);

        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        let mut candidates = CandidateSet::default();
        candidates
            .v4_host
            .push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));

        let result =
            node.maybe_mint_and_broadcast(Instant::now(), 1_700_000_000, candidates, &transport);
        assert!(
            matches!(result, Err(GossipNodeError::WatermarkIo(_))),
            "persist failure must surface as WatermarkIo, got {result:?}"
        );

        // The sequence and mint bookkeeping must be exactly as before the
        // failed attempt — no skip, no phantom mint.
        assert_eq!(node.gossip_sequence, 0, "sequence must not advance");
        assert!(
            node.last_minted_bundle.is_none(),
            "no bundle should be recorded on a failed persist"
        );
        assert_eq!(node.minted_count, 0, "mint count must not advance");
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn watermark_io_error_does_not_leak_state_dir_path() {
        // Privacy/secret-log mandate: a watermark spool i/o failure must not
        // embed the daemon's state-dir layout in its message (the error may be
        // surfaced to shared logs). Use a uniquely-named directory so any leak
        // is unambiguous.
        let dir = TempDir::new().expect("tempdir");
        let secret_marker = "rustynet-secret-statedir-marker";
        let blocker = dir.path().join(secret_marker);
        fs::write(&blocker, b"regular file").expect("write blocker file");
        let mut node = make_node(2, &blocker);

        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        let mut candidates = CandidateSet::default();
        candidates
            .v4_host
            .push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));

        let err = node
            .maybe_mint_and_broadcast(Instant::now(), 1_700_000_000, candidates, &transport)
            .expect_err("persist must fail");
        let rendered = err.to_string();
        assert!(
            !rendered.contains(secret_marker),
            "watermark i/o error must not embed the state-dir path, got: {rendered}"
        );
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn maybe_mint_emits_when_candidates_change_and_persists_sequence() {
        let dir = TempDir::new().expect("tempdir");
        let mut node = make_node(2, dir.path());
        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        let mut candidates = CandidateSet::default();
        candidates
            .v4_host
            .push(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)));
        let bundle = node
            .maybe_mint_and_broadcast(
                Instant::now(),
                1_700_000_000,
                candidates.clone(),
                &transport,
            )
            .expect("mint ok")
            .expect("first mint must emit");
        assert_eq!(bundle.sequence, 1);
        assert_eq!(node.gossip_sequence, 1);
        // Second call with identical candidates and before the
        // heartbeat must NOT mint again.
        let res = node
            .maybe_mint_and_broadcast(Instant::now(), 1_700_000_000, candidates, &transport)
            .expect("second mint ok");
        assert!(res.is_none(), "duplicate mint must be suppressed");
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn rebroadcast_orders_anchor_seed_peers_first() {
        let dir = TempDir::new().expect("tempdir");
        let mut node = make_node(4, dir.path());
        let local = GossipTransport::bind(loopback_bind()).expect("transport");
        let mut ids = Vec::new();
        for byte in [9u8, 3, 7] {
            let key = SigningKey::from_bytes(&[byte; 32]);
            let peer_id = key.verifying_key().to_bytes();
            ids.push((byte, peer_id));
            node.register_peer(
                peer_id,
                key.verifying_key(),
                local.local_addr().expect("addr"),
            );
        }
        let id3 = ids.iter().find(|(byte, _)| *byte == 3).unwrap().1;
        let id7 = ids.iter().find(|(byte, _)| *byte == 7).unwrap().1;
        let id9 = ids.iter().find(|(byte, _)| *byte == 9).unwrap().1;
        let mut anchor_ids = vec![id3, id7];
        anchor_ids.sort_unstable();
        node.set_anchor_gossip_seed_peer_ids(anchor_ids.iter().copied());
        let mut expected = anchor_ids;
        expected.push(id9);

        let ordered = node.ordered_peer_ids_for_rebroadcast(None, None);
        assert_eq!(ordered, expected);

        let excluding_sender = node.ordered_peer_ids_for_rebroadcast(None, Some(id3));
        assert_eq!(excluding_sender, vec![id7, id9]);
    }

    #[test]
    fn anchor_runtime_view_uses_signed_capabilities_and_lex_min_authority() {
        let state = membership_state(vec![
            membership_node(
                "node-z",
                0x11,
                vec![RoleCapability::AnchorPortMappingAuthoritative],
            ),
            membership_node(
                "node-a",
                0x22,
                vec![
                    RoleCapability::AnchorGossipSeed,
                    RoleCapability::AnchorPortMappingAuthoritative,
                ],
            ),
            membership_node("node-m", 0x33, vec![RoleCapability::AnchorGossipSeed]),
        ]);
        let view = anchor_runtime_view_from_membership(&state);
        assert_eq!(
            view.port_mapping_authority_node_id,
            Some("node-a".to_owned())
        );
        assert_eq!(
            view.anchor_gossip_seed_peer_ids,
            vec![[0x22u8; 32], [0x33u8; 32]]
        );
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn ingest_rejects_self_origin_bundle() {
        let dir = TempDir::new().expect("tempdir");
        let mut node = make_node(3, dir.path());
        let key = SigningKey::from_bytes(&[3u8; 32]); // same as node
        let bundle =
            mint_bundle_with_timestamp(&key, 1, 1_700_000_000, CandidateSet::default()).unwrap();
        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        let err = node
            .ingest_inbound_bundle(None, bundle, &transport, 1_700_000_000)
            .expect_err("must reject self-origin");
        assert!(matches!(
            err,
            GossipNodeError::Bundle(GossipError::UnknownSource)
        ));
        assert_eq!(node.rejected_counts.get("self_origin"), Some(&1));
    }

    #[test]
    fn revoked_peer_ids_from_membership_filters_by_status() {
        let state = membership_state(vec![
            membership_node("node-active", 0x11, vec![RoleCapability::Anchor]),
            {
                let mut n = membership_node("node-revoked", 0x22, vec![RoleCapability::Anchor]);
                n.status = MembershipNodeStatus::Revoked;
                n
            },
            {
                let mut n = membership_node("node-quarantined", 0x33, vec![RoleCapability::Anchor]);
                n.status = MembershipNodeStatus::Quarantined;
                n
            },
        ]);
        let revoked = revoked_peer_ids_from_membership(&state);
        assert_eq!(revoked, vec![[0x22u8; 32], [0x33u8; 32]]);
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn ingest_rejects_revoked_source_bundle() {
        // GM-1 / RSA-0034: a bundle that passes signature/freshness/sequence
        // must still be rejected if signed membership marks the source
        // Revoked — defense-in-depth alongside the dataplane ACL revocation
        // check (DD-03/RSA-0007).
        let dir = TempDir::new().expect("tempdir");
        let mut node = make_node(4, dir.path());
        let sender_key = SigningKey::from_bytes(&[7u8; 32]);
        let sender_id = sender_key.verifying_key().to_bytes();
        node.register_peer(sender_id, sender_key.verifying_key(), loopback_bind());
        node.set_revoked_peer_ids([sender_id]);
        let bundle =
            mint_bundle_with_timestamp(&sender_key, 1, 1_700_000_000, CandidateSet::default())
                .unwrap();
        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        let err = node
            .ingest_inbound_bundle(None, bundle, &transport, 1_700_000_000)
            .expect_err("must reject revoked source");
        assert!(matches!(
            err,
            GossipNodeError::Bundle(GossipError::RevokedSource)
        ));
        assert_eq!(node.rejected_counts.get("revoked_source"), Some(&1));
        assert!(
            !node.applied_endpoints.contains_key(&sender_id),
            "a revoked source's endpoints must never be admitted"
        );
    }

    #[cfg(unix)] // uses the unix-only GossipTransport (Track Beta: windows path queued)
    #[test]
    fn ingest_accepts_active_source_not_vacuously_revoked() {
        // Anti-vacuous: an otherwise-identical bundle from a NON-revoked
        // known peer must still be accepted — proves the check above isn't
        // "always reject" and doesn't regress the ordinary accept path.
        let dir = TempDir::new().expect("tempdir");
        let mut node = make_node(5, dir.path());
        let sender_key = SigningKey::from_bytes(&[8u8; 32]);
        let sender_id = sender_key.verifying_key().to_bytes();
        node.register_peer(sender_id, sender_key.verifying_key(), loopback_bind());
        let bundle =
            mint_bundle_with_timestamp(&sender_key, 1, 1_700_000_000, CandidateSet::default())
                .unwrap();
        let transport = GossipTransport::bind(loopback_bind()).expect("transport");
        node.ingest_inbound_bundle(None, bundle, &transport, 1_700_000_000)
            .expect("a non-revoked known peer's bundle must be accepted");
        assert!(node.applied_endpoints.contains_key(&sender_id));
    }
}
