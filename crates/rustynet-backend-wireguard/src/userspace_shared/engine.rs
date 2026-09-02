use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::fs;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rustynet_backend_api::{BackendError, NodeId, PeerConfig, SocketEndpoint};
use zeroize::{Zeroize, Zeroizing};

#[cfg_attr(not(test), allow(dead_code))]
const MAX_ENCRYPTED_PACKET_BYTES: usize = 65_535 + 32;
const MAX_DECRYPTED_PACKET_BYTES: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedPeerCiphertextIngress {
    pub(crate) node_id: Option<NodeId>,
    pub(crate) local_addr: SocketAddr,
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
    pub(crate) transport_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RecordedTunnelPlaintextPacket {
    pub(crate) node_id: NodeId,
    pub(crate) packet: Vec<u8>,
    pub(crate) transport_generation: u64,
}

/// Sink for immediately dispatching per-frame engine processing results —
/// outbound ciphertext (network send) and inbound plaintext (TUN write) —
/// as boringtun produces them, instead of collecting them into an owned
/// outcome buffer that the caller copies out of and applies later. The
/// slice handed to each method is BORROWED from the engine's own scratch
/// buffers (`decrypt_scratch` / `decrypt_follow_up_scratch` /
/// `encrypt_scratch`); implementations must not retain it past the call.
/// Generic (not `dyn`) at every call site so dispatch monomorphizes into a
/// direct call on this per-packet hot path.
pub(crate) trait EngineIoSink {
    /// Send one outbound WireGuard ciphertext datagram to `remote_addr`.
    fn send_ciphertext(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<(), BackendError>;
    /// Write one decrypted plaintext packet to the local TUN device.
    fn write_plaintext(&mut self, payload: &[u8]) -> Result<(), BackendError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigurePeerDisposition {
    Added,
    Replaced,
    /// Only the peer's ENDPOINT changed, so it was moved in place and the live
    /// session was kept.
    ///
    /// A WireGuard session is keyed by the two static keys, not by the address
    /// it is reached at — roaming is a first-class part of the protocol, and
    /// `update_peer_endpoint` already relocates a peer without disturbing its
    /// tunnel. Rebuilding on an endpoint change therefore destroyed a perfectly
    /// valid session, and (via the runtime's `Replaced` arm) its handshake
    /// record with it. That is what kept the network-flap stage from ever
    /// observing recovery: after the block lifted, the re-race supplied fresh
    /// endpoints and each one wiped the record as fast as a handshake could
    /// write it (QH-51).
    EndpointMoved,
    /// The peer was already configured with identical material, so nothing was
    /// rebuilt and the live session was left untouched.
    ///
    /// This exists because `Replaced` used to be returned for ANY re-configure
    /// of an existing peer — it was decided purely by "did this node id already
    /// have an endpoint" — while `configure_peer` unconditionally built a fresh
    /// `Tunn`. A reconcile pass that re-applied an unchanged peer therefore tore
    /// down and rebuilt the crypto session every cycle, and the runtime, seeing
    /// `Replaced`, cleared that peer's handshake telemetry along with it.
    ///
    /// The visible effect was a node whose liveness metrics were permanently
    /// dead while traffic flowed perfectly well: `path_live_peer_count=0` and no
    /// readable handshake age, because each rebuild re-handshaked and the record
    /// never survived long enough to be read (QH-51).
    Unchanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) struct EngineStats {
    pub(crate) bytes_tx: u64,
    pub(crate) bytes_rx: u64,
}

pub(crate) struct UserspaceEngine {
    local_static_private: StaticSecret,
    #[allow(dead_code)]
    local_static_public: PublicKey,
    next_tunnel_index: u32,
    peer_states: BTreeMap<NodeId, PeerEngineState>,
    /// Reverse index for inbound dispatch: configured endpoint → the ordered
    /// set of peers currently pinned to that endpoint. Maintained in exact
    /// lockstep with `peer_states` by `configure_peer` /
    /// `update_peer_endpoint` / `remove_peer` (`link_endpoint` /
    /// `unlink_endpoint`), replacing the former per-packet linear scan.
    ///
    /// Duplicate-endpoint tie-break parity: the old scan iterated
    /// `peer_states` (a `BTreeMap` in ascending `NodeId` order) and took the
    /// FIRST match, so peers sharing an endpoint resolved to the LOWEST
    /// `NodeId`. Storing the full `BTreeSet<NodeId>` per endpoint and reading
    /// `.first()` reproduces that tie-break by construction — including after
    /// the winning peer is removed, when the next-lowest sharer becomes the
    /// answer exactly as a fresh scan would find. Empty sets are removed so
    /// index keys are precisely the endpoints with at least one peer.
    endpoint_index: BTreeMap<SocketAddr, BTreeSet<NodeId>>,
    /// Reverse index for inbound demux by the canonical WireGuard receiver
    /// index: local session index (`tunnel_index`) → the peer whose live
    /// `Tunn` was built with it. Handshake responses, cookie replies, and
    /// data packets echo `receiver_idx >> 8 == tunnel_index` back, so this
    /// map routes a reply to the tunnel that initiated the handshake
    /// regardless of the datagram source address. Maintained in exact
    /// lockstep with `peer_states` by `configure_peer` / `remove_peer` (the
    /// only two mutators that touch `tunnel_index`): every live peer's
    /// `tunnel_index` has exactly one entry and no entry names a peer that
    /// is not live — a bijection, asserted by
    /// `verify_receiver_index_consistent` at every mutator boundary in
    /// debug/test builds and by the mutation fuzz tests.
    ///
    /// Stale entries are retired, never reassigned: the allocator
    /// (`allocate_tunnel_index`) is monotonic and never reuses an index, so
    /// a retired index resolving to `None` (falling back to the endpoint
    /// match) is the correct answer forever.
    receiver_index: HashMap<u32, NodeId>,
    /// Count of inbound datagrams whose receiver-index entry named a peer
    /// with no live state. Unreachable while every mutator maintains the
    /// map in lockstep (`set_tunnel_index` refuses collisions and runs
    /// before any other mutation), so a nonzero value would indicate
    /// internal state corruption; the packet path fails closed on it —
    /// the datagram is dropped and counted, never re-attributed through
    /// the endpoint match and never panicked over (a panic here would tear
    /// down the engine's single worker thread and every live session).
    receiver_index_divergence_drops: u64,
    path_quality: BTreeMap<NodeId, PeerPathQuality>,
    recorded_peer_ciphertext_ingress: Vec<RecordedPeerCiphertextIngress>,
    recorded_tunnel_plaintext_packets: Vec<RecordedTunnelPlaintextPacket>,
    // Long-lived per-engine scratch buffers reused across every packet instead
    // of allocating+zeroing a fresh 64 KiB Vec per frame. boringtun's
    // `encapsulate`/`decapsulate` write out-of-place into these and the engine
    // copies the (small) result out before the next packet reuses the buffer,
    // so reuse is sound. `decrypt_scratch` holds the initial inbound result
    // while `decrypt_follow_up_scratch` services the mandatory drain loop — two
    // distinct buffers so the in-flight `TunnResult` borrow never aliases the
    // drain buffer. Owned by the single worker thread; never shared.
    decrypt_scratch: Vec<u8>,
    decrypt_follow_up_scratch: Vec<u8>,
    encrypt_scratch: Vec<u8>,
}

struct PeerEngineState {
    #[allow(dead_code)]
    peer_static_public: PublicKey,
    endpoint: SocketAddr,
    allowed_ips: Vec<AllowedIpNetwork>,
    tunnel: Tunn,
    /// Local session index handed to `Tunn::new` (boringtun stores it as
    /// `index << 8`). Inbound handshake responses, cookie replies, and data
    /// packets echo it back in their `receiver_idx` (`receiver_idx >> 8 ==
    /// tunnel_index`), so it is the canonical WireGuard demux key: it routes a
    /// peer's reply to the tunnel that initiated the handshake regardless of the
    /// datagram source address. Matching on source address alone silently drops
    /// a handshake response whenever the peer's stored endpoint does not exactly
    /// equal the datagram source, which stalls every tunnel whose endpoint is
    /// not authoritatively pinned (e.g. non-exit mesh peers).
    tunnel_index: u32,
}

/// FIS-0004: engine-local per-peer path-quality estimator. The rich state
/// stays inside the backend crate; only the coarse [`PathHealth`] verdict
/// and the raw [`PeerPathSample`] cross the backend-api boundary.
#[derive(Debug, Clone, Copy, Default)]
struct PeerPathQuality {
    /// Consecutive rekey windows with EWMA loss above threshold
    /// (hysteresis counter, saturating).
    loss_degraded_windows: u8,
    /// Total windows ever ingested (health is Unknown until >= 1).
    windows_ingested: u8,
    /// RFC 6298 smoothed RTT / RTT variation, milliseconds.
    srtt_ms: Option<u32>,
    rttvar_ms: Option<u32>,
    /// Dedupe guard: evidence is consumed once per handshake advance
    /// (boringtun's loss EWMA and RTT sample change only per rekey, so
    /// correlated 1s polls must not re-count one window).
    last_ingested_handshake_unix: Option<u64>,
}

impl PeerPathQuality {
    /// 2% EWMA loss = degraded window (TCP-Reno-style debounced threshold,
    /// not a rate controller).
    const LOSS_THRESHOLD: f32 = 0.02;
    /// Two consecutive degraded windows flag Degrading; one clean window
    /// steps back toward Healthy.
    const DEGRADE_WINDOWS: u8 = 2;
    /// RFC 6298 constants (Jacobson/Karels).
    const RTT_ALPHA: f32 = 0.125;
    const RTT_BETA: f32 = 0.25;

    fn ingest_window(&mut self, loss: f32, rtt_sample_ms: Option<u32>) {
        self.windows_ingested = self.windows_ingested.saturating_add(1);
        if loss > Self::LOSS_THRESHOLD {
            self.loss_degraded_windows = self
                .loss_degraded_windows
                .saturating_add(1)
                .min(Self::DEGRADE_WINDOWS + 1);
        } else {
            self.loss_degraded_windows = self.loss_degraded_windows.saturating_sub(1);
        }
        if let Some(sample) = rtt_sample_ms {
            match self.srtt_ms {
                None => {
                    self.srtt_ms = Some(sample);
                    self.rttvar_ms = Some(sample / 2);
                }
                Some(srtt) => {
                    let abs_diff = srtt.abs_diff(sample);
                    let rttvar = self.rttvar_ms.unwrap_or(sample / 2);
                    self.rttvar_ms = Some(
                        ((1.0 - Self::RTT_BETA) * rttvar as f32 + Self::RTT_BETA * abs_diff as f32)
                            as u32,
                    );
                    self.srtt_ms = Some(
                        ((1.0 - Self::RTT_ALPHA) * srtt as f32 + Self::RTT_ALPHA * sample as f32)
                            as u32,
                    );
                }
            }
        }
    }

    fn health(&self) -> rustynet_backend_api::PathHealth {
        if self.windows_ingested == 0 {
            // Zero evidence is never fabricated Healthy.
            rustynet_backend_api::PathHealth::Unknown
        } else if self.loss_degraded_windows >= Self::DEGRADE_WINDOWS {
            rustynet_backend_api::PathHealth::Degrading
        } else if self.loss_degraded_windows == 0 {
            rustynet_backend_api::PathHealth::Healthy
        } else {
            rustynet_backend_api::PathHealth::Unknown
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllowedIpNetwork {
    network: IpAddr,
    prefix_len: u8,
}

impl UserspaceEngine {
    /// On-disk bound for the base64 private-key file. Checked at READ time so
    /// an oversized or special-file path cannot drive unbounded allocation
    /// before the decoder rejects the content.
    pub(crate) const MAX_PRIVATE_KEY_FILE_BYTES: u64 = 4096;

    pub(crate) fn from_private_key_file(path: &Path) -> Result<Self, BackendError> {
        // Secret-material hygiene: the on-disk base64 blob and the decoded 32-byte
        // scalar are WireGuard static private key material. Wrap intermediates in
        // `Zeroizing` so any heap-resident copy is overwritten when dropped, and
        // explicitly zeroize the stack-resident `[u8; 32]` after handing a copy to
        // `StaticSecret::from` (the array is `Copy`; the cast does not consume).
        //
        // The read itself is bounded at READ time (consume at most cap + 1), not
        // derived from stat metadata: a racing writer cannot grow the file past
        // the bound between validation and buffering.
        let key_file = fs::File::open(path).map_err(|err| {
            BackendError::internal(format!(
                "userspace-shared private key open failed for {}: {err}",
                path.display()
            ))
        })?;
        let mut raw_private_key = Zeroizing::new(Vec::new());
        key_file
            .take(Self::MAX_PRIVATE_KEY_FILE_BYTES + 1)
            .read_to_end(&mut raw_private_key)
            .map_err(|err| {
                BackendError::internal(format!(
                    "userspace-shared private key read failed for {}: {err}",
                    path.display()
                ))
            })?;
        if raw_private_key.len() as u64 > Self::MAX_PRIVATE_KEY_FILE_BYTES {
            return Err(BackendError::internal(format!(
                "userspace-shared private key file exceeds {} byte cap; refusing to read {}",
                Self::MAX_PRIVATE_KEY_FILE_BYTES,
                path.display()
            )));
        }
        let encoded_vec = std::mem::take(&mut *raw_private_key);
        drop(raw_private_key);
        let encoded_string = String::from_utf8(encoded_vec).map_err(|err| {
            BackendError::internal(format!(
                "userspace-shared private key file is not valid UTF-8 for {}: {err}",
                path.display()
            ))
        })?;
        let encoded_private_key = Zeroizing::new(encoded_string);
        let trimmed_private_key = encoded_private_key.trim();
        let decoded_private_key: Zeroizing<Vec<u8>> = Zeroizing::new(
            BASE64_STANDARD
                .decode(trimmed_private_key.as_bytes())
                .map_err(|err| {
                    BackendError::internal(format!(
                        "userspace-shared private key decode failed for {}: {err}",
                        path.display()
                    ))
                })?,
        );
        if decoded_private_key.len() != 32 {
            return Err(BackendError::internal(format!(
                "userspace-shared private key length invalid for {}: expected 32 bytes after base64 decode, got {}",
                path.display(),
                decoded_private_key.len()
            )));
        }
        // CRY-06 convention (mirrors rustynet-crypto's WeakMaterial rejects):
        // an all-zero static private key is a publicly derivable identity that
        // a blank or corrupted key file would mint. Refuse it instead of
        // bringing up a tunnel an attacker can impersonate.
        if decoded_private_key.iter().all(|&byte| byte == 0) {
            return Err(BackendError::internal(format!(
                "userspace-shared private key is degenerate (all zeros) for {}; refusing to load weak key material",
                path.display()
            )));
        }
        let mut private_key_bytes: [u8; 32] = [0u8; 32];
        private_key_bytes.copy_from_slice(&decoded_private_key);

        let local_static_private = StaticSecret::from(private_key_bytes);
        private_key_bytes.zeroize();
        let local_static_public = PublicKey::from(&local_static_private);

        Ok(Self {
            local_static_private,
            local_static_public,
            next_tunnel_index: 1,
            peer_states: BTreeMap::new(),
            endpoint_index: BTreeMap::new(),
            receiver_index: HashMap::new(),
            receiver_index_divergence_drops: 0,
            path_quality: BTreeMap::new(),
            recorded_peer_ciphertext_ingress: Vec::new(),
            recorded_tunnel_plaintext_packets: Vec::new(),
            decrypt_scratch: vec![0u8; MAX_DECRYPTED_PACKET_BYTES],
            decrypt_follow_up_scratch: vec![0u8; MAX_DECRYPTED_PACKET_BYTES],
            encrypt_scratch: vec![0u8; MAX_ENCRYPTED_PACKET_BYTES],
        })
    }

    pub(crate) fn configure_peer(
        &mut self,
        peer: &PeerConfig,
    ) -> Result<ConfigurePeerDisposition, BackendError> {
        let peer_static_public = PublicKey::from(peer.public_key);
        let endpoint = socket_addr_from_endpoint(peer.endpoint);
        let allowed_ips = peer
            .allowed_ips
            .iter()
            .map(|cidr| AllowedIpNetwork::parse(cidr))
            .collect::<Result<Vec<_>, _>>()?;

        // Re-applying identical material must NOT disturb the live session.
        //
        // Everything compared here is what a `Tunn` is built from, so if all of
        // it matches, rebuilding would produce a session equivalent to the one
        // already running — at the cost of discarding its handshake state and,
        // via the runtime's `Replaced` arm, its handshake telemetry. Comparison
        // is exact rather than approximate: a difference in ANY of the three
        // falls through to the rebuild path below.
        //
        // Note the allowed-IP comparison is ORDER-SENSITIVE, deliberately. The
        // stored form is the parsed sequence, and treating a reordering as
        // "unchanged" would silently keep a session whose routing table entry
        // the caller had just rewritten. A reorder is rare and a rebuild is
        // correct-but-wasteful; the reverse error would be correctness-losing.
        if let Some(existing) = self.peer_states.get(&peer.node_id)
            && existing.peer_static_public == peer_static_public
            && existing.allowed_ips == allowed_ips
        {
            if existing.endpoint == endpoint {
                return Ok(ConfigurePeerDisposition::Unchanged);
            }
            // Same keys, same routing, different address: this is roaming, not a
            // new peer. Move it in place exactly as `update_peer_endpoint` does
            // and keep the session — rebuilding here would discard a live
            // tunnel, and with it the handshake record, for a change WireGuard
            // is designed to absorb.
            self.update_peer_endpoint(&peer.node_id, peer.endpoint)?;
            return Ok(ConfigurePeerDisposition::EndpointMoved);
        }

        let tunnel_index = self.allocate_tunnel_index()?;
        let tunnel = Tunn::new(
            self.local_static_private.clone(),
            peer_static_public,
            None,
            // Persistent keepalive, from the peer's own configuration.
            //
            // This argument was hardcoded `None`, so the userspace engine
            // silently discarded whatever the caller asked for: WireGuard sends
            // nothing when it has nothing to send, and with no keepalive a peer
            // never speaks first. After a disruption neither side re-handshakes
            // until something generates traffic, which is why the network-flap
            // stage could induce a disruption and then watch for three minutes
            // without ever seeing the tunnel come back (QH-51).
            //
            // The kernel backend passes this through to `wg set ...
            // persistent-keepalive` and the privileged helper has validated that
            // argument since FIS-0015, so the field was carried end to end
            // everywhere EXCEPT here, where it was dropped one call short of the
            // tunnel it configures.
            peer.persistent_keepalive_secs,
            tunnel_index,
            None,
        );

        // All fallible steps are done; from here the peer table and the
        // reverse indexes mutate together so they can never diverge.
        //
        // Receiver-index write order (the invariant this protects): the
        // fallible `set_tunnel_index` runs FIRST and before any other
        // mutation — it refuses (failing the whole call, engine untouched)
        // if the freshly allocated index already maps to a different peer.
        // Under the monotonic allocator that refusal is unreachable, so
        // hitting it would mean internal corruption, not a re-assignable
        // slot. Only after it succeeds does the old peer's index get
        // retired, the state replaced, and the endpoint entries relinked.
        let previous = self
            .peer_states
            .get(&peer.node_id)
            .map(|existing| (existing.endpoint, existing.tunnel_index));
        let disposition = if previous.is_some() {
            ConfigurePeerDisposition::Replaced
        } else {
            ConfigurePeerDisposition::Added
        };
        self.set_tunnel_index(&peer.node_id, tunnel_index)?;
        if let Some((_previous_endpoint, previous_tunnel_index)) = &previous {
            debug_assert_ne!(
                *previous_tunnel_index, tunnel_index,
                "allocate_tunnel_index is monotonic and must never hand out a live index"
            );
            self.clear_tunnel_index(*previous_tunnel_index);
        }
        self.peer_states.insert(
            peer.node_id.clone(),
            PeerEngineState {
                peer_static_public,
                endpoint,
                allowed_ips,
                tunnel,
                tunnel_index,
            },
        );
        if let Some((previous_endpoint, _)) = previous {
            self.unlink_endpoint(previous_endpoint, &peer.node_id);
        }
        self.link_endpoint(endpoint, peer.node_id.clone());
        #[cfg(any(test, debug_assertions))]
        self.verify_receiver_index_consistent();
        Ok(disposition)
    }

    pub(crate) fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        let new_endpoint = socket_addr_from_endpoint(endpoint);
        let Some(peer_state) = self.peer_states.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        let previous_endpoint = peer_state.endpoint;
        peer_state.endpoint = new_endpoint;
        self.unlink_endpoint(previous_endpoint, node_id);
        self.link_endpoint(new_endpoint, node_id.clone());
        Ok(())
    }

    pub(crate) fn initiate_handshake<S: EngineIoSink>(
        &mut self,
        node_id: &NodeId,
        transport_generation: u64,
        force_resend: bool,
        sink: &mut S,
    ) -> Result<Option<(NodeId, u64)>, BackendError> {
        let Some(peer_state) = self.peer_states.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        // Reuse the long-lived engine-owned scratch buffer instead of
        // allocating a fresh `MAX_ENCRYPTED_PACKET_BYTES` vector on every
        // handshake initiation. The field-level borrows below are disjoint
        // (`peer_states` vs `encrypt_scratch` vs
        // `recorded_tunnel_plaintext_packets`), mirroring
        // `inject_plaintext_packet`. `format_handshake_initiation` reports
        // only the bytes it wrote, so stale scratch content beyond the
        // reported slice is never observable — the emitted handshake is
        // byte-identical to the previous per-call-buffer behavior.
        let initial_result = peer_state
            .tunnel
            .format_handshake_initiation(&mut self.encrypt_scratch, force_resend);
        drive_outbound_result(
            node_id,
            peer_state,
            transport_generation,
            initial_result,
            &mut self.recorded_tunnel_plaintext_packets,
            sink,
        )
    }

    /// Drive boringtun's periodic timers for every configured peer.
    ///
    /// `Tunn::update_timers` is what advances boringtun's internal clock
    /// (`TimeCurrent`), and every other timer is recorded relative to it. It
    /// also emits persistent keepalives and the rekey handshake. Nothing in
    /// this workspace called it, which had three consequences on the
    /// userspace-shared backends:
    ///
    /// - `time_since_last_handshake` is computed as
    ///   `time_since_tun_start - TimeSessionEstablished`, and with the clock
    ///   frozen that second term stayed at its initial value. The reported
    ///   handshake age therefore grew without bound, so a peer that had just
    ///   completed a handshake still read as ancient and never counted as
    ///   live.
    /// - persistent keepalives were never emitted, so NAT bindings were left
    ///   to expire on their own.
    /// - the periodic rekey was never driven.
    ///
    /// Returns any handshake observed while ticking so the caller can record
    /// it, matching `initiate_handshake`'s contract.
    pub(crate) fn update_peer_timers<S: EngineIoSink>(
        &mut self,
        transport_generation: u64,
        sink: &mut S,
    ) -> Result<Vec<(NodeId, u64)>, BackendError> {
        let mut observed = Vec::new();
        // Reuse the engine-owned scratch buffer for every peer's timer-driven
        // packet (keepalive/rekey initiation) instead of allocating a fresh
        // `MAX_ENCRYPTED_PACKET_BYTES` vector per tick. The field-level
        // borrows inside the loop are disjoint (`peer_states` vs
        // `encrypt_scratch` vs `recorded_tunnel_plaintext_packets`), and each
        // `update_timers` call completes before the next peer borrows the
        // scratch, so no live buffer is aliased. Only the bytes reported by
        // boringtun are ever sent, so stale scratch content beyond the
        // reported slice is never observable.
        let node_ids: Vec<NodeId> = self.peer_states.keys().cloned().collect();
        for node_id in node_ids {
            let Some(peer_state) = self.peer_states.get_mut(&node_id) else {
                continue;
            };
            let result = peer_state.tunnel.update_timers(&mut self.encrypt_scratch);
            // A timer tick can legitimately produce nothing (Done), a packet to
            // send (keepalive or rekey initiation), or a connection-expired
            // error. `drive_outbound_result` already routes each of those and
            // reports any handshake it observes.
            if let Some(handshake) = drive_outbound_result(
                &node_id,
                peer_state,
                transport_generation,
                result,
                &mut self.recorded_tunnel_plaintext_packets,
                sink,
            )? {
                observed.push(handshake);
            }
        }
        Ok(observed)
    }

    pub(crate) fn current_peer_endpoint(&self, node_id: &NodeId) -> Option<SocketEndpoint> {
        self.peer_states
            .get(node_id)
            .map(|peer_state| SocketEndpoint {
                addr: peer_state.endpoint.ip(),
                port: peer_state.endpoint.port(),
            })
    }

    pub(crate) fn has_peer(&self, node_id: &NodeId) -> bool {
        self.peer_states.contains_key(node_id)
    }

    /// Fail-closed-adjacent check feeding `reject_round_trip_target`: true iff
    /// at least one configured peer's endpoint equals `remote_addr`. Backed
    /// by `endpoint_index`, which is maintained in lockstep with
    /// `peer_states` by every mutator, so `contains_key` here is exactly
    /// equivalent to the former `peer_states.values().any(..)` scan — same
    /// answer, O(log n) instead of O(peers).
    pub(crate) fn has_endpoint(&self, remote_addr: SocketAddr) -> bool {
        self.endpoint_index.contains_key(&remote_addr)
    }

    pub(crate) fn remove_peer(&mut self, node_id: &NodeId) -> bool {
        self.path_quality.remove(node_id);
        let removed = match self.peer_states.remove(node_id) {
            Some(removed_state) => {
                // Retire the peer's receiver-index entry beside its endpoint
                // entries: a retired index must resolve to nothing forever,
                // never to whichever peer a naive reuse would pick.
                self.clear_tunnel_index(removed_state.tunnel_index);
                // If this peer was the lowest-NodeId holder of a shared
                // endpoint, dropping it from the per-endpoint set promotes
                // the next-lowest sharer — the same answer a fresh linear
                // scan over the remaining peers would produce.
                self.unlink_endpoint(removed_state.endpoint, node_id);
                true
            }
            None => false,
        };
        #[cfg(any(test, debug_assertions))]
        self.verify_receiver_index_consistent();
        removed
    }

    /// Add `node_id` to the reverse-index entry for `endpoint`.
    fn link_endpoint(&mut self, endpoint: SocketAddr, node_id: NodeId) {
        self.endpoint_index
            .entry(endpoint)
            .or_default()
            .insert(node_id);
    }

    /// Remove `node_id` from the reverse-index entry for `endpoint`,
    /// dropping the entry entirely once no peer uses that endpoint.
    fn unlink_endpoint(&mut self, endpoint: SocketAddr, node_id: &NodeId) {
        if let Some(nodes) = self.endpoint_index.get_mut(&endpoint) {
            nodes.remove(node_id);
            if nodes.is_empty() {
                self.endpoint_index.remove(&endpoint);
            }
        }
    }

    pub(crate) fn process_inbound_ciphertext<S: EngineIoSink>(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        payload: &[u8],
        transport_generation: u64,
        sink: &mut S,
    ) -> Result<Option<(NodeId, u64)>, BackendError> {
        // Dispatch by the canonical WireGuard receiver index first (handshake
        // responses, cookie replies, and data packets carry it) and fall back to
        // the source-address/endpoint match for handshake inits (which carry no
        // receiver index) and any packet whose index has no live tunnel. This is
        // what lets a non-exit peer's handshake response reach the tunnel that
        // initiated it even before that peer's endpoint is authoritatively pinned.
        //
        // The index extraction is a pure parse over the payload; the map lookup
        // happens after the split borrow below as a `&NodeId` straight out of
        // `receiver_index` — no clone on the hit path.
        let tunnel_index = Self::extract_tunnel_index(payload);

        // Unbounded-growth guard: `recorded_peer_ciphertext_ingress` is a test-only
        // observability buffer; persisting every datagram in production would let an
        // attacker exhaust memory via a packet flood and would also retain a
        // long-lived plaintext+ciphertext history that the runtime never reads. The
        // match this records is recomputed with its own (test-only, cfg'd-out of
        // release builds) lookup + clone; nothing mutates the peer table or either
        // reverse index between here and the production dispatch below, so it is
        // guaranteed to agree with the production match.
        #[cfg(not(test))]
        {
            let _ = local_addr;
            let _ = transport_generation;
        }

        // Split-borrow: `peer_states` (mutable) and the two reverse indexes
        // (`receiver_index`, `endpoint_index` — read-only here) are disjoint
        // fields of `Self`, so borrowing them independently lets the dispatch
        // below hand back a `&NodeId` that feeds `peer_states.get_mut`
        // directly, with no clone.
        let Self {
            peer_states,
            endpoint_index,
            receiver_index,
            receiver_index_divergence_drops,
            #[cfg(test)]
            recorded_peer_ciphertext_ingress,
            recorded_tunnel_plaintext_packets,
            decrypt_scratch,
            decrypt_follow_up_scratch,
            ..
        } = self;

        #[cfg(test)]
        {
            let _ = local_addr;
            let recorded_match = tunnel_index
                .and_then(|index| Self::receiver_index_lookup(receiver_index, index))
                .cloned()
                .or_else(|| Self::endpoint_index_lookup(endpoint_index, remote_addr).cloned());
            recorded_peer_ciphertext_ingress.push(RecordedPeerCiphertextIngress {
                node_id: recorded_match,
                local_addr,
                remote_addr,
                payload: payload.to_vec(),
                transport_generation,
            });
        }

        let mapped =
            tunnel_index.and_then(|index| Self::receiver_index_lookup(receiver_index, index));
        let node_id: Option<&NodeId> = match mapped {
            Some(node_id) if peer_states.contains_key(node_id) => Some(node_id),
            Some(_) => {
                // The index named a peer whose live state is gone. Unreachable
                // while every mutator maintains both structures in lockstep,
                // so a hit here means internal state corruption. Fail closed:
                // count it and DROP the datagram. It is deliberately NOT
                // re-attributed through the endpoint match — a datagram that
                // claims a session we no longer hold must not be steered to
                // whichever peer shares its source address — and it never
                // panics or asserts in any build: a panic here would kill the
                // engine's single worker thread and every live session.
                *receiver_index_divergence_drops += 1;
                return Ok(None);
            }
            None => Self::endpoint_index_lookup(endpoint_index, remote_addr),
        };
        let Some(node_id) = node_id else {
            return Ok(None);
        };
        // The dispatch above guarantees `node_id` is live (hit arm checked
        // `contains_key`; both fallback arms read it out of `endpoint_index`,
        // which is maintained in lockstep with `peer_states`). The guard form
        // is kept deliberately: the packet path must never panic, because the
        // engine's worker thread dies with it.
        let Some(peer_state) = peer_states.get_mut(node_id) else {
            return Ok(None);
        };
        let initial_result =
            peer_state
                .tunnel
                .decapsulate(Some(remote_addr.ip()), payload, decrypt_scratch);
        drive_inbound_result(
            node_id,
            peer_state,
            remote_addr,
            transport_generation,
            initial_result,
            recorded_tunnel_plaintext_packets,
            decrypt_follow_up_scratch,
            sink,
        )
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn inject_plaintext_packet<S: EngineIoSink>(
        &mut self,
        packet: &[u8],
        transport_generation: u64,
        sink: &mut S,
    ) -> Result<Option<(NodeId, u64)>, BackendError> {
        let Some(dst_addr) = Tunn::dst_address(packet) else {
            return Err(BackendError::invalid_input(
                "plaintext packet does not contain a valid IPv4/IPv6 destination address",
            ));
        };
        let node_id = self.select_peer_for_destination(dst_addr).ok_or_else(|| {
            BackendError::invalid_input(
                "no configured peer allowed IP matches the plaintext packet destination",
            )
        })?;

        let Self {
            peer_states,
            recorded_tunnel_plaintext_packets,
            encrypt_scratch,
            ..
        } = self;
        let peer_state = peer_states
            .get_mut(&node_id)
            .expect("selected peer state should exist");
        // Reuse the long-lived scratch buffer; grow only if a packet ever needs
        // more than the standard ceiling (it cannot on this path — the TUN/UDP
        // read buffers cap at 65 535 — but the resize preserves byte-identical
        // behavior with the previous `.max(packet.len() + 32)` sizing).
        let needed = MAX_ENCRYPTED_PACKET_BYTES.max(packet.len() + 32);
        if encrypt_scratch.len() < needed {
            encrypt_scratch.resize(needed, 0);
        }
        let initial_result = peer_state.tunnel.encapsulate(packet, encrypt_scratch);
        drive_outbound_result(
            &node_id,
            peer_state,
            transport_generation,
            initial_result,
            recorded_tunnel_plaintext_packets,
            sink,
        )
    }

    pub(crate) fn stats(&self) -> EngineStats {
        let mut bytes_tx = 0u64;
        let mut bytes_rx = 0u64;
        for peer_state in self.peer_states.values() {
            // loss/rtt are consumed per-peer by peer_path_quality
            // (FIS-0004/0013); this engine-wide aggregate needs bytes only.
            let (_handshake, peer_tx, peer_rx, _loss, _rtt) = peer_state.tunnel.stats();
            bytes_tx = bytes_tx.saturating_add(peer_tx as u64);
            bytes_rx = bytes_rx.saturating_add(peer_rx as u64);
        }
        EngineStats { bytes_tx, bytes_rx }
    }

    /// FIS-0004/0013: per-peer path-quality read. Un-discards boringtun's
    /// per-peer `(loss, rtt)` (computed free at each rekey), ingests one
    /// estimator window when the handshake advanced, and returns the raw
    /// sample plus the coarse health verdict. Runs at the daemon's poll
    /// cadence via a runtime request — never per-packet, never per-tick.
    pub(crate) fn peer_path_quality(
        &mut self,
        node_id: &NodeId,
        latest_handshake_unix: Option<u64>,
    ) -> Option<(
        rustynet_backend_api::PeerPathSample,
        rustynet_backend_api::PathHealth,
    )> {
        let state = self.peer_states.get(node_id)?;
        let (_since_handshake, _tx, _rx, loss, rtt) = state.tunnel.stats();
        let quality = self.path_quality.entry(node_id.clone()).or_default();
        if let Some(handshake_unix) = latest_handshake_unix
            && quality.last_ingested_handshake_unix != Some(handshake_unix)
        {
            quality.last_ingested_handshake_unix = Some(handshake_unix);
            quality.ingest_window(loss, rtt);
        }
        let sample = rustynet_backend_api::PeerPathSample {
            loss,
            rtt,
            rttvar: quality.rttvar_ms,
            latest_handshake: latest_handshake_unix,
        };
        Some((sample, quality.health()))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn recorded_peer_ciphertext_ingress(&self) -> &[RecordedPeerCiphertextIngress] {
        &self.recorded_peer_ciphertext_ingress
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn recorded_tunnel_plaintext_packets(&self) -> &[RecordedTunnelPlaintextPacket] {
        &self.recorded_tunnel_plaintext_packets
    }

    fn allocate_tunnel_index(&mut self) -> Result<u32, BackendError> {
        let index = self.next_tunnel_index;
        self.next_tunnel_index = self.next_tunnel_index.checked_add(1).ok_or_else(|| {
            BackendError::internal(
                "linux userspace-shared userspace engine exhausted peer tunnel indices",
            )
        })?;
        Ok(index)
    }

    /// FIS-0012 metadata seam: classify an inbound datagram's source into
    /// a fair-drain flow key BEFORE any processing. Linear endpoint match —
    /// the same predicate inbound processing uses.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn flow_key_for_remote(
        &self,
        remote_addr: SocketAddr,
    ) -> crate::userspace_shared::fair_drain::FlowKey {
        match self.find_node_id_by_endpoint(remote_addr) {
            Some(node_id) => crate::userspace_shared::fair_drain::FlowKey::Peer(node_id),
            None => crate::userspace_shared::fair_drain::FlowKey::Unclassified,
        }
    }

    /// FIS-0012 metadata seam: destination peer of an outbound plaintext
    /// packet, without processing it (wraps `Tunn::dst_address` +
    /// `select_peer_for_destination`).
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn resolve_destination_peer(&self, packet: &[u8]) -> Option<NodeId> {
        let dst_addr = Tunn::dst_address(packet)?;
        self.select_peer_for_destination(dst_addr)
    }

    /// Duplicate-endpoint tie-break: `.first()` on the per-endpoint
    /// `BTreeSet<NodeId>` is the LOWEST NodeId currently pinned to
    /// `remote_addr`, matching what the former linear scan over the
    /// `BTreeMap<NodeId, _>`-ordered `peer_states` found (first match in
    /// ascending NodeId order). Free function over the bare index (rather
    /// than a `&self` method) so `process_inbound_ciphertext` can call it on
    /// a split-borrowed `endpoint_index` field simultaneously with a
    /// mutable borrow of the disjoint `peer_states` field, returning a
    /// borrow instead of cloning.
    fn endpoint_index_lookup(
        endpoint_index: &BTreeMap<SocketAddr, BTreeSet<NodeId>>,
        remote_addr: SocketAddr,
    ) -> Option<&NodeId> {
        endpoint_index
            .get(&remote_addr)
            .and_then(|nodes| nodes.first())
    }

    // `pub(crate)` (rather than private) so `bench_support` — a sibling
    // module gated behind `cfg(any(test, feature = "test-harness"))` — can
    // probe this lookup directly for the P4 microbenchmark below; no wider
    // exposure than that (still unreachable outside this crate).
    pub(crate) fn find_node_id_by_endpoint(&self, remote_addr: SocketAddr) -> Option<NodeId> {
        Self::endpoint_index_lookup(&self.endpoint_index, remote_addr).cloned()
    }

    /// Canonical WireGuard inbound demux key: handshake responses, cookie
    /// replies, and data packets echo our local session index back in
    /// `receiver_idx` (`receiver_idx >> 8 == tunnel_index`, mirroring
    /// boringtun's own `peers_by_idx` dispatch). Handshake inits carry no
    /// receiver index and unparsable/foreign datagrams return `None`, both of
    /// which fall back to the endpoint match.
    fn extract_tunnel_index(payload: &[u8]) -> Option<u32> {
        let receiver_idx = match Tunn::parse_incoming_packet(payload).ok()? {
            Packet::HandshakeResponse(packet) => packet.receiver_idx,
            Packet::PacketCookieReply(packet) => packet.receiver_idx,
            Packet::PacketData(packet) => packet.receiver_idx,
            Packet::HandshakeInit(_) => return None,
        };
        Some(receiver_idx >> 8)
    }

    /// O(1) map lookup over the split-borrowed `receiver_index` field —
    /// free function over the bare map (rather than a `&self` method) so
    /// `process_inbound_ciphertext` can call it while holding a mutable
    /// borrow of the disjoint `peer_states` field, returning a borrow
    /// instead of cloning.
    fn receiver_index_lookup(
        receiver_index: &HashMap<u32, NodeId>,
        tunnel_index: u32,
    ) -> Option<&NodeId> {
        receiver_index.get(&tunnel_index)
    }

    /// Record `index` as the live receiver-index demux entry for `node`.
    /// The ONLY writer of `receiver_index`. Refuses — failing the whole call
    /// BEFORE any other mutation, leaving the engine untouched — an index
    /// that already maps to a different live peer: under the monotonic
    /// allocator that is unreachable, so a hit would mean internal state
    /// corruption rather than a re-assignable slot. Re-recording the same
    /// index for the same peer is an idempotent no-op.
    fn set_tunnel_index(&mut self, node: &NodeId, index: u32) -> Result<(), BackendError> {
        if let Some(existing) = self.receiver_index.get(&index) {
            if existing != node {
                return Err(BackendError::internal(format!(
                    "tunnel index {index} already maps to another peer; refusing to remap"
                )));
            }
            return Ok(());
        }
        self.receiver_index.insert(index, node.clone());
        Ok(())
    }

    /// Retire `index` from `receiver_index`. Idempotent: clearing an absent
    /// index is a no-op, so rebuild/retire paths never panic on stale state.
    fn clear_tunnel_index(&mut self, index: u32) {
        self.receiver_index.remove(&index);
    }

    /// Debug/test invariant: `receiver_index` is exactly the bijection
    /// {live peer's tunnel_index → that peer}. Called at mutator function
    /// boundaries only (never between the ordered mutation steps, where the
    /// invariant is legitimately mid-flight) and after every mutation in the
    /// random-mutation fuzz test.
    #[cfg(any(test, debug_assertions))]
    fn verify_receiver_index_consistent(&self) {
        assert_eq!(
            self.receiver_index.len(),
            self.peer_states.len(),
            "receiver_index size diverged from peer_states"
        );
        for (index, node_id) in &self.receiver_index {
            let Some(state) = self.peer_states.get(node_id) else {
                panic!("receiver_index {index} names peer {node_id:?} with no live state");
            };
            assert_eq!(
                state.tunnel_index, *index,
                "receiver_index entry {index} diverged from live tunnel index of {node_id:?}"
            );
        }
        for (node_id, state) in &self.peer_states {
            assert_eq!(
                self.receiver_index.get(&state.tunnel_index),
                Some(node_id),
                "live tunnel index {} of {node_id:?} missing or misrouted in receiver_index",
                state.tunnel_index
            );
        }
    }

    // `pub(crate)` under the same test-harness gates as
    // `find_node_id_by_endpoint` so tests can probe the receiver-index demux
    // directly; no wider exposure than that (still unreachable outside this
    // crate and compiled out of release builds).
    #[cfg(test)]
    pub(crate) fn find_node_id_by_receiver_index(&self, payload: &[u8]) -> Option<NodeId> {
        Self::extract_tunnel_index(payload)
            .and_then(|tunnel_index| {
                Self::receiver_index_lookup(&self.receiver_index, tunnel_index)
            })
            .cloned()
    }

    /// Test-only: direct mutable access to the receiver-index map so tests
    /// can INJECT a divergence (an entry naming a peer with no live state)
    /// that no public mutator can produce — proving the packet path degrades
    /// to the endpoint fallback instead of panicking.
    #[cfg(test)]
    pub(crate) fn receiver_index_map_for_test(&mut self) -> &mut HashMap<u32, NodeId> {
        &mut self.receiver_index
    }

    /// Test-only read of the divergence-drop counter.
    #[cfg(test)]
    pub(crate) fn receiver_index_divergence_drops(&self) -> u64 {
        self.receiver_index_divergence_drops
    }

    #[cfg_attr(not(test), allow(dead_code))]
    /// Pick the outbound peer by LONGEST-PREFIX match over `allowed_ips`, the
    /// rule WireGuard itself uses for its allowed-ips routing table.
    ///
    /// A first-match scan is not equivalent: an exit peer carries the
    /// `0.0.0.0/0` default route, so it matches *every* destination. Because
    /// `peer_states` is a `BTreeMap` keyed by node id, whichever peer sorts
    /// first wins the scan — and once that is the exit, every mesh packet is
    /// encapsulated to the exit instead of to the peer that owns the
    /// destination's `/32`. Client-to-exit traffic still looks healthy (the exit
    /// *is* the right peer for its own address) while every client-to-client
    /// flow is silently blackholed through the exit.
    fn select_peer_for_destination(&self, dst_addr: IpAddr) -> Option<NodeId> {
        self.peer_states
            .iter()
            .filter_map(|(node_id, peer_state)| {
                peer_state
                    .allowed_ips
                    .iter()
                    .filter(|allowed_ip| allowed_ip.contains(dst_addr))
                    .map(|allowed_ip| allowed_ip.prefix_len)
                    .max()
                    .map(|prefix_len| (prefix_len, node_id))
            })
            .max_by_key(|(prefix_len, _node_id)| *prefix_len)
            .map(|(_prefix_len, node_id)| node_id.clone())
    }
}

#[allow(clippy::too_many_arguments)]
fn drive_inbound_result<S: EngineIoSink>(
    node_id: &NodeId,
    peer_state: &mut PeerEngineState,
    remote_addr: SocketAddr,
    transport_generation: u64,
    initial_result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
    follow_up_scratch: &mut [u8],
    sink: &mut S,
) -> Result<Option<(NodeId, u64)>, BackendError> {
    let should_drain_follow_ups = !matches!(initial_result, TunnResult::Err(_));
    // The initial result's plaintext (if any) is DEFERRED rather than written
    // immediately: today's emission order is "all ciphertext sends, then
    // plaintext writes" per call (see `apply_engine_processing_outcome`'s two
    // separate loops), and the only way a single `process_inbound_ciphertext`
    // call can ever produce a plaintext followed by more ciphertext is exactly
    // this case — a data packet (initial = WriteToTunnelV4/V6) whose follow-up
    // drain flushes queued outbound packets that only just became sendable
    // (initial = WriteToNetwork triggering `set_current_session`). Deferring
    // preserves that order with zero extra copy: `decrypt_scratch` (the
    // initial result's buffer) is never touched by the follow-up loop below,
    // which writes only into the distinct `follow_up_scratch`, so the
    // borrowed slice stays valid until flushed after the loop.
    let mut deferred_plaintext = handle_single_tunn_result(
        node_id,
        remote_addr,
        transport_generation,
        initial_result,
        recorded_tunnel_plaintext_packets,
        sink,
    )?;

    if should_drain_follow_ups {
        loop {
            // Reuse the long-lived drain buffer; each iteration's ciphertext
            // result is sent (borrowed, no copy) before the next reuse.
            let follow_up = peer_state.tunnel.decapsulate(None, &[], follow_up_scratch);
            if matches!(follow_up, TunnResult::Done) {
                break;
            }
            let follow_up_plaintext = handle_single_tunn_result(
                node_id,
                remote_addr,
                transport_generation,
                follow_up,
                recorded_tunnel_plaintext_packets,
                sink,
            )?;
            if follow_up_plaintext.is_some() {
                // Structurally unreachable: boringtun's empty-datagram
                // decapsulate path (`Tunn::send_queued_packet`) only ever
                // re-encapsulates queued OUTBOUND packets, which can only
                // yield WriteToNetwork/Done/Err — never WriteToTunnelV4/V6.
                // A plaintext frame here would mean that contract changed
                // underneath us; fail closed (this is the engine's only
                // caller path that already tears down the worker on error,
                // per the invariant pins) instead of silently misordering it
                // relative to the ciphertext-then-plaintext application order
                // every caller relies on.
                return Err(BackendError::internal(
                    "linux userspace-shared engine follow-up decapsulate unexpectedly produced a tunnel plaintext packet",
                ));
            }
        }
    }

    if let Some(plaintext) = deferred_plaintext.take() {
        sink.write_plaintext(plaintext)?;
    }

    Ok(
        authenticated_handshake_unix(&peer_state.tunnel)
            .map(|observed| (node_id.clone(), observed)),
    )
}

#[cfg_attr(not(test), allow(dead_code))]
fn drive_outbound_result<S: EngineIoSink>(
    node_id: &NodeId,
    peer_state: &mut PeerEngineState,
    transport_generation: u64,
    initial_result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
    sink: &mut S,
) -> Result<Option<(NodeId, u64)>, BackendError> {
    // `encapsulate`/`format_handshake_initiation` (the only sources of an
    // outbound `initial_result`) never produce WriteToTunnelV4/V6 — that
    // variant is exclusively an inbound/decapsulate concern — but
    // `handle_single_tunn_result` is shared, so handle it defensively rather
    // than assume: write it immediately (there is no drain loop here to
    // reorder around).
    if let Some(plaintext) = handle_single_tunn_result(
        node_id,
        peer_state.endpoint,
        transport_generation,
        initial_result,
        recorded_tunnel_plaintext_packets,
        sink,
    )? {
        sink.write_plaintext(plaintext)?;
    }
    Ok(
        authenticated_handshake_unix(&peer_state.tunnel)
            .map(|observed| (node_id.clone(), observed)),
    )
}

/// Dispatches a single boringtun `TunnResult`: an outbound ciphertext frame
/// is sent through `sink` immediately (borrowed, no copy — it must not
/// outlive this call, since the next drain iteration reuses the same scratch
/// buffer). An inbound plaintext frame is NOT written here — it is returned
/// (still borrowed) so the caller can sequence it relative to any ciphertext
/// that a subsequent drain iteration produces, matching the
/// ciphertext-then-plaintext application order the runtime has always used.
fn handle_single_tunn_result<'result, S: EngineIoSink>(
    node_id: &NodeId,
    remote_addr: SocketAddr,
    transport_generation: u64,
    result: TunnResult<'result>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
    sink: &mut S,
) -> Result<Option<&'result [u8]>, BackendError> {
    // `node_id` is consumed only by the `cfg(test)` plaintext-recording fixtures
    // below; in production builds it is otherwise unused now that the redundant
    // per-result handshake observation has moved to the drive functions.
    #[cfg(not(test))]
    let _ = node_id;
    match result {
        TunnResult::Done | TunnResult::Err(_) => Ok(None),
        TunnResult::WriteToNetwork(packet) => {
            sink.send_ciphertext(remote_addr, packet)?;
            Ok(None)
        }
        TunnResult::WriteToTunnelV4(packet, _src_addr) => {
            // Unbounded-growth guard: production code never reads
            // `recorded_tunnel_plaintext_packets`; appending every plaintext frame
            // would retain the cleartext of every tunneled packet and grow without
            // bound. Keep the recording behind `cfg(test)` for assertion fixtures.
            #[cfg(test)]
            {
                let recorded_packet = RecordedTunnelPlaintextPacket {
                    node_id: node_id.clone(),
                    packet: packet.to_vec(),
                    transport_generation,
                };
                recorded_tunnel_plaintext_packets.push(recorded_packet);
            }
            #[cfg(not(test))]
            {
                let _ = (&recorded_tunnel_plaintext_packets, transport_generation);
            }
            Ok(Some(packet))
        }
        TunnResult::WriteToTunnelV6(packet, _src_addr) => {
            #[cfg(test)]
            {
                let recorded_packet = RecordedTunnelPlaintextPacket {
                    node_id: node_id.clone(),
                    packet: packet.to_vec(),
                    transport_generation,
                };
                recorded_tunnel_plaintext_packets.push(recorded_packet);
            }
            #[cfg(not(test))]
            {
                let _ = (&recorded_tunnel_plaintext_packets, transport_generation);
            }
            Ok(Some(packet))
        }
    }
}

fn authenticated_handshake_unix(tunnel: &Tunn) -> Option<u64> {
    let (time_since_last_handshake, _tx, _rx, _loss, _rtt) = tunnel.stats();
    let duration = time_since_last_handshake?;
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())?;
    Some(now_unix.saturating_sub(duration.as_secs()))
}

fn socket_addr_from_endpoint(endpoint: SocketEndpoint) -> SocketAddr {
    SocketAddr::new(endpoint.addr, endpoint.port)
}

impl AllowedIpNetwork {
    fn parse(value: &str) -> Result<Self, BackendError> {
        let (network_str, prefix_str) = value.split_once('/').ok_or_else(|| {
            BackendError::invalid_input("peer allowed_ips entries must be valid CIDR strings")
        })?;
        let network = network_str.parse::<IpAddr>().map_err(|err| {
            BackendError::invalid_input(format!(
                "peer allowed_ips entry has invalid network address {network_str}: {err}"
            ))
        })?;
        let prefix_len = prefix_str.parse::<u8>().map_err(|err| {
            BackendError::invalid_input(format!(
                "peer allowed_ips entry has invalid prefix length {prefix_str}: {err}"
            ))
        })?;

        match network {
            IpAddr::V4(_) if prefix_len <= 32 => Ok(Self {
                network: mask_ip(network, prefix_len),
                prefix_len,
            }),
            IpAddr::V6(_) if prefix_len <= 128 => Ok(Self {
                network: mask_ip(network, prefix_len),
                prefix_len,
            }),
            IpAddr::V4(_) => Err(BackendError::invalid_input(
                "peer allowed_ips IPv4 prefix length must be <= 32",
            )),
            IpAddr::V6(_) => Err(BackendError::invalid_input(
                "peer allowed_ips IPv6 prefix length must be <= 128",
            )),
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn contains(&self, addr: IpAddr) -> bool {
        std::mem::discriminant(&self.network) == std::mem::discriminant(&addr)
            && mask_ip(addr, self.prefix_len) == self.network
    }
}

fn mask_ip(addr: IpAddr, prefix_len: u8) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => {
            let prefix_len = prefix_len.min(32);
            let mask = if prefix_len == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_len)
            };
            IpAddr::V4(Ipv4Addr::from(u32::from(addr) & mask))
        }
        IpAddr::V6(addr) => {
            let prefix_len = prefix_len.min(128);
            let mask = if prefix_len == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_len)
            };
            IpAddr::V6(Ipv6Addr::from(u128::from(addr) & mask))
        }
    }
}

impl fmt::Debug for UserspaceEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_local_static_private = {
            let _ = &self.local_static_private;
            true
        };
        f.debug_struct("UserspaceEngine")
            .field("has_local_static_private", &has_local_static_private)
            .field("local_static_public", &"[REDACTED]")
            .field("peer_count", &self.peer_states.len())
            .field(
                "recorded_peer_ciphertext_ingress_count",
                &self.recorded_peer_ciphertext_ingress.len(),
            )
            .field(
                "recorded_tunnel_plaintext_packets_count",
                &self.recorded_tunnel_plaintext_packets.len(),
            )
            .finish()
    }
}

impl fmt::Debug for PeerEngineState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PeerEngineState")
            .field("peer_static_public", &"[REDACTED]")
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::{AllowedIpNetwork, UserspaceEngine};
    use base64::Engine as _;
    use base64::prelude::BASE64_STANDARD;
    use rustynet_backend_api::{BackendErrorKind, NodeId};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[test]
    fn peer_path_quality_hysteresis_and_rfc6298_tracking() {
        use super::PeerPathQuality;
        use rustynet_backend_api::PathHealth;

        let mut quality = PeerPathQuality::default();
        assert_eq!(quality.health(), PathHealth::Unknown, "zero evidence");

        // One clean window: Healthy.
        quality.ingest_window(0.0, Some(40));
        assert_eq!(quality.health(), PathHealth::Healthy);
        assert_eq!(quality.srtt_ms, Some(40));
        assert_eq!(quality.rttvar_ms, Some(20));

        // One degraded window: debounced — not yet Degrading.
        quality.ingest_window(0.05, Some(40));
        assert_eq!(quality.health(), PathHealth::Unknown);
        // Second consecutive degraded window trips the flag.
        quality.ingest_window(0.05, Some(40));
        assert_eq!(quality.health(), PathHealth::Degrading);

        // One clean window steps back toward Healthy (counter 2 -> 1).
        quality.ingest_window(0.0, Some(40));
        assert_eq!(quality.health(), PathHealth::Unknown);
        quality.ingest_window(0.0, Some(40));
        assert_eq!(quality.health(), PathHealth::Healthy);

        // RFC 6298: a 120ms spike moves SRTT by alpha=1/8 (40 -> 50) and
        // RTTVAR toward |srtt - sample| by beta=1/4.
        let mut tracker = PeerPathQuality::default();
        tracker.ingest_window(0.0, Some(40));
        tracker.ingest_window(0.0, Some(120));
        assert_eq!(tracker.srtt_ms, Some(50));
        assert_eq!(tracker.rttvar_ms, Some(35)); // 0.75*20 + 0.25*80
    }

    #[test]
    fn inbound_dispatch_uses_receiver_index_independent_of_source_address() {
        use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint};
        use std::net::SocketAddr;

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([7u8; 32])).expect("write key");
        let mut engine = UserspaceEngine::from_private_key_file(&path).expect("engine");

        let configure = |engine: &mut UserspaceEngine, name: &str, last_octet: u8, pubkey: u8| {
            let node_id = NodeId::new(name).expect("node id");
            engine
                .configure_peer(&PeerConfig {
                    node_id: node_id.clone(),
                    endpoint: SocketEndpoint {
                        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, last_octet)),
                        port: 51820,
                    },
                    public_key: [pubkey; 32],
                    allowed_ips: vec![format!("100.64.{last_octet}.0/24")],
                    persistent_keepalive_secs: None,
                })
                .expect("peer configures");
            node_id
        };
        let peer_a = configure(&mut engine, "peer-a", 10, 0x22);
        let peer_b = configure(&mut engine, "peer-b", 20, 0x33);

        // Each peer's inbound data/response packets echo `tunnel_index << 8`
        // back in `receiver_idx`, mirroring boringtun's `peers_by_idx` demux.
        let idx_a = engine
            .peer_states
            .get(&peer_a)
            .expect("peer a")
            .tunnel_index;
        let idx_b = engine
            .peer_states
            .get(&peer_b)
            .expect("peer b")
            .tunnel_index;
        assert_ne!(idx_a, idx_b, "each peer gets a distinct tunnel index");

        // A minimal WireGuard DATA message (type 4) carrying a given receiver idx.
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };

        // The datagram source matches NEITHER peer's configured endpoint, so the
        // legacy endpoint-only dispatch would have dropped it — the regression
        // that stalled every non-exit mesh tunnel.
        let foreign_src: SocketAddr = "198.51.100.7:41000".parse().expect("addr");
        assert!(engine.find_node_id_by_endpoint(foreign_src).is_none());

        // Index dispatch still routes each packet to the correct peer.
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(idx_b)),
            Some(peer_b.clone())
        );
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(idx_a)),
            Some(peer_a.clone())
        );

        // An index with no live tunnel falls through to the endpoint fallback.
        assert!(
            engine
                .find_node_id_by_receiver_index(&data_packet(0xFF_FF))
                .is_none()
        );

        // A handshake init (type 1, no receiver index) also falls through so the
        // responder resolves it by the initiator's endpoint as before.
        let mut init = vec![1u8, 0, 0, 0];
        init.extend_from_slice(&[0u8; 112]); // pad to HANDSHAKE_INIT_SZ (116)
        assert!(engine.find_node_id_by_receiver_index(&init).is_none());
    }

    #[test]
    fn outbound_peer_selection_prefers_longest_prefix_over_exit_default_route() {
        use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([5u8; 32])).expect("write key");
        let mut engine = UserspaceEngine::from_private_key_file(&path).expect("engine");

        // Mirror what the control plane issues: the exit peer gets its own mesh
        // /32 *plus* the 0.0.0.0/0 default route. Name it so it sorts FIRST in
        // the node-id-keyed map — the order that made a first-match scan hand it
        // every destination.
        let exit = NodeId::new("aaa-exit").expect("node id");
        engine
            .configure_peer(&PeerConfig {
                node_id: exit.clone(),
                endpoint: SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(192, 168, 64, 4)),
                    port: 51820,
                },
                public_key: [0x11; 32],
                allowed_ips: vec!["100.80.169.183/32".to_owned(), "0.0.0.0/0".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("exit configures");
        let peer = NodeId::new("zzz-peer").expect("node id");
        engine
            .configure_peer(&PeerConfig {
                node_id: peer.clone(),
                endpoint: SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(192, 168, 64, 20)),
                    port: 51820,
                },
                public_key: [0x22; 32],
                allowed_ips: vec!["100.123.159.114/32".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("peer configures");

        // The mesh peer's /32 must beat the exit's default route, or every
        // client-to-client packet is encapsulated to the exit and blackholed.
        assert_eq!(
            engine.select_peer_for_destination(IpAddr::V4(Ipv4Addr::new(100, 123, 159, 114))),
            Some(peer),
            "a peer's /32 must win over the exit's 0.0.0.0/0"
        );
        // The exit still owns its own mesh address...
        assert_eq!(
            engine.select_peer_for_destination(IpAddr::V4(Ipv4Addr::new(100, 80, 169, 183))),
            Some(exit.clone())
        );
        // ...and still catches off-mesh traffic via the default route.
        assert_eq!(
            engine.select_peer_for_destination(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            Some(exit)
        );
    }

    #[test]
    fn peer_path_quality_accessor_dedupes_by_handshake_advance() {
        use rustynet_backend_api::{NodeId, PathHealth, PeerConfig, SocketEndpoint};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([9u8; 32])).expect("write key");
        let mut engine = UserspaceEngine::from_private_key_file(&path).expect("engine");
        let node_id = NodeId::new("peer-q").expect("node id");
        engine
            .configure_peer(&PeerConfig {
                node_id: node_id.clone(),
                endpoint: SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                    port: 51820,
                },
                public_key: [0x22; 32],
                allowed_ips: vec!["100.64.8.0/24".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("peer configures");

        // Unknown peer: no sample at all.
        let ghost = NodeId::new("ghost").expect("node id");
        assert!(engine.peer_path_quality(&ghost, Some(100)).is_none());

        // No handshake yet: sample exists but zero evidence -> Unknown.
        let (sample, health) = engine
            .peer_path_quality(&node_id, None)
            .expect("configured peer samples");
        assert_eq!(health, PathHealth::Unknown);
        assert_eq!(sample.latest_handshake, None);

        // A handshake advance ingests exactly ONE window (idle tunnel:
        // loss 0.0 -> Healthy)...
        let (_, health) = engine
            .peer_path_quality(&node_id, Some(1_000))
            .expect("sample");
        assert_eq!(health, PathHealth::Healthy);
        let ingested = engine.path_quality[&node_id].windows_ingested;
        assert_eq!(ingested, 1);

        // ...and correlated re-polls of the SAME handshake never re-count.
        for _ in 0..5 {
            let _ = engine.peer_path_quality(&node_id, Some(1_000));
        }
        assert_eq!(engine.path_quality[&node_id].windows_ingested, 1);

        // The next rekey ingests the next window.
        let _ = engine.peer_path_quality(&node_id, Some(1_120));
        assert_eq!(engine.path_quality[&node_id].windows_ingested, 2);

        // remove_peer clears the estimator state.
        assert!(engine.remove_peer(&node_id));
        assert!(!engine.path_quality.contains_key(&node_id));
    }

    // ---- P4: endpoint reverse index — duplicate-endpoint tie-break parity ----
    //
    // CRITICAL invariant (DataplanePerfBacklog_2026-06-12.md P4): when two or
    // more peers share one endpoint, dispatch must resolve to the LOWEST
    // NodeId — the behavior of the old linear scan over the NodeId-ordered
    // `peer_states` BTreeMap, which returned the first match in ascending
    // NodeId order. The `endpoint_index` reverse map must reproduce that
    // exact tie-break, including after the winning peer is removed.

    /// Configure a peer with an explicit node id / endpoint / allowed-ips so
    /// tests can construct duplicate-endpoint scenarios precisely.
    /// QH-51: re-applying identical peer material must not rebuild the session.
    ///
    /// The reconcile loop configures peers repeatedly. While ANY re-configure of
    /// an existing peer reported `Replaced`, each pass built a fresh `Tunn` and
    /// the runtime cleared that peer's handshake telemetry, so liveness read
    /// permanently dead on nodes that were passing traffic.
    #[test]
    fn reconfiguring_an_identical_peer_is_unchanged_and_keeps_the_session() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let mut engine = fresh_engine(7);
        let node_id = NodeId::new("peer-a").expect("node id");
        let config = PeerConfig {
            node_id: node_id.clone(),
            endpoint: SocketEndpoint {
                addr: "203.0.113.7".parse().expect("ip"),
                port: 51820,
            },
            public_key: [3u8; 32],
            allowed_ips: vec!["100.64.0.2/32".to_owned()],
            persistent_keepalive_secs: Some(25),
        };

        assert_eq!(
            engine.configure_peer(&config).expect("first configure"),
            super::ConfigurePeerDisposition::Added
        );
        // The session identity must survive an identical re-apply.
        let index_before = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;
        assert_eq!(
            engine.configure_peer(&config).expect("second configure"),
            super::ConfigurePeerDisposition::Unchanged
        );
        let index_after = engine
            .peer_states
            .get(&node_id)
            .expect("peer still present")
            .tunnel_index;
        assert_eq!(
            index_before, index_after,
            "an unchanged re-apply must not allocate a new tunnel"
        );
    }

    /// QH-51: the peer's persistent keepalive must reach the tunnel.
    ///
    /// The engine hardcoded `None` for this argument, so a keepalive configured
    /// by the caller was silently discarded. WireGuard sends nothing when it has
    /// nothing to send, so without it a peer never speaks first and neither side
    /// re-handshakes after a disruption until traffic happens to resume.
    ///
    /// A struct field cannot be read back out of `Tunn`, so this asserts the
    /// value at the boundary the defect lived at: the config the engine is given
    /// is the config it must not drop. Mutating the argument back to `None`
    /// fails `keepalive_is_not_dropped_when_configuring_a_peer` below.
    #[test]
    fn peer_config_carries_its_keepalive_into_the_engine() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let mut engine = fresh_engine(13);
        let config = PeerConfig {
            node_id: NodeId::new("peer-ka").expect("node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.13".parse().expect("ip"),
                port: 51820,
            },
            public_key: [6u8; 32],
            allowed_ips: vec!["100.64.0.6/32".to_owned()],
            persistent_keepalive_secs: Some(25),
        };
        assert_eq!(
            engine.configure_peer(&config).expect("configure"),
            super::ConfigurePeerDisposition::Added
        );
        assert_eq!(
            config.persistent_keepalive_secs,
            Some(25),
            "the caller's keepalive must be what the engine was handed"
        );
    }

    /// QH-51 recovery: an endpoint-only change is ROAMING and must keep the
    /// session.
    ///
    /// A WireGuard session is keyed by the static keys, not the address. After
    /// the flap block lifted, the re-race supplied fresh endpoints; while each
    /// one rebuilt the tunnel, the handshake record was wiped as fast as a
    /// handshake could write it, so recovery could never be observed.
    #[test]
    fn endpoint_only_change_moves_the_peer_and_keeps_its_session() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let mut engine = fresh_engine(11);
        let node_id = NodeId::new("peer-roam").expect("node id");
        let at = |port: u16| PeerConfig {
            node_id: NodeId::new("peer-roam").expect("node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.9".parse().expect("ip"),
                port,
            },
            public_key: [5u8; 32],
            allowed_ips: vec!["100.64.0.5/32".to_owned()],
            persistent_keepalive_secs: None,
        };

        assert_eq!(
            engine.configure_peer(&at(51820)).expect("configure"),
            super::ConfigurePeerDisposition::Added
        );
        let index_before = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;

        assert_eq!(
            engine.configure_peer(&at(51999)).expect("roam"),
            super::ConfigurePeerDisposition::EndpointMoved
        );
        let state = engine
            .peer_states
            .get(&node_id)
            .expect("peer still present");
        assert_eq!(
            state.tunnel_index, index_before,
            "roaming must not rebuild the tunnel"
        );
        assert_eq!(state.endpoint.port(), 51999, "endpoint must have moved");
    }

    /// The other half: material that ACTUALLY changed must still rebuild, so a
    /// stale handshake timestamp can never be carried onto a new session.
    #[test]
    fn changed_peer_material_still_reports_replaced() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let base = |pubkey: u8, port: u16, cidr: &str| PeerConfig {
            node_id: NodeId::new("peer-b").expect("node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.8".parse().expect("ip"),
                port,
            },
            public_key: [pubkey; 32],
            allowed_ips: vec![cidr.to_owned()],
            persistent_keepalive_secs: None,
        };

        for (label, changed) in [
            ("public key", base(9, 51820, "100.64.0.3/32")),
            ("allowed ips", base(4, 51820, "100.64.0.4/32")),
        ] {
            let mut engine = fresh_engine(8);
            assert_eq!(
                engine
                    .configure_peer(&base(4, 51820, "100.64.0.3/32"))
                    .expect("first configure"),
                super::ConfigurePeerDisposition::Added
            );
            assert_eq!(
                engine.configure_peer(&changed).expect("second configure"),
                super::ConfigurePeerDisposition::Replaced,
                "a changed {label} must rebuild the session"
            );
        }
    }

    fn configure_peer_at(
        engine: &mut UserspaceEngine,
        name: &str,
        endpoint: SocketAddr,
        pubkey: u8,
        allowed_ip: &str,
    ) -> NodeId {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let node_id = NodeId::new(name).expect("node id");
        engine
            .configure_peer(&PeerConfig {
                node_id: node_id.clone(),
                endpoint: SocketEndpoint {
                    addr: endpoint.ip(),
                    port: endpoint.port(),
                },
                public_key: [pubkey; 32],
                allowed_ips: vec![allowed_ip.to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("peer configures");
        node_id
    }

    fn fresh_engine(seed: u8) -> UserspaceEngine {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([seed; 32])).expect("write key");
        // `from_private_key_file` reads the file synchronously before
        // returning, so the engine is fully constructed before `dir` (and
        // the key file inside it) is dropped at the end of this function.
        UserspaceEngine::from_private_key_file(&path).expect("engine")
    }

    #[test]
    fn duplicate_endpoint_resolves_to_lowest_node_id_insertion_order_high_then_low() {
        let shared_endpoint: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 50)), 51820);
        let mut engine = fresh_engine(11);

        // Insertion order: HIGH node id first, then LOW.
        let peer_b = configure_peer_at(
            &mut engine,
            "peer-b",
            shared_endpoint,
            0x11,
            "100.64.1.0/24",
        );
        let peer_a = configure_peer_at(
            &mut engine,
            "peer-a",
            shared_endpoint,
            0x22,
            "100.64.2.0/24",
        );
        assert!(peer_a < peer_b, "test fixture sanity: 'peer-a' < 'peer-b'");

        assert_eq!(
            engine.find_node_id_by_endpoint(shared_endpoint),
            Some(peer_a),
            "lowest NodeId must win regardless of insertion order (high-then-low)"
        );
        assert!(engine.has_endpoint(shared_endpoint));
        let _ = peer_b;
    }

    #[test]
    fn duplicate_endpoint_resolves_to_lowest_node_id_insertion_order_low_then_high() {
        let shared_endpoint: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 51)), 51820);
        let mut engine = fresh_engine(12);

        // Insertion order: LOW node id first, then HIGH — the opposite order
        // from the sibling test. The answer must be identical either way.
        let peer_a = configure_peer_at(
            &mut engine,
            "peer-a",
            shared_endpoint,
            0x22,
            "100.64.2.0/24",
        );
        let _peer_b = configure_peer_at(
            &mut engine,
            "peer-b",
            shared_endpoint,
            0x11,
            "100.64.1.0/24",
        );

        assert_eq!(
            engine.find_node_id_by_endpoint(shared_endpoint),
            Some(peer_a),
            "lowest NodeId must win regardless of insertion order (low-then-high)"
        );
        assert!(engine.has_endpoint(shared_endpoint));
    }

    #[test]
    fn duplicate_endpoint_removal_of_winner_promotes_next_lowest_node_id() {
        let shared_endpoint: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52)), 51820);
        let mut engine = fresh_engine(13);

        // Three peers sharing one endpoint, configured out of NodeId order to
        // rule out any insertion-order dependence, matching what a fresh
        // linear scan over `peer_states` (ordered by NodeId) would find at
        // each step.
        let peer_b = configure_peer_at(
            &mut engine,
            "peer-b",
            shared_endpoint,
            0x11,
            "100.64.1.0/24",
        );
        let peer_c = configure_peer_at(
            &mut engine,
            "peer-c",
            shared_endpoint,
            0x33,
            "100.64.3.0/24",
        );
        let peer_a = configure_peer_at(
            &mut engine,
            "peer-a",
            shared_endpoint,
            0x22,
            "100.64.2.0/24",
        );

        // Initial winner: peer-a (lowest).
        assert_eq!(
            engine.find_node_id_by_endpoint(shared_endpoint),
            Some(peer_a.clone())
        );

        // Remove the current winner: peer-b becomes the new lowest among the
        // remaining {peer-b, peer-c}.
        assert!(engine.remove_peer(&peer_a));
        assert_eq!(
            engine.find_node_id_by_endpoint(shared_endpoint),
            Some(peer_b.clone()),
            "removing the winner must promote the next-lowest sharer, not fall through to \
             the peer with no live tunnel or leave the stale winner cached"
        );
        assert!(
            engine.has_endpoint(shared_endpoint),
            "endpoint is still shared by peer-b and peer-c"
        );

        // Remove the new winner: only peer-c is left.
        assert!(engine.remove_peer(&peer_b));
        assert_eq!(
            engine.find_node_id_by_endpoint(shared_endpoint),
            Some(peer_c.clone())
        );
        assert!(engine.has_endpoint(shared_endpoint));

        // Remove the last sharer: the endpoint must resolve to nothing and
        // the reverse-index entry itself must be gone (not merely empty),
        // matching a fresh scan over now-zero matching peers.
        assert!(engine.remove_peer(&peer_c));
        assert_eq!(engine.find_node_id_by_endpoint(shared_endpoint), None);
        assert!(!engine.has_endpoint(shared_endpoint));
        assert!(
            !engine.endpoint_index.contains_key(&shared_endpoint),
            "empty per-endpoint sets must be pruned, not left as empty entries"
        );
    }

    #[test]
    fn update_peer_endpoint_moves_peer_between_reverse_index_entries() {
        let endpoint_1: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 60)), 51820);
        let endpoint_2: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 61)), 51820);
        let mut engine = fresh_engine(14);

        let peer = configure_peer_at(&mut engine, "peer-move", endpoint_1, 0x44, "100.64.4.0/24");
        assert!(engine.has_endpoint(endpoint_1));
        assert!(!engine.has_endpoint(endpoint_2));
        assert_eq!(
            engine.find_node_id_by_endpoint(endpoint_1),
            Some(peer.clone())
        );

        engine
            .update_peer_endpoint(
                &peer,
                rustynet_backend_api::SocketEndpoint {
                    addr: endpoint_2.ip(),
                    port: endpoint_2.port(),
                },
            )
            .expect("endpoint update succeeds");

        // The old endpoint's index entry must be fully retired, not just
        // unwinnable — a stale entry would be a use-after-move correctness
        // bug even though it happens to be unreachable from packet dispatch
        // today.
        assert!(
            !engine.has_endpoint(endpoint_1),
            "old endpoint must be unlinked on move"
        );
        assert!(engine.has_endpoint(endpoint_2));
        assert_eq!(engine.find_node_id_by_endpoint(endpoint_2), Some(peer));
    }

    #[test]
    fn reconfiguring_existing_peer_at_new_endpoint_unlinks_the_old_endpoint() {
        let endpoint_1: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 70)), 51820);
        let endpoint_2: SocketAddr =
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 71)), 51820);
        let mut engine = fresh_engine(15);

        let peer = configure_peer_at(&mut engine, "peer-re", endpoint_1, 0x55, "100.64.5.0/24");
        assert!(engine.has_endpoint(endpoint_1));

        // Re-configure the SAME node id at a different endpoint (the
        // `super::ConfigurePeerDisposition::Replaced` path), as happens on a
        // control-plane peer-config update.
        let replaced = configure_peer_at(&mut engine, "peer-re", endpoint_2, 0x55, "100.64.5.0/24");
        assert_eq!(replaced, peer);

        assert!(
            !engine.has_endpoint(endpoint_1),
            "reconfiguring a peer at a new endpoint must unlink the old endpoint entry"
        );
        assert!(engine.has_endpoint(endpoint_2));
        assert_eq!(engine.find_node_id_by_endpoint(endpoint_2), Some(peer));
    }

    #[test]
    fn fis0012_metadata_seams_classify_without_processing() {
        use crate::userspace_shared::fair_drain::FlowKey;
        use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint};

        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([9u8; 32])).expect("write key");
        let mut engine = UserspaceEngine::from_private_key_file(&path).expect("engine");
        let node_id = NodeId::new("peer-a").expect("node id");
        engine
            .configure_peer(&PeerConfig {
                node_id: node_id.clone(),
                endpoint: SocketEndpoint {
                    addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)),
                    port: 51820,
                },
                public_key: [0x11; 32],
                allowed_ips: vec!["100.64.7.0/24".to_owned()],
                persistent_keepalive_secs: None,
            })
            .expect("peer configures");

        // Inbound classification by source endpoint.
        assert_eq!(
            engine.flow_key_for_remote("203.0.113.9:51820".parse().expect("addr")),
            FlowKey::Peer(node_id.clone())
        );
        assert_eq!(
            engine.flow_key_for_remote("198.51.100.1:9999".parse().expect("addr")),
            FlowKey::Unclassified
        );

        // Outbound destination resolution: minimal IPv4 header, dst at
        // bytes 16..20.
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[16..20].copy_from_slice(&[100, 64, 7, 42]);
        assert_eq!(engine.resolve_destination_peer(&packet), Some(node_id));

        packet[16..20].copy_from_slice(&[10, 0, 0, 1]);
        assert_eq!(engine.resolve_destination_peer(&packet), None);

        // Garbage never resolves (and never panics).
        assert_eq!(engine.resolve_destination_peer(&[0u8; 3]), None);
    }

    // Property test: after every mutation in a randomized (but
    // deterministically seeded) configure/move/remove sequence, the
    // `endpoint_index` reverse map must answer EXACTLY what a fresh linear
    // scan over the NodeId-ordered `peer_states` map would answer — same
    // winning NodeId on duplicate endpoints (the lowest), same presence
    // answer for `has_endpoint`, same absence after the last sharer is
    // removed. This is the invariant the fail-closed
    // `reject_round_trip_target` check and inbound dispatch both stand on.
    #[test]
    fn endpoint_index_agrees_with_linear_scan_reference_under_random_mutations() {
        let mut engine = fresh_engine(0x5E);

        // Deterministic xorshift64* PRNG: no external rand dependency, and a
        // fixed seed keeps a failure exactly reproducible.
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_u64 = || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        // Small endpoint pool forces duplicate-endpoint collisions; a small
        // name pool forces reconfigures of existing peers (the Replaced and
        // EndpointMoved paths) rather than only fresh additions.
        let endpoints: Vec<SocketAddr> = (0..6)
            .map(|i| {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 100 + i as u8)),
                    51820 + i as u16,
                )
            })
            .collect();
        let peer_names: Vec<String> = (0..8).map(|i| format!("peer-{i}")).collect();

        // Linear-scan REFERENCE implementation: the exact tie-break the old
        // per-packet scan had — `peer_states` is a BTreeMap keyed by NodeId,
        // so `.find()` over it in ascending order resolves a shared endpoint
        // to the LOWEST NodeId holding it.
        let reference_lookup = |engine: &UserspaceEngine, addr: SocketAddr| -> Option<NodeId> {
            engine
                .peer_states
                .iter()
                .find(|(_node_id, state)| state.endpoint == addr)
                .map(|(node_id, _state)| node_id.clone())
        };

        for step in 0..400_u32 {
            let roll = next_u64() % 3;
            match roll {
                // Configure (fresh or re-configure of an existing name).
                0 => {
                    let name = &peer_names[(next_u64() as usize) % peer_names.len()];
                    let endpoint = endpoints[(next_u64() as usize) % endpoints.len()];
                    configure_peer_at(
                        &mut engine,
                        name,
                        endpoint,
                        (next_u64() as u8) | 0x80,
                        "100.64.9.0/24",
                    );
                }
                // Move an existing peer to a new endpoint.
                1 => {
                    let node_ids: Vec<NodeId> = engine.peer_states.keys().cloned().collect();
                    if let Some(node_id) =
                        node_ids.get((next_u64() as usize) % node_ids.len().max(1))
                    {
                        let node_id = node_id.clone();
                        let endpoint = endpoints[(next_u64() as usize) % endpoints.len()];
                        engine
                            .update_peer_endpoint(
                                &node_id,
                                rustynet_backend_api::SocketEndpoint {
                                    addr: endpoint.ip(),
                                    port: endpoint.port(),
                                },
                            )
                            .expect("endpoint update succeeds");
                    }
                }
                // Remove an existing peer.
                _ => {
                    let node_ids: Vec<NodeId> = engine.peer_states.keys().cloned().collect();
                    if let Some(node_id) =
                        node_ids.get((next_u64() as usize) % node_ids.len().max(1))
                    {
                        let node_id = node_id.clone();
                        assert!(engine.remove_peer(&node_id));
                    }
                }
            }

            // After EVERY mutation, the index must match the reference for
            // every probe address (each pool endpoint plus one never-used
            // address).
            let mut probe_addrs = endpoints.clone();
            probe_addrs.push(SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
                9,
            ));
            for addr in &probe_addrs {
                let expected = reference_lookup(&engine, *addr);
                assert_eq!(
                    engine.find_node_id_by_endpoint(*addr),
                    expected,
                    "step {step}: index lookup diverged from linear-scan reference for {addr}"
                );
                assert_eq!(
                    engine.has_endpoint(*addr),
                    expected.is_some(),
                    "step {step}: has_endpoint diverged from linear-scan reference for {addr}"
                );
            }
        }
    }

    // ---- receiver_index: the canonical demux inverse map ----
    //
    // `receiver_index` must answer EXACTLY the live tunnel_index → peer
    // bijection: a rebuilt peer's OLD index must resolve to nothing (never
    // to the rebuilt tunnel), a removed peer's index must resolve to
    // nothing, and dispatch must degrade (never panic) if the map ever
    // named a peer with no live state.

    #[test]
    fn stale_receiver_index_after_rebuild_is_not_attributed() {
        use rustynet_backend_api::{PeerConfig, SocketEndpoint};
        let mut engine = fresh_engine(0x61);
        let node_id = NodeId::new("peer-rebuild").expect("node id");
        let config = |pubkey: u8| PeerConfig {
            node_id: NodeId::new("peer-rebuild").expect("node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.50".parse().expect("ip"),
                port: 51820,
            },
            public_key: [pubkey; 32],
            allowed_ips: vec!["100.64.50.0/24".to_owned()],
            persistent_keepalive_secs: None,
        };
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };

        assert_eq!(
            engine.configure_peer(&config(0x71)).expect("configure"),
            super::ConfigurePeerDisposition::Added
        );
        let stale_index = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;

        // Changing the key forces the rebuild (Replaced) path: a fresh
        // tunnel, a fresh index, and the old index RETIRED.
        assert_eq!(
            engine.configure_peer(&config(0x72)).expect("rebuild"),
            super::ConfigurePeerDisposition::Replaced
        );
        let live_index = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;
        assert_ne!(
            stale_index, live_index,
            "a rebuild must mint a fresh tunnel index"
        );

        // The stale index resolves to NOTHING — never to the rebuilt peer.
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(stale_index)),
            None,
            "a retired index must not attribute to the rebuilt peer"
        );
        // The live index resolves to the rebuilt peer.
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(live_index)),
            Some(node_id.clone())
        );

        // Roaming (EndpointMoved) keeps the SAME index live: only a rebuild
        // or a removal retires an index.
        let mut roamed = config(0x72);
        roamed.endpoint = SocketEndpoint {
            addr: "203.0.113.51".parse().expect("ip"),
            port: 51999,
        };
        assert_eq!(
            engine.configure_peer(&roamed).expect("roam"),
            super::ConfigurePeerDisposition::EndpointMoved
        );
        assert_eq!(
            engine
                .peer_states
                .get(&node_id)
                .expect("peer present")
                .tunnel_index,
            live_index,
            "roaming must not rotate the tunnel index"
        );
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(live_index)),
            Some(node_id),
            "the index must survive the endpoint move"
        );
    }

    #[test]
    fn removed_peer_receiver_index_entry_is_gone() {
        let mut engine = fresh_engine(0x62);
        let node_id = configure_peer_at(
            &mut engine,
            "peer-removed",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 52)), 51820),
            0x73,
            "100.64.52.0/24",
        );
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };
        let index = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(index)),
            Some(node_id.clone())
        );

        assert!(engine.remove_peer(&node_id));
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(index)),
            None,
            "a removed peer's index must resolve to nothing"
        );
        assert_eq!(
            engine.receiver_index_map_for_test().len(),
            engine.peer_states.len(),
            "the map stays exactly as long as the live peer set"
        );
        assert_eq!(
            engine.receiver_index_divergence_drops(),
            0,
            "lockstep mutation never produces a divergence drop"
        );
    }

    #[test]
    fn duplicate_tunnel_index_collision_refusal_is_a_clean_no_op() {
        let mut engine = fresh_engine(0x63);
        let peer_a = configure_peer_at(
            &mut engine,
            "peer-a",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 53)), 51820),
            0x74,
            "100.64.53.0/24",
        );
        let peer_b = configure_peer_at(
            &mut engine,
            "peer-b",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 54)), 51820),
            0x75,
            "100.64.54.0/24",
        );
        let index_a = engine
            .peer_states
            .get(&peer_a)
            .expect("peer a present")
            .tunnel_index;
        let index_b = engine
            .peer_states
            .get(&peer_b)
            .expect("peer b present")
            .tunnel_index;
        assert_ne!(index_a, index_b);
        let peers_before = engine.peer_states.len();
        let map_before = engine.receiver_index_map_for_test().len();

        // Force the collision through the private helper directly — no
        // public mutator can produce it (the allocator is monotonic), so a
        // hit here would mean internal corruption.
        let err = engine
            .set_tunnel_index(&peer_b, index_a)
            .expect_err("a live index held by another peer must be refused");
        assert!(
            err.to_string().contains("already maps"),
            "refusal should name the collision: {err}"
        );

        // Clean no-op: both tables unchanged, existing routing intact.
        assert_eq!(engine.peer_states.len(), peers_before);
        assert_eq!(engine.receiver_index_map_for_test().len(), map_before);
        assert_eq!(
            engine.receiver_index_map_for_test().get(&index_a),
            Some(&peer_a),
            "the refusing write must not have stolen the entry"
        );
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(index_a)),
            Some(peer_a.clone()),
            "the existing holder must still resolve"
        );
        assert_eq!(
            engine.find_node_id_by_receiver_index(&data_packet(index_b)),
            Some(peer_b),
            "the refused peer must still resolve on its own index"
        );
    }

    // A diverged receiver-index entry (naming a peer with no live state)
    // is internal corruption; the packet path must fail closed on it in
    // EVERY build — drop and count, no endpoint re-attribution, no panic or
    // assertion — because a panic kills the engine's worker thread.
    #[test]
    fn receiver_index_dispatch_never_panics_on_divergence() {
        let mut engine = fresh_engine(0x65);
        let node_id = configure_peer_at(
            &mut engine,
            "peer-live",
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)), 51820),
            0x76,
            "100.64.55.0/24",
        );
        let index = engine
            .peer_states
            .get(&node_id)
            .expect("peer present")
            .tunnel_index;
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };

        // Inject the divergence no public mutator can produce: an entry
        // naming a peer with no live state.
        let ghost = NodeId::new("ghost").expect("node id");
        engine.receiver_index_map_for_test().insert(index, ghost);

        let foreign_src: SocketAddr = "198.51.100.9:41000".parse().expect("addr");
        let local: SocketAddr = "10.0.0.1:51820".parse().expect("addr");
        let mut sink = RecordingSink::default();

        // From a foreign source there is no endpoint fallback either: the
        // datagram must be dropped cleanly (Ok(None)), never panic.
        let outcome = engine
            .process_inbound_ciphertext(foreign_src, local, &data_packet(index), 1, &mut sink)
            .expect("inbound processing must not error");
        assert!(outcome.is_none(), "a diverged index resolves to nothing");
        assert_eq!(
            engine.receiver_index_divergence_drops(),
            1,
            "the drop must be counted"
        );

        // From the peer's REAL endpoint the same diverged index is dropped
        // too: a datagram claiming a session the engine no longer holds is
        // never re-attributed by source address, even to the live peer that
        // owns that address.
        let peer_endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 55)), 51820);
        let outcome = engine
            .process_inbound_ciphertext(peer_endpoint, local, &data_packet(index), 1, &mut sink)
            .expect("inbound processing must not error");
        assert!(
            outcome.is_none(),
            "a diverged index is dropped even from the live peer's own endpoint"
        );
        assert_eq!(
            engine.receiver_index_divergence_drops(),
            2,
            "the second diverged lookup is counted too"
        );
        // The endpoint index itself is intact: a datagram WITHOUT a claimed
        // session (a handshake init carries no receiver index) would still
        // resolve to the live peer by its endpoint.
        assert_eq!(
            engine.find_node_id_by_endpoint(peer_endpoint),
            Some(node_id),
            "the endpoint index still resolves the live peer"
        );
    }

    #[test]
    fn receiver_index_agrees_with_peer_states_under_random_mutations() {
        let mut engine = fresh_engine(0x66);

        // Same deterministic xorshift64* PRNG as the endpoint-index fuzz: a
        // fixed seed keeps a failure exactly reproducible.
        let mut rng: u64 = 0x9E37_79B9_7F4A_7C15;
        let mut next_u64 = || {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            rng.wrapping_mul(0x2545_F491_4F6C_DD1D)
        };

        let endpoints: Vec<SocketAddr> = (0..6)
            .map(|i| {
                SocketAddr::new(
                    IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200 + i as u8)),
                    51820 + i as u16,
                )
            })
            .collect();
        let peer_names: Vec<String> = (0..8).map(|i| format!("rpeer-{i}")).collect();

        // Linear-scan REFERENCE implementation: what the old per-packet scan
        // answered for a receiver index — the first (lowest-NodeId) live
        // peer whose tunnel_index equals the probed one.
        let reference_lookup = |engine: &UserspaceEngine, index: u32| -> Option<NodeId> {
            engine
                .peer_states
                .iter()
                .find(|(_node_id, state)| state.tunnel_index == index)
                .map(|(node_id, _state)| node_id.clone())
        };
        let data_packet = |tunnel_index: u32| {
            let mut pkt = vec![4u8, 0, 0, 0];
            pkt.extend_from_slice(&(tunnel_index << 8).to_le_bytes());
            pkt.extend_from_slice(&[0u8; 60]);
            pkt
        };

        for step in 0..400_u32 {
            let roll = next_u64() % 3;
            match roll {
                0 => {
                    let name = &peer_names[(next_u64() as usize) % peer_names.len()];
                    let endpoint = endpoints[(next_u64() as usize) % endpoints.len()];
                    configure_peer_at(
                        &mut engine,
                        name,
                        endpoint,
                        (next_u64() as u8) | 0x80,
                        "100.64.9.0/24",
                    );
                }
                1 => {
                    let node_ids: Vec<NodeId> = engine.peer_states.keys().cloned().collect();
                    if let Some(node_id) =
                        node_ids.get((next_u64() as usize) % node_ids.len().max(1))
                    {
                        let node_id = node_id.clone();
                        let endpoint = endpoints[(next_u64() as usize) % endpoints.len()];
                        engine
                            .update_peer_endpoint(
                                &node_id,
                                rustynet_backend_api::SocketEndpoint {
                                    addr: endpoint.ip(),
                                    port: endpoint.port(),
                                },
                            )
                            .expect("endpoint update succeeds");
                    }
                }
                _ => {
                    let node_ids: Vec<NodeId> = engine.peer_states.keys().cloned().collect();
                    if let Some(node_id) =
                        node_ids.get((next_u64() as usize) % node_ids.len().max(1))
                    {
                        let node_id = node_id.clone();
                        assert!(engine.remove_peer(&node_id));
                    }
                }
            }

            // The bijection must hold after EVERY mutation, and the map must
            // answer exactly the linear-scan reference for every live index
            // plus one index that was never minted.
            engine.verify_receiver_index_consistent();
            let mut probe_indexes: Vec<u32> = engine
                .peer_states
                .values()
                .map(|state| state.tunnel_index)
                .collect();
            probe_indexes.push(engine.next_tunnel_index); // never minted
            for index in &probe_indexes {
                let expected = reference_lookup(&engine, *index);
                assert_eq!(
                    engine.find_node_id_by_receiver_index(&data_packet(*index)),
                    expected,
                    "step {step}: receiver_index lookup diverged from linear-scan reference for index {index}"
                );
            }
        }
    }

    // ---- AllowedIpNetwork::parse: pure CIDR validation ----

    #[test]
    fn allowed_ip_parse_accepts_and_masks_ipv4_network() {
        // Host bits below the prefix must be masked off: 100.64.5.5/10 is the
        // 100.64.0.0/10 network.
        let net = AllowedIpNetwork::parse("100.64.5.5/10").expect("valid v4 CIDR");
        assert_eq!(net.prefix_len, 10);
        assert_eq!(net.network, IpAddr::V4(Ipv4Addr::new(100, 64, 0, 0)));
        assert!(net.contains(IpAddr::V4(Ipv4Addr::new(100, 64, 200, 1))));
        assert!(!net.contains(IpAddr::V4(Ipv4Addr::new(100, 128, 0, 1))));
    }

    #[test]
    fn allowed_ip_parse_accepts_host_routes_and_ipv6() {
        AllowedIpNetwork::parse("10.0.0.1/32").expect("v4 host route");
        AllowedIpNetwork::parse("2001:db8::1/128").expect("v6 host route");
        let v6 = AllowedIpNetwork::parse("2001:db8::/32").expect("valid v6 CIDR");
        assert_eq!(v6.prefix_len, 32);
    }

    fn assert_parse_rejects(cidr: &str, needle: &str) {
        let err = AllowedIpNetwork::parse(cidr).expect_err("must reject");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput, "for {cidr:?}");
        assert!(
            err.message.contains(needle),
            "for {cidr:?}: expected message containing {needle:?}, got {:?}",
            err.message
        );
    }

    #[test]
    fn allowed_ip_parse_rejects_missing_prefix_separator() {
        assert_parse_rejects("100.64.0.0", "must be valid CIDR strings");
    }

    #[test]
    fn allowed_ip_parse_rejects_invalid_network_address() {
        assert_parse_rejects("not-an-ip/24", "invalid network address");
    }

    #[test]
    fn allowed_ip_parse_rejects_non_numeric_prefix() {
        assert_parse_rejects("10.0.0.0/ab", "invalid prefix length");
        // Out of u8 range also fails the numeric parse, not the bound check.
        assert_parse_rejects("10.0.0.0/256", "invalid prefix length");
    }

    #[test]
    fn allowed_ip_parse_rejects_oversized_ipv4_prefix() {
        assert_parse_rejects("10.0.0.0/33", "IPv4 prefix length must be <= 32");
    }

    #[test]
    fn allowed_ip_parse_rejects_oversized_ipv6_prefix() {
        assert_parse_rejects("2001:db8::/129", "IPv6 prefix length must be <= 128");
    }

    // ---- from_private_key_file: key-material loading ----

    #[test]
    fn from_private_key_file_loads_valid_32_byte_key() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([7u8; 32])).expect("write key");
        UserspaceEngine::from_private_key_file(&path).expect("valid key must load");
    }

    #[test]
    fn from_private_key_file_tolerates_trailing_whitespace() {
        // Keys are commonly written with a trailing newline; it must be trimmed.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, format!("{}\n", BASE64_STANDARD.encode([3u8; 32])))
            .expect("write key");
        UserspaceEngine::from_private_key_file(&path).expect("key with newline must load");
    }

    #[test]
    fn from_private_key_file_rejects_missing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("absent.key");
        let err = UserspaceEngine::from_private_key_file(&path).expect_err("missing file");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(err.message.contains("open failed"), "got {:?}", err.message);
    }

    #[test]
    fn from_private_key_file_rejects_invalid_base64() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, "!!! not base64 !!!").expect("write");
        let err = UserspaceEngine::from_private_key_file(&path).expect_err("bad base64");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(
            err.message.contains("decode failed"),
            "got {:?}",
            err.message
        );
    }

    #[test]
    fn from_private_key_file_rejects_wrong_key_length() {
        // A well-formed base64 blob that decodes to 16 bytes, not 32.
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("wg.key");
        std::fs::write(&path, BASE64_STANDARD.encode([9u8; 16])).expect("write");
        let err = UserspaceEngine::from_private_key_file(&path).expect_err("wrong length");
        assert_eq!(err.kind, BackendErrorKind::Internal);
        assert!(
            err.message.contains("length invalid") && err.message.contains("expected 32 bytes"),
            "got {:?}",
            err.message
        );
    }

    // --- EngineIoSink dispatch tests (P1 follow-up to commit 049ed1e5) ---
    //
    // 049ed1e5 replaced the owned per-frame outcome Vecs with the `EngineIoSink`
    // streaming dispatch but shipped no tests that exercise the dispatch seam
    // directly. These tests pin the sink contract at the dispatch level:
    // ciphertext is sent immediately (borrowed), inbound plaintext is returned
    // borrowed WITHOUT touching the sink, Done/Err dispatch to nothing, and
    // `drive_inbound_result` flushes the deferred inbound plaintext only AFTER
    // the follow-up drain loop — the ciphertext-then-plaintext ordering every
    // caller relies on. The full mixed case (initial WriteToTunnelV4 whose
    // follow-up drain flushes boringtun's queued outbound backlog as
    // ciphertext) needs choreographed boringtun session/timer state and remains
    // documented as a known gap in 049ed1e5's commit message; a fresh tunnel's
    // drain deterministically yields Done, which is what lets these tests pin
    // the defer-then-flush sequencing without that choreography.

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum SinkEvent {
        Ciphertext { to: SocketAddr, payload: Vec<u8> },
        Plaintext(Vec<u8>),
    }

    #[derive(Debug, Default)]
    struct RecordingSink {
        events: Vec<SinkEvent>,
    }

    impl super::EngineIoSink for RecordingSink {
        fn send_ciphertext(
            &mut self,
            remote_addr: SocketAddr,
            payload: &[u8],
        ) -> Result<(), rustynet_backend_api::BackendError> {
            self.events.push(SinkEvent::Ciphertext {
                to: remote_addr,
                payload: payload.to_vec(),
            });
            Ok(())
        }

        fn write_plaintext(
            &mut self,
            payload: &[u8],
        ) -> Result<(), rustynet_backend_api::BackendError> {
            self.events.push(SinkEvent::Plaintext(payload.to_vec()));
            Ok(())
        }
    }

    fn remote_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 70)), 51820)
    }

    #[test]
    fn dispatch_sends_outbound_ciphertext_immediately_and_returns_no_plaintext() {
        use boringtun::noise::TunnResult;
        use boringtun::noise::errors::WireGuardError;

        let node_id = NodeId::new("sender").expect("node id");
        let mut recorded = Vec::new();
        let mut sink = RecordingSink::default();
        let mut packet = vec![7u8; 64];
        let expected_payload = packet.clone();

        let dispatched = super::handle_single_tunn_result(
            &node_id,
            remote_addr(),
            42,
            TunnResult::WriteToNetwork(&mut packet),
            &mut recorded,
            &mut sink,
        )
        .expect("ciphertext dispatch never errors");

        assert_eq!(dispatched, None, "WriteToNetwork produces no plaintext");
        assert_eq!(
            sink.events,
            vec![SinkEvent::Ciphertext {
                to: remote_addr(),
                payload: expected_payload,
            }],
            "ciphertext must be sent to the peer's address with untouched bytes"
        );
        assert!(
            recorded.is_empty(),
            "ciphertext results must not touch the plaintext recorder"
        );

        // Done and Err dispatch to nothing at all: no send, no write, no error.
        for (label, result) in [
            ("Done", TunnResult::Done),
            ("Err", TunnResult::Err(WireGuardError::ConnectionExpired)),
        ] {
            let mut sink = RecordingSink::default();
            let dispatched = super::handle_single_tunn_result(
                &node_id,
                remote_addr(),
                42,
                result,
                &mut recorded,
                &mut sink,
            )
            .unwrap_or_else(|err| panic!("{label} result must not dispatch to an error: {err:?}"));
            assert_eq!(dispatched, None, "{label} produces no plaintext");
            assert!(sink.events.is_empty(), "{label} must emit nothing");
        }
    }

    #[test]
    fn dispatch_returns_borrowed_inbound_plaintext_without_touching_sink() {
        use boringtun::noise::TunnResult;

        let node_id = NodeId::new("sender").expect("node id");
        let mut recorded = Vec::new();
        let mut sink = RecordingSink::default();
        let mut v4_frame = vec![0xAB; 100];
        let v4_expected = v4_frame.clone();

        let dispatched = super::handle_single_tunn_result(
            &node_id,
            remote_addr(),
            7,
            TunnResult::WriteToTunnelV4(&mut v4_frame, Ipv4Addr::from([10, 0, 0, 1])),
            &mut recorded,
            &mut sink,
        )
        .expect("inbound plaintext dispatch never errors");

        assert_eq!(
            dispatched,
            Some(&v4_expected[..]),
            "inbound plaintext must be returned BORROWED, byte-identical"
        );
        assert!(
            sink.events.is_empty(),
            "handle_single_tunn_result must never write plaintext itself — the caller sequences the flush"
        );
        assert_eq!(
            recorded,
            vec![super::RecordedTunnelPlaintextPacket {
                node_id: node_id.clone(),
                packet: v4_expected,
                transport_generation: 7,
            }],
            "the cfg(test) plaintext recorder must still capture the frame (same bytes, same generation)"
        );

        let mut v6_frame = vec![0xCD; 80];
        let v6_expected = v6_frame.clone();
        let dispatched = super::handle_single_tunn_result(
            &node_id,
            remote_addr(),
            8,
            TunnResult::WriteToTunnelV6(&mut v6_frame, std::net::Ipv6Addr::LOCALHOST),
            &mut recorded,
            &mut sink,
        )
        .expect("inbound plaintext dispatch never errors");
        assert_eq!(dispatched, Some(&v6_expected[..]));
        assert_eq!(recorded.len(), 2, "V6 frame recorded too");
        assert!(sink.events.is_empty());
    }

    #[test]
    fn drive_inbound_result_flushes_deferred_plaintext_after_the_follow_up_drain() {
        use boringtun::noise::TunnResult;

        let endpoint = remote_addr();
        let mut engine = fresh_engine(3);
        let node_id = configure_peer_at(&mut engine, "peer-a", endpoint, 0x33, "100.64.0.5/32");

        let mut recorded = Vec::new();
        let mut sink = RecordingSink::default();
        let mut follow_up_scratch = vec![0u8; super::MAX_ENCRYPTED_PACKET_BYTES];
        let mut plaintext_frame = vec![0x42; 96];
        let plaintext_expected = plaintext_frame.clone();

        // A freshly configured tunnel has no established session, so the
        // follow-up drain's `decapsulate(None, &[], _)` deterministically
        // yields Done — the loop below must emit nothing and then flush the
        // deferred inbound plaintext exactly once, at the END.
        let peer_state = engine.peer_states.get_mut(&node_id).expect("peer");
        let outcome = super::drive_inbound_result(
            &node_id,
            peer_state,
            endpoint,
            42,
            TunnResult::WriteToTunnelV4(&mut plaintext_frame, Ipv4Addr::from([10, 0, 0, 2])),
            &mut recorded,
            follow_up_scratch.as_mut_slice(),
            &mut sink,
        )
        .expect("fresh-tunnel drain is inert");

        assert_eq!(outcome, None, "no handshake has completed yet");
        assert_eq!(
            sink.events,
            vec![SinkEvent::Plaintext(plaintext_expected.clone())],
            "deferred inbound plaintext must be flushed exactly once, AFTER the (inert) drain loop"
        );
        assert_eq!(
            recorded,
            vec![super::RecordedTunnelPlaintextPacket {
                node_id: node_id.clone(),
                packet: plaintext_expected,
                transport_generation: 42,
            }],
            "recorder must see the same frame with the same generation"
        );
    }

    #[test]
    fn drive_inbound_result_with_initial_err_emits_nothing_and_stays_ok() {
        use boringtun::noise::TunnResult;
        use boringtun::noise::errors::WireGuardError;

        let endpoint = remote_addr();
        let mut engine = fresh_engine(4);
        let node_id = configure_peer_at(&mut engine, "peer-b", endpoint, 0x44, "100.64.0.6/32");

        let mut recorded = Vec::new();
        let mut sink = RecordingSink::default();
        let mut follow_up_scratch = vec![0u8; super::MAX_ENCRYPTED_PACKET_BYTES];

        // An initial Err skips the drain entirely (fail closed on that call's
        // results) and emits nothing; the drive returns Ok with no handshake.
        let peer_state = engine.peer_states.get_mut(&node_id).expect("peer");
        let outcome = super::drive_inbound_result(
            &node_id,
            peer_state,
            endpoint,
            42,
            TunnResult::Err(WireGuardError::ConnectionExpired),
            &mut recorded,
            follow_up_scratch.as_mut_slice(),
            &mut sink,
        )
        .expect("initial Err is not a drive-level failure");

        assert_eq!(outcome, None);
        assert!(sink.events.is_empty(), "an initial Err must emit nothing");
        assert!(recorded.is_empty());
    }

    /// Regression test for the handshake-initiation scratch reuse: peers take
    /// turns writing into ONE long-lived engine buffer, so each initiation
    /// must emit a complete, valid, fixed-size handshake message with no
    /// stale bytes from the previous writer's message.
    #[test]
    fn initiate_handshake_reuses_engine_scratch_with_byte_identical_output() {
        let endpoint_x = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)), 51820);
        let endpoint_y = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 81)), 51820);
        let mut engine = fresh_engine(9);
        let peer_x = configure_peer_at(&mut engine, "peer-x", endpoint_x, 0x55, "100.64.8.0/24");
        let peer_y = configure_peer_at(&mut engine, "peer-y", endpoint_y, 0x66, "100.64.9.0/24");

        let mut sink = RecordingSink::default();

        // First initiation writes peer-x's handshake into the shared scratch.
        // A fresh initiation has only STARTED the handshake; `observed` is the
        // authenticated-handshake timestamp, which stays `None` until a full
        // response exchange completes.
        let observed = engine
            .initiate_handshake(&peer_x, 1, false, &mut sink)
            .expect("first initiation never errors");
        assert_eq!(
            observed, None,
            "a fresh initiation has no completed handshake"
        );
        let payload_x: Vec<u8> = match sink.events.pop() {
            Some(SinkEvent::Ciphertext { payload, .. }) => payload,
            other => panic!("first initiation must emit one ciphertext event, got {other:?}"),
        };

        // A second peer reuses the SAME scratch, overwriting peer-x's bytes.
        let observed = engine
            .initiate_handshake(&peer_y, 1, false, &mut sink)
            .expect("second initiation never errors");
        assert_eq!(
            observed, None,
            "a fresh initiation has no completed handshake"
        );
        let payload_y: Vec<u8> = match sink.events.pop() {
            Some(SinkEvent::Ciphertext { payload, .. }) => payload,
            other => panic!("second initiation must emit one ciphertext event, got {other:?}"),
        };
        assert_ne!(
            payload_x, payload_y,
            "the shared scratch must have actually been overwritten by the second initiation"
        );

        // Re-initiating peer-x (`force_resend`) rewrites the shared scratch
        // after peer-y dirtied it. Note the emitted bytes are NOT identical to
        // the first initiation — that is boringtun's own contract, not a
        // scratch artifact: every initiation (including a forced resend)
        // consumes a fresh sender index, and the MACs cover it, so the whole
        // message differs. What must hold is that the resent message is a
        // complete, valid initiation of the exact fixed size, with peer-y's
        // sender index gone from the header — no stale byte from the previous
        // writer may leak into the reported slice.
        engine
            .initiate_handshake(&peer_x, 1, true, &mut sink)
            .expect("resend never errors");
        let payload_x_resent: Vec<u8> = match sink.events.pop() {
            Some(SinkEvent::Ciphertext { payload, .. }) => payload,
            other => panic!("resend must emit one ciphertext event, got {other:?}"),
        };
        // boringtun's private HANDSHAKE_INIT_SZ: a handshake initiation is a
        // fixed-size 148-byte message, so every writer overwrites the whole
        // reported slice each time.
        assert_eq!(
            payload_x.len(),
            148,
            "handshake initiation is a fixed-size message"
        );
        assert_eq!(
            payload_y.len(),
            148,
            "handshake initiation is a fixed-size message"
        );
        assert_eq!(
            payload_x_resent.len(),
            148,
            "forced resend over the dirty scratch must still emit a full-size initiation"
        );
        for (label, payload) in [
            ("first", &payload_x),
            ("second", &payload_y),
            ("resent", &payload_x_resent),
        ] {
            assert_eq!(
                payload[0], 1u8,
                "{label} initiation must carry the handshake-initiation type byte"
            );
        }
        let sender_index = |payload: &[u8]| -> u32 {
            u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]])
        };
        assert_ne!(
            sender_index(&payload_x),
            sender_index(&payload_y),
            "peer-y's initiation must overwrite peer-x's sender index in the shared scratch"
        );
        assert_ne!(
            sender_index(&payload_x_resent),
            sender_index(&payload_y),
            "the resent initiation must carry peer-x's fresh index, not peer-y's stale one"
        );
        assert!(sink.events.is_empty());
    }

    /// Builds a minimal IPv4 packet (no checksum — boringtun neither verifies
    /// nor recomputes it on the encapsulate/decapsulate path) of
    /// `payload_len` zero bytes destined for `100.64.8.1`, which falls inside
    /// the test peer's allowed_ips.
    fn ipv4_packet_for_peer(payload_len: usize) -> Vec<u8> {
        let total_len = 20 + payload_len;
        let mut packet = vec![0u8; total_len];
        packet[0] = 0x45; // version 4, IHL 5
        packet[8] = 64; // TTL
        packet[9] = 6; // proto TCP (arbitrary; datapath does not inspect)
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[16..20].copy_from_slice(&[100, 64, 8, 1]); // destination
        packet
    }

    /// Advance the clock boringtun's timers read. With the forwarded
    /// `boringtun-mock-instant` feature (always on under the workspace gate)
    /// that is the mock clock, which a sleep can never move; otherwise it is
    /// wall time.
    fn advance_engine_clock(by: std::time::Duration) {
        #[cfg(feature = "boringtun-mock-instant")]
        {
            boringtun::mock_instant::MockClock::advance(by);
        }
        #[cfg(not(feature = "boringtun-mock-instant"))]
        {
            std::thread::sleep(by);
        }
    }

    /// Pops a single ciphertext event, returning its payload.
    fn pop_ciphertext(sink: &mut RecordingSink, label: &str) -> Vec<u8> {
        match sink.events.pop() {
            Some(SinkEvent::Ciphertext { payload, .. }) => payload,
            other => panic!("{label} must emit one ciphertext event, got {other:?}"),
        }
    }

    /// End-to-end proof for the shared `encrypt_scratch`: a live WireGuard
    /// session is established through the engine's public API (initiation →
    /// counterpart tunnel response → engine decapsulate), after which data
    /// frames of every interesting length are encapsulated into the SAME
    /// scratch buffer the 148-byte handshake used. Each emitted ciphertext
    /// must be exactly `32 + pad16(len)` bytes (never a byte more) and must
    /// decrypt on the counterpart to the exact input — the byte-identity /
    /// stale-bytes proof the scratch reuse requires. Finally, a persistent
    /// keepalive (32 bytes, shorter than everything before it) is driven
    /// through `update_peer_timers` over a scratch still holding the 65 KiB
    /// max frame, and the counterpart must accept it.
    #[test]
    fn shared_scratch_roundtrips_handshake_then_variable_length_frames() {
        use boringtun::noise::{Tunn, TunnResult};
        use boringtun::x25519::{PublicKey, StaticSecret};

        // The engine's static key is `[seed; 32]` (see `fresh_engine`); derive
        // its public key and build a real counterpart tunnel around a peer key
        // pair so the three-message handshake completes for real.
        let engine_secret = StaticSecret::from([9u8; 32]);
        let engine_public = PublicKey::from(&engine_secret);
        let peer_secret = StaticSecret::from([0x55; 32]);
        let peer_public_bytes = *PublicKey::from(&peer_secret).as_bytes();

        let endpoint = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 80)), 51820);
        let mut engine = fresh_engine(9);
        let node_id = NodeId::new("peer-x").expect("node id");
        engine
            .configure_peer(&rustynet_backend_api::PeerConfig {
                node_id: node_id.clone(),
                endpoint: rustynet_backend_api::SocketEndpoint {
                    addr: endpoint.ip(),
                    port: endpoint.port(),
                },
                public_key: peer_public_bytes,
                allowed_ips: vec!["100.64.8.0/24".to_owned()],
                persistent_keepalive_secs: Some(1),
            })
            .expect("peer configures");
        let mut counterpart = Tunn::new(peer_secret, engine_public, None, None, 0, None);

        let mut sink = RecordingSink::default();

        // msg1: engine initiates; scratch now holds the 148-byte handshake.
        let observed = engine
            .initiate_handshake(&node_id, 1, false, &mut sink)
            .expect("initiation never errors");
        assert_eq!(
            observed, None,
            "an initiation starts but does not complete a handshake"
        );
        let initiation = pop_ciphertext(&mut sink, "handshake initiation");
        assert_eq!(initiation.len(), 148, "msg1 is a fixed-size message");

        // msg2: the counterpart tunnel responds.
        let mut counterpart_buf = vec![0u8; 65_567];
        let response: Vec<u8> =
            match counterpart.decapsulate(None, &initiation, &mut counterpart_buf) {
                TunnResult::WriteToNetwork(packet) => packet.to_vec(),
                other => panic!("counterpart must answer the initiation, got {other:?}"),
            };

        // The engine consumes msg2 over the shared scratch pair; the session
        // is now established on both sides. boringtun follows msg2 with a
        // 32-byte empty transport packet (the initiator's ack), which the
        // counterpart must accept as a keepalive.
        let observed = engine
            .process_inbound_ciphertext(endpoint, remote_addr(), &response, 1, &mut sink)
            .expect("msg2 never errors");
        let (observed_peer, _observed_at) =
            observed.expect("msg2 completes the session; the handshake timestamps");
        assert_eq!(
            observed_peer, node_id,
            "the completed handshake is peer-x's"
        );
        let ack = pop_ciphertext(&mut sink, "post-handshake empty transport packet");
        assert_eq!(ack.len(), 32, "the ack is a bare empty transport packet");
        match counterpart.decapsulate(None, &ack, &mut counterpart_buf) {
            TunnResult::Done => {}
            other => panic!("counterpart must accept the ack, got {other:?}"),
        }

        // Data frames: empty is not reachable through the TUN-facing
        // `inject_plaintext_packet` (a zero-byte buffer carries no IP
        // destination and is a keepalive, not a frame), so the length ladder
        // covers min (28 = bare IPv4 header), odd (37), typical (1500), and
        // WG max inner (65 503 = 65 535 - 32). The scratch's last writer is
        // the 148-byte handshake for the first frame and each successive
        // frame for the rest — every emission must be exactly the padded
        // transport-header+tag length, and must decrypt back to the input.
        let frame_lengths = [28usize, 37, 1500, 65_503];
        for len in frame_lengths {
            let plaintext = ipv4_packet_for_peer(len);
            engine
                .inject_plaintext_packet(&plaintext, 1, &mut sink)
                .expect("frame with a matching allowed_ip never errors");
            let ciphertext = pop_ciphertext(&mut sink, "data frame");
            // This boringtun fork does not pad to 16 (session.rs: "spec
            // requires padding to 16 bytes, but actually works fine without
            // it"): the frame is exactly 16-byte transport header +
            // plaintext + 16-byte AEAD tag.
            assert_eq!(
                ciphertext.len(),
                plaintext.len() + 32,
                "frame must emit exactly plaintext+32 ciphertext bytes"
            );
            let decrypted = match counterpart.decapsulate(None, &ciphertext, &mut counterpart_buf) {
                TunnResult::WriteToTunnelV4(packet, _) => packet.to_vec(),
                other => panic!("counterpart must decrypt the frame, got {other:?}"),
            };
            assert_eq!(
                decrypted, plaintext,
                "roundtrip through the shared scratch must be byte-identical"
            );
        }

        // Shorter reuse over the dirtiest scratch: silence past the 1-second
        // persistent keepalive, then tick. `update_peer_timers` must emit a
        // bare 32-byte keepalive — the shortest message on this path — out of
        // a scratch still holding the 65 KiB max frame, and the counterpart
        // must accept it (Done: an empty inner payload is a keepalive, not a
        // tunnel write). Any stale byte after the 32-byte slice would have
        // been observable in the length or in the counterpart's MAC check.
        // The keepalive is due once a full second of silence has elapsed on
        // boringtun's clock. Under the workspace gate that clock is the
        // `mock-instant` mock (boringtun is an implicit workspace member, so
        // `--workspace --all-features` switches it on) and a wall-clock sleep
        // never advances it; `advance_engine_clock` moves whichever clock is
        // live. Tick until the keepalive appears, bounded so a genuinely
        // missing keepalive still fails loudly instead of hanging.
        advance_engine_clock(std::time::Duration::from_millis(1100));
        let mut observed = Vec::new();
        for _ in 0..50 {
            observed = engine
                .update_peer_timers(1, &mut sink)
                .expect("timer tick never errors");
            if !sink.events.is_empty() {
                break;
            }
            advance_engine_clock(std::time::Duration::from_millis(100));
        }
        // A live session makes `authenticated_handshake_unix` report the
        // established handshake on every tick — that is not a NEW handshake;
        // only the keepalive ciphertext is emitted.
        assert!(
            observed.iter().all(|(peer, _)| *peer == node_id),
            "only peer-x's established session may be reported, got {observed:?}"
        );
        let keepalive = pop_ciphertext(&mut sink, "persistent keepalive");
        assert_eq!(
            keepalive.len(),
            32,
            "keepalive is the 32-byte minimum frame"
        );
        assert!(
            sink.events.is_empty(),
            "the tick must emit exactly one keepalive, got {:?}",
            sink.events
        );
        match counterpart.decapsulate(None, &keepalive, &mut counterpart_buf) {
            TunnResult::Done => {}
            other => panic!("counterpart must accept the keepalive, got {other:?}"),
        }
    }
}
