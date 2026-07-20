use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutboundCiphertextPacket {
    pub(crate) remote_addr: SocketAddr,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub(crate) struct EngineProcessingOutcome {
    pub(crate) outbound_ciphertext_packets: Vec<OutboundCiphertextPacket>,
    pub(crate) tunnel_plaintext_packets: Vec<Vec<u8>>,
    pub(crate) authenticated_handshake: Option<(NodeId, u64)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigurePeerDisposition {
    Added,
    Replaced,
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
    pub(crate) fn from_private_key_file(path: &Path) -> Result<Self, BackendError> {
        // Secret-material hygiene: the on-disk base64 blob and the decoded 32-byte
        // scalar are WireGuard static private key material. Wrap intermediates in
        // `Zeroizing` so any heap-resident copy is overwritten when dropped, and
        // explicitly zeroize the stack-resident `[u8; 32]` after handing a copy to
        // `StaticSecret::from` (the array is `Copy`; the cast does not consume).
        let encoded_private_key: Zeroizing<String> =
            Zeroizing::new(fs::read_to_string(path).map_err(|err| {
                BackendError::internal(format!(
                    "linux userspace-shared private key read failed for {}: {err}",
                    path.display()
                ))
            })?);
        let trimmed_private_key = encoded_private_key.trim();
        let decoded_private_key: Zeroizing<Vec<u8>> = Zeroizing::new(
            BASE64_STANDARD
                .decode(trimmed_private_key.as_bytes())
                .map_err(|err| {
                    BackendError::internal(format!(
                        "linux userspace-shared private key decode failed for {}: {err}",
                        path.display()
                    ))
                })?,
        );
        if decoded_private_key.len() != 32 {
            return Err(BackendError::internal(format!(
                "linux userspace-shared private key length invalid for {}: expected 32 bytes after base64 decode, got {}",
                path.display(),
                decoded_private_key.len()
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
        let tunnel_index = self.allocate_tunnel_index()?;
        let tunnel = Tunn::new(
            self.local_static_private.clone(),
            peer_static_public,
            None,
            None,
            tunnel_index,
            None,
        );

        // All fallible steps are done; from here the peer table and the
        // endpoint reverse index mutate together so they can never diverge.
        let previous_endpoint = self
            .peer_states
            .get(&peer.node_id)
            .map(|existing| existing.endpoint);
        let disposition = if previous_endpoint.is_some() {
            ConfigurePeerDisposition::Replaced
        } else {
            ConfigurePeerDisposition::Added
        };
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
        if let Some(previous_endpoint) = previous_endpoint {
            self.unlink_endpoint(previous_endpoint, &peer.node_id);
        }
        self.link_endpoint(endpoint, peer.node_id.clone());
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

    pub(crate) fn initiate_handshake(
        &mut self,
        node_id: &NodeId,
        transport_generation: u64,
        force_resend: bool,
    ) -> Result<EngineProcessingOutcome, BackendError> {
        let Some(peer_state) = self.peer_states.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        let mut encrypt_buf = vec![0u8; MAX_ENCRYPTED_PACKET_BYTES];
        let initial_result = peer_state
            .tunnel
            .format_handshake_initiation(&mut encrypt_buf, force_resend);
        Ok(drive_outbound_result(
            node_id,
            peer_state,
            transport_generation,
            initial_result,
            &mut self.recorded_tunnel_plaintext_packets,
        ))
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
        match self.peer_states.remove(node_id) {
            Some(removed_state) => {
                // If this peer was the lowest-NodeId holder of a shared
                // endpoint, dropping it from the per-endpoint set promotes
                // the next-lowest sharer — the same answer a fresh linear
                // scan over the remaining peers would produce.
                self.unlink_endpoint(removed_state.endpoint, node_id);
                true
            }
            None => false,
        }
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

    pub(crate) fn process_inbound_ciphertext(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        payload: &[u8],
        transport_generation: u64,
    ) -> Result<EngineProcessingOutcome, BackendError> {
        // Dispatch by the canonical WireGuard receiver index first (handshake
        // responses, cookie replies, and data packets carry it) and fall back to
        // the source-address/endpoint match for handshake inits (which carry no
        // receiver index) and any packet whose index has no live tunnel. This is
        // what lets a non-exit peer's handshake response reach the tunnel that
        // initiated it even before that peer's endpoint is authoritatively pinned.
        //
        // `receiver_index_match` is unavoidably owned — `find_node_id_by_receiver_index`
        // does its own linear scan-and-clone and is out of scope for this change (P4
        // only replaces the endpoint-keyed lookup). The endpoint fallback below is
        // resolved separately, after the split-borrow, as a `&NodeId` straight out of
        // `endpoint_index` — no clone on that path.
        let receiver_index_match = self.find_node_id_by_receiver_index(payload);

        // Unbounded-growth guard: `recorded_peer_ciphertext_ingress` is a test-only
        // observability buffer; persisting every datagram in production would let an
        // attacker exhaust memory via a packet flood and would also retain a
        // long-lived plaintext+ciphertext history that the runtime never reads. The
        // match this records is recomputed with its own (test-only, cfg'd-out of
        // release builds) endpoint lookup + clone; nothing mutates `peer_states` or
        // `endpoint_index` between here and the production dispatch below, so it is
        // guaranteed to agree with the production match.
        #[cfg(test)]
        {
            let _ = local_addr;
            let recorded_match = receiver_index_match
                .clone()
                .or_else(|| self.find_node_id_by_endpoint(remote_addr));
            self.recorded_peer_ciphertext_ingress
                .push(RecordedPeerCiphertextIngress {
                    node_id: recorded_match,
                    local_addr,
                    remote_addr,
                    payload: payload.to_vec(),
                    transport_generation,
                });
        }
        #[cfg(not(test))]
        {
            let _ = local_addr;
            let _ = transport_generation;
        }

        // Split-borrow: `peer_states` (mutable) and `endpoint_index` (read-only here)
        // are disjoint fields of `Self`, so borrowing them independently lets the
        // endpoint-reverse-index fallback hand back a `&NodeId` that feeds
        // `peer_states.get_mut` directly, with no clone — the split-borrow this
        // backlog item asks for.
        let Self {
            peer_states,
            endpoint_index,
            recorded_tunnel_plaintext_packets,
            decrypt_scratch,
            decrypt_follow_up_scratch,
            ..
        } = self;

        let node_id: &NodeId = match &receiver_index_match {
            Some(node_id) => node_id,
            None => {
                let Some(node_id) = Self::endpoint_index_lookup(endpoint_index, remote_addr) else {
                    return Ok(EngineProcessingOutcome::default());
                };
                node_id
            }
        };

        let peer_state = peer_states
            .get_mut(node_id)
            .expect("matched peer state should exist");
        let initial_result =
            peer_state
                .tunnel
                .decapsulate(Some(remote_addr.ip()), payload, decrypt_scratch);
        Ok(drive_inbound_result(
            node_id,
            peer_state,
            remote_addr,
            transport_generation,
            initial_result,
            recorded_tunnel_plaintext_packets,
            decrypt_follow_up_scratch,
        ))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn inject_plaintext_packet(
        &mut self,
        packet: &[u8],
        transport_generation: u64,
    ) -> Result<EngineProcessingOutcome, BackendError> {
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
        Ok(drive_outbound_result(
            &node_id,
            peer_state,
            transport_generation,
            initial_result,
            recorded_tunnel_plaintext_packets,
        ))
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

    /// Canonical WireGuard inbound demux: handshake responses, cookie replies,
    /// and data packets echo our local session index back in `receiver_idx`
    /// (`receiver_idx >> 8 == tunnel_index`, mirroring boringtun's own
    /// `peers_by_idx` dispatch). Resolving the peer by that index — rather than
    /// by the datagram source address — routes a reply to the tunnel that
    /// initiated the handshake even before the peer's endpoint is confirmed,
    /// which is required for tunnels whose endpoint is not authoritatively
    /// pinned. Handshake inits carry no receiver index and unparsable/foreign
    /// datagrams return `None`, both of which fall back to the endpoint match.
    fn find_node_id_by_receiver_index(&self, payload: &[u8]) -> Option<NodeId> {
        let receiver_idx = match Tunn::parse_incoming_packet(payload).ok()? {
            Packet::HandshakeResponse(packet) => packet.receiver_idx,
            Packet::PacketCookieReply(packet) => packet.receiver_idx,
            Packet::PacketData(packet) => packet.receiver_idx,
            Packet::HandshakeInit(_) => return None,
        };
        let tunnel_index = receiver_idx >> 8;
        self.peer_states
            .iter()
            .find(|(_node_id, peer_state)| peer_state.tunnel_index == tunnel_index)
            .map(|(node_id, _peer_state)| node_id.clone())
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

fn drive_inbound_result(
    node_id: &NodeId,
    peer_state: &mut PeerEngineState,
    remote_addr: SocketAddr,
    transport_generation: u64,
    initial_result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
    follow_up_scratch: &mut [u8],
) -> EngineProcessingOutcome {
    let should_drain_follow_ups = !matches!(initial_result, TunnResult::Err(_));
    let mut outcome = handle_single_tunn_result(
        node_id,
        remote_addr,
        transport_generation,
        initial_result,
        recorded_tunnel_plaintext_packets,
    );

    if should_drain_follow_ups {
        loop {
            // Reuse the long-lived drain buffer; each iteration's result is
            // copied out by `handle_single_tunn_result` before the next reuse.
            let follow_up = peer_state.tunnel.decapsulate(None, &[], follow_up_scratch);
            if matches!(follow_up, TunnResult::Done) {
                break;
            }
            let next = handle_single_tunn_result(
                node_id,
                remote_addr,
                transport_generation,
                follow_up,
                recorded_tunnel_plaintext_packets,
            );
            merge_engine_processing_outcomes(&mut outcome, next);
        }
    }

    let observed_handshake = authenticated_handshake_unix(&peer_state.tunnel);
    if let Some(observed_handshake) = observed_handshake {
        outcome.authenticated_handshake = Some((node_id.clone(), observed_handshake));
    }
    outcome
}

#[cfg_attr(not(test), allow(dead_code))]
fn drive_outbound_result(
    node_id: &NodeId,
    peer_state: &mut PeerEngineState,
    transport_generation: u64,
    initial_result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
) -> EngineProcessingOutcome {
    let mut outcome = handle_single_tunn_result(
        node_id,
        peer_state.endpoint,
        transport_generation,
        initial_result,
        recorded_tunnel_plaintext_packets,
    );
    let observed_handshake = authenticated_handshake_unix(&peer_state.tunnel);
    if let Some(observed_handshake) = observed_handshake {
        outcome.authenticated_handshake = Some((node_id.clone(), observed_handshake));
    }
    outcome
}

fn handle_single_tunn_result(
    node_id: &NodeId,
    remote_addr: SocketAddr,
    transport_generation: u64,
    result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
) -> EngineProcessingOutcome {
    // `node_id` is consumed only by the `cfg(test)` plaintext-recording fixtures
    // below; in production builds it is otherwise unused now that the redundant
    // per-result handshake observation has moved to the drive functions.
    #[cfg(not(test))]
    let _ = node_id;
    let mut outcome = EngineProcessingOutcome::default();
    match result {
        TunnResult::Done | TunnResult::Err(_) => {}
        TunnResult::WriteToNetwork(packet) => {
            outcome
                .outbound_ciphertext_packets
                .push(OutboundCiphertextPacket {
                    remote_addr,
                    payload: packet.to_vec(),
                });
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
            outcome.tunnel_plaintext_packets.push(packet.to_vec());
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
            outcome.tunnel_plaintext_packets.push(packet.to_vec());
        }
    }

    // The observed-handshake timestamp is computed once per drive (at the end
    // of `drive_inbound_result` / `drive_outbound_result`), which always
    // overwrites this outcome's value. Computing it per result here is pure
    // redundancy (an extra `Tunn::stats()` + clock read per Tunn result), so it
    // is intentionally omitted — `authenticated_handshake` stays `None` here and
    // is filled in by the drive function. Handshake time is monotonic, so the
    // end-of-drive value is always >= any per-result observation.
    outcome
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

fn merge_engine_processing_outcomes(
    current: &mut EngineProcessingOutcome,
    next: EngineProcessingOutcome,
) {
    current
        .outbound_ciphertext_packets
        .extend(next.outbound_ciphertext_packets);
    current
        .tunnel_plaintext_packets
        .extend(next.tunnel_plaintext_packets);
    match (
        &current.authenticated_handshake,
        next.authenticated_handshake,
    ) {
        (_, None) => {}
        (None, Some(observed)) => current.authenticated_handshake = Some(observed),
        (Some((current_node_id, current_unix)), Some((next_node_id, next_unix)))
            if current_node_id == &next_node_id && next_unix > *current_unix =>
        {
            current.authenticated_handshake = Some((next_node_id, next_unix));
        }
        _ => {}
    }
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
        // `ConfigurePeerDisposition::Replaced` path), as happens on a
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
        assert!(err.message.contains("read failed"), "got {:?}", err.message);
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
}
