use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use rustynet_backend_api::{BackendError, NodeId, PeerConfig, SocketEndpoint};

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
    local_static_public: PublicKey,
    next_tunnel_index: u32,
    peer_states: BTreeMap<NodeId, PeerEngineState>,
    recorded_peer_ciphertext_ingress: Vec<RecordedPeerCiphertextIngress>,
    recorded_tunnel_plaintext_packets: Vec<RecordedTunnelPlaintextPacket>,
}

struct PeerEngineState {
    peer_static_public: PublicKey,
    endpoint: SocketAddr,
    allowed_ips: Vec<AllowedIpNetwork>,
    tunnel: Tunn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllowedIpNetwork {
    network: IpAddr,
    prefix_len: u8,
}

impl UserspaceEngine {
    pub(crate) fn from_private_key_file(path: &Path) -> Result<Self, BackendError> {
        let encoded_private_key = fs::read_to_string(path).map_err(|err| {
            BackendError::internal(format!(
                "linux userspace-shared private key read failed for {}: {err}",
                path.display()
            ))
        })?;
        let trimmed_private_key = encoded_private_key.trim();
        let decoded_private_key = BASE64_STANDARD
            .decode(trimmed_private_key.as_bytes())
            .map_err(|err| {
                BackendError::internal(format!(
                    "linux userspace-shared private key decode failed for {}: {err}",
                    path.display()
                ))
            })?;
        let private_key_bytes: [u8; 32] =
            decoded_private_key.try_into().map_err(|bytes: Vec<u8>| {
                BackendError::internal(format!(
                    "linux userspace-shared private key length invalid for {}: expected 32 bytes after base64 decode, got {}",
                    path.display(),
                    bytes.len()
                ))
            })?;

        let local_static_private = StaticSecret::from(private_key_bytes);
        let local_static_public = PublicKey::from(&local_static_private);

        Ok(Self {
            local_static_private,
            local_static_public,
            next_tunnel_index: 1,
            peer_states: BTreeMap::new(),
            recorded_peer_ciphertext_ingress: Vec::new(),
            recorded_tunnel_plaintext_packets: Vec::new(),
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
        let tunnel = Tunn::new(
            self.local_static_private.clone(),
            peer_static_public,
            None,
            None,
            self.allocate_tunnel_index()?,
            None,
        );

        let disposition = if self.peer_states.contains_key(&peer.node_id) {
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
            },
        );
        Ok(disposition)
    }

    pub(crate) fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        let Some(peer_state) = self.peer_states.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        peer_state.endpoint = socket_addr_from_endpoint(endpoint);
        Ok(())
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

    pub(crate) fn has_endpoint(&self, remote_addr: SocketAddr) -> bool {
        self.peer_states
            .values()
            .any(|peer_state| peer_state.endpoint == remote_addr)
    }

    pub(crate) fn remove_peer(&mut self, node_id: &NodeId) -> bool {
        self.peer_states.remove(node_id).is_some()
    }

    pub(crate) fn process_inbound_ciphertext(
        &mut self,
        remote_addr: SocketAddr,
        local_addr: SocketAddr,
        payload: Vec<u8>,
        transport_generation: u64,
    ) -> Result<EngineProcessingOutcome, BackendError> {
        let matched_node_id = self.find_node_id_by_endpoint(remote_addr);
        self.recorded_peer_ciphertext_ingress
            .push(RecordedPeerCiphertextIngress {
                node_id: matched_node_id.clone(),
                local_addr,
                remote_addr,
                payload: payload.clone(),
                transport_generation,
            });

        let Some(node_id) = matched_node_id else {
            return Ok(EngineProcessingOutcome::default());
        };

        let Self {
            peer_states,
            recorded_tunnel_plaintext_packets,
            ..
        } = self;
        let peer_state = peer_states
            .get_mut(&node_id)
            .expect("matched peer state should exist");
        let mut decrypt_buf = vec![0u8; MAX_DECRYPTED_PACKET_BYTES];
        let initial_result =
            peer_state
                .tunnel
                .decapsulate(Some(remote_addr.ip()), &payload, &mut decrypt_buf);
        Ok(drive_inbound_result(
            &node_id,
            peer_state,
            remote_addr,
            transport_generation,
            initial_result,
            recorded_tunnel_plaintext_packets,
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
            ..
        } = self;
        let peer_state = peer_states
            .get_mut(&node_id)
            .expect("selected peer state should exist");
        let mut encrypt_buf = vec![0u8; MAX_ENCRYPTED_PACKET_BYTES.max(packet.len() + 32)];
        let initial_result = peer_state.tunnel.encapsulate(packet, &mut encrypt_buf);
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
            let (_handshake, peer_tx, peer_rx, _loss, _rtt) = peer_state.tunnel.stats();
            bytes_tx = bytes_tx.saturating_add(peer_tx as u64);
            bytes_rx = bytes_rx.saturating_add(peer_rx as u64);
        }
        EngineStats { bytes_tx, bytes_rx }
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

    fn find_node_id_by_endpoint(&self, remote_addr: SocketAddr) -> Option<NodeId> {
        self.peer_states
            .iter()
            .find(|(_node_id, peer_state)| peer_state.endpoint == remote_addr)
            .map(|(node_id, _peer_state)| node_id.clone())
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn select_peer_for_destination(&self, dst_addr: IpAddr) -> Option<NodeId> {
        self.peer_states
            .iter()
            .find(|(_node_id, peer_state)| {
                peer_state
                    .allowed_ips
                    .iter()
                    .any(|allowed_ip| allowed_ip.contains(dst_addr))
            })
            .map(|(node_id, _peer_state)| node_id.clone())
    }
}

fn drive_inbound_result(
    node_id: &NodeId,
    peer_state: &mut PeerEngineState,
    remote_addr: SocketAddr,
    transport_generation: u64,
    initial_result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
) -> EngineProcessingOutcome {
    let should_drain_follow_ups = !matches!(initial_result, TunnResult::Err(_));
    let mut outcome = handle_single_tunn_result(
        node_id,
        peer_state,
        remote_addr,
        transport_generation,
        initial_result,
        recorded_tunnel_plaintext_packets,
    );

    if should_drain_follow_ups {
        loop {
            let mut follow_up_buf = vec![0u8; MAX_DECRYPTED_PACKET_BYTES];
            let follow_up = peer_state.tunnel.decapsulate(None, &[], &mut follow_up_buf);
            if matches!(follow_up, TunnResult::Done) {
                break;
            }
            let next = handle_single_tunn_result(
                node_id,
                peer_state,
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
        peer_state,
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
    peer_state: &mut PeerEngineState,
    remote_addr: SocketAddr,
    transport_generation: u64,
    result: TunnResult<'_>,
    recorded_tunnel_plaintext_packets: &mut Vec<RecordedTunnelPlaintextPacket>,
) -> EngineProcessingOutcome {
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
            let recorded_packet = RecordedTunnelPlaintextPacket {
                node_id: node_id.clone(),
                packet: packet.to_vec(),
                transport_generation,
            };
            recorded_tunnel_plaintext_packets.push(recorded_packet);
        }
        TunnResult::WriteToTunnelV6(packet, _src_addr) => {
            let recorded_packet = RecordedTunnelPlaintextPacket {
                node_id: node_id.clone(),
                packet: packet.to_vec(),
                transport_generation,
            };
            recorded_tunnel_plaintext_packets.push(recorded_packet);
        }
    }

    let observed_handshake = authenticated_handshake_unix(&peer_state.tunnel);
    if let Some(observed_handshake) = observed_handshake {
        outcome.authenticated_handshake = Some((node_id.clone(), observed_handshake));
    }
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
            .field("local_static_public", self.local_static_public.as_bytes())
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
            .field("peer_static_public", self.peer_static_public.as_bytes())
            .field("endpoint", &self.endpoint)
            .field("allowed_ips", &self.allowed_ips)
            .finish()
    }
}
