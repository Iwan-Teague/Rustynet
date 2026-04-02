use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use base64::prelude::*;
use rustynet_backend_api::{
    AuthoritativeTransportIdentity, AuthoritativeTransportResponse, BackendCapabilities,
    BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext, SocketEndpoint,
    TunnelBackend, TunnelStats,
};

const WG_LATEST_HANDSHAKES_MAX_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedAuthoritativeTransportOperationKind {
    RoundTrip,
    Send,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedAuthoritativeTransportOperation {
    pub kind: RecordedAuthoritativeTransportOperationKind,
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub payload: Vec<u8>,
    pub timeout: Option<Duration>,
}

#[derive(Debug, Clone)]
struct InMemoryAuthoritativeTransport {
    identity: AuthoritativeTransportIdentity,
    scripted_round_trip_results: VecDeque<ScriptedAuthoritativeRoundTrip>,
    scripted_send_results: VecDeque<Result<(), BackendError>>,
    recorded_operations: Vec<RecordedAuthoritativeTransportOperation>,
}

#[derive(Debug, Clone)]
enum ScriptedAuthoritativeRoundTrip {
    Static(Result<AuthoritativeTransportResponse, BackendError>),
    StunMappedEndpoint {
        remote_addr: SocketAddr,
        mapped_endpoint: SocketAddr,
    },
}

#[derive(Debug, Clone)]
pub struct WireguardBackend {
    running: bool,
    context: Option<RuntimeContext>,
    peers: BTreeMap<NodeId, PeerConfig>,
    peer_latest_handshakes_by_node: BTreeMap<NodeId, u64>,
    peer_latest_handshakes_by_endpoint: BTreeMap<String, u64>,
    routes: Vec<Route>,
    exit_mode: ExitMode,
    stats: TunnelStats,
    authoritative_transport: Option<InMemoryAuthoritativeTransport>,
}

impl Default for WireguardBackend {
    fn default() -> Self {
        Self {
            running: false,
            context: None,
            peers: BTreeMap::new(),
            peer_latest_handshakes_by_node: BTreeMap::new(),
            peer_latest_handshakes_by_endpoint: BTreeMap::new(),
            routes: Vec::new(),
            exit_mode: ExitMode::Off,
            stats: TunnelStats::default(),
            authoritative_transport: None,
        }
    }
}

impl WireguardBackend {
    fn endpoint_cache_key(endpoint: SocketEndpoint) -> String {
        format!("{}:{}", endpoint.addr, endpoint.port)
    }

    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }

        Err(BackendError::not_running(
            "wireguard backend is not running",
        ))
    }

    fn refresh_stats(&mut self) {
        self.stats.peer_count = self.peers.len();
    }

    fn fetch_latest_handshakes(&mut self) -> Result<(), BackendError> {
        let interface_name = match &self.context {
            Some(ctx) => &ctx.interface_name,
            None => {
                return Err(BackendError::not_running(
                    "wireguard backend context missing",
                ));
            }
        };

        let output = Command::new("wg")
            .arg("show")
            .arg(interface_name)
            .arg("latest-handshakes")
            .output()
            .map_err(|err| BackendError::internal(format!("wg show failed: {err}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(BackendError::internal(format!(
                "wg show failed with status {}: {stderr}",
                output.status
            )));
        }

        let stdout = output.stdout;
        if stdout.len() > WG_LATEST_HANDSHAKES_MAX_BYTES {
            return Err(BackendError::internal(format!(
                "wg latest-handshakes output exceeded {WG_LATEST_HANDSHAKES_MAX_BYTES} bytes"
            )));
        }

        let output_str = String::from_utf8(stdout)
            .map_err(|err| BackendError::internal(format!("wg show output not utf8: {err}")))?;

        let mut pubkey_to_node_id = BTreeMap::new();
        for (node_id, peer) in &self.peers {
            pubkey_to_node_id.insert(peer.public_key, node_id.clone());
        }

        for line in output_str.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let pubkey_str = parts[0];
            let timestamp_str = parts[1];

            let timestamp = timestamp_str.parse::<u64>().map_err(|err| {
                BackendError::internal(format!(
                    "wg latest-handshakes timestamp parse failed: {err}"
                ))
            })?;

            if timestamp == 0 {
                continue;
            }

            let pubkey_vec = BASE64_STANDARD.decode(pubkey_str).map_err(|err| {
                BackendError::internal(format!("wg pubkey base64 decode failed: {err}"))
            })?;

            let pubkey: [u8; 32] = pubkey_vec.try_into().map_err(|vec: Vec<u8>| {
                BackendError::internal(format!("wg pubkey wrong length: {}", vec.len()))
            })?;

            if let Some(node_id) = pubkey_to_node_id.get(&pubkey) {
                self.peer_latest_handshakes_by_node
                    .insert(node_id.clone(), timestamp);
            }
        }

        Ok(())
    }

    #[doc(hidden)]
    pub fn set_peer_latest_handshake_unix_for_test(
        &mut self,
        node_id: &NodeId,
        latest_handshake_unix: Option<u64>,
    ) {
        if let Some(timestamp) = latest_handshake_unix {
            self.peer_latest_handshakes_by_node
                .insert(node_id.clone(), timestamp);
        } else {
            self.peer_latest_handshakes_by_node.remove(node_id);
        }
        if let Some(peer) = self.peers.get(node_id) {
            let endpoint_key = Self::endpoint_cache_key(peer.endpoint);
            if let Some(timestamp) = latest_handshake_unix {
                self.peer_latest_handshakes_by_endpoint
                    .insert(endpoint_key, timestamp);
            } else {
                self.peer_latest_handshakes_by_endpoint
                    .remove(&endpoint_key);
            }
        }
    }

    #[doc(hidden)]
    pub fn cached_peer_latest_handshake_unix_for_test(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        self.ensure_running()?;
        if !self.peers.contains_key(node_id) {
            return Err(BackendError::invalid_input("peer is not configured"));
        }
        Ok(self.peer_latest_handshakes_by_node.get(node_id).copied())
    }

    #[doc(hidden)]
    pub fn set_endpoint_latest_handshake_unix_for_test(
        &mut self,
        endpoint: SocketEndpoint,
        latest_handshake_unix: Option<u64>,
    ) {
        let mut target_node_id = None;
        for (node_id, peer) in &self.peers {
            if peer.endpoint == endpoint {
                target_node_id = Some(node_id.clone());
                break;
            }
        }

        if let Some(node_id) = target_node_id {
            if let Some(timestamp) = latest_handshake_unix {
                self.peer_latest_handshakes_by_node
                    .insert(node_id, timestamp);
            } else {
                self.peer_latest_handshakes_by_node.remove(&node_id);
            }
        }
        let endpoint_key = Self::endpoint_cache_key(endpoint);
        if let Some(timestamp) = latest_handshake_unix {
            self.peer_latest_handshakes_by_endpoint
                .insert(endpoint_key, timestamp);
        } else {
            self.peer_latest_handshakes_by_endpoint
                .remove(&endpoint_key);
        }
    }

    fn authoritative_transport_unavailable_error(&self, action: &str) -> BackendError {
        BackendError::internal(format!(
            "authoritative shared transport {action} unavailable: {}",
            self.transport_socket_identity_blocker().unwrap_or_else(|| {
                "in-memory backend authoritative shared transport is not configured".to_string()
            })
        ))
    }

    #[doc(hidden)]
    pub fn configure_authoritative_shared_transport_for_test(
        &mut self,
        local_addr: SocketAddr,
        label: impl Into<String>,
    ) {
        self.authoritative_transport = Some(InMemoryAuthoritativeTransport {
            identity: AuthoritativeTransportIdentity {
                local_addr,
                label: label.into(),
            },
            scripted_round_trip_results: VecDeque::new(),
            scripted_send_results: VecDeque::new(),
            recorded_operations: Vec::new(),
        });
    }

    #[doc(hidden)]
    pub fn disable_authoritative_shared_transport_for_test(&mut self) {
        self.authoritative_transport = None;
    }

    #[doc(hidden)]
    pub fn script_authoritative_round_trip_for_test(
        &mut self,
        result: Result<AuthoritativeTransportResponse, BackendError>,
    ) {
        if self.authoritative_transport.is_none() {
            let local_addr = SocketAddr::from(([127, 0, 0, 1], 51_820));
            self.configure_authoritative_shared_transport_for_test(
                local_addr,
                "wireguard-in-memory-authoritative-shared-transport",
            );
        }
        self.authoritative_transport
            .as_mut()
            .expect("authoritative transport should exist")
            .scripted_round_trip_results
            .push_back(ScriptedAuthoritativeRoundTrip::Static(result));
    }

    #[doc(hidden)]
    pub fn script_authoritative_stun_round_trip_for_test(
        &mut self,
        remote_addr: SocketAddr,
        mapped_endpoint: SocketAddr,
    ) {
        if self.authoritative_transport.is_none() {
            let local_addr = SocketAddr::from(([127, 0, 0, 1], 51_820));
            self.configure_authoritative_shared_transport_for_test(
                local_addr,
                "wireguard-in-memory-authoritative-shared-transport",
            );
        }
        self.authoritative_transport
            .as_mut()
            .expect("authoritative transport should exist")
            .scripted_round_trip_results
            .push_back(ScriptedAuthoritativeRoundTrip::StunMappedEndpoint {
                remote_addr,
                mapped_endpoint,
            });
    }

    #[doc(hidden)]
    pub fn script_authoritative_send_result_for_test(&mut self, result: Result<(), BackendError>) {
        if self.authoritative_transport.is_none() {
            let local_addr = SocketAddr::from(([127, 0, 0, 1], 51_820));
            self.configure_authoritative_shared_transport_for_test(
                local_addr,
                "wireguard-in-memory-authoritative-shared-transport",
            );
        }
        self.authoritative_transport
            .as_mut()
            .expect("authoritative transport should exist")
            .scripted_send_results
            .push_back(result);
    }

    #[doc(hidden)]
    pub fn authoritative_transport_identity_for_test(
        &self,
    ) -> Option<AuthoritativeTransportIdentity> {
        self.authoritative_transport
            .as_ref()
            .map(|transport| transport.identity.clone())
    }

    #[doc(hidden)]
    pub fn recorded_authoritative_transport_operations_for_test(
        &self,
    ) -> Vec<RecordedAuthoritativeTransportOperation> {
        self.authoritative_transport
            .as_ref()
            .map(|transport| transport.recorded_operations.clone())
            .unwrap_or_default()
    }

    #[doc(hidden)]
    pub fn clear_authoritative_transport_operations_for_test(&mut self) {
        if let Some(transport) = self.authoritative_transport.as_mut() {
            transport.recorded_operations.clear();
        }
    }

    fn build_scripted_stun_response(
        request: &[u8],
        remote_addr: SocketAddr,
        mapped_endpoint: SocketAddr,
        local_addr: SocketAddr,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
        const STUN_BINDING_RESPONSE: u16 = 0x0101;
        const STUN_ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

        if request.len() < 20 {
            return Err(BackendError::internal(
                "scripted STUN round trip request too short",
            ));
        }
        let tx_id = &request[8..20];
        let family = match mapped_endpoint {
            SocketAddr::V4(_) => 0x01u8,
            SocketAddr::V6(_) => 0x02u8,
        };
        let mut attribute = Vec::with_capacity(24);
        attribute.extend_from_slice(&STUN_ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        match mapped_endpoint {
            SocketAddr::V4(endpoint) => {
                attribute.extend_from_slice(&(8u16).to_be_bytes());
                attribute.push(0);
                attribute.push(family);
                let port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                attribute.extend_from_slice(&port.to_be_bytes());
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (byte, mask) in endpoint.ip().octets().iter().zip(cookie.iter()) {
                    attribute.push(byte ^ mask);
                }
            }
            SocketAddr::V6(endpoint) => {
                attribute.extend_from_slice(&(20u16).to_be_bytes());
                attribute.push(0);
                attribute.push(family);
                let port = endpoint.port() ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                attribute.extend_from_slice(&port.to_be_bytes());
                let cookie = STUN_MAGIC_COOKIE.to_be_bytes();
                for (index, byte) in endpoint.ip().octets().iter().enumerate() {
                    let mask = if index < 4 {
                        cookie[index]
                    } else {
                        tx_id[index - 4]
                    };
                    attribute.push(byte ^ mask);
                }
            }
        }

        let mut payload = Vec::with_capacity(20 + attribute.len());
        payload.extend_from_slice(&STUN_BINDING_RESPONSE.to_be_bytes());
        payload.extend_from_slice(&(attribute.len() as u16).to_be_bytes());
        payload.extend_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
        payload.extend_from_slice(tx_id);
        payload.extend_from_slice(&attribute);
        Ok(AuthoritativeTransportResponse {
            local_addr,
            remote_addr,
            payload,
        })
    }
}

impl TunnelBackend for WireguardBackend {
    fn name(&self) -> &'static str {
        "wireguard"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: true,
        }
    }

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running(
                "wireguard backend already started",
            ));
        }

        self.context = Some(context);
        self.running = true;
        self.refresh_stats();
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        let endpoint_key = Self::endpoint_cache_key(peer.endpoint);
        if let Some(timestamp) = self
            .peer_latest_handshakes_by_endpoint
            .get(&endpoint_key)
            .copied()
        {
            self.peer_latest_handshakes_by_node
                .insert(peer.node_id.clone(), timestamp);
        }
        self.peers.insert(peer.node_id.clone(), peer);
        self.refresh_stats();
        Ok(())
    }

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        self.ensure_running()?;
        let Some(peer) = self.peers.get_mut(node_id) else {
            return Err(BackendError::invalid_input("peer is not configured"));
        };
        peer.endpoint = endpoint;
        let endpoint_key = Self::endpoint_cache_key(endpoint);
        if let Some(timestamp) = self
            .peer_latest_handshakes_by_endpoint
            .get(&endpoint_key)
            .copied()
        {
            self.peer_latest_handshakes_by_node
                .insert(node_id.clone(), timestamp);
        }
        Ok(())
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.ensure_running()?;
        Ok(self.peers.get(node_id).map(|peer| peer.endpoint))
    }

    fn peer_latest_handshake_unix(
        &mut self,
        node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        self.ensure_running()?;
        if !self.peers.contains_key(node_id) {
            return Err(BackendError::invalid_input("peer is not configured"));
        }

        self.fetch_latest_handshakes()?;

        Ok(self.peer_latest_handshakes_by_node.get(node_id).copied())
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        if let Some(peer) = self.peers.remove(node_id) {
            let endpoint_key = Self::endpoint_cache_key(peer.endpoint);
            self.peer_latest_handshakes_by_endpoint
                .remove(&endpoint_key);
        }
        self.peer_latest_handshakes_by_node.remove(node_id);
        self.refresh_stats();
        Ok(())
    }

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.routes = routes;
        Ok(())
    }

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.exit_mode = mode;
        Ok(())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        self.ensure_running()?;
        Ok(self.stats)
    }

    fn authoritative_transport_identity(&self) -> Option<AuthoritativeTransportIdentity> {
        self.authoritative_transport
            .as_ref()
            .map(|transport| transport.identity.clone())
    }

    fn authoritative_transport_round_trip(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
        timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        self.ensure_running()?;
        let Some(transport) = self.authoritative_transport.as_mut() else {
            return Err(self.authoritative_transport_unavailable_error("round trip"));
        };
        let identity = transport.identity.clone();
        transport
            .recorded_operations
            .push(RecordedAuthoritativeTransportOperation {
                kind: RecordedAuthoritativeTransportOperationKind::RoundTrip,
                local_addr: identity.local_addr,
                remote_addr,
                payload: payload.to_vec(),
                timeout: Some(timeout),
            });
        let result = transport
            .scripted_round_trip_results
            .pop_front()
            .ok_or_else(|| {
                BackendError::internal(
                    "authoritative shared transport round trip has no scripted response",
                )
            })?;
        let result = match result {
            ScriptedAuthoritativeRoundTrip::Static(result) => result?,
            ScriptedAuthoritativeRoundTrip::StunMappedEndpoint {
                remote_addr: scripted_remote_addr,
                mapped_endpoint,
            } => Self::build_scripted_stun_response(
                payload,
                scripted_remote_addr,
                mapped_endpoint,
                identity.local_addr,
            )?,
        };
        if result.local_addr != identity.local_addr {
            return Err(BackendError::internal(format!(
                "authoritative shared transport round trip returned local addr {} but backend identity is {}",
                result.local_addr, identity.local_addr
            )));
        }
        Ok(result)
    }

    fn authoritative_transport_send(
        &mut self,
        remote_addr: SocketAddr,
        payload: &[u8],
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        self.ensure_running()?;
        let Some(transport) = self.authoritative_transport.as_mut() else {
            return Err(self.authoritative_transport_unavailable_error("send"));
        };
        let identity = transport.identity.clone();
        transport
            .recorded_operations
            .push(RecordedAuthoritativeTransportOperation {
                kind: RecordedAuthoritativeTransportOperationKind::Send,
                local_addr: identity.local_addr,
                remote_addr,
                payload: payload.to_vec(),
                timeout: None,
            });
        if let Some(result) = transport.scripted_send_results.pop_front() {
            result?;
        }
        Ok(identity)
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.running = false;
        self.context = None;
        self.peers.clear();
        self.peer_latest_handshakes_by_node.clear();
        self.peer_latest_handshakes_by_endpoint.clear();
        self.routes.clear();
        self.exit_mode = ExitMode::Off;
        self.stats = TunnelStats::default();
        self.authoritative_transport = None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustynet_backend_api::{BackendErrorKind, RouteKind, SocketEndpoint};

    use super::*;

    fn runtime_context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("local-node").expect("valid node id"),
            interface_name: "rustynet0".to_string(),
            mesh_cidr: "100.64.0.1/32".to_string(),
            local_cidr: "100.64.0.1/32".to_string(),
        }
    }

    fn sample_peer(name: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(name).expect("valid node id"),
            endpoint: SocketEndpoint {
                addr: "203.0.113.10".parse().expect("valid ip"),
                port: 51820,
            },
            public_key: [7; 32],
            allowed_ips: vec!["100.64.1.0/24".to_string()],
        }
    }

    #[test]
    fn in_memory_backend_preserves_lifecycle_contract() {
        let mut backend = WireguardBackend::default();

        let pre_start_err = backend.stats().expect_err("stats before start should fail");
        assert_eq!(pre_start_err.kind, BackendErrorKind::NotRunning);

        backend
            .start(runtime_context())
            .expect("backend should start");
        backend
            .configure_peer(sample_peer("peer-a"))
            .expect("peer config should succeed");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode switch should succeed");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("peer-a").expect("valid node id"),
                kind: RouteKind::ExitNodeDefault,
            }])
            .expect("route apply should succeed");

        let stats = backend.stats().expect("stats should succeed");
        assert_eq!(stats.peer_count, 1);

        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn in_memory_backend_authoritative_transport_round_trip_records_shared_identity() {
        let mut backend = WireguardBackend::default();
        backend
            .start(runtime_context())
            .expect("backend should start");
        let local_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let remote_addr: SocketAddr = "198.51.100.1:3478".parse().unwrap();
        backend.configure_authoritative_shared_transport_for_test(
            local_addr,
            "wireguard-in-memory-authoritative-shared-transport",
        );
        backend.script_authoritative_round_trip_for_test(Ok(AuthoritativeTransportResponse {
            local_addr,
            remote_addr,
            payload: b"response".to_vec(),
        }));

        let response = backend
            .authoritative_transport_round_trip(remote_addr, b"request", Duration::from_millis(250))
            .expect("round trip should succeed");

        assert_eq!(response.local_addr, local_addr);
        let operations = backend.recorded_authoritative_transport_operations_for_test();
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::RoundTrip
        );
        assert_eq!(operations[0].local_addr, local_addr);
        assert_eq!(operations[0].remote_addr, remote_addr);
    }

    #[test]
    fn in_memory_backend_authoritative_transport_send_records_shared_identity() {
        let mut backend = WireguardBackend::default();
        backend
            .start(runtime_context())
            .expect("backend should start");
        let local_addr: SocketAddr = "0.0.0.0:51820".parse().unwrap();
        let remote_addr: SocketAddr = "203.0.113.77:61040".parse().unwrap();
        backend.configure_authoritative_shared_transport_for_test(
            local_addr,
            "wireguard-in-memory-authoritative-shared-transport",
        );

        let identity = backend
            .authoritative_transport_send(remote_addr, b"keepalive")
            .expect("send should succeed");

        assert_eq!(identity.local_addr, local_addr);
        let operations = backend.recorded_authoritative_transport_operations_for_test();
        assert_eq!(operations.len(), 1);
        assert_eq!(
            operations[0].kind,
            RecordedAuthoritativeTransportOperationKind::Send
        );
        assert_eq!(operations[0].local_addr, local_addr);
        assert_eq!(operations[0].remote_addr, remote_addr);
    }

    #[test]
    fn in_memory_backend_promotes_cached_endpoint_handshake_on_endpoint_update() {
        let mut backend = WireguardBackend::default();
        backend
            .start(runtime_context())
            .expect("backend should start");
        let peer = sample_peer("peer-a");
        let peer_id = peer.node_id.clone();
        backend
            .configure_peer(peer)
            .expect("peer config should succeed");

        let direct_endpoint = SocketEndpoint {
            addr: "198.51.100.55".parse().expect("valid ip"),
            port: 51820,
        };
        backend.set_endpoint_latest_handshake_unix_for_test(direct_endpoint, Some(4_242));
        assert_eq!(
            backend
                .cached_peer_latest_handshake_unix_for_test(&peer_id)
                .expect("cached handshake query should succeed"),
            None
        );

        backend
            .update_peer_endpoint(&peer_id, direct_endpoint)
            .expect("endpoint update should succeed");
        assert_eq!(
            backend
                .cached_peer_latest_handshake_unix_for_test(&peer_id)
                .expect("cached handshake query should succeed"),
            Some(4_242)
        );
    }
}
