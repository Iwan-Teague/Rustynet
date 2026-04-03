#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, BackendError> {
        let value = value.into();
        let normalized = value.trim();
        if normalized.is_empty() {
            return Err(BackendError::invalid_input("node id must not be empty"));
        }
        Ok(Self(normalized.to_string()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SocketEndpoint {
    pub addr: IpAddr,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeTransportIdentity {
    pub local_addr: SocketAddr,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoritativeTransportResponse {
    pub local_addr: SocketAddr,
    pub remote_addr: SocketAddr,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitMode {
    Off,
    FullTunnel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteKind {
    Mesh,
    ExitNodeLan,
    ExitNodeDefault,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Route {
    pub destination_cidr: String,
    pub via_node: NodeId,
    pub kind: RouteKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerConfig {
    pub node_id: NodeId,
    pub endpoint: SocketEndpoint,
    pub public_key: [u8; 32],
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeContext {
    pub local_node: NodeId,
    pub interface_name: String,
    pub mesh_cidr: String,
    pub local_cidr: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendCapabilities {
    pub supports_roaming: bool,
    pub supports_exit_nodes: bool,
    pub supports_lan_routes: bool,
    pub supports_ipv6: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TunnelStats {
    pub peer_count: usize,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub using_relay_path: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendErrorKind {
    InvalidInput,
    AlreadyRunning,
    NotRunning,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackendError {
    pub kind: BackendErrorKind,
    pub message: String,
}

impl BackendError {
    pub fn invalid_input(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::InvalidInput,
            message: message.into(),
        }
    }

    pub fn already_running(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::AlreadyRunning,
            message: message.into(),
        }
    }

    pub fn not_running(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::NotRunning,
            message: message.into(),
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self {
            kind: BackendErrorKind::Internal,
            message: message.into(),
        }
    }
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.message)
    }
}

impl Error for BackendError {}

pub trait TunnelBackend: Send + Sync {
    fn name(&self) -> &'static str;

    fn capabilities(&self) -> BackendCapabilities;

    fn start(&mut self, context: RuntimeContext) -> Result<(), BackendError>;

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError>;

    fn update_peer_endpoint(
        &mut self,
        node_id: &NodeId,
        endpoint: SocketEndpoint,
    ) -> Result<(), BackendError>;

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError>;

    fn peer_latest_handshake_unix(&mut self, node_id: &NodeId)
    -> Result<Option<u64>, BackendError>;

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError>;

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError>;

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError>;

    fn stats(&self) -> Result<TunnelStats, BackendError>;

    /// Requests that the backend initiate a peer handshake on the currently
    /// configured transport path for the given peer.
    ///
    /// Backends that do not require an explicit handshake trigger may leave the
    /// default no-op behavior in place. Backends that own their own userspace
    /// transport should override this when endpoint reconfiguration alone does
    /// not emit any peer traffic.
    fn initiate_peer_handshake(
        &mut self,
        _node_id: &NodeId,
        _force_resend: bool,
    ) -> Result<(), BackendError> {
        Ok(())
    }

    /// Returns diagnostics for the backend-owned authoritative shared transport
    /// when the backend can safely originate STUN and relay control traffic on
    /// the same peer-traffic transport identity.
    fn authoritative_transport_identity(&self) -> Option<AuthoritativeTransportIdentity> {
        None
    }

    /// Executes a bounded request/response exchange on the backend-owned
    /// authoritative peer-traffic transport identity.
    fn authoritative_transport_round_trip(
        &mut self,
        _remote_addr: SocketAddr,
        _payload: &[u8],
        _timeout: Duration,
    ) -> Result<AuthoritativeTransportResponse, BackendError> {
        Err(BackendError::internal(format!(
            "authoritative shared transport round trip unavailable: {}",
            self.transport_socket_identity_blocker().unwrap_or_else(|| {
                "backend does not expose backend-owned authoritative transport operations"
                    .to_string()
            })
        )))
    }

    /// Sends a datagram on the backend-owned authoritative peer-traffic
    /// transport identity without waiting for a response.
    fn authoritative_transport_send(
        &mut self,
        _remote_addr: SocketAddr,
        _payload: &[u8],
    ) -> Result<AuthoritativeTransportIdentity, BackendError> {
        Err(BackendError::internal(format!(
            "authoritative shared transport send unavailable: {}",
            self.transport_socket_identity_blocker().unwrap_or_else(|| {
                "backend does not expose backend-owned authoritative transport operations"
                    .to_string()
            })
        )))
    }

    /// Returns a blocker reason when the backend owns peer transport on an
    /// opaque socket identity that cannot be safely shared with daemon-side
    /// STUN or relay bootstrap paths.
    ///
    /// Production code must treat a returned blocker as fail-closed for any
    /// workflow that would otherwise create a second UDP socket and infer that
    /// it represents the authoritative peer-traffic transport identity.
    ///
    /// Binding a second socket to the same local port is not sufficient. The
    /// authoritative transport path must be the same backend-owned socket, or a
    /// backend-owned multiplexed transport capability explicitly provided by the
    /// backend that can safely demultiplex STUN/relay control traffic alongside
    /// the real peer-traffic socket identity. Command-only backends that merely
    /// configure an OS-managed tunnel do not satisfy this requirement.
    fn transport_socket_identity_blocker(&self) -> Option<String> {
        None
    }

    fn shutdown(&mut self) -> Result<(), BackendError>;
}

#[cfg(test)]
mod tests {
    use super::{BackendErrorKind, NodeId};

    #[test]
    fn node_id_trims_outer_whitespace() {
        let node_id = NodeId::new("  mini-pc-1  ").expect("node id should be valid");
        assert_eq!(node_id.as_str(), "mini-pc-1");
    }

    #[test]
    fn node_id_rejects_empty_or_whitespace_only_values() {
        let err = NodeId::new("   ").expect_err("whitespace-only node id must be rejected");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    }
}
