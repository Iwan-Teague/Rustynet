#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, BackendError> {
        let value = value.into();
        if value.trim().is_empty() {
            return Err(BackendError::invalid_input("node id must not be empty"));
        }
        Ok(Self(value))
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
    pub mesh_cidr: String,
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

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError>;

    fn apply_routes(&mut self, routes: Vec<Route>) -> Result<(), BackendError>;

    fn set_exit_mode(&mut self, mode: ExitMode) -> Result<(), BackendError>;

    fn stats(&self) -> Result<TunnelStats, BackendError>;

    fn shutdown(&mut self) -> Result<(), BackendError>;
}
