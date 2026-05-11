use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    SocketEndpoint, TunnelBackend, TunnelStats,
};

pub(crate) const MACOS_USERSPACE_SHARED_BACKEND_MODE: &str = "macos-wireguard-userspace-shared";

/// Phase 1 scaffolding for the macOS boringtun userspace WireGuard backend.
///
/// Declares shared-transport intent by not overriding
/// `transport_socket_identity_blocker()` (the default returns `None`), signaling
/// that this backend will own its authoritative peer-traffic UDP socket so that
/// STUN and relay control can run on the same transport identity as peer traffic.
///
/// Phase 1 establishes the type and module layout. Phase 2 will implement the
/// macOS TUN lifecycle (`utun` device), UDP socket, boringtun engine, and async
/// runtime worker. All operational methods return an internal error until then.
#[allow(dead_code)] // fields will be consumed by Phase 2 runtime implementation
pub struct MacosUserspaceSharedBackend {
    interface_name: String,
    private_key_path: String,
    listen_port: u16,
}

impl MacosUserspaceSharedBackend {
    pub fn new(
        interface_name: impl Into<String>,
        private_key_path: impl Into<String>,
        listen_port: u16,
    ) -> Result<Self, BackendError> {
        Ok(Self {
            interface_name: interface_name.into(),
            private_key_path: private_key_path.into(),
            listen_port,
        })
    }
}

fn phase1_unimplemented() -> BackendError {
    BackendError::internal(
        "macos userspace-shared backend: phase 1 scaffolding — runtime datapath not yet implemented",
    )
}

impl TunnelBackend for MacosUserspaceSharedBackend {
    fn name(&self) -> &'static str {
        MACOS_USERSPACE_SHARED_BACKEND_MODE
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: true,
            supports_exit_client: true,
            supports_exit_serving: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    // transport_socket_identity_blocker() is intentionally NOT overridden.
    // Inheriting the trait default (returns None) declares this backend as the
    // authoritative shared-socket path. Once Phase 2+ implements the runtime,
    // STUN and relay control will share the backend-owned socket identity rather
    // than requiring a second daemon-side UDP socket.

    fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn configure_peer(&mut self, _peer: PeerConfig) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn update_peer_endpoint(
        &mut self,
        _node_id: &NodeId,
        _endpoint: SocketEndpoint,
    ) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn current_peer_endpoint(
        &self,
        _node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        Err(phase1_unimplemented())
    }

    fn peer_latest_handshake_unix(
        &mut self,
        _node_id: &NodeId,
    ) -> Result<Option<u64>, BackendError> {
        Err(phase1_unimplemented())
    }

    fn remove_peer(&mut self, _node_id: &NodeId) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn apply_routes(&mut self, _routes: Vec<Route>) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn set_exit_mode(&mut self, _mode: ExitMode) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }

    fn stats(&self) -> Result<TunnelStats, BackendError> {
        Err(phase1_unimplemented())
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        Err(phase1_unimplemented())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn macos_userspace_shared_backend_name_matches_mode_constant() {
        let backend = MacosUserspaceSharedBackend::new("utun9", "/tmp/key.pem", 51820)
            .expect("construction should succeed");
        assert_eq!(backend.name(), MACOS_USERSPACE_SHARED_BACKEND_MODE);
    }

    #[test]
    fn macos_userspace_shared_backend_transport_socket_identity_blocker_returns_none() {
        let backend = MacosUserspaceSharedBackend::new("utun9", "/tmp/key.pem", 51820)
            .expect("construction should succeed");
        // Shared-socket intent: no blocker, so STUN/relay can use this backend's socket.
        assert!(backend.transport_socket_identity_blocker().is_none());
    }

    #[test]
    fn macos_userspace_shared_backend_phase1_start_returns_internal_error() {
        let mut backend = MacosUserspaceSharedBackend::new("utun9", "/tmp/key.pem", 51820)
            .expect("construction should succeed");
        let ctx = rustynet_backend_api::RuntimeContext {
            local_node: rustynet_backend_api::NodeId::new("test-node").unwrap(),
            interface_name: "utun9".to_string(),
            mesh_cidr: "100.64.0.0/10".to_string(),
            local_cidr: "100.64.0.1/32".to_string(),
        };
        let err = backend.start(ctx).unwrap_err();
        assert!(
            err.message.contains("phase 1 scaffolding"),
            "start should return phase-1 error, got: {}",
            err.message
        );
    }
}
