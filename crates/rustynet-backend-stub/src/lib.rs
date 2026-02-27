#![forbid(unsafe_code)]

use std::collections::BTreeMap;

use rustynet_backend_api::{
    BackendCapabilities, BackendError, ExitMode, NodeId, PeerConfig, Route, RuntimeContext,
    TunnelBackend, TunnelStats,
};

#[derive(Debug, Clone)]
pub struct StubBackend {
    running: bool,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    exit_mode: ExitMode,
}

impl Default for StubBackend {
    fn default() -> Self {
        Self {
            running: false,
            peers: BTreeMap::new(),
            routes: Vec::new(),
            exit_mode: ExitMode::Off,
        }
    }
}

impl StubBackend {
    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }
        Err(BackendError::not_running("stub backend is not running"))
    }
}

impl TunnelBackend for StubBackend {
    fn name(&self) -> &'static str {
        "stub-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: false,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running(
                "stub backend already started",
            ));
        }
        self.running = true;
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers.insert(peer.node_id.clone(), peer);
        Ok(())
    }

    fn remove_peer(&mut self, node_id: &NodeId) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers.remove(node_id);
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
        Ok(TunnelStats {
            peer_count: self.peers.len(),
            bytes_tx: 0,
            bytes_rx: 0,
            using_relay_path: false,
        })
    }

    fn shutdown(&mut self) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.running = false;
        self.peers.clear();
        self.routes.clear();
        self.exit_mode = ExitMode::Off;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use rustynet_backend_api::{
        BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext,
        SocketEndpoint, TunnelBackend,
    };

    use super::StubBackend;

    fn context() -> RuntimeContext {
        RuntimeContext {
            local_node: NodeId::new("stub-local").expect("node id should be valid"),
            mesh_cidr: "100.64.0.0/10".to_string(),
        }
    }

    fn peer(id: &str) -> PeerConfig {
        PeerConfig {
            node_id: NodeId::new(id).expect("node id should be valid"),
            endpoint: SocketEndpoint {
                addr: "198.51.100.5".parse().expect("ip should parse"),
                port: 51820,
            },
            public_key: [9; 32],
            allowed_ips: vec!["100.100.10.1/32".to_string()],
        }
    }

    #[test]
    fn stub_backend_passes_lifecycle_and_peer_route_flow() {
        let mut backend = StubBackend::default();
        backend.start(context()).expect("start should succeed");
        backend
            .configure_peer(peer("peer-a"))
            .expect("configure should succeed");
        backend
            .apply_routes(vec![Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("peer-a").expect("node id should be valid"),
                kind: RouteKind::ExitNodeDefault,
            }])
            .expect("route apply should succeed");
        backend
            .set_exit_mode(ExitMode::FullTunnel)
            .expect("exit mode should succeed");
        assert_eq!(backend.stats().expect("stats should work").peer_count, 1);
        backend.shutdown().expect("shutdown should succeed");
    }

    #[test]
    fn stub_backend_rejects_mutation_while_stopped() {
        let mut backend = StubBackend::default();
        let err = backend
            .configure_peer(peer("peer-a"))
            .expect_err("configure should fail while stopped");
        assert_eq!(err.kind, BackendErrorKind::NotRunning);
    }
}
