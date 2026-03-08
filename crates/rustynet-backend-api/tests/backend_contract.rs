#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};

use rustynet_backend_api::{
    BackendCapabilities, BackendError, BackendErrorKind, ExitMode, NodeId, PeerConfig, Route,
    RouteKind, RuntimeContext, SocketEndpoint, TunnelBackend, TunnelStats,
};

struct ContractBackend {
    running: bool,
    peers: BTreeMap<NodeId, PeerConfig>,
    routes: Vec<Route>,
    exit_mode: ExitMode,
}

impl Default for ContractBackend {
    fn default() -> Self {
        Self {
            running: false,
            peers: BTreeMap::new(),
            routes: Vec::new(),
            exit_mode: ExitMode::Off,
        }
    }
}

impl ContractBackend {
    fn ensure_running(&self) -> Result<(), BackendError> {
        if self.running {
            return Ok(());
        }

        Err(BackendError::not_running("backend is not running"))
    }
}

impl TunnelBackend for ContractBackend {
    fn name(&self) -> &'static str {
        "contract-backend"
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            supports_roaming: true,
            supports_exit_nodes: true,
            supports_lan_routes: true,
            supports_ipv6: false,
        }
    }

    fn start(&mut self, _context: RuntimeContext) -> Result<(), BackendError> {
        if self.running {
            return Err(BackendError::already_running("backend already started"));
        }
        self.running = true;
        Ok(())
    }

    fn configure_peer(&mut self, peer: PeerConfig) -> Result<(), BackendError> {
        self.ensure_running()?;
        self.peers.insert(peer.node_id.clone(), peer);
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
        Ok(())
    }

    fn current_peer_endpoint(
        &self,
        node_id: &NodeId,
    ) -> Result<Option<SocketEndpoint>, BackendError> {
        self.ensure_running()?;
        Ok(self.peers.get(node_id).map(|peer| peer.endpoint))
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

fn sample_runtime_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        mesh_cidr: "100.64.0.0/10".to_string(),
        local_cidr: "100.64.0.1/32".to_string(),
    }
}

fn sample_peer(node_name: &str) -> PeerConfig {
    PeerConfig {
        node_id: NodeId::new(node_name).expect("valid node id"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            port: 51820,
        },
        public_key: [7; 32],
        allowed_ips: vec!["100.64.1.0/24".to_string()],
    }
}

#[test]
fn backend_contract_requires_running_state_for_mutations() {
    let mut backend = ContractBackend::default();

    let err = backend
        .configure_peer(sample_peer("peer-a"))
        .expect_err("configure_peer must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = backend
        .apply_routes(vec![Route {
            destination_cidr: "0.0.0.0/0".to_string(),
            via_node: NodeId::new("peer-a").expect("valid node id"),
            kind: RouteKind::ExitNodeDefault,
        }])
        .expect_err("apply_routes must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);
}

#[test]
fn backend_contract_rejects_double_start_and_resets_on_shutdown() {
    let mut backend = ContractBackend::default();
    backend
        .start(sample_runtime_context())
        .expect("backend should start successfully");
    backend
        .configure_peer(sample_peer("peer-a"))
        .expect("configure_peer should succeed");

    let err = backend
        .start(sample_runtime_context())
        .expect_err("second start must fail");
    assert_eq!(err.kind, BackendErrorKind::AlreadyRunning);

    backend.shutdown().expect("shutdown should succeed");
    let err = backend
        .stats()
        .expect_err("stats after shutdown must fail because backend is not running");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);
}

#[test]
fn backend_contract_replaces_route_set_deterministically() {
    let mut backend = ContractBackend::default();
    backend
        .start(sample_runtime_context())
        .expect("backend should start successfully");

    backend
        .apply_routes(vec![
            Route {
                destination_cidr: "192.168.0.0/24".to_string(),
                via_node: NodeId::new("peer-a").expect("valid node id"),
                kind: RouteKind::Mesh,
            },
            Route {
                destination_cidr: "0.0.0.0/0".to_string(),
                via_node: NodeId::new("peer-b").expect("valid node id"),
                kind: RouteKind::ExitNodeDefault,
            },
        ])
        .expect("first route apply should succeed");

    backend
        .apply_routes(vec![Route {
            destination_cidr: "10.0.0.0/8".to_string(),
            via_node: NodeId::new("peer-c").expect("valid node id"),
            kind: RouteKind::ExitNodeLan,
        }])
        .expect("second route apply should replace route set");

    assert_eq!(backend.routes.len(), 1);
    assert_eq!(backend.routes[0].destination_cidr, "10.0.0.0/8");
}

#[test]
fn backend_contract_updates_peer_endpoint_without_replacing_peer() {
    let mut backend = ContractBackend::default();
    backend
        .start(sample_runtime_context())
        .expect("backend should start successfully");
    let peer = sample_peer("peer-a");
    let node_id = peer.node_id.clone();
    backend
        .configure_peer(peer)
        .expect("configure_peer should succeed");

    let rotated_endpoint = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
        port: 443,
    };
    backend
        .update_peer_endpoint(&node_id, rotated_endpoint)
        .expect("endpoint update should succeed");

    let current = backend
        .current_peer_endpoint(&node_id)
        .expect("current peer endpoint should resolve");
    assert_eq!(current, Some(rotated_endpoint));
    assert_eq!(
        backend
            .peers
            .get(&node_id)
            .expect("peer should remain present")
            .allowed_ips,
        vec!["100.64.1.0/24".to_string()]
    );
}
