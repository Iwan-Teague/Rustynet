#![forbid(unsafe_code)]

use rustynet_backend_api::{
    BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext,
    SocketEndpoint, TunnelBackend,
};
use rustynet_backend_wireguard::WireguardBackend;

fn runtime_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        mesh_cidr: "100.64.0.0/10".to_string(),
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
fn wireguard_backend_follows_lifecycle_contract() {
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
fn wireguard_backend_rejects_double_start() {
    let mut backend = WireguardBackend::default();
    backend
        .start(runtime_context())
        .expect("backend should start");
    let err = backend
        .start(runtime_context())
        .expect_err("second start should fail");
    assert_eq!(err.kind, BackendErrorKind::AlreadyRunning);
}

#[test]
fn wireguard_backend_remove_peer_updates_runtime_state() {
    let mut backend = WireguardBackend::default();
    backend
        .start(runtime_context())
        .expect("backend should start successfully");
    backend
        .configure_peer(sample_peer("peer-a"))
        .expect("peer a should configure");
    backend
        .configure_peer(sample_peer("peer-b"))
        .expect("peer b should configure");

    backend
        .remove_peer(&NodeId::new("peer-a").expect("valid node id"))
        .expect("peer removal should succeed");
    let stats = backend.stats().expect("stats should be available");
    assert_eq!(stats.peer_count, 1);
}
