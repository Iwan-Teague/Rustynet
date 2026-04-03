#![forbid(unsafe_code)]

use rustynet_backend_api::{
    BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext,
    SocketEndpoint, TunnelBackend,
};
use rustynet_backend_wireguard::{
    LinuxUserspaceSharedBackend, LinuxWireguardBackend, MacosWireguardBackend, WireguardBackend,
    WireguardCommandOutput, WireguardCommandRunner,
};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::prelude::*;

fn runtime_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        interface_name: "rustynet0".to_string(),
        mesh_cidr: "100.64.0.0/10".to_string(),
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

#[derive(Debug, Default)]
struct StubRunner;

impl WireguardCommandRunner for StubRunner {
    fn run(
        &mut self,
        _program: &str,
        _args: &[String],
    ) -> Result<(), rustynet_backend_api::BackendError> {
        Ok(())
    }

    fn run_capture(
        &mut self,
        _program: &str,
        _args: &[String],
    ) -> Result<WireguardCommandOutput, rustynet_backend_api::BackendError> {
        Ok(WireguardCommandOutput {
            stdout: String::new(),
            stderr: String::new(),
        })
    }
}

fn unique_path(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rustynet-userspace-shared-conformance-{name}-{}-{nanos}.key",
        std::process::id()
    ))
}

fn write_private_key(bytes: [u8; 32]) -> PathBuf {
    let path = unique_path("valid");
    fs::write(&path, format!("{}\n", BASE64_STANDARD.encode(bytes)))
        .expect("private key should be written");
    path
}

fn free_listen_port() -> u16 {
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
        .expect("ephemeral port should be available");
    socket.local_addr().expect("local addr").port()
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

#[test]
fn linux_userspace_shared_backend_lifecycle_exposes_authoritative_identity_only_while_running() {
    let private_key_path = write_private_key([17; 32]);
    let listen_port = free_listen_port();
    let expected_local_addr = SocketAddr::from(([0, 0, 0, 0], listen_port));
    let mut backend = LinuxUserspaceSharedBackend::new_for_test(
        "rustynet0",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");

    assert!(backend.authoritative_transport_identity().is_none());

    backend
        .start(runtime_context())
        .expect("backend should start successfully");

    let identity = backend
        .authoritative_transport_identity()
        .expect("identity should exist after start");
    assert_eq!(identity.local_addr, expected_local_addr);

    let second_start_err = backend
        .start(runtime_context())
        .expect_err("second start should fail");
    assert_eq!(second_start_err.kind, BackendErrorKind::AlreadyRunning);

    backend.shutdown().expect("shutdown should succeed");
    assert!(backend.authoritative_transport_identity().is_none());

    let rebound = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], listen_port)))
        .expect("shutdown should release the authoritative UDP socket");
    drop(rebound);

    let _ = fs::remove_file(private_key_path);
}

#[test]
fn linux_userspace_shared_backend_supports_route_and_exit_mode_lifecycle() {
    let private_key_path = write_private_key([18; 32]);
    let listen_port = free_listen_port();
    let mut backend = LinuxUserspaceSharedBackend::new_for_test(
        "rustynet0",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");

    backend
        .start(runtime_context())
        .expect("backend should start successfully");
    backend
        .configure_peer(sample_peer("peer-a"))
        .expect("peer should configure");
    backend
        .apply_routes(vec![Route {
            destination_cidr: "100.64.20.0/24".to_string(),
            via_node: NodeId::new("peer-a").expect("valid node id"),
            kind: RouteKind::ExitNodeLan,
        }])
        .expect("route apply should succeed");
    backend
        .set_exit_mode(ExitMode::FullTunnel)
        .expect("exit mode switch should succeed");

    let capabilities = backend.capabilities();
    assert!(capabilities.supports_exit_nodes);
    assert!(capabilities.supports_lan_routes);

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn command_only_linux_backend_blocker_remains_unchanged() {
    let backend = LinuxWireguardBackend::new(StubRunner, "rustynet0", "/tmp/wg.key", 51820)
        .expect("backend should construct");

    assert_eq!(
        backend.transport_socket_identity_blocker(),
        Some(
            "linux wireguard backend is a command-only adapter over an OS-managed WireGuard UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_string()
        )
    );
}

#[test]
fn command_only_macos_backend_blocker_remains_unchanged() {
    let backend = MacosWireguardBackend::new(StubRunner, "utun9", "/tmp/wg.key", "en0", 51820)
        .expect("backend should construct");

    assert_eq!(
        backend.transport_socket_identity_blocker(),
        Some(
            "macos wireguard backend is a command-only adapter over wireguard-go and its OS-managed UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_string()
        )
    );
}
