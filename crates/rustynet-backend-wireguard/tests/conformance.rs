#![forbid(unsafe_code)]
#![cfg(feature = "test-harness")]

use rustynet_backend_api::{
    BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext,
    SocketEndpoint, TunnelBackend,
};
use rustynet_backend_wireguard::{
    LinuxUserspaceSharedBackend, LinuxWireguardBackend, MacosUserspaceSharedBackend,
    MacosWireguardBackend, WindowsWireguardBackend, WireguardBackend, WireguardCommandOutput,
    WireguardCommandRunner,
};
use std::fs;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::prelude::*;

fn runtime_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        interface_name: "rustynet0".to_owned(),
        mesh_cidr: "100.64.0.0/10".to_owned(),
        local_cidr: "100.64.0.1/32".to_owned(),
    }
}

fn macos_runtime_context(interface_name: &str) -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        interface_name: interface_name.to_owned(),
        mesh_cidr: "100.64.0.0/10".to_owned(),
        local_cidr: "100.64.0.1/32".to_owned(),
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
        allowed_ips: vec!["100.64.1.0/24".to_owned()],
        persistent_keepalive_secs: None,
    }
}

#[derive(Debug, Clone, Default)]
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
    static NEXT_PATH_ID: AtomicU64 = AtomicU64::new(1);
    let path_id = NEXT_PATH_ID.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time should move forward")
        .as_nanos();
    std::env::temp_dir().join(format!(
        "rustynet-userspace-shared-conformance-{name}-{}-{path_id}-{nanos}.key",
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

fn wait_for<T>(timeout: Duration, mut check: impl FnMut() -> Option<T>) -> T {
    let start = std::time::Instant::now();
    loop {
        if let Some(value) = check() {
            return value;
        }
        if start.elapsed() >= timeout {
            panic!("condition was not satisfied within {timeout:?}");
        }
        thread::sleep(Duration::from_millis(10));
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
            destination_cidr: "0.0.0.0/0".to_owned(),
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
            destination_cidr: "100.64.20.0/24".to_owned(),
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
fn macos_userspace_shared_backend_lifecycle_exposes_authoritative_identity_only_while_running() {
    let private_key_path = write_private_key([19; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun9",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");

    assert!(backend.authoritative_transport_identity().is_none());

    backend
        .start(macos_runtime_context("utun9"))
        .expect("backend should start successfully");

    let identity = backend
        .authoritative_transport_identity()
        .expect("identity should exist after start");
    assert_eq!(
        identity.label,
        "wireguard-macos-userspace-shared-authoritative-transport"
    );
    // In test mode the backend binds to loopback (127.0.0.1) with an
    // ephemeral port to avoid requiring real WireGuard networking.
    assert!(identity.local_addr.ip().is_loopback());
    assert_ne!(identity.local_addr.port(), 0);

    let second_start_err = backend
        .start(macos_runtime_context("utun9"))
        .expect_err("second start should fail");
    assert_eq!(second_start_err.kind, BackendErrorKind::AlreadyRunning);

    backend.shutdown().expect("shutdown should succeed");
    assert!(backend.authoritative_transport_identity().is_none());

    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_supports_route_and_exit_mode_lifecycle() {
    let private_key_path = write_private_key([20; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun10",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");

    backend
        .start(macos_runtime_context("utun10"))
        .expect("backend should start successfully");
    backend
        .configure_peer(sample_peer("peer-a"))
        .expect("peer should configure");
    backend
        .apply_routes(vec![Route {
            destination_cidr: "100.64.20.0/24".to_owned(),
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
    assert!(!capabilities.supports_ipv6);

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_rejects_malformed_allowed_ips_before_state_mutation() {
    let private_key_path = write_private_key([21; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun11",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun11"))
        .expect("backend should start successfully");

    let mut peer = sample_peer("peer-a");
    peer.allowed_ips = vec!["999.64.1.0/24;rm -rf /".to_owned()];
    let err = backend
        .configure_peer(peer)
        .expect_err("malformed allowed_ips must fail");
    assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_rejects_invalid_peer_endpoints_before_state_mutation() {
    let private_key_path = write_private_key([22; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun12",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun12"))
        .expect("backend should start successfully");

    for endpoint in [
        SocketEndpoint {
            addr: "127.0.0.1".parse().expect("valid ip"),
            port: 0,
        },
        SocketEndpoint {
            addr: "0.0.0.0".parse().expect("valid ip"),
            port: 51820,
        },
        SocketEndpoint {
            addr: "2001:db8::1".parse().expect("valid ip"),
            port: 51820,
        },
        SocketEndpoint {
            addr: "224.0.0.1".parse().expect("valid ip"),
            port: 51820,
        },
        SocketEndpoint {
            addr: "255.255.255.255".parse().expect("valid ip"),
            port: 51820,
        },
    ] {
        let mut peer = sample_peer("peer-a");
        peer.endpoint = endpoint;
        let err = backend
            .configure_peer(peer)
            .expect_err("invalid endpoint must fail before peer mutation");
        assert_eq!(err.kind, BackendErrorKind::InvalidInput);
        assert_eq!(backend.stats().expect("stats should resolve").peer_count, 0);
    }

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_rejects_control_send_to_configured_peer_endpoint() {
    let private_key_path = write_private_key([23; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun13",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun13"))
        .expect("backend should start successfully");
    let peer = sample_peer("peer-a");
    let peer_endpoint = SocketAddr::new(peer.endpoint.addr, peer.endpoint.port);
    backend.configure_peer(peer).expect("peer should configure");

    let err = backend
        .authoritative_transport_send(peer_endpoint, b"relay-control")
        .expect_err("control send to configured peer endpoint must fail");
    assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    assert!(err.message.contains("configured peer endpoint"));
    assert_eq!(backend.stats().expect("stats should resolve").peer_count, 1);

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_hides_identity_after_dead_worker() {
    let private_key_path = write_private_key([24; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun14",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun14"))
        .expect("backend should start successfully");
    assert!(backend.authoritative_transport_identity().is_some());

    backend
        .set_next_tun_recv_error_for_test("conformance simulated TUN failure")
        .expect("test TUN error should inject");
    wait_for(Duration::from_secs(1), || {
        backend
            .authoritative_transport_identity()
            .is_none()
            .then_some(())
    });

    let _ = backend.shutdown();
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_recovers_authoritative_send_after_dead_worker() {
    let private_key_path = write_private_key([25; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun15",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun15"))
        .expect("backend should start successfully");
    backend
        .set_next_tun_recv_error_for_test("conformance simulated TUN failure before send")
        .expect("test TUN error should inject");
    wait_for(Duration::from_secs(1), || {
        backend
            .authoritative_transport_identity()
            .is_none()
            .then_some(())
    });

    let remote = UdpSocket::bind("127.0.0.1:0").expect("remote bind");
    remote
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("remote read timeout");
    let identity = backend
        .authoritative_transport_send(
            remote.local_addr().expect("remote addr"),
            b"conformance-relay-send",
        )
        .expect("authoritative send should recover worker");
    let mut buffer = [0u8; 128];
    let (len, source) = remote.recv_from(&mut buffer).expect("send should arrive");

    assert_eq!(&buffer[..len], b"conformance-relay-send");
    assert_eq!(identity.local_addr.port(), source.port());
    assert!(backend.authoritative_transport_identity().is_some());

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_route_apply_failure_is_retryable() {
    let private_key_path = write_private_key([26; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun16",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun16"))
        .expect("backend should start successfully");
    let stable = Route {
        destination_cidr: "100.64.30.0/24".to_owned(),
        via_node: NodeId::new("peer-a").expect("valid node id"),
        kind: RouteKind::Mesh,
    };
    let replacement = Route {
        destination_cidr: "100.64.31.0/24".to_owned(),
        via_node: NodeId::new("peer-a").expect("valid node id"),
        kind: RouteKind::Mesh,
    };
    backend
        .apply_routes(vec![stable])
        .expect("stable route should apply");
    backend
        .set_route_add_failure_for_test(
            replacement.destination_cidr.clone(),
            "conformance route add failure",
        )
        .expect("route failure should arm");

    let err = backend
        .apply_routes(vec![replacement.clone()])
        .expect_err("route add failure must fail closed");
    assert_eq!(err.kind, BackendErrorKind::Internal);
    assert!(err.message.contains("conformance route add failure"));

    backend
        .clear_route_failure_for_test()
        .expect("route failure should clear");
    backend
        .apply_routes(vec![replacement])
        .expect("route apply should retry after failure clears");

    backend.shutdown().expect("shutdown should succeed");
    let _ = fs::remove_file(private_key_path);
}

#[test]
fn macos_userspace_shared_backend_exit_mode_failure_is_retryable() {
    let private_key_path = write_private_key([27; 32]);
    let listen_port = free_listen_port();
    let mut backend = MacosUserspaceSharedBackend::new_for_test(
        "utun17",
        private_key_path.to_string_lossy(),
        listen_port,
    )
    .expect("backend should construct");
    backend
        .start(macos_runtime_context("utun17"))
        .expect("backend should start successfully");
    backend
        .set_full_tunnel_failure_for_test("conformance full-tunnel failure")
        .expect("exit-mode failure should arm");

    let err = backend
        .set_exit_mode(ExitMode::FullTunnel)
        .expect_err("full-tunnel failure must fail closed");
    assert_eq!(err.kind, BackendErrorKind::Internal);
    assert!(err.message.contains("conformance full-tunnel failure"));

    backend
        .clear_exit_mode_failure_for_test()
        .expect("exit-mode failure should clear");
    backend
        .set_exit_mode(ExitMode::FullTunnel)
        .expect("full tunnel should retry after failure clears");
    backend
        .set_exit_mode(ExitMode::Off)
        .expect("exit mode should clear");

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
            "linux wireguard backend is a command-only adapter over an OS-managed WireGuard UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned()
        )
    );
}

#[test]
fn command_only_macos_backend_blocker_remains_unchanged() {
    let backend =
        MacosWireguardBackend::new_for_test(StubRunner, "utun9", "/tmp/wg.key", "en0", 51820)
            .expect("backend should construct");

    assert_eq!(
        backend.transport_socket_identity_blocker(),
        Some(
            "macos wireguard backend is a command-only adapter over wireguard-go and its OS-managed UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned()
        )
    );
}

#[test]
fn command_only_windows_backend_blocker_remains_explicit() {
    let backend = WindowsWireguardBackend::new(
        StubRunner,
        "rustynet0",
        "/tmp/rustynet0.conf.dpapi",
        "/tmp/wg.key",
        "/tmp/wireguard.exe",
        "/tmp/wg.exe",
        "/tmp/netsh.exe",
        51820,
    )
    .expect("windows backend should construct");

    assert_eq!(
        backend.transport_socket_identity_blocker(),
        Some(
            "windows wireguard backend is a command-only adapter over the official WireGuard for Windows tunnel service and its OS-managed WireGuardNT UDP socket; it exposes configuration and handshake queries but no authoritative packet-I/O handle or backend-owned datagram multiplexer, so the daemon cannot safely run STUN or relay bootstrap/refresh on the real peer-traffic transport, and a same-port daemon side socket is not authoritative transport identity".to_owned()
        )
    );
}
