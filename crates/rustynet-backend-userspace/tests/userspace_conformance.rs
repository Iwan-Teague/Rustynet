//! TunnelBackend conformance suite run against UserspaceBackend.
//!
//! On Linux, UserspaceBackend delegates to LinuxUserspaceSharedBackend which
//! requires a real TUN device and a valid private key file. Tests that need a
//! live engine are gated behind a well-known env var
//! (RUSTYNET_USERSPACE_CONFORMANCE_KEY) so they can be skipped in CI
//! environments without TUN capability.
//!
//! On macOS, UserspaceBackend delegates to MacosUserspaceSharedBackend (Phase 1
//! scaffolding): construction succeeds but all operational methods return an
//! internal error. Platform invariant tests verify this Phase 1 contract.
//!
//! Platform invariant tests (capability advertisement, constructor error
//! handling) run unconditionally on all platforms.

#![forbid(unsafe_code)]

#[cfg(not(target_os = "macos"))]
use rustynet_backend_api::BackendErrorKind;
use rustynet_backend_api::TunnelBackend;
use rustynet_backend_userspace::UserspaceBackend;

// ── Platform-invariant tests ──────────────────────────────────────────────────

#[test]
fn userspace_backend_name_is_stable() {
    // On Linux, use a guaranteed-invalid key path so the constructor rejects
    // it without touching the network — we still get a valid error type.
    // On macOS, Phase 1 scaffolding construction succeeds; verify name.
    // On other platforms, construction returns an Internal error.
    #[cfg(target_os = "linux")]
    {
        let result = UserspaceBackend::new("rustynet0", "/nonexistent/key.key", 51820);
        match result {
            Ok(mut b) => {
                assert_eq!(b.name(), "userspace-wireguard");
                let _ = b.shutdown();
            }
            Err(e) => {
                assert_eq!(
                    e.kind,
                    BackendErrorKind::InvalidInput,
                    "invalid key path should return InvalidInput, got: {e}"
                );
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Phase 1: construction succeeds; name is stable.
        let b = UserspaceBackend::new("utun9", "/any/key", 51820)
            .expect("MacosUserspaceSharedBackend Phase 1 construction must succeed");
        assert_eq!(b.name(), "userspace-wireguard");
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let result = UserspaceBackend::new("rustynet0", "/any/key", 51820);
        assert!(
            result.is_err(),
            "UserspaceBackend must fail on unsupported platform"
        );
        let err = result.err().expect("already asserted is_err");
        assert_eq!(err.kind, BackendErrorKind::Internal);
    }
}

#[test]
fn userspace_backend_capabilities_struct_is_well_formed() {
    // Capabilities is available even without starting; on Linux and macOS we
    // inspect it from a constructed instance; on other platforms we verify the
    // platform error path.
    #[cfg(target_os = "linux")]
    {
        let result = UserspaceBackend::new("rustynet0", "/nonexistent/key.key", 51820);
        if let Ok(b) = result {
            let _ = b.capabilities();
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Phase 1: construction succeeds; capabilities is well-formed.
        let b = UserspaceBackend::new("utun9", "/any/key", 51820)
            .expect("MacosUserspaceSharedBackend Phase 1 construction must succeed");
        let caps = b.capabilities();
        assert!(
            caps.supports_exit_nodes,
            "macOS userspace-shared backend declares exit-node support"
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let result = UserspaceBackend::new("rustynet0", "/any/key", 51820);
        assert!(
            result.is_err(),
            "unsupported platform must reject construction"
        );
        let err = result.err().expect("already asserted is_err");
        assert_eq!(err.kind, BackendErrorKind::Internal);
    }
}

// ── Linux TUN-capable conformance (opt-in via env var) ───────────────────────

/// Returns the private key path from RUSTYNET_USERSPACE_CONFORMANCE_KEY if
/// set and the file exists, otherwise None (test is skipped).
#[cfg(target_os = "linux")]
fn conformance_key_path() -> Option<std::path::PathBuf> {
    let path = std::path::PathBuf::from(std::env::var("RUSTYNET_USERSPACE_CONFORMANCE_KEY").ok()?);
    if path.exists() { Some(path) } else { None }
}

#[cfg(target_os = "linux")]
fn make_backend(key_path: &std::path::Path) -> UserspaceBackend {
    UserspaceBackend::new(
        "rustynet-test0",
        key_path.to_str().expect("key path must be valid utf-8"),
        59820,
    )
    .expect("UserspaceBackend should construct from a valid key on Linux")
}

#[test]
#[cfg(target_os = "linux")]
fn userspace_backend_tun_conformance_requires_env() {
    let Some(key_path) = conformance_key_path() else {
        // No key provided — skip. This is expected in CI without TUN.
        return;
    };

    use rustynet_backend_api::{
        ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext, SocketEndpoint,
        TunnelBackend,
    };
    use std::net::{IpAddr, Ipv4Addr};

    let ctx = RuntimeContext {
        local_node: NodeId::new("userspace-test-node").expect("valid node id"),
        interface_name: "rustynet-test0".to_string(),
        mesh_cidr: "100.64.0.0/10".to_string(),
        local_cidr: "100.64.0.1/32".to_string(),
    };

    let sample_peer = PeerConfig {
        node_id: NodeId::new("remote-peer").expect("valid node id"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            port: 51820,
        },
        public_key: [7u8; 32],
        allowed_ips: vec!["100.64.1.0/24".to_string()],
    };

    let mut backend = make_backend(&key_path);
    assert_eq!(backend.name(), "userspace-wireguard");

    backend.start(ctx).expect("start should succeed");

    backend
        .configure_peer(sample_peer.clone())
        .expect("configure_peer should succeed");

    let ep = backend
        .current_peer_endpoint(&sample_peer.node_id)
        .expect("current_peer_endpoint should succeed");
    assert!(ep.is_some(), "configured peer must have an endpoint");

    backend
        .update_peer_endpoint(
            &sample_peer.node_id,
            SocketEndpoint {
                addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)),
                port: 51821,
            },
        )
        .expect("update_peer_endpoint should succeed");

    backend
        .peer_latest_handshake_unix(&sample_peer.node_id)
        .expect("peer_latest_handshake_unix should succeed for known peer");

    backend
        .apply_routes(vec![Route {
            destination_cidr: "100.64.0.0/10".to_string(),
            via_node: sample_peer.node_id.clone(),
            kind: RouteKind::Mesh,
        }])
        .expect("apply_routes should succeed");

    backend
        .set_exit_mode(ExitMode::Off)
        .expect("set_exit_mode should succeed");

    let stats = backend.stats().expect("stats should succeed");
    assert_eq!(stats.peer_count, 1);

    backend
        .remove_peer(&sample_peer.node_id)
        .expect("remove_peer should succeed");

    let stats_after = backend.stats().expect("stats after remove should succeed");
    assert_eq!(stats_after.peer_count, 0);

    backend.shutdown().expect("shutdown should succeed");
}

#[test]
#[cfg(target_os = "linux")]
fn userspace_backend_rejects_ops_before_start() {
    let Some(key_path) = conformance_key_path() else {
        return;
    };

    use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint, TunnelBackend};
    use std::net::{IpAddr, Ipv4Addr};

    let mut backend = make_backend(&key_path);

    let p = PeerConfig {
        node_id: NodeId::new("p1").expect("valid node id"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            port: 51820,
        },
        public_key: [1u8; 32],
        allowed_ips: vec!["100.64.2.0/24".to_string()],
    };

    let err = backend
        .configure_peer(p)
        .expect_err("configure_peer must require running state");
    assert_eq!(
        err.kind,
        BackendErrorKind::NotRunning,
        "pre-start configure_peer must return NotRunning"
    );
}
