#![forbid(unsafe_code)]

//! TunnelBackend conformance suite run against StubBackend.
//!
//! Each test scenario mirrors the equivalent test in
//! `rustynet-backend-api/tests/backend_contract.rs`.  Both files must be kept
//! in sync: any scenario added to `backend_contract.rs` must be added here too.
//!
//! Passing all scenarios demonstrates that `StubBackend` is a conformant
//! `TunnelBackend` implementation that can stand in for any backend in tests.

use std::net::{IpAddr, Ipv4Addr};

use rustynet_backend_api::{
    BackendErrorKind, ExitMode, NodeId, PeerConfig, Route, RouteKind, RuntimeContext,
    SocketEndpoint, TunnelBackend,
};
use rustynet_backend_stub::StubBackend;

// ── Shared test data helpers ──────────────────────────────────────────────────

fn sample_context() -> RuntimeContext {
    RuntimeContext {
        local_node: NodeId::new("local-node").expect("valid node id"),
        interface_name: "rustynet0".to_string(),
        mesh_cidr: "100.64.0.0/10".to_string(),
        local_cidr: "100.64.0.1/32".to_string(),
    }
}

fn peer(name: &str) -> PeerConfig {
    PeerConfig {
        node_id: NodeId::new(name).expect("valid node id"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)),
            port: 51820,
        },
        public_key: [7; 32],
        allowed_ips: vec!["100.64.1.0/24".to_string()],
    }
}

fn peer_with_key(name: &str, key_byte: u8) -> PeerConfig {
    PeerConfig {
        node_id: NodeId::new(name).expect("valid node id"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20)),
            port: 51820,
        },
        public_key: [key_byte; 32],
        allowed_ips: vec!["100.64.2.0/24".to_string()],
    }
}

fn nid(name: &str) -> NodeId {
    NodeId::new(name).expect("valid node id")
}

// ── Conformance scenario helpers ──────────────────────────────────────────────

fn contract_not_running_rejects_mutations(b: &mut dyn TunnelBackend) {
    let p = peer("p1");
    let err = b
        .configure_peer(p)
        .expect_err("configure_peer must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b
        .peer_latest_handshake_unix(&nid("p1"))
        .expect_err("handshake must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b
        .apply_routes(vec![])
        .expect_err("apply_routes must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b
        .remove_peer(&nid("p1"))
        .expect_err("remove_peer must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b
        .set_exit_mode(ExitMode::FullTunnel)
        .expect_err("set_exit_mode must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b.stats().expect_err("stats must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);

    let err = b
        .shutdown()
        .expect_err("shutdown must require running state");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);
}

fn contract_start_is_idempotent_reject(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("first start must succeed");
    let err = b
        .start(sample_context())
        .expect_err("second start must fail");
    assert_eq!(err.kind, BackendErrorKind::AlreadyRunning);
    b.shutdown().expect("shutdown after double-start attempt");
}

fn contract_start_and_shutdown_lifecycle(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.configure_peer(peer("lifecycle-peer")).expect("configure");
    b.shutdown().expect("shutdown");
    let err = b
        .configure_peer(peer("lifecycle-peer"))
        .expect_err("ops after shutdown must fail");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);
    b.start(sample_context()).expect("restart after shutdown");
    b.shutdown().expect("second shutdown");
}

fn contract_configure_peer_round_trip(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let p = peer("rt-peer");
    let endpoint = p.endpoint;
    let node_id = p.node_id.clone();
    b.configure_peer(p).expect("configure_peer");
    let got = b
        .current_peer_endpoint(&node_id)
        .expect("current_peer_endpoint should succeed for known peer");
    assert_eq!(got, Some(endpoint), "endpoint round-trip mismatch");
    b.shutdown().expect("shutdown");
}

fn contract_configure_peer_replaces_existing(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let p1 = peer_with_key("replace-peer", 0x01);
    let node_id = p1.node_id.clone();
    b.configure_peer(p1).expect("first configure");
    let p2 = peer_with_key("replace-peer", 0x02);
    b.configure_peer(p2)
        .expect("second configure replaces first");
    b.current_peer_endpoint(&node_id)
        .expect("endpoint should still be accessible after replace");
    b.shutdown().expect("shutdown");
}

fn contract_remove_peer_makes_it_absent(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let p = peer("remove-me");
    let node_id = p.node_id.clone();
    b.configure_peer(p).expect("configure");
    b.remove_peer(&node_id).expect("remove_peer");
    let err = b
        .peer_latest_handshake_unix(&node_id)
        .expect_err("handshake of removed peer must fail");
    assert_eq!(
        err.kind,
        BackendErrorKind::InvalidInput,
        "removed peer must return InvalidInput"
    );
    let result = b.remove_peer(&node_id);
    if let Err(e) = result {
        assert_ne!(
            e.kind,
            BackendErrorKind::NotRunning,
            "remove of absent peer must not return NotRunning"
        );
    }
    b.shutdown().expect("shutdown");
}

fn contract_update_endpoint_preserves_allowed_ips(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let p = peer("ep-peer");
    let node_id = p.node_id.clone();
    b.configure_peer(p).expect("configure");

    let new_ep = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 88)),
        port: 443,
    };
    b.update_peer_endpoint(&node_id, new_ep)
        .expect("update_peer_endpoint");

    let current = b
        .current_peer_endpoint(&node_id)
        .expect("current_peer_endpoint after update");
    assert_eq!(current, Some(new_ep));

    b.peer_latest_handshake_unix(&node_id)
        .expect("handshake must still succeed after endpoint update");
    b.shutdown().expect("shutdown");
}

fn contract_update_endpoint_unknown_peer_rejected(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let ep = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        port: 51820,
    };
    let err = b
        .update_peer_endpoint(&nid("ghost-peer"), ep)
        .expect_err("update on unknown peer must fail");
    assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    b.shutdown().expect("shutdown");
}

fn contract_endpoint_unknown_peer_returns_none_or_error(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let result = b.current_peer_endpoint(&nid("never-configured"));
    match result {
        Ok(None) => {}
        Ok(Some(_)) => panic!("unconfigured peer should not have an endpoint"),
        Err(e) => assert_eq!(
            e.kind,
            BackendErrorKind::InvalidInput,
            "unconfigured peer endpoint error must be InvalidInput"
        ),
    }
    b.shutdown().expect("shutdown");
}

fn contract_handshake_unknown_peer_rejected(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let err = b
        .peer_latest_handshake_unix(&nid("unknown"))
        .expect_err("handshake lookup on unconfigured peer must fail");
    assert_eq!(err.kind, BackendErrorKind::InvalidInput);
    b.shutdown().expect("shutdown");
}

fn contract_handshake_known_peer_returns_none_initially(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.configure_peer(peer("hs-peer")).expect("configure");
    let hs = b
        .peer_latest_handshake_unix(&nid("hs-peer"))
        .expect("handshake lookup must succeed for known peer");
    assert_eq!(hs, None, "fresh peer should have no handshake timestamp");
    b.shutdown().expect("shutdown");
}

fn contract_routes_replaced_deterministically(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.apply_routes(vec![
        Route {
            destination_cidr: "192.168.0.0/24".to_string(),
            via_node: nid("r-peer-a"),
            kind: RouteKind::Mesh,
        },
        Route {
            destination_cidr: "0.0.0.0/0".to_string(),
            via_node: nid("r-peer-b"),
            kind: RouteKind::ExitNodeDefault,
        },
    ])
    .expect("first apply_routes");

    b.apply_routes(vec![Route {
        destination_cidr: "10.0.0.0/8".to_string(),
        via_node: nid("r-peer-c"),
        kind: RouteKind::ExitNodeLan,
    }])
    .expect("second apply_routes replaces first");

    b.stats().expect("stats after routes replaced");
    b.shutdown().expect("shutdown");
}

fn contract_routes_cleared_on_empty_apply(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.apply_routes(vec![Route {
        destination_cidr: "0.0.0.0/0".to_string(),
        via_node: nid("exit-peer"),
        kind: RouteKind::ExitNodeDefault,
    }])
    .expect("seed routes");
    b.apply_routes(vec![])
        .expect("clear routes via empty apply");
    b.shutdown().expect("shutdown");
}

fn contract_exit_mode_off_is_default(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.set_exit_mode(ExitMode::Off).expect("set exit mode off");
    b.shutdown().expect("shutdown");
}

fn contract_exit_mode_full_tunnel_accepted(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.set_exit_mode(ExitMode::FullTunnel)
        .expect("set exit mode full tunnel");
    b.set_exit_mode(ExitMode::Off)
        .expect("reset exit mode to off");
    b.shutdown().expect("shutdown");
}

fn contract_stats_peer_count_reflects_configured_peers(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let s0 = b.stats().expect("stats with no peers");
    assert_eq!(s0.peer_count, 0);

    b.configure_peer(peer("stats-peer-1")).expect("configure 1");
    b.configure_peer(peer("stats-peer-2")).expect("configure 2");
    let s2 = b.stats().expect("stats with 2 peers");
    assert_eq!(s2.peer_count, 2);

    b.remove_peer(&nid("stats-peer-1")).expect("remove peer 1");
    let s1 = b.stats().expect("stats with 1 peer");
    assert_eq!(s1.peer_count, 1);

    b.shutdown().expect("shutdown");
}

fn contract_shutdown_then_ops_require_restart(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    b.shutdown().expect("shutdown");
    let err = b.stats().expect_err("stats after shutdown must fail");
    assert_eq!(err.kind, BackendErrorKind::NotRunning);
    b.start(sample_context()).expect("re-start");
    b.stats().expect("stats after re-start must succeed");
    b.shutdown().expect("final shutdown");
}

fn contract_multi_peer_isolated_operations(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let p_a = peer_with_key("multi-a", 0xAA);
    let p_b = peer_with_key("multi-b", 0xBB);
    let id_a = p_a.node_id.clone();
    let id_b = p_b.node_id.clone();
    b.configure_peer(p_a).expect("configure a");
    b.configure_peer(p_b).expect("configure b");

    let ep_new = SocketEndpoint {
        addr: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 99)),
        port: 51821,
    };
    b.update_peer_endpoint(&id_a, ep_new).expect("update a");

    let ep_b = b
        .current_peer_endpoint(&id_b)
        .expect("b's endpoint should be accessible");
    assert!(ep_b.is_some(), "peer b must still have an endpoint");
    assert_ne!(
        ep_b.unwrap(),
        ep_new,
        "updating peer a must not affect peer b"
    );

    b.remove_peer(&id_a).expect("remove a");
    b.peer_latest_handshake_unix(&id_b)
        .expect("peer b still accessible after removing peer a");

    b.shutdown().expect("shutdown");
}

fn contract_configure_same_peer_multiple_ips(b: &mut dyn TunnelBackend) {
    b.start(sample_context()).expect("start");
    let base = PeerConfig {
        node_id: nid("multi-ip-peer"),
        endpoint: SocketEndpoint {
            addr: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 51820,
        },
        public_key: [0x01; 32],
        allowed_ips: vec![
            "100.64.5.0/24".to_string(),
            "192.168.100.0/24".to_string(),
            "10.10.0.0/16".to_string(),
        ],
    };
    b.configure_peer(base)
        .expect("configure with multiple allowed IPs");
    b.peer_latest_handshake_unix(&nid("multi-ip-peer"))
        .expect("handshake accessible after multi-IP configure");
    b.shutdown().expect("shutdown");
}

/// Run all conformance scenarios against the given backend in sequence.
///
/// Scenarios are order-dependent within this function (each starts/stops the
/// backend cleanly so the next scenario starts from a stopped state).
fn run_stub_conformance_suite(mut backend: StubBackend) {
    contract_not_running_rejects_mutations(&mut backend);
    contract_start_is_idempotent_reject(&mut backend);
    contract_start_and_shutdown_lifecycle(&mut backend);
    contract_configure_peer_round_trip(&mut backend);
    contract_configure_peer_replaces_existing(&mut backend);
    contract_remove_peer_makes_it_absent(&mut backend);
    contract_update_endpoint_preserves_allowed_ips(&mut backend);
    contract_update_endpoint_unknown_peer_rejected(&mut backend);
    contract_endpoint_unknown_peer_returns_none_or_error(&mut backend);
    contract_handshake_unknown_peer_rejected(&mut backend);
    contract_handshake_known_peer_returns_none_initially(&mut backend);
    contract_routes_replaced_deterministically(&mut backend);
    contract_routes_cleared_on_empty_apply(&mut backend);
    contract_exit_mode_off_is_default(&mut backend);
    contract_exit_mode_full_tunnel_accepted(&mut backend);
    contract_stats_peer_count_reflects_configured_peers(&mut backend);
    contract_shutdown_then_ops_require_restart(&mut backend);
    contract_multi_peer_isolated_operations(&mut backend);
    contract_configure_same_peer_multiple_ips(&mut backend);
}

// ── Named test functions ──────────────────────────────────────────────────────

#[test]
fn stub_backend_requires_running_state_for_mutations() {
    let mut b = StubBackend::default();
    contract_not_running_rejects_mutations(&mut b);
}

#[test]
fn stub_backend_rejects_double_start_and_resets_on_shutdown() {
    let mut b = StubBackend::default();
    contract_start_is_idempotent_reject(&mut b);
}

#[test]
fn stub_backend_start_and_shutdown_lifecycle() {
    let mut b = StubBackend::default();
    contract_start_and_shutdown_lifecycle(&mut b);
}

#[test]
fn stub_backend_configure_peer_round_trip() {
    let mut b = StubBackend::default();
    contract_configure_peer_round_trip(&mut b);
}

#[test]
fn stub_backend_configure_peer_replaces_existing() {
    let mut b = StubBackend::default();
    contract_configure_peer_replaces_existing(&mut b);
}

#[test]
fn stub_backend_remove_peer_makes_it_absent() {
    let mut b = StubBackend::default();
    contract_remove_peer_makes_it_absent(&mut b);
}

#[test]
fn stub_backend_update_endpoint_preserves_peer_identity() {
    let mut b = StubBackend::default();
    contract_update_endpoint_preserves_allowed_ips(&mut b);
}

#[test]
fn stub_backend_update_endpoint_unknown_peer_rejected() {
    let mut b = StubBackend::default();
    contract_update_endpoint_unknown_peer_rejected(&mut b);
}

#[test]
fn stub_backend_current_endpoint_unknown_peer_safe() {
    let mut b = StubBackend::default();
    contract_endpoint_unknown_peer_returns_none_or_error(&mut b);
}

#[test]
fn stub_backend_handshake_unknown_peer_rejected() {
    let mut b = StubBackend::default();
    contract_handshake_unknown_peer_rejected(&mut b);
}

#[test]
fn stub_backend_handshake_known_peer_returns_none_initially() {
    let mut b = StubBackend::default();
    contract_handshake_known_peer_returns_none_initially(&mut b);
}

#[test]
fn stub_backend_replaces_route_set_deterministically() {
    let mut b = StubBackend::default();
    contract_routes_replaced_deterministically(&mut b);
}

#[test]
fn stub_backend_routes_cleared_on_empty_apply() {
    let mut b = StubBackend::default();
    contract_routes_cleared_on_empty_apply(&mut b);
}

#[test]
fn stub_backend_exit_mode_off_is_default() {
    let mut b = StubBackend::default();
    contract_exit_mode_off_is_default(&mut b);
}

#[test]
fn stub_backend_exit_mode_full_tunnel_accepted() {
    let mut b = StubBackend::default();
    contract_exit_mode_full_tunnel_accepted(&mut b);
}

#[test]
fn stub_backend_stats_peer_count_reflects_configured_peers() {
    let mut b = StubBackend::default();
    contract_stats_peer_count_reflects_configured_peers(&mut b);
}

#[test]
fn stub_backend_shutdown_then_ops_require_restart() {
    let mut b = StubBackend::default();
    contract_shutdown_then_ops_require_restart(&mut b);
}

#[test]
fn stub_backend_multi_peer_isolated_operations() {
    let mut b = StubBackend::default();
    contract_multi_peer_isolated_operations(&mut b);
}

#[test]
fn stub_backend_configure_same_peer_with_multiple_allowed_ips() {
    let mut b = StubBackend::default();
    contract_configure_same_peer_multiple_ips(&mut b);
}

#[test]
fn stub_backend_passes_full_conformance_suite() {
    run_stub_conformance_suite(StubBackend::default());
}
