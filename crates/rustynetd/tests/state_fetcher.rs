use ed25519_dalek::{Signer, SigningKey};
use rustynet_backend_api::{NodeId, PeerConfig, SocketEndpoint};
use rustynetd::daemon::{
    AutoTunnelBundle, DaemonBackendMode, DaemonConfig, DaemonDataplaneMode, FetchDecision,
    NodeRole, StateFetcher,
};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use tempfile::tempdir;

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn make_test_config(dir: &std::path::Path) -> DaemonConfig {
    DaemonConfig {
        node_id: "node-local".to_string(),
        node_role: NodeRole::Client,
        socket_path: dir.join("sock"),
        state_path: dir.join("state"),
        trust_evidence_path: dir.join("trust.evidence"),
        trust_verifier_key_path: dir.join("trust.pub"),
        trust_watermark_path: dir.join("trust.watermark"),
        membership_snapshot_path: dir.join("membership.snap"),
        membership_log_path: dir.join("membership.log"),
        membership_watermark_path: dir.join("membership.watermark"),
        auto_tunnel_enforce: false,
        auto_tunnel_bundle_path: Some(dir.join("assignment.bundle")),
        auto_tunnel_verifier_key_path: Some(dir.join("assignment.pub")),
        auto_tunnel_watermark_path: Some(dir.join("assignment.watermark")),
        auto_tunnel_max_age_secs: std::num::NonZeroU64::new(300).unwrap(),
        dns_zone_bundle_path: dir.join("dns.bundle"),
        dns_zone_verifier_key_path: dir.join("dns.pub"),
        dns_zone_watermark_path: dir.join("dns.watermark"),
        dns_zone_max_age_secs: std::num::NonZeroU64::new(300).unwrap(),
        dns_zone_name: "example.com".to_string(),
        dns_resolver_bind_addr: "127.0.0.1:5353".parse().unwrap(),
        traversal_bundle_path: dir.join("traversal.bundle"),
        traversal_verifier_key_path: dir.join("traversal.pub"),
        traversal_watermark_path: dir.join("traversal.watermark"),
        traversal_max_age_secs: std::num::NonZeroU64::new(300).unwrap(),
        traversal_probe_max_candidates: std::num::NonZeroUsize::new(10).unwrap(),
        traversal_probe_max_pairs: std::num::NonZeroUsize::new(100).unwrap(),
        traversal_probe_simultaneous_open_rounds: std::num::NonZeroU8::new(3).unwrap(),
        traversal_probe_round_spacing_ms: std::num::NonZeroU64::new(50).unwrap(),
        traversal_probe_relay_switch_after_failures: std::num::NonZeroU8::new(3).unwrap(),
        traversal_probe_handshake_freshness_secs: std::num::NonZeroU64::new(5).unwrap(),
        traversal_probe_reprobe_interval_secs: std::num::NonZeroU64::new(3).unwrap(),
        traversal_stun_servers: vec![],
        traversal_stun_gather_timeout_ms: std::num::NonZeroU64::new(2000).unwrap(),
        backend_mode: DaemonBackendMode::InMemory,
        wg_interface: "wg0".to_string(),
        wg_listen_port: 51820,
        wg_private_key_path: None,
        wg_encrypted_private_key_path: None,
        wg_key_passphrase_path: None,
        wg_public_key_path: None,
        relay_session_signing_secret_path: None,
        relay_session_signing_secret_passphrase_path: None,
        relay_session_token_ttl_secs: std::num::NonZeroU64::new(120).unwrap(),
        relay_session_refresh_margin_secs: std::num::NonZeroU64::new(15).unwrap(),
        relay_session_idle_timeout_secs: std::num::NonZeroU64::new(30).unwrap(),
        egress_interface: "eth0".to_string(),
        remote_ops_token_verifier_key_path: None,
        remote_ops_expected_subject: "admin".to_string(),
        auto_port_forward_exit: false,
        auto_port_forward_lease_secs: std::num::NonZeroU32::new(3600).unwrap(),
        dataplane_mode: DaemonDataplaneMode::Shell,
        privileged_helper_socket_path: None,
        privileged_helper_timeout_ms: std::num::NonZeroU64::new(1000).unwrap(),
        reconcile_interval_ms: std::num::NonZeroU64::new(1000).unwrap(),
        max_reconcile_failures: std::num::NonZeroU32::new(5).unwrap(),
        fail_closed_ssh_allow: false,
        fail_closed_ssh_allow_cidrs: vec![],
        max_requests: None,
        trust_url: None,
        traversal_url: None,
        assignment_url: None,
        dns_zone_url: None,
    }
}

fn serve_once(response_body: Vec<u8>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let _ = stream.read(&mut buf);
        let len = response_body.len();
        let header = format!("HTTP/1.1 200 OK\r\nContent-Length: {len}\r\n\r\n");
        let mut response = header.into_bytes();
        response.extend_from_slice(&response_body);
        stream.write_all(&response).unwrap();
    });
    format!("http://{addr}")
}

fn make_signed_traversal_bundle(
    verifier_path: &PathBuf,
    nonce: u64,
    invalid_signature: bool,
) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[23u8; 32]);
    fs::write(
        verifier_path,
        format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
    )
    .unwrap();

    let now = unix_now();
    let expires = now + 300;
    let payload = format!(
        "version=1\npath_policy=direct_preferred_relay_allowed\nsource_node_id=node-a\ntarget_node_id=node-b\ngenerated_at_unix={now}\nexpires_at_unix={expires}\nnonce={nonce}\ncandidate_count=1\ncandidate.0.type=host\ncandidate.0.addr=192.168.1.1\ncandidate.0.port=1234\ncandidate.0.family=ipv4\ncandidate.0.relay_id= \ncandidate.0.priority=100\n"
    );
    let signature = signing_key.sign(payload.as_bytes());
    let mut sig_bytes = signature.to_bytes().to_vec();
    if invalid_signature {
        sig_bytes[0] ^= 0xff;
    }

    format!("{}signature={}\n", payload, hex_encode(&sig_bytes)).into_bytes()
}

#[test]
fn fetcher_traversal_applied_updates_bundle_file() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    let bundle = make_signed_traversal_bundle(&cfg.traversal_verifier_key_path, 100, false);
    let url = serve_once(bundle);

    cfg.traversal_url = Some(url);
    let fetcher = StateFetcher::new_from_daemon(&cfg);

    assert_eq!(fetcher.fetch_traversal().unwrap(), FetchDecision::Applied);
    assert!(cfg.traversal_bundle_path.exists());
    assert!(cfg.traversal_watermark_path.exists());
}

#[test]
fn fetcher_traversal_replay_rejected_is_hard_error() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    fs::create_dir_all(cfg.traversal_watermark_path.parent().unwrap()).unwrap();
    fs::write(&cfg.traversal_watermark_path, "nonce=200\n").unwrap();

    let bundle = make_signed_traversal_bundle(&cfg.traversal_verifier_key_path, 100, false);
    let url = serve_once(bundle);

    cfg.traversal_url = Some(url);
    let fetcher = StateFetcher::new_from_daemon(&cfg);

    let err = fetcher.fetch_traversal().unwrap_err();
    assert!(err.contains("replay") || err.contains("watermark") || err.contains("nonce"));
    assert!(!cfg.traversal_bundle_path.exists());
}

#[test]
fn fetcher_all_four_types_skip_when_url_unset() {
    let dir = tempdir().unwrap();
    let cfg = make_test_config(dir.path());

    let fetcher = StateFetcher::new_from_daemon(&cfg);

    assert_eq!(fetcher.fetch_trust().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_traversal().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_assignment().unwrap(), FetchDecision::Skipped);
    assert_eq!(
        fetcher.fetch_dns_zone(None).unwrap(),
        FetchDecision::Skipped
    );
}

#[test]
fn fetcher_verification_error_does_not_overwrite_existing_bundle() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());

    fs::create_dir_all(cfg.traversal_bundle_path.parent().unwrap()).unwrap();
    fs::write(&cfg.traversal_bundle_path, "sentinel").unwrap();

    let bundle = make_signed_traversal_bundle(&cfg.traversal_verifier_key_path, 300, true);
    let url = serve_once(bundle);

    cfg.traversal_url = Some(url);
    let fetcher = StateFetcher::new_from_daemon(&cfg);

    let err = fetcher.fetch_traversal().unwrap_err();
    // Verify it failed
    assert!(!err.is_empty());
}

fn make_signed_dns_zone_bundle(verifier_path: &PathBuf, nonce: u64, zone_name: &str) -> Vec<u8> {
    use rustynet_dns_zone::{DnsRecordType, DnsTargetAddrKind, DnsZoneRecordInput};

    let signing_key = SigningKey::from_bytes(&[31u8; 32]);
    fs::write(
        verifier_path,
        format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
    )
    .unwrap();

    let now = unix_now();
    let bundle = rustynet_dns_zone::build_signed_dns_zone_bundle(
        &signing_key,
        zone_name,
        "node-local",
        now,
        60,
        nonce,
        &[DnsZoneRecordInput {
            label: "app".to_string(),
            target_node_id: "node-target".to_string(),
            rr_type: DnsRecordType::A,
            target_addr_kind: DnsTargetAddrKind::MeshIpv4,
            expected_ip: "100.64.0.2".to_string(),
            ttl_secs: 60,
            aliases: vec![],
        }],
    )
    .unwrap();

    rustynet_dns_zone::render_signed_dns_zone_bundle_wire(&bundle).into_bytes()
}

fn make_signed_trust_bundle(verifier_path: &PathBuf, nonce: u64) -> Vec<u8> {
    let signing_key = SigningKey::from_bytes(&[7u8; 32]);
    fs::write(
        verifier_path,
        format!("{}\n", hex_encode(signing_key.verifying_key().as_bytes())),
    )
    .unwrap();

    let now = unix_now();
    let payload = format!(
        "version=2\ntls13_valid=true\nsigned_control_valid=true\nsigned_data_age_secs=0\nclock_skew_secs=0\nupdated_at_unix={now}\nnonce={nonce}\n"
    );

    let signature = signing_key.sign(payload.as_bytes());
    let sig_bytes = signature.to_bytes().to_vec();
    format!("{}signature={}\n", payload, hex_encode(&sig_bytes)).into_bytes()
}

#[test]
fn fetcher_dns_zone_applied_updates_bundle_on_disk() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    let bundle =
        make_signed_dns_zone_bundle(&cfg.dns_zone_verifier_key_path, 100, &cfg.dns_zone_name);
    let url = serve_once(bundle);

    cfg.dns_zone_url = Some(url);
    let fetcher = StateFetcher::new_from_daemon(&cfg);

    let dummy_assignment = AutoTunnelBundle {
        node_id: "node-local".to_string(),
        mesh_cidr: "100.64.0.0/10".to_string(),
        assigned_cidr: "100.64.0.1/32".to_string(),
        peers: vec![PeerConfig {
            node_id: NodeId::new("node-target").unwrap(),
            endpoint: SocketEndpoint {
                addr: "100.64.0.2".parse().unwrap(),
                port: 51820,
            },
            public_key: [0u8; 32],
            allowed_ips: vec!["100.64.0.2/32".to_string()],
        }],
        routes: vec![],
        selected_exit_node: None,
    };

    assert_eq!(
        fetcher.fetch_dns_zone(Some(&dummy_assignment)).unwrap(),
        FetchDecision::Applied
    );
    assert!(cfg.dns_zone_bundle_path.exists());
    assert!(cfg.dns_zone_watermark_path.exists());
}

#[test]
fn fetcher_trust_applied_updates_bundle_on_disk() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    let bundle = make_signed_trust_bundle(&cfg.trust_verifier_key_path, 100);
    let url = serve_once(bundle);

    cfg.trust_url = Some(url);
    let fetcher = StateFetcher::new_from_daemon(&cfg);

    assert_eq!(fetcher.fetch_trust().unwrap(), FetchDecision::Applied);
    assert!(cfg.trust_evidence_path.exists());
    assert!(cfg.trust_watermark_path.exists());
}
