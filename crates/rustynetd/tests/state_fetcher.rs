use rustynetd::daemon::{
    DaemonBackendMode, DaemonConfig, DaemonDataplaneMode, FetchDecision, NodeRole, StateFetcher,
};
use std::fs;
use tempfile::tempdir;

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
fn fetcher_all_four_types_skip_when_remote_urls_are_configured() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    cfg.trust_url = Some("http://127.0.0.1:1/trust".to_string());
    cfg.traversal_url = Some("http://127.0.0.1:1/traversal".to_string());
    cfg.assignment_url = Some("http://127.0.0.1:1/assignment".to_string());
    cfg.dns_zone_url = Some("http://127.0.0.1:1/dns".to_string());

    let fetcher = StateFetcher::new_from_daemon(&cfg);

    assert_eq!(fetcher.fetch_trust().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_traversal().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_assignment().unwrap(), FetchDecision::Skipped);
    assert_eq!(
        fetcher.fetch_dns_zone(None).unwrap(),
        FetchDecision::Skipped
    );
    assert!(!cfg.trust_evidence_path.exists());
    assert!(!cfg.trust_watermark_path.exists());
    assert!(!cfg.traversal_bundle_path.exists());
    assert!(!cfg.traversal_watermark_path.exists());
    assert!(!cfg.dns_zone_bundle_path.exists());
    assert!(!cfg.dns_zone_watermark_path.exists());
    assert!(!cfg.auto_tunnel_bundle_path.as_ref().unwrap().exists());
    assert!(!cfg.auto_tunnel_watermark_path.as_ref().unwrap().exists());
}

#[test]
fn fetcher_skip_does_not_overwrite_existing_local_artifacts() {
    let dir = tempdir().unwrap();
    let mut cfg = make_test_config(dir.path());
    cfg.trust_url = Some("http://127.0.0.1:1/trust".to_string());
    cfg.traversal_url = Some("http://127.0.0.1:1/traversal".to_string());
    cfg.assignment_url = Some("http://127.0.0.1:1/assignment".to_string());
    cfg.dns_zone_url = Some("http://127.0.0.1:1/dns".to_string());

    fs::write(&cfg.trust_evidence_path, "trust-sentinel").unwrap();
    fs::write(&cfg.traversal_bundle_path, "traversal-sentinel").unwrap();
    fs::write(&cfg.dns_zone_bundle_path, "dns-sentinel").unwrap();
    fs::write(
        cfg.auto_tunnel_bundle_path.as_ref().unwrap(),
        "assignment-sentinel",
    )
    .unwrap();

    let fetcher = StateFetcher::new_from_daemon(&cfg);

    assert_eq!(fetcher.fetch_trust().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_traversal().unwrap(), FetchDecision::Skipped);
    assert_eq!(fetcher.fetch_assignment().unwrap(), FetchDecision::Skipped);
    assert_eq!(
        fetcher.fetch_dns_zone(None).unwrap(),
        FetchDecision::Skipped
    );
    assert_eq!(
        fs::read_to_string(&cfg.trust_evidence_path).unwrap(),
        "trust-sentinel"
    );
    assert_eq!(
        fs::read_to_string(&cfg.traversal_bundle_path).unwrap(),
        "traversal-sentinel"
    );
    assert_eq!(
        fs::read_to_string(&cfg.dns_zone_bundle_path).unwrap(),
        "dns-sentinel"
    );
    assert_eq!(
        fs::read_to_string(cfg.auto_tunnel_bundle_path.as_ref().unwrap()).unwrap(),
        "assignment-sentinel"
    );
    assert!(!cfg.trust_watermark_path.exists());
    assert!(!cfg.traversal_watermark_path.exists());
    assert!(!cfg.dns_zone_watermark_path.exists());
    assert!(!cfg.auto_tunnel_watermark_path.as_ref().unwrap().exists());
}
