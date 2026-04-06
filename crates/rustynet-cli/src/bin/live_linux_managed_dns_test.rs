#![forbid(unsafe_code)]

mod live_lab_support;

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::thread::sleep;
use std::time::{SystemTime, UNIX_EPOCH};

use live_lab_support::{
    LiveLabContext, Logger, repo_root, shell_single_quote, write_secure_json, write_secure_text,
};
use serde_json::json;

const MANAGED_LABEL: &str = "exit";
const MANAGED_ALIAS: &str = "gateway";
const ISSUE_DIR: &str = "/run/rustynet/dns-zone-issue";
const TRAVERSAL_ISSUE_DIR: &str = "/run/rustynet/traversal-issue";
const DNS_ZONE_PUB_REMOTE: &str = "/run/rustynet/dns-zone-issue/rn-dns-zone.pub";
const DNS_VALID_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/valid.dns-zone";
const DNS_STALE_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/stale.dns-zone";
const DNS_REPLAY_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue/replay.dns-zone";
const DNS_POLICY_INVALID_BUNDLE_REMOTE: &str =
    "/run/rustynet/dns-zone-issue/policy-invalid.dns-zone";
const DNS_RECORDS_REMOTE: &str = "/tmp/rn-dns-records.manifest";
const TRAVERSAL_ENV_REMOTE: &str = "/tmp/rn_issue_dns_traversal.env";
const TRAVERSAL_PUB_REMOTE: &str = "/run/rustynet/traversal-issue/rn-traversal.pub";
const REPLAY_PROBE_ALIAS: &str = "gatewayreplay";
const SOAK_SSH_RETRY_ATTEMPTS: u32 = 10;
const SOAK_SSH_RETRY_SLEEP_SECS: u64 = 3;

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(err) => {
            eprintln!("{err}");
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), String> {
    let root_dir = repo_root()?;
    let config = Config::parse(env::args().skip(1).collect())?;

    for command in ["cargo", "git", "ssh", "scp", "ssh-keygen", "date"] {
        require_command(command)?;
    }

    let ssh_identity = PathBuf::from(&config.ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-managed-dns", ssh_identity.as_path())?;
    let logger = Logger::new(&config.log_path)?;

    validate_targets(&config)?;

    logger.line("[managed-dns] starting live managed DNS validation")?;
    for host in [&config.signer_host, &config.client_host] {
        ctx.push_sudo_password(host)?;
    }
    refresh_signer_trust_evidence(&ctx, &config.signer_host)?;

    logger.line("[managed-dns] collecting WireGuard public keys")?;
    let client_status_before = ctx.capture_root(
        &config.client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "status",
        ],
    )?;
    let current_exit_node = parse_status_field(&client_status_before, "exit_node")
        .ok_or_else(|| "unable to parse exit_node from client rustynet status".to_string())?;
    logger.line(
        format!(
            "[managed-dns] client runtime exit selection before bundle refresh: exit_node={current_exit_node}"
        )
        .as_str(),
    )?;

    let mut host_by_node = HashMap::new();
    host_by_node.insert(config.signer_node_id.clone(), config.signer_host.clone());
    host_by_node.insert(config.client_node_id.clone(), config.client_host.clone());
    for peer in &config.managed_peers {
        host_by_node.insert(peer.node_id.clone(), peer.host.clone());
    }

    if current_exit_node != "none"
        && current_exit_node != config.signer_node_id
        && current_exit_node != config.client_node_id
        && !host_by_node.contains_key(&current_exit_node)
    {
        return Err(format!(
            "client exit_node {current_exit_node} is not mapped to a host; provide --managed-peer {current_exit_node}|<user@host>"
        ));
    }
    let assignment_scopes = capture_assignment_authority_scopes(&ctx, &host_by_node)?;

    let mut mesh_peers = Vec::new();
    for (node_id, host) in sorted_node_host_pairs(&host_by_node) {
        mesh_peers.push(ManagedPeerRuntime {
            node_id,
            address: LiveLabContext::resolved_target_address(&host)?,
            pubkey_hex: ctx.collect_pubkey_hex(&host)?,
        });
    }

    let nodes_spec = mesh_peers
        .iter()
        .map(|peer| {
            format!(
                "{}|{}:51820|{}",
                peer.node_id, peer.address, peer.pubkey_hex
            )
        })
        .collect::<Vec<_>>()
        .join(";");
    let allow_spec = build_authorized_allow_spec(&assignment_scopes, &host_by_node)?;
    ensure_safe_spec("NODES_SPEC", &nodes_spec)?;
    ensure_safe_spec("ALLOW_SPEC", &allow_spec)?;

    let workspace = ctx.work_dir.clone();
    let base_records = managed_dns_base_records(&config.signer_node_id, &config.client_node_id);
    let records_manifest = workspace.join("rn-dns-records.manifest");
    let client_scope = assignment_scopes
        .get(&config.client_node_id)
        .ok_or_else(|| {
            format!(
                "missing assignment authority scope for client node {}",
                config.client_node_id
            )
        })?;
    write_secure_text(
        &records_manifest,
        &managed_dns_records_manifest_for_scope(&base_records, client_scope)?,
    )?;

    let issue_dir = ISSUE_DIR;
    let valid_generated_at = unix_now();
    let valid_nonce = valid_generated_at.saturating_mul(2).saturating_add(17);
    let stale_generated_at = valid_generated_at.saturating_sub(7200);
    let stale_nonce = valid_nonce.saturating_sub(1);
    let replay_records = managed_dns_replay_records(&base_records, &config.signer_node_id)?;
    let replay_records_manifest = workspace.join("rn-dns-records-replay.manifest");
    write_secure_text(
        &replay_records_manifest,
        &managed_dns_records_manifest_for_scope(&replay_records, client_scope)?,
    )?;
    let policy_invalid_scope = assignment_scopes
        .get(&config.signer_node_id)
        .ok_or_else(|| {
            format!(
                "missing assignment authority scope for signer node {}",
                config.signer_node_id
            )
        })?;
    let policy_invalid_records_manifest = workspace.join("rn-dns-records-policy-invalid.manifest");
    write_secure_text(
        &policy_invalid_records_manifest,
        &managed_dns_records_manifest_for_scope(&base_records, policy_invalid_scope)?,
    )?;
    let passphrase_file = ctx
        .capture_root(
            &config.signer_host,
            &["mktemp", "/tmp/rn-dns-zone-passphrase.XXXXXX"],
        )?
        .trim()
        .to_string();
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "ops",
            "materialize-signing-passphrase",
            "--output",
            &passphrase_file,
        ],
    )?;
    ctx.run_root(&config.signer_host, &["chmod", "0600", &passphrase_file])?;
    ctx.run_root(&config.signer_host, &["rm", "-rf", issue_dir])?;
    ctx.run_root(
        &config.signer_host,
        &["install", "-d", "-m", "0700", issue_dir],
    )?;
    ctx.scp_to(&records_manifest, &config.signer_host, DNS_RECORDS_REMOTE)?;
    let replay_records_remote = "/tmp/rn-dns-records-replay.manifest";
    ctx.scp_to(
        &replay_records_manifest,
        &config.signer_host,
        replay_records_remote,
    )?;
    let policy_invalid_records_remote = "/tmp/rn-dns-records-policy-invalid.manifest";
    ctx.scp_to(
        &policy_invalid_records_manifest,
        &config.signer_host,
        policy_invalid_records_remote,
    )?;

    logger.line(
        format!(
            "[managed-dns] issuing signed DNS bundles on {}",
            config.signer_host
        )
        .as_str(),
    )?;
    issue_dns_bundle(
        &ctx,
        &config.signer_host,
        &passphrase_file,
        &config.client_node_id,
        &config.zone_name,
        &nodes_spec,
        &allow_spec,
        DNS_RECORDS_REMOTE,
        issue_dir,
        "valid.dns-zone",
        Some(valid_generated_at),
        Some(valid_nonce),
    )?;
    issue_dns_bundle(
        &ctx,
        &config.signer_host,
        &passphrase_file,
        &config.client_node_id,
        &config.zone_name,
        &nodes_spec,
        &allow_spec,
        DNS_RECORDS_REMOTE,
        issue_dir,
        "stale.dns-zone",
        Some(stale_generated_at),
        Some(stale_nonce),
    )?;
    issue_dns_bundle(
        &ctx,
        &config.signer_host,
        &passphrase_file,
        &config.client_node_id,
        &config.zone_name,
        &nodes_spec,
        &allow_spec,
        replay_records_remote,
        issue_dir,
        "replay.dns-zone",
        Some(valid_generated_at),
        Some(valid_nonce),
    )?;
    issue_dns_bundle(
        &ctx,
        &config.signer_host,
        &passphrase_file,
        &config.signer_node_id,
        &config.zone_name,
        &nodes_spec,
        &allow_spec,
        policy_invalid_records_remote,
        issue_dir,
        "policy-invalid.dns-zone",
        Some(valid_generated_at.saturating_add(1)),
        Some(valid_nonce.saturating_add(1)),
    )?;

    let verifier_local = workspace.join("dns-zone.pub");
    let valid_bundle_local = workspace.join("dns-zone-valid.bundle");
    let stale_bundle_local = workspace.join("dns-zone-stale.bundle");
    let replay_bundle_local = workspace.join("dns-zone-replay.bundle");
    let policy_invalid_bundle_local = workspace.join("dns-zone-policy-invalid.bundle");
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_ZONE_PUB_REMOTE,
        &verifier_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_VALID_BUNDLE_REMOTE,
        &valid_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_STALE_BUNDLE_REMOTE,
        &stale_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_REPLAY_BUNDLE_REMOTE,
        &replay_bundle_local,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        DNS_POLICY_INVALID_BUNDLE_REMOTE,
        &policy_invalid_bundle_local,
    )?;
    let valid_bundle_wire = std::fs::read_to_string(&valid_bundle_local).map_err(|err| {
        format!(
            "failed to read valid dns bundle {}: {err}",
            valid_bundle_local.display()
        )
    })?;
    let forged_bundle_local = workspace.join("dns-zone-forged.bundle");
    write_secure_text(
        &forged_bundle_local,
        &rewrite_bundle_signature(&valid_bundle_wire, "0")?,
    )?;
    let tampered_bundle_local = workspace.join("dns-zone-tampered.bundle");
    write_secure_text(
        &tampered_bundle_local,
        &rewrite_bundle_line_value(&valid_bundle_wire, "record.0.fqdn", "tampered.rustynet")?,
    )?;

    logger.line("[managed-dns] verifying signed managed DNS bundles on signer host")?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_VALID_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_REPLAY_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_POLICY_INVALID_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.signer_node_id,
        ],
    )?;
    ctx.run_root(
        &config.signer_host,
        &[
            "rustynet",
            "dns",
            "zone",
            "verify",
            "--bundle",
            DNS_STALE_BUNDLE_REMOTE,
            "--verifier-key",
            DNS_ZONE_PUB_REMOTE,
            "--expected-zone-name",
            &config.zone_name,
            "--expected-subject-node-id",
            &config.client_node_id,
        ],
    )?;

    logger.line(
        format!(
            "[managed-dns] installing valid managed DNS bundle on {}",
            config.client_host
        )
        .as_str(),
    )?;
    install_dns_bundle(
        &ctx,
        &config.client_host,
        &verifier_local,
        &valid_bundle_local,
    )?;
    refresh_traversal_bundles(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
    )?;
    restart_managed_dns_stack(&ctx, &config.client_host)?;

    let dns_inspect_valid =
        wait_for_dns_inspect_state(&ctx, &config.client_host, Some("valid"), 20, 2)?;
    let resolvectl_status_valid = ctx.capture_root_allow_failure(
        &config.client_host,
        &["resolvectl", "status", &config.dns_interface],
    )?;
    let direct_query_valid =
        remote_dns_query_capture(&ctx, &config.client_host, &config, &config.managed_fqdn())?;
    let direct_alias_query_valid = remote_dns_query_capture(
        &ctx,
        &config.client_host,
        &config,
        &config.managed_alias_fqdn(),
    )?;
    let non_managed_direct_query =
        remote_dns_query_capture(&ctx, &config.client_host, &config, "example.com")?;
    let _ = ctx.run_root_allow_failure(&config.client_host, &["resolvectl", "flush-caches"])?;
    let managed_fqdn = config.managed_fqdn();
    let resolvectl_query_cmd = format!(
        "if command -v timeout >/dev/null 2>&1; then timeout 15 resolvectl query --legend=no {fqdn}; else resolvectl query --legend=no {fqdn}; fi",
        fqdn = shell_single_quote(managed_fqdn.as_str())
    );
    let resolvectl_query_valid = ctx.capture_root_allow_failure(
        &config.client_host,
        &["sh", "-lc", resolvectl_query_cmd.as_str()],
    )?;

    let expected_ip =
        extract_managed_dns_expected_ip(&root_dir, &config.managed_fqdn(), &dns_inspect_valid)?;

    logger.block("[managed-dns] valid dns inspect", &dns_inspect_valid)?;
    logger.block(
        "[managed-dns] valid resolvectl status",
        &resolvectl_status_valid,
    )?;
    logger.block(
        "[managed-dns] valid loopback DNS query",
        &direct_query_valid,
    )?;
    logger.block(
        "[managed-dns] valid resolvectl query",
        &resolvectl_query_valid,
    )?;

    let stale_case = exercise_invalid_bundle_case(
        &ctx,
        &logger,
        &root_dir,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &stale_bundle_local,
        true,
        "stale",
        &["stale"],
    )?;

    restore_valid_bundle_after_invalid_case(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &valid_bundle_local,
    )?;

    let replay_case = exercise_invalid_bundle_case(
        &ctx,
        &logger,
        &root_dir,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &replay_bundle_local,
        false,
        "replay",
        &["replay detected"],
    )?;
    restore_valid_bundle_after_invalid_case(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &valid_bundle_local,
    )?;

    let forged_case = exercise_invalid_bundle_case(
        &ctx,
        &logger,
        &root_dir,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &forged_bundle_local,
        true,
        "forged",
        &["signature verification failed"],
    )?;
    restore_valid_bundle_after_invalid_case(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &valid_bundle_local,
    )?;

    let tampered_case = exercise_invalid_bundle_case(
        &ctx,
        &logger,
        &root_dir,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &tampered_bundle_local,
        true,
        "tampered",
        &["invalid format"],
    )?;
    restore_valid_bundle_after_invalid_case(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &valid_bundle_local,
    )?;

    let policy_invalid_case = exercise_invalid_bundle_case(
        &ctx,
        &logger,
        &root_dir,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &policy_invalid_bundle_local,
        true,
        "policy-invalid",
        &["subject node id does not match local node"],
    )?;

    // Re-issue a fresh valid client bundle after the adversarial sequence.
    // The original valid bundle can age out during long soak runs.
    issue_dns_bundle(
        &ctx,
        &config.signer_host,
        &passphrase_file,
        &config.client_node_id,
        &config.zone_name,
        &nodes_spec,
        &allow_spec,
        DNS_RECORDS_REMOTE,
        issue_dir,
        "valid-refresh.dns-zone",
        None,
        None,
    )?;
    capture_remote_text(
        &ctx,
        &config.signer_host,
        &format!("{issue_dir}/valid-refresh.dns-zone"),
        &valid_bundle_local,
    )?;
    restore_valid_bundle_after_invalid_case(
        &ctx,
        &config,
        &workspace,
        &host_by_node,
        &nodes_spec,
        &allow_spec,
        &verifier_local,
        &valid_bundle_local,
    )?;
    let dns_inspect_restored =
        wait_for_dns_inspect_state(&ctx, &config.client_host, Some("valid"), 20, 2)?;

    for (node_id, host) in managed_dns_distribution_targets(&host_by_node, &config.client_host) {
        logger.line(
            format!(
                "[managed-dns] issuing valid managed DNS bundle for {node_id} on {}",
                config.signer_host
            )
            .as_str(),
        )?;
        let scope = assignment_scopes.get(&node_id).ok_or_else(|| {
            format!("missing assignment authority scope for managed DNS node {node_id}")
        })?;
        let peer_records_local = workspace.join(format!("rn-dns-records-{node_id}.manifest"));
        let peer_records_remote = format!("/tmp/rn-dns-records-{node_id}.manifest");
        write_secure_text(
            &peer_records_local,
            &managed_dns_records_manifest_for_scope(&base_records, scope)?,
        )?;
        ctx.scp_to(
            &peer_records_local,
            &config.signer_host,
            peer_records_remote.as_str(),
        )?;

        let output_name = format!("valid-{node_id}.dns-zone");
        issue_dns_bundle(
            &ctx,
            &config.signer_host,
            &passphrase_file,
            &node_id,
            &config.zone_name,
            &nodes_spec,
            &allow_spec,
            peer_records_remote.as_str(),
            issue_dir,
            output_name.as_str(),
            None,
            None,
        )?;
        let _ = ctx.run_root_allow_failure(
            &config.signer_host,
            &["rm", "-f", peer_records_remote.as_str()],
        );
        let peer_bundle_local = workspace.join(format!("dns-zone-valid-{node_id}.bundle"));
        let remote_bundle_path = format!("{issue_dir}/{output_name}");
        capture_remote_text(
            &ctx,
            &config.signer_host,
            remote_bundle_path.as_str(),
            &peer_bundle_local,
        )?;
        logger.line(
            format!("[managed-dns] propagating valid managed DNS bundle to {host}").as_str(),
        )?;
        install_dns_bundle(&ctx, &host, &verifier_local, &peer_bundle_local)?;
        if host == config.client_host {
            continue;
        }
        if host == config.signer_host {
            refresh_signer_trust_evidence(&ctx, &host)?;
        }
        restart_managed_dns_stack(&ctx, &host)?;
    }

    let check_zone_issue_verify = "pass";
    let mut check_dns_inspect_valid = "fail";
    let mut check_managed_dns_service_active = "fail";
    let mut check_resolvectl_split_dns = "fail";
    let mut check_loopback_query_valid = "fail";
    let mut check_resolvectl_query_valid = "fail";
    let mut check_alias_query_valid = "fail";
    let mut check_non_managed_refused = "fail";
    let mut check_stale_bundle_fail_closed = "fail";
    let mut check_replayed_bundle_fail_closed = "fail";
    let mut check_forged_bundle_fail_closed = "fail";
    let mut check_tampered_bundle_fail_closed = "fail";
    let mut check_policy_invalid_bundle_fail_closed = "fail";
    let mut check_valid_bundle_restored = "fail";

    if dns_inspect_valid.contains("dns inspect: state=valid")
        && dns_inspect_valid.contains(&format!("zone_name={}", config.zone_name))
    {
        check_dns_inspect_valid = "pass";
    }
    let managed_service_active = ctx.capture_root_allow_failure(
        &config.client_host,
        &["systemctl", "is-active", "rustynetd-managed-dns.service"],
    )?;
    if managed_service_active.trim() == "active" {
        check_managed_dns_service_active = "pass";
    }
    if resolvectl_status_valid.contains(&config.dns_bind_addr)
        && (resolvectl_status_valid.contains(&format!("~{}", config.zone_name))
            || resolvectl_status_valid.contains(&format!("DNS Domain: {}", config.zone_name)))
    {
        check_resolvectl_split_dns = "pass";
    }
    if json_field(&root_dir, &direct_query_valid, "rcode")? == "0"
        && json_field(&root_dir, &direct_query_valid, "answer_ip")? == expected_ip
    {
        check_loopback_query_valid = "pass";
    }
    if json_field(&root_dir, &direct_alias_query_valid, "rcode")? == "0"
        && json_field(&root_dir, &direct_alias_query_valid, "answer_ip")? == expected_ip
    {
        check_alias_query_valid = "pass";
    }
    if resolvectl_query_valid.contains(&expected_ip) {
        check_resolvectl_query_valid = "pass";
    }
    if json_field(&root_dir, &non_managed_direct_query, "rcode")? == "5" {
        check_non_managed_refused = "pass";
    }

    if stale_case.passed {
        check_stale_bundle_fail_closed = "pass";
    }
    if replay_case.passed {
        check_replayed_bundle_fail_closed = "pass";
    }
    if forged_case.passed {
        check_forged_bundle_fail_closed = "pass";
    }
    if tampered_case.passed {
        check_tampered_bundle_fail_closed = "pass";
    }
    if policy_invalid_case.passed {
        check_policy_invalid_bundle_fail_closed = "pass";
    }
    if dns_inspect_restored.contains("dns inspect: state=valid") {
        check_valid_bundle_restored = "pass";
    }

    let overall = [
        check_zone_issue_verify,
        check_dns_inspect_valid,
        check_managed_dns_service_active,
        check_resolvectl_split_dns,
        check_loopback_query_valid,
        check_resolvectl_query_valid,
        check_alias_query_valid,
        check_non_managed_refused,
        check_stale_bundle_fail_closed,
        check_replayed_bundle_fail_closed,
        check_forged_bundle_fail_closed,
        check_tampered_bundle_fail_closed,
        check_policy_invalid_bundle_fail_closed,
        check_valid_bundle_restored,
    ]
    .into_iter()
    .all(|value| value == "pass");

    let captured_at_utc = utc_now_string();
    let captured_at_unix = unix_now();
    let git_commit = git_commit(&root_dir);

    let report = json!({
        "phase": "phase10",
        "mode": "live_linux_managed_dns",
        "evidence_mode": "measured",
        "captured_at": captured_at_utc,
        "captured_at_unix": captured_at_unix,
        "git_commit": git_commit,
        "status": if overall { "pass" } else { "fail" },
        "zone_name": config.zone_name,
        "signer_host": config.signer_host,
        "client_host": config.client_host,
        "managed_fqdn": config.managed_fqdn(),
        "managed_alias_fqdn": config.managed_alias_fqdn(),
        "expected_ip": expected_ip,
        "checks": {
            "zone_issue_verify_passes": check_zone_issue_verify,
            "dns_inspect_valid": check_dns_inspect_valid,
            "managed_dns_service_active": check_managed_dns_service_active,
            "resolvectl_split_dns_configured": check_resolvectl_split_dns,
            "loopback_resolver_answers_managed_name": check_loopback_query_valid,
            "systemd_resolved_answers_managed_name": check_resolvectl_query_valid,
            "alias_resolves_to_expected_ip": check_alias_query_valid,
            "non_managed_query_refused": check_non_managed_refused,
            "stale_bundle_fail_closed": check_stale_bundle_fail_closed,
            "replayed_bundle_fail_closed": check_replayed_bundle_fail_closed,
            "forged_bundle_fail_closed": check_forged_bundle_fail_closed,
            "tampered_bundle_fail_closed": check_tampered_bundle_fail_closed,
            "policy_invalid_bundle_fail_closed": check_policy_invalid_bundle_fail_closed,
            "valid_bundle_restored": check_valid_bundle_restored,
        },
        "source_artifacts": [
            config.log_path.display().to_string(),
        ],
    });
    write_secure_json(&config.report_path, &report)?;

    logger.line(
        format!(
            "[managed-dns] report written: {}",
            config.report_path.display()
        )
        .as_str(),
    )?;

    let _ = ctx.run_root_allow_failure(
        &config.signer_host,
        &[
            "rm",
            "-f",
            DNS_RECORDS_REMOTE,
            replay_records_remote,
            policy_invalid_records_remote,
            &passphrase_file,
        ],
    );
    let _ = ctx.run_root_allow_failure(
        &config.signer_host,
        &["rm", "-rf", issue_dir, TRAVERSAL_ISSUE_DIR],
    );
    Ok(())
}

#[derive(Debug, Clone)]
struct Config {
    ssh_identity_file: String,
    signer_host: String,
    client_host: String,
    signer_node_id: String,
    client_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    log_path: PathBuf,
    zone_name: String,
    dns_interface: String,
    dns_bind_addr: String,
    managed_peers: Vec<ManagedPeerSpec>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            ssh_identity_file: String::new(),
            signer_host: "debian@192.168.18.49".to_string(),
            client_host: "ubuntu@192.168.18.52".to_string(),
            signer_node_id: "exit-49".to_string(),
            client_node_id: "client-52".to_string(),
            ssh_allow_cidrs: "192.168.18.0/24".to_string(),
            report_path: PathBuf::from("artifacts/phase10/source/managed_dns_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/managed_dns_report.log"),
            zone_name: "rustynet".to_string(),
            dns_interface: "rustynet0".to_string(),
            dns_bind_addr: "127.0.0.1:53535".to_string(),
            managed_peers: Vec::new(),
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--ssh-identity-file" => config.ssh_identity_file = next_value(&mut iter, &arg)?,
                "--signer-host" => config.signer_host = next_value(&mut iter, &arg)?,
                "--client-host" => config.client_host = next_value(&mut iter, &arg)?,
                "--signer-node-id" => config.signer_node_id = next_value(&mut iter, &arg)?,
                "--client-node-id" => config.client_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--zone-name" => config.zone_name = next_value(&mut iter, &arg)?,
                "--dns-interface" => config.dns_interface = next_value(&mut iter, &arg)?,
                "--dns-bind-addr" => config.dns_bind_addr = next_value(&mut iter, &arg)?,
                "--managed-peer" => {
                    let value = next_value(&mut iter, &arg)?;
                    config.managed_peers.push(parse_managed_peer_spec(&value)?);
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.is_empty() {
            return Err(
                "usage: live_linux_managed_dns_test --ssh-identity-file <path> [options]"
                    .to_string(),
            );
        }
        Ok(config)
    }

    fn managed_fqdn(&self) -> String {
        format!("{MANAGED_LABEL}.{}", self.zone_name)
    }

    fn managed_alias_fqdn(&self) -> String {
        format!("{MANAGED_ALIAS}.{}", self.zone_name)
    }

    fn dns_server(&self) -> String {
        self.dns_bind_addr
            .split_once(':')
            .map(|(server, _)| server.to_string())
            .unwrap_or_else(|| self.dns_bind_addr.clone())
    }

    fn dns_port(&self) -> String {
        self.dns_bind_addr
            .split_once(':')
            .map(|(_, port)| port.to_string())
            .unwrap_or_else(|| "53535".to_string())
    }
}

fn validate_targets(config: &Config) -> Result<(), String> {
    for (label, value) in [
        ("signer-host", config.signer_host.as_str()),
        ("client-host", config.client_host.as_str()),
        ("signer-node-id", config.signer_node_id.as_str()),
        ("client-node-id", config.client_node_id.as_str()),
        ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ("zone-name", config.zone_name.as_str()),
        ("dns-interface", config.dns_interface.as_str()),
        ("dns-bind-addr", config.dns_bind_addr.as_str()),
    ] {
        ensure_safe_token(label, value)?;
    }
    let mut seen_node_ids = HashSet::new();
    let mut seen_hosts = HashSet::new();
    for (label, value) in [
        ("signer-node-id", config.signer_node_id.as_str()),
        ("client-node-id", config.client_node_id.as_str()),
    ] {
        if !seen_node_ids.insert(value.to_string()) {
            return Err(format!("{label} is duplicated: {value}"));
        }
    }
    for (label, value) in [
        ("signer-host", config.signer_host.as_str()),
        ("client-host", config.client_host.as_str()),
    ] {
        if !seen_hosts.insert(value.to_string()) {
            return Err(format!("{label} is duplicated: {value}"));
        }
    }
    for peer in &config.managed_peers {
        ensure_safe_token("--managed-peer node-id", peer.node_id.as_str())?;
        ensure_safe_token("--managed-peer host", peer.host.as_str())?;
        if !seen_node_ids.insert(peer.node_id.clone()) {
            return Err(format!(
                "--managed-peer node-id duplicates an existing node id: {}",
                peer.node_id
            ));
        }
        if !seen_hosts.insert(peer.host.clone()) {
            return Err(format!(
                "--managed-peer host duplicates an existing host: {}",
                peer.host
            ));
        }
    }
    let _ = config
        .dns_bind_addr
        .split_once(':')
        .ok_or_else(|| "dns-bind-addr must be <ip:port>".to_string())?
        .1
        .parse::<u16>()
        .map_err(|err| format!("invalid dns-bind-addr port: {err}"))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn issue_dns_bundle(
    ctx: &LiveLabContext,
    signer_host: &str,
    passphrase_file: &str,
    subject_node_id: &str,
    zone_name: &str,
    nodes_spec: &str,
    allow_spec: &str,
    records_manifest_remote: &str,
    issue_dir: &str,
    output_name: &str,
    generated_at: Option<u64>,
    nonce: Option<u64>,
) -> Result<(), String> {
    let output_path = format!("{issue_dir}/{output_name}");
    let verifier_key_output = format!("{issue_dir}/rn-dns-zone.pub");
    let generated_at_string = generated_at.map(|value| value.to_string());
    let nonce_string = nonce.map(|value| value.to_string());
    let mut args = vec![
        "rustynet",
        "dns",
        "zone",
        "issue",
        "--signing-secret",
        "/etc/rustynet/membership.owner.key",
        "--signing-secret-passphrase-file",
        passphrase_file,
        "--subject-node-id",
        subject_node_id,
        "--nodes",
        nodes_spec,
        "--allow",
        allow_spec,
        "--records-manifest",
        records_manifest_remote,
        "--output",
        output_path.as_str(),
        "--verifier-key-output",
        verifier_key_output.as_str(),
        "--zone-name",
        zone_name,
        "--ttl-secs",
        "300",
    ];
    if generated_at.is_some() {
        args.push("--generated-at");
        if let Some(generated_at_string) = generated_at_string.as_ref() {
            args.push(generated_at_string.as_str());
        }
    }
    if nonce.is_some() {
        args.push("--nonce");
        if let Some(nonce_string) = nonce_string.as_ref() {
            args.push(nonce_string.as_str());
        }
    }
    ctx.run_root(signer_host, &args)?;
    Ok(())
}

fn install_dns_bundle(
    ctx: &LiveLabContext,
    client_host: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    install_dns_bundle_with_options(ctx, client_host, verifier_local, bundle_local, true)
}

fn install_dns_bundle_with_options(
    ctx: &LiveLabContext,
    client_host: &str,
    verifier_local: &Path,
    bundle_local: &Path,
    clear_watermark: bool,
) -> Result<(), String> {
    retry_remote_step(
        &format!("install managed DNS bundle on {client_host}"),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            ctx.scp_to(verifier_local, client_host, "/tmp/rn-dns-zone.pub")?;
            ctx.scp_to(bundle_local, client_host, "/tmp/rn-dns-zone.bundle")?;
            ctx.run_root(
                client_host,
                &[
                    "install",
                    "-m",
                    "0644",
                    "-o",
                    "root",
                    "-g",
                    "root",
                    "/tmp/rn-dns-zone.pub",
                    "/etc/rustynet/dns-zone.pub",
                ],
            )?;
            ctx.run_root(
                client_host,
                &[
                    "install",
                    "-m",
                    "0640",
                    "-o",
                    "root",
                    "-g",
                    "rustynetd",
                    "/tmp/rn-dns-zone.bundle",
                    "/var/lib/rustynet/rustynetd.dns-zone",
                ],
            )?;
            ctx.run_root(
                client_host,
                if clear_watermark {
                    &[
                        "rm",
                        "-f",
                        "/var/lib/rustynet/rustynetd.dns-zone.watermark",
                        "/tmp/rn-dns-zone.pub",
                        "/tmp/rn-dns-zone.bundle",
                    ]
                } else {
                    &[
                        "rm",
                        "-f",
                        "/tmp/rn-dns-zone.pub",
                        "/tmp/rn-dns-zone.bundle",
                    ]
                },
            )?;
            Ok(())
        },
    )
}

fn refresh_traversal_bundles(
    ctx: &LiveLabContext,
    config: &Config,
    workspace: &Path,
    host_by_node: &HashMap<String, String>,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<(), String> {
    retry_remote_step(
        &format!("refresh traversal bundles from {}", config.signer_host),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            let traversal_env = workspace.join("rn_issue_dns_traversal.env");
            write_env_file(
                &traversal_env,
                &[("NODES_SPEC", nodes_spec), ("ALLOW_SPEC", allow_spec)],
            )?;
            let remote_env_path = TRAVERSAL_ENV_REMOTE;
            ctx.scp_to(&traversal_env, &config.signer_host, remote_env_path)?;
            ctx.run_root(
                &config.signer_host,
                &[
                    "rustynet",
                    "ops",
                    "e2e-issue-traversal-bundles-from-env",
                    "--env-file",
                    remote_env_path,
                ],
            )?;
            ctx.run_root_allow_failure(&config.signer_host, &["rm", "-f", remote_env_path])?;

            let traversal_pub_local = workspace.join("traversal.pub");
            capture_remote_text(
                ctx,
                &config.signer_host,
                TRAVERSAL_PUB_REMOTE,
                &traversal_pub_local,
            )?;
            for (node_id, host) in sorted_node_host_pairs(host_by_node) {
                let traversal_remote = traversal_bundle_remote_path(node_id.as_str());
                let traversal_local = workspace.join(format!("traversal-{node_id}.bundle"));
                capture_remote_text(
                    ctx,
                    &config.signer_host,
                    traversal_remote.as_str(),
                    &traversal_local,
                )?;
                install_traversal_bundle(ctx, &host, &traversal_pub_local, &traversal_local)?;
            }
            ctx.run_root_allow_failure(&config.signer_host, &["rm", "-rf", TRAVERSAL_ISSUE_DIR])?;
            Ok(())
        },
    )
}

fn sorted_node_host_pairs(host_by_node: &HashMap<String, String>) -> Vec<(String, String)> {
    let mut entries = host_by_node
        .iter()
        .map(|(node_id, host)| (node_id.clone(), host.clone()))
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0).then(left.1.cmp(&right.1)));
    entries
}

fn managed_dns_distribution_targets(
    host_by_node: &HashMap<String, String>,
    client_host: &str,
) -> Vec<(String, String)> {
    sorted_node_host_pairs(host_by_node)
        .into_iter()
        .filter(|(_, host)| host != client_host)
        .collect()
}

fn traversal_bundle_remote_path(node_id: &str) -> String {
    format!("/run/rustynet/traversal-issue/rn-traversal-{node_id}.traversal")
}

fn install_traversal_bundle(
    ctx: &LiveLabContext,
    host: &str,
    traversal_pub_local: &Path,
    traversal_bundle_local: &Path,
) -> Result<(), String> {
    ctx.scp_to(traversal_pub_local, host, "/tmp/rn-traversal.pub")?;
    ctx.scp_to(traversal_bundle_local, host, "/tmp/rn-traversal.bundle")?;
    ctx.run_root(
        host,
        &[
            "install",
            "-m",
            "0644",
            "-o",
            "root",
            "-g",
            "root",
            "/tmp/rn-traversal.pub",
            "/etc/rustynet/traversal.pub",
        ],
    )?;
    ctx.run_root(
        host,
        &[
            "install",
            "-m",
            "0640",
            "-o",
            "root",
            "-g",
            "rustynetd",
            "/tmp/rn-traversal.bundle",
            "/var/lib/rustynet/rustynetd.traversal",
        ],
    )?;
    ctx.run_root(
        host,
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.traversal.watermark",
            "/tmp/rn-traversal.pub",
            "/tmp/rn-traversal.bundle",
        ],
    )?;
    Ok(())
}

fn restart_managed_dns_stack(ctx: &LiveLabContext, client_host: &str) -> Result<(), String> {
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "stop",
            "rustynetd-managed-dns.service",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-managed-dns.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "start", "rustynetd-privileged-helper.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &[
            "systemctl",
            "is-active",
            "rustynetd-privileged-helper.service",
        ],
        15,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "start", "rustynetd.service"],
        5,
        2,
    )?;
    ctx.wait_for_daemon_socket(client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    ctx.retry_root(
        client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "state",
            "refresh",
        ],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "restart", "rustynetd-managed-dns.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "is-active", "rustynetd-managed-dns.service"],
        15,
        2,
    )?;
    wait_for_dns_inspect_state(ctx, client_host, Some("valid"), 20, 2)?;
    Ok(())
}

fn refresh_signer_trust_evidence(ctx: &LiveLabContext, signer_host: &str) -> Result<(), String> {
    ctx.retry_root(
        signer_host,
        &["rustynet", "ops", "refresh-signed-trust"],
        5,
        2,
    )
}

fn build_authorized_allow_spec(
    assignment_scopes: &HashMap<String, AssignmentAuthorityScope>,
    host_by_node: &HashMap<String, String>,
) -> Result<String, String> {
    let mut pairs = Vec::new();
    for node_id in sorted_node_host_pairs(host_by_node)
        .into_iter()
        .map(|(node_id, _)| node_id)
    {
        let scope = assignment_scopes
            .get(&node_id)
            .ok_or_else(|| format!("missing assignment authority scope for {node_id}"))?;
        for peer_node_id in &scope.peer_node_ids {
            if !host_by_node.contains_key(peer_node_id.as_str()) {
                return Err(format!(
                    "assignment bundle for {node_id} references unmanaged peer {peer_node_id}"
                ));
            }
            pairs.push(format!("{node_id}|{peer_node_id}"));
        }
    }
    pairs.sort();
    pairs.dedup();
    if pairs.is_empty() {
        return Err(
            "managed DNS traversal issuance requires at least one authorized allow pair"
                .to_string(),
        );
    }
    Ok(pairs.join(";"))
}

fn capture_assignment_authority_scopes(
    ctx: &LiveLabContext,
    host_by_node: &HashMap<String, String>,
) -> Result<HashMap<String, AssignmentAuthorityScope>, String> {
    let mut scopes = HashMap::new();
    for (node_id, host) in sorted_node_host_pairs(host_by_node) {
        let assignment_bundle =
            ctx.capture_root(&host, &["cat", "/var/lib/rustynet/rustynetd.assignment"])?;
        let scope = parse_assignment_authority_scope(&assignment_bundle)?;
        if scope.node_id != node_id {
            return Err(format!(
                "assignment bundle subject {subject} does not match expected node {expected} on {host}",
                subject = scope.node_id,
                expected = node_id,
            ));
        }
        scopes.insert(node_id, scope);
    }
    Ok(scopes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AssignmentAuthorityScope {
    node_id: String,
    peer_node_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedDnsRecordTemplate {
    label: String,
    target_node_id: String,
    ttl_secs: u64,
    aliases: Vec<String>,
}

fn managed_dns_base_records(
    signer_node_id: &str,
    client_node_id: &str,
) -> Vec<ManagedDnsRecordTemplate> {
    vec![
        ManagedDnsRecordTemplate {
            label: MANAGED_LABEL.to_string(),
            target_node_id: signer_node_id.to_string(),
            ttl_secs: 300,
            aliases: vec![MANAGED_ALIAS.to_string()],
        },
        ManagedDnsRecordTemplate {
            label: "client".to_string(),
            target_node_id: client_node_id.to_string(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
    ]
}

fn managed_dns_replay_records(
    records: &[ManagedDnsRecordTemplate],
    signer_node_id: &str,
) -> Result<Vec<ManagedDnsRecordTemplate>, String> {
    let mut replay_records = records.to_vec();
    let signer_record = replay_records
        .iter_mut()
        .find(|record| record.target_node_id == signer_node_id)
        .ok_or_else(|| {
            format!("managed DNS replay probe could not find signer record for {signer_node_id}")
        })?;
    if signer_record
        .aliases
        .iter()
        .any(|alias| alias == REPLAY_PROBE_ALIAS)
    {
        return Err(format!(
            "managed DNS replay probe alias already present: {REPLAY_PROBE_ALIAS}"
        ));
    }
    signer_record.aliases.push(REPLAY_PROBE_ALIAS.to_string());
    Ok(replay_records)
}

fn managed_dns_records_manifest_for_scope(
    records: &[ManagedDnsRecordTemplate],
    scope: &AssignmentAuthorityScope,
) -> Result<String, String> {
    let allowed_targets = scope.peer_node_ids.iter().cloned().collect::<HashSet<_>>();
    let filtered = records
        .iter()
        .filter(|record| {
            record.target_node_id == scope.node_id
                || allowed_targets.contains(&record.target_node_id)
        })
        .cloned()
        .collect::<Vec<_>>();
    if filtered.is_empty() {
        return Err(format!(
            "managed DNS scope for {} produced no policy-authorized records",
            scope.node_id
        ));
    }
    let mut manifest = String::new();
    manifest.push_str("version=1\n");
    manifest.push_str(&format!("record_count={}\n", filtered.len()));
    for (index, record) in filtered.iter().enumerate() {
        manifest.push_str(&format!("record.{index}.label={}\n", record.label));
        manifest.push_str(&format!(
            "record.{index}.target_node_id={}\n",
            record.target_node_id
        ));
        manifest.push_str(&format!("record.{index}.ttl_secs={}\n", record.ttl_secs));
        manifest.push_str(&format!(
            "record.{index}.alias_count={}\n",
            record.aliases.len()
        ));
        for (alias_index, alias) in record.aliases.iter().enumerate() {
            manifest.push_str(&format!("record.{index}.alias.{alias_index}={alias}\n"));
        }
    }
    Ok(manifest)
}

fn parse_assignment_authority_scope(bundle: &str) -> Result<AssignmentAuthorityScope, String> {
    let mut node_id = None;
    let mut peer_node_ids = Vec::new();
    for line in bundle.lines() {
        if let Some(value) = line.strip_prefix("node_id=") {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err("assignment bundle node_id must not be empty".to_string());
            }
            node_id = Some(trimmed.to_string());
            continue;
        }
        if let Some((prefix, value)) = line.split_once('=')
            && prefix.starts_with("peer.")
            && prefix.ends_with(".node_id")
        {
            let trimmed = value.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "assignment bundle peer id must not be empty: {prefix}"
                ));
            }
            peer_node_ids.push(trimmed.to_string());
        }
    }
    peer_node_ids.sort();
    peer_node_ids.dedup();
    Ok(AssignmentAuthorityScope {
        node_id: node_id.ok_or_else(|| "assignment bundle is missing node_id".to_string())?,
        peer_node_ids,
    })
}

fn rewrite_bundle_line_value(
    bundle: &str,
    field_key: &str,
    new_value: &str,
) -> Result<String, String> {
    let prefix = format!("{field_key}=");
    let mut updated = Vec::new();
    let mut replaced = false;
    for line in bundle.lines() {
        if !replaced && line.starts_with(prefix.as_str()) {
            updated.push(format!("{prefix}{new_value}"));
            replaced = true;
        } else {
            updated.push(line.to_string());
        }
    }
    if !replaced {
        return Err(format!(
            "dns bundle field not found for rewrite: {field_key}"
        ));
    }
    Ok(updated.join("\n") + "\n")
}

fn rewrite_bundle_signature(bundle: &str, fill: &str) -> Result<String, String> {
    let mut updated = Vec::new();
    let mut replaced = false;
    for line in bundle.lines() {
        if !replaced && line.starts_with("signature=") {
            let hex = line.trim_start_matches("signature=");
            if hex.is_empty() {
                return Err("dns bundle signature line must not be empty".to_string());
            }
            updated.push(format!("signature={}", fill.repeat(hex.len())));
            replaced = true;
        } else {
            updated.push(line.to_string());
        }
    }
    if !replaced {
        return Err("dns bundle is missing signature line".to_string());
    }
    Ok(updated.join("\n") + "\n")
}

#[derive(Debug, Clone)]
struct InvalidBundleCaseResult {
    passed: bool,
}

#[derive(Debug, Clone)]
struct RemoteDnsQueryCapture {
    payload: String,
    command_failed: bool,
    failure_reason: String,
}

#[allow(clippy::too_many_arguments)]
fn exercise_invalid_bundle_case(
    ctx: &LiveLabContext,
    logger: &Logger,
    root_dir: &Path,
    config: &Config,
    workspace: &Path,
    host_by_node: &HashMap<String, String>,
    nodes_spec: &str,
    allow_spec: &str,
    verifier_local: &Path,
    bundle_local: &Path,
    clear_watermark: bool,
    case_label: &str,
    expected_reason_fragments: &[&str],
) -> Result<InvalidBundleCaseResult, String> {
    logger.line(
        format!(
            "[managed-dns] installing {case_label} managed DNS bundle on {}",
            config.client_host
        )
        .as_str(),
    )?;
    install_dns_bundle_with_options(
        ctx,
        &config.client_host,
        verifier_local,
        bundle_local,
        clear_watermark,
    )?;
    refresh_traversal_bundles(ctx, config, workspace, host_by_node, nodes_spec, allow_spec)?;
    let dns_inspect = restart_managed_dns_stack_allow_invalid_dns(ctx, &config.client_host)?;
    let rustynetd_state = ctx.capture_root_allow_failure_with_retry(
        &config.client_host,
        &["systemctl", "is-active", "rustynetd.service"],
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
    )?;
    let rustynetd_journal = ctx.capture_root_allow_failure_with_retry(
        &config.client_host,
        &[
            "journalctl",
            "-u",
            "rustynetd.service",
            "-n",
            "40",
            "--no-pager",
        ],
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
    )?;
    let direct_query = remote_dns_query_capture_allow_failure(
        ctx,
        &config.client_host,
        config,
        &config.managed_fqdn(),
    )?;
    let direct_query_log = if direct_query.payload.trim().is_empty() && direct_query.command_failed
    {
        format!(
            "{{\"error\":\"query command failed closed\",\"failure_reason\":{}}}",
            serde_json::to_string(&direct_query.failure_reason)
                .map_err(|err| format!("serialize DNS query failure reason failed: {err}"))?
        )
    } else {
        direct_query.payload.clone()
    };

    logger.block(
        format!("[managed-dns] {case_label} dns inspect").as_str(),
        &dns_inspect,
    )?;
    logger.block(
        format!("[managed-dns] {case_label} rustynetd state").as_str(),
        &rustynetd_state,
    )?;
    logger.block(
        format!("[managed-dns] {case_label} rustynetd journal").as_str(),
        &rustynetd_journal,
    )?;
    logger.block(
        format!("[managed-dns] {case_label} loopback DNS query").as_str(),
        &direct_query_log,
    )?;

    let passed = managed_dns_invalid_state_observed(
        dns_inspect.as_str(),
        rustynetd_journal.as_str(),
        expected_reason_fragments,
    ) && dns_query_failed_closed(
        root_dir,
        direct_query.payload.as_str(),
        direct_query.command_failed,
    )?;

    Ok(InvalidBundleCaseResult { passed })
}

fn restart_managed_dns_stack_allow_invalid_dns(
    ctx: &LiveLabContext,
    client_host: &str,
) -> Result<String, String> {
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "stop",
            "rustynetd-managed-dns.service",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.run_root_allow_failure(
        client_host,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-managed-dns.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.retry_root(
        client_host,
        &["systemctl", "start", "rustynetd-privileged-helper.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        client_host,
        &[
            "systemctl",
            "is-active",
            "rustynetd-privileged-helper.service",
        ],
        15,
        2,
    )?;
    ctx.run_root_allow_failure(client_host, &["systemctl", "start", "rustynetd.service"])?;
    ctx.run_root_allow_failure(
        client_host,
        &["systemctl", "restart", "rustynetd-managed-dns.service"],
    )?;
    ctx.wait_for_daemon_socket(client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    wait_for_dns_inspect_state(ctx, client_host, None, 20, 2)
}

#[allow(clippy::too_many_arguments)]
fn restore_valid_bundle_after_invalid_case(
    ctx: &LiveLabContext,
    config: &Config,
    workspace: &Path,
    host_by_node: &HashMap<String, String>,
    nodes_spec: &str,
    allow_spec: &str,
    verifier_local: &Path,
    valid_bundle_local: &Path,
) -> Result<(), String> {
    retry_remote_step(
        &format!("restore valid managed DNS bundle on {}", config.client_host),
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
        || {
            install_dns_bundle(ctx, &config.client_host, verifier_local, valid_bundle_local)?;
            refresh_traversal_bundles(
                ctx,
                config,
                workspace,
                host_by_node,
                nodes_spec,
                allow_spec,
            )?;
            restart_managed_dns_stack(ctx, &config.client_host)
        },
    )
}

fn retry_remote_step<T, F>(
    label: &str,
    attempts: u32,
    sleep_secs: u64,
    mut operation: F,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, String>,
{
    let mut last_err = None;
    for attempt in 1..=attempts {
        match operation() {
            Ok(value) => return Ok(value),
            Err(err) => {
                last_err = Some(err);
                if attempt < attempts {
                    sleep(std::time::Duration::from_secs(sleep_secs));
                }
            }
        }
    }
    Err(format!(
        "{label} failed after {attempts} attempts: {}",
        last_err.unwrap_or_else(|| "retry exhausted".to_string())
    ))
}

fn wait_for_dns_inspect_state(
    ctx: &LiveLabContext,
    client_host: &str,
    expected_state: Option<&str>,
    attempts: u32,
    sleep_secs: u64,
) -> Result<String, String> {
    let mut last_output = None;
    for attempt in 1..=attempts {
        let output = ctx.capture_root_allow_failure_with_retry(
            client_host,
            &[
                "env",
                "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
                "rustynet",
                "dns",
                "inspect",
            ],
            SOAK_SSH_RETRY_ATTEMPTS,
            SOAK_SSH_RETRY_SLEEP_SECS,
        )?;
        if dns_inspect_readback_ready(output.as_str())
            && dns_inspect_matches_expected_state(output.as_str(), expected_state)
        {
            return Ok(output);
        }
        last_output = Some(output);
        if attempt < attempts {
            sleep(std::time::Duration::from_secs(sleep_secs));
        }
    }
    Err(format!(
        "managed DNS inspect did not converge on {client_host}: {}",
        last_output
            .map(|output| output.trim().to_string())
            .filter(|output| !output.is_empty())
            .unwrap_or_else(|| "empty output".to_string())
    ))
}

fn dns_inspect_readback_ready(output: &str) -> bool {
    let trimmed = output.trim();
    if trimmed.is_empty() {
        return false;
    }
    let normalized = normalize_reason_text(trimmed);
    !normalized.contains("daemon unreachable")
        && !normalized.contains("inspect daemon socket failed")
}

fn dns_inspect_matches_expected_state(output: &str, expected_state: Option<&str>) -> bool {
    match expected_state {
        Some(state) => output.contains(&format!("dns inspect: state={state}")),
        None => output.contains("dns inspect: state="),
    }
}

fn managed_dns_invalid_state_observed(
    dns_inspect: &str,
    rustynetd_journal: &str,
    expected_reason_fragments: &[&str],
) -> bool {
    if dns_inspect.contains("dns inspect: state=invalid")
        && contains_all_reason_fragments(dns_inspect, expected_reason_fragments)
    {
        return true;
    }
    let journal_lower = rustynetd_journal.to_ascii_lowercase();
    let journal_has_preflight_marker = journal_lower.contains("dns zone preflight failed")
        || journal_lower.contains("dns zone preflight skipped invalid managed dns bundle");
    journal_has_preflight_marker
        && contains_all_reason_fragments(rustynetd_journal, expected_reason_fragments)
}

fn contains_all_reason_fragments(haystack: &str, expected_reason_fragments: &[&str]) -> bool {
    let normalized_haystack = normalize_reason_text(haystack);
    expected_reason_fragments.iter().all(|fragment| {
        let normalized_fragment = normalize_reason_text(fragment);
        normalized_haystack.contains(normalized_fragment.as_str())
    })
}

fn normalize_reason_text(value: &str) -> String {
    value.to_ascii_lowercase().replace('_', " ")
}

fn dns_query_failed_closed(
    root_dir: &Path,
    direct_query: &str,
    command_failed: bool,
) -> Result<bool, String> {
    if direct_query.trim().is_empty() {
        return Ok(command_failed);
    }
    let rcode = json_field(root_dir, direct_query, "rcode")?;
    let error = json_field(root_dir, direct_query, "error")?;
    Ok(rcode != "0" || !error.trim().is_empty())
}

fn capture_remote_text(
    ctx: &LiveLabContext,
    host: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let body = ctx.capture_root(host, &["cat", remote_path])?;
    write_secure_text(local_path, &body)
}

fn run_cargo_ops_capture(
    root_dir: &Path,
    subcommand: &str,
    args: &[&str],
) -> Result<String, String> {
    let output = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            subcommand,
        ])
        .args(args)
        .output()
        .map_err(|err| format!("failed to run cargo ops {subcommand}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "cargo ops {subcommand} failed with status {}: {}",
            live_lab_support::status_code(output.status),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn remote_dns_query_capture(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
    qname: &str,
) -> Result<String, String> {
    ctx.capture_root(
        host,
        &[
            "rustynet",
            "ops",
            "e2e-dns-query",
            "--server",
            &config.dns_server(),
            "--port",
            &config.dns_port(),
            "--qname",
            qname,
            "--timeout-ms",
            "3000",
        ],
    )
}

fn remote_dns_query_capture_allow_failure(
    ctx: &LiveLabContext,
    host: &str,
    config: &Config,
    qname: &str,
) -> Result<RemoteDnsQueryCapture, String> {
    let output = ctx.run_root_allow_failure_with_retry(
        host,
        &[
            "rustynet",
            "ops",
            "e2e-dns-query",
            "--server",
            &config.dns_server(),
            "--port",
            &config.dns_port(),
            "--qname",
            qname,
            "--timeout-ms",
            "3000",
        ],
        SOAK_SSH_RETRY_ATTEMPTS,
        SOAK_SSH_RETRY_SLEEP_SECS,
    )?;
    Ok(RemoteDnsQueryCapture {
        payload: String::from_utf8_lossy(&output.stdout).into_owned(),
        command_failed: !output.status.success(),
        failure_reason: render_remote_output(&output),
    })
}

fn render_remote_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr} (stdout: {stdout})")
    } else if !stderr.is_empty() {
        stderr.to_string()
    } else if !stdout.is_empty() {
        format!("stdout: {stdout}")
    } else {
        "remote command exited non-zero without output".to_string()
    }
}

fn json_field(root_dir: &Path, payload: &str, field: &str) -> Result<String, String> {
    run_cargo_ops_capture(
        root_dir,
        "read-json-field",
        &["--payload", payload, "--field", field],
    )
    .map(|value| value.trim().to_string())
}

fn extract_managed_dns_expected_ip(
    root_dir: &Path,
    fqdn: &str,
    inspect_output: &str,
) -> Result<String, String> {
    run_cargo_ops_capture(
        root_dir,
        "extract-managed-dns-expected-ip",
        &["--fqdn", fqdn, "--inspect-output", inspect_output],
    )
    .map(|value| value.trim().to_string())
}

fn write_env_file(path: &Path, entries: &[(&str, &str)]) -> Result<(), String> {
    let mut body = String::new();
    for (key, value) in entries {
        body.push_str(&format_env_assignment(key, value)?);
        body.push('\n');
    }
    write_secure_text(path, &body)
}

fn format_env_assignment(key: &str, value: &str) -> Result<String, String> {
    validate_env_key(key)?;
    Ok(format!("{key}={}", quote_env_value(value)?))
}

fn validate_env_key(key: &str) -> Result<(), String> {
    if key.is_empty()
        || !key
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_')
    {
        return Err(format!("invalid env key: {key}"));
    }
    Ok(())
}

fn quote_env_value(value: &str) -> Result<String, String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err("env value must not contain newline or NUL characters".to_string());
    }
    let mut quoted = String::from("\"");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '$' => quoted.push_str("\\$"),
            '`' => quoted.push_str("\\`"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

fn ensure_safe_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-')
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

fn ensure_safe_spec(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |ch: char| {
        ch.is_ascii_alphanumeric()
            || matches!(
                ch,
                '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-' | '|' | ';'
            )
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

#[derive(Debug, Clone)]
struct ManagedPeerSpec {
    node_id: String,
    host: String,
}

#[derive(Debug, Clone)]
struct ManagedPeerRuntime {
    node_id: String,
    address: String,
    pubkey_hex: String,
}

fn parse_managed_peer_spec(value: &str) -> Result<ManagedPeerSpec, String> {
    let trimmed = value.trim();
    let (node_id_raw, host_raw) = trimmed.split_once('|').ok_or_else(|| {
        format!("invalid --managed-peer value (expected <node-id>|<user@host>): {value}")
    })?;
    let node_id = node_id_raw.trim();
    let host = host_raw.trim();
    if node_id.is_empty() || host.is_empty() {
        return Err(format!(
            "invalid --managed-peer value (node-id and host must be non-empty): {value}"
        ));
    }
    Ok(ManagedPeerSpec {
        node_id: node_id.to_string(),
        host: host.to_string(),
    })
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn utc_now_string() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_string()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn git_commit(root_dir: &Path) -> String {
    if let Ok(value) = env::var("RUSTYNET_EXPECTED_GIT_COMMIT") {
        return value.trim().to_lowercase();
    }
    let output = Command::new("git")
        .current_dir(root_dir)
        .args(["rev-parse", "HEAD"])
        .output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8_lossy(&output.stdout)
            .trim()
            .to_lowercase(),
        _ => "unknown".to_string(),
    }
}

fn require_command(command: &str) -> Result<(), String> {
    let status = Command::new("sh")
        .args([
            "-lc",
            &format!("command -v {} >/dev/null 2>&1", shell_single_quote(command)),
        ])
        .status()
        .map_err(|err| format!("failed to probe command {command}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
    }
}

fn parse_status_field(status: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    status.split_whitespace().find_map(|token| {
        token
            .strip_prefix(prefix.as_str())
            .map(|value| value.to_string())
    })
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_managed_dns_test --ssh-identity-file <path> [options]\n\noptions:\n  --signer-host <user@host>\n  --client-host <user@host>\n  --signer-node-id <id>\n  --client-node-id <id>\n  --managed-peer <node-id|user@host>   (repeatable)\n  --ssh-allow-cidrs <cidrs>\n  --report-path <path>\n  --log-path <path>\n  --zone-name <name>\n  --dns-interface <name>\n  --dns-bind-addr <ip:port>"
    );
}

#[cfg(test)]
mod tests {
    use super::{
        Config, ManagedDnsRecordTemplate, ManagedPeerSpec, dns_inspect_matches_expected_state,
        dns_inspect_readback_ready, dns_query_failed_closed, managed_dns_distribution_targets,
        managed_dns_invalid_state_observed, managed_dns_replay_records,
        parse_assignment_authority_scope, parse_managed_peer_spec, parse_status_field,
        rewrite_bundle_line_value, rewrite_bundle_signature, sorted_node_host_pairs,
        validate_targets,
    };
    use std::collections::HashMap;
    use std::path::{Path, PathBuf};

    fn base_config() -> Config {
        Config {
            ssh_identity_file: "/tmp/rn-test-key".to_string(),
            signer_host: "debian@192.168.64.22".to_string(),
            client_host: "debian@192.168.64.24".to_string(),
            signer_node_id: "exit-1".to_string(),
            client_node_id: "client-1".to_string(),
            ssh_allow_cidrs: "192.168.64.0/24".to_string(),
            report_path: PathBuf::from("/tmp/managed_dns_report.json"),
            log_path: PathBuf::from("/tmp/managed_dns_report.log"),
            zone_name: "rustynet".to_string(),
            dns_interface: "rustynet0".to_string(),
            dns_bind_addr: "127.0.0.1:53535".to_string(),
            managed_peers: Vec::new(),
        }
    }

    #[test]
    fn parse_managed_peer_spec_accepts_node_id_and_host() {
        let parsed = parse_managed_peer_spec("client-2|debian@192.168.64.26")
            .expect("managed peer should parse");
        assert_eq!(parsed.node_id, "client-2");
        assert_eq!(parsed.host, "debian@192.168.64.26");
    }

    #[test]
    fn parse_managed_peer_spec_rejects_invalid_shape() {
        let err = parse_managed_peer_spec("client-2:debian@192.168.64.26").expect_err("must fail");
        assert!(
            err.contains("expected <node-id>|<user@host>"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_targets_rejects_duplicate_managed_peer_node_id() {
        let mut config = base_config();
        config.managed_peers.push(ManagedPeerSpec {
            node_id: "client-1".to_string(),
            host: "debian@192.168.64.26".to_string(),
        });
        let err = validate_targets(&config).expect_err("duplicate node id must fail");
        assert!(
            err.contains("duplicates an existing node id"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_targets_rejects_duplicate_managed_peer_host() {
        let mut config = base_config();
        config.managed_peers.push(ManagedPeerSpec {
            node_id: "client-2".to_string(),
            host: "debian@192.168.64.22".to_string(),
        });
        let err = validate_targets(&config).expect_err("duplicate host must fail");
        assert!(
            err.contains("duplicates an existing host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_status_field_extracts_exit_node() {
        let status = "node_id=client-1 node_role=client state=ExitActive exit_node=client-2 dns_zone_state=valid";
        let exit = parse_status_field(status, "exit_node").expect("exit_node missing");
        assert_eq!(exit, "client-2");
    }

    #[test]
    fn parse_status_field_returns_none_when_missing() {
        let status = "node_id=client-1 node_role=client state=ExitActive";
        assert!(parse_status_field(status, "exit_node").is_none());
    }

    #[test]
    fn sorted_node_host_pairs_returns_deterministic_order() {
        let mut host_by_node = HashMap::new();
        host_by_node.insert("client-3".to_string(), "debian@192.168.64.28".to_string());
        host_by_node.insert("exit-1".to_string(), "debian@192.168.64.22".to_string());
        host_by_node.insert("client-1".to_string(), "debian@192.168.64.24".to_string());
        host_by_node.insert("client-2".to_string(), "debian@192.168.64.26".to_string());

        let ordered = sorted_node_host_pairs(&host_by_node);

        assert_eq!(
            ordered,
            vec![
                ("client-1".to_string(), "debian@192.168.64.24".to_string()),
                ("client-2".to_string(), "debian@192.168.64.26".to_string()),
                ("client-3".to_string(), "debian@192.168.64.28".to_string()),
                ("exit-1".to_string(), "debian@192.168.64.22".to_string()),
            ]
        );
    }

    #[test]
    fn managed_dns_distribution_targets_excludes_client_host() {
        let mut host_by_node = HashMap::new();
        host_by_node.insert("exit-1".to_string(), "debian@192.168.64.22".to_string());
        host_by_node.insert("client-1".to_string(), "debian@192.168.64.24".to_string());
        host_by_node.insert("client-2".to_string(), "debian@192.168.64.26".to_string());

        let targets = managed_dns_distribution_targets(&host_by_node, "debian@192.168.64.24");

        assert_eq!(
            targets,
            vec![
                ("client-2".to_string(), "debian@192.168.64.26".to_string()),
                ("exit-1".to_string(), "debian@192.168.64.22".to_string()),
            ]
        );
    }

    #[test]
    fn parse_assignment_authority_scope_collects_subject_and_peers() {
        let bundle = "\
version=1
node_id=client-2
peer_count=2
peer.0.node_id=client-1
peer.1.node_id=exit-1
signature=test
";

        let scope =
            parse_assignment_authority_scope(bundle).expect("assignment authority should parse");

        assert_eq!(scope.node_id, "client-2");
        assert_eq!(
            scope.peer_node_ids,
            vec!["client-1".to_string(), "exit-1".to_string()]
        );
    }

    #[test]
    fn parse_assignment_authority_scope_rejects_missing_subject() {
        let bundle = "\
version=1
peer.0.node_id=exit-1
";

        let err = parse_assignment_authority_scope(bundle).expect_err("missing node_id must fail");
        assert!(err.contains("missing node_id"), "unexpected error: {err}");
    }

    #[test]
    fn managed_dns_replay_records_adds_probe_alias_to_signer_record() {
        let records = vec![
            ManagedDnsRecordTemplate {
                label: "exit".to_string(),
                target_node_id: "exit-1".to_string(),
                ttl_secs: 300,
                aliases: vec!["gateway".to_string()],
            },
            ManagedDnsRecordTemplate {
                label: "client".to_string(),
                target_node_id: "client-1".to_string(),
                ttl_secs: 300,
                aliases: Vec::new(),
            },
        ];

        let replay =
            managed_dns_replay_records(&records, "exit-1").expect("replay records should build");

        assert_eq!(
            replay[0].aliases,
            vec!["gateway".to_string(), "gatewayreplay".to_string()]
        );
        assert!(replay[1].aliases.is_empty());
    }

    #[test]
    fn rewrite_bundle_line_value_updates_requested_field() {
        let bundle = "\
version=1
record.0.fqdn=exit.rustynet
signature=abcd
";

        let rewritten = rewrite_bundle_line_value(bundle, "record.0.fqdn", "tampered.rustynet")
            .expect("bundle rewrite should succeed");

        assert!(rewritten.contains("record.0.fqdn=tampered.rustynet"));
        assert!(rewritten.contains("signature=abcd"));
    }

    #[test]
    fn rewrite_bundle_signature_rewrites_signature_hex() {
        let bundle = "\
version=1
record.0.fqdn=exit.rustynet
signature=abcd
";

        let rewritten =
            rewrite_bundle_signature(bundle, "0").expect("signature rewrite should succeed");

        assert!(rewritten.contains("signature=0000"));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_dns_inspect_reason_match() {
        assert!(managed_dns_invalid_state_observed(
            "dns inspect: state=invalid error=dns zone bundle replay detected",
            "",
            &["replay detected"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_dns_inspect_reason_with_underscores() {
        assert!(managed_dns_invalid_state_observed(
            "dns inspect: state=invalid error=dns_zone_bundle_subject_node_id_does_not_match_local_node",
            "",
            &["subject node id does not match local node"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_journal_reason_match() {
        assert!(managed_dns_invalid_state_observed(
            "",
            "dns zone preflight failed: dns zone bundle subject node id does not match local node",
            &["subject node id does not match local node"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_rejects_daemon_unreachable_without_invalid_state() {
        assert!(!managed_dns_invalid_state_observed(
            "daemon unreachable: inspect daemon socket failed (/run/rustynet/rustynetd.sock): No such file or directory",
            "",
            &["replay detected"]
        ));
    }

    #[test]
    fn managed_dns_invalid_state_observed_accepts_skipped_preflight_journal_marker() {
        assert!(managed_dns_invalid_state_observed(
            "",
            "rustynetd startup warning: dns zone preflight skipped invalid managed DNS bundle: dns zone bundle replay detected",
            &["replay detected"]
        ));
    }

    #[test]
    fn dns_query_failed_closed_accepts_empty_payload_when_command_failed() {
        assert!(
            dns_query_failed_closed(Path::new("/tmp"), "", true)
                .expect("empty failed query should be accepted as fail-closed")
        );
    }

    #[test]
    fn dns_query_failed_closed_rejects_empty_payload_without_command_failure() {
        assert!(
            !dns_query_failed_closed(Path::new("/tmp"), "", false)
                .expect("empty successful query should not be treated as fail-closed")
        );
    }

    #[test]
    fn dns_inspect_readback_ready_rejects_daemon_unreachable_output() {
        assert!(!dns_inspect_readback_ready(
            "daemon unreachable: inspect daemon socket failed (/run/rustynet/rustynetd.sock): No such file or directory"
        ));
    }

    #[test]
    fn dns_inspect_readback_ready_accepts_invalid_state_output() {
        assert!(dns_inspect_readback_ready(
            "dns inspect: state=invalid error=dns zone bundle replay detected"
        ));
    }

    #[test]
    fn dns_inspect_matches_expected_state_enforces_requested_state() {
        assert!(dns_inspect_matches_expected_state(
            "dns inspect: state=valid zone_name=rustynet",
            Some("valid")
        ));
        assert!(!dns_inspect_matches_expected_state(
            "dns inspect: state=invalid error=signature verification failed",
            Some("valid")
        ));
        assert!(dns_inspect_matches_expected_state(
            "dns inspect: state=invalid error=signature verification failed",
            None
        ));
    }
}
