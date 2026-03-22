#![forbid(unsafe_code)]

mod live_lab_support;

use std::collections::{HashMap, HashSet};
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;
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
const DNS_RECORDS_REMOTE: &str = "/tmp/rn-dns-records.json";
const TRAVERSAL_ENV_REMOTE: &str = "/tmp/rn_issue_dns_traversal.env";
const TRAVERSAL_PUB_REMOTE: &str = "/run/rustynet/traversal-issue/rn-traversal.pub";

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

    let mut required_node_ids = vec![config.signer_node_id.clone(), config.client_node_id.clone()];
    if current_exit_node != "none"
        && current_exit_node != config.signer_node_id
        && current_exit_node != config.client_node_id
    {
        if !host_by_node.contains_key(&current_exit_node) {
            return Err(format!(
                "client exit_node {} is not mapped to a host; provide --managed-peer {}|<user@host>",
                current_exit_node, current_exit_node
            ));
        }
        required_node_ids.push(current_exit_node.clone());
    }

    let mut mesh_peers = Vec::new();
    for node_id in required_node_ids {
        let host = host_by_node
            .get(&node_id)
            .ok_or_else(|| format!("missing host mapping for traversal node id: {node_id}"))?;
        mesh_peers.push(ManagedPeerRuntime {
            node_id,
            address: target_address(host).to_string(),
            pubkey_hex: ctx.collect_pubkey_hex(host)?,
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
    let allow_spec = mesh_peers
        .iter()
        .flat_map(|source| {
            mesh_peers.iter().filter_map(move |destination| {
                if source.node_id == destination.node_id {
                    None
                } else {
                    Some(format!("{}|{}", source.node_id, destination.node_id))
                }
            })
        })
        .collect::<Vec<_>>()
        .join(";");
    ensure_safe_spec("NODES_SPEC", &nodes_spec)?;
    ensure_safe_spec("ALLOW_SPEC", &allow_spec)?;

    let workspace = ctx.work_dir.clone();
    let records_json = workspace.join("rn-dns-records.json");
    write_secure_json(
        &records_json,
        &json!([
            {
                "label": MANAGED_LABEL,
                "target_node_id": config.signer_node_id,
                "ttl_secs": 300,
                "aliases": [MANAGED_ALIAS],
            },
            {
                "label": "client",
                "target_node_id": config.client_node_id,
                "ttl_secs": 300,
            },
        ]),
    )?;

    let issue_dir = ISSUE_DIR;
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
    ctx.scp_to(&records_json, &config.signer_host, DNS_RECORDS_REMOTE)?;

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
        None,
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
        Some(unix_now().saturating_sub(7200)),
    )?;

    let verifier_local = workspace.join("dns-zone.pub");
    let valid_bundle_local = workspace.join("dns-zone-valid.bundle");
    let stale_bundle_local = workspace.join("dns-zone-stale.bundle");
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
    refresh_traversal_bundles(&ctx, &config, &workspace, &nodes_spec, &allow_spec)?;
    restart_managed_dns_stack(&ctx, &config.client_host)?;

    let dns_inspect_valid = ctx.capture_root(
        &config.client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "dns",
            "inspect",
        ],
    )?;
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

    logger.line(
        format!(
            "[managed-dns] installing stale managed DNS bundle on {}",
            config.client_host
        )
        .as_str(),
    )?;
    install_dns_bundle(
        &ctx,
        &config.client_host,
        &verifier_local,
        &stale_bundle_local,
    )?;
    refresh_traversal_bundles(&ctx, &config, &workspace, &nodes_spec, &allow_spec)?;
    ctx.run_root_allow_failure(
        &config.client_host,
        &[
            "systemctl",
            "stop",
            "rustynetd-managed-dns.service",
            "rustynetd.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.run_root_allow_failure(
        &config.client_host,
        &[
            "systemctl",
            "reset-failed",
            "rustynetd.service",
            "rustynetd-managed-dns.service",
            "rustynetd-privileged-helper.service",
        ],
    )?;
    ctx.retry_root(
        &config.client_host,
        &["systemctl", "start", "rustynetd-privileged-helper.service"],
        5,
        2,
    )?;
    ctx.retry_root(
        &config.client_host,
        &[
            "systemctl",
            "is-active",
            "rustynetd-privileged-helper.service",
        ],
        15,
        2,
    )?;
    ctx.run_root_allow_failure(
        &config.client_host,
        &["systemctl", "start", "rustynetd.service"],
    )?;
    ctx.wait_for_daemon_socket(&config.client_host, "/run/rustynet/rustynetd.sock", 20, 2)?;
    ctx.run_root_allow_failure(
        &config.client_host,
        &["systemctl", "restart", "rustynetd-managed-dns.service"],
    )?;
    ctx.retry_root(
        &config.client_host,
        &["systemctl", "is-active", "rustynetd-managed-dns.service"],
        15,
        2,
    )?;

    let dns_inspect_stale = ctx.capture_root_allow_failure(
        &config.client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "dns",
            "inspect",
        ],
    )?;
    let rustynetd_state_stale = ctx.capture_root_allow_failure(
        &config.client_host,
        &["systemctl", "is-active", "rustynetd.service"],
    )?;
    let rustynetd_journal_stale = ctx.capture_root_allow_failure(
        &config.client_host,
        &[
            "journalctl",
            "-u",
            "rustynetd.service",
            "-n",
            "40",
            "--no-pager",
        ],
    )?;
    let direct_query_stale =
        remote_dns_query_capture(&ctx, &config.client_host, &config, &config.managed_fqdn())?;

    logger.block("[managed-dns] stale dns inspect", &dns_inspect_stale)?;
    logger.block(
        "[managed-dns] stale rustynetd state",
        &rustynetd_state_stale,
    )?;
    logger.block(
        "[managed-dns] stale loopback DNS query",
        &direct_query_stale,
    )?;

    logger.line(
        format!(
            "[managed-dns] restoring valid managed DNS bundle on {}",
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
    refresh_traversal_bundles(&ctx, &config, &workspace, &nodes_spec, &allow_spec)?;
    restart_managed_dns_stack(&ctx, &config.client_host)?;
    let dns_inspect_restored = ctx.capture_root(
        &config.client_host,
        &[
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "rustynet",
            "dns",
            "inspect",
        ],
    )?;

    let mut distribution_hosts = host_by_node
        .values()
        .cloned()
        .collect::<Vec<String>>();
    distribution_hosts.sort();
    distribution_hosts.dedup();
    for host in distribution_hosts {
        if host == config.client_host {
            continue;
        }
        logger.line(
            format!(
                "[managed-dns] propagating valid managed DNS bundle to {}",
                host
            )
            .as_str(),
        )?;
        install_dns_bundle(&ctx, &host, &verifier_local, &valid_bundle_local)?;
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

    let mut stale_state_observed = false;
    if dns_inspect_stale.contains("dns inspect: state=invalid")
        && dns_inspect_stale.contains("stale")
    {
        stale_state_observed = true;
    }
    if dns_inspect_stale.contains("daemon unreachable") {
        stale_state_observed = true;
    }
    if rustynetd_journal_stale.contains("dns zone preflight failed")
        && rustynetd_journal_stale.contains("stale")
    {
        stale_state_observed = true;
    }
    if stale_state_observed {
        let stale_rcode = json_field(&root_dir, &direct_query_stale, "rcode")?;
        let stale_error = json_field(&root_dir, &direct_query_stale, "error")?;
        if stale_rcode != "0" || !stale_error.trim().is_empty() {
            check_stale_bundle_fail_closed = "pass";
        }
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
        &["rm", "-f", DNS_RECORDS_REMOTE, &passphrase_file],
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
    records_json_remote: &str,
    issue_dir: &str,
    output_name: &str,
    generated_at: Option<u64>,
) -> Result<(), String> {
    let output_path = format!("{issue_dir}/{output_name}");
    let verifier_key_output = format!("{issue_dir}/rn-dns-zone.pub");
    let generated_at_string = generated_at.map(|value| value.to_string());
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
        "--records-json",
        records_json_remote,
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
    ctx.run_root(signer_host, &args)?;
    Ok(())
}

fn install_dns_bundle(
    ctx: &LiveLabContext,
    client_host: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
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
        &[
            "rm",
            "-f",
            "/var/lib/rustynet/rustynetd.dns-zone.watermark",
            "/tmp/rn-dns-zone.pub",
            "/tmp/rn-dns-zone.bundle",
        ],
    )?;
    Ok(())
}

fn refresh_traversal_bundles(
    ctx: &LiveLabContext,
    config: &Config,
    workspace: &Path,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<(), String> {
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
    let signer_traversal_local = workspace.join("traversal-signer.bundle");
    let client_traversal_local = workspace.join("traversal-client.bundle");
    capture_remote_text(
        ctx,
        &config.signer_host,
        TRAVERSAL_PUB_REMOTE,
        &traversal_pub_local,
    )?;
    let signer_traversal_remote = traversal_bundle_remote_path(&config.signer_node_id);
    let client_traversal_remote = traversal_bundle_remote_path(&config.client_node_id);
    capture_remote_text(
        ctx,
        &config.signer_host,
        signer_traversal_remote.as_str(),
        &signer_traversal_local,
    )?;
    capture_remote_text(
        ctx,
        &config.signer_host,
        client_traversal_remote.as_str(),
        &client_traversal_local,
    )?;

    install_traversal_bundle(
        ctx,
        &config.signer_host,
        &traversal_pub_local,
        &signer_traversal_local,
    )?;
    install_traversal_bundle(
        ctx,
        &config.client_host,
        &traversal_pub_local,
        &client_traversal_local,
    )?;
    ctx.run_root_allow_failure(&config.signer_host, &["rm", "-rf", TRAVERSAL_ISSUE_DIR])?;
    Ok(())
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
    Ok(())
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
    if let Some(output) = output {
        if output.status.success() {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if !text.is_empty() {
                return text;
            }
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

fn target_address(target: &str) -> &str {
    target
        .split_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target)
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
        Config, ManagedPeerSpec, parse_managed_peer_spec, parse_status_field, validate_targets,
    };
    use std::path::PathBuf;

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
}
