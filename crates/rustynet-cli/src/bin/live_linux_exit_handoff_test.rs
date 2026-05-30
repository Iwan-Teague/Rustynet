#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]
// Track B Phase 28 transition: still calls the deprecated
// `capture_root` shim. Phase 29 rewrites on the new
// `RemoteShellHost` trait. Allow until then so `-D warnings` passes.
#![allow(deprecated)]

mod live_lab_bin_support;

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, append_env_assignment, capture_root, create_workspace, enforce_host,
    ensure_pinned_known_hosts_file, ensure_safe_token, git_head_commit,
    issue_assignment_bundles_from_env, issue_traversal_bundles_from_env,
    load_home_known_hosts_path, read_file, remote_src_dir, require_command,
    resolved_target_address, run_root, scp_to, seed_known_hosts, shell_quote, status, unix_now,
    wait_for_daemon_socket, write_file,
};

const DNS_ZONE_NAME: &str = "rustynet";
const DNS_MANAGED_LABEL: &str = "exit";
const DNS_MANAGED_ALIAS: &str = "gateway";
const DNS_ZONE_ISSUE_DIR: &str = "/run/rustynet/dns-zone-issue-handoff";
const DNS_ZONE_RECORDS_REMOTE: &str = "/tmp/rn-exit-handoff-dns-records.manifest";
const DNS_ZONE_VALID_BUNDLE_REMOTE: &str = "/run/rustynet/dns-zone-issue-handoff/valid.dns-zone";
const DNS_ZONE_VERIFIER_REMOTE: &str = "/run/rustynet/dns-zone-issue-handoff/rn-dns-zone.pub";
const ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";
const MAX_TRAVERSAL_COORDINATION_TTL_SECS: u64 = 30;
const HANDOFF_PRE_MONITOR_TIMEOUT_SECS: u64 = 60;
const HANDOFF_REFRESH_CONVERGENCE_TIMEOUT_SECS: u64 = 20;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManagedDnsRefreshTarget {
    host: String,
    node_id: String,
    records_local: PathBuf,
    bundle_local: PathBuf,
}

fn main() {
    if let Err(err) = run() {
        // X6 taxonomy classifier for live-lab test binaries. The
        // shape of errors these tests emit is well-known: missing
        // commands / paths → ConfigError, ssh/scp transient
        // failures → TransientFailure, daemon-state drift →
        // PolicyReject.
        let code = classify_live_lab_error(err.as_str());
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("error [{code}]: {err}");
        } else {
            eprintln!("error [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

fn classify_live_lab_error(message: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = message.to_ascii_lowercase();
    if lower.contains("missing required")
        || lower.contains("unknown command")
        || lower.contains("missing required argument")
    {
        ExitCode::BadArgs
    } else if lower.contains("drift")
        || lower.contains("fail-closed")
        || lower.contains("signature verification")
        || lower.contains("policy reject")
        || lower.contains("forbidden")
    {
        ExitCode::PolicyReject
    } else if lower.contains("missing required command")
        || lower.contains("identity file")
        || lower.contains("invalid path")
        || lower.contains("config")
        || lower.contains("schema")
    {
        ExitCode::ConfigError
    } else if lower.contains("ssh")
        || lower.contains("scp")
        || lower.contains("timed out")
        || lower.contains("connection refused")
        || lower.contains("transient")
        || lower.contains("retry")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;

    // Track B per-platform dispatch. Linux runs the full handoff
    // validator (existing path). macOS runs the Track B Phase 4
    // pf+sysctl lifecycle validator. Windows runs the Track B
    // Phase 5 NetNat+forwarding lifecycle validator via PowerShell
    // over SSH, mirroring the macOS shape using the existing
    // `rustynetd::windows_exit_nat_lifecycle` builder helpers.
    match config.platform {
        ExitHandoffPlatform::Linux => {}
        ExitHandoffPlatform::MacOs => {
            return run_macos_exit_handoff(&config);
        }
        ExitHandoffPlatform::Windows => {
            return run_windows_exit_handoff(&config);
        }
    }

    let root_dir = live_lab_support::repo_root()?;

    for command in [
        "cargo",
        "git",
        "ssh",
        "scp",
        "ssh-keygen",
        "awk",
        "sed",
        "openssl",
        "xxd",
        "mktemp",
        "chmod",
        "tr",
    ] {
        require_command(command)?;
    }

    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;

    let workspace = create_workspace("exit-handoff")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;
    let mut logger = Logger::new(&config.log_path)?;
    logger.line(
        format!(
            "[exit-handoff] traversal bundle TTL for handoff stage: {}s (refresh every {}s)",
            config.traversal_ttl_secs, config.traversal_refresh_interval_secs
        )
        .as_str(),
    )?;

    for host in [
        &config.exit_a_host,
        &config.exit_b_host,
        &config.client_host,
    ] {
        live_lab_support::verify_sudo(&config.ssh_identity_file, &work_known_hosts, host)?;
    }

    logger.line("[exit-handoff] collecting WireGuard public keys")?;
    let exit_a_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
    )?;
    let exit_b_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
    )?;
    let client_pub_hex = live_lab_support::collect_pubkey_hex(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;

    let exit_a_addr = resolved_target_address(&config.exit_a_host)?;
    let exit_b_addr = resolved_target_address(&config.exit_b_host)?;
    let client_addr = resolved_target_address(&config.client_host)?;

    // Capabilities must appear in BOTH the 4th field (read by parse_generic_nodes
    // during issuance) and the 8th field (read by parse_assignment_nodes when the
    // local rustynetd-assignment-refresh service regenerates the bundle from
    // RUSTYNET_ASSIGNMENT_NODES). The node-spec layout is
    // node_id|endpoint|pubkey|owner|hostname|os|tags|capabilities. Emitting caps
    // only in the 4th field made the refresh service default every node to bare
    // `client`, dropping relay_host/exit_server, so the daemon rejected the
    // regenerated bundle ("route peer ... lacks signed relay_host or exit_server")
    // and fail-closed on the enforce restart. Mirror build_onehop_specs:
    // `caps||||caps`.
    // exit_a and exit_b are both enforced as `admin` (the handoff keeps a
    // standby exit), so both need `anchor` in their assignment intent —
    // otherwise the daemon rejects the bundle with "assignment target intent
    // lacks required local capability anchor". They are the two anchor/exit
    // servers; the client stays client,relay_host. (upgrade_admin already
    // granted these nodes anchor in signed membership.)
    let nodes_spec = format!(
        "{}|{}:51820|{}|anchor,exit_server||||anchor,exit_server;{}|{}:51820|{}|anchor,exit_server||||anchor,exit_server;{}|{}:51820|{}|client,relay_host||||client,relay_host",
        config.exit_a_node_id,
        exit_a_addr,
        exit_a_pub_hex,
        config.exit_b_node_id,
        exit_b_addr,
        exit_b_pub_hex,
        config.client_node_id,
        client_addr,
        client_pub_hex,
    );
    let allow_spec = format!(
        "{}|{};{}|{};{}|{};{}|{}",
        config.client_node_id,
        config.exit_a_node_id,
        config.exit_a_node_id,
        config.client_node_id,
        config.client_node_id,
        config.exit_b_node_id,
        config.exit_b_node_id,
        config.client_node_id,
    );
    ensure_safe_token("exit-a-host", &config.exit_a_host)?;
    ensure_safe_token("exit-b-host", &config.exit_b_host)?;
    ensure_safe_token("client-host", &config.client_host)?;
    ensure_safe_token("exit-a-node-id", &config.exit_a_node_id)?;
    ensure_safe_token("exit-b-node-id", &config.exit_b_node_id)?;
    ensure_safe_token("client-node-id", &config.client_node_id)?;
    ensure_safe_token("ssh-allow-cidrs", &config.ssh_allow_cidrs)?;

    let issue_env = workspace.path().join("rn_issue_handoff.env");
    write_file(&issue_env, "")?;
    append_env_assignment(&issue_env, "NODES_SPEC", &nodes_spec)?;
    append_env_assignment(&issue_env, "ALLOW_SPEC", &allow_spec)?;
    append_env_assignment(
        &issue_env,
        "ASSIGNMENTS_SPEC",
        &format!(
            "{}|-;{}|-;{}|{}",
            config.exit_a_node_id,
            config.exit_b_node_id,
            config.client_node_id,
            config.exit_a_node_id
        ),
    )?;
    // BUNDLE_TTL_SECS: extend so handoff bundles survive the long enforce
    // pipeline that follows (default 300s expires before validation runs).
    append_env_assignment(&issue_env, "BUNDLE_TTL_SECS", "3600")?;

    logger.line(
        format!(
            "[exit-handoff] issuing signed handoff assignments on {}",
            config.exit_a_host
        )
        .as_str(),
    )?;
    issue_assignment_bundles_from_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &issue_env,
        "/tmp/rn_issue_handoff.env",
    )?;

    let assign_pub_local = workspace.path().join("assignment.pub");
    let exit_a_assignment_local = workspace.path().join("assignment-exit-a");
    let exit_b_assignment_local = workspace.path().join("assignment-exit-b");
    let client_assignment_local = workspace.path().join("assignment-client");
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "/run/rustynet/assignment-issue/rn-assignment.pub",
        &assign_pub_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.exit_a_node_id
        ),
        &exit_a_assignment_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.exit_b_node_id
        ),
        &exit_b_assignment_local,
    )?;
    capture_root_file_to_local(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &format!(
            "/run/rustynet/assignment-issue/rn-assignment-{}.assignment",
            config.client_node_id
        ),
        &client_assignment_local,
    )?;

    logger.line("[exit-handoff] distributing signed assignments")?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &assign_pub_local,
        &exit_a_assignment_local,
    )?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        &assign_pub_local,
        &exit_b_assignment_local,
    )?;
    install_assignment_bundle(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &assign_pub_local,
        &client_assignment_local,
    )?;
    let assignment_scopes = HashMap::from([
        (
            config.exit_a_node_id.clone(),
            parse_assignment_authority_scope(&read_file(&exit_a_assignment_local)?)?,
        ),
        (
            config.exit_b_node_id.clone(),
            parse_assignment_authority_scope(&read_file(&exit_b_assignment_local)?)?,
        ),
        (
            config.client_node_id.clone(),
            parse_assignment_authority_scope(&read_file(&client_assignment_local)?)?,
        ),
    ]);

    let exit_a_refresh_local = workspace.path().join("assignment-refresh-exit-a.env");
    let exit_b_refresh_local = workspace.path().join("assignment-refresh-exit-b.env");
    let client_refresh_local = workspace.path().join("assignment-refresh-client.env");
    live_lab_support::write_assignment_refresh_env(
        &exit_a_refresh_local,
        &config.exit_a_node_id,
        &nodes_spec,
        &allow_spec,
        None,
    )?;
    live_lab_support::write_assignment_refresh_env(
        &exit_b_refresh_local,
        &config.exit_b_node_id,
        &nodes_spec,
        &allow_spec,
        None,
    )?;
    live_lab_support::write_assignment_refresh_env(
        &client_refresh_local,
        &config.client_node_id,
        &nodes_spec,
        &allow_spec,
        Some(&config.exit_a_node_id),
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &exit_a_refresh_local,
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        &exit_b_refresh_local,
    )?;
    install_assignment_refresh_env(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &client_refresh_local,
    )?;

    let traversal_env = workspace.path().join("rn_issue_handoff_traversal.env");
    write_file(&traversal_env, "")?;
    append_env_assignment(&traversal_env, "NODES_SPEC", &nodes_spec)?;
    append_env_assignment(&traversal_env, "ALLOW_SPEC", &allow_spec)?;
    append_env_assignment(
        &traversal_env,
        "TRAVERSAL_TTL_SECS",
        &config.traversal_ttl_secs.to_string(),
    )?;

    let traversal_pub_local = workspace.path().join("traversal.pub");
    let exit_a_traversal_local = workspace.path().join("traversal-exit-a");
    let exit_b_traversal_local = workspace.path().join("traversal-exit-b");
    let client_traversal_local = workspace.path().join("traversal-client");
    let dns_verifier_local = workspace.path().join("dns-zone.pub");
    let dns_refresh_targets = managed_dns_refresh_targets(workspace.path(), &config);
    let dns_base_records = managed_dns_base_records(&config.exit_a_node_id, &config.client_node_id);
    let dns_records_by_node = dns_refresh_targets
        .iter()
        .map(|target| {
            let scope = assignment_scopes.get(&target.node_id).ok_or_else(|| {
                format!(
                    "missing assignment authority scope for exit handoff DNS node {}",
                    target.node_id
                )
            })?;
            let records_manifest =
                managed_dns_records_manifest_for_scope(&dns_base_records, scope)?;
            Ok((target.node_id.clone(), records_manifest))
        })
        .collect::<Result<HashMap<_, _>, String>>()?;

    refresh_traversal_bundles(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &config.exit_b_host,
        &config.client_host,
        &traversal_env,
        &traversal_pub_local,
        &exit_a_traversal_local,
        &exit_b_traversal_local,
        &client_traversal_local,
        &config.exit_a_node_id,
        &config.exit_b_node_id,
        &config.client_node_id,
    )?;
    let dns_passphrase_remote = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "mktemp /tmp/rn-exit-handoff-dns-passphrase.XXXXXX",
    )?
    .trim()
    .to_owned();
    let materialize_dns_passphrase_cmd = format!(
        "rustynet ops materialize-signing-passphrase --output {}",
        shell_quote(dns_passphrase_remote.as_str())
    );
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        materialize_dns_passphrase_cmd.as_str(),
    )?;
    let chmod_dns_passphrase_cmd =
        format!("chmod 0600 {}", shell_quote(dns_passphrase_remote.as_str()));
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        chmod_dns_passphrase_cmd.as_str(),
    )?;
    let mkdir_dns_issue_dir_cmd = format!("install -d -m 0700 {}", shell_quote(DNS_ZONE_ISSUE_DIR));
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        mkdir_dns_issue_dir_cmd.as_str(),
    )?;
    logger.line("[exit-handoff] refreshing signed handoff coordination before monitor")?;
    refresh_handoff_coordination(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        &config.exit_b_host,
        &config.client_host,
        &traversal_env,
        &traversal_pub_local,
        &exit_a_traversal_local,
        &exit_b_traversal_local,
        &client_traversal_local,
        &config.exit_a_node_id,
        &config.exit_b_node_id,
        &config.client_node_id,
        &dns_verifier_local,
        &dns_records_by_node,
        &dns_refresh_targets,
        dns_passphrase_remote.as_str(),
        &nodes_spec,
        &allow_spec,
    )?;

    logger.line("[exit-handoff] enforcing runtime roles")?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "admin",
        &config.exit_a_node_id,
        &remote_src_dir(&config.exit_a_host),
        &config.ssh_allow_cidrs,
    )?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        "admin",
        &config.exit_b_node_id,
        &remote_src_dir(&config.exit_b_host),
        &config.ssh_allow_cidrs,
    )?;
    enforce_host(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "client",
        &config.client_node_id,
        &remote_src_dir(&config.client_host),
        &config.ssh_allow_cidrs,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;
    wait_for_daemon_socket(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "/run/rustynet/rustynetd.sock",
        20,
        2,
    )?;

    // After enforce_host the daemons come up cold and stay in
    // restricted-safe mode until they ingest fresh signed trust
    // evidence. The route advertise calls below are mutating IPC
    // commands and would be refused while restricted-safe is set.
    // Today this stage passes because earlier orchestrator stages
    // (enforce_baseline_runtime, role_switch_matrix) leave trust
    // evidence fresh enough that re-enforce here doesn't re-trip the
    // gate before the route advertise lands. That is fragile; a slower
    // run, a reordered stage list, or an enforce_host implementation
    // that wipes trust state would put us back in two_hop's pre-fix
    // failure mode. Mirror the explicit refresh from
    // live_linux_two_hop_test (commit cca0418) so the route advertise
    // sees fresh trust independent of the orchestrator's stage timing.
    logger.line("[exit-handoff] refreshing signed trust evidence on all nodes")?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
    )?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
    )?;
    refresh_trust_evidence(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;

    logger.line("[exit-handoff] advertising default route on both exits")?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0",
    )?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet route advertise 0.0.0.0/0",
    )?;
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &config.exit_a_node_id,
    )?;

    wait_for_handoff_monitor_prereqs(
        &mut logger,
        &config,
        &work_known_hosts,
        &traversal_env,
        &traversal_pub_local,
        &exit_a_traversal_local,
        &exit_b_traversal_local,
        &client_traversal_local,
        &dns_verifier_local,
        &dns_records_by_node,
        &dns_refresh_targets,
        dns_passphrase_remote.as_str(),
        &nodes_spec,
        &allow_spec,
    )?;

    let monitor_path = config.monitor_log.clone();
    write_file(&monitor_path, "")?;
    let mut switch_ts = 0u64;
    let mut next_coordination_refresh_ts =
        next_refresh_deadline(unix_now(), config.traversal_refresh_interval_secs);
    for i in 1..=config.monitor_iterations {
        let ts = unix_now();
        if ts >= next_coordination_refresh_ts {
            logger.line(
                "[exit-handoff] refreshing signed handoff coordination during handoff monitor",
            )?;
            refresh_handoff_coordination(
                &config.ssh_identity_file,
                &work_known_hosts,
                &config.exit_a_host,
                &config.exit_b_host,
                &config.client_host,
                &traversal_env,
                &traversal_pub_local,
                &exit_a_traversal_local,
                &exit_b_traversal_local,
                &client_traversal_local,
                &config.exit_a_node_id,
                &config.exit_b_node_id,
                &config.client_node_id,
                &dns_verifier_local,
                &dns_records_by_node,
                &dns_refresh_targets,
                dns_passphrase_remote.as_str(),
                &nodes_spec,
                &allow_spec,
            )?;
            wait_for_handoff_monitor_expected_exit(
                &mut logger,
                &config,
                &work_known_hosts,
                if switch_ts == 0 {
                    &config.exit_a_node_id
                } else {
                    &config.exit_b_node_id
                },
            )?;
            next_coordination_refresh_ts = advance_periodic_refresh_deadline(
                next_coordination_refresh_ts,
                config.traversal_refresh_interval_secs,
                unix_now(),
            );
        }
        let client_status = status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
        )?;
        let route_line = capture_root(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true",
        )?;
        let wg_endpoints = capture_root(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            "wg show rustynet0 endpoints 2>/dev/null || true",
        )?;
        let ping_rc = match live_lab_support::ssh_status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1",
        ) {
            Ok(status) if status.success() => 0,
            Ok(status) => live_lab_support::status_code(status),
            Err(_) => 1,
        };
        append_monitor_line(
            &monitor_path,
            &format!(
                "{}|iter={}|ping_rc={}|route={}|status={}|wg_endpoints={}",
                ts,
                i,
                ping_rc,
                route_line.replace('\n', " "),
                client_status.replace('\n', " "),
                wg_endpoints.replace('\n', " ")
            ),
        )?;
        if i == config.switch_iteration {
            logger
                .line("[exit-handoff] refreshing signed handoff coordination before exit switch")?;
            refresh_handoff_coordination(
                &config.ssh_identity_file,
                &work_known_hosts,
                &config.exit_a_host,
                &config.exit_b_host,
                &config.client_host,
                &traversal_env,
                &traversal_pub_local,
                &exit_a_traversal_local,
                &exit_b_traversal_local,
                &client_traversal_local,
                &config.exit_a_node_id,
                &config.exit_b_node_id,
                &config.client_node_id,
                &dns_verifier_local,
                &dns_records_by_node,
                &dns_refresh_targets,
                dns_passphrase_remote.as_str(),
                &nodes_spec,
                &allow_spec,
            )?;
            next_coordination_refresh_ts =
                next_refresh_deadline(unix_now(), config.traversal_refresh_interval_secs);
            switch_ts = ts;
            logger.line(
                format!(
                    "[exit-handoff] switching client exit to {}",
                    config.exit_b_node_id
                )
                .as_str(),
            )?;
            pin_client_to_expected_exit(
                &config.ssh_identity_file,
                &work_known_hosts,
                &config.client_host,
                &config.exit_b_node_id,
            )?;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let client_status_final = status(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
    )?;
    let exit_a_status_final = status(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
    )?;
    let exit_b_status_final = status(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
    )?;
    let client_route_final = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "ip -4 route get 1.1.1.1 || true",
    )?;
    let client_wg_endpoints_final = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "wg show rustynet0 endpoints || true",
    )?;
    let selected_exit_peer_endpoint_final =
        status_field(&client_status_final, "selected_exit_peer_endpoint").unwrap_or("none");
    let selected_exit_peer_endpoint_error =
        status_field(&client_status_final, "selected_exit_peer_endpoint_error").unwrap_or("none");
    let cleanup_dns_refresh_cmd = format!(
        "rm -f {} {} {} {}",
        shell_quote(dns_passphrase_remote.as_str()),
        shell_quote(DNS_ZONE_RECORDS_REMOTE),
        shell_quote(DNS_ZONE_VALID_BUNDLE_REMOTE),
        shell_quote(DNS_ZONE_VERIFIER_REMOTE)
    );
    let _ = run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        cleanup_dns_refresh_cmd.as_str(),
    );
    let cleanup_dns_issue_dir_cmd = format!(
        "rmdir {} >/dev/null 2>&1 || true",
        shell_quote(DNS_ZONE_ISSUE_DIR)
    );
    let _ = run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        cleanup_dns_issue_dir_cmd.as_str(),
    );
    let exit_a_nft = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_a_host,
        "nft list ruleset || true",
    )?;
    let exit_b_nft = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        "nft list ruleset || true",
    )?;

    logger.line("[exit-handoff] final client status")?;
    logger.block(&(client_status_final.clone() + "\n"))?;
    logger.line("[exit-handoff] final exit A status")?;
    logger.block(&(exit_a_status_final.clone() + "\n"))?;
    logger.line("[exit-handoff] final exit B status")?;
    logger.block(&(exit_b_status_final.clone() + "\n"))?;
    logger.line("[exit-handoff] final client route")?;
    logger.block(&(client_route_final.clone() + "\n"))?;
    logger.line("[exit-handoff] final client selected exit peer endpoint")?;
    logger.block(&(selected_exit_peer_endpoint_final.to_owned() + "\n"))?;
    logger.line("[exit-handoff] final client wg endpoints (debug only)")?;
    logger.block(&(client_wg_endpoints_final.clone() + "\n"))?;

    let monitor_text = read_file(&monitor_path)?;
    let route_leak_count = monitor_text
        .lines()
        .filter(|line| !line.contains("route=") || !line.contains("dev rustynet0"))
        .count();
    let restricted_count = monitor_text
        .lines()
        .filter(|line| line.contains("restricted_safe_mode=true"))
        .count();
    let first_switch_ts = monitor_text.lines().find_map(|line| {
        let mut parts = line.split('|');
        let ts = parts.next()?.parse::<u64>().ok()?;
        if ts < switch_ts {
            return None;
        }
        line.contains(&format!("exit_node={}", config.exit_b_node_id))
            .then_some(ts)
    });
    let reconvergence_secs = first_switch_ts
        .and_then(|value| value.checked_sub(switch_ts))
        .map_or(-1, |value| value as i64);

    let check_handoff_reconvergence = if (0..=30).contains(&reconvergence_secs) {
        "pass"
    } else {
        "fail"
    };
    let check_no_route_leak = if route_leak_count == 0 {
        "pass"
    } else {
        "fail"
    };
    let check_no_restricted_safe_mode = if restricted_count == 0 {
        "pass"
    } else {
        "fail"
    };
    let check_exit_b_endpoint_visible = if selected_exit_peer_endpoint_error == "none"
        && selected_exit_peer_endpoint_final == format!("{exit_b_addr}:51820")
        && client_status_final.contains(&format!("exit_node={}", config.exit_b_node_id))
    {
        "pass"
    } else {
        "fail"
    };
    let check_both_exits_nat =
        if exit_a_nft.contains("masquerade") && exit_b_nft.contains("masquerade") {
            "pass"
        } else {
            "fail"
        };
    let check_managed_dns_fresh_all_nodes = if managed_dns_state_is_valid(&client_status_final)
        && managed_dns_state_is_valid(&exit_a_status_final)
        && managed_dns_state_is_valid(&exit_b_status_final)
    {
        "pass"
    } else {
        "fail"
    };

    let overall = [
        check_handoff_reconvergence,
        check_no_route_leak,
        check_no_restricted_safe_mode,
        check_exit_b_endpoint_visible,
        check_both_exits_nat,
        check_managed_dns_fresh_all_nodes,
    ]
    .into_iter()
    .all(|value| value == "pass");

    let captured_at_utc = utc_now_string();
    let captured_at_unix = unix_now();
    let git_commit = config.git_commit.unwrap_or_else(|| {
        git_head_commit(&root_dir).unwrap_or_else(|err| {
            eprintln!("{err}");
            std::process::exit(1);
        })
    });

    let report = format!(
        "{{\n  \"phase\": \"phase10\",\n  \"mode\": \"live_linux_exit_handoff\",\n  \"evidence_mode\": \"measured\",\n  \"captured_at\": \"{}\",\n  \"captured_at_unix\": {},\n  \"git_commit\": \"{}\",\n  \"status\": \"{}\",\n  \"exit_a_host\": \"{}\",\n  \"exit_b_host\": \"{}\",\n  \"client_host\": \"{}\",\n  \"switch_iteration\": {},\n  \"monitor_iterations\": {},\n  \"reconvergence_seconds\": {},\n  \"checks\": {{\n    \"handoff_reconvergence\": \"{}\",\n    \"no_route_leak_during_handoff\": \"{}\",\n    \"no_restricted_safe_mode\": \"{}\",\n    \"exit_b_endpoint_visible\": \"{}\",\n    \"both_exits_nat\": \"{}\",\n    \"managed_dns_fresh_all_nodes\": \"{}\"\n  }},\n  \"source_artifacts\": [\n    \"{}\",\n    \"{}\"\n  ]\n}}\n",
        captured_at_utc,
        captured_at_unix,
        git_commit,
        if overall { "pass" } else { "fail" },
        config.exit_a_host,
        config.exit_b_host,
        config.client_host,
        config.switch_iteration,
        config.monitor_iterations,
        reconvergence_secs,
        check_handoff_reconvergence,
        check_no_route_leak,
        check_no_restricted_safe_mode,
        check_exit_b_endpoint_visible,
        check_both_exits_nat,
        check_managed_dns_fresh_all_nodes,
        config.log_path.display(),
        config.monitor_log.display(),
    );
    write_file(&config.report_path, &report)?;
    logger.line(
        format!(
            "[exit-handoff] report written: {}",
            config.report_path.display()
        )
        .as_str(),
    )?;
    if !overall {
        return Err("exit-handoff validation failed".to_owned());
    }
    Ok(())
}

/// Target platform of the host running the active mesh exit role.
///
/// Today the live exit-handoff stages only have a fully-implemented
/// Linux validator (systemd + nftables + iproute2). The `--platform`
/// flag exists so the orchestrator's `stage_run_live_exit_handoff`
/// can dispatch per-platform symmetrically with
/// `stage_run_live_anchor`. Non-Linux platforms fail closed with an
/// honest "not yet enabled" message until the per-platform
/// validators land (Track B Phases 2 + 3). Mirrors the pattern in
/// `live_linux_anchor_test::AnchorPlatform`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitHandoffPlatform {
    Linux,
    MacOs,
    Windows,
}

impl ExitHandoffPlatform {
    #[cfg_attr(not(test), allow(dead_code))]
    fn as_str(self) -> &'static str {
        match self {
            ExitHandoffPlatform::Linux => "linux",
            ExitHandoffPlatform::MacOs => "macos",
            ExitHandoffPlatform::Windows => "windows",
        }
    }

    fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "linux" => Ok(ExitHandoffPlatform::Linux),
            "macos" | "darwin" => Ok(ExitHandoffPlatform::MacOs),
            "windows" => Ok(ExitHandoffPlatform::Windows),
            other => Err(format!(
                "unsupported --platform value {other:?}; expected linux|macos|windows"
            )),
        }
    }
}

#[derive(Debug)]
struct Config {
    platform: ExitHandoffPlatform,
    ssh_identity_file: PathBuf,
    exit_a_host: String,
    exit_b_host: String,
    client_host: String,
    exit_a_node_id: String,
    exit_b_node_id: String,
    client_node_id: String,
    ssh_allow_cidrs: String,
    switch_iteration: usize,
    monitor_iterations: usize,
    traversal_ttl_secs: u64,
    traversal_refresh_interval_secs: u64,
    report_path: PathBuf,
    log_path: PathBuf,
    monitor_log: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
    git_commit: Option<String>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: ExitHandoffPlatform::Linux,
            ssh_identity_file: PathBuf::new(),
            exit_a_host: "debian@192.168.18.49".to_owned(),
            exit_b_host: "mint@192.168.18.53".to_owned(),
            client_host: "debian@192.168.18.65".to_owned(),
            exit_a_node_id: "exit-49".to_owned(),
            exit_b_node_id: "client-53".to_owned(),
            client_node_id: "client-65".to_owned(),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            switch_iteration: 20,
            monitor_iterations: 55,
            traversal_ttl_secs: 120,
            traversal_refresh_interval_secs: 60,
            report_path: PathBuf::from("artifacts/phase10/live_linux_exit_handoff_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_exit_handoff.log"),
            monitor_log: PathBuf::from(
                "artifacts/phase10/source/live_linux_exit_handoff_monitor.log",
            ),
            pinned_known_hosts_file: None,
            git_commit: None,
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform =
                        ExitHandoffPlatform::parse(next_value(&mut iter, &arg)?.as_str())?;
                }
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--exit-a-host" => config.exit_a_host = next_value(&mut iter, &arg)?,
                "--exit-b-host" => config.exit_b_host = next_value(&mut iter, &arg)?,
                "--client-host" => config.client_host = next_value(&mut iter, &arg)?,
                "--exit-a-node-id" => config.exit_a_node_id = next_value(&mut iter, &arg)?,
                "--exit-b-node-id" => config.exit_b_node_id = next_value(&mut iter, &arg)?,
                "--client-node-id" => config.client_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--switch-iteration" => {
                    config.switch_iteration = next_value(&mut iter, &arg)?
                        .parse()
                        .map_err(|_| "switch iteration must be a positive integer".to_owned())?;
                }
                "--monitor-iterations" => {
                    config.monitor_iterations = next_value(&mut iter, &arg)?
                        .parse()
                        .map_err(|_| "monitor iterations must be a positive integer".to_owned())?;
                }
                "--traversal-ttl-secs" => {
                    config.traversal_ttl_secs = next_value(&mut iter, &arg)?
                        .parse()
                        .map_err(|_| "traversal ttl seconds must be an integer".to_owned())?;
                }
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--monitor-log" => config.monitor_log = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?));
                }
                "--git-commit" => config.git_commit = Some(next_value(&mut iter, &arg)?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_exit_handoff_test --ssh-identity-file <path> [options]"
                    .to_owned(),
            );
        }
        validate_positive_integer("switch iteration", config.switch_iteration)?;
        validate_positive_integer("monitor iterations", config.monitor_iterations)?;
        if config.traversal_ttl_secs == 0 || config.traversal_ttl_secs > 120 {
            return Err("traversal ttl seconds must be in the range 1..=120".to_owned());
        }
        config.traversal_refresh_interval_secs =
            traversal_refresh_interval_secs(config.traversal_ttl_secs);
        for (label, value) in [
            ("exit-a-host", config.exit_a_host.as_str()),
            ("exit-b-host", config.exit_b_host.as_str()),
            ("client-host", config.client_host.as_str()),
            ("exit-a-node-id", config.exit_a_node_id.as_str()),
            ("exit-b-node-id", config.exit_b_node_id.as_str()),
            ("client-node-id", config.client_node_id.as_str()),
            ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ] {
            ensure_safe_token(label, value)?;
        }
        Ok(config)
    }
}

fn traversal_refresh_interval_secs(traversal_ttl_secs: u64) -> u64 {
    let coordination_ttl_secs = traversal_ttl_secs.min(MAX_TRAVERSAL_COORDINATION_TTL_SECS);
    std::cmp::max(1, coordination_ttl_secs / 2)
}

fn next_refresh_deadline(now: u64, interval_secs: u64) -> u64 {
    now.saturating_add(std::cmp::max(1, interval_secs))
}

fn advance_periodic_refresh_deadline(previous_deadline: u64, interval_secs: u64, now: u64) -> u64 {
    let interval_secs = std::cmp::max(1, interval_secs);
    let mut next_deadline = previous_deadline.saturating_add(interval_secs);
    while next_deadline <= now {
        let advanced = next_deadline.saturating_add(interval_secs);
        if advanced == next_deadline {
            break;
        }
        next_deadline = advanced;
    }
    next_deadline
}

fn status_field<'a>(status: &'a str, key: &str) -> Option<&'a str> {
    let prefix = format!("{key}=");
    status
        .split_whitespace()
        .find_map(|field| field.strip_prefix(prefix.as_str()))
}

#[allow(clippy::too_many_arguments)]
fn refresh_traversal_bundles(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    exit_b_host: &str,
    client_host: &str,
    traversal_env: &Path,
    traversal_pub_local: &Path,
    exit_a_traversal_local: &Path,
    exit_b_traversal_local: &Path,
    client_traversal_local: &Path,
    exit_a_node_id: &str,
    exit_b_node_id: &str,
    client_node_id: &str,
) -> Result<(), String> {
    issue_traversal_bundles_from_env(
        identity,
        known_hosts,
        target,
        traversal_env,
        "/tmp/rn_issue_handoff_traversal.env",
    )?;
    capture_root_file_to_local(
        identity,
        known_hosts,
        target,
        "/run/rustynet/traversal-issue/rn-traversal.pub",
        traversal_pub_local,
    )?;
    capture_root_file_to_local(
        identity,
        known_hosts,
        target,
        &format!("/run/rustynet/traversal-issue/rn-traversal-{exit_a_node_id}.traversal"),
        exit_a_traversal_local,
    )?;
    capture_root_file_to_local(
        identity,
        known_hosts,
        target,
        &format!("/run/rustynet/traversal-issue/rn-traversal-{exit_b_node_id}.traversal"),
        exit_b_traversal_local,
    )?;
    capture_root_file_to_local(
        identity,
        known_hosts,
        target,
        &format!("/run/rustynet/traversal-issue/rn-traversal-{client_node_id}.traversal"),
        client_traversal_local,
    )?;
    install_traversal_bundle(
        identity,
        known_hosts,
        target,
        traversal_pub_local,
        exit_a_traversal_local,
    )?;
    install_traversal_bundle(
        identity,
        known_hosts,
        exit_b_host,
        traversal_pub_local,
        exit_b_traversal_local,
    )?;
    install_traversal_bundle(
        identity,
        known_hosts,
        client_host,
        traversal_pub_local,
        client_traversal_local,
    )?;
    refresh_signed_state(identity, known_hosts, target)?;
    refresh_signed_state(identity, known_hosts, exit_b_host)?;
    refresh_signed_state(identity, known_hosts, client_host)?;
    Ok(())
}

fn refresh_signed_state(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet state refresh",
    )
}

fn refresh_trust_evidence(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        "rustynet ops refresh-signed-trust",
    )
}

#[allow(clippy::too_many_arguments)]
fn refresh_handoff_coordination(
    identity: &Path,
    known_hosts: &Path,
    signer_host: &str,
    exit_b_host: &str,
    client_host: &str,
    traversal_env: &Path,
    traversal_pub_local: &Path,
    exit_a_traversal_local: &Path,
    exit_b_traversal_local: &Path,
    client_traversal_local: &Path,
    exit_a_node_id: &str,
    exit_b_node_id: &str,
    client_node_id: &str,
    verifier_local: &Path,
    records_by_node: &HashMap<String, String>,
    refresh_targets: &[ManagedDnsRefreshTarget],
    passphrase_remote: &str,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<(), String> {
    refresh_traversal_bundles(
        identity,
        known_hosts,
        signer_host,
        exit_b_host,
        client_host,
        traversal_env,
        traversal_pub_local,
        exit_a_traversal_local,
        exit_b_traversal_local,
        client_traversal_local,
        exit_a_node_id,
        exit_b_node_id,
        client_node_id,
    )?;
    refresh_dns_bundles(
        identity,
        known_hosts,
        signer_host,
        nodes_spec,
        allow_spec,
        passphrase_remote,
        verifier_local,
        records_by_node,
        refresh_targets,
    )?;
    for target in refresh_targets {
        // Keep trust evidence fresh immediately before the strict signed-state refresh.
        refresh_trust_evidence(identity, known_hosts, target.host.as_str())?;
        refresh_signed_state(identity, known_hosts, target.host.as_str())?;
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn refresh_dns_bundles(
    identity: &Path,
    known_hosts: &Path,
    signer_host: &str,
    nodes_spec: &str,
    allow_spec: &str,
    passphrase_remote: &str,
    verifier_local: &Path,
    records_by_node: &HashMap<String, String>,
    refresh_targets: &[ManagedDnsRefreshTarget],
) -> Result<(), String> {
    if refresh_targets.is_empty() {
        return Err("managed DNS refresh requires at least one target".to_owned());
    }
    let mut verifier_captured = false;
    for target in refresh_targets {
        let records_manifest = records_by_node.get(&target.node_id).ok_or_else(|| {
            format!(
                "missing scoped DNS records for exit handoff node {}",
                target.node_id
            )
        })?;
        write_file(target.records_local.as_path(), records_manifest)?;
        let records_remote = format!(
            "/tmp/rn-exit-handoff-dns-records-{}.manifest",
            target.node_id
        );
        scp_to(
            identity,
            known_hosts,
            target.records_local.as_path(),
            signer_host,
            records_remote.as_str(),
        )?;
        let issue_cmd = format!(
            "rustynet dns zone issue --signing-secret /etc/rustynet/membership.owner.key --signing-secret-passphrase-file {} --subject-node-id {} --nodes {} --allow {} --zone-name {} --records-manifest {} --output {} --verifier-key-output {}",
            shell_quote(passphrase_remote),
            shell_quote(target.node_id.as_str()),
            shell_quote(nodes_spec),
            shell_quote(allow_spec),
            shell_quote(DNS_ZONE_NAME),
            shell_quote(records_remote.as_str()),
            shell_quote(DNS_ZONE_VALID_BUNDLE_REMOTE),
            shell_quote(DNS_ZONE_VERIFIER_REMOTE),
        );
        run_root(identity, known_hosts, signer_host, issue_cmd.as_str())?;
        let cleanup_cmd = format!("rm -f {}", shell_quote(records_remote.as_str()));
        run_root(identity, known_hosts, signer_host, cleanup_cmd.as_str())?;
        if !verifier_captured {
            capture_root_file_to_local(
                identity,
                known_hosts,
                signer_host,
                DNS_ZONE_VERIFIER_REMOTE,
                verifier_local,
            )?;
            verifier_captured = true;
        }
        capture_root_file_to_local(
            identity,
            known_hosts,
            signer_host,
            DNS_ZONE_VALID_BUNDLE_REMOTE,
            target.bundle_local.as_path(),
        )?;
        install_dns_bundle(
            identity,
            known_hosts,
            target.host.as_str(),
            verifier_local,
            target.bundle_local.as_path(),
        )?;
    }
    Ok(())
}

fn managed_dns_refresh_targets(workspace: &Path, config: &Config) -> Vec<ManagedDnsRefreshTarget> {
    vec![
        ManagedDnsRefreshTarget {
            host: config.exit_a_host.clone(),
            node_id: config.exit_a_node_id.clone(),
            records_local: workspace.join("dns-zone-records-exit-a.json"),
            bundle_local: workspace.join("dns-zone-exit-a.bundle"),
        },
        ManagedDnsRefreshTarget {
            host: config.exit_b_host.clone(),
            node_id: config.exit_b_node_id.clone(),
            records_local: workspace.join("dns-zone-records-exit-b.json"),
            bundle_local: workspace.join("dns-zone-exit-b.bundle"),
        },
        ManagedDnsRefreshTarget {
            host: config.client_host.clone(),
            node_id: config.client_node_id.clone(),
            records_local: workspace.join("dns-zone-records-client.json"),
            bundle_local: workspace.join("dns-zone-client.bundle"),
        },
    ]
}

fn managed_dns_state_is_valid(status: &str) -> bool {
    status.contains("dns_zone_state=valid")
        && status.contains("dns_zone_error=none")
        && status.contains("dns_alarm_state=ok")
}

fn pin_client_to_expected_exit(
    identity: &Path,
    known_hosts: &Path,
    client_host: &str,
    expected_exit_node_id: &str,
) -> Result<(), String> {
    live_lab_support::apply_role_coupling(
        identity,
        known_hosts,
        client_host,
        "client",
        Some(expected_exit_node_id),
        false,
        ASSIGNMENT_REFRESH_ENV_PATH,
        "linux",
    )?;
    run_root(
        identity,
        known_hosts,
        client_host,
        "rustynet ops force-local-assignment-refresh-now",
    )
}

fn handoff_runtime_ready(status: &str) -> bool {
    status_field(status, "restricted_safe_mode") == Some("false")
        && status_field(status, "bootstrap_error") == Some("none")
        && status_field(status, "last_reconcile_error") == Some("none")
        && status_field(status, "state") != Some("FailClosed")
}

fn route_uses_rustynet0(route: &str) -> bool {
    route.contains("dev rustynet0")
}

fn handoff_monitor_prereqs_ready(
    client_status: &str,
    exit_a_status: &str,
    exit_b_status: &str,
    client_route: &str,
    exit_a_node_id: &str,
) -> bool {
    status_field(client_status, "exit_node") == Some(exit_a_node_id)
        && route_uses_rustynet0(client_route)
        && handoff_runtime_ready(client_status)
        && managed_dns_state_is_valid(client_status)
        && managed_dns_state_is_valid(exit_a_status)
        && managed_dns_state_is_valid(exit_b_status)
}

fn wait_for_handoff_monitor_expected_exit(
    logger: &mut Logger,
    config: &Config,
    known_hosts: &Path,
    expected_exit_node_id: &str,
) -> Result<(), String> {
    logger.line(
        format!(
            "[exit-handoff] waiting for protected-route convergence after coordination refresh on {}",
            expected_exit_node_id
        )
        .as_str(),
    )?;
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        known_hosts,
        &config.client_host,
        expected_exit_node_id,
    )?;
    let start_ts = unix_now();
    let mut last_client_status = String::new();
    let mut last_exit_a_status = String::new();
    let mut last_exit_b_status = String::new();
    let mut last_client_route = String::new();

    while unix_now().saturating_sub(start_ts) < HANDOFF_REFRESH_CONVERGENCE_TIMEOUT_SECS {
        last_client_status = status(&config.ssh_identity_file, known_hosts, &config.client_host)?;
        last_exit_a_status = status(&config.ssh_identity_file, known_hosts, &config.exit_a_host)?;
        last_exit_b_status = status(&config.ssh_identity_file, known_hosts, &config.exit_b_host)?;
        last_client_route = capture_root(
            &config.ssh_identity_file,
            known_hosts,
            &config.client_host,
            "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true",
        )?;

        if handoff_monitor_prereqs_ready(
            &last_client_status,
            &last_exit_a_status,
            &last_exit_b_status,
            &last_client_route,
            expected_exit_node_id,
        ) {
            return Ok(());
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Err(format!(
        "exit handoff protected-route convergence did not recover after coordination refresh within {}s for {}: client_route={} client_status={} exit_a_status={} exit_b_status={}",
        HANDOFF_REFRESH_CONVERGENCE_TIMEOUT_SECS,
        expected_exit_node_id,
        last_client_route.replace('\n', " "),
        last_client_status.replace('\n', " "),
        last_exit_a_status.replace('\n', " "),
        last_exit_b_status.replace('\n', " "),
    ))
}

#[allow(clippy::too_many_arguments)]
fn wait_for_handoff_monitor_prereqs(
    logger: &mut Logger,
    config: &Config,
    known_hosts: &Path,
    traversal_env: &Path,
    traversal_pub_local: &Path,
    exit_a_traversal_local: &Path,
    exit_b_traversal_local: &Path,
    client_traversal_local: &Path,
    dns_verifier_local: &Path,
    dns_records_by_node: &HashMap<String, String>,
    dns_refresh_targets: &[ManagedDnsRefreshTarget],
    dns_passphrase_remote: &str,
    nodes_spec: &str,
    allow_spec: &str,
) -> Result<(), String> {
    logger.line(
        "[exit-handoff] waiting for baseline exit route and managed DNS freshness before monitor",
    )?;
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        known_hosts,
        &config.client_host,
        &config.exit_a_node_id,
    )?;
    let start_ts = unix_now();
    let mut next_coordination_refresh_ts =
        next_refresh_deadline(start_ts, config.traversal_refresh_interval_secs);
    let mut last_client_status = String::new();
    let mut last_exit_a_status = String::new();
    let mut last_exit_b_status = String::new();
    let mut last_client_route = String::new();

    while unix_now().saturating_sub(start_ts) < HANDOFF_PRE_MONITOR_TIMEOUT_SECS {
        let ts = unix_now();
        if ts >= next_coordination_refresh_ts {
            logger.line(
                "[exit-handoff] refreshing signed handoff coordination during pre-monitor convergence",
            )?;
            refresh_handoff_coordination(
                &config.ssh_identity_file,
                known_hosts,
                &config.exit_a_host,
                &config.exit_b_host,
                &config.client_host,
                traversal_env,
                traversal_pub_local,
                exit_a_traversal_local,
                exit_b_traversal_local,
                client_traversal_local,
                &config.exit_a_node_id,
                &config.exit_b_node_id,
                &config.client_node_id,
                dns_verifier_local,
                dns_records_by_node,
                dns_refresh_targets,
                dns_passphrase_remote,
                nodes_spec,
                allow_spec,
            )?;
            pin_client_to_expected_exit(
                &config.ssh_identity_file,
                known_hosts,
                &config.client_host,
                &config.exit_a_node_id,
            )?;
            next_coordination_refresh_ts = advance_periodic_refresh_deadline(
                next_coordination_refresh_ts,
                config.traversal_refresh_interval_secs,
                unix_now(),
            );
        }

        last_client_status = status(&config.ssh_identity_file, known_hosts, &config.client_host)?;
        last_exit_a_status = status(&config.ssh_identity_file, known_hosts, &config.exit_a_host)?;
        last_exit_b_status = status(&config.ssh_identity_file, known_hosts, &config.exit_b_host)?;
        last_client_route = capture_root(
            &config.ssh_identity_file,
            known_hosts,
            &config.client_host,
            "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true",
        )?;

        if handoff_monitor_prereqs_ready(
            &last_client_status,
            &last_exit_a_status,
            &last_exit_b_status,
            &last_client_route,
            &config.exit_a_node_id,
        ) {
            return Ok(());
        }

        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    Err(format!(
        "exit handoff baseline did not converge before monitor within {}s: client_route={} client_status={} exit_a_status={} exit_b_status={}",
        HANDOFF_PRE_MONITOR_TIMEOUT_SECS,
        last_client_route.replace('\n', " "),
        last_client_status.replace('\n', " "),
        last_exit_a_status.replace('\n', " "),
        last_exit_b_status.replace('\n', " "),
    ))
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
            label: DNS_MANAGED_LABEL.to_owned(),
            target_node_id: signer_node_id.to_owned(),
            ttl_secs: 300,
            aliases: vec![DNS_MANAGED_ALIAS.to_owned()],
        },
        ManagedDnsRecordTemplate {
            label: "client".to_owned(),
            target_node_id: client_node_id.to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        },
    ]
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
                return Err("assignment bundle node_id must not be empty".to_owned());
            }
            node_id = Some(trimmed.to_owned());
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
            peer_node_ids.push(trimmed.to_owned());
        }
    }
    peer_node_ids.sort();
    peer_node_ids.dedup();
    Ok(AssignmentAuthorityScope {
        node_id: node_id.ok_or_else(|| "assignment bundle is missing node_id".to_owned())?,
        peer_node_ids,
    })
}

fn install_assignment_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    assignment_pub_local: &Path,
    assignment_bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        assignment_pub_local,
        target,
        "/tmp/rn-assignment.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        assignment_bundle_local,
        target,
        "/tmp/rn-assignment.bundle",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub && install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment && rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rn-assignment.pub /tmp/rn-assignment.bundle",
    )
}

fn install_dns_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    verifier_local: &Path,
    bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        verifier_local,
        target,
        "/tmp/rn-dns-zone.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        bundle_local,
        target,
        "/tmp/rn-dns-zone.bundle",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-dns-zone.pub /etc/rustynet/dns-zone.pub && install -m 0640 -o root -g rustynetd /tmp/rn-dns-zone.bundle /var/lib/rustynet/rustynetd.dns-zone && rm -f /var/lib/rustynet/rustynetd.dns-zone.watermark /tmp/rn-dns-zone.pub /tmp/rn-dns-zone.bundle",
    )
}

fn capture_root_file_to_local(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    remote_path: &str,
    local_path: &Path,
) -> Result<(), String> {
    let body = capture_root(
        identity,
        known_hosts,
        target,
        format!("cat {}", shell_quote(remote_path)).as_str(),
    )?;
    write_file(local_path, &body)
}

fn install_assignment_refresh_env(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    env_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        env_local,
        target,
        "/tmp/rn-assignment-refresh.env",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0600 -o root -g root /tmp/rn-assignment-refresh.env /etc/rustynet/assignment-refresh.env && rm -f /tmp/rn-assignment-refresh.env",
    )
}

fn install_traversal_bundle(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    traversal_pub_local: &Path,
    traversal_bundle_local: &Path,
) -> Result<(), String> {
    scp_to(
        identity,
        known_hosts,
        traversal_pub_local,
        target,
        "/tmp/rn-traversal.pub",
    )?;
    scp_to(
        identity,
        known_hosts,
        traversal_bundle_local,
        target,
        "/tmp/rn-traversal.bundle",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -d -m 0750 -o root -g rustynetd /etc/rustynet",
    )?;
    run_root(
        identity,
        known_hosts,
        target,
        "install -m 0644 -o root -g root /tmp/rn-traversal.pub /etc/rustynet/traversal.pub && install -m 0640 -o root -g rustynetd /tmp/rn-traversal.bundle /var/lib/rustynet/rustynetd.traversal && rm -f /var/lib/rustynet/rustynetd.traversal.watermark /tmp/rn-traversal.pub /tmp/rn-traversal.bundle",
    )
}

fn append_monitor_line(path: &Path, line: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("open monitor log failed ({}): {err}", path.display()))?;
    writeln!(file, "{line}").map_err(|err| format!("write monitor log failed: {err}"))
}

fn validate_positive_integer(name: &str, value: usize) -> Result<(), String> {
    if value == 0 {
        Err(format!("{name} must be a positive integer"))
    } else {
        Ok(())
    }
}

// ─── Track B Phase 4: macOS exit-handoff live validator ────────────
//
// Real (not scaffold) macOS exit-mode validator. Captures pf + sysctl
// state on the exit_a_host while the daemon is serving exit, stops
// the daemon via launchctl, re-captures, merges into the canonical
// macOS_exit_nat_lifecycle artifact shape, and asserts the same
// invariants `evaluate_macos_exit_nat_lifecycle_artifact` in
// `crates/rustynet-cli/src/vm_lab/mod.rs` enforces for static
// artifacts:
//
// * during_run:  pf anchor present, internal_prefix matches mesh_cidr,
//                tunnel_forwarding=Enabled, egress_forwarding=Enabled.
// * after_stop:  pf anchor removed, forwarding_restored=true (both
//                tunnel + egress sysctl back to Disabled).
//
// On any assertion failure the bin returns Err so the orchestrator's
// `assert_json_report_status_pass` helper surfaces the failure. The
// JSON report `status` is `pass` only when every assertion holds.
//
// The bin reuses the pure builder helpers from
// `rustynetd::macos_exit_nat_lifecycle` so the parser shape stays in
// lockstep with the daemon-side single-phase snapshot collector
// (`collect_macos_exit_nat_lifecycle_snapshot`) and the orchestrator-
// side merger (`merge_macos_exit_nat_lifecycle_artifact`).
// Constants are imported (not duplicated) so a future rename of the pf
// anchor or launchd label surfaces here as a compile break.
use rustynetd::macos_exit_nat_lifecycle::DEFAULT_MACOS_EXIT_PF_ANCHOR as MACOS_PF_ANCHOR;
use rustynetd::macos_service_hardening::REVIEWED_SERVICE_LABEL as MACOS_DAEMON_LAUNCHD_LABEL;

/// Report envelope matching the canonical live-lab shape consumed by
/// `ops_fresh_install_os_matrix::load_json_report`. The `lifecycle`
/// field carries the nested `during_run`/`after_stop` artefact built
/// by `merge_macos_exit_nat_lifecycle_artifact` so the schema stays
/// in lockstep with `evaluate_macos_exit_nat_lifecycle_artifact`.
#[derive(Debug, serde::Serialize)]
struct MacosExitHandoffReport {
    schema_version: u32,
    phase: &'static str,
    mode: &'static str,
    evidence_mode: &'static str,
    status: &'static str,
    platform: &'static str,
    captured_at: String,
    captured_at_unix: u64,
    git_commit: String,
    exit_host: String,
    exit_node_id: String,
    pf_anchor: String,
    mesh_cidr: String,
    daemon_restart_status: String,
    lifecycle: serde_json::Value,
    source_artifacts: Vec<String>,
    detail: String,
}

fn run_macos_exit_handoff(config: &Config) -> Result<(), String> {
    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;
    let workspace = create_workspace("macos-exit-handoff")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let exit_target = config.exit_a_host.as_str();
    // Preflight: explicit passwordless-sudo check so the first
    // pfctl/sysctl capture below fails with a precise diagnostic
    // instead of an opaque "ssh command failed... status 1".
    // verify_sudo (Linux) refuses hosts whose hostname is not in
    // /etc/hosts; macOS does not maintain that mapping, so use the
    // minimal helper that only probes `sudo -n -k true`.
    live_lab_support::verify_passwordless_sudo(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
    )?;

    let mesh_cidr = "100.64.0.0/10".to_owned(); // canonical Rustynet mesh CIDR

    // Phase 1: during-run snapshot. Capture pfctl anchor state +
    // sysctl forwarding while the daemon is serving exit. Both
    // captures are run via sudo so the helper has the privilege to
    // call /sbin/pfctl and read kernel sysctls.
    let during_pf = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!("/sbin/pfctl -a {} -s nat", MACOS_PF_ANCHOR),
    )
    .map_err(|err| format!("macos exit-handoff: during-run pfctl capture failed: {err}"))?;
    let during_sysctl = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        "/usr/sbin/sysctl -n net.inet.ip.forwarding",
    )
    .map_err(|err| {
        format!("macos exit-handoff: during-run sysctl forwarding capture failed: {err}")
    })?;
    let captured_at_during = unix_now() as i64;
    let during_snapshot =
        rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            captured_at_during,
            mesh_cidr.as_str(),
            MACOS_PF_ANCHOR,
            during_pf.as_str(),
            during_sysctl.as_str(),
        );

    // Phase 2: stop the daemon via launchctl so the killswitch
    // teardown path runs. `bootout` is the canonical macOS daemon
    // stop verb; we accept a non-zero exit code (daemon may already
    // be loaded under a different domain) but we DO require the
    // subsequent pfctl/sysctl captures to prove the cleanup happened.
    let _ = run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!(
            "/bin/launchctl bootout system/{} 2>/dev/null || /bin/launchctl unload /Library/LaunchDaemons/{}.plist 2>/dev/null || true",
            MACOS_DAEMON_LAUNCHD_LABEL, MACOS_DAEMON_LAUNCHD_LABEL
        ),
    );
    // Give the daemon a couple of seconds to release pf + sysctl.
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Phase 3: after-stop snapshot. Same captures; the validator
    // expects pf anchor gone + ip.forwarding back to 0.
    let after_pf = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!(
            "/sbin/pfctl -a {} -s nat 2>/dev/null || true",
            MACOS_PF_ANCHOR
        ),
    )
    .map_err(|err| format!("macos exit-handoff: after-stop pfctl capture failed: {err}"))?;
    let after_sysctl = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        "/usr/sbin/sysctl -n net.inet.ip.forwarding",
    )
    .map_err(|err| {
        format!("macos exit-handoff: after-stop sysctl forwarding capture failed: {err}")
    })?;
    let captured_at_after = unix_now() as i64;
    let after_snapshot =
        rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            captured_at_after,
            mesh_cidr.as_str(),
            MACOS_PF_ANCHOR,
            after_pf.as_str(),
            after_sysctl.as_str(),
        );

    // Phase 4: restart the daemon so subsequent stages (or the
    // operator) inherit a running mesh. Capture the restart outcome
    // so the operator sees a `restart_failed: <reason>` value rather
    // than a silently-stopped daemon under a passing report.
    let daemon_restart_status = match run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!(
            "/bin/launchctl bootstrap system /Library/LaunchDaemons/{}.plist 2>/dev/null || /bin/launchctl load /Library/LaunchDaemons/{}.plist",
            MACOS_DAEMON_LAUNCHD_LABEL, MACOS_DAEMON_LAUNCHD_LABEL
        ),
    ) {
        Ok(()) => "restarted".to_owned(),
        Err(err) => format!("restart_failed: {err}"),
    };

    // Phase 5: assert invariants. Mirror
    // `evaluate_macos_exit_nat_lifecycle_artifact` from vm_lab/mod.rs.
    // Each failure produces a precise diagnostic.
    let mut failures: Vec<String> = Vec::new();
    if !during_snapshot.pf_anchor_present {
        failures.push("during-run pf anchor was NOT present (daemon not serving exit?)".to_owned());
    }
    if during_snapshot.pf_anchor_present && during_snapshot.internal_prefix != mesh_cidr {
        failures.push(format!(
            "during-run pf NAT internal_prefix {:?} did not match mesh_cidr {:?}",
            during_snapshot.internal_prefix, mesh_cidr
        ));
    }
    if !during_snapshot
        .tunnel_forwarding
        .eq_ignore_ascii_case("enabled")
    {
        failures.push(format!(
            "during-run tunnel_forwarding {:?} expected 'Enabled'",
            during_snapshot.tunnel_forwarding
        ));
    }
    if !during_snapshot
        .egress_forwarding
        .eq_ignore_ascii_case("enabled")
    {
        failures.push(format!(
            "during-run egress_forwarding {:?} expected 'Enabled'",
            during_snapshot.egress_forwarding
        ));
    }
    if after_snapshot.pf_anchor_present {
        failures.push(
            "after-stop pf anchor was STILL present (daemon teardown leaked the anchor)".to_owned(),
        );
    }
    let forwarding_restored = after_snapshot
        .tunnel_forwarding
        .eq_ignore_ascii_case("disabled")
        && after_snapshot
            .egress_forwarding
            .eq_ignore_ascii_case("disabled");
    if !forwarding_restored {
        failures.push(format!(
            "after-stop forwarding NOT restored (tunnel={:?}, egress={:?})",
            after_snapshot.tunnel_forwarding, after_snapshot.egress_forwarding
        ));
    }
    // Reviewer-flagged regression: the restart phase must assert
    // success, not just capture the outcome. A silent launchctl
    // bootstrap failure left the macOS exit daemon offline under a
    // passing status.
    if daemon_restart_status.starts_with("restart_failed:") {
        failures.push(format!(
            "post-test launchctl bootstrap failed; macOS exit daemon is OFFLINE — {}",
            daemon_restart_status
        ));
    }

    let status = if failures.is_empty() { "pass" } else { "fail" };
    let detail = if failures.is_empty() {
        "all invariants held".to_owned()
    } else {
        failures.join("; ")
    };

    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        live_lab_support::repo_root()?.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        live_lab_support::repo_root()?.join(&config.report_path)
    };
    let root_dir = live_lab_support::repo_root()?;
    let git_commit = config
        .git_commit
        .clone()
        .unwrap_or_else(|| git_head_commit(&root_dir).unwrap_or_else(|_| "unknown".to_owned()));
    let lifecycle = rustynetd::macos_exit_nat_lifecycle::merge_macos_exit_nat_lifecycle_artifact(
        &during_snapshot,
        &after_snapshot,
    );
    let report = MacosExitHandoffReport {
        schema_version: 1,
        phase: "phase10",
        mode: "live_macos_exit_handoff",
        evidence_mode: "measured",
        status,
        platform: "macos",
        captured_at: utc_now_string(),
        captured_at_unix: captured_at_after as u64,
        git_commit,
        exit_host: config.exit_a_host.clone(),
        exit_node_id: config.exit_a_node_id.clone(),
        pf_anchor: MACOS_PF_ANCHOR.to_owned(),
        mesh_cidr,
        daemon_restart_status,
        lifecycle,
        source_artifacts: vec![log_path.display().to_string()],
        detail: detail.clone(),
    };
    let _ = captured_at_during; // captured_at_unix carries after timestamp
    let _ = forwarding_restored; // surfaced via merged lifecycle
    let mut body = serde_json::to_string(&report)
        .map_err(|err| format!("serialize macos exit-handoff report failed: {err}"))?;
    body.push('\n');
    write_file(&report_path, body.as_str())?;

    let log_body = format!(
        "[macos-exit-handoff] status={status} exit_host={} exit_node_id={} detail={}\n",
        config.exit_a_host, config.exit_a_node_id, detail
    );
    write_file(&log_path, log_body.as_str())?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "macos exit-handoff invariants failed: {}",
            failures.join("; ")
        ))
    }
}

// ─── Track B Phase 5: Windows exit-handoff live validator ──────────
//
// Mirrors run_macos_exit_handoff but uses PowerShell-over-SSH and
// the existing `rustynetd::windows_exit_nat_lifecycle` builder.
// Captures Get-NetNat + Get-NetIPInterface forwarding state for the
// tunnel + egress interfaces, stops the SCM service, re-captures,
// asserts that NetNat is gone + forwarding restored. Schema mirrors
// the canonical envelope and embeds `merge_windows_exit_nat_lifecycle_artifact`
// so a future change to the orchestrator-side evaluator surfaces here.
use rustynetd::windows_exit_nat_lifecycle::DEFAULT_WINDOWS_EXIT_NAT_NAME as WINDOWS_NAT_NAME;
use rustynetd::windows_exit_nat_lifecycle::DEFAULT_WINDOWS_TUNNEL_ALIAS as WINDOWS_TUNNEL_ALIAS;
const WINDOWS_SCM_SERVICE: &str = "rustynetd";

/// Sanitize an interface alias that came back from a previous SSH
/// PowerShell capture so it is safe to embed inside the
/// single-quoted PowerShell argument of the follow-up
/// `Get-NetIPInterface -InterfaceAlias '<alias>' ...` invocation.
/// A compromised target host could otherwise return an alias
/// containing `'`, `;`, `"`, newline, etc. to break out of the
/// quote and inject shell commands. CLAUDE.md mandates no shell
/// construction with untrusted values.
///
/// PowerShell interface aliases are localized on non-English
/// Windows hosts (e.g. `イーサネット`, `Ethernet-Verbindung`), so an
/// ASCII-only allowlist would surface those healthy interfaces as
/// missing. We use a denylist: reject the bytes that have meaning
/// to PowerShell single-quote parsing or could terminate the outer
/// ssh-bash command, plus any C0/C1 control character. Everything
/// else — including non-ASCII letters/digits, paren / dot / dash /
/// underscore / space — survives.
///
/// Length cap of 96 bytes mirrors the PowerShell InterfaceAlias
/// maximum and keeps a single capture's failure from being able to
/// inflate the formatted command beyond the SSH argv budget.
fn sanitize_windows_interface_alias(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.len() > 96 {
        return String::new();
    }
    const FORBIDDEN: &[char] = &[
        '\'', '"', '`', '$', ';', '|', '&', '<', '>', '\\', '{', '}', '\n', '\r', '\t', '\0',
    ];
    if trimmed
        .chars()
        .any(|ch| ch.is_control() || FORBIDDEN.contains(&ch))
    {
        return String::new();
    }
    trimmed.to_owned()
}

#[derive(Debug, serde::Serialize)]
struct WindowsExitHandoffReport {
    schema_version: u32,
    phase: &'static str,
    mode: &'static str,
    evidence_mode: &'static str,
    status: &'static str,
    platform: &'static str,
    captured_at: String,
    captured_at_unix: u64,
    git_commit: String,
    exit_host: String,
    exit_node_id: String,
    nat_name: String,
    tunnel_alias: String,
    mesh_cidr: String,
    daemon_restart_status: String,
    lifecycle: serde_json::Value,
    source_artifacts: Vec<String>,
    detail: String,
}

fn run_windows_exit_handoff(config: &Config) -> Result<(), String> {
    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;
    let workspace = create_workspace("windows-exit-handoff")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let exit_target = config.exit_a_host.as_str();
    // Preflight: confirm SSH session is in BUILTIN\Administrators
    // before any NetNat/SCM command runs. Without admin rights those
    // commands return access-denied opaquely.
    live_lab_support::verify_windows_admin(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
    )?;
    let mesh_cidr = "100.64.0.0/10".to_owned();
    let options = rustynetd::windows_exit_nat_lifecycle::WindowsExitNatLifecycleOptions {
        mesh_cidr: mesh_cidr.clone(),
        nat_name: WINDOWS_NAT_NAME.to_owned(),
        tunnel_alias: WINDOWS_TUNNEL_ALIAS.to_owned(),
    };

    // PowerShell capture commands — invoked via SSH against a
    // Windows host where the SSH user is Administrator. Each line is
    // a single PowerShell expression with -NoProfile -Command for
    // hermetic behaviour. Use Compress for compact JSON so the
    // builder's parse_netnat_json can consume it deterministically.
    // `Out-String -Width 32767` keeps PowerShell's default
    // Out-Default formatter from wrapping the JSON at host width
    // (~80 in non-interactive SSH). ConvertTo-Json -Compress emits
    // a single line but the rendering stage still wraps; the
    // explicit Out-String + max-int width prevents the parser from
    // seeing a truncated JSON body. Width-32767 matches the safer
    // default the Phase 14 reviewer recommended over 4096 for
    // long-lived per-host status lines.
    let netnat_cmd = format!(
        "powershell -NoProfile -Command \"Get-NetNat -Name '{}' -ErrorAction SilentlyContinue | ConvertTo-Json -Depth 4 -Compress | Out-String -Width 32767\"",
        WINDOWS_NAT_NAME
    );
    let tunnel_forwarding_cmd = format!(
        "powershell -NoProfile -Command \"(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Forwarding\"",
        WINDOWS_TUNNEL_ALIAS
    );
    let egress_alias_cmd = format!(
        "powershell -NoProfile -Command \"(Get-NetIPInterface -AddressFamily IPv4 -ConnectionState Connected | Where-Object {{ $_.InterfaceAlias -ne '{}' }} | Sort-Object InterfaceMetric | Select-Object -First 1).InterfaceAlias\"",
        WINDOWS_TUNNEL_ALIAS
    );
    let portproxy_cmd = "netsh interface portproxy show all".to_owned();

    // During-run captures.
    let netnat_json_during = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        netnat_cmd.as_str(),
    )
    .map_err(|err| format!("windows exit-handoff: during-run Get-NetNat capture failed: {err}"))?;
    let tunnel_fwd_during = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        tunnel_forwarding_cmd.as_str(),
    )
    .map_err(|err| {
        format!("windows exit-handoff: during-run tunnel forwarding capture failed: {err}")
    })?;
    let egress_alias_during_raw = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        egress_alias_cmd.as_str(),
    )
    .unwrap_or_default();
    let egress_alias_during = sanitize_windows_interface_alias(egress_alias_during_raw.as_str());
    let egress_fwd_during = if egress_alias_during.is_empty() {
        "Error: no non-tunnel default egress interface detected".to_owned()
    } else {
        let cmd = format!(
            "powershell -NoProfile -Command \"(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Forwarding\"",
            egress_alias_during
        );
        live_lab_support::capture_remote_stdout(
            &config.ssh_identity_file,
            &work_known_hosts,
            exit_target,
            cmd.as_str(),
        )
        .unwrap_or_default()
    };
    let portproxy_during = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        portproxy_cmd.as_str(),
    )
    .unwrap_or_default();
    let captured_at_during = unix_now() as i64;
    let during_snapshot =
        rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
            captured_at_during,
            &options,
            netnat_json_during.as_str(),
            tunnel_fwd_during.as_str(),
            egress_fwd_during.as_str(),
            egress_alias_during.as_str(),
            portproxy_during.as_str(),
        )
        .map_err(|err| format!("windows exit-handoff: during-run snapshot build failed: {err}"))?;

    // Stop the SCM service so the daemon's exit-mode teardown runs.
    let _ = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!(
            "powershell -NoProfile -Command \"Stop-Service -Name '{}' -Force -ErrorAction SilentlyContinue\"",
            WINDOWS_SCM_SERVICE
        ),
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    // After-stop captures.
    let netnat_json_after = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        netnat_cmd.as_str(),
    )
    .unwrap_or_default();
    let tunnel_fwd_after = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        tunnel_forwarding_cmd.as_str(),
    )
    .unwrap_or_else(|_| "Disabled".to_owned());
    let egress_alias_after_raw = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        egress_alias_cmd.as_str(),
    )
    .unwrap_or_default();
    let egress_alias_after = sanitize_windows_interface_alias(egress_alias_after_raw.as_str());
    let egress_fwd_after = if egress_alias_after.is_empty() {
        "Disabled".to_owned()
    } else {
        let cmd = format!(
            "powershell -NoProfile -Command \"(Get-NetIPInterface -InterfaceAlias '{}' -AddressFamily IPv4 -ErrorAction SilentlyContinue).Forwarding\"",
            egress_alias_after
        );
        live_lab_support::capture_remote_stdout(
            &config.ssh_identity_file,
            &work_known_hosts,
            exit_target,
            cmd.as_str(),
        )
        .unwrap_or_else(|_| "Disabled".to_owned())
    };
    let portproxy_after = live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        portproxy_cmd.as_str(),
    )
    .unwrap_or_default();
    let captured_at_after = unix_now() as i64;
    let after_snapshot =
        rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
            captured_at_after,
            &options,
            netnat_json_after.as_str(),
            tunnel_fwd_after.as_str(),
            egress_fwd_after.as_str(),
            egress_alias_after.as_str(),
            portproxy_after.as_str(),
        )
        .map_err(|err| format!("windows exit-handoff: after-stop snapshot build failed: {err}"))?;

    // Restart the SCM service. Capture the outcome so the operator
    // sees `restart_failed: <reason>` rather than a silently-stopped
    // service under a passing report.
    let daemon_restart_status = match live_lab_support::capture_remote_stdout(
        &config.ssh_identity_file,
        &work_known_hosts,
        exit_target,
        &format!(
            "powershell -NoProfile -Command \"Start-Service -Name '{}'\"",
            WINDOWS_SCM_SERVICE
        ),
    ) {
        Ok(_) => "restarted".to_owned(),
        Err(err) => format!("restart_failed: {err}"),
    };

    // Assert invariants — mirrors the macOS shape.
    let mut failures: Vec<String> = Vec::new();
    if !during_snapshot.netnat_present {
        failures
            .push("during-run NetNat object was NOT present (daemon not serving exit?)".to_owned());
    }
    if during_snapshot.netnat_present && during_snapshot.internal_prefix != mesh_cidr {
        failures.push(format!(
            "during-run NetNat internal_prefix {:?} did not match mesh_cidr {:?}",
            during_snapshot.internal_prefix, mesh_cidr
        ));
    }
    if !during_snapshot
        .tunnel_forwarding
        .eq_ignore_ascii_case("Enabled")
    {
        failures.push(format!(
            "during-run tunnel_forwarding {:?} expected 'Enabled'",
            during_snapshot.tunnel_forwarding
        ));
    }
    if !during_snapshot
        .egress_forwarding
        .eq_ignore_ascii_case("Enabled")
    {
        failures.push(format!(
            "during-run egress_forwarding {:?} expected 'Enabled'",
            during_snapshot.egress_forwarding
        ));
    }
    if after_snapshot.netnat_present {
        failures.push(
            "after-stop NetNat object was STILL present (daemon teardown leaked it)".to_owned(),
        );
    }
    let forwarding_restored = !after_snapshot
        .tunnel_forwarding
        .eq_ignore_ascii_case("Enabled")
        && !after_snapshot
            .egress_forwarding
            .eq_ignore_ascii_case("Enabled");
    if !forwarding_restored {
        failures.push(format!(
            "after-stop forwarding NOT restored (tunnel={:?}, egress={:?})",
            after_snapshot.tunnel_forwarding, after_snapshot.egress_forwarding
        ));
    }
    // Reviewer-flagged regression: the restart phase must assert
    // success, not just capture the outcome. A silent SCM restart
    // failure left the Windows exit daemon offline under a passing
    // status.
    if daemon_restart_status.starts_with("restart_failed:") {
        failures.push(format!(
            "post-test Start-Service failed; Windows exit daemon is OFFLINE — {}",
            daemon_restart_status
        ));
    }

    let status = if failures.is_empty() { "pass" } else { "fail" };
    let detail = if failures.is_empty() {
        "all invariants held".to_owned()
    } else {
        failures.join("; ")
    };

    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        live_lab_support::repo_root()?.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        live_lab_support::repo_root()?.join(&config.report_path)
    };
    let root_dir = live_lab_support::repo_root()?;
    let git_commit = config
        .git_commit
        .clone()
        .unwrap_or_else(|| git_head_commit(&root_dir).unwrap_or_else(|_| "unknown".to_owned()));
    let lifecycle =
        rustynetd::windows_exit_nat_lifecycle::merge_windows_exit_nat_lifecycle_artifact(
            &during_snapshot,
            &after_snapshot,
        );
    let report = WindowsExitHandoffReport {
        schema_version: 1,
        phase: "phase10",
        mode: "live_windows_exit_handoff",
        evidence_mode: "measured",
        status,
        platform: "windows",
        captured_at: utc_now_string(),
        captured_at_unix: captured_at_after as u64,
        git_commit,
        exit_host: config.exit_a_host.clone(),
        exit_node_id: config.exit_a_node_id.clone(),
        nat_name: WINDOWS_NAT_NAME.to_owned(),
        tunnel_alias: WINDOWS_TUNNEL_ALIAS.to_owned(),
        mesh_cidr,
        daemon_restart_status,
        lifecycle,
        source_artifacts: vec![log_path.display().to_string()],
        detail: detail.clone(),
    };
    let _ = captured_at_during;
    let _ = forwarding_restored;
    let mut body = serde_json::to_string(&report)
        .map_err(|err| format!("serialize windows exit-handoff report failed: {err}"))?;
    body.push('\n');
    write_file(&report_path, body.as_str())?;
    let log_body = format!(
        "[windows-exit-handoff] status={status} exit_host={} exit_node_id={} detail={}\n",
        config.exit_a_host, config.exit_a_node_id, detail
    );
    write_file(&log_path, log_body.as_str())?;
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "windows exit-handoff invariants failed: {}",
            failures.join("; ")
        ))
    }
}

fn validate_identity(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing ssh identity file: {}", path.display()));
    }
    if path.is_symlink() {
        return Err(format!(
            "ssh identity file must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("{flag} requires a value"))
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_exit_handoff_test --ssh-identity-file <path> [options]\n\noptions:\n  --exit-a-host <user@host>\n  --exit-b-host <user@host>\n  --client-host <user@host>\n  --exit-a-node-id <id>\n  --exit-b-node-id <id>\n  --client-node-id <id>\n  --ssh-allow-cidrs <cidrs>\n  --switch-iteration <n>\n  --monitor-iterations <n>\n  --traversal-ttl-secs <n>\n  --report-path <path>\n  --log-path <path>\n  --monitor-log <path>\n  --known-hosts <path>\n  --git-commit <sha>"
    );
}

fn utc_now_string() -> String {
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{
        Config, handoff_monitor_prereqs_ready, handoff_runtime_ready, managed_dns_base_records,
        managed_dns_records_manifest_for_scope, managed_dns_refresh_targets,
        managed_dns_state_is_valid, parse_assignment_authority_scope, route_uses_rustynet0,
    };
    use std::path::{Path, PathBuf};

    fn sample_config() -> Config {
        Config {
            platform: super::ExitHandoffPlatform::Linux,
            ssh_identity_file: PathBuf::from("/tmp/id"),
            exit_a_host: "debian@192.168.128.22".to_owned(),
            exit_b_host: "debian@192.168.128.26".to_owned(),
            client_host: "debian@192.168.128.24".to_owned(),
            exit_a_node_id: "exit-1".to_owned(),
            exit_b_node_id: "client-2".to_owned(),
            client_node_id: "client-1".to_owned(),
            ssh_allow_cidrs: "192.168.128.0/24".to_owned(),
            switch_iteration: 20,
            monitor_iterations: 55,
            traversal_ttl_secs: 120,
            traversal_refresh_interval_secs: 15,
            report_path: PathBuf::from("report.json"),
            log_path: PathBuf::from("handoff.log"),
            monitor_log: PathBuf::from("handoff-monitor.log"),
            pinned_known_hosts_file: None,
            git_commit: None,
        }
    }

    #[test]
    fn managed_dns_refresh_targets_cover_both_exits_and_client() {
        let targets = managed_dns_refresh_targets(Path::new("/tmp/exit-handoff"), &sample_config());
        assert_eq!(targets.len(), 3);
        assert_eq!(targets[0].host, "debian@192.168.128.22");
        assert_eq!(targets[0].node_id, "exit-1");
        assert_eq!(
            targets[0].bundle_local,
            Path::new("/tmp/exit-handoff").join("dns-zone-exit-a.bundle")
        );
        assert_eq!(targets[1].host, "debian@192.168.128.26");
        assert_eq!(targets[1].node_id, "client-2");
        assert_eq!(
            targets[1].bundle_local,
            Path::new("/tmp/exit-handoff").join("dns-zone-exit-b.bundle")
        );
        assert_eq!(targets[2].host, "debian@192.168.128.24");
        assert_eq!(targets[2].node_id, "client-1");
        assert_eq!(
            targets[2].bundle_local,
            Path::new("/tmp/exit-handoff").join("dns-zone-client.bundle")
        );
    }

    #[test]
    fn managed_dns_state_validator_requires_valid_and_alarm_ok() {
        assert!(managed_dns_state_is_valid(
            "dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok"
        ));
        assert!(!managed_dns_state_is_valid(
            "dns_zone_state=invalid dns_zone_error=dns_zone_bundle_is_stale dns_alarm_state=error"
        ));
        assert!(!managed_dns_state_is_valid(
            "dns_zone_state=valid dns_zone_error=none dns_alarm_state=error"
        ));
    }

    #[test]
    fn handoff_runtime_ready_requires_non_restricted_non_failclosed_state() {
        assert!(handoff_runtime_ready(
            "state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none"
        ));
        assert!(!handoff_runtime_ready(
            "state=ExitActive restricted_safe_mode=true bootstrap_error=none last_reconcile_error=none"
        ));
        assert!(!handoff_runtime_ready(
            "state=FailClosed restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none"
        ));
        assert!(!handoff_runtime_ready(
            "state=ExitActive restricted_safe_mode=false bootstrap_error=traversal_sync_failed last_reconcile_error=none"
        ));
        assert!(!handoff_runtime_ready(
            "state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=route_apply_failed"
        ));
    }

    #[test]
    fn parse_assignment_authority_scope_collects_subject_and_peers() {
        let bundle = "\
node_id=exit-1
peer.0.node_id=client-1
peer.1.node_id=client-2
peer.1.endpoint=192.168.128.26:51820
";
        let scope =
            parse_assignment_authority_scope(bundle).expect("assignment authority should parse");
        assert_eq!(scope.node_id, "exit-1");
        assert_eq!(
            scope.peer_node_ids,
            vec!["client-1".to_owned(), "client-2".to_owned()]
        );
    }

    #[test]
    fn managed_dns_records_manifest_for_scope_filters_unauthorized_targets() {
        let scope = parse_assignment_authority_scope(
            "node_id=exit-1\npeer.0.node_id=client-1\npeer.1.node_id=client-2\n",
        )
        .expect("scope should parse");
        let mut records = managed_dns_base_records("exit-1", "client-1");
        records.push(super::ManagedDnsRecordTemplate {
            label: "unauthorized".to_owned(),
            target_node_id: "client-9".to_owned(),
            ttl_secs: 300,
            aliases: Vec::new(),
        });
        let filtered = managed_dns_records_manifest_for_scope(&records, &scope)
            .expect("records should filter");
        assert!(filtered.contains("record.0.target_node_id=exit-1"));
        assert!(filtered.contains("record.1.target_node_id=client-1"));
        assert!(!filtered.contains("client-9"));
    }

    #[test]
    fn traversal_refresh_interval_is_capped_by_coordination_ttl() {
        assert_eq!(super::traversal_refresh_interval_secs(120), 15);
        assert_eq!(super::traversal_refresh_interval_secs(30), 15);
        assert_eq!(super::traversal_refresh_interval_secs(20), 10);
        assert_eq!(super::traversal_refresh_interval_secs(1), 1);
    }

    #[test]
    fn next_refresh_deadline_uses_interval_from_current_time() {
        assert_eq!(super::next_refresh_deadline(100, 15), 115);
        assert_eq!(super::next_refresh_deadline(100, 0), 101);
    }

    #[test]
    fn advance_periodic_refresh_deadline_keeps_schedule_from_due_time() {
        assert_eq!(super::advance_periodic_refresh_deadline(115, 15, 122), 130);
        assert_eq!(super::advance_periodic_refresh_deadline(115, 15, 145), 160);
    }

    #[test]
    fn status_field_extracts_selected_exit_peer_endpoint() {
        let status = "node_id=client-1 exit_node=client-2 selected_exit_peer_endpoint=192.168.64.26:51820 selected_exit_peer_endpoint_error=none";
        assert_eq!(
            super::status_field(status, "selected_exit_peer_endpoint"),
            Some("192.168.64.26:51820")
        );
        assert_eq!(
            super::status_field(status, "selected_exit_peer_endpoint_error"),
            Some("none")
        );
        assert_eq!(super::status_field(status, "missing"), None);
    }

    #[test]
    fn route_uses_rustynet0_requires_tunnel_device() {
        assert!(route_uses_rustynet0(
            "1.1.1.1 dev rustynet0 table 51820 src 100.64.0.10 uid 0"
        ));
        assert!(!route_uses_rustynet0(
            "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.24 uid 0"
        ));
    }

    #[test]
    fn handoff_monitor_prereqs_require_exit_a_route_and_fresh_dns() {
        let client_status = "exit_node=exit-1 state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok";
        let exit_a_status = "dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok";
        let exit_b_status = "dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok";
        let route = "1.1.1.1 dev rustynet0 table 51820 src 100.64.0.10 uid 0";
        assert!(handoff_monitor_prereqs_ready(
            client_status,
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
        ));
        assert!(!handoff_monitor_prereqs_ready(
            client_status,
            exit_a_status,
            exit_b_status,
            "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.24 uid 0",
            "exit-1",
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=exit-1 state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=invalid dns_zone_error=dns_zone_bundle_is_stale dns_alarm_state=error",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=client-2 state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=exit-1 state=FailClosed restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
        ));
    }

    #[test]
    fn exit_handoff_source_contains_explicit_trust_refresh_before_state_refresh() {
        let source_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bin/live_linux_exit_handoff_test.rs");
        let source = std::fs::read_to_string(&source_path)
            .expect("live exit handoff source should be readable");
        let trust_idx = source
            .find("refresh_trust_evidence(identity, known_hosts, target.host.as_str())")
            .expect("source should refresh trust evidence inside handoff coordination");
        let state_idx = source
            .find("refresh_signed_state(identity, known_hosts, target.host.as_str())")
            .expect("source should refresh signed state inside handoff coordination");
        assert!(
            trust_idx < state_idx,
            "trust refresh must happen before signed state refresh in handoff coordination"
        );
    }

    // ─── Track B Phase 1: --platform parser + dispatcher fabric ──

    #[test]
    fn platform_parser_accepts_canonical_strings() {
        assert_eq!(
            super::ExitHandoffPlatform::parse("linux").unwrap(),
            super::ExitHandoffPlatform::Linux
        );
        assert_eq!(
            super::ExitHandoffPlatform::parse("MacOS").unwrap(),
            super::ExitHandoffPlatform::MacOs
        );
        assert_eq!(
            super::ExitHandoffPlatform::parse("darwin").unwrap(),
            super::ExitHandoffPlatform::MacOs
        );
        assert_eq!(
            super::ExitHandoffPlatform::parse("WINDOWS").unwrap(),
            super::ExitHandoffPlatform::Windows
        );
    }

    #[test]
    fn platform_parser_rejects_garbage() {
        let err = super::ExitHandoffPlatform::parse("freebsd").expect_err("garbage rejected");
        assert!(err.contains("unsupported --platform"));
    }

    #[test]
    fn platform_as_str_matches_canonical_form() {
        assert_eq!(super::ExitHandoffPlatform::Linux.as_str(), "linux");
        assert_eq!(super::ExitHandoffPlatform::MacOs.as_str(), "macos");
        assert_eq!(super::ExitHandoffPlatform::Windows.as_str(), "windows");
    }

    // ─── Track B Phase 4: macOS exit-handoff validator ────────────
    //
    // The macOS run_macos_exit_handoff function is end-to-end SSH-
    // driven and can't be exercised hermetically here, but the
    // snapshot-parsing helpers it relies on (the
    // `build_macos_exit_nat_lifecycle_snapshot` builder from
    // `rustynetd::macos_exit_nat_lifecycle`) are pure-input. Pin the
    // expected parser behaviour for the EXACT pfctl + sysctl outputs
    // the bin captures so a future refactor of either side surfaces
    // here.

    #[test]
    fn macos_during_run_capture_parses_pf_anchor_present() {
        let pfctl_output = "nat-anchor \"com.rustynet/nat\" all\nnat on en0 inet from 100.64.0.0/10 to any -> en0:0\n";
        let snapshot = rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            100,
            "100.64.0.0/10",
            "com.rustynet/nat",
            pfctl_output,
            "1\n",
        );
        assert!(
            snapshot.pf_anchor_present,
            "pf anchor must parse as present"
        );
        assert_eq!(snapshot.internal_prefix, "100.64.0.0/10");
        assert_eq!(snapshot.tunnel_forwarding, "Enabled");
        assert_eq!(snapshot.egress_forwarding, "Enabled");
    }

    #[test]
    fn macos_after_stop_capture_parses_anchor_absent_and_forwarding_disabled() {
        let snapshot = rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            200,
            "100.64.0.0/10",
            "com.rustynet/nat",
            "",
            "0\n",
        );
        assert!(
            !snapshot.pf_anchor_present,
            "empty pfctl output must parse as anchor-absent"
        );
        assert_eq!(snapshot.tunnel_forwarding, "Disabled");
        assert_eq!(snapshot.egress_forwarding, "Disabled");
    }

    fn macos_lifecycle_artifact_fixture(during_present: bool, restored: bool) -> serde_json::Value {
        let during = rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            100,
            "100.64.0.0/10",
            "com.rustynet/nat",
            if during_present {
                "nat-anchor \"com.rustynet/nat\" all\nnat on en0 inet from 100.64.0.0/10 to any -> en0:0\n"
            } else {
                ""
            },
            "1\n",
        );
        let after = rustynetd::macos_exit_nat_lifecycle::build_macos_exit_nat_lifecycle_snapshot(
            200,
            "100.64.0.0/10",
            "com.rustynet/nat",
            "",
            if restored { "0\n" } else { "1\n" },
        );
        rustynetd::macos_exit_nat_lifecycle::merge_macos_exit_nat_lifecycle_artifact(
            &during, &after,
        )
    }

    #[test]
    fn macos_exit_handoff_report_serializes_with_serde() {
        // The report struct must round-trip through serde_json so a
        // malicious operator-supplied exit_host string can't break
        // the report parser downstream. Envelope mirrors the canonical
        // live-lab shape consumed by `ops_fresh_install_os_matrix::load_json_report`.
        let report = super::MacosExitHandoffReport {
            schema_version: 1,
            phase: "phase10",
            mode: "live_macos_exit_handoff",
            evidence_mode: "measured",
            status: "fail",
            platform: "macos",
            captured_at: "1970-01-01T00:00:00Z".to_owned(),
            captured_at_unix: 200,
            git_commit: "deadbeef".to_owned(),
            exit_host: "admin@192.168.18.49 \" inject \n more".to_owned(),
            exit_node_id: "exit-49".to_owned(),
            pf_anchor: "com.rustynet/nat".to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            daemon_restart_status: "restart_failed: ssh down".to_owned(),
            lifecycle: macos_lifecycle_artifact_fixture(true, true),
            source_artifacts: vec!["live-lab/macos-exit-handoff.log".to_owned()],
            detail: "all invariants held".to_owned(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must produce valid JSON round-trip");
        assert_eq!(parsed["status"], "fail");
        assert_eq!(parsed["platform"], "macos");
        assert_eq!(parsed["phase"], "phase10");
        assert_eq!(parsed["mode"], "live_macos_exit_handoff");
        assert_eq!(parsed["evidence_mode"], "measured");
        assert_eq!(parsed["lifecycle"]["during_run"]["pf_anchor_present"], true);
        assert_eq!(
            parsed["lifecycle"]["after_stop"]["forwarding_restored"],
            true
        );
        assert_eq!(
            parsed["daemon_restart_status"], "restart_failed: ssh down",
            "restart failure must be visible in the report"
        );
        assert_eq!(
            parsed["exit_host"], "admin@192.168.18.49 \" inject \n more",
            "embedded quote/newline must survive serde escaping"
        );
    }

    #[test]
    fn macos_lifecycle_merger_surfaces_failure_when_forwarding_not_restored() {
        // Negative-path coverage of the contract our report relies on:
        // the merger's `forwarding_restored` field must be `false`
        // when after_stop forwarding is still Enabled. A change in
        // `merge_macos_exit_nat_lifecycle_artifact` that breaks this
        // would silently turn a leaked-forwarding host into a passing
        // run, so pin the shape here.
        let merged = macos_lifecycle_artifact_fixture(true, false);
        assert_eq!(merged["during_run"]["pf_anchor_present"], true);
        assert_eq!(
            merged["after_stop"]["forwarding_restored"], false,
            "after_stop forwarding still Enabled must surface as restored=false"
        );
    }

    // ─── Track B Phase 5: Windows exit-handoff validator ──────────
    //
    // Mirror the macOS test shape: pin the parser behaviour for the
    // EXACT PowerShell capture outputs that run_windows_exit_handoff
    // feeds into rustynetd::windows_exit_nat_lifecycle, then prove
    // the report struct survives serde with operator-supplied chars.
    fn windows_options() -> rustynetd::windows_exit_nat_lifecycle::WindowsExitNatLifecycleOptions {
        rustynetd::windows_exit_nat_lifecycle::WindowsExitNatLifecycleOptions {
            mesh_cidr: "100.64.0.0/10".to_owned(),
            nat_name: super::WINDOWS_NAT_NAME.to_owned(),
            tunnel_alias: super::WINDOWS_TUNNEL_ALIAS.to_owned(),
        }
    }

    #[test]
    fn windows_during_run_capture_parses_netnat_present_and_forwarding_enabled() {
        // The PowerShell pipe is `Get-NetNat ... | ConvertTo-Json
        // -Depth 4 -Compress` which yields a JSON object with the
        // InternalIPInterfaceAddressPrefix property.
        let netnat_json = r#"{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#;
        let snapshot =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                100,
                &windows_options(),
                netnat_json,
                "Enabled\n",
                "Enabled\n",
                "Ethernet\n",
                "",
            )
            .expect("snapshot must build");
        assert!(
            snapshot.netnat_present,
            "NetNat object must parse as present"
        );
        assert_eq!(snapshot.internal_prefix, "100.64.0.0/10");
        assert_eq!(snapshot.tunnel_forwarding, "Enabled");
        assert_eq!(snapshot.egress_forwarding, "Enabled");
        assert_eq!(snapshot.egress_alias, "Ethernet");
    }

    #[test]
    fn windows_after_stop_capture_parses_netnat_absent_and_forwarding_disabled() {
        let snapshot =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                200,
                &windows_options(),
                "",
                "Disabled\n",
                "Disabled\n",
                "Ethernet\n",
                "",
            )
            .expect("snapshot must build");
        assert!(
            !snapshot.netnat_present,
            "empty Get-NetNat output must parse as NetNat-absent"
        );
        assert_eq!(snapshot.tunnel_forwarding, "Disabled");
        assert_eq!(snapshot.egress_forwarding, "Disabled");
    }

    #[test]
    fn windows_netnat_array_form_also_parses_present() {
        // PowerShell sometimes emits an array when ConvertTo-Json sees
        // a single object — pin both shapes to keep this validator in
        // lockstep with rustynetd::windows_exit_nat_lifecycle.
        let netnat_json = r#"[{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}]"#;
        let snapshot =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                300,
                &windows_options(),
                netnat_json,
                "Enabled",
                "Enabled",
                "Ethernet",
                "",
            )
            .expect("snapshot must build");
        assert!(snapshot.netnat_present);
        assert_eq!(snapshot.internal_prefix, "100.64.0.0/10");
    }

    fn windows_lifecycle_artifact_fixture(present: bool, restored: bool) -> serde_json::Value {
        let during =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                100,
                &windows_options(),
                if present {
                    r#"{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#
                } else {
                    ""
                },
                "Enabled",
                "Enabled",
                "Ethernet",
                "",
            )
            .expect("during snapshot");
        let after =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                200,
                &windows_options(),
                "",
                if restored { "Disabled" } else { "Enabled" },
                if restored { "Disabled" } else { "Enabled" },
                "Ethernet",
                "",
            )
            .expect("after snapshot");
        rustynetd::windows_exit_nat_lifecycle::merge_windows_exit_nat_lifecycle_artifact(
            &during, &after,
        )
    }

    #[test]
    fn windows_exit_handoff_report_serializes_with_serde() {
        // Operator-supplied exit_host with embedded quote+newline must
        // survive serde escaping. Envelope mirrors the canonical
        // live-lab shape consumed by `ops_fresh_install_os_matrix::load_json_report`.
        let report = super::WindowsExitHandoffReport {
            schema_version: 1,
            phase: "phase10",
            mode: "live_windows_exit_handoff",
            evidence_mode: "measured",
            status: "fail",
            platform: "windows",
            captured_at: "1970-01-01T00:00:00Z".to_owned(),
            captured_at_unix: 200,
            git_commit: "deadbeef".to_owned(),
            exit_host: "admin@192.168.18.40 \" inject \n more".to_owned(),
            exit_node_id: "exit-40".to_owned(),
            nat_name: super::WINDOWS_NAT_NAME.to_owned(),
            tunnel_alias: super::WINDOWS_TUNNEL_ALIAS.to_owned(),
            mesh_cidr: "100.64.0.0/10".to_owned(),
            daemon_restart_status: "restart_failed: SCM access denied".to_owned(),
            lifecycle: windows_lifecycle_artifact_fixture(true, true),
            source_artifacts: vec!["live-lab/windows-exit-handoff.log".to_owned()],
            detail: "all invariants held".to_owned(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must produce valid JSON round-trip");
        assert_eq!(parsed["status"], "fail");
        assert_eq!(parsed["platform"], "windows");
        assert_eq!(parsed["phase"], "phase10");
        assert_eq!(parsed["mode"], "live_windows_exit_handoff");
        assert_eq!(parsed["evidence_mode"], "measured");
        assert_eq!(parsed["nat_name"], super::WINDOWS_NAT_NAME);
        assert_eq!(parsed["tunnel_alias"], super::WINDOWS_TUNNEL_ALIAS);
        assert_eq!(parsed["lifecycle"]["during_run"]["netnat_present"], true);
        assert_eq!(
            parsed["lifecycle"]["after_stop"]["forwarding_restored"],
            true
        );
        assert_eq!(
            parsed["daemon_restart_status"], "restart_failed: SCM access denied",
            "SCM restart failure must be visible in the report"
        );
        assert_eq!(
            parsed["exit_host"], "admin@192.168.18.40 \" inject \n more",
            "embedded quote/newline must survive serde escaping"
        );
    }

    #[test]
    fn windows_lifecycle_merger_surfaces_failure_when_netnat_leaks_after_stop() {
        // Negative-path coverage: if after_stop NetNat is still
        // present, the merger must surface forwarding_restored=false
        // so the validator's assertion cannot pass.
        let during =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                100,
                &windows_options(),
                r#"{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#,
                "Enabled",
                "Enabled",
                "Ethernet",
                "",
            )
            .expect("during");
        let after =
            rustynetd::windows_exit_nat_lifecycle::build_windows_exit_nat_lifecycle_snapshot(
                200,
                &windows_options(),
                r#"{"Name":"RustyNetExit-rustynet0","InternalIPInterfaceAddressPrefix":"100.64.0.0/10"}"#,
                "Disabled",
                "Disabled",
                "Ethernet",
                "",
            )
            .expect("after");
        let merged =
            rustynetd::windows_exit_nat_lifecycle::merge_windows_exit_nat_lifecycle_artifact(
                &during, &after,
            );
        assert_eq!(merged["after_stop"]["netnat_present"], true);
        assert_eq!(
            merged["after_stop"]["forwarding_restored"], false,
            "leaked NetNat must surface as forwarding_restored=false"
        );
    }

    #[test]
    fn windows_scm_service_name_is_canonical() {
        // Defense-in-depth: pin the SCM service identifier the
        // validator stops/restarts so a future rename surfaces here.
        assert_eq!(super::WINDOWS_SCM_SERVICE, "rustynetd");
    }

    #[test]
    fn sanitize_windows_interface_alias_keeps_realistic_aliases() {
        for ok in [
            "Ethernet",
            "Wi-Fi",
            "vEthernet (Default Switch)",
            "Local Area Connection 3",
        ] {
            assert_eq!(
                super::sanitize_windows_interface_alias(ok),
                ok,
                "alias {ok:?} must pass"
            );
        }
    }

    #[test]
    fn sanitize_windows_interface_alias_accepts_localized_unicode_aliases() {
        // Real-world non-English Windows interface alias names.
        // An ASCII-only allowlist would surface these as missing
        // and cause spurious failures on JP/DE/FR/KR hosts.
        for ok in [
            "イーサネット",
            "Ethernet-Verbindung",
            "Сетевое подключение",
            "이더넷",
            "vEthernet (既定のスイッチ)",
        ] {
            assert_eq!(
                super::sanitize_windows_interface_alias(ok),
                ok,
                "localized alias {ok:?} must pass the denylist sanitizer"
            );
        }
    }

    #[test]
    fn sanitize_windows_interface_alias_strips_trailing_newline_carriage_return() {
        assert_eq!(
            super::sanitize_windows_interface_alias("Ethernet\r\n"),
            "Ethernet"
        );
    }

    #[test]
    fn sanitize_windows_interface_alias_rejects_powershell_quote_escape() {
        // A compromised target host could return an alias designed to
        // break out of the single-quoted argument and inject
        // additional PowerShell commands. Must collapse to empty.
        for bad in [
            "Ethernet'; Remove-Item C:\\Windows",
            "evil`whoami",
            "evil\"injection",
            "evil$(echo pwn)",
            "evil; del /q *",
            "evil\\nmkdir foo",
            "<script>",
        ] {
            assert_eq!(
                super::sanitize_windows_interface_alias(bad),
                "",
                "alias {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn sanitize_windows_interface_alias_rejects_oversized_input() {
        let long = "A".repeat(200);
        assert_eq!(super::sanitize_windows_interface_alias(&long), "");
    }

    #[test]
    fn sanitize_windows_interface_alias_returns_empty_for_blank() {
        assert_eq!(super::sanitize_windows_interface_alias(""), "");
        assert_eq!(super::sanitize_windows_interface_alias("   "), "");
    }
}
