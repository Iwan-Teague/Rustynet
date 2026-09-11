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
    Logger, REMOTE_RUSTYNET_BIN, append_env_assignment, capture_root, create_workspace,
    enforce_host, ensure_pinned_known_hosts_file, ensure_safe_token, git_head_commit,
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
const MAX_TRAVERSAL_COORDINATION_TTL_SECS: u64 = 30;
const HANDOFF_PRE_MONITOR_TIMEOUT_SECS: u64 = 60;
/// Upper bound on acceptable exit-failover reconvergence time (client observes
/// exit_b as its exit after exit_a is downed). Exit failover is bounded by the
/// traversal reprobe cycle: handshake-freshness (default 30s) + reprobe
/// interval (default 30s) + a reconcile, so the dataplane plan's
/// interval-bounded convergence model makes this ~one reprobe cycle, not
/// instantaneous. Set to 3x the 30s default reprobe interval; never-reconverged
/// (reconvergence_secs = -1) and gross slowness still fail.
const MAX_HANDOFF_RECONVERGENCE_SECS: i64 = 90;
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

    // Wave 2 (W2-A): the SINGLE real A->B exit-handoff failover
    // assertion runs for EVERY platform. There is no longer a
    // narrower substitute validator for macOS / Windows. The audit's
    // "deceptive false-parity" finding was that `--platform
    // macos|windows` previously dispatched to a single-exit
    // pf/NetNat setup-teardown lifecycle (`run_macos_exit_handoff` /
    // `run_windows_exit_handoff`) and reported "pass" while running
    // ZERO of the 6 real failover checks (handoff reconvergence,
    // no-route-leak during handoff, no-restricted-safe-mode,
    // exit_b-endpoint-visible, both-exits-NAT, managed-DNS-fresh).
    // Those substitute validators are removed; the real flow below
    // now threads `config.platform` through every OS-specific
    // command via `PlatformCommands` (see
    // `PlatformCommands::for_platform`) so the macOS / Windows paths
    // exercise the EXACT same assertion body as Linux — failing
    // closed honestly where the daemon lacks support rather than
    // fake-passing. The Linux behaviour is byte-identical to before.
    let platform = config.platform;
    let cmds = PlatformCommands::for_platform(platform);

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

    // Preflight every host with the platform-appropriate privilege
    // verifier, modeled on `live_linux_relay_test` /
    // `live_linux_mixed_topology_test`. `verify_sudo`'s
    // `/etc/hosts`-hostname grep is Linux-PAM-specific and would
    // spuriously reject a healthy macOS host, so macOS uses the
    // minimal passwordless-sudo probe and Windows confirms
    // BUILTIN\Administrators. A failed preflight fails closed before
    // any capture runs, so a missing privilege cannot be silently
    // mistaken for a failover failure.
    for host in [
        &config.exit_a_host,
        &config.exit_b_host,
        &config.client_host,
    ] {
        match platform {
            ExitHandoffPlatform::Linux => {
                live_lab_support::verify_sudo(&config.ssh_identity_file, &work_known_hosts, host)?;
            }
            ExitHandoffPlatform::MacOs => {
                live_lab_support::verify_passwordless_sudo(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    host,
                )?;
            }
            ExitHandoffPlatform::Windows => {
                live_lab_support::verify_windows_admin(
                    &config.ssh_identity_file,
                    &work_known_hosts,
                    host,
                )?;
            }
        }
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
    // exit_a and exit_b carry the full admin capability set
    // (client,relay_host,exit_server,anchor), mirroring upgrade_admin's signed
    // membership. The daemon validates the assignment intent against its
    // *current* role: before the handoff enforces `admin` these nodes are still
    // `client` (intent must include client), and after enforce they are `admin`
    // (intent must include anchor). A narrower set fails one side or the other
    // ("assignment target intent lacks required local capability client" /
    // "... anchor"). Caps appear in both the 4th and 8th pipe fields so both the
    // issuance parser (parse_generic_nodes) and the assignment-refresh parser
    // (parse_assignment_nodes) read them. The client node stays client,relay_host.
    let nodes_spec = format!(
        "{}|{}:51820|{}|client,relay_host,exit_server,anchor||||client,relay_host,exit_server,anchor;{}|{}:51820|{}|client,relay_host,exit_server,anchor||||client,relay_host,exit_server,anchor;{}|{}:51820|{}|client,relay_host||||client,relay_host",
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
        "{REMOTE_RUSTYNET_BIN} ops materialize-signing-passphrase --output {}",
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
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {REMOTE_RUSTYNET_BIN} route advertise 0.0.0.0/0"
        ),
    )?;
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.exit_b_host,
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {REMOTE_RUSTYNET_BIN} route advertise 0.0.0.0/0"
        ),
    )?;
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        &config.exit_a_node_id,
        platform,
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
        let client_status = capture_client_status(&config, &work_known_hosts, platform)?;
        let route_line = capture_platform_command(
            &config,
            &work_known_hosts,
            &config.client_host,
            cmds.route_get,
            cmds.route_get_needs_root,
        )?;
        let wg_endpoints = capture_platform_command(
            &config,
            &work_known_hosts,
            &config.client_host,
            cmds.wg_endpoints,
            cmds.wg_endpoints_needs_root,
        )?;
        let ping_rc = match live_lab_support::ssh_status(
            &config.ssh_identity_file,
            &work_known_hosts,
            &config.client_host,
            cmds.ping_probe,
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
                platform,
            )?;
        }
        std::thread::sleep(std::time::Duration::from_secs(1));
    }

    let client_status_final = capture_client_status(&config, &work_known_hosts, platform)?;
    let exit_a_status_final =
        capture_exit_status(&config, &work_known_hosts, &config.exit_a_host, platform)?;
    let exit_b_status_final =
        capture_exit_status(&config, &work_known_hosts, &config.exit_b_host, platform)?;
    let client_route_final = capture_platform_command(
        &config,
        &work_known_hosts,
        &config.client_host,
        cmds.route_get,
        cmds.route_get_needs_root,
    )?;
    let client_wg_endpoints_final = capture_platform_command(
        &config,
        &work_known_hosts,
        &config.client_host,
        cmds.wg_endpoints,
        cmds.wg_endpoints_needs_root,
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
    let exit_a_nat = capture_platform_command(
        &config,
        &work_known_hosts,
        &config.exit_a_host,
        cmds.nat_capture,
        cmds.nat_capture_needs_root,
    )?;
    let exit_b_nat = capture_platform_command(
        &config,
        &work_known_hosts,
        &config.exit_b_host,
        cmds.nat_capture,
        cmds.nat_capture_needs_root,
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
    // Per-OS route-leak detection. Every monitor sample's client
    // default route MUST egress the rustynet tunnel device; any
    // off-tunnel route (or a sample with no parseable `route=` field)
    // is a leak. The tunnel-device token differs per OS
    // (`dev rustynet0` on Linux, `interface: utunN` on macOS,
    // `InterfaceAlias rustynet0` on Windows) so the predicate is
    // selected via `platform`, not a hard-coded substring. A sample
    // whose route never converged to the tunnel counts as a leak and
    // fails the check closed.
    let route_leak_count = monitor_text
        .lines()
        .filter(|line| monitor_line_route_leaks(line, platform))
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

    // Exit failover is bounded by the traversal reprobe cycle, not a hard 30s:
    // the client must observe exit_a's handshake go stale (handshake-freshness,
    // default 30s) AND complete a reprobe (reprobe interval, default 30s) before
    // switching to exit_b, then reconcile to reprogram routes. The dataplane
    // execution plan models such convergence as interval-bounded (e.g. STUN
    // gather ~60s), so a sub-reprobe-interval bound was unachievable and flaky.
    // Budget = MAX_HANDOFF_RECONVERGENCE_SECS (3x the 30s default reprobe
    // interval). A failover that never reconverges yields reconvergence_secs=-1
    // and still fails; gross slowness beyond the budget still fails.
    let check_handoff_reconvergence =
        if (0..=MAX_HANDOFF_RECONVERGENCE_SECS).contains(&reconvergence_secs) {
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
    let check_both_exits_nat = if exit_nat_present_for_platform(platform, &exit_a_nat)
        && exit_nat_present_for_platform(platform, &exit_b_nat)
    {
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

/// Target platform of the client failing over between the two exit
/// hosts. As of Wave 2 (W2-A) the SINGLE real A->B failover assertion
/// runs for every platform: `--platform` selects the per-OS command
/// branches threaded through the 6 failover checks (see
/// [`PlatformCommands`]), not a different/narrower validator. macOS /
/// Windows exercise the EXACT same assertion body as Linux and fail
/// closed honestly where the daemon lacks support (Windows-as-exit is
/// unsupported at the role gate — see the `// REVIEW:` flags in
/// `PlatformCommands::for_platform`). Mirrors the cross-OS
/// `RemoteShellHost` command-branch pattern proven in
/// `live_linux_relay_test`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitHandoffPlatform {
    Linux,
    MacOs,
    Windows,
}

impl ExitHandoffPlatform {
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

    /// Platform label consumed by the shared `apply_role_coupling`
    /// helper (and its socket / bundle / watermark path selectors in
    /// `live_lab_bin_support`). `as_str` already produces the
    /// canonical `linux|macos|windows` token the helper matches on.
    fn role_coupling_label(self) -> &'static str {
        self.as_str()
    }
}

/// Per-OS command set + tunnel-device tokens for the SINGLE real
/// exit-handoff failover assertion. Every OS-specific command used by
/// the 6 failover checks is selected here once via
/// [`PlatformCommands::for_platform`] and threaded through the
/// capture sites, mirroring the `match platform` command-branch seam
/// proven in `live_linux_relay_test.rs`. Keeping every branch in one
/// struct means a missing port surfaces as a compile error rather
/// than a silently-skipped check, and keeps the Linux strings
/// byte-identical to the pre-Wave-2 hard-coded form.
#[derive(Debug, Clone)]
struct PlatformCommands {
    /// Client-side default-route inspection toward an off-mesh target
    /// (1.1.1.1). Output feeds `route=` in the monitor line and the
    /// route-leak detector ([`route_uses_tunnel_for_platform`]). Run
    /// via `capture_root` (sudo) on Linux / macOS; on Windows it is a
    /// PowerShell `Get-NetRoute` query run via `capture_remote_stdout`
    /// against the Administrator session.
    route_get: &'static str,
    /// Whether `route_get` must be run through `capture_root` (sudo).
    /// Windows captures run via `capture_remote_stdout` (no sudo verb).
    route_get_needs_root: bool,
    /// Debug-only WireGuard endpoint dump (never asserted on; recorded
    /// in the monitor line for triage).
    wg_endpoints: &'static str,
    wg_endpoints_needs_root: bool,
    /// Client-side reachability probe through the active exit. Run via
    /// `ssh_status` (raw, no sudo wrapper — byte-identical to the
    /// pre-Wave-2 Linux invocation) so only the exact rc is observed.
    /// Linux/macOS use `ping`; Windows uses a PowerShell
    /// `Test-Connection` whose `exit` code carries the result.
    ping_probe: &'static str,
    /// Exit-side NAT-presence capture. Output is fed to
    /// [`exit_nat_present_for_platform`] which applies the per-OS
    /// match (Linux `masquerade`, macOS pf `nat on`, Windows NetNat
    /// object). Run via `capture_root` on Linux/macOS, via
    /// `capture_remote_stdout` (PowerShell) on Windows.
    nat_capture: &'static str,
    nat_capture_needs_root: bool,
}

impl PlatformCommands {
    fn for_platform(platform: ExitHandoffPlatform) -> Self {
        match platform {
            // Linux strings are byte-identical to the pre-Wave-2
            // hard-coded captures so the Linux path does not change.
            ExitHandoffPlatform::Linux => PlatformCommands {
                route_get: "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true",
                route_get_needs_root: true,
                wg_endpoints: "wg show rustynet0 endpoints 2>/dev/null || true",
                wg_endpoints_needs_root: true,
                ping_probe: "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1",
                nat_capture: "nft list ruleset || true",
                nat_capture_needs_root: true,
            },
            // macOS: `route -n get <dst>` is the BSD equivalent of
            // `ip route get`; its `interface: utunN` line names the
            // egress device (the rustynet tunnel surfaces as a utun*
            // on macOS — see `macos_exit_dns_failclosed.rs` test
            // fixtures `interface: utun4`). `wg show` is available on
            // macOS when wireguard-tools is installed. `ping -c 1 -t 1`
            // — macOS `ping` spells the deadline `-t` (TTL on Linux),
            // and has no `-W` per-probe timeout, so `-t 1` bounds the
            // probe. NAT is captured from the daemon's pf anchor.
            //
            // REVIEW: macOS-as-exit maps to the `blind_exit` daemon
            // role (role.rs `daemon_node_role_for_platform`), and this
            // test enforces the `admin` role on both exits. The macOS
            // daemon's admin role requires the `anchor` capability,
            // which is Linux-only today (role.rs:61
            // `is_supported_for_platform`). Expect the macOS exit
            // hosts to fail closed at `enforce_host`/route-advertise
            // on a live run; that is the honest daemon-side gap, not a
            // test bug.
            ExitHandoffPlatform::MacOs => PlatformCommands {
                route_get: "/sbin/route -n get 1.1.1.1 2>/dev/null || true",
                route_get_needs_root: true,
                wg_endpoints: "wg show rustynet0 endpoints 2>/dev/null || true",
                wg_endpoints_needs_root: true,
                ping_probe: "/sbin/ping -c 1 -t 1 1.1.1.1 >/dev/null 2>&1",
                nat_capture: "/sbin/pfctl -a com.rustynet/nat -s nat 2>/dev/null || true",
                nat_capture_needs_root: true,
            },
            // Windows: PowerShell `Get-NetRoute` for the default route
            // names the ifIndex; the route-leak detector matches the
            // rustynet WireGuard adapter alias in the row. `ping -n 1
            // -w 1000` is the Windows flag spelling (count `-n`,
            // per-probe timeout `-w` in ms). `wg.exe show` is present
            // when the WireGuard tooling is installed but the Windows
            // backend is WFP-based, so it may be empty — debug only.
            // NAT presence is read from `Get-NetNat`.
            //
            // REVIEW: Windows-as-exit is unsupported at the role gate
            // (role.rs:65 `is_supported_for_platform` returns false
            // for a Windows membership owner, and the exit's `admin`
            // role requires the `anchor` capability which is Linux-only
            // per role.rs:61). The Windows exit hosts WILL fail closed
            // at `enforce_host`/route-advertise on a live run. This is
            // the CORRECT, honest outcome — the ported test lights up
            // the real daemon-side gap rather than fake-passing.
            ExitHandoffPlatform::Windows => PlatformCommands {
                route_get: "powershell -NoProfile -Command \"Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Sort-Object -Property RouteMetric | Select-Object -First 1 | Format-List ifIndex,InterfaceAlias,NextHop | Out-String -Width 32767\"",
                route_get_needs_root: false,
                wg_endpoints: "powershell -NoProfile -Command \"try { wg.exe show rustynet0 endpoints } catch { '' }\"",
                wg_endpoints_needs_root: false,
                ping_probe: "powershell -NoProfile -Command \"if ((Test-Connection -ComputerName 1.1.1.1 -Count 1 -Quiet -ErrorAction SilentlyContinue)) { exit 0 } else { exit 1 }\"",
                nat_capture: "powershell -NoProfile -Command \"Get-NetNat -ErrorAction SilentlyContinue | Format-List Name,InternalIPInterfaceAddressPrefix | Out-String -Width 32767\"",
                nat_capture_needs_root: false,
            },
        }
    }
}

/// Pure, unit-testable route-leak / tunnel-egress detector. Split out
/// of [`PlatformCommands`] so it can be exercised with realistic
/// per-OS `route_get` samples (the live commands are not runnable on
/// this orchestrator host, so the parser is the verifiable surface).
fn route_uses_tunnel_for_platform(platform: ExitHandoffPlatform, route: &str) -> bool {
    match platform {
        // Byte-identical to the pre-Wave-2 `route_uses_rustynet0`.
        ExitHandoffPlatform::Linux => route.contains("dev rustynet0"),
        // `route -n get` emits `  interface: utun4`. Accept any
        // `utun*` (the rustynet macOS tunnel) OR an explicit
        // `rustynet0` alias. Anchoring on the `interface:` KEY (and
        // reading only the device token that immediately follows it)
        // means a stray mention of `utun` elsewhere cannot satisfy
        // the check. `key_value_token` works whether the capture is
        // the raw multi-line `route -n get` block OR the
        // newline-collapsed monitor-line `route=` field (the monitor
        // line replaces `\n` with spaces, so the device sits inline).
        ExitHandoffPlatform::MacOs => match key_value_token(route, "interface:") {
            Some(iface) => iface.starts_with("utun") || iface == "rustynet0",
            None => false,
        },
        // `Get-NetRoute | Format-List` emits `InterfaceAlias :
        // rustynet0`. Match the alias key + the rustynet adapter name
        // so a default route via the physical NIC (a leak) fails. Same
        // raw-vs-collapsed robustness as the macOS branch.
        ExitHandoffPlatform::Windows => match key_value_token(route, "InterfaceAlias") {
            Some(alias) => alias.eq_ignore_ascii_case("rustynet0"),
            None => false,
        },
    }
}

/// Extract the value token that follows the first occurrence of `key`
/// in `text`, skipping a single PowerShell `Format-List` `:`
/// separator if present. Used to read the egress device / adapter
/// name out of either a raw multi-line route capture (`interface:
/// utun4`) or the newline-collapsed monitor-line `route=` field, and
/// the Windows `InterfaceAlias : rustynet0` shape alike. Returns
/// `None` when `key` is absent or has no following value token
/// (fail-closed: an unparsed capture is NOT a tunnel match).
fn key_value_token<'a>(text: &'a str, key: &str) -> Option<&'a str> {
    let after = text.split(key).nth(1)?;
    // Drop a leading `:` separator token (Format-List `Key : Value`)
    // before reading the value, so both `interface: utun4` and
    // `InterfaceAlias : rustynet0` yield the device/alias token.
    after.split_whitespace().find(|tok| *tok != ":")
}

/// Pure, unit-testable exit-side NAT-presence detector.
fn exit_nat_present_for_platform(platform: ExitHandoffPlatform, capture: &str) -> bool {
    match platform {
        // Byte-identical to the pre-Wave-2 `nft ... contains
        // "masquerade"` check.
        ExitHandoffPlatform::Linux => capture.contains("masquerade"),
        // `pfctl -a com.rustynet/nat -s nat` prints `nat on <if> ...`
        // when the daemon installed its egress NAT anchor.
        ExitHandoffPlatform::MacOs => capture.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed.starts_with("nat on ") || trimmed.starts_with("nat-anchor")
        }),
        // `Get-NetNat | Format-List` prints a `Name : <nat>` line when
        // a NetNat object exists. Empty output = no NAT.
        ExitHandoffPlatform::Windows => capture.lines().any(|line| {
            let trimmed = line.trim();
            trimmed
                .strip_prefix("Name")
                .map(|rest| !rest.trim_start_matches([':', ' ']).trim().is_empty())
                .unwrap_or(false)
        }),
    }
}

/// Capture the client daemon `status` line on the active platform.
/// Linux retains the byte-identical `status()` helper (sudo +
/// `/run/rustynet/rustynetd.sock`); macOS / Windows go through the
/// shared `capture_daemon_status_for_platform` so the correct
/// per-OS socket / `rustynet.exe` invocation is used (the Linux-only
/// `status()` helper hard-codes the Linux socket and would never
/// connect on macOS/Windows — using it there would be a silent
/// fail-closed masquerading as an empty status). A never-captured
/// status propagates the Err so the failover assertion fails closed.
fn capture_client_status(
    config: &Config,
    known_hosts: &Path,
    platform: ExitHandoffPlatform,
) -> Result<String, String> {
    match platform {
        ExitHandoffPlatform::Linux => {
            status(&config.ssh_identity_file, known_hosts, &config.client_host)
        }
        ExitHandoffPlatform::MacOs | ExitHandoffPlatform::Windows => {
            live_lab_support::capture_daemon_status_for_platform(
                &config.ssh_identity_file,
                known_hosts,
                &config.client_host,
                platform.as_str(),
            )
        }
    }
}

/// Capture an exit host's daemon `status` line on the active
/// platform. Same per-OS socket / invocation rationale as
/// [`capture_client_status`]; split so the exit host can be targeted.
fn capture_exit_status(
    config: &Config,
    known_hosts: &Path,
    exit_host: &str,
    platform: ExitHandoffPlatform,
) -> Result<String, String> {
    match platform {
        ExitHandoffPlatform::Linux => status(&config.ssh_identity_file, known_hosts, exit_host),
        ExitHandoffPlatform::MacOs | ExitHandoffPlatform::Windows => {
            live_lab_support::capture_daemon_status_for_platform(
                &config.ssh_identity_file,
                known_hosts,
                exit_host,
                platform.as_str(),
            )
        }
    }
}

/// Per-OS route-leak predicate over a single monitor-log line. A line
/// "leaks" when it has no `route=` field, or when the captured route
/// did NOT egress the rustynet tunnel device for `platform`. The
/// monitor line embeds the (newline-collapsed) route capture as
/// `...|route=<capture>|status=...`; extract the `route=` field up to
/// the next `|status=` delimiter and apply
/// [`route_uses_tunnel_for_platform`]. Pure + unit-tested with
/// realistic per-OS monitor samples.
fn monitor_line_route_leaks(line: &str, platform: ExitHandoffPlatform) -> bool {
    let Some(route_field) = monitor_line_route_field(line) else {
        return true;
    };
    !route_uses_tunnel_for_platform(platform, route_field)
}

/// Extract the `route=<...>` field value from a monitor line, bounded
/// by the following `|status=` delimiter (the monitor line is
/// `ts|iter=..|ping_rc=..|route=<route>|status=<status>|wg_endpoints=<..>`).
/// Returns `None` when the line carries no `route=` field at all.
fn monitor_line_route_field(line: &str) -> Option<&str> {
    let after = line.split("route=").nth(1)?;
    Some(match after.find("|status=") {
        Some(end) => &after[..end],
        None => after,
    })
}

/// Run a per-OS capture command on `target`, choosing the sudo
/// (`capture_root`) vs raw (`capture_remote_stdout`) seam per the
/// command's `needs_root` flag. Linux/macOS captures that read kernel
/// route / pf state need sudo; Windows PowerShell captures run under
/// the Administrator SSH session and do not use a sudo verb. A failed
/// capture propagates as Err so the dependent check fails closed
/// rather than silently treating an unreadable probe as a pass.
fn capture_platform_command(
    config: &Config,
    known_hosts: &Path,
    target: &str,
    command: &str,
    needs_root: bool,
) -> Result<String, String> {
    if needs_root {
        capture_root(&config.ssh_identity_file, known_hosts, target, command)
    } else {
        live_lab_support::capture_remote_stdout(
            &config.ssh_identity_file,
            known_hosts,
            target,
            command,
        )
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
        &format!(
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock {REMOTE_RUSTYNET_BIN} state refresh"
        ),
    )
}

fn refresh_trust_evidence(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    run_root(
        identity,
        known_hosts,
        target,
        &format!("{REMOTE_RUSTYNET_BIN} ops refresh-signed-trust"),
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
            "{REMOTE_RUSTYNET_BIN} dns zone issue --signing-secret /etc/rustynet/membership.owner.key --signing-secret-passphrase-file {} --subject-node-id {} --nodes {} --allow {} --zone-name {} --records-manifest {} --output {} --verifier-key-output {}",
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
    platform: ExitHandoffPlatform,
) -> Result<(), String> {
    // Thread the active platform through the shared
    // `apply_role_coupling` helper so it selects the correct per-OS
    // daemon socket / assignment-bundle / watermark paths (the helper
    // hard-coded "linux" before Wave 2, which would have driven the
    // wrong socket on macOS/Windows). The env path stays platform-
    // appropriate via the same helper's selectors on the daemon side.
    //
    // REVIEW: on macOS the client maps the `client` role to the
    // `client` daemon role (role.rs `daemon_node_role_for_platform`),
    // which the macOS daemon supports; on Windows the client role is
    // likewise supported. The unconfirmed daemon-side surface is the
    // *exit-route reconvergence wait* inside apply-role-coupling — the
    // lab does not assert macOS client full-tunnel exit-route
    // convergence (the helper passes
    // `--skip-client-exit-route-convergence-wait` on macOS), so a
    // macOS client pinned to a freshly-elected exit may report
    // convergence the orchestrator did not actually verify. The
    // failover reconvergence is still asserted independently via the
    // monitor-line `exit_node=` transition.
    live_lab_support::apply_role_coupling(
        identity,
        known_hosts,
        client_host,
        "client",
        Some(expected_exit_node_id),
        false,
        live_lab_support::assignment_refresh_env_path_for_platform(platform.role_coupling_label()),
        platform.role_coupling_label(),
    )?;
    run_root(
        identity,
        known_hosts,
        client_host,
        &format!("{REMOTE_RUSTYNET_BIN} ops force-local-assignment-refresh-now"),
    )
}

fn handoff_runtime_ready(status: &str) -> bool {
    status_field(status, "restricted_safe_mode") == Some("false")
        && status_field(status, "bootstrap_error") == Some("none")
        && status_field(status, "last_reconcile_error") == Some("none")
        && status_field(status, "state") != Some("FailClosed")
}

/// Linux-only tunnel-egress predicate, retained as the byte-identical
/// Linux definition that `route_uses_tunnel_for_platform(Linux, ..)`
/// must agree with. Test-only oracle pinned by
/// `route_uses_rustynet0_requires_tunnel_device` and
/// `route_uses_tunnel_linux_matches_byte_identical_legacy_predicate`;
/// the production route-leak path goes through
/// `route_uses_tunnel_for_platform`.
#[cfg(test)]
fn route_uses_rustynet0(route: &str) -> bool {
    route.contains("dev rustynet0")
}

fn handoff_monitor_prereqs_ready(
    client_status: &str,
    exit_a_status: &str,
    exit_b_status: &str,
    client_route: &str,
    exit_a_node_id: &str,
    platform: ExitHandoffPlatform,
) -> bool {
    status_field(client_status, "exit_node") == Some(exit_a_node_id)
        && route_uses_tunnel_for_platform(platform, client_route)
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
    let platform = config.platform;
    let cmds = PlatformCommands::for_platform(platform);
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        known_hosts,
        &config.client_host,
        expected_exit_node_id,
        platform,
    )?;
    let start_ts = unix_now();
    let mut last_client_status = String::new();
    let mut last_exit_a_status = String::new();
    let mut last_exit_b_status = String::new();
    let mut last_client_route = String::new();

    while unix_now().saturating_sub(start_ts) < HANDOFF_REFRESH_CONVERGENCE_TIMEOUT_SECS {
        last_client_status = capture_client_status(config, known_hosts, platform)?;
        last_exit_a_status =
            capture_exit_status(config, known_hosts, &config.exit_a_host, platform)?;
        last_exit_b_status =
            capture_exit_status(config, known_hosts, &config.exit_b_host, platform)?;
        last_client_route = capture_platform_command(
            config,
            known_hosts,
            &config.client_host,
            cmds.route_get,
            cmds.route_get_needs_root,
        )?;

        if handoff_monitor_prereqs_ready(
            &last_client_status,
            &last_exit_a_status,
            &last_exit_b_status,
            &last_client_route,
            expected_exit_node_id,
            platform,
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
    let platform = config.platform;
    let cmds = PlatformCommands::for_platform(platform);
    pin_client_to_expected_exit(
        &config.ssh_identity_file,
        known_hosts,
        &config.client_host,
        &config.exit_a_node_id,
        platform,
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
                platform,
            )?;
            next_coordination_refresh_ts = advance_periodic_refresh_deadline(
                next_coordination_refresh_ts,
                config.traversal_refresh_interval_secs,
                unix_now(),
            );
        }

        last_client_status = capture_client_status(config, known_hosts, platform)?;
        last_exit_a_status =
            capture_exit_status(config, known_hosts, &config.exit_a_host, platform)?;
        last_exit_b_status =
            capture_exit_status(config, known_hosts, &config.exit_b_host, platform)?;
        last_client_route = capture_platform_command(
            config,
            known_hosts,
            &config.client_host,
            cmds.route_get,
            cmds.route_get_needs_root,
        )?;

        if handoff_monitor_prereqs_ready(
            &last_client_status,
            &last_exit_a_status,
            &last_exit_b_status,
            &last_client_route,
            &config.exit_a_node_id,
            platform,
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
        let linux = super::ExitHandoffPlatform::Linux;
        assert!(handoff_monitor_prereqs_ready(
            client_status,
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
            linux,
        ));
        assert!(!handoff_monitor_prereqs_ready(
            client_status,
            exit_a_status,
            exit_b_status,
            "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.24 uid 0",
            "exit-1",
            linux,
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=exit-1 state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=invalid dns_zone_error=dns_zone_bundle_is_stale dns_alarm_state=error",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
            linux,
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=client-2 state=ExitActive restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
            linux,
        ));
        assert!(!handoff_monitor_prereqs_ready(
            "exit_node=exit-1 state=FailClosed restricted_safe_mode=false bootstrap_error=none last_reconcile_error=none dns_zone_state=valid dns_zone_error=none dns_alarm_state=ok",
            exit_a_status,
            exit_b_status,
            route,
            "exit-1",
            linux,
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

    // ─── Wave 2 (W2-A): per-OS failover command-branch parsers ────
    //
    // The live route / NAT capture commands can't run on this Linux
    // orchestrator host, so the pure parsers they feed are the
    // verifiable surface. Each is pinned with REALISTIC per-OS output
    // samples (real `ip route get` / `route -n get` / `Get-NetRoute`
    // / `nft` / `pfctl` / `Get-NetNat` shapes).

    #[test]
    fn route_uses_tunnel_linux_matches_byte_identical_legacy_predicate() {
        // The Linux branch MUST agree with the pre-Wave-2
        // `route_uses_rustynet0` so the Linux behaviour is unchanged.
        let tunnel = "1.1.1.1 dev rustynet0 table 51820 src 100.64.0.10 uid 0";
        let leak = "1.1.1.1 via 192.168.64.1 dev enp0s1 src 192.168.64.24 uid 0";
        assert_eq!(
            super::route_uses_tunnel_for_platform(super::ExitHandoffPlatform::Linux, tunnel),
            super::route_uses_rustynet0(tunnel),
        );
        assert_eq!(
            super::route_uses_tunnel_for_platform(super::ExitHandoffPlatform::Linux, leak),
            super::route_uses_rustynet0(leak),
        );
        assert!(super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Linux,
            tunnel
        ));
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Linux,
            leak
        ));
    }

    #[test]
    fn route_uses_tunnel_macos_requires_utun_interface_line() {
        // `route -n get 1.1.1.1` egressing the rustynet utun tunnel.
        let tunnel = "   route to: 1.1.1.1\ndestination: default\n       gateway: 100.64.0.1\n     interface: utun4\n";
        // A route via the physical en0 NIC is a LEAK and must fail.
        let leak = "   route to: 1.1.1.1\ndestination: default\n       gateway: 192.168.64.1\n     interface: en0\n";
        assert!(super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::MacOs,
            tunnel
        ));
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::MacOs,
            leak
        ));
        // An explicit rustynet0 alias is also accepted.
        assert!(super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::MacOs,
            "     interface: rustynet0\n"
        ));
        // A stray mention of utun NOT on an `interface:` line must
        // NOT satisfy the predicate (fail-closed).
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::MacOs,
            "  note: utun4 was previously up\n     interface: en0\n"
        ));
        // Empty / unparsed capture fails closed.
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::MacOs,
            ""
        ));
    }

    #[test]
    fn route_uses_tunnel_windows_requires_rustynet_adapter_alias() {
        // `Get-NetRoute ... | Format-List ifIndex,InterfaceAlias,NextHop`.
        let tunnel = "ifIndex        : 27\nInterfaceAlias : rustynet0\nNextHop        : 0.0.0.0\n";
        let leak =
            "ifIndex        : 12\nInterfaceAlias : Ethernet\nNextHop        : 192.168.64.1\n";
        assert!(super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Windows,
            tunnel
        ));
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Windows,
            leak
        ));
        // Case-insensitive on the adapter name.
        assert!(super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Windows,
            "InterfaceAlias : RustyNet0\n"
        ));
        // Empty capture fails closed.
        assert!(!super::route_uses_tunnel_for_platform(
            super::ExitHandoffPlatform::Windows,
            ""
        ));
    }

    #[test]
    fn exit_nat_present_linux_matches_masquerade_token() {
        let with_nat = "table ip rustynet-nat {\n  chain postrouting {\n    oifname \"eth0\" masquerade\n  }\n}\n";
        assert!(super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Linux,
            with_nat
        ));
        // No masquerade rule = no exit NAT = fail closed.
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Linux,
            "table ip filter {\n  chain input {}\n}\n"
        ));
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Linux,
            ""
        ));
    }

    #[test]
    fn exit_nat_present_macos_matches_pf_nat_rule() {
        // `pfctl -a com.rustynet/nat -s nat` with the egress NAT rule.
        let with_nat = "nat on en0 inet from 100.64.0.0/10 to any -> (en0)\n";
        assert!(super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::MacOs,
            with_nat
        ));
        // A nat-anchor reference also counts (anchor present).
        assert!(super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::MacOs,
            "nat-anchor \"com.rustynet/nat\" all\n"
        ));
        // Empty pf anchor = no NAT = fail closed.
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::MacOs,
            ""
        ));
        // A pass/block rule that merely mentions an interface must
        // NOT be mistaken for a NAT rule.
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::MacOs,
            "pass out quick on en0 all keep state\n"
        ));
    }

    #[test]
    fn exit_nat_present_windows_matches_netnat_object() {
        // `Get-NetNat | Format-List Name,InternalIPInterfaceAddressPrefix`.
        let with_nat = "Name                            : RustyNetExit-rustynet0\nInternalIPInterfaceAddressPrefix : 100.64.0.0/10\n";
        assert!(super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Windows,
            with_nat
        ));
        // Zero NetNat objects = empty stdout = fail closed.
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Windows,
            ""
        ));
        // A `Name :` line with an empty value must not count.
        assert!(!super::exit_nat_present_for_platform(
            super::ExitHandoffPlatform::Windows,
            "Name                            : \n"
        ));
    }

    #[test]
    fn monitor_line_route_field_extracts_bounded_route_value() {
        let line = "1700000000|iter=3|ping_rc=0|route=1.1.1.1 dev rustynet0 src 100.64.0.10|status=exit_node=exit-1 state=ExitActive|wg_endpoints=peer ...";
        assert_eq!(
            super::monitor_line_route_field(line),
            Some("1.1.1.1 dev rustynet0 src 100.64.0.10")
        );
        // A line with no route field returns None.
        assert_eq!(
            super::monitor_line_route_field("1700000000|iter=3|ping_rc=0"),
            None
        );
        // A trailing route field with no following status= keeps the rest.
        assert_eq!(
            super::monitor_line_route_field("ts|route=default via utun4"),
            Some("default via utun4")
        );
    }

    #[test]
    fn monitor_line_route_leaks_linux_flags_off_tunnel_routes() {
        let tunnel_line = "1700000000|iter=3|ping_rc=0|route=1.1.1.1 dev rustynet0 table 51820 src 100.64.0.10|status=exit_node=exit-1|wg_endpoints=x";
        let leak_line = "1700000000|iter=4|ping_rc=1|route=1.1.1.1 via 192.168.64.1 dev enp0s1|status=exit_node=none|wg_endpoints=x";
        let missing_route_line = "1700000000|iter=5|ping_rc=1|status=exit_node=none";
        assert!(!super::monitor_line_route_leaks(
            tunnel_line,
            super::ExitHandoffPlatform::Linux
        ));
        assert!(super::monitor_line_route_leaks(
            leak_line,
            super::ExitHandoffPlatform::Linux
        ));
        // A sample with no parseable route is treated as a leak
        // (fail-closed: a never-observed route is NOT a pass).
        assert!(super::monitor_line_route_leaks(
            missing_route_line,
            super::ExitHandoffPlatform::Linux
        ));
    }

    #[test]
    fn monitor_line_route_leaks_macos_uses_utun_interface() {
        // macOS route capture is multi-line; the monitor line collapses
        // newlines to spaces, so the `interface: utunN` token survives
        // inline in the route= field.
        let tunnel_line = "1700000000|iter=3|ping_rc=0|route=route to: 1.1.1.1 destination: default gateway: 100.64.0.1 interface: utun4|status=exit_node=exit-1|wg_endpoints=x";
        let leak_line = "1700000000|iter=4|ping_rc=1|route=route to: 1.1.1.1 destination: default gateway: 192.168.64.1 interface: en0|status=exit_node=none|wg_endpoints=x";
        assert!(!super::monitor_line_route_leaks(
            tunnel_line,
            super::ExitHandoffPlatform::MacOs
        ));
        assert!(super::monitor_line_route_leaks(
            leak_line,
            super::ExitHandoffPlatform::MacOs
        ));
    }

    #[test]
    fn monitor_line_route_leaks_windows_uses_adapter_alias() {
        let tunnel_line = "1700000000|iter=3|ping_rc=0|route=ifIndex : 27 InterfaceAlias : rustynet0 NextHop : 0.0.0.0|status=exit_node=exit-1|wg_endpoints=x";
        let leak_line = "1700000000|iter=4|ping_rc=1|route=ifIndex : 12 InterfaceAlias : Ethernet NextHop : 192.168.64.1|status=exit_node=none|wg_endpoints=x";
        assert!(!super::monitor_line_route_leaks(
            tunnel_line,
            super::ExitHandoffPlatform::Windows
        ));
        assert!(super::monitor_line_route_leaks(
            leak_line,
            super::ExitHandoffPlatform::Windows
        ));
    }

    #[test]
    fn platform_commands_linux_strings_are_byte_identical_to_legacy() {
        // Guard: the Linux command strings must NOT drift from the
        // pre-Wave-2 hard-coded captures (Linux behaviour unchanged).
        let cmds = super::PlatformCommands::for_platform(super::ExitHandoffPlatform::Linux);
        assert_eq!(
            cmds.route_get,
            "ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true"
        );
        assert!(cmds.route_get_needs_root);
        assert_eq!(
            cmds.wg_endpoints,
            "wg show rustynet0 endpoints 2>/dev/null || true"
        );
        assert!(cmds.wg_endpoints_needs_root);
        assert_eq!(cmds.ping_probe, "ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1");
        assert_eq!(cmds.nat_capture, "nft list ruleset || true");
        assert!(cmds.nat_capture_needs_root);
    }

    #[test]
    fn platform_commands_windows_captures_run_without_sudo() {
        // Windows PowerShell captures run under the Administrator SSH
        // session, not a sudo verb — the route / NAT captures must be
        // raw (`capture_remote_stdout`), and the route command must be
        // the Get-NetRoute query, not the Linux iproute2 form.
        let cmds = super::PlatformCommands::for_platform(super::ExitHandoffPlatform::Windows);
        assert!(!cmds.route_get_needs_root);
        assert!(!cmds.nat_capture_needs_root);
        assert!(cmds.route_get.contains("Get-NetRoute"));
        assert!(cmds.nat_capture.contains("Get-NetNat"));
        assert!(cmds.ping_probe.contains("Test-Connection"));
    }

    #[test]
    fn platform_commands_macos_captures_use_bsd_route_and_pf() {
        let cmds = super::PlatformCommands::for_platform(super::ExitHandoffPlatform::MacOs);
        assert!(cmds.route_get_needs_root);
        assert!(cmds.nat_capture_needs_root);
        assert!(cmds.route_get.contains("route -n get"));
        assert!(cmds.nat_capture.contains("pfctl"));
        // macOS ping uses the `-t` deadline spelling, not Linux `-W`.
        assert!(cmds.ping_probe.contains("-t 1"));
    }
}
