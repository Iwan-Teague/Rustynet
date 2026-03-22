#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

mod live_lab_bin_support;

use std::env;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use live_lab_bin_support as live_lab_support;

use live_lab_support::{
    Logger, append_env_assignment, capture_root, create_workspace, enforce_host,
    ensure_pinned_known_hosts_file, ensure_safe_token, git_head_commit,
    issue_assignment_bundles_from_env, issue_traversal_bundles_from_env,
    load_home_known_hosts_path, read_file, remote_src_dir, require_command, run_root, scp_to,
    seed_known_hosts, shell_quote, status, target_address, unix_now, wait_for_daemon_socket,
    write_file,
};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;
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
    let pinned_known_hosts = match config.pinned_known_hosts_file {
        Some(path) => path,
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

    let exit_a_addr = target_address(&config.exit_a_host).to_string();
    let exit_b_addr = target_address(&config.exit_b_host).to_string();
    let client_addr = target_address(&config.client_host).to_string();

    let nodes_spec = format!(
        "{}|{}:51820|{};{}|{}:51820|{};{}|{}:51820|{}",
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

    std::thread::sleep(std::time::Duration::from_secs(5));

    let monitor_path = config.monitor_log.clone();
    write_file(&monitor_path, "")?;
    let mut switch_ts = 0u64;
    let mut last_traversal_refresh_ts = unix_now();
    for i in 1..=config.monitor_iterations {
        let ts = unix_now();
        if ts.saturating_sub(last_traversal_refresh_ts) >= config.traversal_refresh_interval_secs {
            logger.line(
                "[exit-handoff] refreshing signed traversal bundles during handoff monitor",
            )?;
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
            last_traversal_refresh_ts = unix_now();
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
        let endpoints = capture_root(
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
                "{}|iter={}|ping_rc={}|route={}|status={}|endpoints={}",
                ts,
                i,
                ping_rc,
                route_line.replace('\n', " "),
                client_status.replace('\n', " "),
                endpoints.replace('\n', " ")
            ),
        )?;
        if i == config.switch_iteration {
            logger.line("[exit-handoff] refreshing signed traversal bundles before exit switch")?;
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
            last_traversal_refresh_ts = unix_now();
            switch_ts = ts;
            logger.line(
                format!(
                    "[exit-handoff] switching client exit to {}",
                    config.exit_b_node_id
                )
                .as_str(),
            )?;
            live_lab_support::apply_role_coupling(
                &config.ssh_identity_file,
                &work_known_hosts,
                &config.client_host,
                "client",
                Some(&config.exit_b_node_id),
                false,
                "/etc/rustynet/assignment-refresh.env",
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
    let client_endpoints_final = capture_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        &config.client_host,
        "wg show rustynet0 endpoints || true",
    )?;
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
    logger.line("[exit-handoff] final client endpoints")?;
    logger.block(&(client_endpoints_final.clone() + "\n"))?;

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
        if line.contains(&format!("exit_node={}", config.exit_b_node_id)) {
            Some(ts)
        } else {
            None
        }
    });
    let reconvergence_secs = first_switch_ts
        .and_then(|value| value.checked_sub(switch_ts))
        .map(|value| value as i64)
        .unwrap_or(-1);

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
    let check_exit_b_endpoint_visible = if client_endpoints_final
        .contains(&format!("{exit_b_addr}:51820"))
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

    let overall = [
        check_handoff_reconvergence,
        check_no_route_leak,
        check_no_restricted_safe_mode,
        check_exit_b_endpoint_visible,
        check_both_exits_nat,
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
        "{{\n  \"phase\": \"phase10\",\n  \"mode\": \"live_linux_exit_handoff\",\n  \"evidence_mode\": \"measured\",\n  \"captured_at\": \"{}\",\n  \"captured_at_unix\": {},\n  \"git_commit\": \"{}\",\n  \"status\": \"{}\",\n  \"exit_a_host\": \"{}\",\n  \"exit_b_host\": \"{}\",\n  \"client_host\": \"{}\",\n  \"switch_iteration\": {},\n  \"monitor_iterations\": {},\n  \"reconvergence_seconds\": {},\n  \"checks\": {{\n    \"handoff_reconvergence\": \"{}\",\n    \"no_route_leak_during_handoff\": \"{}\",\n    \"no_restricted_safe_mode\": \"{}\",\n    \"exit_b_endpoint_visible\": \"{}\",\n    \"both_exits_nat\": \"{}\"\n  }},\n  \"source_artifacts\": [\n    \"{}\",\n    \"{}\"\n  ]\n}}\n",
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
        return Err("exit-handoff validation failed".to_string());
    }
    Ok(())
}

#[derive(Debug)]
struct Config {
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
            ssh_identity_file: PathBuf::new(),
            exit_a_host: "debian@192.168.18.49".to_string(),
            exit_b_host: "mint@192.168.18.53".to_string(),
            client_host: "debian@192.168.18.65".to_string(),
            exit_a_node_id: "exit-49".to_string(),
            exit_b_node_id: "client-53".to_string(),
            client_node_id: "client-65".to_string(),
            ssh_allow_cidrs: "192.168.18.0/24".to_string(),
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
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?)
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
                        .map_err(|_| "switch iteration must be a positive integer".to_string())?
                }
                "--monitor-iterations" => {
                    config.monitor_iterations = next_value(&mut iter, &arg)?
                        .parse()
                        .map_err(|_| "monitor iterations must be a positive integer".to_string())?
                }
                "--traversal-ttl-secs" => {
                    config.traversal_ttl_secs = next_value(&mut iter, &arg)?
                        .parse()
                        .map_err(|_| "traversal ttl seconds must be an integer".to_string())?
                }
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--monitor-log" => config.monitor_log = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?))
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
                    .to_string(),
            );
        }
        validate_positive_integer("switch iteration", config.switch_iteration)?;
        validate_positive_integer("monitor iterations", config.monitor_iterations)?;
        if config.traversal_ttl_secs == 0 || config.traversal_ttl_secs > 120 {
            return Err("traversal ttl seconds must be in the range 1..=120".to_string());
        }
        config.traversal_refresh_interval_secs = if config.traversal_ttl_secs <= 30 {
            10
        } else {
            config.traversal_ttl_secs / 2
        };
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
    Ok(())
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
        "install -m 0644 -o root -g root /tmp/rn-assignment.pub /etc/rustynet/assignment.pub && install -m 0640 -o root -g rustynetd /tmp/rn-assignment.bundle /var/lib/rustynet/rustynetd.assignment && rm -f /var/lib/rustynet/rustynetd.assignment.watermark /tmp/rn-assignment.pub /tmp/rn-assignment.bundle",
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
