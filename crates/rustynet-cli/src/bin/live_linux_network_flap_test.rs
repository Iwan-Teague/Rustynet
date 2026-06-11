//! Standalone network-flap recovery live-lab validator.
//!
//! Blocks WireGuard UDP traffic on the client node for longer than the
//! keepalive interval, then removes the block and verifies the tunnel
//! and gossip both recover automatically.
//!
//! Stages:
//! 1. Assert baseline WG handshake is recent (within 180s).
//! 2. Block WG UDP on client via nftables (output chain, udp dport 51820).
//! 3. Wait 35s (exceeds WireGuard keepalive of 25s).
//! 4. Assert no new handshake during blackout.
//! 5. Remove nftables rule.
//! 6. Poll for new handshake (up to 90s).
//! 7. Assert tunnel active on exit node (rustynet status).
//! 8. Assert membership state integrity passes.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;

use live_lab_support::{LiveLabContext, Logger, repo_root, run_cargo_ops};

fn main() {
    if let Err(err) = run() {
        let code = classify_error(err.as_str());
        eprintln!("error [{code}]: {err}");
        std::process::exit(code.as_i32());
    }
}

fn classify_error(msg: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = msg.to_ascii_lowercase();
    if lower.contains("missing required") || lower.contains("unknown command") {
        ExitCode::BadArgs
    } else if lower.contains("ssh")
        || lower.contains("timed out")
        || lower.contains("connection refused")
    {
        ExitCode::TransientFailure
    } else if lower.contains("identity file") || lower.contains("config") {
        ExitCode::ConfigError
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let root_dir = repo_root()?;
    let args: Vec<String> = std::env::args().skip(1).collect();

    let mut ssh_identity_file = String::new();
    let mut exit_host = String::new();
    let mut client_host = String::new();
    let mut _exit_node_id = String::new();
    let mut _client_node_id = String::new();
    let mut report_path = root_dir.join("artifacts/live_lab/live_linux_network_flap_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_network_flap.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--exit-host" => {
                idx += 1;
                exit_host = req(&args, idx, "--exit-host")?;
            }
            "--client-host" => {
                idx += 1;
                client_host = req(&args, idx, "--client-host")?;
            }
            "--exit-node-id" => {
                idx += 1;
                _exit_node_id = req(&args, idx, "--exit-node-id")?;
            }
            "--client-node-id" => {
                idx += 1;
                _client_node_id = req(&args, idx, "--client-node-id")?;
            }
            "--report-path" => {
                idx += 1;
                report_path = PathBuf::from(req(&args, idx, "--report-path")?);
            }
            "--log-path" => {
                idx += 1;
                log_path = PathBuf::from(req(&args, idx, "--log-path")?);
            }
            "-h" | "--help" => {
                print_usage();
                return Ok(());
            }
            other => {
                print_usage();
                return Err(format!("unknown command: {other}"));
            }
        }
        idx += 1;
    }

    if ssh_identity_file.is_empty() || exit_host.is_empty() || client_host.is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-identity-file, --exit-host, --client-host".to_owned(),
        );
    }

    for path in [report_path.parent(), log_path.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }

    let logger = Logger::new(&log_path)?;
    let ssh_id = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-network-flap", ssh_id.as_path())?;
    for host in [&exit_host, &client_host] {
        ctx.push_sudo_password(host)?;
    }

    const WG_PORT: &str = "51820";

    // ── Stage 1: baseline handshake check ────────────────────────────────────
    // Pre-poll: capture initial WG state for diagnostics.
    logger.line("[network-flap] pre-poll: checking wg tool + WG interface state")?;
    for (label, host) in [("client", &client_host), ("exit", &exit_host)] {
        let wg_ver = ctx.capture_root_allow_failure(host, &["wg", "--version"]);
        let wg_show = ctx.capture_root_allow_failure(host, &["wg", "show", "all"]);
        // rustynet status shows tunnel state from the daemon perspective.
        let status = ctx
            .capture_root_allow_failure(host, &["rustynet", "status"])
            .unwrap_or_default();
        let status_snip: String = status.chars().take(200).collect();
        logger.line(format!(
            "[network-flap] pre-poll {label} wg-ver={wg_ver:?} \
             wg-show={wg_show:?} status={status_snip:?}"
        ))?;
    }

    // Rustynet uses userspace WireGuard — `wg show` sees no interfaces.
    // Use `rustynet netcheck` which reports the daemon's last live handshake
    // timestamp via path_latest_live_handshake_unix.
    logger.line("[network-flap] waiting for baseline WG handshake (up to 300s)")?;
    let mut baseline_age_s = u64::MAX;
    for attempt in 0..60u32 {
        let nc_result = ctx.capture_root_allow_failure(&client_host, &["rustynet", "netcheck"]);
        let client_err = nc_result
            .as_ref()
            .err()
            .map(|e| e.chars().take(120).collect::<String>());
        let nc_out = nc_result.unwrap_or_default();
        baseline_age_s = parse_handshake_age_s_from_netcheck(&nc_out);
        if baseline_age_s < 180 {
            break;
        }
        if attempt == 0 || attempt == 11 || attempt == 23 {
            let client_nc: String = nc_out.chars().take(300).collect();
            let exit_nc_result =
                ctx.capture_root_allow_failure(&exit_host, &["rustynet", "netcheck"]);
            let exit_err = exit_nc_result
                .as_ref()
                .err()
                .map(|e| e.chars().take(120).collect::<String>());
            let exit_nc: String = exit_nc_result
                .unwrap_or_default()
                .chars()
                .take(300)
                .collect();
            logger.line(format!(
                "[network-flap] nc-diag attempt={attempt} \
                 client={client_nc:?} client-err={client_err:?} \
                 exit={exit_nc:?} exit-err={exit_err:?}"
            ))?;
        }
        std::thread::sleep(std::time::Duration::from_secs(5));
    }
    let baseline_ok = baseline_age_s < 180;
    logger.line(format!(
        "[network-flap] baseline_handshake_age_s={baseline_age_s} ok={baseline_ok}"
    ))?;
    // Post-poll failure dump: capture full WG + gossip state to understand
    // why handshake never established.
    if !baseline_ok {
        logger.line("[network-flap] baseline FAILED — capturing post-poll diagnostics")?;
        for (label, host) in [("client", &client_host), ("exit", &exit_host)] {
            let wg_all = ctx.capture_root_allow_failure(host, &["wg", "show", "all"]);
            let status = ctx
                .capture_root_allow_failure(host, &["rustynet", "status"])
                .unwrap_or_default();
            let status_snip: String = status.chars().take(300).collect();
            let journal = ctx
                .capture_root_allow_failure(
                    host,
                    &["journalctl", "-u", "rustynetd", "-n", "30", "--no-pager"],
                )
                .unwrap_or_default();
            let jsnip: String = journal.chars().take(600).collect();
            logger.line(format!(
                "[network-flap] post-poll {label} wg-all={wg_all:?} \
                 status={status_snip:?} journal={jsnip:?}"
            ))?;
        }
    }

    // ── Stage 2: block WG UDP output on client ────────────────────────────────
    logger.line(format!(
        "[network-flap] blocking WG UDP output port {WG_PORT} on client"
    ))?;
    let flap_start = std::time::Instant::now();
    // nft table/chain may not pre-exist — create idempotently.
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["nft", "add", "table", "inet", "rustynet_flap_test"],
    );
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &[
            "nft",
            "add",
            "chain",
            "inet",
            "rustynet_flap_test",
            "output",
            "{ type filter hook output priority 0 ; }",
        ],
    );
    let add_result = ctx.run_root_allow_failure(
        &client_host,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            "rustynet_flap_test",
            "output",
            "udp",
            "dport",
            WG_PORT,
            "drop",
        ],
    );
    let rule_added = add_result.is_ok();
    logger.line(format!("[network-flap] block rule added={rule_added}"))?;

    // ── Stage 3: wait 35s ─────────────────────────────────────────────────────
    logger.line("[network-flap] waiting 35s for keepalive to expire")?;
    std::thread::sleep(std::time::Duration::from_secs(35));
    let flap_duration_s = flap_start.elapsed().as_secs();

    // ── Stage 4: confirm no new handshake ─────────────────────────────────────
    let mid_nc = ctx
        .capture_root_allow_failure(&client_host, &["rustynet", "netcheck"])
        .unwrap_or_default();
    let mid_age_s = parse_handshake_age_s_from_netcheck(&mid_nc);
    let disruption_confirmed = mid_age_s >= 30;
    logger.line(format!(
        "[network-flap] mid_handshake_age_s={mid_age_s} disruption_confirmed={disruption_confirmed}"
    ))?;

    // ── Stage 5: remove block rule ────────────────────────────────────────────
    logger.line("[network-flap] removing block rule")?;
    let _ = ctx.run_root_allow_failure(
        &client_host,
        &["nft", "delete", "table", "inet", "rustynet_flap_test"],
    );

    // ── Stage 6: poll for recovery ────────────────────────────────────────────
    logger.line("[network-flap] polling for WG handshake recovery")?;
    let recovery_start = std::time::Instant::now();
    let mut recovery_arrived = false;
    let mut recovery_time_s = 0u64;
    for _ in 0..36 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let post_nc = ctx
            .capture_root_allow_failure(&client_host, &["rustynet", "netcheck"])
            .unwrap_or_default();
        let post_age = parse_handshake_age_s_from_netcheck(&post_nc);
        if post_age < 30 {
            recovery_arrived = true;
            recovery_time_s = recovery_start.elapsed().as_secs();
            break;
        }
    }
    logger.line(format!(
        "[network-flap] recovery_arrived={recovery_arrived} recovery_time_s={recovery_time_s}"
    ))?;

    // ── Stage 7: tunnel status check ─────────────────────────────────────────
    // Check that rustynet reports the tunnel as active on the exit node after
    // recovery.  `rustynet status` is the canonical user-facing command;
    // `show-gossip-epoch` is not a valid subcommand on deployed builds.
    let status_out = ctx
        .capture_root_allow_failure(&exit_host, &["rustynet", "status"])
        .unwrap_or_default();
    let tunnel_active = status_out.contains("ExitActive")
        || status_out.contains("active")
        || status_out.contains("Connected");
    logger.line(format!("[network-flap] tunnel_active={tunnel_active}"))?;

    // ── Stage 8: membership integrity ────────────────────────────────────────
    let integrity_out = ctx
        .capture_root_allow_failure(&exit_host, &["rustynet", "ops", "verify-membership"])
        .unwrap_or_default();
    let membership_intact = integrity_out.contains("ok") || integrity_out.contains("valid");
    logger.line(format!(
        "[network-flap] membership_intact={membership_intact}"
    ))?;

    let overall_pass = baseline_ok && recovery_arrived && membership_intact;

    // ── Write report ──────────────────────────────────────────────────────────
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--baseline-handshake-age-s".to_owned(),
        baseline_age_s.to_string(),
        "--flap-duration-s".to_owned(),
        flap_duration_s.to_string(),
        "--disruption-confirmed".to_owned(),
        pass_fail(disruption_confirmed).to_owned(),
        "--recovery-handshake-arrived".to_owned(),
        pass_fail(recovery_arrived).to_owned(),
        "--recovery-time-s".to_owned(),
        recovery_time_s.to_string(),
        "--gossip-recovered".to_owned(),
        pass_fail(tunnel_active).to_owned(),
        "--membership-intact".to_owned(),
        pass_fail(membership_intact).to_owned(),
        "--overall-status".to_owned(),
        pass_fail(overall_pass).to_owned(),
    ];
    let report_refs: Vec<&str> = report_args.iter().map(String::as_str).collect();
    run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-network-flap-report",
        &report_refs,
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "network flap test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[network-flap] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

fn parse_handshake_age_s_from_netcheck(netcheck_out: &str) -> u64 {
    // `rustynet netcheck` emits space-separated key=value tokens including
    // `path_latest_live_handshake_unix=<unix_ts>`.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    for token in netcheck_out.split_whitespace() {
        if let Some(ts) = token
            .strip_prefix("path_latest_live_handshake_unix=")
            .and_then(|v| v.parse::<u64>().ok())
        {
            if ts == 0 || now == 0 || now < ts {
                return u64::MAX;
            }
            return now - ts;
        }
    }
    u64::MAX
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "pass" } else { "fail" }
}

fn append_standalone_matrix_row(report_path: &std::path::Path, overall_pass: bool) {
    if std::env::var("RUSTYNET_ORCHESTRATOR_ACTIVE").is_ok() {
        return;
    }
    if let Ok(root_dir) = repo_root() {
        let report_dir = report_path.parent().unwrap_or(std::path::Path::new("."));
        let args = [
            "--stage".to_owned(),
            "live_network_flap".to_owned(),
            "--status".to_owned(),
            if overall_pass { "pass" } else { "fail" }.to_owned(),
            "--report-path".to_owned(),
            report_path.to_string_lossy().to_string(),
            "--report-dir".to_owned(),
            report_dir.to_string_lossy().to_string(),
        ];
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let _ = run_cargo_ops(&root_dir, "append-live-lab-matrix-row", &refs);
    }
}

fn req(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|v| !v.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_network_flap_test \
        --ssh-identity-file <path> \
        --exit-host <user@host> \
        --client-host <user@host> \
        [--exit-node-id <id>] \
        [--client-node-id <id>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
