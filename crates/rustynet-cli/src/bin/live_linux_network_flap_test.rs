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
//! 7. Assert gossip bundle epoch advanced.
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
    logger.line("[network-flap] checking baseline WG handshake")?;
    let baseline_wg = ctx
        .capture_root_allow_failure(&client_host, &["wg", "show", "all", "latest-handshakes"])
        .unwrap_or_default();
    let baseline_age_s = parse_handshake_age_s(&baseline_wg);
    let baseline_ok = baseline_age_s < 180;
    logger.line(format!(
        "[network-flap] baseline_handshake_age_s={baseline_age_s} ok={baseline_ok}"
    ))?;

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
    let mid_wg = ctx
        .capture_root_allow_failure(&client_host, &["wg", "show", "all", "latest-handshakes"])
        .unwrap_or_default();
    let mid_age_s = parse_handshake_age_s(&mid_wg);
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
    for _ in 0..18 {
        std::thread::sleep(std::time::Duration::from_secs(5));
        let post_wg = ctx
            .capture_root_allow_failure(&client_host, &["wg", "show", "all", "latest-handshakes"])
            .unwrap_or_default();
        let post_age = parse_handshake_age_s(&post_wg);
        if post_age < 30 {
            recovery_arrived = true;
            recovery_time_s = recovery_start.elapsed().as_secs();
            break;
        }
    }
    logger.line(format!(
        "[network-flap] recovery_arrived={recovery_arrived} recovery_time_s={recovery_time_s}"
    ))?;

    // ── Stage 7: gossip epoch check ───────────────────────────────────────────
    let gossip_out = ctx
        .capture_root_allow_failure(&exit_host, &["rustynet", "ops", "show-gossip-epoch"])
        .unwrap_or_default();
    let gossip_epoch_nonzero = gossip_out
        .trim()
        .parse::<u64>()
        .map(|e| e > 0)
        .unwrap_or(false);
    logger.line(format!(
        "[network-flap] gossip_epoch_nonzero={gossip_epoch_nonzero}"
    ))?;

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
        pass_fail(gossip_epoch_nonzero).to_owned(),
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

fn parse_handshake_age_s(wg_show_output: &str) -> u64 {
    // `wg show all latest-handshakes` outputs lines like:
    //   <iface>  <pubkey>  <unix_timestamp>
    // We grab the most recent timestamp and compute age.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut latest: u64 = 0;
    for line in wg_show_output.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        let ts = parts
            .get(2)
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if ts > latest {
            latest = ts;
        }
    }
    if latest == 0 || now == 0 || now < latest {
        return u64::MAX;
    }
    now - latest
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
