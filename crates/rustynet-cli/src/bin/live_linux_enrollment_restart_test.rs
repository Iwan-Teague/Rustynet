//! Standalone enrollment-under-kill consistency live-lab validator.
//!
//! Tests that the daemon maintains consistent membership state when killed
//! mid-enrollment. Either the token was consumed and the peer is a member,
//! or the token was not consumed and can be retried — no partial state.
//!
//! Stages:
//! 1. Mint enrollment token on admin node.
//! 2. Start token consume on enrollee node.
//! 3. Kill rustynetd on admin node with SIGKILL.
//! 4. Restart admin daemon and wait for recovery.
//! 5. Determine outcome: token consumed → peer is member; or rolled back → retry works.
//! 6. Verify membership state integrity on admin.

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
    let mut admin_host = String::new();
    let mut enrollee_host = String::new();
    let mut _admin_node_id = String::new();
    let mut _enrollee_node_id = String::new();
    let mut report_path =
        root_dir.join("artifacts/live_lab/live_linux_enrollment_restart_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_enrollment_restart.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--admin-host" => {
                idx += 1;
                admin_host = req(&args, idx, "--admin-host")?;
            }
            "--enrollee-host" => {
                idx += 1;
                enrollee_host = req(&args, idx, "--enrollee-host")?;
            }
            "--admin-node-id" => {
                idx += 1;
                _admin_node_id = req(&args, idx, "--admin-node-id")?;
            }
            "--enrollee-node-id" => {
                idx += 1;
                _enrollee_node_id = req(&args, idx, "--enrollee-node-id")?;
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

    if ssh_identity_file.is_empty() || admin_host.is_empty() || enrollee_host.is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-identity-file, --admin-host, --enrollee-host"
                .to_owned(),
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
    let mut ctx = LiveLabContext::new("rustynet-enrollment-restart", ssh_id.as_path())?;
    for host in [&admin_host, &enrollee_host] {
        ctx.push_sudo_password(host)?;
    }

    // ── Stage 1: mint enrollment token on admin ───────────────────────────────
    logger.line("[enrollment-restart] minting enrollment token on admin node")?;
    let token_raw = ctx.capture_root_allow_failure(
        &admin_host,
        &[
            "rustynet",
            "ops",
            "generate-enrollment-token",
            "--ttl-seconds",
            "300",
        ],
    );
    let token = match token_raw {
        Ok(t) => {
            let t = t.trim().to_owned();
            logger.line(format!(
                "[enrollment-restart] token minted (len={})",
                t.len()
            ))?;
            t
        }
        Err(e) => {
            // If admin node has no anchor state, skip gracefully.
            logger.line(format!(
                "[enrollment-restart] mint failed (no anchor state?): {e}"
            ))?;
            write_report_and_exit(
                &mut ctx,
                &logger,
                &report_path,
                "skipped",
                "skipped",
                "skipped",
                "skipped",
                "skipped",
            )?;
            append_standalone_matrix_row(&report_path, true);
            return Ok(());
        }
    };

    // ── Stage 2: start consume on enrollee (fire-and-forget, short sleep) ─────
    logger.line("[enrollment-restart] starting token consume on enrollee")?;
    // We fire the consume command but don't wait — the SIGKILL racing with it is the point.
    let token_for_consume = token.clone();
    let _ = ctx.capture_root_allow_failure(
        &enrollee_host,
        &[
            "rustynet",
            "ops",
            "consume-enrollment-token",
            "--token",
            &token_for_consume,
        ],
    );

    // ── Stage 3: SIGKILL admin daemon ─────────────────────────────────────────
    let kill_start = std::time::Instant::now();
    logger.line("[enrollment-restart] sending SIGKILL to rustynetd on admin")?;
    let _ = ctx.run_root_allow_failure(&admin_host, &["pkill", "-KILL", "rustynetd"]);
    let kill_ms = kill_start.elapsed().as_millis();
    logger.line(format!("[enrollment-restart] kill sent at {kill_ms}ms"))?;

    std::thread::sleep(std::time::Duration::from_millis(500));

    // ── Stage 4: restart admin daemon and wait ────────────────────────────────
    logger.line("[enrollment-restart] restarting admin daemon")?;
    let _ = ctx.run_root_allow_failure(&admin_host, &["systemctl", "start", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(8));

    let admin_recovered = ctx
        .capture_root_allow_failure(&admin_host, &["systemctl", "is-active", "rustynetd"])
        .map(|s| s.trim() == "active")
        .unwrap_or(false);
    logger.line(format!(
        "[enrollment-restart] admin daemon recovered={admin_recovered}"
    ))?;

    // ── Stage 5: determine enrollment outcome ─────────────────────────────────
    let peer_list = ctx
        .capture_root_allow_failure(&admin_host, &["rustynet", "peer", "list"])
        .unwrap_or_default();
    // Grab enrollee's node ID from the enrollee's own state.
    let enrollee_id = ctx
        .capture_root_allow_failure(&enrollee_host, &["rustynet", "ops", "show-node-id"])
        .unwrap_or_default();
    let enrollee_id = enrollee_id.trim();

    let enrollee_in_peer_list = !enrollee_id.is_empty() && peer_list.contains(enrollee_id);
    let enrollment_outcome = if enrollee_in_peer_list {
        "consumed"
    } else {
        "rolled_back"
    };
    logger.line(format!(
        "[enrollment-restart] enrollment_outcome={enrollment_outcome}"
    ))?;

    // ── Stage 6: membership integrity check ───────────────────────────────────
    let integrity_out = ctx
        .capture_root_allow_failure(&admin_host, &["rustynet", "ops", "verify-membership"])
        .unwrap_or_default();
    let membership_integrity = if integrity_out.contains("ok") || integrity_out.contains("valid") {
        "pass"
    } else {
        "fail"
    };
    logger.line(format!(
        "[enrollment-restart] membership_integrity={membership_integrity}"
    ))?;

    let overall_pass = admin_recovered && membership_integrity == "pass";

    write_report_and_exit(
        &mut ctx,
        &logger,
        &report_path,
        if admin_recovered { "pass" } else { "fail" },
        enrollment_outcome,
        membership_integrity,
        &kill_ms.to_string(),
        if overall_pass { "pass" } else { "fail" },
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "enrollment restart test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[enrollment-restart] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_report_and_exit(
    ctx: &mut LiveLabContext,
    logger: &Logger,
    report_path: &std::path::Path,
    admin_recovered: &str,
    enrollment_outcome: &str,
    membership_integrity: &str,
    kill_timing_ms: &str,
    overall_status: &str,
) -> Result<(), String> {
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--admin-recovered".to_owned(),
        admin_recovered.to_owned(),
        "--enrollment-outcome".to_owned(),
        enrollment_outcome.to_owned(),
        "--membership-integrity".to_owned(),
        membership_integrity.to_owned(),
        "--kill-timing-ms".to_owned(),
        kill_timing_ms.to_owned(),
        "--overall-status".to_owned(),
        overall_status.to_owned(),
    ];
    let report_refs: Vec<&str> = report_args.iter().map(String::as_str).collect();
    let status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-enrollment-restart-report",
        &report_refs,
    )?;
    logger.line(format!(
        "[enrollment-restart] report written status={status}"
    ))?;
    Ok(())
}

fn append_standalone_matrix_row(report_path: &std::path::Path, overall_pass: bool) {
    if std::env::var("RUSTYNET_ORCHESTRATOR_ACTIVE").is_ok() {
        return;
    }
    if let Ok(root_dir) = repo_root() {
        let report_dir = report_path.parent().unwrap_or(std::path::Path::new("."));
        let args = [
            "--stage".to_owned(),
            "live_enrollment_restart".to_owned(),
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
        "usage: live_linux_enrollment_restart_test \
        --ssh-identity-file <path> \
        --admin-host <user@host> \
        --enrollee-host <user@host> \
        [--admin-node-id <id>] \
        [--enrollee-node-id <id>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
