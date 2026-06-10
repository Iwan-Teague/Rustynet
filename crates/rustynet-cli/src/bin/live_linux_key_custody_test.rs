//! Standalone key-custody enforcement live-lab validator.
//!
//! Verifies that the daemon rejects or refuses to start when the
//! device key file has insecure permissions, and that it recovers
//! cleanly once permissions are restored.
//!
//! Stages:
//! 1. Assert initial key file mode is 0600 and key dir mode is 0700.
//! 2. chmod key file to 0644 via sudo.
//! 3. Restart daemon; assert it fails to start or logs a custody error.
//! 4. Restore permissions to 0600.
//! 5. Restart daemon; assert it recovers and becomes active.

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
    let mut target_host = String::new();
    let mut report_path = root_dir.join("artifacts/live_lab/live_linux_key_custody_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_key_custody.log");

    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--ssh-identity-file" => {
                idx += 1;
                ssh_identity_file = req(&args, idx, "--ssh-identity-file")?;
            }
            "--target-host" => {
                idx += 1;
                target_host = req(&args, idx, "--target-host")?;
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

    if ssh_identity_file.is_empty() || target_host.is_empty() {
        print_usage();
        return Err("missing required argument: --ssh-identity-file, --target-host".to_owned());
    }

    for path in [report_path.parent(), log_path.parent()]
        .into_iter()
        .flatten()
    {
        std::fs::create_dir_all(path).map_err(|e| format!("mkdir {}: {e}", path.display()))?;
    }

    let logger = Logger::new(&log_path)?;
    let ssh_id = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-key-custody", ssh_id.as_path())?;
    ctx.push_sudo_password(&target_host)?;

    const KEY_FILE: &str = "/var/lib/rustynet/keys/wireguard.key.enc";
    const KEY_DIR: &str = "/var/lib/rustynet/keys";

    // ── Stage 1: initial permission check ────────────────────────────────────
    logger.line("[key-custody] checking initial key file permissions")?;
    let initial_key_mode = ctx
        .capture_root_allow_failure(&target_host, &["stat", "--format=%a", KEY_FILE])
        .unwrap_or_default();
    let initial_key_mode = initial_key_mode.trim().to_owned();
    let initial_dir_mode = ctx
        .capture_root_allow_failure(&target_host, &["stat", "--format=%a", KEY_DIR])
        .unwrap_or_default();
    let initial_dir_mode = initial_dir_mode.trim().to_owned();

    let initial_mode_ok = initial_key_mode == "600" && initial_dir_mode == "700";
    logger.line(format!(
        "[key-custody] key file mode={initial_key_mode} dir mode={initial_dir_mode} ok={initial_mode_ok}"
    ))?;

    // ── Stage 2: set insecure permissions ────────────────────────────────────
    logger.line("[key-custody] setting insecure permissions (0644) on key file")?;
    let _ = ctx.run_root_allow_failure(&target_host, &["chmod", "0644", KEY_FILE]);
    let _ = ctx.run_root_allow_failure(&target_host, &["systemctl", "stop", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(2));

    // ── Stage 3: restart with bad permissions — expect rejection ─────────────
    logger.line("[key-custody] attempting daemon start with insecure key permissions")?;
    let _ = ctx.run_root_allow_failure(&target_host, &["systemctl", "start", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(5));

    let daemon_active_after_bad_mode = ctx
        .capture_root_allow_failure(&target_host, &["systemctl", "is-active", "rustynetd"])
        .map(|s| s.trim() == "active")
        .unwrap_or(false);

    // Daemon should NOT be active (failed to start) or should log custody rejection.
    let daemon_rejected = !daemon_active_after_bad_mode;

    // Check journal for custody rejection log lines.
    let journal_snippet = ctx
        .capture_root_allow_failure(
            &target_host,
            &["journalctl", "-u", "rustynetd", "-n", "50", "--no-pager"],
        )
        .unwrap_or_default();
    let custody_log_found = journal_snippet.contains("custody")
        || journal_snippet.contains("permission")
        || journal_snippet.contains("0600")
        || journal_snippet.contains("insecure");

    let rejection_confirmed = daemon_rejected || custody_log_found;
    logger.line(format!(
        "[key-custody] daemon active after bad mode={daemon_active_after_bad_mode} \
         custody_log_found={custody_log_found} rejection_confirmed={rejection_confirmed}"
    ))?;

    // ── Stage 4: restore permissions ─────────────────────────────────────────
    logger.line("[key-custody] restoring key file permissions to 0600")?;
    let _ = ctx.run_root_allow_failure(&target_host, &["chmod", "0600", KEY_FILE]);
    // Clear systemd's failed-start counter before restarting: a single
    // rejected start (bad perms) increments the burst counter and the unit
    // stays in "failed" state, blocking the next `systemctl start`.
    let _ = ctx.run_root_allow_failure(&target_host, &["systemctl", "reset-failed", "rustynetd"]);
    let _ = ctx.run_root_allow_failure(&target_host, &["systemctl", "start", "rustynetd"]);
    std::thread::sleep(std::time::Duration::from_secs(8));

    // ── Stage 5: assert recovery ──────────────────────────────────────────────
    let daemon_recovered = ctx
        .capture_root_allow_failure(&target_host, &["systemctl", "is-active", "rustynetd"])
        .map(|s| s.trim() == "active")
        .unwrap_or(false);
    logger.line(format!(
        "[key-custody] daemon recovered after restore={daemon_recovered}"
    ))?;

    let restored_mode = ctx
        .capture_root_allow_failure(&target_host, &["stat", "--format=%a", KEY_FILE])
        .unwrap_or_default();
    let final_mode_ok = restored_mode.trim() == "600";

    let overall_pass = initial_mode_ok && rejection_confirmed && daemon_recovered && final_mode_ok;

    // ── Write report ──────────────────────────────────────────────────────────
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--initial-key-file-mode".to_owned(),
        initial_key_mode,
        "--initial-key-dir-mode".to_owned(),
        initial_dir_mode,
        "--initial-mode-ok".to_owned(),
        pass_fail(initial_mode_ok).to_owned(),
        "--daemon-rejected-bad-mode".to_owned(),
        pass_fail(rejection_confirmed).to_owned(),
        "--daemon-recovered".to_owned(),
        pass_fail(daemon_recovered).to_owned(),
        "--final-mode-ok".to_owned(),
        pass_fail(final_mode_ok).to_owned(),
        "--overall-status".to_owned(),
        pass_fail(overall_pass).to_owned(),
    ];
    let report_refs: Vec<&str> = report_args.iter().map(String::as_str).collect();
    run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-key-custody-report",
        &report_refs,
    )?;

    append_standalone_matrix_row(&report_path, overall_pass);

    if !overall_pass {
        return Err(format!(
            "key custody test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[key-custody] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
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
            "live_key_custody".to_owned(),
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
        "usage: live_linux_key_custody_test \
        --ssh-identity-file <path> \
        --target-host <user@host> \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
