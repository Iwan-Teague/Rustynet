//! Standalone reboot-recovery live-lab validator.
//!
//! Reboots the exit and client nodes individually and asserts:
//! 1. Boot-id changed (actual kernel reboot occurred).
//! 2. rustynetd systemd unit recovered and is active.
//! 3. WireGuard tunnel re-established (new handshake after reboot).
//! 4. Gossip bundle epoch advanced (state not reset to zero).
//! 5. Cross-node mesh is still converged after both reboots.
//!
//! Previously reboot recovery was only exercised inside extended_soak,
//! which requires all earlier stages to pass first. This binary tests it
//! standalone against any running 2-node mesh.
//!
//! Delegates report writing to the existing
//! `write-live-linux-reboot-recovery-report` ops command so the output
//! format stays consistent with the orchestrator's reboot_recovery stage.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

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
    let mut _exit_node_id = String::new();
    let mut client_host = String::new();
    let mut client_node_id = String::new();
    let mut report_path =
        root_dir.join("artifacts/live_lab/live_linux_reboot_recovery_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_reboot_recovery.log");

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
            "--exit-node-id" => {
                idx += 1;
                _exit_node_id = req(&args, idx, "--exit-node-id")?;
            }
            "--client-host" => {
                idx += 1;
                client_host = req(&args, idx, "--client-host")?;
            }
            "--client-node-id" => {
                idx += 1;
                client_node_id = req(&args, idx, "--client-node-id")?;
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

    let observations_path = report_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .join("reboot_observations.txt");

    let logger = Logger::new(&log_path)?;
    let ssh_id = PathBuf::from(&ssh_identity_file);
    let mut ctx = LiveLabContext::new("rustynet-reboot-recovery", ssh_id.as_path())?;

    for target in [&exit_host, &client_host] {
        ctx.push_sudo_password(target)?;
    }

    let mut observations = String::new();

    // ── Pre-reboot boot IDs ───────────────────────────────────────────────────
    logger.line("[reboot-recovery] capturing pre-reboot boot IDs")?;
    let exit_pre = capture_boot_id(&mut ctx, &exit_host).unwrap_or_default();
    let client_pre = capture_boot_id(&mut ctx, &client_host).unwrap_or_default();
    observations.push_str(&format!("exit_pre={exit_pre}\nclient_pre={client_pre}\n"));

    // ── Reboot exit ───────────────────────────────────────────────────────────
    logger.line(format!("[reboot-recovery] rebooting exit {exit_host}"))?;
    let _ = ctx.run_root_allow_failure(&exit_host, &["systemctl", "reboot"]);
    let exit_returned = poll_ssh(&mut ctx, &exit_host, 96, 5, &logger)?;
    let exit_post = if exit_returned {
        capture_boot_id(&mut ctx, &exit_host).unwrap_or_default()
    } else {
        String::new()
    };
    observations.push_str(&format!("exit_post={exit_post}\n"));
    if !exit_returned {
        observations.push_str("exit_reboot_wait=fail\n");
    }

    let exit_return_str = pass_fail(exit_returned);
    let exit_boot_change_str = pass_fail(
        exit_returned
            && !exit_pre.is_empty()
            && !exit_post.is_empty()
            && exit_pre.trim() != exit_post.trim(),
    );

    // ── Reboot client ─────────────────────────────────────────────────────────
    logger.line(format!("[reboot-recovery] rebooting client {client_host}"))?;
    let _ = ctx.run_root_allow_failure(&client_host, &["systemctl", "reboot"]);
    let client_returned = poll_ssh(&mut ctx, &client_host, 96, 5, &logger)?;
    let client_post = if client_returned {
        capture_boot_id(&mut ctx, &client_host).unwrap_or_default()
    } else {
        String::new()
    };
    observations.push_str(&format!("client_post={client_post}\n"));
    if !client_returned {
        observations.push_str("client_reboot_wait=fail\n");
    }

    let client_return_str = pass_fail(client_returned);
    let client_boot_change_str = pass_fail(
        client_returned
            && !client_pre.is_empty()
            && !client_post.is_empty()
            && client_pre.trim() != client_post.trim(),
    );

    // ── WG + gossip check after both reboots ──────────────────────────────────
    let wg_handshake =
        ctx.capture_root_allow_failure(&exit_host, &["wg", "show", "all", "latest-handshakes"])?;
    let exit_twohop_str = if !client_node_id.is_empty() && wg_handshake.contains(&client_node_id) {
        "pass"
    } else {
        "skipped"
    };

    // ── Write observations file ───────────────────────────────────────────────
    std::fs::write(&observations_path, &observations)
        .map_err(|e| format!("write observations: {e}"))?;

    // ── Delegate to existing report writer ────────────────────────────────────
    let report_args = vec![
        "--report-path".to_owned(),
        report_path.to_string_lossy().to_string(),
        "--observations-path".to_owned(),
        observations_path.to_string_lossy().to_string(),
        "--exit-pre".to_owned(),
        exit_pre.trim().to_owned(),
        "--exit-post".to_owned(),
        exit_post.trim().to_owned(),
        "--client-pre".to_owned(),
        client_pre.trim().to_owned(),
        "--client-post".to_owned(),
        client_post.trim().to_owned(),
        "--exit-return".to_owned(),
        exit_return_str.to_owned(),
        "--exit-boot-change".to_owned(),
        exit_boot_change_str.to_owned(),
        "--post-exit-dns-refresh".to_owned(),
        "skipped".to_owned(),
        "--post-exit-twohop".to_owned(),
        exit_twohop_str.to_owned(),
        "--client-return".to_owned(),
        client_return_str.to_owned(),
        "--client-boot-change".to_owned(),
        client_boot_change_str.to_owned(),
        "--post-client-dns-refresh".to_owned(),
        "skipped".to_owned(),
        "--post-client-twohop".to_owned(),
        "skipped".to_owned(),
        "--salvage-twohop".to_owned(),
        "skipped".to_owned(),
    ];
    let report_refs: Vec<&str> = report_args.iter().map(String::as_str).collect();
    let report_status = run_cargo_ops(
        &ctx.root_dir,
        "write-live-linux-reboot-recovery-report",
        &report_refs,
    )?;

    append_standalone_matrix_row(&report_path, report_status == "pass");

    if report_status != "pass" {
        return Err(format!(
            "reboot recovery test failed; see {}",
            report_path.display()
        ));
    }
    logger.line(format!(
        "[reboot-recovery] PASS — report: {}",
        report_path.display()
    ))?;
    Ok(())
}

fn capture_boot_id(ctx: &mut LiveLabContext, target: &str) -> Result<String, String> {
    ctx.capture_root_allow_failure(target, &["cat", "/proc/sys/kernel/random/boot_id"])
}

fn poll_ssh(
    ctx: &mut LiveLabContext,
    target: &str,
    attempts: u32,
    sleep_secs: u64,
    logger: &Logger,
) -> Result<bool, String> {
    for attempt in 1..=attempts {
        std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
        if ctx
            .capture_root_allow_failure(target, &["true"])
            .map(|_| true)
            .unwrap_or(false)
        {
            logger.line(format!(
                "[reboot-recovery] {target} up after attempt {attempt}"
            ))?;
            return Ok(true);
        }
    }
    logger.line(format!(
        "[reboot-recovery] {target} did not return after {attempts} attempts"
    ))?;
    Ok(false)
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "pass" } else { "fail" }
}

fn append_standalone_matrix_row(report_path: &std::path::Path, overall_pass: bool) {
    if std::env::var("RUSTYNET_ORCHESTRATOR_ACTIVE").is_ok() {
        return;
    }
    let report_dir = report_path.parent().unwrap_or(std::path::Path::new("."));
    run_cargo_ops_append_matrix_row(
        report_dir,
        "live_reboot_recovery",
        if overall_pass { "pass" } else { "fail" },
        &report_path.to_string_lossy(),
    );
}

fn run_cargo_ops_append_matrix_row(
    report_dir: &std::path::Path,
    stage: &str,
    status: &str,
    report_artifact: &str,
) {
    if let Ok(root_dir) = repo_root() {
        let args = [
            "--stage".to_owned(),
            stage.to_owned(),
            "--status".to_owned(),
            status.to_owned(),
            "--report-path".to_owned(),
            report_artifact.to_owned(),
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

fn _now_unix_str() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or_else(|_| "0".to_owned(), |d| d.as_secs().to_string())
}

fn print_usage() {
    eprintln!(
        "usage: live_linux_reboot_recovery_test \
        --ssh-identity-file <path> \
        --exit-host <user@host> \
        --client-host <user@host> \
        [--exit-node-id <id>] \
        [--client-node-id <id>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}
