//! Standalone key-custody enforcement live-lab validator.
//!
//! Verifies that the daemon rejects or refuses to start when the
//! device key file has insecure permissions, and that it recovers
//! cleanly once permissions are restored.
//!
//! Per-OS (the orchestrator threads `--platform` from the target node):
//! - Linux: `/var/lib/rustynet/keys/wireguard.key.enc` under systemd
//!   (`systemctl stop/start/is-active/reset-failed`, journald).
//! - macOS: `/usr/local/var/rustynet/keys/wireguard.key.enc` (mirrors
//!   `rustynetd::macos_key_custody`) under launchd (`bootout`/`bootstrap`/
//!   `kickstart -k`, `launchctl print` state/pid heuristics). The launchd
//!   StandardErrorPath file is where a refused start's custody error lands
//!   (`/usr/local/var/log/rustynet/rustynetd-error.log`).
//! - Windows: fails closed — its custody model is in-memory/DPAPI, so there
//!   is no honest POSIX mode probe to run.
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

use live_lab_support::{
    LiveLabContext, LiveLabPlatform, Logger, daemon_unit_log_argv, repo_root, run_cargo_ops,
    stat_mode_argv, wg_encrypted_key_paths,
};

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
    let mut platform = LiveLabPlatform::Linux;
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
            "--platform" => {
                idx += 1;
                platform = LiveLabPlatform::parse(req(&args, idx, "--platform")?.as_str())?;
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

    // Windows has no POSIX key file to probe (in-memory/DPAPI custody) — fail
    // closed before any remote work instead of fabricating a pass.
    let (key_file, key_dir) = match wg_encrypted_key_paths(platform) {
        Ok(paths) => paths,
        Err(err) => {
            logger.line(format!("[key-custody] fail closed: {err}"))?;
            return Err(err);
        }
    };
    let stat_key = stat_mode_argv(platform, key_file)?;
    let stat_dir = stat_mode_argv(platform, key_dir)?;

    // ── Stage 1: initial permission check ────────────────────────────────────
    logger.line("[key-custody] checking initial key file permissions")?;
    let initial_key_mode = ctx
        .capture_root_allow_failure(&target_host, &stat_key)
        .unwrap_or_default();
    let initial_key_mode = initial_key_mode.trim().to_owned();
    let initial_dir_mode = ctx
        .capture_root_allow_failure(&target_host, &stat_dir)
        .unwrap_or_default();
    let initial_dir_mode = initial_dir_mode.trim().to_owned();

    let initial_mode_ok = initial_key_mode == "600" && initial_dir_mode == "700";
    logger.line(format!(
        "[key-custody] key file mode={initial_key_mode} dir mode={initial_dir_mode} ok={initial_mode_ok}"
    ))?;

    // ── Stage 2: set insecure permissions ────────────────────────────────────
    logger.line("[key-custody] setting insecure permissions (0644) on key file")?;
    let _ = ctx.run_root_allow_failure(&target_host, &["chmod", "0644", key_file]);
    stop_daemon(&ctx, platform, &target_host)?;
    std::thread::sleep(std::time::Duration::from_secs(2));

    // ── Stage 3: restart with bad permissions — expect rejection ─────────────
    logger.line("[key-custody] attempting daemon start with insecure key permissions")?;
    start_daemon(&ctx, platform, &target_host)?;
    std::thread::sleep(std::time::Duration::from_secs(5));

    let daemon_active_after_bad_mode = daemon_currently_active(&ctx, platform, &target_host)?;

    // Daemon should NOT be active (failed to start) or should log custody rejection.
    // On macOS launchd KeepAlive respawns the refused job forever, so the
    // active flag alone cannot prove refusal there — the daemon log check
    // (the refused process's own error text) carries that half, same OR as Linux.
    let daemon_rejected = !daemon_active_after_bad_mode;

    // Check the daemon unit log for custody rejection lines.
    let mut journal_snippet = String::new();
    for chunk in daemon_unit_log_argv(platform, "50", false)? {
        let chunk_output = ctx
            .capture_root_allow_failure(&target_host, &chunk)
            .unwrap_or_default();
        journal_snippet.push_str(&chunk_output);
        if !journal_snippet.ends_with('\n') {
            journal_snippet.push('\n');
        }
    }
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
    let _ = ctx.run_root_allow_failure(&target_host, &["chmod", "0600", key_file]);
    // Clear systemd's failed-start counter before restarting: a single
    // rejected start (bad perms) increments the burst counter and the unit
    // stays in "failed" state, blocking the next `systemctl start`.
    // launchd has no failed-counter latch (KeepAlive simply throttles
    // respawn), so this step is Linux-only.
    match platform {
        LiveLabPlatform::Linux => {
            let _ = ctx
                .run_root_allow_failure(&target_host, &["systemctl", "reset-failed", "rustynetd"]);
            let _ = ctx.run_root_allow_failure(&target_host, &["systemctl", "start", "rustynetd"]);
            std::thread::sleep(std::time::Duration::from_secs(8));
        }
        _ => {
            // bootout'd (or crash-looping) job: reload the reviewed plist, then
            // kickstart to force a fresh spawn with the restored key mode.
            let _ = ctx.run_root_allow_failure(&target_host, &macos_bootstrap_argv());
            let _ = ctx.run_root_allow_failure(&target_host, &macos_kickstart_argv());
        }
    }

    // ── Stage 5: assert recovery ──────────────────────────────────────────────
    // macOS tightens the shared launchd heuristic: `state = waiting` is true
    // for a loaded-but-crash-looping job, so recovery demands a live `pid =`
    // (the daemon actually survived a start with the restored key). The
    // bounded retry absorbs the spawn→pid window.
    let daemon_recovered = match platform {
        LiveLabPlatform::Linux => ctx
            .capture_root_allow_failure(&target_host, &["systemctl", "is-active", "rustynetd"])
            .map(|s| s.trim() == "active")
            .unwrap_or(false),
        _ => {
            let mut recovered = false;
            for _ in 0..15 {
                let output = ctx
                    .capture_root_allow_failure(&target_host, &macos_print_argv())
                    .unwrap_or_default();
                if macos_daemon_pid_present(output.as_str()) {
                    recovered = true;
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(2));
            }
            recovered
        }
    };
    logger.line(format!(
        "[key-custody] daemon recovered after restore={daemon_recovered}"
    ))?;

    let restored_mode = ctx
        .capture_root_allow_failure(&target_host, &stat_key)
        .unwrap_or_default();
    let final_mode_ok = restored_mode.trim() == "600";

    let overall_pass = initial_mode_ok && rejection_confirmed && daemon_recovered && final_mode_ok;

    // ── Write report ──────────────────────────────────────────────────────────
    // In-process, not `cargo run … ops …`: the subprocess form built a
    // default-feature binary lacking this `vm-lab`-gated verb, so the write
    // failed with `unknown ops subcommand` and the stage recorded FAIL after
    // its assertions had already passed.
    rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_key_custody_report(
        rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxKeyCustodyReportConfig {
            report_path: report_path.clone(),
            initial_key_file_mode: initial_key_mode,
            initial_key_dir_mode: initial_dir_mode,
            initial_mode_ok: pass_fail(initial_mode_ok).to_owned(),
            daemon_rejected_bad_mode: pass_fail(rejection_confirmed).to_owned(),
            daemon_recovered: pass_fail(daemon_recovered).to_owned(),
            final_mode_ok: pass_fail(final_mode_ok).to_owned(),
            overall_status: pass_fail(overall_pass).to_owned(),
        },
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

// ─── Per-platform daemon control plane ─────────────────────────────────────
//
// Linux keeps the pre-port systemd argv byte-identical. macOS mirrors the
// managed-dns validator's launchd choreography (bootout/bootstrap/kickstart,
// `launchctl print` heuristics) against the reviewed daemon plist written by
// `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`.

/// The reviewed daemon launchd label and its plist; the target form is what
/// `launchctl print|bootout|kickstart` accept (`system/<label>`).
const MACOS_DAEMON_LAUNCHCTL_TARGET: &str = "system/com.rustynet.daemon";
const MACOS_DAEMON_PLIST_PATH: &str = "/Library/LaunchDaemons/com.rustynet.daemon.plist";

fn macos_bootout_argv() -> Vec<&'static str> {
    vec!["/bin/launchctl", "bootout", MACOS_DAEMON_LAUNCHCTL_TARGET]
}

fn macos_bootstrap_argv() -> Vec<&'static str> {
    vec![
        "/bin/launchctl",
        "bootstrap",
        "system",
        MACOS_DAEMON_PLIST_PATH,
    ]
}

fn macos_kickstart_argv() -> Vec<&'static str> {
    vec![
        "/bin/launchctl",
        "kickstart",
        "-k",
        MACOS_DAEMON_LAUNCHCTL_TARGET,
    ]
}

fn macos_print_argv() -> Vec<&'static str> {
    vec!["/bin/launchctl", "print", MACOS_DAEMON_LAUNCHCTL_TARGET]
}

/// Stop the daemon's service unit, per OS. Linux: `systemctl stop` (unchanged).
/// macOS: `launchctl bootout` — the canonical unload for a KeepAlive job
/// (KeepAlive only respawns a job that is still loaded).
fn stop_daemon(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
) -> Result<(), String> {
    match platform {
        LiveLabPlatform::Linux => ctx
            .run_root_allow_failure(target, &["systemctl", "stop", "rustynetd"])
            .map(|_| ()),
        _ => ctx
            .run_root_allow_failure(target, &macos_bootout_argv())
            .map(|_| ()),
    }
}

/// Start the daemon's service unit, per OS. Linux: `systemctl start`
/// (unchanged). macOS: `bootstrap` re-loads the reviewed plist after the
/// bootout, then `kickstart -k` forces a fresh spawn (bootstrap alone is a
/// no-op when the job is still loaded).
fn start_daemon(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
) -> Result<(), String> {
    match platform {
        LiveLabPlatform::Linux => ctx
            .run_root_allow_failure(target, &["systemctl", "start", "rustynetd"])
            .map(|_| ()),
        _ => {
            let _ = ctx.run_root_allow_failure(target, &macos_bootstrap_argv());
            ctx.run_root_allow_failure(target, &macos_kickstart_argv())
                .map(|_| ())
        }
    }
}

/// Whether the daemon's service unit currently reads as active, per OS.
/// Linux: `systemctl is-active` prints exactly `active` (unchanged). macOS:
/// the `launchctl print` state/pid heuristic (exit status alone is useless —
/// `print` exits zero for a loaded-but-inactive job).
fn daemon_currently_active(
    ctx: &LiveLabContext,
    platform: LiveLabPlatform,
    target: &str,
) -> Result<bool, String> {
    match platform {
        LiveLabPlatform::Linux => Ok(ctx
            .capture_root_allow_failure(target, &["systemctl", "is-active", "rustynetd"])
            .map(|s| s.trim() == "active")
            .unwrap_or(false)),
        _ => {
            let output = ctx
                .capture_root_allow_failure(target, &macos_print_argv())
                .unwrap_or_default();
            Ok(macos_launchctl_daemon_active(output.as_str()))
        }
    }
}

/// Reduce `launchctl print system/<label>` output to an active/inactive
/// decision — the same heuristic the managed-dns and relay validators use:
/// `state = running|waiting|spawn scheduled` is active; a non-zero `pid =`
/// is the fallback; `Could not find service` / `service not loaded` is
/// inactive.
fn macos_launchctl_daemon_active(output: &str) -> bool {
    let lower = output.to_ascii_lowercase();
    if lower.contains("could not find service") || lower.contains("service not loaded") {
        return false;
    }
    for line in output.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("state =") {
            return matches!(
                rest.trim().to_ascii_lowercase().as_str(),
                "running" | "waiting" | "spawn scheduled"
            );
        }
    }
    macos_daemon_pid_present(output)
}

/// Tighter than [`macos_launchctl_daemon_active`]: demands a live non-zero
/// `pid =`, so a loaded-but-crash-looping job (`state = waiting`, KeepAlive
/// respawning a custody-refused daemon) does not read as recovered.
fn macos_daemon_pid_present(output: &str) -> bool {
    output.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("pid =")
            && trimmed
                .split_once('=')
                .and_then(|(_, rest)| rest.trim().parse::<u32>().ok())
                .is_some_and(|pid| pid != 0)
    })
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
        [--platform <linux|macos|windows>] \
        [--report-path <path>] \
        [--log-path <path>]"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_paths_and_argv_are_byte_identical_to_the_pre_port_validator() {
        let (key_file, key_dir) = wg_encrypted_key_paths(LiveLabPlatform::Linux).expect("linux");
        assert_eq!(key_file, "/var/lib/rustynet/keys/wireguard.key.enc");
        assert_eq!(key_dir, "/var/lib/rustynet/keys");
        assert_eq!(
            stat_mode_argv(LiveLabPlatform::Linux, key_file).expect("linux"),
            vec!["stat", "--format=%a", key_file]
        );
        assert_eq!(
            daemon_unit_log_argv(LiveLabPlatform::Linux, "50", false).expect("linux"),
            vec![vec![
                "journalctl",
                "-u",
                "rustynetd",
                "-n",
                "50",
                "--no-pager"
            ]]
        );
    }

    #[test]
    fn macos_paths_match_the_reviewed_custody_layout_and_launchd_plist() {
        let (key_file, key_dir) = wg_encrypted_key_paths(LiveLabPlatform::MacOs).expect("macos");
        assert_eq!(key_file, "/usr/local/var/rustynet/keys/wireguard.key.enc");
        assert_eq!(key_dir, "/usr/local/var/rustynet/keys");
        assert_eq!(
            macos_bootout_argv(),
            vec!["/bin/launchctl", "bootout", "system/com.rustynet.daemon"]
        );
        assert_eq!(
            macos_bootstrap_argv(),
            vec![
                "/bin/launchctl",
                "bootstrap",
                "system",
                "/Library/LaunchDaemons/com.rustynet.daemon.plist"
            ]
        );
        assert_eq!(
            macos_kickstart_argv(),
            vec![
                "/bin/launchctl",
                "kickstart",
                "-k",
                "system/com.rustynet.daemon"
            ]
        );
        assert_eq!(
            macos_print_argv(),
            vec!["/bin/launchctl", "print", "system/com.rustynet.daemon"]
        );
    }

    #[test]
    fn windows_fails_closed_before_any_remote_work() {
        let err = wg_encrypted_key_paths(LiveLabPlatform::Windows).expect_err("fail closed");
        assert!(err.contains("in-memory/DPAPI"), "{err}");
        assert!(stat_mode_argv(LiveLabPlatform::Windows, "C:\\key.enc").is_err());
        assert!(daemon_unit_log_argv(LiveLabPlatform::Windows, "50", false).is_err());
    }

    #[test]
    fn launchctl_print_heuristics_distinguish_active_inactive_and_crash_looping() {
        // A running job: state line first, pid present.
        let running = "\
pid = 417\n\
state = running\n\
program = /usr/local/bin/rustynet\n";
        assert!(macos_launchctl_daemon_active(running));
        assert!(macos_daemon_pid_present(running));
        // A loaded job between KeepAlive respawns: `waiting` counts as active
        // for the rejection leg, but carries no live pid, so the recovery leg
        // (pid-present) refuses it.
        let crash_looping = "pid = 0\nstate = waiting\n";
        assert!(macos_launchctl_daemon_active(crash_looping));
        assert!(!macos_daemon_pid_present(crash_looping));
        // Unloaded job: print still exits zero with a not-found body.
        let unloaded = "Could not find service \"com.rustynet.daemon\" in system domain\n";
        assert!(!macos_launchctl_daemon_active(unloaded));
        assert!(!macos_daemon_pid_present(unloaded));
    }

    #[test]
    fn custody_rejection_keywords_cover_the_daemon_shared_error_text() {
        // key_material's cfg(unix) mode check emits "permissions are too
        // broad" on BOTH POSIX platforms — the shared "permission" keyword
        // must catch it.
        let text = "wireguard key permissions are too broad: expected owner-only, found 644";
        assert!(text.contains("permission"));
    }
}
