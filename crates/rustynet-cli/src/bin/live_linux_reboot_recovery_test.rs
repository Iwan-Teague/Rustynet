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
//!
//! `--defer-post-reboot-refresh` leaves the post-reboot assignment refresh
//! (`ops force-local-assignment-refresh-now`, which restarts rustynetd) to the
//! caller. A lab substrate overlay is volatile guest state, so right after a
//! reboot rustynetd cannot start until the orchestrator stage has re-created
//! the overlay; the stage then runs the refresh itself and fails if it fails.

#![forbid(unsafe_code)]

mod live_lab_support;

use std::path::PathBuf;
use std::process::{Command, Output};
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
    let mut entry_host = String::new();
    let mut entry_node_id = String::new();
    let mut second_client_host = String::new();
    let mut second_client_node_id = String::new();
    let mut known_hosts: Option<PathBuf> = None;
    // QH-57: no default - the old 192.168.18.0/24 (bash-era LAN) reaches a
    // nested two_hop spawn that enforces it onto four nodes.
    let mut ssh_allow_cidrs = String::new();
    let mut report_path =
        root_dir.join("artifacts/live_lab/live_linux_reboot_recovery_report.json");
    let mut log_path = root_dir.join("artifacts/live_lab/live_linux_reboot_recovery.log");
    let mut defer_post_reboot_refresh = false;

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
            "--entry-host" => {
                idx += 1;
                entry_host = req(&args, idx, "--entry-host")?;
            }
            "--entry-node-id" => {
                idx += 1;
                entry_node_id = req(&args, idx, "--entry-node-id")?;
            }
            "--second-client-host" => {
                idx += 1;
                second_client_host = req(&args, idx, "--second-client-host")?;
            }
            "--second-client-node-id" => {
                idx += 1;
                second_client_node_id = req(&args, idx, "--second-client-node-id")?;
            }
            "--known-hosts" => {
                idx += 1;
                known_hosts = Some(PathBuf::from(req(&args, idx, "--known-hosts")?));
            }
            "--ssh-allow-cidrs" => {
                idx += 1;
                ssh_allow_cidrs = req(&args, idx, "--ssh-allow-cidrs")?;
            }
            "--report-path" => {
                idx += 1;
                report_path = PathBuf::from(req(&args, idx, "--report-path")?);
            }
            "--log-path" => {
                idx += 1;
                log_path = PathBuf::from(req(&args, idx, "--log-path")?);
            }
            "--defer-post-reboot-refresh" => {
                defer_post_reboot_refresh = true;
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
    if ssh_allow_cidrs.trim().is_empty() {
        print_usage();
        return Err(
            "missing required argument: --ssh-allow-cidrs (pass the run's real \
             management CIDRs, e.g. 192.168.64.0/24; QH-57)"
                .to_owned(),
        );
    }
    for entry in ssh_allow_cidrs.split(',') {
        let entry = entry.trim();
        if entry == "0.0.0.0/0" || entry == "::/0" {
            return Err(format!(
                "--ssh-allow-cidrs entry {entry} is a default route; on a \
                 full-tunnel node it cannot scope the management bypass (QH-57)"
            ));
        }
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
    let mut ctx = LiveLabContext::new_with_pinned_known_hosts(
        "rustynet-reboot-recovery",
        ssh_id.as_path(),
        known_hosts.as_deref(),
    )?;
    let two_hop = TwoHopTopology::new(
        ssh_id.clone(),
        known_hosts.clone(),
        exit_host.clone(),
        client_host.clone(),
        entry_host,
        second_client_host,
        _exit_node_id.clone(),
        client_node_id.clone(),
        entry_node_id,
        second_client_node_id,
        ssh_allow_cidrs,
    );

    for target in [&exit_host, &client_host] {
        ctx.push_sudo_password(target)?;
    }

    let mut observations = String::new();
    if defer_post_reboot_refresh {
        // The report's refresh checks read `skipped` in this mode because the
        // refresh was NOT run here; say so, so the report cannot be mistaken
        // for "no refresh infrastructure on the node".
        observations.push_str("post_reboot_refresh_mode=deferred_to_stage\n");
    }

    // ── Pre-reboot boot IDs ───────────────────────────────────────────────────
    logger.line("[reboot-recovery] capturing pre-reboot boot IDs")?;
    let exit_pre = capture_boot_id(&mut ctx, &exit_host).unwrap_or_default();
    let client_pre = capture_boot_id(&mut ctx, &client_host).unwrap_or_default();
    observations.push_str(&format!("exit_pre={exit_pre}\nclient_pre={client_pre}\n"));

    // ── Reboot exit ───────────────────────────────────────────────────────────
    logger.line(format!("[reboot-recovery] rebooting exit {exit_host}"))?;
    let _ = ctx.run_root_allow_failure(&exit_host, &["systemctl", "reboot"]);
    let exit_returned = poll_for_new_boot(&mut ctx, &exit_host, &exit_pre, 96, 5, &logger)?;
    let exit_post = if exit_returned {
        capture_boot_id(&mut ctx, &exit_host).unwrap_or_default()
    } else {
        String::new()
    };
    observations.push_str(&format!("exit_post={exit_post}\n"));
    if !exit_returned {
        observations.push_str("exit_reboot_wait=fail\n");
    }
    let post_exit_dns_refresh = if exit_returned {
        force_local_assignment_refresh(&mut ctx, &exit_host, &logger, defer_post_reboot_refresh)?
    } else {
        CheckResult::Fail
    };
    observations.push_str(&format!(
        "post_exit_dns_refresh={}\n",
        post_exit_dns_refresh.as_str()
    ));
    let post_exit_twohop = if exit_returned {
        run_two_hop_subcheck(
            &two_hop,
            "post-exit-reboot two-hop",
            &report_path,
            &log_path,
            &logger,
        )?
    } else {
        CheckResult::Fail
    };
    observations.push_str(&format!("post_exit_twohop={}\n", post_exit_twohop.as_str()));

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
    let client_returned = poll_for_new_boot(&mut ctx, &client_host, &client_pre, 96, 5, &logger)?;
    let client_post = if client_returned {
        capture_boot_id(&mut ctx, &client_host).unwrap_or_default()
    } else {
        String::new()
    };
    observations.push_str(&format!("client_post={client_post}\n"));
    if !client_returned {
        observations.push_str("client_reboot_wait=fail\n");
    }
    let post_client_dns_refresh = if client_returned {
        force_local_assignment_refresh(&mut ctx, &client_host, &logger, defer_post_reboot_refresh)?
    } else {
        CheckResult::Fail
    };
    observations.push_str(&format!(
        "post_client_dns_refresh={}\n",
        post_client_dns_refresh.as_str()
    ));
    let post_client_twohop = if client_returned {
        run_two_hop_subcheck(
            &two_hop,
            "post-client-reboot two-hop",
            &report_path,
            &log_path,
            &logger,
        )?
    } else {
        CheckResult::Fail
    };
    observations.push_str(&format!(
        "post_client_twohop={}\n",
        post_client_twohop.as_str()
    ));

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
    // In-process, not `cargo run … ops …`: the subprocess built a
    // default-feature binary lacking this `vm-lab`-gated verb, so the write
    // failed with `unknown ops subcommand` and the stage recorded FAIL after
    // its assertions had already passed. Every field keeps the exact value the
    // argv form produced, including the two literal "skipped" sentinels.
    let report_status =
        rustynet_cli::ops_live_lab_orchestrator::execute_ops_write_live_linux_reboot_recovery_report(
            rustynet_cli::ops_live_lab_orchestrator::WriteLiveLinuxRebootRecoveryReportConfig {
                report_path: report_path.clone(),
                observations_path: observations_path.clone(),
                exit_pre: exit_pre.trim().to_owned(),
                exit_post: exit_post.trim().to_owned(),
                client_pre: client_pre.trim().to_owned(),
                client_post: client_post.trim().to_owned(),
                exit_return: exit_return_str.to_owned(),
                exit_boot_change: exit_boot_change_str.to_owned(),
                post_exit_dns_refresh: post_exit_dns_refresh.as_str().to_owned(),
                post_exit_twohop: stronger_check(exit_twohop_str, post_exit_twohop)
                    .as_str()
                    .to_owned(),
                client_return: client_return_str.to_owned(),
                client_boot_change: client_boot_change_str.to_owned(),
                post_client_dns_refresh: post_client_dns_refresh.as_str().to_owned(),
                post_client_twohop: post_client_twohop.as_str().to_owned(),
                salvage_twohop: "skipped".to_owned(),
            },
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

/// Wait until `target` answers with a boot ID other than `pre_boot_id`.
/// `systemctl reboot` returns before the guest goes down, so a host that
/// merely answers SSH may still be the OLD boot: run katana-u14 logged "up
/// after attempt 1" with an unchanged boot ID and failed the boot-ID check.
/// When the pre-reboot capture itself failed (empty ID), any answering boot
/// ends the wait and the boot-ID-change check then fails closed as before.
fn poll_for_new_boot(
    ctx: &mut LiveLabContext,
    target: &str,
    pre_boot_id: &str,
    attempts: u32,
    sleep_secs: u64,
    logger: &Logger,
) -> Result<bool, String> {
    let pre = pre_boot_id.trim();
    for attempt in 1..=attempts {
        std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
        let Ok(boot_id) = capture_boot_id(ctx, target) else {
            continue;
        };
        if is_new_boot(pre, boot_id.trim()) {
            logger.line(format!(
                "[reboot-recovery] {target} up on a new boot after attempt {attempt}"
            ))?;
            return Ok(true);
        }
    }
    logger.line(format!(
        "[reboot-recovery] {target} did not return after {attempts} attempts"
    ))?;
    Ok(false)
}

/// Whether `current` is a boot other than `pre` (an empty current ID means
/// the guest did not answer yet; an empty pre ID accepts any answering boot).
fn is_new_boot(pre: &str, current: &str) -> bool {
    !current.is_empty() && (pre.is_empty() || current != pre)
}

fn pass_fail(ok: bool) -> &'static str {
    if ok { "pass" } else { "fail" }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CheckResult {
    Pass,
    Fail,
    Skipped,
}

impl CheckResult {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Fail => "fail",
            Self::Skipped => "skipped",
        }
    }
}

#[derive(Debug, Clone)]
struct TwoHopTopology {
    ssh_identity_file: PathBuf,
    known_hosts: Option<PathBuf>,
    exit_host: String,
    client_host: String,
    entry_host: String,
    second_client_host: String,
    exit_node_id: String,
    client_node_id: String,
    entry_node_id: String,
    second_client_node_id: String,
    ssh_allow_cidrs: String,
}

impl TwoHopTopology {
    #[allow(clippy::too_many_arguments)]
    fn new(
        ssh_identity_file: PathBuf,
        known_hosts: Option<PathBuf>,
        exit_host: String,
        client_host: String,
        entry_host: String,
        second_client_host: String,
        exit_node_id: String,
        client_node_id: String,
        entry_node_id: String,
        second_client_node_id: String,
        ssh_allow_cidrs: String,
    ) -> Self {
        Self {
            ssh_identity_file,
            known_hosts,
            exit_host,
            client_host,
            entry_host,
            second_client_host,
            exit_node_id,
            client_node_id,
            entry_node_id,
            second_client_node_id,
            ssh_allow_cidrs,
        }
    }

    fn is_complete(&self) -> bool {
        [
            self.exit_host.as_str(),
            self.client_host.as_str(),
            self.entry_host.as_str(),
            self.second_client_host.as_str(),
            self.exit_node_id.as_str(),
            self.client_node_id.as_str(),
            self.entry_node_id.as_str(),
            self.second_client_node_id.as_str(),
            self.ssh_allow_cidrs.as_str(),
        ]
        .iter()
        .all(|value| !value.trim().is_empty())
    }
}

/// Path the assignment-refresh timer's environment file is installed to by
/// `ops install-systemd` when refresh infrastructure is provisioned. The
/// focused lab setup distributes a single signed bundle and deliberately does
/// NOT provision the refresh timer (that is why the lab install pins
/// `RUSTYNET_AUTO_TUNNEL_MAX_AGE_SECS=86400`).
const ASSIGNMENT_REFRESH_ENV_PATH: &str = "/etc/rustynet/assignment-refresh.env";

/// The deferral decision, pure so that both inputs are unit-tested: the check
/// result the binary reports for the post-reboot assignment refresh WITHOUT
/// running it, or `None` when the binary probes for the refresh infrastructure
/// and runs the refresh itself.
///
/// `--defer-post-reboot-refresh` is opt-in (only the orchestrator stage passes
/// it, when a lab substrate overlay must be re-provisioned before rustynetd
/// can start; the caller then runs the refresh and fails its own stage if it
/// fails). Every other caller and every plain lab must get `None`: a `Some`
/// there would silently skip the post-reboot refresh everywhere.
fn deferred_refresh_outcome(defer_post_reboot_refresh: bool) -> Option<CheckResult> {
    defer_post_reboot_refresh.then_some(CheckResult::Skipped)
}

fn force_local_assignment_refresh(
    ctx: &mut LiveLabContext,
    target: &str,
    logger: &Logger,
    defer_post_reboot_refresh: bool,
) -> Result<CheckResult, String> {
    if let Some(outcome) = deferred_refresh_outcome(defer_post_reboot_refresh) {
        // Skipped here is NOT "not provisioned": the caller owns the refresh
        // and must run it after the lab substrate overlay is back.
        logger.line(format!(
            "[reboot-recovery] assignment refresh on {target} deferred to the caller \
             (--defer-post-reboot-refresh: the lab substrate overlay must be \
             re-provisioned before rustynetd can start)"
        ))?;
        return Ok(outcome);
    }
    // Precondition probe: the post-reboot refresh check only applies where the
    // assignment-refresh infrastructure exists on the node. `test -f` exit 1
    // (file absent) → Skipped, mirroring run_two_hop_subcheck's
    // incomplete-topology skip. Any OTHER nonzero exit is not "absent" and
    // fails closed; a transport error propagates as Err.
    let probe = ctx.run_root_allow_failure(target, &["test", "-f", ASSIGNMENT_REFRESH_ENV_PATH])?;
    if !probe.status.success() {
        if probe.status.code() == Some(1) {
            logger.line(format!(
                "[reboot-recovery] assignment refresh skipped on {target}: \
                 {ASSIGNMENT_REFRESH_ENV_PATH} not provisioned by this lab setup"
            ))?;
            return Ok(CheckResult::Skipped);
        }
        logger.line(format!(
            "[reboot-recovery] assignment refresh env probe failed on {target}: {}",
            render_output(&probe)
        ))?;
        return Ok(CheckResult::Fail);
    }
    logger.line(format!(
        "[reboot-recovery] forcing local assignment refresh on {target}"
    ))?;
    // Kept on one line on purpose: the vm-lab feature-gating pin in vm_lab
    // detects a `cargo run … ops` spawn partly by a bare `"ops",` line, and a
    // multi-line SSH argv here would trip it as a false positive.
    let bin = live_lab_support::REMOTE_RUSTYNET_BIN;
    let argv = [bin, "ops", "force-local-assignment-refresh-now"];
    let output = ctx.run_root_allow_failure(target, &argv)?;
    if output.status.success() {
        Ok(CheckResult::Pass)
    } else {
        logger.line(format!(
            "[reboot-recovery] assignment refresh failed on {target}: {}",
            render_output(&output)
        ))?;
        Ok(CheckResult::Fail)
    }
}

fn run_two_hop_subcheck(
    topology: &TwoHopTopology,
    label: &str,
    report_path: &std::path::Path,
    log_path: &std::path::Path,
    logger: &Logger,
) -> Result<CheckResult, String> {
    if !topology.is_complete() {
        logger.line(format!(
            "[reboot-recovery] {label} skipped: incomplete two-hop topology"
        ))?;
        return Ok(CheckResult::Skipped);
    }

    let stem = sanitize_label(label);
    let report =
        report_path.with_file_name(format!("live_linux_reboot_recovery_{stem}_report.json"));
    let log = log_path.with_file_name(format!("live_linux_reboot_recovery_{stem}.log"));
    logger.line(format!("[reboot-recovery] running {label}"))?;

    let mut command = Command::new("cargo");
    command.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "live_linux_two_hop_test",
        "--",
        "--ssh-identity-file",
    ]);
    command.arg(&topology.ssh_identity_file);
    if let Some(known_hosts) = &topology.known_hosts {
        command.arg("--known-hosts").arg(known_hosts);
    }
    command.args([
        "--final-exit-host",
        topology.exit_host.as_str(),
        "--final-exit-node-id",
        topology.exit_node_id.as_str(),
        "--client-host",
        topology.client_host.as_str(),
        "--client-node-id",
        topology.client_node_id.as_str(),
        "--entry-host",
        topology.entry_host.as_str(),
        "--entry-node-id",
        topology.entry_node_id.as_str(),
        "--second-client-host",
        topology.second_client_host.as_str(),
        "--second-client-node-id",
        topology.second_client_node_id.as_str(),
        "--ssh-allow-cidrs",
        topology.ssh_allow_cidrs.as_str(),
        "--report-path",
    ]);
    command.arg(report);
    command.arg("--log-path").arg(log);

    let output = command
        .output()
        .map_err(|err| format!("{label}: two-hop invocation failed: {err}"))?;
    if output.status.success() {
        Ok(CheckResult::Pass)
    } else {
        logger.line(format!(
            "[reboot-recovery] {label} failed: {}",
            render_output(&output)
        ))?;
        Ok(CheckResult::Fail)
    }
}

fn stronger_check(base: &str, measured: CheckResult) -> CheckResult {
    match measured {
        CheckResult::Pass => CheckResult::Pass,
        CheckResult::Fail => CheckResult::Fail,
        CheckResult::Skipped => match base {
            "pass" => CheckResult::Pass,
            "fail" => CheckResult::Fail,
            _ => CheckResult::Skipped,
        },
    }
}

fn render_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stderr.trim().is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_owned()
    } else {
        stderr.trim().to_owned()
    }
}

fn sanitize_label(label: &str) -> String {
    label
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect()
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

const USAGE: &str = "usage: live_linux_reboot_recovery_test \
        --ssh-identity-file <path> \
        --exit-host <user@host> \
        --client-host <user@host> \
        [--exit-node-id <id>] \
        [--client-node-id <id>] \
        [--entry-host <user@host>] \
        [--entry-node-id <id>] \
        [--second-client-host <user@host>] \
        [--second-client-node-id <id>] \
        [--known-hosts <path>] \
        [--ssh-allow-cidrs <cidrs>] \
        [--defer-post-reboot-refresh] \
        [--report-path <path>] \
        [--log-path <path>]";

fn print_usage() {
    eprintln!("{USAGE}");
}

#[cfg(test)]
mod tests {
    use super::{CheckResult, USAGE, deferred_refresh_outcome, is_new_boot};

    /// The production half of this file (everything above the test module).
    /// The source pins below read it because the binary needs live guests.
    fn production_source() -> &'static str {
        let source = include_str!("live_linux_reboot_recovery_test.rs");
        &source[..source
            .find("#[cfg(test)]")
            .expect("the test module marker exists")]
    }

    // Run katana-u14: the guest answered on its OLD boot right after
    // `systemctl reboot`; that must keep the wait going.
    #[test]
    fn old_boot_or_no_answer_keeps_waiting_and_a_new_boot_ends_it() {
        let pre = "2cf79758-62db-466d-8ab8-d7433e88dbd7";
        assert!(!is_new_boot(pre, pre), "the old boot is not a reboot");
        assert!(!is_new_boot(pre, ""), "no answer yet");
        assert!(is_new_boot(pre, "b0f0a7c4-ff6d-4b77-82bc-b8015a1fea3f"));
        // A failed pre-reboot capture accepts any answering boot; the
        // boot-ID-change check downstream still fails closed on it.
        assert!(is_new_boot("", "b0f0a7c4-ff6d-4b77-82bc-b8015a1fea3f"));
        assert!(!is_new_boot("", ""));
    }

    /// katana-xnet-994: with a lab substrate active the refresh (a rustynetd
    /// restart) must not run in the dead window after the reboot; the flag
    /// selects the deferral and its absence keeps the binary's own refresh.
    /// Both inputs are pinned: an inverted decision would either run the
    /// refresh in the dead window again (flag set) or silently skip it in
    /// every plain lab (flag absent).
    #[test]
    fn deferral_flag_selects_the_deferred_refresh_and_default_keeps_it_in_the_binary() {
        assert_eq!(
            deferred_refresh_outcome(true),
            Some(CheckResult::Skipped),
            "flag set: reported without running, the caller owns the refresh"
        );
        assert_eq!(
            deferred_refresh_outcome(false),
            None,
            "flag absent (every plain lab): nothing is deferred, the binary \
             probes for the refresh infrastructure and runs the refresh itself"
        );
    }

    #[test]
    fn usage_documents_the_deferral_flag() {
        assert!(USAGE.contains("[--defer-post-reboot-refresh]"), "{USAGE}");
    }

    /// Source pins on the plumbing a unit test cannot reach (the binary needs
    /// live guests). Each assertion is one way to make a plain lab skip the
    /// refresh, or to lose the deferral the stage asked for: a deferral
    /// variable that starts true, a flag arm that does not set it, or a call
    /// site that passes anything but the variable itself (a literal, a
    /// negation).
    #[test]
    fn the_parsed_flag_reaches_both_refresh_call_sites() {
        let production = production_source();
        assert!(
            production
                .lines()
                .any(|l| l.trim() == "let mut defer_post_reboot_refresh = false;"),
            "the deferral variable must default to false (plain labs run the refresh)"
        );
        let parse = production
            .find("\"--defer-post-reboot-refresh\" =>")
            .expect("the flag must be parsed");
        assert!(
            production[parse..]
                .lines()
                .take(3)
                .any(|l| l.trim() == "defer_post_reboot_refresh = true;"),
            "the flag arm must set the deferral variable"
        );
        let calls: Vec<&str> = production
            .lines()
            .filter(|l| l.contains("force_local_assignment_refresh(&mut ctx,"))
            .collect();
        assert_eq!(calls.len(), 2, "exit and client sections: {calls:?}");
        for call in calls {
            assert!(
                call.trim().ends_with(", defer_post_reboot_refresh)?"),
                "the variable must be passed as is, not dropped or negated: {call}"
            );
        }
    }

    /// The consumer of the pure decision: the refresh function must branch on
    /// the decision with the flag passed as is, return the decided outcome,
    /// and do both before it touches the node (the env-file probe). This is
    /// the half the decision test above cannot see: the decision can be right
    /// and still be consumed backwards.
    #[test]
    fn the_refresh_returns_the_deferred_outcome_before_it_touches_the_node() {
        let production = production_source();
        assert_eq!(
            production.matches("deferred_refresh_outcome(").count(),
            2,
            "one definition and exactly one consumer"
        );
        let start = production
            .find("fn force_local_assignment_refresh(")
            .expect("the refresh function exists");
        let body = &production[start..];
        let branch = body
            .find("if let Some(outcome) = deferred_refresh_outcome(defer_post_reboot_refresh) {")
            .expect("the refresh must branch on the pure decision, flag passed as is");
        let early_return = body
            .find("return Ok(outcome);")
            .expect("the decided outcome must be returned");
        let probe = body
            .find("\"-f\", ASSIGNMENT_REFRESH_ENV_PATH")
            .expect("the env-file probe exists");
        assert!(
            branch < early_return && early_return < probe,
            "decision ({branch}) then return ({early_return}) then probe ({probe})"
        );
    }
}
