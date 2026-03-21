#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

const BASELINE_NAT_PROFILES: &str = "baseline_lan";
const DUAL_NAT_PROFILES: &str = "baseline_lan,symmetric_nat";
const FAILURE_MESSAGE: &str =
    "expected matrix validation to fail when only one suite has symmetric_nat evidence";

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let _ignored_args = env::args_os().skip(1).count();
    let repo_root = repo_root()?;
    let temp_dir = TempDir::create()?;

    let source_file = temp_dir.path().join("source.txt");
    let log_file = temp_dir.path().join("report.log");
    fs::write(&source_file, "source\n").map_err(|err| {
        format!(
            "failed to write source fixture {}: {err}",
            source_file.display()
        )
    })?;
    fs::write(&log_file, "log\n")
        .map_err(|err| format!("failed to write log fixture {}: {err}", log_file.display()))?;

    let current_commit = git_rev_parse_head(&repo_root)?;

    for (suite, report_name) in baseline_reports() {
        generate_pass_report(
            &repo_root,
            &source_file,
            &log_file,
            suite,
            &temp_dir.path().join(report_name),
            BASELINE_NAT_PROFILES,
        )?;
    }

    generate_pass_report(
        &repo_root,
        &source_file,
        &log_file,
        "cross_network_direct_remote_exit",
        &temp_dir
            .path()
            .join("cross_network_direct_remote_exit_report_symmetric_partial.json"),
        "symmetric_nat",
    )?;

    validate_nat_matrix(
        &repo_root,
        temp_dir.path(),
        &current_commit,
        BASELINE_NAT_PROFILES,
        Some(temp_dir.path().join("nat_matrix_baseline.md")),
    )?;

    match validate_nat_matrix(
        &repo_root,
        temp_dir.path(),
        &current_commit,
        DUAL_NAT_PROFILES,
        None,
    ) {
        Ok(status) if status.success() => {
            return Err(FAILURE_MESSAGE.to_string());
        }
        Ok(_) | Err(_) => {}
    }

    for (suite, report_name) in symmetric_reports() {
        generate_pass_report(
            &repo_root,
            &source_file,
            &log_file,
            suite,
            &temp_dir.path().join(report_name),
            "symmetric_nat",
        )?;
    }

    validate_nat_matrix(
        &repo_root,
        temp_dir.path(),
        &current_commit,
        DUAL_NAT_PROFILES,
        Some(temp_dir.path().join("nat_matrix_dual.md")),
    )?;

    println!("Cross-network NAT matrix validation tests: PASS");
    Ok(())
}

fn baseline_reports() -> [(&'static str, &'static str); 6] {
    [
        (
            "cross_network_direct_remote_exit",
            "cross_network_direct_remote_exit_report.json",
        ),
        (
            "cross_network_relay_remote_exit",
            "cross_network_relay_remote_exit_report.json",
        ),
        (
            "cross_network_failback_roaming",
            "cross_network_failback_roaming_report.json",
        ),
        (
            "cross_network_traversal_adversarial",
            "cross_network_traversal_adversarial_report.json",
        ),
        (
            "cross_network_remote_exit_dns",
            "cross_network_remote_exit_dns_report.json",
        ),
        (
            "cross_network_remote_exit_soak",
            "cross_network_remote_exit_soak_report.json",
        ),
    ]
}

fn symmetric_reports() -> [(&'static str, &'static str); 6] {
    [
        (
            "cross_network_direct_remote_exit",
            "cross_network_direct_remote_exit_report_symmetric_full.json",
        ),
        (
            "cross_network_relay_remote_exit",
            "cross_network_relay_remote_exit_report_symmetric_full.json",
        ),
        (
            "cross_network_failback_roaming",
            "cross_network_failback_roaming_report_symmetric_full.json",
        ),
        (
            "cross_network_traversal_adversarial",
            "cross_network_traversal_adversarial_report_symmetric_full.json",
        ),
        (
            "cross_network_remote_exit_dns",
            "cross_network_remote_exit_dns_report_symmetric_full.json",
        ),
        (
            "cross_network_remote_exit_soak",
            "cross_network_remote_exit_soak_report_symmetric_full.json",
        ),
    ]
}

fn generate_pass_report(
    repo_root: &Path,
    source_file: &Path,
    log_file: &Path,
    suite: &str,
    report_path: &Path,
    nat_profile: &str,
) -> Result<(), String> {
    let mut command = cargo_ops_command("generate-cross-network-remote-exit-report");
    command.current_dir(repo_root);
    command.stdout(Stdio::null());
    command.arg("--suite").arg(suite);
    command.arg("--report-path").arg(report_path);
    command.arg("--log-path").arg(log_file);
    command.arg("--status").arg("pass");
    command.arg("--environment").arg("ci");
    command.arg("--implementation-state").arg("implemented");
    command.arg("--source-artifact").arg(source_file);
    command.arg("--client-host").arg("client@example");
    command.arg("--exit-host").arg("exit@example");
    command.arg("--client-network-id").arg("net-a");
    command.arg("--exit-network-id").arg("net-b");
    command.arg("--nat-profile").arg(nat_profile);
    command.arg("--impairment-profile").arg("none");

    match suite {
        "cross_network_direct_remote_exit" => {
            command.args([
                "--check",
                "direct_remote_exit_success=pass",
                "--check",
                "remote_exit_no_underlay_leak=pass",
                "--check",
                "remote_exit_server_ip_bypass_is_narrow=pass",
            ]);
        }
        "cross_network_relay_remote_exit" => {
            command.args([
                "--relay-host",
                "relay@example",
                "--relay-network-id",
                "net-c",
                "--check",
                "relay_remote_exit_success=pass",
                "--check",
                "remote_exit_no_underlay_leak=pass",
                "--check",
                "remote_exit_server_ip_bypass_is_narrow=pass",
            ]);
        }
        "cross_network_failback_roaming" => {
            command.args([
                "--relay-host",
                "relay@example",
                "--relay-network-id",
                "net-c",
                "--check",
                "relay_to_direct_failback_success=pass",
                "--check",
                "endpoint_roam_recovery_success=pass",
                "--check",
                "remote_exit_no_underlay_leak=pass",
            ]);
        }
        "cross_network_traversal_adversarial" => {
            command.args([
                "--probe-host",
                "probe@example",
                "--check",
                "forged_traversal_rejected=pass",
                "--check",
                "stale_traversal_rejected=pass",
                "--check",
                "replayed_traversal_rejected=pass",
                "--check",
                "rogue_endpoint_rejected=pass",
                "--check",
                "control_surface_exposure_blocked=pass",
            ]);
        }
        "cross_network_remote_exit_dns" => {
            command.args([
                "--check",
                "managed_dns_resolution_success=pass",
                "--check",
                "remote_exit_dns_fail_closed=pass",
                "--check",
                "remote_exit_no_underlay_leak=pass",
            ]);
        }
        "cross_network_remote_exit_soak" => {
            command.args([
                "--check",
                "long_soak_stable=pass",
                "--check",
                "remote_exit_no_underlay_leak=pass",
                "--check",
                "remote_exit_server_ip_bypass_is_narrow=pass",
                "--check",
                "cross_network_topology_heuristic=pass",
                "--check",
                "direct_remote_exit_ready=pass",
                "--check",
                "post_soak_bypass_ready=pass",
                "--check",
                "no_plaintext_passphrase_files=pass",
            ]);
        }
        _ => {
            return Err(format!(
                "unsupported suite in test fixture generator: {suite}"
            ));
        }
    }

    run_checked(command).map(|_| ())
}

fn validate_nat_matrix(
    repo_root: &Path,
    artifact_dir: &Path,
    expected_git_commit: &str,
    required_nat_profiles: &str,
    output_path: Option<PathBuf>,
) -> Result<ExitStatus, String> {
    let mut command = cargo_ops_command("validate-cross-network-nat-matrix");
    command.current_dir(repo_root);
    command.arg("--artifact-dir").arg(artifact_dir);
    command
        .arg("--required-nat-profiles")
        .arg(required_nat_profiles);
    command
        .arg("--expected-git-commit")
        .arg(expected_git_commit);
    command.arg("--require-pass-status");
    if let Some(output_path) = output_path {
        command.arg("--output").arg(output_path);
    }
    run_status(command)
}

fn cargo_ops_command(op: &str) -> Command {
    let mut command = Command::new("cargo");
    command.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        "rustynet-cli",
        "--",
        "ops",
        op,
    ]);
    command
}

fn run_checked(command: Command) -> Result<ExitStatus, String> {
    let status = run_status(command)?;
    if status.success() {
        Ok(status)
    } else {
        Err(format!("command exited unsuccessfully: {status}"))
    }
}

fn run_status(mut command: Command) -> Result<ExitStatus, String> {
    command.stderr(Stdio::inherit());
    command
        .status()
        .map_err(|err| format!("failed to run command: {err}"))
}

fn git_rev_parse_head(repo_root: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(repo_root)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;

    if !output.status.success() {
        return Err(format!(
            "git rev-parse HEAD failed with status {}",
            output.status
        ));
    }

    let commit = String::from_utf8(output.stdout)
        .map_err(|err| format!("git rev-parse HEAD returned invalid utf-8: {err}"))?;
    Ok(commit.trim().to_string())
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest_dir.join("../..").canonicalize().map_err(|err| {
        format!(
            "failed to resolve repository root from {}: {err}",
            manifest_dir.display()
        )
    })
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, String> {
        let root = env::temp_dir();
        let pid = std::process::id();
        let base = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("system clock is before UNIX_EPOCH: {err}"))?
            .as_nanos();

        for _ in 0..1024 {
            let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = root.join(format!("rustynet-cli-nat-matrix-{pid}-{base}-{counter}"));
            match fs::create_dir(&path) {
                Ok(()) => {
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).map_err(
                        |err| {
                            format!(
                                "failed to set permissions on temporary directory {}: {err}",
                                path.display()
                            )
                        },
                    )?;
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(err) => {
                    return Err(format!(
                        "failed to create temporary directory {}: {err}",
                        path.display()
                    ));
                }
            }
        }

        Err("failed to allocate a unique temporary directory".to_string())
    }

    fn path(&self) -> &Path {
        self.path.as_path()
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
