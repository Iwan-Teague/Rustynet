#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root_dir =
        env::current_dir().map_err(|err| format!("resolve current directory failed: {err}"))?;

    let temp_dir = TempDir::create()?;
    let ssh_identity = temp_dir.path().join("id_test");
    fs::write(&ssh_identity, "not-a-real-private-key\n").map_err(|err| {
        format!(
            "write ssh identity fixture failed ({}): {err}",
            ssh_identity.display()
        )
    })?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_direct_remote_exit_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--client-node-id",
            "client-1",
            "--exit-node-id",
            "exit-1",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_direct_remote_exit_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_direct_remote_exit.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_relay_remote_exit_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--relay-host",
            "relay@example",
            "--client-node-id",
            "client-1",
            "--exit-node-id",
            "exit-1",
            "--relay-node-id",
            "relay-1",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--relay-network-id",
            "net-c",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_relay_remote_exit_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_relay_remote_exit.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_failback_roaming_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--relay-host",
            "relay@example",
            "--client-node-id",
            "client-1",
            "--exit-node-id",
            "exit-1",
            "--relay-node-id",
            "relay-1",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--relay-network-id",
            "net-c",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_failback_roaming_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_failback_roaming.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--probe-host",
            "probe@example",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_traversal_adversarial_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_traversal_adversarial.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--client-node-id",
            "client-1",
            "--exit-node-id",
            "exit-1",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_remote_exit_dns_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_remote_exit_dns.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_expect_fail(
        &root_dir,
        "scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh",
        &[
            "--ssh-identity-file",
            ssh_identity.to_str().ok_or_else(|| {
                format!(
                    "ssh identity path is not valid utf-8: {}",
                    ssh_identity.display()
                )
            })?,
            "--client-host",
            "client@example",
            "--exit-host",
            "exit@example",
            "--client-network-id",
            "net-a",
            "--exit-network-id",
            "net-b",
            "--report-path",
            temp_dir
                .path()
                .join("cross_network_remote_exit_soak_report.json")
                .to_str()
                .ok_or_else(|| "report path is not valid utf-8".to_string())?,
            "--log-path",
            temp_dir
                .path()
                .join("cross_network_remote_exit_soak.log")
                .to_str()
                .ok_or_else(|| "log path is not valid utf-8".to_string())?,
        ],
    )?;

    run_cargo_ops(
        &root_dir,
        &[
            "ops",
            "validate-cross-network-remote-exit-reports",
            "--artifact-dir",
            temp_dir
                .path()
                .to_str()
                .ok_or_else(|| "artifact dir is not valid utf-8".to_string())?,
            "--output",
            temp_dir
                .path()
                .join("skeleton_validation.md")
                .to_str()
                .ok_or_else(|| "output path is not valid utf-8".to_string())?,
        ],
    )?;

    println!("Cross-network remote-exit fail-closed bootstrap tests: PASS");
    Ok(())
}

fn run_expect_fail(root_dir: &Path, script_path: &str, args: &[&str]) -> Result<(), String> {
    let status = run_bash(root_dir, script_path, args)?;
    if status.success() {
        return Err(format!(
            "expected validator to fail without live lab prerequisites: {script_path}"
        ));
    }
    Ok(())
}

fn run_cargo_ops(root_dir: &Path, args: &[&str]) -> Result<(), String> {
    let status = run_cargo(root_dir, args)?;
    if status.success() {
        return Ok(());
    }
    Err(format!(
        "cargo run failed for ops command {:?} with status {:?}",
        args,
        status.code()
    ))
}

fn run_bash(root_dir: &Path, script_path: &str, args: &[&str]) -> Result<ExitStatus, String> {
    Command::new("bash")
        .current_dir(root_dir)
        .arg(script_path)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run {script_path}: {err}"))
}

fn run_cargo(root_dir: &Path, args: &[&str]) -> Result<ExitStatus, String> {
    Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "rustynet-cli",
            "--",
        ])
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(|err| format!("failed to run cargo: {err}"))
}

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn create() -> Result<Self, String> {
        let path = env::temp_dir().join(format!(
            "rustynet-test-cross-network-remote-exit-skeleton-validators-{}-{}",
            std::process::id(),
            unique_suffix()?
        ));
        fs::create_dir(&path)
            .map_err(|err| format!("create temp dir failed ({}): {err}", path.display()))?;
        Ok(Self { path })
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

fn unique_suffix() -> Result<u128, String> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .map_err(|err| format!("clock failure while creating temp dir: {err}"))
}
