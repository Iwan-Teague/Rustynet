#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_REPORT_PATH: &str = "artifacts/phase10/rogue_path_hijack_e2e_report.json";
const SOCKET_PATH: &str = "/run/rustynet/rustynetd.sock";
const ASSIGNMENT_PATH: &str = "/var/lib/rustynet/rustynetd.assignment";
const ASSIGNMENT_WATERMARK_PATH: &str = "/var/lib/rustynet/rustynetd.assignment.watermark";

struct Config {
    report_path: String,
    ssh_port: String,
    ssh_user: String,
    ssh_identity: String,
    ssh_sudo_mode: String,
    ssh_known_hosts_file: String,
    exit_host: String,
    client_host: String,
    rogue_endpoint_ip: String,
    forward_args: Vec<String>,
}

struct Cleanup<'a> {
    ssh: &'a SshContext,
    client_target: String,
    backup_path: String,
    assignment_timer_was_active: bool,
}

impl Drop for Cleanup<'_> {
    fn drop(&mut self) {
        if self.backup_path.is_empty() {
            return;
        }
        let _ = self
            .ssh
            .remote_exec_root(&self.client_target, &["test", "-f", &self.backup_path]);
        let _ = self.ssh.remote_exec_root(
            &self.client_target,
            &["cp", &self.backup_path, ASSIGNMENT_PATH],
        );
        let _ = self.ssh.remote_exec_root(
            &self.client_target,
            &["rm", "-f", &self.backup_path, ASSIGNMENT_WATERMARK_PATH],
        );
        let _ = self
            .ssh
            .remote_exec_root(&self.client_target, &["systemctl", "restart", "rustynetd"]);
        if self.assignment_timer_was_active {
            let _ = self.ssh.remote_exec_root(
                &self.client_target,
                &["systemctl", "start", "rustynetd-assignment-refresh.timer"],
            );
        }
    }
}

struct SshContext {
    base: Vec<String>,
    sudo_mode: String,
    ssh_user: String,
}

impl SshContext {
    fn needs_sudo(&self) -> bool {
        match self.sudo_mode.as_str() {
            "never" => false,
            "always" => true,
            "auto" => self.ssh_user != "root",
            _ => false,
        }
    }

    fn remote_exec(&self, target: &str, args: &[&str]) -> Result<(), String> {
        let mut command = Command::new(&self.base[0]);
        command.args(&self.base[1..]);
        command.arg(target);
        command.args(args);
        run_ok(command)
    }

    fn remote_exec_root(&self, target: &str, args: &[&str]) -> Result<(), String> {
        if self.needs_sudo() {
            let mut prefixed = vec!["sudo", "-n", "--"];
            prefixed.extend_from_slice(args);
            self.remote_exec(target, &prefixed)
        } else {
            self.remote_exec(target, args)
        }
    }

    fn capture_remote_root(&self, target: &str, args: &[&str]) -> String {
        let mut command = Command::new(&self.base[0]);
        command.args(&self.base[1..]);
        command.arg(target);
        if self.needs_sudo() {
            command.args(["sudo", "-n", "--"]);
        }
        command.args(args);
        match command.output() {
            Ok(output) => {
                let mut combined = output.stdout;
                combined.extend_from_slice(&output.stderr);
                String::from_utf8_lossy(&combined).into_owned()
            }
            Err(_) => String::new(),
        }
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let mut config = parse_args(env::args().skip(1).collect())?;
    config.ssh_known_hosts_file = resolve_known_hosts(&config.ssh_known_hosts_file)?;
    let root_dir = repo_root()?;
    env::set_current_dir(&root_dir).map_err(|e| format!("cd {}: {e}", root_dir.display()))?;

    validate_common_inputs(
        &config.exit_host,
        &config.client_host,
        &config.ssh_port,
        &config.ssh_identity,
        &config.ssh_sudo_mode,
        &config.ssh_known_hosts_file,
    )?;
    let mut validate_ip = Command::new("cargo");
    validate_ip
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "validate-ipv4-address",
            "--ip",
            &config.rogue_endpoint_ip,
        ])
        .current_dir(&root_dir)
        .stdout(Stdio::null());
    run_ok(validate_ip)?;
    for command in ["ssh", "ssh-keygen", "cargo"] {
        require_command(command)?;
    }
    for host in [&config.exit_host, &config.client_host] {
        ensure_known_host(&config.ssh_known_hosts_file, host)?;
    }
    let report_parent = Path::new(&config.report_path)
        .parent()
        .ok_or_else(|| format!("report path has no parent: {}", config.report_path))?;
    fs::create_dir_all(report_parent).map_err(|e| format!("create report dir: {e}"))?;

    let ssh = build_ssh_context(&config);
    let client_target = format!("{}@{}", config.ssh_user, config.client_host);

    if ssh.needs_sudo() {
        let mut command = Command::new(&ssh.base[0]);
        command
            .args(&ssh.base[1..])
            .arg(&client_target)
            .args(["sudo", "-n", "true"]);
        if !command
            .status()
            .map_err(|e| format!("run ssh sudo probe: {e}"))?
            .success()
        {
            return Err(format!(
                "passwordless sudo is required for post-bootstrap hijack operations on {client_target}"
            ));
        }
    }

    let baseline_status = "pass";
    let mut hijack_reject_status = "fail";
    let mut fail_closed_status = "fail";
    let mut netcheck_fail_closed_status = "fail";
    let mut no_rogue_endpoint_status = "fail";
    let mut recovery_status = "fail";
    let mut recovery_endpoint_status = "fail";

    let backup_path = format!(
        "/var/lib/rustynet/rustynetd.assignment.securitytest.{}.bak",
        unix_now()?
    );

    let mut cleanup = Cleanup {
        ssh: &ssh,
        client_target: client_target.clone(),
        backup_path: backup_path.clone(),
        assignment_timer_was_active: false,
    };

    let mut baseline = Command::new("cargo");
    baseline
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-debian-two-node-e2e",
        ])
        .args(&config.forward_args)
        .current_dir(&root_dir);
    run_ok(baseline)?;

    let timer_state = ssh.capture_remote_root(
        &client_target,
        &[
            "systemctl",
            "is-active",
            "rustynetd-assignment-refresh.timer",
        ],
    );
    if timer_state.contains("active") {
        cleanup.assignment_timer_was_active = true;
    }
    let _ = ssh.remote_exec_root(
        &client_target,
        &["systemctl", "stop", "rustynetd-assignment-refresh.timer"],
    );
    let _ = ssh.remote_exec_root(
        &client_target,
        &["systemctl", "stop", "rustynetd-assignment-refresh.service"],
    );

    let wg_endpoints_before =
        ssh.capture_remote_root(&client_target, &["wg", "show", "rustynet0", "endpoints"]);
    ssh.remote_exec_root(&client_target, &["cp", ASSIGNMENT_PATH, &backup_path])?;

    ssh.remote_exec_root(
        &client_target,
        &[
            "rustynet",
            "ops",
            "rewrite-assignment-peer-endpoint-ip",
            "--assignment-path",
            ASSIGNMENT_PATH,
            "--endpoint-ip",
            &config.rogue_endpoint_ip,
        ],
    )?;
    ssh.remote_exec_root(&client_target, &["rm", "-f", ASSIGNMENT_WATERMARK_PATH])?;
    ssh.remote_exec_root(&client_target, &["systemctl", "restart", "rustynetd"])?;
    thread::sleep(Duration::from_secs(3));

    let status_after_hijack = ssh.capture_remote_root(
        &client_target,
        &[
            "env",
            &format!("RUSTYNET_DAEMON_SOCKET={SOCKET_PATH}"),
            "rustynet",
            "status",
        ],
    );
    let netcheck_after_hijack = ssh.capture_remote_root(
        &client_target,
        &[
            "env",
            &format!("RUSTYNET_DAEMON_SOCKET={SOCKET_PATH}"),
            "rustynet",
            "netcheck",
        ],
    );
    let wg_endpoints_after_hijack =
        ssh.capture_remote_root(&client_target, &["wg", "show", "rustynet0", "endpoints"]);

    if status_after_hijack.contains("state=FailClosed") {
        hijack_reject_status = "pass";
    }
    if status_after_hijack.contains("restricted_safe_mode=true") {
        fail_closed_status = "pass";
    }
    if netcheck_after_hijack.contains("path_mode=fail_closed") {
        netcheck_fail_closed_status = "pass";
    }
    if !wg_endpoints_after_hijack.contains(&config.rogue_endpoint_ip) {
        no_rogue_endpoint_status = "pass";
    }

    ssh.remote_exec_root(&client_target, &["cp", &backup_path, ASSIGNMENT_PATH])?;
    ssh.remote_exec_root(
        &client_target,
        &["rm", "-f", ASSIGNMENT_WATERMARK_PATH, &backup_path],
    )?;
    cleanup.backup_path.clear();
    ssh.remote_exec_root(&client_target, &["systemctl", "restart", "rustynetd"])?;
    thread::sleep(Duration::from_secs(3));

    if cleanup.assignment_timer_was_active {
        ssh.remote_exec_root(
            &client_target,
            &["systemctl", "start", "rustynetd-assignment-refresh.timer"],
        )?;
    }
    let status_after_recovery = ssh.capture_remote_root(
        &client_target,
        &[
            "env",
            &format!("RUSTYNET_DAEMON_SOCKET={SOCKET_PATH}"),
            "rustynet",
            "status",
        ],
    );
    let wg_endpoints_after_recovery =
        ssh.capture_remote_root(&client_target, &["wg", "show", "rustynet0", "endpoints"]);

    if status_after_recovery.contains("restricted_safe_mode=false")
        && !status_after_recovery.contains("state=FailClosed")
    {
        recovery_status = "pass";
    }
    if !wg_endpoints_after_recovery.contains(&config.rogue_endpoint_ip) {
        recovery_endpoint_status = "pass";
    }

    let (captured_at_utc, captured_at_unix) = utc_now()?;
    let mut report = Command::new("cargo");
    report
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "write-active-network-rogue-path-hijack-report",
            "--report-path",
            &config.report_path,
            "--baseline-status",
            baseline_status,
            "--hijack-reject-status",
            hijack_reject_status,
            "--fail-closed-status",
            fail_closed_status,
            "--netcheck-fail-closed-status",
            netcheck_fail_closed_status,
            "--no-rogue-endpoint-status",
            no_rogue_endpoint_status,
            "--recovery-status",
            recovery_status,
            "--recovery-endpoint-status",
            recovery_endpoint_status,
            "--rogue-endpoint-ip",
            &config.rogue_endpoint_ip,
            "--exit-host",
            &config.exit_host,
            "--client-host",
            &config.client_host,
            "--endpoints-before",
            &wg_endpoints_before,
            "--endpoints-after-hijack",
            &wg_endpoints_after_hijack,
            "--endpoints-after-recovery",
            &wg_endpoints_after_recovery,
            "--status-after-hijack",
            &status_after_hijack,
            "--netcheck-after-hijack",
            &netcheck_after_hijack,
            "--status-after-recovery",
            &status_after_recovery,
            "--captured-at-utc",
            &captured_at_utc,
            "--captured-at-unix",
            &captured_at_unix,
        ])
        .current_dir(&root_dir);
    let overall_status = command_stdout(report)?;
    if overall_status.trim() != "pass" {
        return Err(format!(
            "rogue-path hijack e2e failed; see {}",
            config.report_path
        ));
    }

    drop(cleanup);
    println!(
        "Rogue-path hijack e2e report written to {}",
        config.report_path
    );
    Ok(())
}

fn parse_args(args: Vec<String>) -> Result<Config, String> {
    let mut report_path = DEFAULT_REPORT_PATH.to_owned();
    let mut ssh_port = "22".to_owned();
    let mut ssh_user = "root".to_owned();
    let mut ssh_identity = String::new();
    let mut ssh_sudo_mode = "auto".to_owned();
    let mut ssh_known_hosts_file = env::var("SSH_KNOWN_HOSTS_FILE").unwrap_or_default();
    let mut exit_host = String::new();
    let mut client_host = String::new();
    let mut rogue_endpoint_ip = String::new();
    let mut forward_args = Vec::new();

    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--hijack-report-path" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --hijack-report-path".to_owned())?;
                report_path = value.clone();
                index += 2;
            }
            "--rogue-endpoint-ip" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --rogue-endpoint-ip".to_owned())?;
                rogue_endpoint_ip = value.clone();
                index += 2;
            }
            "--exit-host" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --exit-host".to_owned())?;
                exit_host = value.clone();
                forward_args.push(args[index].clone());
                forward_args.push(value.clone());
                index += 2;
            }
            "--client-host" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "missing value for --client-host".to_owned())?;
                client_host = value.clone();
                forward_args.push(args[index].clone());
                forward_args.push(value.clone());
                index += 2;
            }
            "--ssh-user"
            | "--ssh-port"
            | "--ssh-identity"
            | "--ssh-sudo"
            | "--ssh-known-hosts-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| format!("missing value for {}", args[index]))?;
                match args[index].as_str() {
                    "--ssh-user" => ssh_user = value.clone(),
                    "--ssh-port" => ssh_port = value.clone(),
                    "--ssh-identity" => ssh_identity = value.clone(),
                    "--ssh-sudo" => ssh_sudo_mode = value.clone(),
                    "--ssh-known-hosts-file" => ssh_known_hosts_file = value.clone(),
                    _ => {}
                }
                forward_args.push(args[index].clone());
                forward_args.push(value.clone());
                index += 2;
            }
            other => {
                forward_args.push(other.to_owned());
                index += 1;
            }
        }
    }

    if exit_host.is_empty() || client_host.is_empty() {
        return Err("--exit-host and --client-host are required".to_owned());
    }
    if rogue_endpoint_ip.is_empty() {
        return Err("--rogue-endpoint-ip is required".to_owned());
    }

    Ok(Config {
        report_path,
        ssh_port,
        ssh_user,
        ssh_identity,
        ssh_sudo_mode,
        ssh_known_hosts_file,
        exit_host,
        client_host,
        rogue_endpoint_ip,
        forward_args,
    })
}

fn validate_common_inputs(
    exit_host: &str,
    client_host: &str,
    ssh_port: &str,
    ssh_identity: &str,
    ssh_sudo_mode: &str,
    ssh_known_hosts_file: &str,
) -> Result<(), String> {
    let _ = (exit_host, client_host);
    if ssh_port.parse::<u16>().is_err() {
        return Err("--ssh-port must be numeric".to_owned());
    }
    if !ssh_identity.is_empty() && !Path::new(ssh_identity).is_file() {
        return Err(format!("--ssh-identity does not exist: {ssh_identity}"));
    }
    match ssh_sudo_mode {
        "auto" | "always" | "never" => {}
        _ => return Err("--ssh-sudo must be one of: auto|always|never".to_owned()),
    }
    run_ok({
        let mut command = Command::new("cargo");
        command
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--",
                "ops",
                "check-local-file-mode",
                "--path",
                ssh_known_hosts_file,
                "--policy",
                "no-group-world-write",
                "--label",
                "pinned SSH known_hosts file",
            ])
            .current_dir(repo_root()?)
            .stdout(Stdio::null());
        command
    })?;
    Ok(())
}

fn resolve_known_hosts(value: &str) -> Result<String, String> {
    let mut candidate = value.to_owned();
    if candidate.is_empty() {
        let home = env::var("HOME").map_err(|e| format!("resolve HOME: {e}"))?;
        let default_path = Path::new(&home).join(".ssh/known_hosts");
        if default_path.is_file() {
            candidate = default_path.to_string_lossy().into_owned();
        }
    }
    if candidate.is_empty() {
        return Err(
            "--ssh-known-hosts-file is required (or pre-populate ~/.ssh/known_hosts)".to_owned(),
        );
    }
    let path = Path::new(&candidate);
    if !path.is_file() {
        return Err(format!("missing pinned SSH known_hosts file: {candidate}"));
    }
    if fs::symlink_metadata(path)
        .map_err(|e| format!("stat known_hosts: {e}"))?
        .file_type()
        .is_symlink()
    {
        return Err(format!(
            "pinned SSH known_hosts file must not be a symlink: {candidate}"
        ));
    }
    Ok(candidate)
}

fn ensure_known_host(known_hosts_file: &str, host: &str) -> Result<(), String> {
    let status = Command::new("ssh-keygen")
        .args(["-F", host, "-f", known_hosts_file])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("run ssh-keygen: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "pinned SSH known_hosts file lacks host key for {host}: {known_hosts_file}"
        ))
    }
}

fn build_ssh_context(config: &Config) -> SshContext {
    let mut base = vec![
        "ssh".to_owned(),
        "-o".to_owned(),
        "BatchMode=yes".to_owned(),
        "-o".to_owned(),
        "StrictHostKeyChecking=yes".to_owned(),
        "-o".to_owned(),
        format!("UserKnownHostsFile={}", config.ssh_known_hosts_file),
        "-o".to_owned(),
        "ConnectTimeout=15".to_owned(),
        "-p".to_owned(),
        config.ssh_port.clone(),
    ];
    if !config.ssh_identity.is_empty() {
        base.push("-i".to_owned());
        base.push(config.ssh_identity.clone());
    }
    SshContext {
        base,
        sudo_mode: config.ssh_sudo_mode.clone(),
        ssh_user: config.ssh_user.clone(),
    }
}

fn require_command(command: &str) -> Result<(), String> {
    let status = Command::new("which")
        .arg(command)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|e| format!("run which: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
    }
}

fn run_ok(mut command: Command) -> Result<(), String> {
    let status = command.status().map_err(|e| format!("run command: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("command failed with status {status}"))
    }
}

fn command_stdout(mut command: Command) -> Result<String, String> {
    let output = command.output().map_err(|e| format!("run command: {e}"))?;
    if !output.status.success() {
        return Err(format!("command failed with status {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("command output not utf8: {e}"))
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .ancestors()
        .nth(2)
        .map(Path::to_path_buf)
        .ok_or_else(|| "unable to resolve repository root".to_owned())
}

fn unix_now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("system clock before unix epoch: {e}"))
}

fn utc_now() -> Result<(String, String), String> {
    let unix = unix_now()?.to_string();
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .map_err(|e| format!("run date: {e}"))?;
    if !output.status.success() {
        return Err(format!("date failed with status {}", output.status));
    }
    let utc = String::from_utf8(output.stdout).map_err(|e| format!("date output not utf8: {e}"))?;
    Ok((utc.trim().to_owned(), unix))
}
