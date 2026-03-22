#![forbid(unsafe_code)]
#![allow(dead_code)]

#[path = "../../env_file.rs"]
#[allow(dead_code)]
mod env_file;

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct Logger {
    file: File,
}

impl Logger {
    pub fn new(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|err| format!("create log parent failed ({}): {err}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
            .map_err(|err| format!("open log file failed ({}): {err}", path.display()))?;
        Ok(Self { file })
    }

    pub fn line(&mut self, line: &str) -> Result<(), String> {
        println!("{line}");
        writeln!(self.file, "{line}").map_err(|err| format!("write log line failed: {err}"))
    }

    pub fn block(&mut self, text: &str) -> Result<(), String> {
        print!("{text}");
        self.file
            .write_all(text.as_bytes())
            .map_err(|err| format!("write log block failed: {err}"))
    }
}

pub struct Workspace {
    root: PathBuf,
}

impl Workspace {
    pub fn new(prefix: &str) -> Result<Self, String> {
        let pid = std::process::id();
        let suffix = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let stamp = unix_now();
        let root = env::temp_dir().join(format!("{prefix}.{pid}.{stamp}.{suffix}"));
        fs::create_dir_all(&root)
            .map_err(|err| format!("create workspace failed ({}): {err}", root.display()))?;
        set_mode(&root, 0o700)?;
        Ok(Self { root })
    }

    pub fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn require_command(command: &str) -> Result<(), String> {
    if command_exists(command) {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
    }
}

pub fn command_exists(command: &str) -> bool {
    if Path::new(command).components().count() > 1 {
        return Path::new(command).is_file();
    }
    let Some(path_value) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_value).any(|dir| dir.join(command).is_file())
}

pub fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

pub fn ensure_safe_token(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(c, '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-')
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

pub fn ensure_safe_spec(label: &str, value: &str) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("{label} must not be empty"));
    }
    let allowed = |c: char| {
        c.is_ascii_alphanumeric()
            || matches!(
                c,
                '.' | '_' | ':' | '/' | ',' | '@' | '+' | '=' | '-' | '|' | ';'
            )
    };
    if !value.chars().all(allowed) {
        return Err(format!("{label} contains unsupported characters: {value}"));
    }
    Ok(())
}

pub fn target_user(target: &str) -> &str {
    target
        .split_once('@')
        .map(|(user, _)| user)
        .unwrap_or(target)
}

pub fn target_address(target: &str) -> &str {
    target
        .split_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target)
}

pub fn remote_src_dir(target: &str) -> String {
    match target_user(target) {
        "root" => "/root/Rustynet".to_string(),
        user => format!("/home/{user}/Rustynet"),
    }
}

pub fn shell_quote(value: &str) -> String {
    let mut out = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

pub fn quote_env_value(value: &str) -> Result<String, String> {
    if value.contains('\0') || value.contains('\n') || value.contains('\r') {
        return Err("env value contains newline or NUL characters".to_string());
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '$' => quoted.push_str("\\$"),
            '`' => quoted.push_str("\\`"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    Ok(quoted)
}

pub fn append_env_assignment(path: &Path, key: &str, value: &str) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map_err(|err| format!("open env file failed ({}): {err}", path.display()))?;
    let value = quote_env_value(value)?;
    writeln!(file, "{key}={value}")
        .map_err(|err| format!("write env assignment failed ({}): {err}", path.display()))
}

pub fn write_assignment_refresh_env(
    path: &Path,
    target_node_id: &str,
    nodes_spec: &str,
    allow_spec: &str,
    exit_node_id: Option<&str>,
) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create assignment refresh env parent failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, b"").map_err(|err| {
        format!(
            "truncate assignment refresh env failed ({}): {err}",
            path.display()
        )
    })?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_AUTO_REFRESH", "true")?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_TARGET_NODE_ID", target_node_id)?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_NODES", nodes_spec)?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_ALLOW", allow_spec)?;
    append_env_assignment(
        path,
        "RUSTYNET_ASSIGNMENT_SIGNING_SECRET",
        "/etc/rustynet/assignment.signing.secret",
    )?;
    append_env_assignment(
        path,
        "RUSTYNET_ASSIGNMENT_SIGNING_SECRET_PASSPHRASE_FILE",
        "/run/credentials/rustynetd-assignment-refresh.service/signing_key_passphrase",
    )?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_TTL_SECS", "300")?;
    append_env_assignment(path, "RUSTYNET_ASSIGNMENT_MIN_REMAINING_SECS", "180")?;
    if let Some(exit_node_id) = exit_node_id {
        append_env_assignment(path, "RUSTYNET_ASSIGNMENT_EXIT_NODE_ID", exit_node_id)?;
    }
    Ok(())
}

pub fn run_cargo_ops(root_dir: &Path, subcommand: &str, args: &[OsString]) -> Result<(), String> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            subcommand,
        ])
        .args(args.iter().map(OsString::as_os_str))
        .status()
        .map_err(|err| format!("failed to run ops {subcommand}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ops {subcommand} failed with status {}",
            status_code(status)
        ))
    }
}

pub fn run_cargo_bin(root_dir: &Path, bin_name: &str, args: &[OsString]) -> Result<(), String> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            bin_name,
            "--",
        ])
        .args(args.iter().map(OsString::as_os_str))
        .status()
        .map_err(|err| format!("failed to run bin {bin_name}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "bin {bin_name} failed with status {}",
            status_code(status)
        ))
    }
}

pub fn ensure_pinned_known_hosts_file(path: &Path) -> Result<(), String> {
    if path.as_os_str().is_empty() {
        return Err("pinned known_hosts file path is required".to_string());
    }
    if !path.is_file() {
        return Err(format!(
            "missing pinned known_hosts file: {}",
            path.display()
        ));
    }
    if is_symlink(path) {
        return Err(format!(
            "pinned known_hosts file must not be a symlink: {}",
            path.display()
        ));
    }
    run_cargo_ops(
        &repo_root()?,
        "check-local-file-mode",
        &[
            OsString::from("--path"),
            path.as_os_str().to_os_string(),
            OsString::from("--policy"),
            OsString::from("no-group-world-write"),
            OsString::from("--label"),
            OsString::from("pinned known_hosts file"),
        ],
    )
}

pub fn load_home_known_hosts_path() -> Result<PathBuf, String> {
    let home = env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "HOME is not set".to_string())?;
    Ok(PathBuf::from(home).join(".ssh/known_hosts"))
}

pub fn seed_known_hosts(src: &Path, dst: &Path) -> Result<(), String> {
    fs::copy(src, dst).map_err(|err| {
        format!(
            "failed to seed known_hosts from {} to {}: {err}",
            src.display(),
            dst.display()
        )
    })?;
    set_mode(dst, 0o600)?;
    Ok(())
}

pub fn require_pinned_host_entry(pinned_known_hosts: &Path, target: &str) -> Result<(), String> {
    let host = target_address(target);
    let status = Command::new("ssh-keygen")
        .args(["-F", host, "-f"])
        .arg(pinned_known_hosts)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|err| format!("failed to run ssh-keygen -F for {host}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "pinned known_hosts file lacks host key for {host}: {}",
            pinned_known_hosts.display()
        ))
    }
}

fn ssh_base_command(identity: &Path, known_hosts: &Path, target: &str) -> Command {
    let mut command = Command::new("ssh");
    command.args([
        "-n",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=20",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
    ]);
    command.arg(identity);
    command.arg("--");
    command.arg(target);
    command
}

fn scp_base_command(identity: &Path, known_hosts: &Path) -> Command {
    let mut command = Command::new("scp");
    command.args([
        "-q",
        "-o",
        "LogLevel=ERROR",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts.display()),
        "-o",
        "ConnectTimeout=15",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
    ]);
    command.arg(identity);
    command.arg("--");
    command
}

pub fn ssh_status(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    command: &str,
) -> Result<ExitStatus, String> {
    require_pinned_host_entry(known_hosts, target)?;
    let mut ssh = ssh_base_command(identity, known_hosts, target);
    ssh.arg(command);
    ssh.stdin(Stdio::null())
        .status()
        .map_err(|err| format!("failed to run ssh against {target}: {err}"))
}

pub fn ssh_output(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    command: &str,
) -> Result<String, String> {
    require_pinned_host_entry(known_hosts, target)?;
    let mut ssh = ssh_base_command(identity, known_hosts, target);
    ssh.arg(command);
    let output = ssh
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to run ssh against {target}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "ssh command failed against {target} with status {}",
            status_code(output.status)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn scp_to(
    identity: &Path,
    known_hosts: &Path,
    src: &Path,
    target: &str,
    dst: &str,
) -> Result<(), String> {
    require_pinned_host_entry(known_hosts, target)?;
    let mut scp = scp_base_command(identity, known_hosts);
    scp.arg(src);
    scp.arg(format!("{target}:{dst}"));
    let status = scp
        .stdin(Stdio::null())
        .status()
        .map_err(|err| format!("failed to scp {} to {target}:{dst}: {err}", src.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "scp {} to {target}:{dst} failed with status {}",
            src.display(),
            status_code(status)
        ))
    }
}

pub fn scp_from(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    src: &str,
    dst: &Path,
) -> Result<(), String> {
    require_pinned_host_entry(known_hosts, target)?;
    let mut scp = scp_base_command(identity, known_hosts);
    scp.arg(format!("{target}:{src}"));
    scp.arg(dst);
    let status = scp
        .stdin(Stdio::null())
        .status()
        .map_err(|err| format!("failed to scp {target}:{src} to {}: {err}", dst.display()))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "scp {target}:{src} to {} failed with status {}",
            dst.display(),
            status_code(status)
        ))
    }
}

pub fn capture_remote_stdout(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    command: &str,
) -> Result<String, String> {
    require_pinned_host_entry(known_hosts, target)?;
    let mut ssh = ssh_base_command(identity, known_hosts, target);
    ssh.arg(command);
    let output = ssh
        .stdin(Stdio::null())
        .output()
        .map_err(|err| format!("failed to run ssh against {target}: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "ssh command failed against {target} with status {}",
            status_code(output.status)
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

pub fn push_sudo_password(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    verify_sudo(identity, known_hosts, target)
}

pub fn verify_sudo(identity: &Path, known_hosts: &Path, target: &str) -> Result<(), String> {
    let hostname_check = "current_hostname=$(hostname); if ! grep -Eq '(^|[[:space:]])'\"$current_hostname\"'([[:space:]]|$)' /etc/hosts; then printf 'local hostname %s is missing from /etc/hosts\\n' \"$current_hostname\"; exit 1; fi";
    let status = ssh_status(identity, known_hosts, target, hostname_check)?;
    if !status.success() {
        return Err(format!("hostname verification failed for {target}"));
    }
    let verify_cmd = "if sudo -n -k true >/dev/null 2>&1; then :; else printf 'passwordless sudo (sudo -n) is required for live lab automation\\n'; printf 'user: %s\\n' \"$(id -un)\"; printf 'groups: %s\\n' \"$(id -Gn)\"; exit 1; fi";
    let status = ssh_status(identity, known_hosts, target, verify_cmd)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "passwordless sudo verification failed for {target}"
        ))
    }
}

pub fn capture_root(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    body: &str,
) -> Result<String, String> {
    let command = format!("sudo -n sh -lc {}", shell_quote(body));
    capture_remote_stdout(identity, known_hosts, target, &command)
}

pub fn run_root(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    body: &str,
) -> Result<(), String> {
    let command = format!("sudo -n sh -lc {}", shell_quote(body));
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "root command failed for {target} with status {}",
            status_code(status)
        ))
    }
}

pub fn retry_root(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    body: &str,
    attempts: usize,
    sleep_secs: u64,
) -> Result<(), String> {
    for attempt in 1..=attempts {
        if run_root(identity, known_hosts, target, body).is_ok() {
            return Ok(());
        }
        if attempt < attempts {
            std::thread::sleep(std::time::Duration::from_secs(sleep_secs));
        }
    }
    run_root(identity, known_hosts, target, body)
}

pub fn wait_for_daemon_socket(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    socket_path: &str,
    attempts: usize,
    sleep_secs: u64,
) -> Result<(), String> {
    let body = format!("test -S {}", shell_quote(socket_path));
    retry_root(
        identity,
        known_hosts,
        target,
        body.as_str(),
        attempts,
        sleep_secs,
    )
}

pub fn status(identity: &Path, known_hosts: &Path, target: &str) -> Result<String, String> {
    capture_root(
        identity,
        known_hosts,
        target,
        "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status",
    )
}

pub fn no_plaintext_passphrase_check(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<String, String> {
    capture_root(
        identity,
        known_hosts,
        target,
        "test ! -e /var/lib/rustynet/keys/wireguard.passphrase && test ! -e /etc/rustynet/wireguard.passphrase && test ! -e /etc/rustynet/signing_key_passphrase && echo no-plaintext-passphrase-files",
    )
}

pub fn issue_assignment_bundles_from_env(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), String> {
    scp_to(identity, known_hosts, env_local, target, remote_env_path)?;
    let command = format!(
        "sudo -n rustynet ops e2e-issue-assignment-bundles-from-env --env-file {}",
        shell_quote(remote_env_path)
    );
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if !status.success() {
        let _ = run_root(
            identity,
            known_hosts,
            target,
            &format!("rm -f {}", shell_quote(remote_env_path)),
        );
        return Err(format!(
            "issue assignment bundles from env failed for {target} with status {}",
            status_code(status)
        ));
    }
    run_root(
        identity,
        known_hosts,
        target,
        &format!("rm -f {}", shell_quote(remote_env_path)),
    )
}

pub fn issue_traversal_bundles_from_env(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    env_local: &Path,
    remote_env_path: &str,
) -> Result<(), String> {
    scp_to(identity, known_hosts, env_local, target, remote_env_path)?;
    let command = format!(
        "sudo -n rustynet ops e2e-issue-traversal-bundles-from-env --env-file {}",
        shell_quote(remote_env_path)
    );
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if !status.success() {
        let _ = run_root(
            identity,
            known_hosts,
            target,
            &format!("rm -f {}", shell_quote(remote_env_path)),
        );
        return Err(format!(
            "issue traversal bundles from env failed for {target} with status {}",
            status_code(status)
        ));
    }
    run_root(
        identity,
        known_hosts,
        target,
        &format!("rm -f {}", shell_quote(remote_env_path)),
    )
}

pub fn enforce_host(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    role: &str,
    node_id: &str,
    src_dir: &str,
    ssh_allow_cidrs: &str,
) -> Result<(), String> {
    let command = format!(
        "sudo -n rustynet ops e2e-enforce-host --role {} --node-id {} --src-dir {} --ssh-allow-cidrs {}",
        shell_quote(role),
        shell_quote(node_id),
        shell_quote(src_dir),
        shell_quote(ssh_allow_cidrs)
    );
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "enforce-host failed for {target} with status {}",
            status_code(status)
        ))
    }
}

pub fn apply_role_coupling(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    target_role: &str,
    preferred_exit_node_id: Option<&str>,
    enable_exit_advertise: bool,
    env_path: &str,
) -> Result<(), String> {
    let mut command = format!(
        "sudo -n env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-role-coupling --target-role {} --enable-exit-advertise {} --env-path {}",
        shell_quote(target_role),
        shell_quote(if enable_exit_advertise {
            "true"
        } else {
            "false"
        }),
        shell_quote(env_path),
    );
    if let Some(preferred_exit_node_id) = preferred_exit_node_id {
        command.push_str(" --preferred-exit-node-id ");
        command.push_str(shell_quote(preferred_exit_node_id).as_str());
    }
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "apply-role-coupling failed for {target} with status {}",
            status_code(status)
        ))
    }
}

pub fn apply_lan_access_coupling(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    enable: bool,
    lan_routes: Option<&str>,
    env_path: &str,
) -> Result<(), String> {
    let mut command = format!(
        "sudo -n env RUSTYNET_SOCKET=/run/rustynet/rustynetd.sock RUSTYNET_AUTO_TUNNEL_BUNDLE=/var/lib/rustynet/rustynetd.assignment RUSTYNET_AUTO_TUNNEL_WATERMARK=/var/lib/rustynet/rustynetd.assignment.watermark rustynet ops apply-lan-access-coupling --enable {} --env-path {}",
        shell_quote(if enable { "true" } else { "false" }),
        shell_quote(env_path)
    );
    if let Some(lan_routes) = lan_routes {
        command.push_str(" --lan-routes ");
        command.push_str(shell_quote(lan_routes).as_str());
    }
    let status = ssh_status(identity, known_hosts, target, &command)?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "apply-lan-access-coupling failed for {target} with status {}",
            status_code(status)
        ))
    }
}

pub fn collect_pubkey_hex(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<String, String> {
    let pub_b64 = capture_root(
        identity,
        known_hosts,
        target,
        "cat /var/lib/rustynet/keys/wireguard.pub | tr -d '[:space:]'",
    )?;
    let pub_hex = base64_to_hex(pub_b64.trim())?;
    if pub_hex.len() != 64 || !pub_hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(format!("failed to decode wireguard pubkey for {target}"));
    }
    Ok(pub_hex)
}

pub fn base64_to_hex(value: &str) -> Result<String, String> {
    let decoded = decode_base64(value.trim())?;
    let mut output = String::with_capacity(decoded.len() * 2);
    for byte in decoded {
        output.push_str(format!("{byte:02x}").as_str());
    }
    Ok(output)
}

fn decode_base64(value: &str) -> Result<Vec<u8>, String> {
    use std::collections::BTreeMap;

    const TABLE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut reverse = BTreeMap::new();
    for (index, ch) in TABLE.chars().enumerate() {
        reverse.insert(ch, index as u8);
    }
    let clean = value
        .chars()
        .filter(|ch| !ch.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if clean.is_empty() || clean.len() % 4 != 0 {
        return Err("invalid base64 wireguard public key".to_string());
    }
    let mut output = Vec::with_capacity(clean.len() / 4 * 3);
    for chunk in clean.chunks(4) {
        let mut sextets = [0u8; 4];
        let mut padding = 0usize;
        for (index, ch) in chunk.iter().enumerate() {
            if *ch == '=' {
                sextets[index] = 0;
                padding += 1;
            } else if let Some(value) = reverse.get(ch) {
                sextets[index] = *value;
            } else {
                return Err("invalid base64 wireguard public key".to_string());
            }
        }
        let b0 = (sextets[0] << 2) | (sextets[1] >> 4);
        let b1 = ((sextets[1] & 0x0f) << 4) | (sextets[2] >> 2);
        let b2 = ((sextets[2] & 0x03) << 6) | sextets[3];
        output.push(b0);
        if padding < 2 {
            output.push(b1);
        }
        if padding < 1 {
            output.push(b2);
        }
    }
    Ok(output)
}

pub fn git_head_commit(root_dir: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .current_dir(root_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err("git rev-parse HEAD returned empty output".to_string());
    }
    Ok(trimmed)
}

pub fn read_last_matching_line(text: &str, needle: &str) -> String {
    text.lines()
        .filter(|line| line.contains(needle))
        .next_back()
        .unwrap_or("")
        .to_string()
}

pub fn field_value(line: &str, key: &str) -> String {
    for field in line.split_whitespace() {
        if let Some(value) = field.strip_prefix(&format!("{key}=")) {
            return value.to_string();
        }
    }
    String::new()
}

pub fn read_file(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))
}

pub fn write_file(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create parent directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, body.as_bytes())
        .map_err(|err| format!("write {} failed: {err}", path.display()))
}

pub fn create_workspace(prefix: &str) -> Result<Workspace, String> {
    Workspace::new(prefix)
}

#[cfg(unix)]
fn set_mode(path: &Path, mode: u32) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;

    let metadata = fs::metadata(path)
        .map_err(|err| format!("read metadata failed ({}): {err}", path.display()))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(mode);
    fs::set_permissions(path, permissions).map_err(|err| {
        format!(
            "set permissions failed ({} mode {:o}): {err}",
            path.display(),
            mode
        )
    })
}

#[cfg(not(unix))]
fn set_mode(_path: &Path, _mode: u32) -> Result<(), String> {
    Ok(())
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
}
