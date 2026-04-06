#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use serde_json::Value;

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

pub fn read_text(path: &Path) -> Result<String, String> {
    fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))
}

pub fn write_secure_text(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let mut file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    file.write_all(contents.as_bytes())
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("failed to flush {}: {err}", path.display()))
}

pub fn write_secure_json(path: &Path, value: &Value) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let file = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))
}

pub fn ensure_dir_secure(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    let metadata =
        fs::metadata(path).map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
    let mut permissions = metadata.permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|err| format!("failed to secure {}: {err}", path.display()))
}

pub fn require_local_file_mode(path: &Path, policy: &str, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("missing {label}: {} ({err})", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} must be a regular file: {}",
            path.display()
        ));
    }
    let current_uid = Uid::current().as_raw();
    if metadata.uid() != current_uid {
        return Err(format!(
            "{label} must be owned by the current user (path: {}, owner uid: {}, current uid: {})",
            path.display(),
            metadata.uid(),
            current_uid
        ));
    }
    let mode = metadata.mode() & 0o777;
    match policy {
        "owner-only" => {
            if mode & 0o077 != 0 {
                return Err(format!(
                    "{label} must be owner-only (mode {:o}, path: {})",
                    mode,
                    path.display()
                ));
            }
        }
        "no-group-world-write" => {
            if mode & 0o022 != 0 {
                return Err(format!(
                    "{label} must not be group/world-writable (mode {:o}, path: {})",
                    mode,
                    path.display()
                ));
            }
        }
        other => {
            return Err(format!("unsupported local file policy: {other}"));
        }
    }
    Ok(())
}

pub fn shell_single_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_string();
    }
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\\''");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

#[derive(Debug, Clone)]
pub struct Logger {
    file: PathBuf,
}

impl Logger {
    pub fn new(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            ensure_dir_secure(parent)?;
        }
        write_secure_text(path, "")?;
        Ok(Self {
            file: path.to_path_buf(),
        })
    }

    pub fn line(&self, text: impl AsRef<str>) -> Result<(), String> {
        let text = text.as_ref();
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.file)
            .map_err(|err| format!("failed to append {}: {err}", self.file.display()))?;
        writeln!(file, "{text}")
            .map_err(|err| format!("failed to append {}: {err}", self.file.display()))?;
        println!("{text}");
        Ok(())
    }

    pub fn raw(&self, text: impl AsRef<str>) -> Result<(), String> {
        let text = text.as_ref();
        if text.is_empty() {
            return Ok(());
        }
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.file)
            .map_err(|err| format!("failed to append {}: {err}", self.file.display()))?;
        file.write_all(text.as_bytes())
            .map_err(|err| format!("failed to append {}: {err}", self.file.display()))?;
        if !text.ends_with('\n') {
            file.write_all(b"\n")
                .map_err(|err| format!("failed to append {}: {err}", self.file.display()))?;
        }
        print!("{text}");
        if !text.ends_with('\n') {
            println!();
        }
        Ok(())
    }

    pub fn block(&self, label: impl AsRef<str>, body: impl AsRef<str>) -> Result<(), String> {
        self.line(label)?;
        self.raw(body)
    }
}

#[derive(Debug, Clone)]
pub struct LiveLabContext {
    pub root_dir: PathBuf,
    pub ssh_identity_file: PathBuf,
    pub pinned_known_hosts_file: PathBuf,
    pub work_dir: PathBuf,
    pub known_hosts_file: PathBuf,
    verified_hosts: HashSet<String>,
}

impl LiveLabContext {
    pub fn new(prefix: &str, ssh_identity_file: &Path) -> Result<Self, String> {
        require_local_file_mode(ssh_identity_file, "owner-only", "ssh identity file")?;
        let pinned_known_hosts_file = env::var_os("LIVE_LAB_PINNED_KNOWN_HOSTS_FILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from("/root"))
                    .join(".ssh/known_hosts")
            });
        require_local_file_mode(
            pinned_known_hosts_file.as_path(),
            "no-group-world-write",
            "pinned known_hosts file",
        )?;

        let root_dir = repo_root()?;
        let work_dir = create_unique_work_dir(prefix)?;
        let known_hosts_file = work_dir.join("known_hosts");
        fs::copy(&pinned_known_hosts_file, &known_hosts_file).map_err(|err| {
            format!(
                "failed to seed {} from {}: {err}",
                known_hosts_file.display(),
                pinned_known_hosts_file.display()
            )
        })?;
        fs::set_permissions(&known_hosts_file, fs::Permissions::from_mode(0o600))
            .map_err(|err| format!("failed to secure {}: {err}", known_hosts_file.display()))?;

        Ok(Self {
            root_dir,
            ssh_identity_file: ssh_identity_file.to_path_buf(),
            pinned_known_hosts_file,
            work_dir,
            known_hosts_file,
            verified_hosts: HashSet::new(),
        })
    }

    pub fn cleanup(&self) {
        let _ = fs::remove_dir_all(&self.work_dir);
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
            .map(|(_, addr)| addr)
            .unwrap_or(target)
    }

    pub fn resolved_target_address(target: &str) -> Result<String, String> {
        let resolved = Command::new("ssh")
            .args(["-G", target])
            .stdin(Stdio::null())
            .output()
            .map_err(|err| format!("failed resolving SSH target address for {target}: {err}"))?;
        if !resolved.status.success() {
            return Err(format!(
                "failed resolving SSH target address for {target}: {}",
                String::from_utf8_lossy(&resolved.stderr).trim()
            ));
        }
        let resolved_text = String::from_utf8_lossy(&resolved.stdout);
        let host = resolved_target_address_from_ssh_g(target, &resolved_text);
        if host.is_empty() {
            Err(format!("resolved SSH target address is empty for {target}"))
        } else {
            Ok(host)
        }
    }

    pub fn remote_src_dir(target: &str) -> String {
        if Self::target_user(target) == "root" {
            "/root/Rustynet".to_string()
        } else {
            format!("/home/{}/Rustynet", Self::target_user(target))
        }
    }

    fn require_pinned_host_entry(&self, target: &str) -> Result<(), String> {
        let resolved = Command::new("ssh")
            .args(["-G", target])
            .stdin(Stdio::null())
            .output()
            .map_err(|err| {
                format!("failed resolving SSH target for host-key verification {target}: {err}")
            })?;
        if !resolved.status.success() {
            return Err(format!(
                "failed resolving SSH target for host-key verification {target}: {}",
                String::from_utf8_lossy(&resolved.stderr).trim()
            ));
        }

        let resolved_text = String::from_utf8_lossy(&resolved.stdout);
        let lookup_candidates = resolved_known_hosts_candidates(target, &resolved_text)?;
        if lookup_candidates.is_empty() {
            return Err(format!(
                "pinned known_hosts verification resolved no lookup candidates for {target}"
            ));
        }

        for lookup_host in &lookup_candidates {
            let output = Command::new("ssh-keygen")
                .arg("-F")
                .arg(lookup_host)
                .arg("-f")
                .arg(&self.pinned_known_hosts_file)
                .output()
                .map_err(|err| {
                    format!("failed to inspect pinned known_hosts for {lookup_host}: {err}")
                })?;
            if output.status.success() {
                return Ok(());
            }
        }

        Err(format!(
            "pinned known_hosts file lacks host key for {target}; checked {} in {}",
            lookup_candidates.join(", "),
            self.pinned_known_hosts_file.display()
        ))
    }

    fn ssh_command(&self, target: &str) -> Command {
        let mut command = Command::new("ssh");
        command.args([
            "-n",
            "-o",
            "LogLevel=ERROR",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
        ]);
        command.arg("-o").arg(format!(
            "UserKnownHostsFile={}",
            self.known_hosts_file.display()
        ));
        command.args([
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
        command.arg(&self.ssh_identity_file);
        command.arg("--");
        command.arg(target);
        command
    }

    fn run_ssh(&self, target: &str, args: &[&str], allow_failure: bool) -> Result<Output, String> {
        self.require_pinned_host_entry(target)?;
        let remote_command = render_remote_argv(args)?;
        let mut command = self.ssh_command(target);
        command
            .args(["sh", "-lc"])
            .arg(shell_single_quote(remote_command.as_str()))
            .stdin(Stdio::null());
        let output = command
            .output()
            .map_err(|err| format!("failed to run ssh for {target}: {err}"))?;
        if !allow_failure && !output.status.success() {
            return Err(format!(
                "remote command failed on {target}: {}",
                render_failure_output(&output)
            ));
        }
        Ok(output)
    }

    pub fn run(&self, target: &str, args: &[&str]) -> Result<(), String> {
        let output = self.run_ssh(target, args, false)?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "remote command failed on {target}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ))
        }
    }

    pub fn run_allow_failure(&self, target: &str, args: &[&str]) -> Result<Output, String> {
        self.run_ssh(target, args, true)
    }

    pub fn capture(&self, target: &str, args: &[&str]) -> Result<String, String> {
        let output = self.run_ssh(target, args, false)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn capture_allow_failure(&self, target: &str, args: &[&str]) -> Result<String, String> {
        let output = self.run_ssh(target, args, true)?;
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    pub fn scp_to(&self, src: &Path, target: &str, dst: &str) -> Result<(), String> {
        self.require_pinned_host_entry(target)?;
        let status = Command::new("scp")
            .arg("-q")
            .args([
                "-o",
                "LogLevel=ERROR",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
            ])
            .arg("-o")
            .arg(format!(
                "UserKnownHostsFile={}",
                self.known_hosts_file.display()
            ))
            .args(["-o", "ConnectTimeout=15", "-o", "IdentitiesOnly=yes", "-i"])
            .arg(&self.ssh_identity_file)
            .arg("--")
            .arg(src)
            .arg(format!("{target}:{dst}"))
            .status()
            .map_err(|err| format!("failed to run scp to {target}: {err}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("scp to {target} failed"))
        }
    }

    pub fn run_root(&self, target: &str, args: &[&str]) -> Result<(), String> {
        self.run(target, &["sudo", "-n", "-k", "true"])?;
        let mut full_args = vec!["sudo", "-n"];
        full_args.extend_from_slice(args);
        self.run(target, &full_args)
    }

    pub fn run_root_allow_failure(&self, target: &str, args: &[&str]) -> Result<Output, String> {
        self.run(target, &["sudo", "-n", "-k", "true"])?;
        let mut full_args = vec!["sudo", "-n"];
        full_args.extend_from_slice(args);
        self.run_allow_failure(target, &full_args)
    }

    pub fn capture_root(&self, target: &str, args: &[&str]) -> Result<String, String> {
        self.run(target, &["sudo", "-n", "-k", "true"])?;
        let mut full_args = vec!["sudo", "-n"];
        full_args.extend_from_slice(args);
        self.capture(target, &full_args)
    }

    pub fn capture_root_allow_failure(
        &self,
        target: &str,
        args: &[&str],
    ) -> Result<String, String> {
        self.run(target, &["sudo", "-n", "-k", "true"])?;
        let mut full_args = vec!["sudo", "-n"];
        full_args.extend_from_slice(args);
        self.capture_allow_failure(target, &full_args)
    }

    pub fn capture_root_allow_failure_with_retry(
        &self,
        target: &str,
        args: &[&str],
        attempts: u32,
        sleep_secs: u64,
    ) -> Result<String, String> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.capture_root_allow_failure(target, args) {
                Ok(output) => return Ok(output),
                Err(err) => {
                    last_err = Some(err);
                    if attempt < attempts {
                        sleep(Duration::from_secs(sleep_secs));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_string()))
    }

    pub fn run_root_allow_failure_with_retry(
        &self,
        target: &str,
        args: &[&str],
        attempts: u32,
        sleep_secs: u64,
    ) -> Result<Output, String> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.run_root_allow_failure(target, args) {
                Ok(output) => return Ok(output),
                Err(err) => {
                    last_err = Some(err);
                    if attempt < attempts {
                        sleep(Duration::from_secs(sleep_secs));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_string()))
    }

    pub fn retry_root(
        &self,
        target: &str,
        args: &[&str],
        attempts: u32,
        sleep_secs: u64,
    ) -> Result<(), String> {
        let mut last_err = None;
        for attempt in 1..=attempts {
            match self.run_root(target, args) {
                Ok(()) => return Ok(()),
                Err(err) => {
                    last_err = Some(err);
                    if attempt < attempts {
                        sleep(Duration::from_secs(sleep_secs));
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_string()))
    }

    pub fn wait_for_daemon_socket(
        &self,
        target: &str,
        socket_path: &str,
        attempts: u32,
        sleep_secs: u64,
    ) -> Result<(), String> {
        self.retry_root(target, &["test", "-S", socket_path], attempts, sleep_secs)
    }

    pub fn verify_sudo(&self, target: &str) -> Result<(), String> {
        let hostname = self.capture(target, &["hostname"])?;
        let hostname = hostname.trim().to_string();
        if hostname.is_empty() {
            return Err(format!("failed to resolve hostname on {target}"));
        }
        let hosts = self.capture(target, &["cat", "/etc/hosts"])?;
        if !hosts_contains_hostname(&hosts, &hostname) {
            return Err(format!(
                "local hostname {hostname} is missing from /etc/hosts on {target}"
            ));
        }
        let output = self.run_allow_failure(target, &["sudo", "-n", "-k", "true"])?;
        if output.status.success() {
            Ok(())
        } else {
            Err(format!(
                "passwordless sudo (sudo -n) is required for live lab automation on {target}"
            ))
        }
    }

    pub fn push_sudo_password(&mut self, target: &str) -> Result<(), String> {
        if self.verified_hosts.contains(target) {
            return Ok(());
        }
        self.verify_sudo(target)?;
        self.verified_hosts.insert(target.to_string());
        Ok(())
    }

    pub fn collect_pubkey_hex(&mut self, target: &str) -> Result<String, String> {
        self.push_sudo_password(target)?;
        let pub_b64 =
            self.capture_root(target, &["cat", "/var/lib/rustynet/keys/wireguard.pub"])?;
        let decoded = base64_decode(pub_b64.trim())?;
        Ok(hex_encode_lower(&decoded))
    }

    pub fn remote_src_dir_for(target: &str) -> String {
        Self::remote_src_dir(target)
    }
}

fn render_failure_output(output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stderr = stderr.trim();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stdout = stdout.trim();
    if !stderr.is_empty() && !stdout.is_empty() {
        format!("{stderr} (stdout: {stdout})")
    } else if !stderr.is_empty() {
        stderr.to_string()
    } else if !stdout.is_empty() {
        format!("stdout: {stdout}")
    } else {
        "remote command exited non-zero without output".to_string()
    }
}

fn render_remote_argv(args: &[&str]) -> Result<String, String> {
    if args.is_empty() {
        return Err("refusing to run empty remote command".to_string());
    }
    let mut rendered = String::new();
    for (index, arg) in args.iter().enumerate() {
        if arg.contains('\0') {
            return Err(format!(
                "remote command argument {} contains NUL byte",
                index + 1
            ));
        }
        if arg.contains('\n') || arg.contains('\r') {
            return Err(format!(
                "remote command argument {} contains newline byte",
                index + 1
            ));
        }
        if index > 0 {
            rendered.push(' ');
        }
        rendered.push_str(shell_single_quote(arg).as_str());
    }
    Ok(rendered)
}

impl Drop for LiveLabContext {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.work_dir);
    }
}

fn hosts_contains_hostname(hosts: &str, hostname: &str) -> bool {
    for line in hosts.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        for token in line.split_whitespace() {
            if token == hostname {
                return true;
            }
        }
    }
    false
}

fn create_unique_work_dir(prefix: &str) -> Result<PathBuf, String> {
    let base = env::temp_dir();
    let pid = std::process::id();
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system clock before epoch: {err}"))?
        .as_nanos();
    for salt in 0u32..1000 {
        let candidate = base.join(format!("{prefix}.{pid}.{timestamp}.{salt}"));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                fs::set_permissions(&candidate, fs::Permissions::from_mode(0o700))
                    .map_err(|err| format!("failed to secure {}: {err}", candidate.display()))?;
                return Ok(candidate);
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "failed to create work dir {}: {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "failed to create unique work dir for prefix {prefix}"
    ))
}

fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    let mut table = [0xFFu8; 256];
    for (idx, ch) in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        .iter()
        .enumerate()
    {
        table[*ch as usize] = idx as u8;
    }
    let compact = input
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect::<Vec<_>>();
    if compact.len() % 4 != 0 {
        return Err("invalid base64 length".to_string());
    }
    let mut output = Vec::with_capacity((compact.len() / 4) * 3);
    let mut index = 0usize;
    while index < compact.len() {
        let c0 = compact[index];
        let c1 = compact[index + 1];
        let c2 = compact[index + 2];
        let c3 = compact[index + 3];
        if c0 == b'=' || c1 == b'=' {
            return Err("invalid base64 padding".to_string());
        }
        let v0 = table[c0 as usize];
        let v1 = table[c1 as usize];
        if v0 == 0xFF || v1 == 0xFF {
            return Err("invalid base64 character".to_string());
        }
        output.push((v0 << 2) | (v1 >> 4));

        let pad2 = c2 == b'=';
        let pad3 = c3 == b'=';
        if pad2 {
            if !pad3 {
                return Err("invalid base64 padding".to_string());
            }
        } else {
            let v2 = table[c2 as usize];
            if v2 == 0xFF {
                return Err("invalid base64 character".to_string());
            }
            output.push((v1 << 4) | (v2 >> 2));
            if !pad3 {
                let v3 = table[c3 as usize];
                if v3 == 0xFF {
                    return Err("invalid base64 character".to_string());
                }
                output.push((v2 << 6) | v3);
            }
        }

        if (pad2 || pad3) && index + 4 != compact.len() {
            return Err("invalid base64 padding".to_string());
        }
        index += 4;
    }
    Ok(output)
}

fn hex_encode_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut out, "{byte:02x}");
    }
    out
}

#[allow(dead_code)]
pub fn run_cargo_ops(
    root_dir: &Path,
    ops_subcommand: &str,
    args: &[&str],
) -> Result<String, String> {
    let output = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            ops_subcommand,
        ])
        .args(args)
        .output()
        .map_err(|err| format!("failed to run cargo ops {ops_subcommand}: {err}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(format!(
            "cargo ops {ops_subcommand} failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[allow(dead_code)]
pub fn parse_ipv4(value: &str, label: &str) -> Result<Ipv4Addr, String> {
    value
        .trim()
        .parse::<Ipv4Addr>()
        .map_err(|err| format!("invalid {label} {value:?}: {err}"))
}

fn known_hosts_lookup_host(host: &str, port: &str) -> Result<String, String> {
    if host.is_empty() {
        return Err("known_hosts lookup host must not be empty".to_string());
    }
    if port.is_empty() || port == "22" {
        Ok(host.to_string())
    } else {
        Ok(format!("[{host}]:{port}"))
    }
}

fn ssh_g_value<'a>(resolved: &'a str, key: &str) -> Option<&'a str> {
    resolved.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(found_key), Some(value)) if found_key == key => Some(value),
            _ => None,
        }
    })
}

fn resolved_target_address_from_ssh_g(target: &str, resolved: &str) -> String {
    ssh_g_value(resolved, "hostname")
        .filter(|hostname| !hostname.is_empty() && *hostname != "none")
        .unwrap_or_else(|| LiveLabContext::target_address(target))
        .to_string()
}

fn resolved_known_hosts_candidates(target: &str, resolved: &str) -> Result<Vec<String>, String> {
    let raw_host = LiveLabContext::target_address(target);
    let port = ssh_g_value(resolved, "port").unwrap_or("22");
    let mut lookup_candidates = Vec::new();

    if let Some(hostkeyalias) = ssh_g_value(resolved, "hostkeyalias") {
        if hostkeyalias != "none" {
            let lookup_host = known_hosts_lookup_host(hostkeyalias, port)?;
            lookup_candidates.push(lookup_host);
        }
    }

    let raw_lookup = known_hosts_lookup_host(raw_host, port)?;
    lookup_candidates.push(raw_lookup);

    if let Some(hostname) = ssh_g_value(resolved, "hostname") {
        let lookup_host = known_hosts_lookup_host(hostname, port)?;
        if !lookup_candidates.contains(&lookup_host) {
            lookup_candidates.push(lookup_host);
        }
    }

    Ok(lookup_candidates)
}

#[allow(dead_code)]
pub fn run_remote_shell(
    ctx: &LiveLabContext,
    target: &str,
    shell_command: &str,
) -> Result<Output, String> {
    let mut command = ctx.ssh_command(target);
    command
        .args(["sh", "-lc"])
        .arg(shell_single_quote(shell_command))
        .stdin(Stdio::null());
    let output = command
        .output()
        .map_err(|err| format!("failed to run remote shell on {target}: {err}"))?;
    if output.status.success() {
        Ok(output)
    } else {
        Err(format!(
            "remote shell command failed on {target}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        known_hosts_lookup_host, resolved_known_hosts_candidates,
        resolved_target_address_from_ssh_g,
    };

    #[test]
    fn resolved_known_hosts_candidates_include_alias_raw_and_hostname() {
        let resolved = "\
hostkeyalias rusty-lab
hostname debian-headless-2
port 2222
";
        let candidates =
            resolved_known_hosts_candidates("debian@192.168.18.65", resolved).expect("candidates");
        assert_eq!(
            candidates,
            vec![
                "[rusty-lab]:2222".to_string(),
                "[192.168.18.65]:2222".to_string(),
                "[debian-headless-2]:2222".to_string()
            ]
        );
    }

    #[test]
    fn resolved_known_hosts_candidates_dedupe_hostname_matches_raw_host() {
        let resolved = "\
hostname debian-headless-2
port 22
";
        let candidates = resolved_known_hosts_candidates("debian@debian-headless-2", resolved)
            .expect("candidates");
        assert_eq!(candidates, vec!["debian-headless-2".to_string()]);
    }

    #[test]
    fn known_hosts_lookup_host_uses_bracket_form_for_non_default_port() {
        assert_eq!(
            known_hosts_lookup_host("debian-headless-2", "2200").expect("lookup host"),
            "[debian-headless-2]:2200"
        );
        assert_eq!(
            known_hosts_lookup_host("debian-headless-2", "22").expect("lookup host"),
            "debian-headless-2"
        );
    }

    #[test]
    fn resolved_target_address_prefers_ssh_hostname() {
        let resolved = "\
hostname 192.168.64.22
port 22
";
        assert_eq!(
            resolved_target_address_from_ssh_g("debian@debian-headless-1", resolved),
            "192.168.64.22"
        );
    }

    #[test]
    fn resolved_target_address_falls_back_to_raw_target_host() {
        let resolved = "\
port 22
";
        assert_eq!(
            resolved_target_address_from_ssh_g("debian@debian-headless-1", resolved),
            "debian-headless-1"
        );
    }
}
