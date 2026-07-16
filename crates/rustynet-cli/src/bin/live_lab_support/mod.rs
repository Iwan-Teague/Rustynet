#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use nix::unistd::Uid;
use serde_json::Value;

/// Track B dispatcher fabric — the target platform that the
/// orchestrator picked for the live-lab stage. Bin-level entrypoints
/// re-export this type and gate their `run()` body on it so a
/// non-Linux invocation surfaces an honest "not yet enabled" message
/// instead of silently running Linux-specific assertions (systemd /
/// nftables / iproute2) against a macOS or Windows host. Mirrors the
/// shape of `live_linux_anchor_test::AnchorPlatform` and the Phase 1
/// `ExitHandoffPlatform`. The duplicate definition in
/// `live_lab_bin_support` exists because the two helper modules are
/// not unified (1476 vs 1285 lines on this branch); future cleanup
/// can collapse them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveLabPlatform {
    Linux,
    MacOs,
    Windows,
}

impl LiveLabPlatform {
    pub fn as_str(self) -> &'static str {
        match self {
            LiveLabPlatform::Linux => "linux",
            LiveLabPlatform::MacOs => "macos",
            LiveLabPlatform::Windows => "windows",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "linux" => Ok(LiveLabPlatform::Linux),
            "macos" | "darwin" => Ok(LiveLabPlatform::MacOs),
            "windows" => Ok(LiveLabPlatform::Windows),
            other => Err(format!(
                "unsupported --platform value {other:?}; expected linux|macos|windows"
            )),
        }
    }
}

/// Helper for bin entrypoints: returns Err with an honest
/// "Phase N pending" message when the orchestrator picked a non-
/// Linux target before the per-platform validator landed.
pub fn enforce_linux_only_until_validator_lands(
    platform: LiveLabPlatform,
    stage: &str,
    phase_note: &str,
) -> Result<(), String> {
    match platform {
        LiveLabPlatform::Linux => Ok(()),
        LiveLabPlatform::MacOs => Err(format!(
            "macOS {stage} live execution is not enabled yet; {phase_note}. \
             Use --platform linux for the existing Linux-host coverage."
        )),
        LiveLabPlatform::Windows => Err(format!(
            "Windows {stage} live execution is not enabled yet; {phase_note}. \
             Use --platform linux for the existing Linux-host coverage."
        )),
    }
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Absolute path to the deployed `rustynet` binary on a managed guest
/// (identical on Linux and macOS).
///
/// Never invoke the binary by bare name in a remote command: `sudo` does not
/// inherit the caller's PATH, it uses `secure_path` from `/etc/sudoers`, and
/// the RHEL family ships `secure_path = /sbin:/bin:/usr/sbin:/usr/bin` --
/// which omits `/usr/local/bin`. A bare name therefore works on Debian and
/// Ubuntu and fails on Rocky/Fedora with `command not found` (status 127).
/// Mirrors `live_lab_bin_support::REMOTE_RUSTYNET_BIN`.
pub const REMOTE_RUSTYNET_BIN: &str = "/usr/local/bin/rustynet";

const PROCESS_POLL_INTERVAL_MILLIS: u64 = 100;
const UTM_EXEC_TIMEOUT_SECS: u64 = 120;
const UTM_FILE_TIMEOUT_SECS: u64 = 120;

#[derive(Debug, Clone)]
struct UtmTransport {
    utm_name: String,
    user: String,
    home: String,
}

fn target_home(target: &str) -> String {
    match LiveLabContext::target_user(target) {
        "root" => "/root".to_owned(),
        user => format!("/home/{user}"),
    }
}

fn env_var_nonempty(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
}

fn env_flag_truthy(value: Option<&str>) -> bool {
    matches!(
        value.map(|value| value.trim().to_ascii_lowercase()),
        Some(flag) if matches!(flag.as_str(), "1" | "true" | "yes" | "on")
    )
}

fn utm_transport_enabled() -> bool {
    if env_flag_truthy(env::var("LIVE_LAB_FORCE_SSH_TRANSPORT").ok().as_deref()) {
        return false;
    }
    env_flag_truthy(env::var("LIVE_LAB_ENABLE_UTM_TRANSPORT").ok().as_deref())
}

fn utm_transport_for_target(target: &str) -> Option<UtmTransport> {
    if !utm_transport_enabled() {
        return None;
    }
    for (target_key, utm_key) in [
        ("EXIT_TARGET", "EXIT_UTM_NAME"),
        ("CLIENT_TARGET", "CLIENT_UTM_NAME"),
        ("ENTRY_TARGET", "ENTRY_UTM_NAME"),
        ("AUX_TARGET", "AUX_UTM_NAME"),
        ("EXTRA_TARGET", "EXTRA_UTM_NAME"),
        ("FIFTH_CLIENT_TARGET", "FIFTH_CLIENT_UTM_NAME"),
    ] {
        let Some(mapped_target) = env_var_nonempty(target_key) else {
            continue;
        };
        if mapped_target != target {
            continue;
        }
        let Some(utm_name) = env_var_nonempty(utm_key) else {
            continue;
        };
        return Some(UtmTransport {
            utm_name,
            user: LiveLabContext::target_user(target).to_owned(),
            home: target_home(target),
        });
    }
    None
}

fn utmctl_path() -> PathBuf {
    env::var_os("LIVE_LAB_UTMCTL_PATH")
        .filter(|value| !value.is_empty())
        .map_or_else(
            || PathBuf::from("/Applications/UTM.app/Contents/MacOS/utmctl"),
            PathBuf::from,
        )
}

fn run_status_with_timeout(command: &mut Command, timeout: Duration) -> Result<ExitStatus, String> {
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            return Ok(status);
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
    }
}

fn run_output_with_timeout(command: &mut Command, timeout: Duration) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|err| format!("spawn failed: {err}"))?;
    let started_at = Instant::now();
    loop {
        if let Some(_status) = child
            .try_wait()
            .map_err(|err| format!("wait failed: {err}"))?
        {
            return child
                .wait_with_output()
                .map_err(|err| format!("wait_with_output failed: {err}"));
        }
        if started_at.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("timed out after {} seconds", timeout.as_secs()));
        }
        sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
    }
}

fn utm_guest_shell_command(transport: &UtmTransport, command: &str) -> String {
    let quoted_command = shell_single_quote(command);
    if transport.user == "root" {
        format!("exec /bin/bash -lc {quoted_command}")
    } else {
        let quoted_user = shell_single_quote(&transport.user);
        let quoted_home = shell_single_quote(&transport.home);
        format!(
            "exec runuser -u {quoted_user} -- env HOME={quoted_home} USER={quoted_user} LOGNAME={quoted_user} PATH=/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin /bin/bash -lc {quoted_command}"
        )
    }
}

fn utm_exec_status(transport: &UtmTransport, command: &str) -> Result<ExitStatus, String> {
    let utmctl = utmctl_path();
    if !utmctl.is_file() {
        return Err(format!(
            "missing executable UTM control tool: {}",
            utmctl.display()
        ));
    }
    let mut utm = Command::new(&utmctl);
    utm.args([
        "exec",
        transport.utm_name.as_str(),
        "--cmd",
        "/bin/bash",
        "-lc",
    ]);
    utm.arg(utm_guest_shell_command(transport, command));
    run_status_with_timeout(&mut utm, Duration::from_secs(UTM_EXEC_TIMEOUT_SECS)).map_err(|err| {
        format!(
            "failed to run utm exec against {}: {err}",
            transport.utm_name
        )
    })
}

fn utm_exec_output(transport: &UtmTransport, command: &str) -> Result<Output, String> {
    let utmctl = utmctl_path();
    if !utmctl.is_file() {
        return Err(format!(
            "missing executable UTM control tool: {}",
            utmctl.display()
        ));
    }
    let mut utm = Command::new(&utmctl);
    utm.args([
        "exec",
        transport.utm_name.as_str(),
        "--cmd",
        "/bin/bash",
        "-lc",
    ]);
    utm.arg(utm_guest_shell_command(transport, command));
    run_output_with_timeout(&mut utm, Duration::from_secs(UTM_EXEC_TIMEOUT_SECS)).map_err(|err| {
        format!(
            "failed to run utm exec against {}: {err}",
            transport.utm_name
        )
    })
}

fn utm_exec_root_status(transport: &UtmTransport, command: &str) -> Result<ExitStatus, String> {
    let root_transport = UtmTransport {
        utm_name: transport.utm_name.clone(),
        user: "root".to_owned(),
        home: "/root".to_owned(),
    };
    utm_exec_status(&root_transport, command)
}

fn utm_file_push(transport: &UtmTransport, src: &Path, dst: &str) -> Result<(), String> {
    let utmctl = utmctl_path();
    if !utmctl.is_file() {
        return Err(format!(
            "missing executable UTM control tool: {}",
            utmctl.display()
        ));
    }
    let stdin = fs::File::open(src)
        .map_err(|err| format!("failed to open {} for UTM push: {err}", src.display()))?;
    let mut utm = Command::new(&utmctl);
    utm.args(["file", "push", transport.utm_name.as_str(), dst]);
    utm.stdin(Stdio::from(stdin));
    let status = run_status_with_timeout(&mut utm, Duration::from_secs(UTM_FILE_TIMEOUT_SECS))
        .map_err(|err| {
            format!(
                "failed to push {} to {}:{}: {err}",
                src.display(),
                transport.utm_name,
                dst
            )
        })?;
    if !status.success() {
        return Err(format!(
            "push {} to {}:{} failed with status {}",
            src.display(),
            transport.utm_name,
            dst,
            status_code(status)
        ));
    }
    if transport.user != "root" {
        let chown_cmd = format!(
            "chown {}:{} {}",
            shell_single_quote(&transport.user),
            shell_single_quote(&transport.user),
            shell_single_quote(dst)
        );
        let status = utm_exec_root_status(transport, &chown_cmd)?;
        if !status.success() {
            return Err(format!(
                "UTM chown failed for {}:{} with status {}",
                transport.utm_name,
                dst,
                status_code(status)
            ));
        }
    }
    Ok(())
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

fn configure_owner_only_file_open_options(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        options.mode(0o600);
    }
}

fn set_path_mode(path: &Path, mode: u32) -> Result<(), String> {
    #[cfg(unix)]
    {
        let metadata = fs::metadata(path)
            .map_err(|err| format!("failed to stat {}: {err}", path.display()))?;
        let mut permissions = metadata.permissions();
        permissions.set_mode(mode);
        fs::set_permissions(path, permissions)
            .map_err(|err| format!("failed to secure {}: {err}", path.display()))?
    };
    #[cfg(not(unix))]
    {
        let _ = (path, mode);
    }
    Ok(())
}

pub fn write_secure_text(path: &Path, contents: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create {}: {err}", parent.display()))?;
    }
    let mut options = OpenOptions::new();
    configure_owner_only_file_open_options(options.create(true).truncate(true).write(true));
    let mut file = options
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
    let mut options = OpenOptions::new();
    configure_owner_only_file_open_options(options.create(true).truncate(true).write(true));
    let file = options
        .open(path)
        .map_err(|err| format!("failed to write {}: {err}", path.display()))?;
    serde_json::to_writer_pretty(file, value)
        .map_err(|err| format!("failed to serialize {}: {err}", path.display()))
}

pub fn ensure_dir_secure(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|err| format!("failed to create {}: {err}", path.display()))?;
    set_path_mode(path, 0o700)
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
    #[cfg(not(unix))]
    {
        let _ = policy;
        return Ok(());
    }
    #[cfg(unix)]
    {
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
}

pub fn shell_single_quote(value: &str) -> String {
    if value.is_empty() {
        return "''".to_owned();
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

/// Bounded transient-retry budget for the local-scp push path in
/// [`LiveLabContext::scp_to`]. Mirrors the bash orchestrator's
/// `live_lab_scp_to_via_ssh` (scripts/e2e/live_lab_common.sh), which retries
/// the scp three times on ssh connection-level (exit 255) failures before
/// giving up. A single dropped "scp: Connection closed" must not fail an
/// entire 45-minute live-lab stage.
const SCP_RETRY_ATTEMPTS: u32 = 3;
/// Seconds to sleep between transient scp retry attempts. Matches the bash
/// orchestrator's `sleep 2` between connection-level retries.
const SCP_RETRY_SLEEP_SECS: u64 = 2;

/// Classify an scp failure as transient (worth retrying) vs. likely-permanent
/// (fail fast). Retry when the ssh layer reported a connection-level error
/// (exit code 255) or the captured stderr names a recoverable network fault.
/// Permanent failures (permission denied, no such file, etc.) are NOT retried
/// so we don't burn the retry budget on errors that will never succeed.
/// Mirrors how `live_linux_lan_toggle_test` classifies transient ssh/scp
/// failures. `stderr_lower` must already be lowercased by the caller.
fn scp_failure_is_transient(exit_code: Option<i32>, stderr_lower: &str) -> bool {
    if exit_code == Some(255) {
        return true;
    }
    const TRANSIENT_MARKERS: [&str; 7] = [
        "connection closed",
        "connection reset",
        "connection timed out",
        "timed out",
        "broken pipe",
        "lost connection",
        "connection refused",
    ];
    TRANSIENT_MARKERS
        .iter()
        .any(|marker| stderr_lower.contains(marker))
}

impl LiveLabContext {
    pub fn new(prefix: &str, ssh_identity_file: &Path) -> Result<Self, String> {
        Self::new_with_pinned_known_hosts(prefix, ssh_identity_file, None)
    }

    pub fn new_with_pinned_known_hosts(
        prefix: &str,
        ssh_identity_file: &Path,
        pinned_known_hosts_file: Option<&Path>,
    ) -> Result<Self, String> {
        require_local_file_mode(ssh_identity_file, "owner-only", "ssh identity file")?;
        let pinned_known_hosts_file = pinned_known_hosts_file.map_or_else(
            || {
                env::var_os("LIVE_LAB_PINNED_KNOWN_HOSTS_FILE").map_or_else(
                    || {
                        env::var_os("HOME")
                            .map_or_else(|| PathBuf::from("/root"), PathBuf::from)
                            .join(".ssh/known_hosts")
                    },
                    PathBuf::from,
                )
            },
            Path::to_path_buf,
        );
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
        set_path_mode(&known_hosts_file, 0o600)?;

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
        target.split_once('@').map_or(target, |(user, _)| user)
    }

    pub fn target_address(target: &str) -> &str {
        let addr = target.split_once('@').map_or(target, |(_, addr)| addr);
        strip_host_port(addr)
    }

    /// The SSH/scp destination for `target` with any `:port` suffix removed
    /// from the host. The port travels separately as an `-p`/`-P` flag (see
    /// [`target_port`]); leaving it glued to the host makes OpenSSH treat
    /// `192.168.64.4:22` as a literal hostname and fail to resolve it.
    fn ssh_destination(target: &str) -> String {
        match target.split_once('@') {
            Some((user, _)) => format!("{user}@{}", Self::target_address(target)),
            None => Self::target_address(target).to_owned(),
        }
    }

    pub fn resolved_target_address(target: &str) -> Result<String, String> {
        if utm_transport_for_target(target).is_some() {
            return Ok(Self::target_address(target).to_owned());
        }
        let destination = Self::ssh_destination(target);
        let resolved = Command::new("ssh")
            .args(["-G", destination.as_str()])
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
            "/root/Rustynet".to_owned()
        } else {
            format!("/home/{}/Rustynet", Self::target_user(target))
        }
    }

    fn require_pinned_host_entry(&self, target: &str) -> Result<(), String> {
        if utm_transport_for_target(target).is_some() {
            return Ok(());
        }
        let destination = Self::ssh_destination(target);
        let resolved = Command::new("ssh")
            .args(["-G", destination.as_str()])
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
            "ServerAliveInterval=60",
            "-o",
            "ServerAliveCountMax=10",
            "-o",
            "IdentitiesOnly=yes",
            "-i",
        ]);
        command.arg(&self.ssh_identity_file);
        if let Some(port) = target_port(target) {
            command.arg("-p").arg(port.to_string());
        }
        command.arg("--");
        command.arg(Self::ssh_destination(target));
        command
    }

    fn run_ssh(&self, target: &str, args: &[&str], allow_failure: bool) -> Result<Output, String> {
        if let Some(transport) = utm_transport_for_target(target) {
            let remote_command = render_remote_argv(args)?;
            let output = utm_exec_output(&transport, remote_command.as_str())?;
            if !allow_failure && !output.status.success() {
                return Err(format!(
                    "remote command failed on {target}: {}",
                    render_failure_output(&output)
                ));
            }
            return Ok(output);
        }
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
        if let Some(transport) = utm_transport_for_target(target) {
            return utm_file_push(&transport, src, dst);
        }
        self.require_pinned_host_entry(target)?;
        // Bounded transient-retry for the local-scp push, matching the bash
        // orchestrator's `live_lab_scp_to_via_ssh`: a single dropped
        // "scp: Connection closed" must not fail a 45-minute stage. Re-copying
        // on retry is safe because scp overwrites the destination atomically
        // and every caller pushes a fixed local file to a fixed remote path,
        // so the operation is idempotent.
        let mut last_stderr = String::new();
        for attempt in 1..=SCP_RETRY_ATTEMPTS {
            let mut command = Command::new("scp");
            command
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
                .args([
                    "-o",
                    "ConnectTimeout=15",
                    "-o",
                    "ServerAliveInterval=60",
                    "-o",
                    "ServerAliveCountMax=10",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-i",
                ])
                .arg(&self.ssh_identity_file);
            // scp uses `-P` (capital) for the port; the host must be bare or
            // scp reads `192.168.64.4:22:/path` as host `192.168.64.4` writing
            // to a bogus `22:/path`.
            if let Some(port) = target_port(target) {
                command.arg("-P").arg(port.to_string());
            }
            let output = command
                .arg("--")
                .arg(src)
                .arg(format!("{}:{dst}", Self::ssh_destination(target)))
                .output()
                .map_err(|err| format!("failed to run scp to {target}: {err}"))?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            // Fail fast on likely-permanent errors (permission denied, no such
            // file, ...) so we don't waste the retry budget. Only ssh
            // connection-level (exit 255) or recognized network faults retry.
            if !scp_failure_is_transient(output.status.code(), &stderr.to_lowercase()) {
                return Err(format!("scp to {target} failed: {stderr}"));
            }
            last_stderr = stderr;
            if attempt < SCP_RETRY_ATTEMPTS {
                sleep(Duration::from_secs(SCP_RETRY_SLEEP_SECS));
            }
        }
        Err(format!(
            "scp to {target} failed after {SCP_RETRY_ATTEMPTS} attempts: {last_stderr}"
        ))
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
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_owned()))
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
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_owned()))
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
        Err(last_err.unwrap_or_else(|| "retry exhausted".to_owned()))
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
        let hostname = hostname.trim().to_owned();
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
        self.verified_hosts.insert(target.to_owned());
        Ok(())
    }

    pub fn collect_pubkey_hex(&mut self, target: &str) -> Result<String, String> {
        self.push_sudo_password(target)?;
        // The WireGuard public key lives under the platform state root:
        // /var/lib/rustynet on Linux, /usr/local/var/rustynet on macOS. Try the
        // Linux path first, then the macOS path, so this helper works for
        // mixed-OS managed peers (e.g. a macOS node in a Linux-signer topology)
        // without threading per-host platform through every caller. Each
        // attempt is argv-only (no shell construction).
        let pub_b64 =
            match self.capture_root(target, &["cat", "/var/lib/rustynet/keys/wireguard.pub"]) {
                Ok(value) => value,
                Err(linux_err) => self
                    .capture_root(
                        target,
                        &["cat", "/usr/local/var/rustynet/keys/wireguard.pub"],
                    )
                    .map_err(|macos_err| {
                        format!(
                            "wireguard.pub not found at Linux (/var/lib/rustynet) or macOS \
                         (/usr/local/var/rustynet) state root: {linux_err}; {macos_err}"
                        )
                    })?,
            };
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
        stderr.to_owned()
    } else if !stdout.is_empty() {
        format!("stdout: {stdout}")
    } else {
        "remote command exited non-zero without output".to_owned()
    }
}

fn render_remote_argv(args: &[&str]) -> Result<String, String> {
    if args.is_empty() {
        return Err("refusing to run empty remote command".to_owned());
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
    let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
    for salt in 0u32..1000 {
        let candidate = base.join(format!("{prefix}.{pid}.{timestamp}.{counter}.{salt}"));
        match fs::create_dir(&candidate) {
            Ok(()) => {
                set_path_mode(&candidate, 0o700)?;
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
        return Err("invalid base64 length".to_owned());
    }
    let mut output = Vec::with_capacity((compact.len() / 4) * 3);
    let mut index = 0usize;
    while index < compact.len() {
        let c0 = compact[index];
        let c1 = compact[index + 1];
        let c2 = compact[index + 2];
        let c3 = compact[index + 3];
        if c0 == b'=' || c1 == b'=' {
            return Err("invalid base64 padding".to_owned());
        }
        let v0 = table[c0 as usize];
        let v1 = table[c1 as usize];
        if v0 == 0xFF || v1 == 0xFF {
            return Err("invalid base64 character".to_owned());
        }
        output.push((v0 << 2) | (v1 >> 4));

        let pad2 = c2 == b'=';
        let pad3 = c3 == b'=';
        if pad2 {
            if !pad3 {
                return Err("invalid base64 padding".to_owned());
            }
        } else {
            let v2 = table[c2 as usize];
            if v2 == 0xFF {
                return Err("invalid base64 character".to_owned());
            }
            output.push((v1 << 4) | (v2 >> 2));
            if !pad3 {
                let v3 = table[c3 as usize];
                if v3 == 0xFF {
                    return Err("invalid base64 character".to_owned());
                }
                output.push((v2 << 6) | v3);
            }
        }

        if (pad2 || pad3) && index + 4 != compact.len() {
            return Err("invalid base64 padding".to_owned());
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
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
        return Err("known_hosts lookup host must not be empty".to_owned());
    }
    if port.is_empty() || port == "22" {
        Ok(host.to_owned())
    } else {
        Ok(format!("[{host}]:{port}"))
    }
}

/// Strip a trailing `:port` suffix and unwrap a bracketed IPv6 literal from a
/// bare `host` / `host:port` fragment, yielding the host OpenSSH should
/// resolve. Mirrors the orchestrator's `strip_ssh_host`. Unbracketed IPv6
/// literals (which carry multiple colons) are left intact.
fn strip_host_port(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[')
        && let Some(end) = rest.find(']')
    {
        return &rest[..end];
    }
    match addr.rsplit_once(':') {
        Some((host, port))
            if !host.is_empty()
                && !host.contains(':')
                && !port.is_empty()
                && port.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            host
        }
        _ => addr,
    }
}

/// Explicit TCP port carried by a `[user@]host:port` target, if any. `None`
/// means "no explicit suffix; use the SSH default". Handles bracketed IPv6
/// (`[::1]:2222`).
fn target_port(target: &str) -> Option<u16> {
    let addr = target.split_once('@').map_or(target, |(_, addr)| addr);
    let port_str = if let Some(rest) = addr.strip_prefix('[') {
        rest.split_once(']')
            .and_then(|(_, tail)| tail.strip_prefix(':'))?
    } else {
        let (host, port) = addr.rsplit_once(':')?;
        if host.is_empty() || host.contains(':') {
            return None;
        }
        port
    };
    if port_str.is_empty() || !port_str.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    port_str.parse().ok()
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
        .to_owned()
}

fn resolved_known_hosts_candidates(target: &str, resolved: &str) -> Result<Vec<String>, String> {
    let raw_host = LiveLabContext::target_address(target);
    // An explicit `:port` on the target is authoritative for the known_hosts
    // key so it stays consistent with the port the ssh/scp connect uses; fall
    // back to ssh -G's resolved port, then the default.
    let explicit_port = target_port(target).map(|port| port.to_string());
    let port = explicit_port
        .as_deref()
        .or_else(|| ssh_g_value(resolved, "port"))
        .unwrap_or("22");
    let mut lookup_candidates = Vec::new();

    if let Some(hostkeyalias) = ssh_g_value(resolved, "hostkeyalias")
        && hostkeyalias != "none"
    {
        let lookup_host = known_hosts_lookup_host(hostkeyalias, port)?;
        lookup_candidates.push(lookup_host);
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
    if let Some(transport) = utm_transport_for_target(target) {
        let output = utm_exec_output(&transport, shell_command)?;
        if output.status.success() {
            return Ok(output);
        }
        return Err(format!(
            "remote shell command failed on {target}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
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
        LiveLabContext, LiveLabPlatform, enforce_linux_only_until_validator_lands, env_flag_truthy,
        known_hosts_lookup_host, resolved_known_hosts_candidates,
        resolved_target_address_from_ssh_g, scp_failure_is_transient, strip_host_port, target_port,
    };

    #[test]
    fn scp_failure_is_transient_retries_connection_level_and_network_faults() {
        // ssh connection-level error (exit 255) is always transient.
        assert!(scp_failure_is_transient(Some(255), ""));
        // The dropped-connection signature that motivated bash-parity retry.
        assert!(scp_failure_is_transient(Some(1), "scp: connection closed"));
        // Other recognized recoverable network faults.
        assert!(scp_failure_is_transient(
            Some(1),
            "ssh: connect to host: connection reset by peer"
        ));
        assert!(scp_failure_is_transient(
            Some(1),
            "client_loop: send disconnect: broken pipe"
        ));
        // Likely-permanent failures must fail fast, never retry.
        assert!(!scp_failure_is_transient(
            Some(1),
            "scp: /etc/rustynet/bundle: permission denied"
        ));
        assert!(!scp_failure_is_transient(
            Some(1),
            "scp: open local \"/missing\": no such file or directory"
        ));
    }

    #[test]
    fn live_lab_platform_parser_accepts_canonical_strings() {
        assert_eq!(
            LiveLabPlatform::parse("linux").unwrap(),
            LiveLabPlatform::Linux
        );
        assert_eq!(
            LiveLabPlatform::parse("MacOS").unwrap(),
            LiveLabPlatform::MacOs
        );
        assert_eq!(
            LiveLabPlatform::parse("darwin").unwrap(),
            LiveLabPlatform::MacOs
        );
        assert_eq!(
            LiveLabPlatform::parse("WINDOWS").unwrap(),
            LiveLabPlatform::Windows
        );
    }

    #[test]
    fn live_lab_platform_parser_rejects_garbage() {
        let err = LiveLabPlatform::parse("freebsd").expect_err("garbage rejected");
        assert!(err.contains("unsupported --platform"));
    }

    #[test]
    fn live_lab_platform_as_str_matches_canonical_form() {
        assert_eq!(LiveLabPlatform::Linux.as_str(), "linux");
        assert_eq!(LiveLabPlatform::MacOs.as_str(), "macos");
        assert_eq!(LiveLabPlatform::Windows.as_str(), "windows");
    }

    #[test]
    fn enforce_linux_only_gate_lets_linux_pass() {
        enforce_linux_only_until_validator_lands(LiveLabPlatform::Linux, "demo", "Phase Z")
            .unwrap();
    }

    #[test]
    fn enforce_linux_only_gate_fails_closed_for_macos_and_windows() {
        for (platform, name) in [
            (LiveLabPlatform::MacOs, "macOS"),
            (LiveLabPlatform::Windows, "Windows"),
        ] {
            let err = enforce_linux_only_until_validator_lands(platform, "demo", "Phase Z")
                .expect_err("non-linux must fail closed");
            assert!(err.contains(name), "error must name the platform: {err}");
            assert!(
                err.contains("Phase Z"),
                "error must include the phase note: {err}"
            );
        }
    }

    #[test]
    fn env_flag_truthy_accepts_expected_values() {
        for value in ["1", "true", "TRUE", "yes", "on"] {
            assert!(env_flag_truthy(Some(value)));
        }
        for value in [None, Some(""), Some("0"), Some("false"), Some("off")] {
            assert!(!env_flag_truthy(value));
        }
    }

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
                "[rusty-lab]:2222".to_owned(),
                "[192.168.18.65]:2222".to_owned(),
                "[debian-headless-2]:2222".to_owned()
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
        assert_eq!(candidates, vec!["debian-headless-2".to_owned()]);
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

    #[test]
    fn target_address_strips_default_port_suffix() {
        // Regression: the SshConnectionParams-derived target carries a `:22`
        // suffix (`format!("{host}:{port}")`). The known_hosts candidate and
        // the ssh/scp destination must both see the bare host, or OpenSSH
        // treats `192.168.64.4:22` as a literal (unresolvable) hostname.
        assert_eq!(
            LiveLabContext::target_address("debian@192.168.64.4:22"),
            "192.168.64.4"
        );
        assert_eq!(
            LiveLabContext::target_address("debian@192.168.64.4:2222"),
            "192.168.64.4"
        );
        assert_eq!(
            LiveLabContext::target_address("debian@192.168.64.4"),
            "192.168.64.4"
        );
        // Bracketed IPv6 literals unwrap; bare IPv6 (multi-colon) is untouched.
        assert_eq!(
            LiveLabContext::target_address("admin@[fe80::1]:2222"),
            "fe80::1"
        );
        assert_eq!(LiveLabContext::target_address("root@fe80::1"), "fe80::1");
    }

    #[test]
    fn ssh_destination_rebuilds_user_and_bare_host() {
        assert_eq!(
            LiveLabContext::ssh_destination("debian@192.168.64.4:22"),
            "debian@192.168.64.4"
        );
        assert_eq!(
            LiveLabContext::ssh_destination("192.168.64.4:22"),
            "192.168.64.4"
        );
    }

    #[test]
    fn target_port_extracts_explicit_suffix_only() {
        assert_eq!(target_port("debian@192.168.64.4:22"), Some(22));
        assert_eq!(target_port("debian@192.168.64.4:2222"), Some(2222));
        assert_eq!(target_port("admin@[fe80::1]:2200"), Some(2200));
        // No suffix -> use the SSH default (None).
        assert_eq!(target_port("debian@192.168.64.4"), None);
        assert_eq!(target_port("root@fe80::1"), None);
        assert_eq!(target_port("admin@[fe80::1]"), None);
    }

    #[test]
    fn strip_host_port_matches_orchestrator_semantics() {
        assert_eq!(strip_host_port("192.168.64.10"), "192.168.64.10");
        assert_eq!(strip_host_port("192.168.64.10:2222"), "192.168.64.10");
        assert_eq!(strip_host_port("[fe80::1]:2222"), "fe80::1");
        assert_eq!(strip_host_port("fe80::1"), "fe80::1");
    }

    #[test]
    fn resolved_known_hosts_candidates_strips_port_suffix_for_lookup() {
        // ssh -G is fed the bare host, so its hostname/port fields are clean.
        let resolved = "\
hostname 192.168.64.4
port 22
";
        let candidates = resolved_known_hosts_candidates("debian@192.168.64.4:22", resolved)
            .expect("candidates");
        assert_eq!(candidates, vec!["192.168.64.4".to_owned()]);
    }

    #[test]
    fn resolved_known_hosts_candidates_prefers_explicit_nondefault_port() {
        let resolved = "\
hostname 192.168.64.4
port 22
";
        let candidates = resolved_known_hosts_candidates("debian@192.168.64.4:2222", resolved)
            .expect("candidates");
        assert_eq!(candidates, vec!["[192.168.64.4]:2222".to_owned()]);
    }
}
