#![forbid(unsafe_code)]
#![allow(dead_code)]
// Track B Phase 28 — `capture_root` (and the `run_root`/`retry_root`
// pair built on top of it) are POSIX-only. Phase 28 marks
// `capture_root` `#[deprecated]` to drive consumer migration to the
// new [`RemoteShellHost`] trait, but this module is the transition
// shim — it still calls the deprecated helper internally so existing
// substages keep running until Phase 29 rewrites them. Allow the
// deprecation lint here so the shim does not break `-D warnings`.
#![allow(deprecated)]

#[path = "../../env_file.rs"]
#[allow(dead_code)]
mod env_file;

mod remote_shell;

// Each bin compiles `mod live_lab_bin_support` separately, so a
// `pub use` of the trait surface is flagged "unused" in every bin
// that hasn't migrated to the trait yet. Phase 29 starts the
// migration; until then the allow keeps `-D warnings` green without
// hiding the actual public API.
//
// Production surface — substages may construct the real per-OS
// backends or dispatch via `new_remote_shell_host`. The mock backend
// is intentionally NOT exported here; see `testing` below.
#[allow(unused_imports)]
pub use remote_shell::{
    LinuxShellHost, MacosShellHost, RemoteExitStatus, RemoteShellError, RemoteShellHost,
    RemoteStat, WindowsShellHost, new_remote_shell_host,
};

/// Test-only surface for the live-lab support module. `MockShellHost`
/// is an in-process backend with no real transport — exposing it
/// alongside the production backends would let a substage accidentally
/// pass a mock where a real backend is required, defeating the
/// fail-closed cross-platform contract. Callers that need the mock
/// (the trait's own contract tests, future bin-level unit tests, etc.)
/// must reach for it explicitly via
/// `live_lab_bin_support::testing::MockShellHost`.
pub mod testing {
    #[allow(unused_imports)]
    pub use super::remote_shell::{MockRunInvocation, MockShellHost, MockTcpInvocation};
}

use std::env;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);
const PROCESS_POLL_INTERVAL_MILLIS: u64 = 100;
const UTM_EXEC_TIMEOUT_SECS: u64 = 120;
const UTM_FILE_TIMEOUT_SECS: u64 = 120;

/// Absolute path to the deployed `rustynet` binary on a Linux guest.
///
/// Every `sudo` invocation MUST name the binary by this path rather than
/// relying on `sudo -n rustynet` resolving through PATH. `sudo` does not
/// inherit the caller's PATH; it uses the `secure_path` from `/etc/sudoers`,
/// and the RHEL family ships
/// `Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin` — which omits
/// `/usr/local/bin`, where the lab installs `rustynet`. Debian and Ubuntu
/// include `/usr/local/bin` in `secure_path`, so a bare `sudo -n rustynet`
/// works there and fails ONLY on Rocky/Fedora with `sudo: rustynet: command
/// not found`. That asymmetry hides the bug on a Debian-only topology and
/// surfaces it as an opaque stage failure the moment a RHEL-family guest takes
/// a role. The orchestrator's own membership adapter already hardcodes this
/// path for the same reason (linux_membership.rs).
pub const REMOTE_RUSTYNET_BIN: &str = "/usr/local/bin/rustynet";

/// Track B dispatcher fabric — the target platform that the
/// orchestrator picked for the live-lab stage. Bin-level entrypoints
/// re-export this type and gate their `run()` body on it so a
/// non-Linux invocation surfaces an honest "not yet enabled" message
/// instead of silently running Linux-specific assertions (systemd /
/// nftables / iproute2) against a macOS or Windows host. Mirrors the
/// shape of `live_linux_anchor_test::AnchorPlatform` and the Phase 1
/// `ExitHandoffPlatform`.
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
/// Linux target before the per-platform validator landed. The
/// orchestrator's dispatcher fabric already routes by platform; this
/// is the bin-side gate that keeps Linux assertions from running on
/// the wrong OS during the transitional period.
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

#[derive(Clone, Debug)]
struct UtmTransport {
    utm_name: String,
    user: String,
    home: String,
}

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
    target.split_once('@').map_or(target, |(user, _)| user)
}

/// Strip a trailing `:port` suffix and unwrap a bracketed IPv6 literal from a
/// bare `host` / `host:port` fragment. Mirrors `live_lab_support`'s helper of
/// the same name. Unbracketed IPv6 literals (multiple colons) are left intact.
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

/// The bare host for `target`, with both `user@` and any `:port` suffix
/// removed. The port travels separately (an `-p`/`-P` flag, or `ssh -G`'s
/// resolved `port` for known_hosts lookups); leaving it glued to the host makes
/// OpenSSH treat `192.168.64.4:22` as a literal hostname and makes
/// `ssh-keygen -F` miss the (bare) known_hosts entry.
pub fn target_address(target: &str) -> &str {
    let addr = target.split_once('@').map_or(target, |(_, host)| host);
    strip_host_port(addr)
}

/// Explicit TCP port carried by a `[user@]host:port` target, if any. `None`
/// means "no explicit suffix; use the SSH default". Handles bracketed IPv6
/// literals. Mirrors `live_lab_support::target_port`.
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

/// The SSH/scp destination for `target` with any `:port` suffix removed from
/// the host. The port travels separately as an `-p` (ssh) / `-P` (scp) flag —
/// see [`target_port`]. Leaving it glued to the host makes OpenSSH treat
/// `192.168.64.4:22` as a literal hostname ("could not resolve hostname").
/// Mirrors `live_lab_support`'s `ssh_destination`.
fn ssh_destination(target: &str) -> String {
    match target.split_once('@') {
        Some((user, _)) => format!("{user}@{}", target_address(target)),
        None => target_address(target).to_owned(),
    }
}

/// `ssh -G <destination>` for `target`, with the port passed as `-p` rather
/// than glued to the host. Handing OpenSSH `host:22` makes it echo back
/// `hostname host:22`, which then poisons every value derived from the resolved
/// config (the target address and the known_hosts lookup candidates).
fn ssh_resolve_command(target: &str) -> Command {
    let mut command = Command::new("ssh");
    command.arg("-G");
    if let Some(port) = target_port(target) {
        command.arg("-p").arg(port.to_string());
    }
    command.arg(ssh_destination(target));
    command
}

fn target_home(target: &str) -> String {
    match target_user(target) {
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
            user: target_user(target).to_owned(),
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
        thread::sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
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
        thread::sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
    }
}

fn utm_guest_shell_command(transport: &UtmTransport, command: &str) -> String {
    let quoted_command = shell_quote(command);
    if transport.user == "root" {
        format!("exec /bin/bash -lc {quoted_command}")
    } else {
        let quoted_user = shell_quote(&transport.user);
        let quoted_home = shell_quote(&transport.home);
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
    let stdin = File::open(src)
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
            shell_quote(&transport.user),
            shell_quote(&transport.user),
            shell_quote(dst)
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

fn utm_file_pull(transport: &UtmTransport, src: &str, dst: &Path) -> Result<(), String> {
    let utmctl = utmctl_path();
    if !utmctl.is_file() {
        return Err(format!(
            "missing executable UTM control tool: {}",
            utmctl.display()
        ));
    }
    let mut utm = Command::new(&utmctl);
    utm.args(["file", "pull", transport.utm_name.as_str(), src]);
    let output = run_output_with_timeout(&mut utm, Duration::from_secs(UTM_FILE_TIMEOUT_SECS))
        .map_err(|err| format!("failed to pull {}:{}: {err}", transport.utm_name, src))?;
    if !output.status.success() {
        return Err(format!(
            "pull {}:{} failed with status {}",
            transport.utm_name,
            src,
            status_code(output.status)
        ));
    }
    fs::write(dst, output.stdout).map_err(|err| format!("failed to write {}: {err}", dst.display()))
}

fn resolved_target_address_from_ssh_g(target: &str, resolved: &str) -> String {
    ssh_g_value(resolved, "hostname")
        .filter(|hostname| !hostname.is_empty() && *hostname != "none")
        .unwrap_or_else(|| target_address(target))
        .to_owned()
}

pub fn resolved_target_address(target: &str) -> Result<String, String> {
    let resolved = ssh_resolve_command(target)
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
    match target_user(target) {
        "root" => "/root/Rustynet".to_owned(),
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
        return Err("env value contains newline or NUL characters".to_owned());
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
        return Err("pinned known_hosts file path is required".to_owned());
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
        .ok_or_else(|| "HOME is not set".to_owned())?;
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

fn ssh_g_value<'a>(resolved: &'a str, key: &str) -> Option<&'a str> {
    resolved.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        match (fields.next(), fields.next()) {
            (Some(found_key), Some(value)) if found_key == key => Some(value),
            _ => None,
        }
    })
}

fn resolved_known_hosts_candidates(target: &str, resolved: &str) -> Result<Vec<String>, String> {
    let raw_host = target_address(target);
    let port = ssh_g_value(resolved, "port").unwrap_or("22");
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

pub fn require_pinned_host_entry(pinned_known_hosts: &Path, target: &str) -> Result<(), String> {
    if utm_transport_for_target(target).is_some() {
        return Ok(());
    }
    let resolved = ssh_resolve_command(target)
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
        let status = Command::new("ssh-keygen")
            .args(["-F", lookup_host, "-f"])
            .arg(pinned_known_hosts)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|err| format!("failed to run ssh-keygen -F for {lookup_host}: {err}"))?;
        if status.success() {
            return Ok(());
        }
    }

    Err(format!(
        "pinned known_hosts file lacks host key for {target}; checked {} in {}",
        lookup_candidates.join(", "),
        pinned_known_hosts.display()
    ))
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
        "UpdateHostKeys=no",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts.display()),
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
    command.arg(identity);
    if let Some(port) = target_port(target) {
        command.arg("-p").arg(port.to_string());
    }
    command.arg("--");
    command.arg(ssh_destination(target));
    command
}

fn scp_base_command(identity: &Path, known_hosts: &Path, target: &str) -> Command {
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
        "UpdateHostKeys=no",
        "-o",
        &format!("UserKnownHostsFile={}", known_hosts.display()),
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
    command.arg(identity);
    if let Some(port) = target_port(target) {
        // scp spells the port `-P`, unlike ssh's `-p`. It must precede the `--`
        // end-of-options marker, or scp parses it as a local source path
        // (`stat local "-P": No such file or directory`).
        command.arg("-P").arg(port.to_string());
    }
    command.arg("--");
    command
}

pub fn ssh_status(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    command: &str,
) -> Result<ExitStatus, String> {
    if let Some(transport) = utm_transport_for_target(target) {
        return utm_exec_status(&transport, command);
    }
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
    if let Some(transport) = utm_transport_for_target(target) {
        let output = utm_exec_output(&transport, command)?;
        if !output.status.success() {
            return Err(format!(
                "UTM command failed against {target} with status {}",
                status_code(output.status)
            ));
        }
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
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
    if let Some(transport) = utm_transport_for_target(target) {
        return utm_file_push(&transport, src, dst);
    }
    require_pinned_host_entry(known_hosts, target)?;
    let mut scp = scp_base_command(identity, known_hosts, target);
    scp.arg(src);
    scp.arg(format!("{}:{dst}", ssh_destination(target)));
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
    if let Some(transport) = utm_transport_for_target(target) {
        return utm_file_pull(&transport, src, dst);
    }
    require_pinned_host_entry(known_hosts, target)?;
    let mut scp = scp_base_command(identity, known_hosts, target);
    scp.arg(format!("{}:{src}", ssh_destination(target)));
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
    if let Some(transport) = utm_transport_for_target(target) {
        let output = utm_exec_output(&transport, command)?;
        if !output.status.success() {
            return Err(format!(
                "UTM command failed against {target} with status {}",
                status_code(output.status)
            ));
        }
        return Ok(String::from_utf8_lossy(&output.stdout).to_string());
    }
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

/// Minimal passwordless-sudo preflight WITHOUT the Linux-PAM
/// hostname-in-/etc/hosts check. macOS does not maintain hostnames in
/// /etc/hosts (HostName lives in scutil), so `verify_sudo` rejects
/// healthy mac hosts spuriously. Use this from macOS live-lab paths.
pub fn verify_passwordless_sudo(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<(), String> {
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

/// Windows admin preflight: probes the remote PowerShell session to
/// confirm the SSH user is in the BUILTIN\Administrators group. Live
/// lab Windows hosts run OpenSSH server as the user; without admin
/// rights, NetNat/SCM commands return access-denied opaquely.
pub fn verify_windows_admin(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
) -> Result<(), String> {
    let probe = "powershell -NoProfile -Command \"if (([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) { 'admin' } else { 'not_admin'; exit 1 }\"";
    let output = capture_remote_stdout(identity, known_hosts, target, probe)?;
    if output.trim().eq_ignore_ascii_case("admin") {
        Ok(())
    } else {
        Err(format!(
            "Windows live-lab target {target} SSH session is not in BUILTIN\\Administrators; NetNat + SCM commands will fail"
        ))
    }
}

/// POSIX-only sudo-wrapped capture. Track B Phase 28 introduced the
/// [`RemoteShellHost`] trait as the cross-platform replacement;
/// Phase 29 rewrites the in-tree call sites. This shim stays
/// functional during the transition so existing Linux/macOS substages
/// keep working — the deprecation marker is the audit signal that
/// new code MUST use [`RemoteShellHost::run_argv`] instead.
#[deprecated(
    since = "0.1.0",
    note = "POSIX-only; use RemoteShellHost::run_argv via the Phase 28 trait (Phase 29 rewrites in-tree call sites)"
)]
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

/// Cross-platform daemon-status capture. Track B Phase 13 — the
/// canonical `status` helper above wraps the command in `sudo -n
/// sh -lc` via capture_root, which only works on POSIX shells.
/// macOS works via the same POSIX wrap (sudo is available) but the
/// daemon socket path is different from Linux. Windows has no sudo
/// and an Administrator OpenSSH session by default; run PowerShell
/// against `rustynet.exe status` instead.
///
/// Returns the canonical single-line `node_id=... node_role=...
/// ... path_live_proven=... path_latest_live_handshake_unix=...`
/// status output emitted by `crates/rustynetd/src/daemon.rs` so the
/// caller can parse handshake freshness, live peer count, and
/// proven-path state without knowing the platform.
pub fn capture_daemon_status_for_platform(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    platform_label: &str,
) -> Result<String, String> {
    let trimmed = platform_label.trim().to_ascii_lowercase();
    match trimmed.as_str() {
        "linux" => capture_root(
            identity,
            known_hosts,
            target,
            "env RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock rustynet status",
        ),
        "macos" | "darwin" => capture_root(
            identity,
            known_hosts,
            target,
            // Phase 13 reviewer BLOCKER fix — the macOS daemon
            // listens on /private/var/run/rustynet/rustynetd.sock
            // (see crates/rustynetd/src/daemon.rs ~line 158 +
            // vm_lab/orchestrator/adapter/macos_install.rs). The
            // /usr/local/var/rustynet path is the macOS STATE root,
            // not the IPC socket dir — first Phase 13 commit had
            // that wrong and every macOS status capture would have
            // failed to connect.
            "env RUSTYNET_DAEMON_SOCKET=/private/var/run/rustynet/rustynetd.sock rustynet status",
        ),
        "windows" | "win32" => {
            // Use `if (-not (Get-Command ...))` so a missing
            // rustynet.exe surfaces an explicit diagnostic rather
            // than the bare PSCommandNotFoundException. Pipe the
            // output through `Out-String -Width 32767` so PowerShell
            // does NOT wrap the very long single-line status output
            // at the host's terminal width — the parser depends on
            // a single `key=value ...` line and a wrapped line
            // would split keys across lines and be silently dropped.
            let command = "powershell -NoProfile -Command \"if (-not (Get-Command rustynet.exe -ErrorAction SilentlyContinue)) { Write-Error 'rustynet.exe not on PATH'; exit 1 }; rustynet.exe status | Out-String -Width 32767\"";
            capture_remote_stdout(identity, known_hosts, target, command)
        }
        other => Err(format!(
            "capture_daemon_status_for_platform: unsupported platform label {other:?}"
        )),
    }
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
        "sudo -n {REMOTE_RUSTYNET_BIN} ops e2e-issue-assignment-bundles-from-env --env-file {}",
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
        "sudo -n {REMOTE_RUSTYNET_BIN} ops e2e-issue-traversal-bundles-from-env --env-file {}",
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

/// Daemon IPC socket path for the given platform. The macOS daemon
/// listens under `/private/var/run` (there is no `/run` on macOS),
/// while Linux uses `/run/rustynet`.
pub fn daemon_socket_path_for_platform(platform: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "macos" | "darwin" => "/private/var/run/rustynet/rustynetd.sock",
        _ => "/run/rustynet/rustynetd.sock",
    }
}

/// Auto-tunnel assignment bundle path for the given platform. macOS
/// keeps trust state under `/usr/local/var/rustynet/trust`.
pub fn assignment_bundle_path_for_platform(platform: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "macos" | "darwin" => "/usr/local/var/rustynet/trust/rustynetd.assignment",
        _ => "/var/lib/rustynet/rustynetd.assignment",
    }
}

/// Auto-tunnel assignment watermark path for the given platform.
pub fn assignment_watermark_path_for_platform(platform: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "macos" | "darwin" => "/usr/local/var/rustynet/trust/rustynetd.assignment.watermark",
        _ => "/var/lib/rustynet/rustynetd.assignment.watermark",
    }
}

/// Assignment-refresh env file path for the given platform. macOS
/// config lives under `/usr/local/etc/rustynet`.
pub fn assignment_refresh_env_path_for_platform(platform: &str) -> &'static str {
    match platform.trim().to_ascii_lowercase().as_str() {
        "macos" | "darwin" => "/usr/local/etc/rustynet/assignment-refresh.env",
        _ => "/etc/rustynet/assignment-refresh.env",
    }
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
        "sudo -n {REMOTE_RUSTYNET_BIN} ops e2e-enforce-host --role {} --node-id {} --src-dir {} --ssh-allow-cidrs {}",
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

#[allow(clippy::too_many_arguments)]
pub fn apply_role_coupling(
    identity: &Path,
    known_hosts: &Path,
    target: &str,
    target_role: &str,
    preferred_exit_node_id: Option<&str>,
    enable_exit_advertise: bool,
    env_path: &str,
    platform: &str,
) -> Result<(), String> {
    let mut command = format!(
        "sudo -n env RUSTYNET_SOCKET={} RUSTYNET_AUTO_TUNNEL_BUNDLE={} RUSTYNET_AUTO_TUNNEL_WATERMARK={} rustynet ops apply-role-coupling --target-role {} --enable-exit-advertise {} --env-path {}",
        daemon_socket_path_for_platform(platform),
        assignment_bundle_path_for_platform(platform),
        assignment_watermark_path_for_platform(platform),
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
    // The lab does not verify macOS client full-tunnel exit-route convergence:
    // baseline validation skips apply-role-coupling entirely for macOS and
    // relies on the pre-written assignment-refresh env + daemon pickup. Mirror
    // that here so the role-switch restore performs the coupling mutation +
    // launchd refresh without waiting on a route convergence the lab does not
    // assert on macOS.
    if platform == "macos" {
        command.push_str(" --skip-client-exit-route-convergence-wait");
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
    platform: &str,
) -> Result<(), String> {
    let mut command = format!(
        "sudo -n env RUSTYNET_SOCKET={} RUSTYNET_AUTO_TUNNEL_BUNDLE={} RUSTYNET_AUTO_TUNNEL_WATERMARK={} rustynet ops apply-lan-access-coupling --enable {} --env-path {}",
        daemon_socket_path_for_platform(platform),
        assignment_bundle_path_for_platform(platform),
        assignment_watermark_path_for_platform(platform),
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
        return Err("invalid base64 wireguard public key".to_owned());
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
                return Err("invalid base64 wireguard public key".to_owned());
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
        return Err("git rev-parse HEAD failed".to_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim().to_lowercase();
    if trimmed.is_empty() {
        return Err("git rev-parse HEAD returned empty output".to_owned());
    }
    Ok(trimmed)
}

pub fn read_last_matching_line(text: &str, needle: &str) -> String {
    text.lines()
        .rfind(|line| line.contains(needle))
        .unwrap_or("")
        .to_owned()
}

pub fn field_value(line: &str, key: &str) -> String {
    for field in line.split_whitespace() {
        if let Some(value) = field.strip_prefix(&format!("{key}=")) {
            return value.to_owned();
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

#[cfg(test)]
mod tests {
    use super::{
        LiveLabPlatform, enforce_linux_only_until_validator_lands, env_flag_truthy,
        known_hosts_lookup_host, resolved_known_hosts_candidates,
        resolved_target_address_from_ssh_g, ssh_destination, target_address, target_port,
    };

    #[test]
    fn target_address_strips_default_port_suffix() {
        // Regression: SshConnectionParams-derived targets carry a `:22` suffix
        // (`format!("{host}:{port}")`). The known_hosts candidate must see the
        // bare host: default-port entries are stored unqualified, so a
        // "192.168.64.4:22" candidate makes `ssh-keygen -F` miss the entry and
        // every pinned-host check fails ("lacks host key"). The sibling
        // live_lab_support module pins the same invariant.
        assert_eq!(target_address("debian@192.168.64.4:22"), "192.168.64.4");
        assert_eq!(target_address("debian@192.168.64.4:2222"), "192.168.64.4");
        assert_eq!(target_address("debian@192.168.64.4"), "192.168.64.4");
        assert_eq!(target_address("192.168.64.4:22"), "192.168.64.4");
        // Bracketed IPv6 yields the literal; a bare IPv6 literal is untouched.
        assert_eq!(target_address("debian@[fd00::1]:2222"), "fd00::1");
        assert_eq!(target_address("debian@fd00::1"), "fd00::1");
    }

    #[test]
    fn ssh_destination_rebuilds_user_and_bare_host() {
        // The destination handed to ssh/scp must never carry the port: OpenSSH
        // treats "192.168.64.4:22" as a literal hostname and fails with
        // "could not resolve hostname". The port travels as -p/-P instead.
        assert_eq!(
            ssh_destination("debian@192.168.64.4:22"),
            "debian@192.168.64.4"
        );
        assert_eq!(
            ssh_destination("debian@192.168.64.4:2222"),
            "debian@192.168.64.4"
        );
        assert_eq!(
            ssh_destination("debian@192.168.64.4"),
            "debian@192.168.64.4"
        );
        assert_eq!(ssh_destination("192.168.64.4:22"), "192.168.64.4");
        assert_eq!(ssh_destination("debian@[fd00::1]:2222"), "debian@fd00::1");
    }

    #[test]
    fn target_port_extracts_explicit_suffix_only() {
        assert_eq!(target_port("debian@192.168.64.4:22"), Some(22));
        assert_eq!(target_port("debian@192.168.64.4:2222"), Some(2222));
        assert_eq!(target_port("debian@[fd00::1]:2222"), Some(2222));
        // No explicit suffix -> None (use the SSH default), and a bare IPv6
        // literal's colons must not be mistaken for a port.
        assert_eq!(target_port("debian@192.168.64.4"), None);
        assert_eq!(target_port("debian@fd00::1"), None);
        assert_eq!(target_port("debian@192.168.64.4:"), None);
        assert_eq!(target_port("debian@192.168.64.4:ssh"), None);
    }

    #[test]
    fn scp_base_command_places_port_before_the_end_of_options_marker() {
        // Regression: scp spells the port `-P` and it must precede the `--`
        // end-of-options marker. Appended after it, scp parses `-P` as a local
        // source path and dies with `stat local "-P": No such file or directory`.
        let identity = std::path::Path::new("/tmp/id");
        let known_hosts = std::path::Path::new("/tmp/kh");
        let args: Vec<String> =
            super::scp_base_command(identity, known_hosts, "debian@192.168.64.4:2222")
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
        let port_at = args
            .iter()
            .position(|arg| arg == "-P")
            .expect("-P is emitted for an explicit port");
        let marker_at = args
            .iter()
            .position(|arg| arg == "--")
            .expect("-- marker is emitted");
        assert!(port_at < marker_at, "-P must precede --, got {args:?}");
        assert_eq!(args[port_at + 1], "2222");

        // No explicit port -> no -P at all (fall back to the ssh default).
        let default_args: Vec<String> =
            super::scp_base_command(identity, known_hosts, "debian@192.168.64.4")
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
        assert!(
            !default_args.iter().any(|arg| arg == "-P"),
            "no -P without an explicit port, got {default_args:?}"
        );
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
    fn ssh_and_scp_disable_known_hosts_mutation() {
        let identity = std::path::Path::new("/tmp/id_ed25519");
        let known_hosts = std::path::Path::new("/tmp/known_hosts");

        let ssh_args: Vec<String> =
            super::ssh_base_command(identity, known_hosts, "debian@192.168.64.4")
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
        assert!(
            ssh_args.iter().any(|arg| arg == "UpdateHostKeys=no"),
            "ssh must not mutate the seeded known_hosts file"
        );

        let scp_args: Vec<String> =
            super::scp_base_command(identity, known_hosts, "debian@192.168.64.4")
                .get_args()
                .map(|arg| arg.to_string_lossy().into_owned())
                .collect();
        assert!(
            scp_args.iter().any(|arg| arg == "UpdateHostKeys=no"),
            "scp must not mutate the seeded known_hosts file"
        );
    }

    /// `sudo` resolves the command through `secure_path` from `/etc/sudoers`,
    /// NOT the caller's PATH. The RHEL family ships
    /// `Defaults secure_path = /sbin:/bin:/usr/sbin:/usr/bin`, which omits
    /// `/usr/local/bin` where the lab installs the binary, while Debian and
    /// Ubuntu include it. So a bare `sudo -n rustynet` passes on Debian and
    /// fails on Rocky/Fedora with `sudo: rustynet: command not found` —
    /// invisible on a Debian-only topology, and surfacing only as an opaque
    /// stage failure once a RHEL-family guest takes a role (it cost a full
    /// live-lab cycle on the two-hop entry node). Scan the source so a new
    /// call site cannot reintroduce the whole class.
    #[test]
    fn sudo_invocations_name_the_rustynet_binary_by_absolute_path() {
        assert!(
            super::REMOTE_RUSTYNET_BIN.starts_with('/'),
            "the remote binary must be an absolute path, got {:?}",
            super::REMOTE_RUSTYNET_BIN
        );
        let root = super::repo_root().expect("repo root");
        let bin_dir = root.join("crates/rustynet-cli/src/bin");
        let mut offenders = Vec::new();
        let mut scanned = 0usize;
        // The bare form is `sudo` + optional flags + the unqualified binary
        // name. Build the needles at runtime so this detector's own source
        // does not match itself.
        let bare = ["sudo", "-n", "rustynet "].join(" ");
        let bare_no_flag = ["sudo", "rustynet "].join(" ");
        let mut scan = |path: &std::path::Path| {
            let Ok(body) = std::fs::read_to_string(path) else {
                return;
            };
            scanned += 1;
            // Production code only: a test may legitimately name the bare form
            // in a fixture or an assertion message.
            let production = body.split("#[cfg(test)]").next().unwrap_or(&body);
            for (index, line) in production.lines().enumerate() {
                // Only the bare, PATH-dependent form is a defect; an absolute
                // path (or a `{}`/`{VAR}` placeholder fed one) is correct.
                if line.contains(bare.as_str()) || line.contains(bare_no_flag.as_str()) {
                    offenders.push(format!("{}:{}: {}", path.display(), index + 1, line.trim()));
                }
            }
        };
        scan(bin_dir.join("live_lab_bin_support/mod.rs").as_path());
        if let Ok(entries) = std::fs::read_dir(bin_dir.as_path()) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "rs") {
                    scan(path.as_path());
                }
            }
        }
        assert!(
            scanned > 0,
            "scanned no sources; the bin directory layout moved: {}",
            bin_dir.display()
        );
        assert!(
            offenders.is_empty(),
            "sudo must name the binary by absolute path (REMOTE_RUSTYNET_BIN); \
             a bare `sudo -n rustynet` fails on Rocky/Fedora secure_path:\n{}",
            offenders.join("\n")
        );
    }
}
