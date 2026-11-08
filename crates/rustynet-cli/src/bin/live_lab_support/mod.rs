#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::collections::HashSet;
use std::env;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::net::Ipv4Addr;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
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

/// Deployed Linux state paths. These are the defaults the systemd unit template
/// passes to the daemon (`scripts/systemd/rustynetd.service`) and the ones
/// `ops_install_systemd` creates, so a stage that names them explicitly is
/// pointing at the same files the daemon uses.
pub const LINUX_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
pub const LINUX_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
/// Seeded at install time on **admin** nodes only — non-admin nodes leave it
/// absent so the daemon's enrollment IPC stays fail-closed
/// (`ops_install_systemd.rs`). Its absence is therefore a legitimate,
/// *detectable* "this node has no anchor state" condition, and the only one a
/// stage may treat as a skip rather than a failure.
pub const LINUX_ENROLLMENT_SECRET_PATH: &str = "/var/lib/rustynet/keys/enrollment.secret";
/// Daemon-managed; created on first consume, so its absence means "nothing has
/// been consumed here yet", not "misconfigured".
pub const LINUX_ENROLLMENT_LEDGER_PATH: &str = "/var/lib/rustynet/rustynetd.enrollment.ledger";

/// Deployed macOS state paths. The launchd daemon
/// (`scripts/bootstrap/macos/Install-RustyNetMacosService.sh`) passes
/// `${STATE_ROOT}/keys/enrollment.secret` and
/// `${STATE_ROOT}/keys/rustynetd.enrollment.ledger` with
/// `STATE_ROOT=/usr/local/var/rustynet`
/// (`scripts/bootstrap/macos/Bootstrap-RustyNetMacos.sh`), so these are the
/// same daemon-used files the Linux consts are on systemd guests.
pub const MACOS_ENROLLMENT_SECRET_PATH: &str = "/usr/local/var/rustynet/keys/enrollment.secret";
pub const MACOS_ENROLLMENT_LEDGER_PATH: &str =
    "/usr/local/var/rustynet/keys/rustynetd.enrollment.ledger";
/// Mirrors `rustynetd::macos_key_custody::MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH`
/// / `MACOS_WG_KEYS_DIR` (the reviewed macOS custody layout: 0600 key file in
/// a 0700 rustynetd-owned dir).
pub const MACOS_WG_ENCRYPTED_KEY_PATH: &str = "/usr/local/var/rustynet/keys/wireguard.key.enc";
pub const MACOS_WG_KEYS_DIR: &str = "/usr/local/var/rustynet/keys";
/// Per-OS assignment-refresh env paths. Matches
/// `scripts/e2e/live_lab_common.sh` `assignment_refresh_env_path` exactly:
/// the macOS bootstrap's CONFIG_ROOT is `/usr/local/etc/rustynet` and the
/// Windows config root is `C:\ProgramData\RustyNet\config`.
pub const MACOS_ASSIGNMENT_REFRESH_ENV_PATH: &str =
    "/usr/local/etc/rustynet/assignment-refresh.env";
pub const WINDOWS_ASSIGNMENT_REFRESH_ENV_PATH: &str =
    "C:\\ProgramData\\RustyNet\\config\\assignment-refresh.env";

/// Enrollment-secret path the deployed daemon was seeded with, per OS.
/// Windows fails closed: no Windows enrollment-secret state path is wired up.
pub fn enrollment_secret_path(platform: LiveLabPlatform) -> Result<&'static str, String> {
    match platform {
        LiveLabPlatform::Linux => Ok(LINUX_ENROLLMENT_SECRET_PATH),
        LiveLabPlatform::MacOs => Ok(MACOS_ENROLLMENT_SECRET_PATH),
        LiveLabPlatform::Windows => Err(
            "windows live-lab validators have no enrollment-secret state path wired up yet"
                .to_owned(),
        ),
    }
}

/// Enrollment-ledger path the deployed daemon manages, per OS.
pub fn enrollment_ledger_path(platform: LiveLabPlatform) -> Result<&'static str, String> {
    match platform {
        LiveLabPlatform::Linux => Ok(LINUX_ENROLLMENT_LEDGER_PATH),
        LiveLabPlatform::MacOs => Ok(MACOS_ENROLLMENT_LEDGER_PATH),
        LiveLabPlatform::Windows => Err(
            "windows live-lab validators have no enrollment-ledger state path wired up yet"
                .to_owned(),
        ),
    }
}

/// `(encrypted key file, keys dir)` the deployed daemon enforces custody on,
/// per OS. Windows fails closed: its custody model is in-memory/DPAPI, not a
/// POSIX key file, so there is no honest mode probe to run.
pub fn wg_encrypted_key_paths(
    platform: LiveLabPlatform,
) -> Result<(&'static str, &'static str), String> {
    match platform {
        LiveLabPlatform::Linux => Ok((
            "/var/lib/rustynet/keys/wireguard.key.enc",
            "/var/lib/rustynet/keys",
        )),
        LiveLabPlatform::MacOs => Ok((MACOS_WG_ENCRYPTED_KEY_PATH, MACOS_WG_KEYS_DIR)),
        LiveLabPlatform::Windows => Err(
            "windows key custody is in-memory/DPAPI; no POSIX key file is enforced (fail closed)"
                .to_owned(),
        ),
    }
}

/// Where `ops apply-lan-access-coupling` writes the refresh env file, per OS.
pub fn assignment_refresh_env_path(platform: LiveLabPlatform) -> Result<&'static str, String> {
    match platform {
        LiveLabPlatform::Linux => Ok("/etc/rustynet/assignment-refresh.env"),
        LiveLabPlatform::MacOs => Ok(MACOS_ASSIGNMENT_REFRESH_ENV_PATH),
        LiveLabPlatform::Windows => Ok(WINDOWS_ASSIGNMENT_REFRESH_ENV_PATH),
    }
}

/// `stat` argv that prints the octal permission bits of `path`, per OS. Both
/// forms print bare octal digits (`600`, `755`): GNU `--format=%a` on Linux,
/// BSD `-f %Lp` on macOS.
pub fn stat_mode_argv(
    platform: LiveLabPlatform,
    path: &'static str,
) -> Result<Vec<&'static str>, String> {
    match platform {
        LiveLabPlatform::Linux => Ok(vec!["stat", "--format=%a", path]),
        LiveLabPlatform::MacOs => Ok(vec!["stat", "-f", "%Lp", path]),
        LiveLabPlatform::Windows => {
            Err("windows has no POSIX mode probe for the live-lab custody validator".to_owned())
        }
    }
}

/// D2 (review macos-harness-b): the macOS unified-log chunk's scan window is
/// FIXED at 15 minutes, deliberately NOT derived from the `lines` argument:
/// `journalctl -n <lines>` counts lines while `log show --last` takes a time
/// window and there is no honest line→seconds mapping, so inventing one would
/// silently change how much of the unified log a scan covers. The launchd
/// tail chunks below DO honour `lines` byte-for-byte. The window is named in
/// the argv (pinned byte-for-byte by
/// `daemon_unit_log_argv_macos_scans_unified_log_and_launchd_log_files`) and
/// must be named in every stage's collection log line so a scan window is
/// never silent.
pub const MACOS_UNIFIED_LOG_WINDOW: &str = "15m";

/// Daemon unit-log collection argv, per OS: every chunk's stdout must be
/// scanned for leaked key material. Linux returns the journald unit log
/// (byte-identical to the pre-port argv; `--output=short-monotonic` is
/// appended only when `with_monotonic_output`). macOS returns the unified log
/// window for the daemon process (fixed `--last {MACOS_UNIFIED_LOG_WINDOW}`
/// window — see that const for why `lines` is not threaded into it) plus the
/// launchd StandardOut/StandardError files (`/usr/local/var/log/rustynet/`),
/// because a plain Rust daemon does not mirror its stderr into the unified
/// log. Windows fails closed.
pub fn daemon_unit_log_argv(
    platform: LiveLabPlatform,
    lines: &'static str,
    with_monotonic_output: bool,
) -> Result<Vec<Vec<&'static str>>, String> {
    match platform {
        LiveLabPlatform::Linux => {
            let mut argv = vec!["journalctl", "-u", "rustynetd", "-n", lines, "--no-pager"];
            if with_monotonic_output {
                argv.push("--output=short-monotonic");
            }
            Ok(vec![argv])
        }
        LiveLabPlatform::MacOs => Ok(vec![
            vec![
                "/usr/bin/log",
                "show",
                "--last",
                MACOS_UNIFIED_LOG_WINDOW,
                "--predicate",
                "process == \"rustynetd\"",
                "--style",
                "compact",
            ],
            vec![
                "/usr/bin/tail",
                "-n",
                lines,
                "/usr/local/var/log/rustynet/rustynetd.log",
            ],
            vec![
                "/usr/bin/tail",
                "-n",
                lines,
                "/usr/local/var/log/rustynet/rustynetd-error.log",
            ],
        ]),
        LiveLabPlatform::Windows => Err(
            "windows live-lab validators have no daemon unit-log collection wired up yet"
                .to_owned(),
        ),
    }
}
/// Where a stage points `membership verify --audit-output`. The verb's own
/// default is CWD-relative, and an SSH command's CWD is the login user's home,
/// so stages pin it. Inside the root-owned state dir rather than `/tmp` so the
/// root-written file cannot be pre-empted by a symlink planted at a
/// world-writable path.
pub const REMOTE_MEMBERSHIP_AUDIT_PATH: &str =
    "/var/lib/rustynet/membership_audit_integrity.live_lab.log";
/// Exact success line of `rustynet membership verify`, from
/// `execute_membership`'s `VerifyLog` arm. Stages must match this rather than
/// guess at substrings: the previous `contains("ok") || contains("valid")`
/// heuristic matches neither this line nor any of the verb's failure strings.
pub const MEMBERSHIP_VERIFY_PASS_PREFIX: &str = "membership log verification passed:";
/// The fixed gossip port (`rustynetd::gossip_transport::RUSTYNET_GOSSIP_PORT`).
/// `enrollment consume` wants the enrollee's `<ip>:<port>` push address, and
/// under the production `PushAddressPolicy::Strict` that address must be
/// globally- or privately-scoped — a lab guest's LAN address qualifies.
pub const RUSTYNET_GOSSIP_PORT: u16 = 51821;

const PROCESS_POLL_INTERVAL_MILLIS: u64 = 100;
const UTM_EXEC_TIMEOUT_SECS: u64 = 120;
const UTM_FILE_TIMEOUT_SECS: u64 = 120;

/// Outer wall clock for ONE plain-ssh harness invocation. `ConnectTimeout`
/// bounds only the TCP connect (and, depending on the OpenSSH version, the
/// banner exchange); `ServerAliveInterval` is NOT sent before authentication.
/// A connection that completes TCP and then stalls in key exchange or auth
/// therefore has no client-side bound at all (katana-xnet-1235/1241: sshd
/// logged `Timeout before authentication` after LoginGraceTime 120, while the
/// harness-side ssh stayed blocked for another ~3.5 minutes). When a context
/// opts in, the ssh child runs in its own process group and the whole group
/// is SIGKILLed at this deadline; the error carries [`SSH_TIMEOUT_TOKEN`], the
/// target, the elapsed seconds and the rendered argv.
///
/// The value is deliberately generous. `systemctl restart` legitimately
/// blocks until the old unit has stopped, which systemd bounds by its
/// `DefaultTimeoutStopSec` (90 s on current Debian/Ubuntu), and the observed
/// healthy `ops e2e-enforce-host` call took about 23 s on a lab guest. 150 s
/// keeps a wide margin over both while staying far below the ~5.5 minute
/// client-side stall the katana-xnet-1235/1241 evidence shows.
pub const SSH_CALL_TIMEOUT_SECS: u64 = 150;
/// Stable, greppable token that starts every outer-wall-clock timeout error.
pub const SSH_TIMEOUT_TOKEN: &str = "harness_ssh_timeout";
/// Stable, greppable token that starts every logged single retry.
pub const SSH_RETRY_TOKEN: &str = "harness_ssh_retry";

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

/// Run one already-built ssh command under an OUTER wall clock.
///
/// The child leads its own process group so the whole tree (the ssh client and
/// any local helper it forked) dies on the deadline; `kill -KILL -- -<pgid>` is
/// the no-unsafe/libc group kill this repo already uses in
/// `vm_lab/overnight/executor.rs`, with `--` load-bearing so a bare negative
/// pgid is never parsed as a signal number. The error is
/// [`ssh_timeout_error`], which names the target, the elapsed seconds and the
/// rendered argv. `ConnectTimeout`/`ServerAlive*` alone cannot bound a stall
/// before authentication, which is exactly the katana-xnet-1235/1241 shape.
///
/// Both pipes are DRAINED CONCURRENTLY. A child that writes more than the
/// pipe capacity (~64 KiB) blocks in `write(2)` and never exits; a poll loop
/// that reads nothing would then misreport a healthy, merely chatty command
/// (for example `ss -tni` or `nft list ruleset`) as a wall-clock timeout. One
/// std-only reader thread per pipe collects the bytes, exactly like the
/// `Command::output` path that the dark-by-default arm still uses.
fn run_ssh_command_with_timeout(
    command: &mut Command,
    timeout: Duration,
    target: &str,
    rendered_argv: &str,
) -> Result<Output, String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let started_at = Instant::now();
    let mut child = command
        .spawn()
        .map_err(|err| format!("failed to run ssh for {target}: {err}"))?;
    let stdout = child.stdout.take().map(drain_pipe);
    let stderr = child.stderr.take().map(drain_pipe);
    loop {
        match child
            .try_wait()
            .map_err(|err| format!("failed to wait for ssh on {target}: {err}"))?
        {
            Some(status) => {
                let stdout = collect_drained_pipe(stdout, "stdout", target)?;
                let stderr = collect_drained_pipe(stderr, "stderr", target)?;
                return Ok(Output {
                    status,
                    stdout,
                    stderr,
                });
            }
            None => {
                if started_at.elapsed() >= timeout {
                    let elapsed = started_at.elapsed().as_secs();
                    terminate_process_group(&mut child, GROUP_KILL_PROGRAM);
                    // The join after a kill is BOUNDED. A descendant that
                    // escaped the process group (`setsid`, a daemonising
                    // helper) may still hold a pipe open, so waiting for EOF
                    // would hang the harness past the deadline it just
                    // enforced. The reader thread is left to finish on its
                    // own; nothing here needs its bytes.
                    discard_drained_pipe(stdout);
                    discard_drained_pipe(stderr);
                    return Err(ssh_timeout_error(target, rendered_argv, elapsed));
                }
                sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
            }
        }
    }
}

/// Seconds a pipe-drain join may block before the harness gives up on it.
const PIPE_DRAIN_JOIN_TIMEOUT: Duration = Duration::from_secs(5);
/// Seconds the bounded reap may wait for the direct child after a kill.
const KILL_REAP_TIMEOUT: Duration = Duration::from_secs(5);
/// The program used for the no-unsafe process-group kill.
const GROUP_KILL_PROGRAM: &str = "kill";

type PipeDrain = mpsc::Receiver<std::io::Result<Vec<u8>>>;

/// Start one reader thread that drains a child pipe to EOF.
fn drain_pipe<R>(mut pipe: R) -> PipeDrain
where
    R: Read + Send + 'static,
{
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = pipe.read_to_end(&mut bytes).map(|_| bytes);
        let _ = sender.send(result);
    });
    receiver
}

fn collect_drained_pipe(
    pipe: Option<PipeDrain>,
    label: &str,
    target: &str,
) -> Result<Vec<u8>, String> {
    let Some(receiver) = pipe else {
        return Ok(Vec::new());
    };
    match receiver.recv_timeout(PIPE_DRAIN_JOIN_TIMEOUT) {
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(err)) => Err(format!("failed to drain ssh {label} for {target}: {err}")),
        Err(_) => Err(format!(
            "timed out after {}s draining ssh {label} for {target}",
            PIPE_DRAIN_JOIN_TIMEOUT.as_secs()
        )),
    }
}

fn discard_drained_pipe(pipe: Option<PipeDrain>) {
    if let Some(receiver) = pipe {
        let _ = receiver.recv_timeout(PIPE_DRAIN_JOIN_TIMEOUT);
    }
}

/// Kill the child's whole process group, ALWAYS kill the direct child as a
/// fallback, then reap it under a bound.
///
/// The group kill is best-effort: `kill` may be absent, not executable, or
/// the child may already have left the group. Ignoring that result and then
/// calling an unbounded `wait()` would silently restore the very
/// unbounded-wait bug this whole path exists to remove, so `child.kill()`
/// runs unconditionally afterwards and the reap is bounded.
fn terminate_process_group(child: &mut std::process::Child, kill_program: &str) {
    #[cfg(unix)]
    {
        let pgid = child.id() as i64;
        let _ = Command::new(kill_program)
            .arg("-KILL")
            .arg("--")
            .arg(format!("-{pgid}"))
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = kill_program;
    }
    let _ = child.kill();
    reap_child_bounded(child, KILL_REAP_TIMEOUT);
}

/// Bounded reap: never block on a direct child that somehow survives the
/// kill. Returns as soon as it is reaped or the bound expires.
fn reap_child_bounded(child: &mut std::process::Child, bound: Duration) {
    let started_at = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if started_at.elapsed() < bound => {
                sleep(Duration::from_millis(PROCESS_POLL_INTERVAL_MILLIS));
            }
            Ok(None) => return,
        }
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

/// Result of one remote `rustynet` invocation that was allowed to fail.
///
/// `capture_root_allow_failure` returns only stdout and throws away both the
/// exit status and stderr, which is how a broken invocation could look like a
/// lab observation: the CLI prints its errors to **stdout** (`main.rs`'s error
/// arm uses `println!`, not `eprintln!`), so a caller that keeps only stdout
/// receives the error text as if it were data. Keeping all three fields is what
/// lets a stage tell "the lab said no" apart from "the harness asked wrong".
#[derive(Debug, Clone)]
pub struct RemoteCliOutcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl RemoteCliOutcome {
    pub fn succeeded(&self) -> bool {
        self.exit_code == 0
    }

    pub fn trimmed_stdout(&self) -> &str {
        self.stdout.trim()
    }

    /// One-line rendering for a log or an error, with both streams so a failure
    /// is diagnosable from the stage log alone.
    pub fn detail(&self) -> String {
        format!(
            "exit={} stdout={:?} stderr={:?}",
            self.exit_code,
            self.stdout.trim(),
            self.stderr.trim()
        )
    }
}

/// Decide whether a failed `rustynet` invocation failed because the CLI could
/// not PARSE it, rather than because the lab was in some state.
///
/// This distinction is load-bearing for the FAIL-LOUD live-stage spec
/// (`CrossPlatformRoleParityRoadmap_2026-06-22.md`): a stage's status must be
/// its live result, and a command the CLI never understood produced no live
/// result at all. Such a failure is a harness wiring defect and must abort the
/// stage, never fall through to a graceful-skip or a degraded "rolled back"
/// branch that reports a plausible outcome without having exercised anything.
///
/// Returns `Some(reason)` when the invocation did not parse.
///
/// The signals, in the order they are checked:
/// - exit 127 / `command not found` — the binary is not on the guest at all
///   (`sudo`'s `secure_path` omits `/usr/local/bin` on the RHEL family, so a
///   bare-name argv head lands here; see `REMOTE_RUSTYNET_BIN`).
/// - `unknown command:` — no such top-level command.
/// - `unknown … subcommand:` — no such subcommand. Note this is also what a
///   `vm-lab`-gated verb looks like when the guest's binary was built without
///   `--features vm-lab`, which is equally a wiring defect.
/// - exit 64 / `bad_args (64)` — `classify_cli_error` routes only
///   argument-shaped messages here (unknown verb, missing required option,
///   invalid value), so this code means the argv was wrong, never that the
///   operation was attempted and refused.
pub fn cli_invocation_parse_failure(
    exit_code: i32,
    stdout: &str,
    stderr: &str,
) -> Option<&'static str> {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if exit_code == 127 || combined.contains("command not found") {
        return Some("the rustynet binary is not on the guest's PATH (command not found)");
    }
    if combined.contains("unknown command:") {
        return Some("the CLI has no such top-level command");
    }
    if combined.contains("unknown") && combined.contains("subcommand") {
        return Some(
            "the CLI has no such subcommand (or the guest's binary was built without \
             --features vm-lab)",
        );
    }
    if exit_code == 64 || combined.contains("bad_args (64)") {
        return Some("the CLI rejected the arguments (bad_args): a flag name or value is wrong");
    }
    if combined.contains("invalid option token") {
        return Some("the CLI could not parse an option token");
    }
    None
}

/// A freshly generated, VALID Ed25519 verifying key, URL-safe-base64 without
/// padding — the shape `rustynet enrollment consume --pubkey` requires.
///
/// Generated through `SigningKey` rather than by base64-ing 32 random bytes:
/// the daemon runs the input through `VerifyingKey::from_bytes`, which rejects
/// a non-canonical point, so raw random bytes would fail intermittently and the
/// stage would flake on its own test data instead of on the lab.
pub fn random_enrollee_pubkey_b64() -> Result<String, String> {
    use base64::Engine as _;
    use rand::TryRngCore as _;
    let mut seed = [0u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut seed)
        .map_err(|err| format!("os randomness unavailable for enrollee pubkey: {err}"))?;
    let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
    Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(signing.verifying_key().to_bytes()))
}

/// Read one `key=value` field out of a space-separated CLI status line, e.g.
/// `already_consumed=true` from `rustynet enrollment verify`, or `node_id=…`
/// from `rustynet status`.
///
/// Returns `None` when the key is absent, which callers must treat as "the
/// output was not the shape we expected" rather than as a `false`/empty value —
/// silently defaulting is the failure mode HARNESS-VERBS exists to remove.
pub fn key_value_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(needle.as_str()))
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

/// The daemon-readiness IPC probe, as an argv: point the CLI at the daemon
/// socket with `RUSTYNET_DAEMON_SOCKET` and ask for `status`. A `test -S`
/// socket-file check alone cannot prove readiness — after a `systemctl
/// restart` the OLD socket file lingers until the new daemon binds, so the
/// next IPC call hits `connect … failed: Connection refused` (katana-xnet-148).
/// Only a completed round trip proves the daemon is listening.
/// Guest-side wall-clock bound for ONE status round trip, enforced by the
/// guests' coreutils `timeout`: a daemon that accepts but never answers must
/// consume one attempt — `timeout` kills it with exit 124, which `run_root`
/// reports as an ordinary failed root command — instead of hanging the whole
/// stage on the CLI's unbounded Unix IPC read (product-side read timeout is a
/// separate, not-yet-made decision).
const DAEMON_STATUS_PROBE_TIMEOUT_SECS: &str = "15";

/// The daemon-readiness IPC probe, as an argv: point the CLI at the daemon
/// socket with `RUSTYNET_DAEMON_SOCKET` and ask for `status`, bounded by the
/// guest coreutils `timeout` ([`DAEMON_STATUS_PROBE_TIMEOUT_SECS`]) so a
/// wedged daemon cannot hang the probe — the timeout kill (exit 124) surfaces
/// as an ordinary failed attempt. A `test -S` socket-file check alone cannot
/// prove readiness — after a `systemctl restart` the OLD socket file lingers
/// until the new daemon binds, so the next IPC call hits `connect … failed:
/// Connection refused` (katana-xnet-148). Only a completed round trip proves
/// the daemon is listening.
fn daemon_status_probe_argv(socket_path: &str) -> Vec<String> {
    vec![
        "timeout".to_owned(),
        DAEMON_STATUS_PROBE_TIMEOUT_SECS.to_owned(),
        "env".to_owned(),
        format!("RUSTYNET_DAEMON_SOCKET={socket_path}"),
        REMOTE_RUSTYNET_BIN.to_owned(),
        "status".to_owned(),
    ]
}

/// Shared-budget readiness wait: retry BOTH probes under ONE `attempts`
/// budget. Each iteration checks the socket file (cheap) and, only once it
/// exists, runs the `status` round trip; success is the round trip's exit 0 —
/// whatever posture the daemon reports (including fail-closed) is payload
/// data, not a readiness failure. The final error names the stage that was
/// still failing when the budget ran out, so a caller can tell a socket that
/// never appeared from a socket file the daemon never answered.
///
/// Wall-time note: once the socket file exists the status round trip runs on
/// EVERY iteration, so worst-case wall time grows by up to `attempts` extra
/// root round trips versus the old file-existence-only wait (e.g. 20 attempts
/// at ~1–2 s per ssh round trip ≈ +20–40 s per wait). The probe's `timeout
/// 15` (guest coreutils, exit 124) bounds each round trip in the guest, so a
/// wedged daemon consumes attempts like any other failure instead of hanging
/// the wait on an unbounded IPC read.
fn wait_for_daemon_socket_ready(
    attempts: u32,
    mut socket_present: impl FnMut() -> Result<(), String>,
    mut daemon_answers_status: impl FnMut() -> Result<(), String>,
    mut sleep_between_attempts: impl FnMut(),
) -> Result<(), String> {
    let attempts = attempts.max(1);
    let mut file_stage = true;
    let mut last_error = String::from("no attempt completed");
    for attempt in 1..=attempts {
        let outcome: Result<(), String> = match socket_present() {
            Ok(()) => match daemon_answers_status() {
                Ok(()) => return Ok(()),
                Err(err) => {
                    file_stage = false;
                    Err(err)
                }
            },
            Err(err) => Err(err),
        };
        if let Err(err) = outcome {
            // H2: a TRANSPORT timeout is not "not ready yet". Retrying it
            // burns the whole budget (20 attempts x the ssh wall clock) and
            // the wrapped message below would no longer start with the
            // timeout token, so the caller's stall diagnostics would be
            // skipped. Return the timeout error UNCHANGED, token and argv
            // intact, and let the stage abort immediately.
            if is_ssh_timeout_error(&err) {
                return Err(err);
            }
            last_error = err;
        }
        if attempt < attempts {
            sleep_between_attempts();
        }
    }
    let stage = if file_stage {
        format!("socket file never appeared after {attempts} attempts")
    } else {
        format!(
            "socket file present but the daemon did not answer status after {attempts} attempts"
        )
    };
    Err(format!("{stage}: {last_error}"))
}

/// Wiring of BOTH probes into the shared-budget core for
/// [`LiveLabContext::wait_for_daemon_socket`]: the exact presence argv and the
/// exact timeout-bounded status argv. `run_argv` is the smallest injectable
/// runner (the production caller passes `LiveLabContext::run_root`), so tests
/// execute this wiring end to end without ssh — a wiring regression (status
/// probe swapped for `Ok(())`, probe result ignored) fails those tests.
fn wait_for_daemon_socket_with_runner(
    socket_path: &str,
    attempts: u32,
    sleep_secs: u64,
    run_argv: impl Fn(&[&str]) -> Result<(), String>,
) -> Result<(), String> {
    let status_argv = daemon_status_probe_argv(socket_path);
    let status_argv: Vec<&str> = status_argv.iter().map(String::as_str).collect();
    wait_for_daemon_socket_ready(
        attempts,
        || run_argv(&["test", "-S", socket_path]),
        || run_argv(&status_argv),
        || sleep(Duration::from_secs(sleep_secs)),
    )
}

#[derive(Debug, Clone)]
pub struct LiveLabContext {
    pub root_dir: PathBuf,
    pub ssh_identity_file: PathBuf,
    pub pinned_known_hosts_file: PathBuf,
    pub work_dir: PathBuf,
    pub known_hosts_file: PathBuf,
    /// Shared ownership of [`Self::work_dir`]. Contexts are CLONED all over
    /// the live tests (cleanup guards, RAII fences hold their own copy so
    /// their Drop paths can still run remote calls); the dir must die only
    /// with the LAST clone — see [`WorkDirGuard`].
    work_dir_guard: Arc<WorkDirGuard>,
    verified_hosts: HashSet<String>,
    /// The ssh/scp client programs the transport runs. Defaults to the real
    /// OpenSSH client; overridable only through the test constructor so unit
    /// tests can record the exact argv the harness builds (same escape-hatch
    /// shape as `LIVE_LAB_UTMCTL_PATH`, but process-safe: no env mutation).
    transport_programs: TransportPrograms,
    /// DARK BY DEFAULT: `None` runs `Command::output()` exactly as before, so
    /// every live test that does not opt in is byte-equal. A context that opts
    /// in (the LAN-toggle stage) gets an outer wall clock per ssh call; see
    /// [`SSH_CALL_TIMEOUT_SECS`].
    ssh_call_timeout: Option<Duration>,
}

/// Owns the unique per-run work dir a [`LiveLabContext`] seeds its
/// known_hosts copy into. `derive(Clone)` next to an `impl Drop` on the
/// context itself made EVERY clone's drop delete the shared dir:
/// katana-xnet-178 consumed the bundle-swap fence in
/// `BundleSwapFence::release()`, its ctx clone dropped, the seeded
/// work-dir known_hosts copy vanished, and the W7 restore right after it
/// failed on every participant with "No ED25519 host key is known ...
/// Host key verification failed." The dir must die exactly once, with the
/// last reference, so every remote call — restore included — always sees
/// the same trusted known_hosts context.
#[derive(Debug)]
struct WorkDirGuard {
    path: PathBuf,
    explicitly_removed: AtomicBool,
}

impl WorkDirGuard {
    /// Immediate, explicit removal requested by [`LiveLabContext::cleanup`].
    /// Marks the guard so the final drop does not remove again.
    fn remove_now(&self) {
        self.explicitly_removed.store(true, Ordering::SeqCst);
        let _ = fs::remove_dir_all(&self.path);
    }
}

impl Drop for WorkDirGuard {
    fn drop(&mut self) {
        if !self.explicitly_removed.load(Ordering::SeqCst) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

/// The client programs behind [`LiveLabContext`]'s ssh/scp transport.
#[derive(Debug, Clone)]
struct TransportPrograms {
    ssh: PathBuf,
    scp: PathBuf,
}

/// Test-only: a unique scratch dir OUTSIDE any [`LiveLabContext`] work dir,
/// so artifacts a unit test must read back (recorded argv, fixture files)
/// survive even a context whose work dir was removed on purpose.
#[cfg(test)]
pub(crate) fn test_scratch_dir(prefix: &str) -> Result<PathBuf, String> {
    create_unique_work_dir(prefix)
}

impl Default for TransportPrograms {
    fn default() -> Self {
        Self {
            ssh: PathBuf::from("ssh"),
            scp: PathBuf::from("scp"),
        }
    }
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
        Self::with_transport_programs(
            prefix,
            ssh_identity_file,
            pinned_known_hosts_file,
            TransportPrograms::default(),
        )
    }

    /// Test-only constructor: identical validation and seeding, but the ssh
    /// and scp client programs come from the caller so a unit test can
    /// record the exact argv the harness builds and reproduce transport
    /// failures (missing trusted known_hosts context) without a network.
    #[cfg(test)]
    pub(crate) fn with_transport_programs_for_tests(
        prefix: &str,
        ssh_identity_file: &Path,
        pinned_known_hosts_file: Option<&Path>,
        ssh_program: PathBuf,
        scp_program: PathBuf,
    ) -> Result<Self, String> {
        Self::with_transport_programs(
            prefix,
            ssh_identity_file,
            pinned_known_hosts_file,
            TransportPrograms {
                ssh: ssh_program,
                scp: scp_program,
            },
        )
    }

    fn with_transport_programs(
        prefix: &str,
        ssh_identity_file: &Path,
        pinned_known_hosts_file: Option<&Path>,
        transport_programs: TransportPrograms,
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
        let work_dir_path = create_unique_work_dir(prefix)?;
        let work_dir_guard = Arc::new(WorkDirGuard {
            path: work_dir_path.clone(),
            explicitly_removed: AtomicBool::new(false),
        });
        let known_hosts_file = work_dir_path.join("known_hosts");
        if let Err(err) = fs::copy(&pinned_known_hosts_file, &known_hosts_file) {
            // The guard is the only owner so far: dropping it here removes
            // the just-created dir (the pre-Arc drop-on-construct leak).
            drop(work_dir_guard);
            return Err(format!(
                "failed to seed {} from {}: {err}",
                known_hosts_file.display(),
                pinned_known_hosts_file.display()
            ));
        }
        set_path_mode(&known_hosts_file, 0o600)?;

        Ok(Self {
            root_dir,
            ssh_identity_file: ssh_identity_file.to_path_buf(),
            pinned_known_hosts_file,
            work_dir: work_dir_path,
            known_hosts_file,
            work_dir_guard,
            verified_hosts: HashSet::new(),
            transport_programs,
            ssh_call_timeout: None,
        })
    }

    /// Opt this context into the outer per-call ssh wall clock. Returns the
    /// context so a constructor chain can enable it in one expression. Without
    /// this call the context keeps the pre-fix unbounded `Command::output()`
    /// path byte-for-byte (see the compat test).
    pub fn with_ssh_call_timeout(mut self, timeout: Duration) -> Self {
        self.ssh_call_timeout = Some(timeout);
        self
    }

    /// Explicit, immediate removal of the work dir. Calls on a context whose
    /// clones are still alive strand THOSE clones without their seeded
    /// known_hosts copy (strict checking then refuses every connection, by
    /// design — this is why the live tests release fences instead of calling
    /// this); the final guard drop is the normal cleanup path.
    pub fn cleanup(&self) {
        self.work_dir_guard.remove_now();
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

    /// The one source of truth for the ssh/scp transport options every
    /// remote call in this module runs with. Strict host-key checking is
    /// pinned to `yes` and the trusted host-key context is always THIS run's
    /// seeded work-dir copy of the pinned known_hosts file — never the
    /// user's default file, never an ad-hoc file — so a call built anywhere
    /// in a live test (capture, install, restore, cleanup backstop) shares
    /// exactly the same trust as every other call.
    fn transport_option_argv(&self) -> Vec<std::ffi::OsString> {
        let mut options: Vec<std::ffi::OsString> = Vec::new();
        for option in [
            "LogLevel=ERROR",
            "BatchMode=yes",
            "StrictHostKeyChecking=yes",
        ] {
            options.push("-o".into());
            options.push(option.into());
        }
        options.push("-o".into());
        options.push(format!("UserKnownHostsFile={}", self.known_hosts_file.display()).into());
        for option in [
            "ConnectTimeout=15",
            "ServerAliveInterval=60",
            "ServerAliveCountMax=10",
            "IdentitiesOnly=yes",
        ] {
            options.push("-o".into());
            options.push(option.into());
        }
        options.push("-i".into());
        options.push(self.ssh_identity_file.clone().into_os_string());
        options
    }

    fn ssh_command(&self, target: &str) -> Command {
        let mut command = Command::new(&self.transport_programs.ssh);
        command.arg("-n");
        command.args(self.transport_option_argv());
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
        let output = match self.ssh_call_timeout {
            Some(timeout) => run_ssh_command_with_timeout(
                &mut command,
                timeout,
                target,
                remote_command.as_str(),
            )?,
            // DARK BY DEFAULT: unchanged pre-fix path for every context that
            // did not opt in (see `with_ssh_call_timeout`).
            None => command
                .output()
                .map_err(|err| format!("failed to run ssh for {target}: {err}"))?,
        };
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
            let mut command = Command::new(&self.transport_programs.scp);
            command.arg("-q");
            command.args(self.transport_option_argv());
            // scp uses `-P` (capital) for the port; the host must be bare or
            // scp reads `192.168.64.4:22:/path` as host `192.168.64.4` writing
            // to a bogus `22:/path`.
            if let Some(port) = target_port(target) {
                command.arg("-P").arg(port.to_string());
            }
            command
                .arg("--")
                .arg(src)
                .arg(format!("{}:{dst}", Self::ssh_destination(target)));
            // M5: scp is the same ssh transport, with the same unauthenticated
            // stall exposure. When the context opted into the wall clock, run
            // it through the same bounded, pipe-draining path. A timed-out
            // attempt is transient: re-copying a fixed local file to a fixed
            // remote path is idempotent, so it uses the existing retry loop.
            // Contexts that did not opt in keep `Command::output()` exactly.
            let output = match self.ssh_call_timeout {
                Some(timeout) => {
                    let rendered_scp_argv = render_command_argv(&command);
                    match run_ssh_command_with_timeout(
                        &mut command,
                        timeout,
                        target,
                        &rendered_scp_argv,
                    ) {
                        Ok(output) => output,
                        Err(err) => {
                            // A timeout error already carries the argv and the
                            // stable token; keep it as the terminal error rather
                            // than wrapping it in an scp-specific message.
                            last_stderr = err.clone();
                            if attempt < SCP_RETRY_ATTEMPTS {
                                sleep(Duration::from_secs(SCP_RETRY_SLEEP_SECS));
                                continue;
                            }
                            return Err(err);
                        }
                    }
                }
                None => command
                    .output()
                    .map_err(|err| format!("failed to run scp to {target}: {err}"))?,
            };
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

    /// Run an IDEMPOTENT root argv with at most ONE retry, and only after a
    /// TRANSPORT failure (outer-wall-clock timeout, spawn error, ssh exit 255).
    /// A real remote command failure is returned immediately and is never
    /// retried; a non-allowlisted argv is never retried either. The retry is
    /// logged with [`ssh_retry_token`]; the terminal error is returned
    /// unchanged so a timeout keeps its argv and elapsed seconds.
    pub fn run_root_idempotent_retry(&self, target: &str, args: &[&str]) -> Result<Output, String> {
        self.run_root_idempotent_retry_with(target, args, &mut |line| eprintln!("{line}"))
    }

    /// Same as [`Self::run_root_idempotent_retry`] but injects the retry-token
    /// sink so tests can pin the exact line without capturing stderr.
    pub fn run_root_idempotent_retry_with(
        &self,
        target: &str,
        args: &[&str],
        emit: &mut dyn FnMut(&str),
    ) -> Result<Output, String> {
        run_idempotent_ssh_retry_loop(
            target,
            args,
            || {
                let sudo_probe = classify_ssh_attempt(
                    target,
                    self.run_allow_failure(target, &["sudo", "-n", "-k", "true"]),
                );
                match sudo_probe {
                    SshAttemptOutcome::Succeeded(_) => {}
                    other => return other,
                }
                let mut full_args = vec!["sudo", "-n"];
                full_args.extend_from_slice(args);
                classify_ssh_attempt(target, self.run_allow_failure(target, &full_args))
            },
            emit,
        )
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

    /// Run a `rustynet` argv on a guest as root, FAILING LOUDLY if the CLI did
    /// not parse it, and otherwise handing the caller the full outcome.
    ///
    /// Prefer this over `capture_root_allow_failure` for every `rustynet`
    /// invocation. `capture_root_allow_failure` keeps stdout only, and the CLI
    /// prints its errors to stdout, so an argv the CLI never understood comes
    /// back as an ordinary-looking string that flows into the stage's data —
    /// which is exactly how three stages came to drive `ops` subcommands that do
    /// not exist while still reporting a plausible result (HARNESS-VERBS).
    ///
    /// A parse failure is a harness defect, so it is returned as `Err` and must
    /// abort the stage. A non-zero exit that is NOT a parse failure is returned
    /// as `Ok`, because that is a real live result the caller has to interpret
    /// (for enrollment, "token rejected" is a legitimate answer).
    ///
    /// `label` names the operation for the error text, e.g. `"enrollment mint"`.
    pub fn rustynet_root(
        &self,
        target: &str,
        label: &str,
        args: &[&str],
    ) -> Result<RemoteCliOutcome, String> {
        let output = self.run_root_allow_failure(target, args)?;
        let outcome = RemoteCliOutcome {
            exit_code: status_code(output.status),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        };
        if let Some(reason) =
            cli_invocation_parse_failure(outcome.exit_code, &outcome.stdout, &outcome.stderr)
        {
            return Err(format!(
                "harness wiring defect: `{label}` was not understood by the CLI on {target} \
                 ({reason}); argv: {}; {}",
                args.join(" "),
                outcome.detail()
            ));
        }
        Ok(outcome)
    }

    /// [`Self::rustynet_root`] for an invocation whose success is required:
    /// any non-zero exit is an error, not data.
    pub fn rustynet_root_must_succeed(
        &self,
        target: &str,
        label: &str,
        args: &[&str],
    ) -> Result<String, String> {
        let outcome = self.rustynet_root(target, label, args)?;
        if !outcome.succeeded() {
            return Err(format!(
                "`{label}` failed on {target}; argv: {}; {}",
                args.join(" "),
                outcome.detail()
            ));
        }
        Ok(outcome.stdout)
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
        wait_for_daemon_socket_with_runner(socket_path, attempts, sleep_secs, |argv| {
            self.run_root(target, argv)
        })
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

/// The terminal error text for an ssh call killed by the outer wall clock.
///
/// The token is stable and greppable, and the message NAMES the argv that
/// stalled plus how long it ran, so a recurrence is diagnosable from the
/// stage log alone. `argv` is the rendered remote argv (`sh -lc` payload),
/// never a shell string the harness would execute: the real invocation still
/// passes every element as a separate argv element.
pub fn ssh_timeout_error(target: &str, rendered_argv: &str, elapsed_secs: u64) -> String {
    format!("{SSH_TIMEOUT_TOKEN} target={target} elapsed={elapsed_secs}s argv={rendered_argv}")
}

/// True when `err` is the outer-wall-clock timeout error above. Callers use
/// this to decide whether a terminal failure deserves the one best-effort
/// diagnostic capture; it never changes the verdict.
pub fn is_ssh_timeout_error(err: &str) -> bool {
    err.strip_prefix(SSH_TIMEOUT_TOKEN)
        .is_some_and(|rest| rest.starts_with(' '))
}

/// The stable one-line retry log token. `reason` is a short, fixed class
/// (`timeout` / `transport` / `command`), never free-form stderr.
pub fn ssh_retry_token(target: &str, attempt: u32, reason: &str) -> String {
    format!("{SSH_RETRY_TOKEN} target={target} attempt={attempt} reason={reason}")
}

/// The remote calls that are safe to repeat after a TRANSPORT failure: each
/// either restarts a unit to a fixed state, re-runs a converging installer, or
/// is a read-only probe. This is an allowlist, not a heuristic — an argv that
/// is not one of these exact shapes is never retried.
///
/// `ops e2e-enforce-host` is `ops install-systemd` with a fixed environment
/// plus a socket wait and a signed-state refresh (`ops_e2e.rs:769>`), and
/// `install-systemd` rewrites the same unit files and restarts the same units
/// each run (`ops_install_systemd.rs:1274-1411`), so re-running it on a host
/// that already ran it converges to the same state. The leading token is the
/// harness's absolute `REMOTE_RUSTYNET_BIN`, and the remaining tokens are
/// harness-built values (role, node id, src dir, CIDRs).
pub fn idempotent_ssh_call_retryable(argv: &[&str]) -> bool {
    matches!(
        argv,
        [REMOTE_RUSTYNET_BIN, "ops", "e2e-enforce-host", ..]
            | ["systemctl", "reset-failed", ..]
            | [
                "systemctl",
                "restart",
                "rustynetd-privileged-helper.service"
            ]
            | ["systemctl", "restart", "rustynetd.service"]
            | ["systemctl", "is-active", ..]
            | ["test", "-S", _]
    )
}

/// Outcome of ONE root ssh attempt, classified so the retry decision never
/// has to re-parse an error string.
#[derive(Debug)]
pub enum SshAttemptOutcome {
    /// The remote command ran and exited 0.
    Succeeded(Output),
    /// The transport failed: spawn error, outer-wall-clock timeout, or ssh's
    /// own exit code 255. Repeating an idempotent call may recover it.
    TransportFailure(String),
    /// The remote command ran and exited non-zero (anything but 255). This is
    /// a real result: retrying it would mask a genuine failure.
    CommandFailure(String),
}

impl SshAttemptOutcome {
    /// The fixed retry-reason class for the retry log token.
    pub fn reason(&self) -> &'static str {
        match self {
            Self::Succeeded(_) => "none",
            Self::TransportFailure(detail) if is_ssh_timeout_error(detail) => "timeout",
            Self::TransportFailure(_) => "transport",
            Self::CommandFailure(_) => "command",
        }
    }
}

/// Classify one `run_allow_failure` result. ssh documents exit 255 as its own
/// transport-level failure (the remote command's status is otherwise carried
/// through), so 255 is the only non-zero code treated as retryable transport.
pub fn classify_ssh_attempt(target: &str, result: Result<Output, String>) -> SshAttemptOutcome {
    match result {
        // L8: only the outer-wall-clock timeout proves a TRANSPORT failure.
        // A local setup error (missing pinned known_hosts entry, a refused
        // render_remote_argv, a spawn failure) is a command-level failure
        // that a retry cannot fix, so it must never be retried.
        Err(err) if is_ssh_timeout_error(&err) => SshAttemptOutcome::TransportFailure(err),
        Err(err) => SshAttemptOutcome::CommandFailure(err),
        Ok(output) if output.status.success() => SshAttemptOutcome::Succeeded(output),
        Ok(output) if output.status.code() == Some(255) => {
            SshAttemptOutcome::TransportFailure(format!(
                "remote command failed on {target}: {}",
                render_failure_output(&output)
            ))
        }
        Ok(output) => SshAttemptOutcome::CommandFailure(format!(
            "remote command failed on {target}: {}",
            render_failure_output(&output)
        )),
    }
}

/// Whether the next attempt should run. Pure, so every rule is unit-testable:
/// at most ONE retry, only for an allowlisted idempotent argv, and only after
/// a transport failure. A command failure is never retried.
#[derive(Debug, PartialEq, Eq)]
pub enum SshRetryDecision {
    Return,
    Retry,
}

pub fn decide_ssh_retry(
    argv: &[&str],
    attempt: u32,
    outcome: &SshAttemptOutcome,
) -> SshRetryDecision {
    if attempt >= 2 || !idempotent_ssh_call_retryable(argv) {
        return SshRetryDecision::Return;
    }
    match outcome {
        SshAttemptOutcome::TransportFailure(_) => SshRetryDecision::Retry,
        SshAttemptOutcome::Succeeded(_) | SshAttemptOutcome::CommandFailure(_) => {
            SshRetryDecision::Return
        }
    }
}

/// The retry loop, injectable so tests can drive every outcome without ssh.
/// Emits [`ssh_retry_token`] exactly once before the single retry; the final
/// error is returned unchanged (a timeout error keeps its token, argv and
/// elapsed seconds).
pub fn run_idempotent_ssh_retry_loop(
    target: &str,
    argv: &[&str],
    mut attempt: impl FnMut() -> SshAttemptOutcome,
    mut emit: impl FnMut(&str),
) -> Result<Output, String> {
    let mut attempt_number = 1u32;
    loop {
        let outcome = attempt();
        if decide_ssh_retry(argv, attempt_number, &outcome) == SshRetryDecision::Retry {
            emit(&ssh_retry_token(target, attempt_number, outcome.reason()));
            attempt_number += 1;
            continue;
        }
        return match outcome {
            SshAttemptOutcome::Succeeded(output) => Ok(output),
            SshAttemptOutcome::TransportFailure(detail)
            | SshAttemptOutcome::CommandFailure(detail) => Err(detail),
        };
    }
}

/// Render one already-built local command's program and argv for a diagnostic
/// string. Each element is single-quoted individually, so the rendering never
/// becomes a shell string the harness would execute.
fn render_command_argv(command: &Command) -> String {
    let mut parts = vec![shell_single_quote(&command.get_program().to_string_lossy())];
    for arg in command.get_args() {
        parts.push(shell_single_quote(&arg.to_string_lossy()));
    }
    parts.join(" ")
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

// NOTE: LiveLabContext deliberately has NO Drop. Its work dir is owned by
// the shared [`WorkDirGuard`] (Arc), so the dir is removed exactly once,
// when the LAST context clone drops. A per-clone Drop here deleted the
// seeded known_hosts copy out from under every other clone
// (katana-xnet-178: `BundleSwapFence::release()` dropped its clone, and the
// W7 restore right after it failed strict host-key checking on every
// participant).

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
    // `--features vm-lab` is LOAD-BEARING, not decoration. Most `ops`
    // subcommands reached through here are `vm-lab`-gated in `main.rs`; without
    // the flag cargo builds a DEFAULT-feature binary in which they do not exist,
    // and the call fails with `unknown ops subcommand` *after* the caller's real
    // assertions have already passed — a stage that did its job records FAIL.
    // Observed live on `live_network_flap_validation` at `f22be5af`, where every
    // probe passed (recovery in 5s, tunnel active, membership intact) and only
    // the report write failed.
    //
    // This is a SAFETY NET for call sites not yet migrated. The migration is to
    // call the writer in-process instead (see
    // `rustynet_cli::ops_live_lab_orchestrator`), which makes the mismatch
    // impossible by construction rather than dependent on this argument list.
    // Converted call sites do not rely on this flag.
    let output = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
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

/// TTL every live bin pins when it (re-)issues traversal bundles: the same
/// 24 h the Setup phase distributes, so a mid-run re-issue never shortens the
/// fleet's traversal lifetime (lenovo-bot chaos runs, 2026-09-10).
pub const LAB_TRAVERSAL_TTL_SECS: &str = "86400";

#[cfg(test)]
mod tests {
    use std::process::{ExitStatus, Output};
    use std::time::{Duration, Instant};

    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt;

    use super::{
        LiveLabContext, LiveLabPlatform, MACOS_UNIFIED_LOG_WINDOW, REMOTE_RUSTYNET_BIN,
        SSH_CALL_TIMEOUT_SECS, SSH_RETRY_TOKEN, SSH_TIMEOUT_TOKEN, SshAttemptOutcome,
        SshRetryDecision, assignment_refresh_env_path, classify_ssh_attempt,
        cli_invocation_parse_failure, create_unique_work_dir, daemon_status_probe_argv,
        daemon_unit_log_argv, decide_ssh_retry, enforce_linux_only_until_validator_lands,
        enrollment_ledger_path, enrollment_secret_path, env_flag_truthy,
        idempotent_ssh_call_retryable, is_ssh_timeout_error, known_hosts_lookup_host,
        render_remote_argv, resolved_known_hosts_candidates, resolved_target_address_from_ssh_g,
        run_idempotent_ssh_retry_loop, scp_failure_is_transient, set_path_mode, ssh_timeout_error,
        stat_mode_argv, strip_host_port, target_port, terminate_process_group,
        wait_for_daemon_socket_ready, wait_for_daemon_socket_with_runner, wg_encrypted_key_paths,
    };

    /// The probe must be a full IPC round trip, bounded in the guest by the
    /// coreutils `timeout` at the fixed 15 s bound: `timeout`, the bound, then
    /// the `env` assignment and the pinned absolute binary (sudo does not
    /// inherit PATH) and `status`.
    #[test]
    fn daemon_status_probe_argv_pins_env_var_binary_and_subcommand() {
        assert_eq!(
            daemon_status_probe_argv("/run/rustynet/rustynetd.sock"),
            vec![
                "timeout".to_owned(),
                "15".to_owned(),
                "env".to_owned(),
                "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock".to_owned(),
                "/usr/local/bin/rustynet".to_owned(),
                "status".to_owned(),
            ]
        );
        assert_eq!(
            daemon_status_probe_argv("/run/rustynet/rustynetd.sock")[4],
            REMOTE_RUSTYNET_BIN,
            "the probe binary must be the deployed-guest constant"
        );
    }

    /// D1 wiring: the PUBLIC wait must wire BOTH probes into the core. With an
    /// always-answering daemon the runner sees the cheap `test -S` probe and
    /// then the exact timeout-bounded status argv — a wiring that swaps the
    /// status closure for `Ok(())` never issues the round trip and fails here.
    #[test]
    fn wired_wait_for_daemon_socket_round_trips_status_with_the_pinned_argv() {
        let calls = std::cell::RefCell::new(Vec::<Vec<String>>::new());
        let result = wait_for_daemon_socket_with_runner(
            "/run/rustynet/rustynetd.sock",
            3,
            0,
            |argv: &[&str]| {
                calls
                    .borrow_mut()
                    .push(argv.iter().map(|part| (*part).to_owned()).collect());
                Ok(())
            },
        );
        assert!(
            result.is_ok(),
            "an always-answering daemon must pass the wait: {result:?}"
        );
        assert_eq!(
            *calls.borrow(),
            vec![
                vec![
                    "test".to_owned(),
                    "-S".to_owned(),
                    "/run/rustynet/rustynetd.sock".to_owned(),
                ],
                vec![
                    "timeout".to_owned(),
                    "15".to_owned(),
                    "env".to_owned(),
                    "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock".to_owned(),
                    "/usr/local/bin/rustynet".to_owned(),
                    "status".to_owned(),
                ],
            ],
            "file probe then timeout-bounded status round trip, exactly one of each on the happy path"
        );
    }

    /// D1 wiring: a wedged daemon killed by the guest `timeout` (exit 124)
    /// must FAIL the wired wait — the probe result must propagate, the status
    /// stage must be named, and every 124 must consume one shared-budget
    /// attempt (a wiring that treats 124 as success fails here).
    #[test]
    fn wired_wait_for_daemon_socket_fails_when_the_timeout_kills_the_daemon_probe() {
        let status_probes = std::cell::RefCell::new(0usize);
        let err = wait_for_daemon_socket_with_runner(
            "/run/rustynet/rustynetd.sock",
            3,
            0,
            |argv: &[&str]| {
                if argv.first() == Some(&"test") {
                    Ok(())
                } else {
                    *status_probes.borrow_mut() += 1;
                    Err(
                        "root command failed for host-a with status 124: timeout: sending \
                         signal TERM to command 'rustynet'"
                            .to_owned(),
                    )
                }
            },
        )
        .expect_err("a wedged daemon must fail the wait, not hang it");
        assert!(
            err.contains("socket file present but the daemon did not answer status"),
            "the failed stage must be named: {err}"
        );
        assert!(
            err.contains("after 3 attempts"),
            "the attempts budget must be named: {err}"
        );
        assert!(
            err.contains("status 124"),
            "the timeout kill must be carried as a failure, not swallowed: {err}"
        );
        assert_eq!(
            *status_probes.borrow(),
            3,
            "each timeout kill consumes one attempt of the shared budget"
        );
    }

    /// Stale-socket window: `test -S` succeeds immediately on the lingering
    /// file, the first two `status` round trips hit `Connection refused`, the
    /// third succeeds — the wait must return Ok on exactly that probe.
    #[test]
    fn wait_for_daemon_socket_ready_succeeds_once_the_daemon_answers_status() {
        let file_probes = std::cell::RefCell::new(0usize);
        let status_probes = std::cell::RefCell::new(0usize);
        let sleeps = std::cell::RefCell::new(0usize);
        let result = wait_for_daemon_socket_ready(
            5,
            || {
                *file_probes.borrow_mut() += 1;
                Ok(())
            },
            || {
                let mut count = status_probes.borrow_mut();
                *count += 1;
                if *count <= 2 {
                    Err(
                        "connect /run/rustynet/rustynetd.sock failed: Connection refused"
                            .to_owned(),
                    )
                } else {
                    Ok(())
                }
            },
            || {
                *sleeps.borrow_mut() += 1;
            },
        );
        assert!(
            result.is_ok(),
            "expected Ok once the daemon answers status: {result:?}"
        );
        assert_eq!(*file_probes.borrow(), 3);
        assert_eq!(
            *status_probes.borrow(),
            3,
            "the IPC round trip must run every iteration until it succeeds"
        );
        assert_eq!(
            *sleeps.borrow(),
            2,
            "sleep between attempts only, never after the last"
        );
    }

    /// A daemon that never answers must exhaust the ONE shared budget with
    /// exactly `attempts` round trips (not `attempts` per stage) and the error
    /// must name the status stage, the budget, and carry the guest's stderr.
    #[test]
    fn wait_for_daemon_socket_ready_names_the_status_stage_when_the_daemon_never_answers() {
        let file_probes = std::cell::RefCell::new(0usize);
        let status_probes = std::cell::RefCell::new(0usize);
        let sleeps = std::cell::RefCell::new(0usize);
        let err = wait_for_daemon_socket_ready(
            3,
            || {
                *file_probes.borrow_mut() += 1;
                Ok(())
            },
            || {
                *status_probes.borrow_mut() += 1;
                Err("connect /run/rustynet/rustynetd.sock failed: Connection refused".to_owned())
            },
            || {
                *sleeps.borrow_mut() += 1;
            },
        )
        .expect_err("a daemon that never answers must fail the wait");
        assert!(
            err.contains("socket file present but the daemon did not answer status"),
            "the failed stage must be named: {err}"
        );
        assert!(
            err.contains("after 3 attempts"),
            "the attempts budget must be named: {err}"
        );
        assert!(
            err.contains("Connection refused"),
            "the guest's own stderr must be carried: {err}"
        );
        assert_eq!(*file_probes.borrow(), 3);
        assert_eq!(
            *status_probes.borrow(),
            3,
            "one shared budget: exactly `attempts` round trips, not 2×attempts"
        );
        assert_eq!(*sleeps.borrow(), 2, "sleep between attempts only");
    }

    /// While the socket file is absent no IPC round trip may be issued, and
    /// the error must name the file stage.
    #[test]
    fn wait_for_daemon_socket_ready_names_the_file_stage_and_skips_status_until_the_socket_appears()
    {
        let file_probes = std::cell::RefCell::new(0usize);
        let status_probes = std::cell::RefCell::new(0usize);
        let err = wait_for_daemon_socket_ready(
            4,
            || {
                *file_probes.borrow_mut() += 1;
                Err("remote command failed on host-a: no such file".to_owned())
            },
            || {
                *status_probes.borrow_mut() += 1;
                Ok(())
            },
            || {},
        )
        .expect_err("a socket that never appears must fail the wait");
        assert!(
            err.contains("socket file never appeared"),
            "the failed stage must be named: {err}"
        );
        assert!(
            err.contains("after 4 attempts"),
            "the attempts budget must be named: {err}"
        );
        assert_eq!(*file_probes.borrow(), 4);
        assert_eq!(
            *status_probes.borrow(),
            0,
            "no IPC round trip may be issued while the socket file is absent"
        );
    }

    /// A zero budget is clamped to one attempt rather than looping zero times.
    #[test]
    fn wait_for_daemon_socket_ready_treats_a_zero_budget_as_one_attempt() {
        let status_probes = std::cell::RefCell::new(0usize);
        let result = wait_for_daemon_socket_ready(
            0,
            || Ok(()),
            || {
                *status_probes.borrow_mut() += 1;
                Ok(())
            },
            || {},
        );
        assert!(result.is_ok());
        assert_eq!(*status_probes.borrow(), 1);
    }

    /// H2: a transport timeout is not "not ready yet". The wait must abort on
    /// the FIRST attempt and return the timeout error unchanged, so its token
    /// still gates the terminal-stall diagnostics instead of being wrapped in
    /// "socket file never appeared after N attempts".
    #[test]
    fn wait_for_daemon_socket_ready_aborts_on_the_first_transport_timeout() {
        let file_probes = std::cell::RefCell::new(0usize);
        let sleeps = std::cell::RefCell::new(0usize);
        let err = wait_for_daemon_socket_ready(
            20,
            || {
                *file_probes.borrow_mut() += 1;
                Err(ssh_timeout_error(
                    "debian@192.168.123.222:22",
                    "'test' '-S' '/run/rustynet/rustynetd.sock'",
                    SSH_CALL_TIMEOUT_SECS,
                ))
            },
            || panic!("the socket is absent, the status probe must never run"),
            || {
                *sleeps.borrow_mut() += 1;
            },
        )
        .expect_err("a transport timeout must fail the wait at once");
        assert_eq!(*file_probes.borrow(), 1, "exactly ONE attempt");
        assert_eq!(*sleeps.borrow(), 0, "no sleep after the aborting attempt");
        assert!(
            err.starts_with(SSH_TIMEOUT_TOKEN),
            "the timeout token must survive unchanged: {err}"
        );
        assert!(
            !err.contains("socket file never appeared"),
            "the timeout must not be wrapped: {err}"
        );
    }

    /// H2 negative: an ordinary "socket not there yet" error still consumes the
    /// whole budget.
    #[test]
    fn wait_for_daemon_socket_ready_still_consumes_every_attempt_for_ordinary_errors() {
        let file_probes = std::cell::RefCell::new(0usize);
        let sleeps = std::cell::RefCell::new(0usize);
        let err = wait_for_daemon_socket_ready(
            4,
            || {
                *file_probes.borrow_mut() += 1;
                Err("remote command failed on host-a: no such file".to_owned())
            },
            || Ok(()),
            || {
                *sleeps.borrow_mut() += 1;
            },
        )
        .expect_err("a socket that never appears must fail the wait");
        assert_eq!(*file_probes.borrow(), 4, "every attempt is consumed");
        assert_eq!(*sleeps.borrow(), 3, "sleep between attempts only");
        assert!(err.contains("socket file never appeared"), "{err}");
    }

    /// HARNESS-VERBS. Three stages drove `rustynet ops` subcommands that the
    /// parser does not have. Every call site used an allow-failure helper that
    /// keeps stdout only — and the CLI prints its errors to stdout — so the
    /// error text flowed on as data and the stages reported plausible results
    /// without exercising anything. The classifier is what makes that shape
    /// impossible: a command the CLI never parsed must abort the stage.
    #[test]
    fn a_verb_the_cli_does_not_have_is_classified_as_a_parse_failure() {
        // The exact stdout of the four dead calls, from the CLI's error arm.
        for verb in [
            "generate-enrollment-token",
            "consume-enrollment-token",
            "show-node-id",
            "verify-membership",
        ] {
            let stdout = format!(
                "error [bad_args (64)]: unknown ops subcommand: {verb}\n  \
                 hint: invalid CLI arguments; re-run with --help\n"
            );
            assert!(
                cli_invocation_parse_failure(64, stdout.as_str(), "").is_some(),
                "`ops {verb}` must be classified as a parse failure"
            );
        }
        // Other shapes of the same defect.
        assert!(
            cli_invocation_parse_failure(
                64,
                "error [bad_args (64)]: unknown command: peer list\n",
                ""
            )
            .is_some()
        );
        assert!(
            cli_invocation_parse_failure(
                64,
                "error [bad_args (64)]: unknown enrollment subcommand: consume-token\n",
                ""
            )
            .is_some()
        );
        // A wrong FLAG on a real verb is equally a wiring defect: `--ttl-seconds`
        // does not exist, the real flag is `--ttl`.
        assert!(
            cli_invocation_parse_failure(
                64,
                "error [bad_args (64)]: --ttl <secs> is required\n",
                ""
            )
            .is_some()
        );
        // A missing binary — what a bare-name argv head does on the RHEL family.
        assert!(
            cli_invocation_parse_failure(127, "", "sudo: rustynet: command not found\n").is_some()
        );
    }

    /// The other half: a REAL live result must not be mistaken for a wiring
    /// defect, or the stage would abort on a legitimate lab observation.
    #[test]
    fn a_genuine_live_failure_is_not_classified_as_a_parse_failure() {
        assert!(
            cli_invocation_parse_failure(
                0,
                "membership log verification passed: entries=3 epoch=2 audit=/tmp/a.log\n",
                ""
            )
            .is_none()
        );
        assert!(
            cli_invocation_parse_failure(
                0,
                "enrollment accepted node=0a1b2c3d4e5f6071 expires_at_unix=1790000000\n",
                ""
            )
            .is_none()
        );
        // The daemon refusing the token is a live answer, not a wiring defect.
        assert!(
            cli_invocation_parse_failure(
                1,
                "error [generic_failure (1)]: enrollment token rejected\n",
                ""
            )
            .is_none()
        );
        assert!(
            cli_invocation_parse_failure(
                1,
                "error [generic_failure (1)]: daemon unreachable: connection refused\n",
                ""
            )
            .is_none()
        );
        // A config-error exit (65) is a real state, not a bad argv.
        assert!(
            cli_invocation_parse_failure(
                65,
                "error [config_error (65)]: membership snapshot missing\n",
                ""
            )
            .is_none()
        );
    }

    /// QH-61 regression lock: no live-lab stage binary may spawn `rustynet` by
    /// bare name. Rocky's sudo `secure_path` omits `/usr/local/bin`, so a bare
    /// head dies as "command not found" the moment a role lands on a RHEL-family
    /// guest while Debian silently masks it (proven live, run
    /// `qh57-lantoggle-20260816a`). Every stage binary that drives guests
    /// through this support layer is listed here; the needle is assembled at
    /// runtime so this file cannot satisfy its own negative assertion.
    #[test]
    fn stage_binaries_never_spawn_rustynet_by_bare_name() {
        let sources: [(&str, &str); 10] = [
            (
                "live_linux_lan_toggle_test.rs",
                include_str!("../live_linux_lan_toggle_test.rs"),
            ),
            // Added with HARNESS-VERBS: this stage drove a bare `"rustynet"`
            // argv head and was simply missing from the list, so QH-61 never
            // saw it.
            (
                "live_linux_secrets_not_in_logs_test.rs",
                include_str!("../live_linux_secrets_not_in_logs_test.rs"),
            ),
            (
                "live_linux_enrollment_restart_test.rs",
                include_str!("../live_linux_enrollment_restart_test.rs"),
            ),
            (
                "live_linux_reboot_recovery_test.rs",
                include_str!("../live_linux_reboot_recovery_test.rs"),
            ),
            (
                "live_linux_network_flap_test.rs",
                include_str!("../live_linux_network_flap_test.rs"),
            ),
            (
                "live_linux_control_surface_exposure_test.rs",
                include_str!("../live_linux_control_surface_exposure_test.rs"),
            ),
            (
                "live_linux_endpoint_hijack_test.rs",
                include_str!("../live_linux_endpoint_hijack_test.rs"),
            ),
            (
                "live_linux_server_ip_bypass_test.rs",
                include_str!("../live_linux_server_ip_bypass_test.rs"),
            ),
            (
                "live_linux_two_hop_test.rs",
                include_str!("../live_linux_two_hop_test.rs"),
            ),
            (
                "live_linux_managed_dns_test.rs",
                include_str!("../live_linux_managed_dns_test.rs"),
            ),
        ];
        // The banned shape is a bare "rustynet" string literal as an argv head.
        let needle = format!("\"{}\",", "rustynet");
        let mut offenders = Vec::new();
        for (name, source) in sources {
            // Only inspect the production half: test modules legitimately
            // build fake shells around bare names.
            let production = source
                .find("#[cfg(test)]")
                .map(|at| &source[..at])
                .unwrap_or(source);
            let hits = production.matches(needle.as_str()).count();
            if hits > 0 {
                offenders.push(format!("{name}: {hits} bare `rustynet` argv head(s)"));
            }
        }
        assert!(
            offenders.is_empty(),
            "use REMOTE_RUSTYNET_BIN, never a bare `rustynet` argv head (QH-61): {offenders:?}"
        );
    }

    /// HARNESS-VERBS regression lock. Four `ops` subcommands were driven by
    /// three stage binaries and none of them exists in the parser
    /// (`crates/rustynet-cli/src/main.rs`, `parse_ops_command`): the real verbs
    /// are `enrollment mint`, `enrollment consume`, `status` (for the node id)
    /// and `membership verify`. `--ttl-seconds` is pinned with them because the
    /// real flag is `--ttl`, and a wrong flag fails exactly the same way a wrong
    /// verb does.
    ///
    /// As with the QH-61 lock above, the needles are assembled at runtime so
    /// this file cannot satisfy its own negative assertion, and the shape
    /// matched is a QUOTED argv token — prose in a comment explaining what was
    /// removed must not trip it.
    #[test]
    fn stage_binaries_never_drive_ops_verbs_the_parser_does_not_have() {
        let sources: [(&str, &str); 3] = [
            (
                "live_linux_enrollment_restart_test.rs",
                include_str!("../live_linux_enrollment_restart_test.rs"),
            ),
            (
                "live_linux_secrets_not_in_logs_test.rs",
                include_str!("../live_linux_secrets_not_in_logs_test.rs"),
            ),
            (
                "live_linux_network_flap_test.rs",
                include_str!("../live_linux_network_flap_test.rs"),
            ),
        ];
        let dead_tokens = [
            format!("{}-enrollment-token", "generate"),
            format!("{}-enrollment-token", "consume"),
            format!("{}-node-id", "show"),
            format!("{}-membership", "verify"),
            format!("--{}-seconds", "ttl"),
        ];
        let mut offenders = Vec::new();
        for (name, source) in sources {
            let production = source
                .find("#[cfg(test)]")
                .map(|at| &source[..at])
                .unwrap_or(source);
            for token in &dead_tokens {
                let needle = format!("\"{token}\"");
                if production.contains(needle.as_str()) {
                    offenders.push(format!("{name}: argv token {needle}"));
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "these argv tokens do not exist in the CLI parser; a stage driving one \
             proves nothing (HARNESS-VERBS): {offenders:?}"
        );
    }

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

    #[test]
    fn enrollment_secret_paths_match_the_deployed_daemon_seeded_locations() {
        assert_eq!(
            enrollment_secret_path(LiveLabPlatform::Linux).expect("linux"),
            "/var/lib/rustynet/keys/enrollment.secret",
            "the Linux path is byte-identical to the pre-port const"
        );
        assert_eq!(
            enrollment_secret_path(LiveLabPlatform::MacOs).expect("macos"),
            "/usr/local/var/rustynet/keys/enrollment.secret",
            "the launchd plist passes ${{STATE_ROOT}}/keys/enrollment.secret"
        );
        let err = enrollment_secret_path(LiveLabPlatform::Windows).expect_err("fail closed");
        assert!(err.contains("windows"), "{err}");
    }

    #[test]
    fn enrollment_ledger_paths_match_the_daemon_passed_locations() {
        assert_eq!(
            enrollment_ledger_path(LiveLabPlatform::Linux).expect("linux"),
            "/var/lib/rustynet/rustynetd.enrollment.ledger"
        );
        assert_eq!(
            enrollment_ledger_path(LiveLabPlatform::MacOs).expect("macos"),
            "/usr/local/var/rustynet/keys/rustynetd.enrollment.ledger"
        );
        assert!(enrollment_ledger_path(LiveLabPlatform::Windows).is_err());
    }

    #[test]
    fn wg_encrypted_key_paths_match_the_reviewed_custody_layout() {
        let (linux_key, linux_dir) = wg_encrypted_key_paths(LiveLabPlatform::Linux).expect("linux");
        assert_eq!(linux_key, "/var/lib/rustynet/keys/wireguard.key.enc");
        assert_eq!(linux_dir, "/var/lib/rustynet/keys");
        let (mac_key, mac_dir) = wg_encrypted_key_paths(LiveLabPlatform::MacOs).expect("macos");
        assert_eq!(
            mac_key, "/usr/local/var/rustynet/keys/wireguard.key.enc",
            "mirrors macos_key_custody::MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH"
        );
        assert_eq!(mac_dir, "/usr/local/var/rustynet/keys");
        let err = wg_encrypted_key_paths(LiveLabPlatform::Windows).expect_err("fail closed");
        assert!(err.contains("in-memory/DPAPI"), "{err}");
    }

    #[test]
    fn assignment_refresh_env_paths_match_the_shell_lab_precedent() {
        assert_eq!(
            assignment_refresh_env_path(LiveLabPlatform::Linux).expect("linux"),
            "/etc/rustynet/assignment-refresh.env"
        );
        assert_eq!(
            assignment_refresh_env_path(LiveLabPlatform::MacOs).expect("macos"),
            "/usr/local/etc/rustynet/assignment-refresh.env",
            "matches live_lab_common.sh assignment_refresh_env_path"
        );
        assert_eq!(
            assignment_refresh_env_path(LiveLabPlatform::Windows).expect("windows"),
            "C:\\ProgramData\\RustyNet\\config\\assignment-refresh.env"
        );
    }

    #[test]
    fn stat_mode_argv_prints_bare_octal_on_both_posix_platforms() {
        assert_eq!(
            stat_mode_argv(
                LiveLabPlatform::Linux,
                "/var/lib/rustynet/keys/wireguard.key.enc"
            )
            .expect("linux"),
            vec![
                "stat",
                "--format=%a",
                "/var/lib/rustynet/keys/wireguard.key.enc"
            ],
            "byte-identical to the pre-port GNU stat argv"
        );
        assert_eq!(
            stat_mode_argv(
                LiveLabPlatform::MacOs,
                "/usr/local/var/rustynet/keys/wireguard.key.enc"
            )
            .expect("macos"),
            vec![
                "stat",
                "-f",
                "%Lp",
                "/usr/local/var/rustynet/keys/wireguard.key.enc"
            ],
            "BSD stat -f %Lp prints the same bare-octal shape"
        );
        assert!(stat_mode_argv(LiveLabPlatform::Windows, "C:\\key").is_err());
    }

    #[test]
    fn daemon_unit_log_argv_linux_is_byte_identical_to_the_pre_port_journalctl() {
        assert_eq!(
            daemon_unit_log_argv(LiveLabPlatform::Linux, "500", true).expect("linux"),
            vec![vec![
                "journalctl",
                "-u",
                "rustynetd",
                "-n",
                "500",
                "--no-pager",
                "--output=short-monotonic",
            ]],
            "the secrets stage's journald argv must not change"
        );
        assert_eq!(
            daemon_unit_log_argv(LiveLabPlatform::Linux, "50", false).expect("linux"),
            vec![vec![
                "journalctl",
                "-u",
                "rustynetd",
                "-n",
                "50",
                "--no-pager",
            ]],
            "the custody stage's journald argv must not change"
        );
    }

    #[test]
    fn daemon_unit_log_argv_macos_scans_unified_log_and_launchd_log_files() {
        // D6 (review macos-harness-b): the full macOS argv vectors are pinned
        // byte-for-byte, exactly like the Linux twin above, so a silent argv
        // regression on the macOS half cannot survive the test suite.
        assert_eq!(
            daemon_unit_log_argv(LiveLabPlatform::MacOs, "500", true).expect("macos"),
            vec![
                vec![
                    "/usr/bin/log",
                    "show",
                    "--last",
                    "15m",
                    "--predicate",
                    "process == \"rustynetd\"",
                    "--style",
                    "compact",
                ],
                vec![
                    "/usr/bin/tail",
                    "-n",
                    "500",
                    "/usr/local/var/log/rustynet/rustynetd.log",
                ],
                vec![
                    "/usr/bin/tail",
                    "-n",
                    "500",
                    "/usr/local/var/log/rustynet/rustynetd-error.log",
                ],
            ],
            "unified log + stdout + stderr files; the fixed --last 15m window \
             and the launchd log paths must not drift"
        );
        // The two tail chunks honour the `lines` argument; the unified-log
        // chunk keeps its documented fixed window (MACOS_UNIFIED_LOG_WINDOW).
        let chunks50 = daemon_unit_log_argv(LiveLabPlatform::MacOs, "50", false).expect("macos");
        assert_eq!(chunks50.len(), 3, "unified log + stdout + stderr files");
        assert_eq!(
            chunks50[0],
            vec![
                "/usr/bin/log",
                "show",
                "--last",
                MACOS_UNIFIED_LOG_WINDOW,
                "--predicate",
                "process == \"rustynetd\"",
                "--style",
                "compact",
            ],
            "the unified-log window is fixed and documented, not derived from `lines`"
        );
        assert_eq!(chunks50[1][2], "50", "tail chunks honour `lines`");
        assert_eq!(chunks50[2][2], "50", "tail chunks honour `lines`");
        assert!(daemon_unit_log_argv(LiveLabPlatform::Windows, "50", false).is_err());
    }

    /// A deterministic ed25519 host key line for the test pinned known_hosts
    /// file (`ssh-keygen -F` looks the host up by name, so any well-formed
    /// line works; this blob is a real key so even strict tooling parses it).
    const TEST_KNOWN_HOSTS_LINE: &str = "192.0.2.10 ssh-ed25519 \
AAAAC3NzaC1lZDI1NTE5AAAAIHaDU9pi11/BAvWNTqDiDD9hbS2Hl3gnRcKCx6lWl3mS w11-test-vector";

    fn write_test_identity_and_pinned(
        dir: &std::path::Path,
    ) -> Result<(std::path::PathBuf, std::path::PathBuf), String> {
        let identity = dir.join("identity");
        std::fs::write(&identity, "not-a-real-key\n")
            .map_err(|err| format!("write test identity: {err}"))?;
        set_path_mode(&identity, 0o600)?;
        let pinned = dir.join("pinned_known_hosts");
        std::fs::write(&pinned, format!("{TEST_KNOWN_HOSTS_LINE}\n"))
            .map_err(|err| format!("write test pinned known_hosts: {err}"))?;
        set_path_mode(&pinned, 0o644)?;
        Ok((identity, pinned))
    }

    /// THE katana-xnet-178 witness: `LiveLabContext` is cloned by cleanup
    /// guards and RAII fences (the bundle-swap fence holds its own copy and
    /// `release()` consumes it), so dropping ONE clone must never delete the
    /// work dir the other clones still ssh out of. With the old per-clone
    /// `impl Drop`, the clone's drop removed the seeded known_hosts copy and
    /// every later call — the W7 restore — failed with "No ED25519 host key
    /// is known ... Host key verification failed."
    #[test]
    fn cloned_context_drop_keeps_the_seeded_known_hosts_context() {
        let holder = create_unique_work_dir("w11-known-hosts-witness").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ctx = LiveLabContext::new_with_pinned_known_hosts(
            "w11-known-hosts-witness-ctx",
            &identity,
            Some(&pinned),
        )
        .expect("context");
        assert!(ctx.known_hosts_file.is_file(), "seeded known_hosts copy");

        let clone = ctx.clone();
        drop(clone);

        assert!(
            ctx.known_hosts_file.is_file(),
            "dropping one clone must not delete the shared known_hosts copy at {}",
            ctx.known_hosts_file.display()
        );
        assert!(
            ctx.work_dir.is_dir(),
            "shared work dir must survive a clone drop"
        );

        // The seeded copy must still carry the pinned entry the strict
        // transport trusts (byte copy of the pinned file).
        let seeded =
            std::fs::read_to_string(&ctx.known_hosts_file).expect("read seeded known_hosts");
        assert_eq!(seeded, format!("{TEST_KNOWN_HOSTS_LINE}\n"));

        // Explicit cleanup still removes the shared dir exactly once.
        ctx.cleanup();
        assert!(
            !ctx.work_dir.exists(),
            "explicit cleanup removes the work dir"
        );
    }

    /// Every transport option list pins StrictHostKeyChecking to `yes` and
    /// the trusted host-key context to THIS run's seeded work-dir copy — the
    /// exact options the restore must share with capture/install.
    #[test]
    fn transport_option_argv_pins_strict_checking_to_the_seeded_known_hosts_copy() {
        let holder = create_unique_work_dir("w11-transport-options").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ctx = LiveLabContext::new_with_pinned_known_hosts(
            "w11-transport-options-ctx",
            &identity,
            Some(&pinned),
        )
        .expect("context");

        let options = ctx.transport_option_argv();
        let text: Vec<String> = options
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        let joined = text.join(" ");
        assert!(
            text.windows(2)
                .any(|pair| pair[0] == "-o" && pair[1] == "StrictHostKeyChecking=yes"),
            "strict checking must stay yes: {joined}"
        );
        assert!(
            !joined.contains("StrictHostKeyChecking=accept-new")
                && !joined.contains("StrictHostKeyChecking=no"),
            "checking must never be weakened: {joined}"
        );
        let expected_user_known_hosts =
            format!("UserKnownHostsFile={}", ctx.known_hosts_file.display());
        assert!(
            text.iter()
                .any(|value| value.as_str() == expected_user_known_hosts),
            "the trusted context must be the seeded work-dir copy, not the default file: {joined}"
        );
        assert!(
            text.windows(2)
                .any(|pair| pair[0] == "-i" && pair[1] == ctx.ssh_identity_file.to_string_lossy()),
            "the identity file must be pinned: {joined}"
        );
        assert!(
            text.windows(2)
                .any(|pair| pair[0] == "-o" && pair[1] == "BatchMode=yes"),
            "batch mode keeps a broken transport failing fast: {joined}"
        );
    }

    /// GOLDEN ARGV: every ssh invocation carries the connect/keepalive bounds
    /// the code can express. They do NOT bound a pre-authentication stall
    /// (`ConnectTimeout` stops at the banner; `ServerAlive*` is not sent before
    /// auth), which is why the outer wall clock below is the load-bearing
    /// bound — but they must never disappear.
    #[test]
    fn transport_options_carry_the_connect_and_keepalive_bounds() {
        let holder = create_unique_work_dir("w11-transport-bounds").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ctx = LiveLabContext::new_with_pinned_known_hosts(
            "w11-transport-bounds-ctx",
            &identity,
            Some(&pinned),
        )
        .expect("context");
        let text: Vec<String> = ctx
            .transport_option_argv()
            .iter()
            .map(|value| value.to_string_lossy().into_owned())
            .collect();
        let joined = text.join(" ");
        for expected in [
            "ConnectTimeout=15",
            "ServerAliveInterval=60",
            "ServerAliveCountMax=10",
        ] {
            assert!(
                text.windows(2)
                    .any(|pair| pair[0] == "-o" && pair[1] == expected),
                "{expected} must stay on every ssh call: {joined}"
            );
        }
    }

    /// DARK BY DEFAULT: a context that does not opt in keeps the exact pre-fix
    /// `Command::output()` path, so no other live stage changes behaviour.
    #[cfg(unix)]
    #[test]
    fn ssh_call_timeout_is_dark_by_default() {
        let holder = create_unique_work_dir("w11-ssh-timeout-dark").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ssh = holder.join("instant-ssh");
        std::fs::write(&ssh, "#!/bin/sh\nexit 0\n").expect("write fake ssh");
        set_path_mode(&ssh, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-ssh-timeout-dark-ctx",
            &identity,
            Some(&pinned),
            ssh.clone(),
            ssh,
        )
        .expect("context");
        assert!(
            ctx.ssh_call_timeout.is_none(),
            "the outer wall clock must be opt-in (byte-equal default)"
        );
        let output = ctx
            .run_allow_failure("debian@192.0.2.10:22", &["true"])
            .expect("the unchanged path still runs");
        assert!(output.status.success());
    }

    /// THE FIX: a transport that completes and then stalls is killed by the
    /// outer wall clock, and the error names the target, the elapsed seconds
    /// and the argv. Before the fix this test hangs until the fake sleeps out.
    #[cfg(unix)]
    #[test]
    fn bounded_ssh_call_kills_a_stalling_transport_and_names_the_argv() {
        let holder = create_unique_work_dir("w11-ssh-timeout-bounded").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ssh = holder.join("stalling-ssh");
        std::fs::write(&ssh, "#!/bin/sh\nsleep 30\n").expect("write fake ssh");
        set_path_mode(&ssh, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-ssh-timeout-bounded-ctx",
            &identity,
            Some(&pinned),
            ssh.clone(),
            ssh,
        )
        .expect("context")
        .with_ssh_call_timeout(Duration::from_secs(1));

        let started = Instant::now();
        let err = ctx
            .run(
                "debian@192.0.2.10:22",
                &["systemctl", "restart", "rustynetd.service"],
            )
            .expect_err("a stalled ssh call must be killed, not waited out");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the outer wall clock must bound the call, took {:?}",
            started.elapsed()
        );
        assert!(
            err.starts_with(SSH_TIMEOUT_TOKEN),
            "the terminal error must carry the stable token: {err}"
        );
        assert!(err.contains("target=debian@192.0.2.10:22"), "{err}");
        assert!(err.contains("elapsed="), "{err}");
        assert!(
            err.contains("systemctl") && err.contains("rustynetd.service"),
            "the terminal error must name the stalled argv: {err}"
        );
    }

    #[test]
    fn idempotent_retry_allowlist_is_exactly_the_restart_and_probe_calls() {
        for allowed in [
            vec![
                REMOTE_RUSTYNET_BIN,
                "ops",
                "e2e-enforce-host",
                "--role",
                "client",
                "--node-id",
                "node-1",
                "--src-dir",
                "/home/debian/Rustynet",
                "--ssh-allow-cidrs",
                "192.168.123.0/24",
            ],
            vec!["systemctl", "reset-failed", "rustynetd.service"],
            vec![
                "systemctl",
                "restart",
                "rustynetd-privileged-helper.service",
            ],
            vec!["systemctl", "restart", "rustynetd.service"],
            vec!["systemctl", "is-active", "rustynetd.service"],
            vec!["test", "-S", "/run/rustynet/rustynetd.sock"],
        ] {
            assert!(
                idempotent_ssh_call_retryable(&allowed),
                "must be retryable: {allowed:?}"
            );
        }
        for refused in [
            vec!["systemctl", "stop", "rustynetd.service"],
            vec!["systemctl", "restart", "some-other.service"],
            vec!["rustynet", "ops", "e2e-enforce-host"],
            vec!["/tmp/other", "ops", "e2e-enforce-host"],
            vec![
                REMOTE_RUSTYNET_BIN,
                "ops",
                "install-systemd",
                "--role",
                "client",
            ],
            vec!["rm", "-f", "/run/rustynet/rustynetd.sock"],
            vec!["test", "-e", "/run/rustynet/rustynetd.sock"],
        ] {
            assert!(
                !idempotent_ssh_call_retryable(&refused),
                "must never be retried: {refused:?}"
            );
        }
    }

    fn transport_failure() -> SshAttemptOutcome {
        SshAttemptOutcome::TransportFailure(format!(
            "{SSH_TIMEOUT_TOKEN} target=x elapsed=60s argv='systemctl'"
        ))
    }

    fn command_failure() -> SshAttemptOutcome {
        SshAttemptOutcome::CommandFailure(
            "remote command failed on x: Unit rustynetd.service not found".to_owned(),
        )
    }

    #[test]
    fn retry_decision_allows_exactly_one_transport_retry() {
        let argv = ["systemctl", "restart", "rustynetd.service"];
        assert_eq!(
            decide_ssh_retry(&argv, 1, &transport_failure()),
            SshRetryDecision::Retry
        );
        assert_eq!(
            decide_ssh_retry(&argv, 2, &transport_failure()),
            SshRetryDecision::Return,
            "at most ONE retry"
        );
        let not_allowlisted = ["systemctl", "stop", "rustynetd.service"];
        assert_eq!(
            decide_ssh_retry(&not_allowlisted, 1, &transport_failure()),
            SshRetryDecision::Return,
            "a non-idempotent call is never retried"
        );
    }

    #[test]
    fn retry_decision_never_retries_a_real_command_failure() {
        let argv = ["systemctl", "restart", "rustynetd.service"];
        assert_eq!(
            decide_ssh_retry(&argv, 1, &command_failure()),
            SshRetryDecision::Return,
            "a real remote command failure must surface immediately"
        );
    }

    #[cfg(unix)]
    #[test]
    fn classify_ssh_attempt_treats_only_ssh_exit_255_as_transport() {
        let output = |code: i32| Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        assert!(matches!(
            classify_ssh_attempt("t", Ok(output(0))),
            SshAttemptOutcome::Succeeded(_)
        ));
        assert!(matches!(
            classify_ssh_attempt("t", Ok(output(255))),
            SshAttemptOutcome::TransportFailure(_)
        ));
        assert!(matches!(
            classify_ssh_attempt("t", Ok(output(1))),
            SshAttemptOutcome::CommandFailure(_)
        ));
        assert!(matches!(
            classify_ssh_attempt(
                "t",
                Err(ssh_timeout_error("t", "'x'", SSH_CALL_TIMEOUT_SECS))
            ),
            SshAttemptOutcome::TransportFailure(_)
        ));
        assert!(
            matches!(
                classify_ssh_attempt(
                    "t",
                    Err("pinned known_hosts file lacks host key".to_owned())
                ),
                SshAttemptOutcome::CommandFailure(_)
            ),
            "L8: a non-timeout Err must not be classified as transport"
        );
    }

    #[test]
    fn retry_loop_logs_one_token_then_returns_the_second_terminal_error() {
        let argv = ["systemctl", "restart", "rustynetd.service"];
        let mut calls = 0u32;
        let mut emitted: Vec<String> = Vec::new();
        let err = run_idempotent_ssh_retry_loop(
            "debian@192.0.2.10:22",
            &argv,
            || {
                calls += 1;
                SshAttemptOutcome::TransportFailure(format!(
                    "{SSH_TIMEOUT_TOKEN} target=debian@192.0.2.10:22 elapsed=60s argv=call{calls}"
                ))
            },
            |line| emitted.push(line.to_owned()),
        )
        .expect_err("both attempts time out");
        assert_eq!(calls, 2, "exactly one retry");
        assert_eq!(emitted.len(), 1, "exactly one retry log line");
        assert!(emitted[0].starts_with(SSH_RETRY_TOKEN), "{}", emitted[0]);
        assert!(emitted[0].contains("attempt=1"), "{}", emitted[0]);
        assert!(emitted[0].contains("reason=timeout"), "{}", emitted[0]);
        assert!(
            err.contains("argv=call2"),
            "the terminal error is the last attempt, unchanged: {err}"
        );
    }

    #[test]
    fn retry_loop_never_retries_a_real_command_failure() {
        let argv = ["systemctl", "restart", "rustynetd.service"];
        let mut calls = 0u32;
        let mut emitted: Vec<String> = Vec::new();
        let err = run_idempotent_ssh_retry_loop(
            "t",
            &argv,
            || {
                calls += 1;
                command_failure()
            },
            |line| emitted.push(line.to_owned()),
        )
        .expect_err("a real failure is returned");
        assert_eq!(calls, 1, "a command failure is never retried");
        assert!(emitted.is_empty(), "no retry token for a command failure");
        assert!(err.contains("Unit rustynetd.service not found"), "{err}");
    }

    /// M4: the outer bound must be the reviewed 150 s, not the round-1 60 s
    /// (too tight for a 90 s unit stop and a ~23 s healthy enforce) and not a
    /// value so large it no longer bounds the observed ~5.5 min stall.
    #[test]
    fn ssh_call_timeout_is_the_reviewed_150_seconds() {
        assert_eq!(SSH_CALL_TIMEOUT_SECS, 150);
    }

    /// H1: a healthy command that writes more than the pipe capacity on BOTH
    /// streams must complete with every byte collected. Before the drain
    /// threads this deadlocked at ~64 KiB and was falsely killed at the bound.
    #[cfg(unix)]
    #[test]
    fn bounded_ssh_call_drains_more_than_a_pipe_of_output_on_both_streams() {
        let holder = create_unique_work_dir("w11-ssh-drain").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ssh = holder.join("chatty-ssh");
        std::fs::write(
            &ssh,
            "#!/bin/sh\n\
             head -c 204800 /dev/zero\n\
             head -c 204800 /dev/zero >&2\n\
             exit 0\n",
        )
        .expect("write fake ssh");
        set_path_mode(&ssh, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-ssh-drain-ctx",
            &identity,
            Some(&pinned),
            ssh.clone(),
            ssh,
        )
        .expect("context")
        .with_ssh_call_timeout(Duration::from_secs(5));
        let started = Instant::now();
        let output = ctx
            .run_allow_failure("debian@192.0.2.10:22", &["true"])
            .expect("a chatty but healthy command must not time out");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "draining must let the child finish before the bound, took {:?}",
            started.elapsed()
        );
        assert_eq!(output.stdout.len(), 204_800, "all stdout bytes collected");
        assert_eq!(output.stderr.len(), 204_800, "all stderr bytes collected");
    }

    /// H1: draining must not mask a real stall: some output then no exit still
    /// hits the wall clock and keeps the token.
    #[cfg(unix)]
    #[test]
    fn bounded_ssh_call_still_times_out_a_child_that_writes_then_stalls() {
        let holder = create_unique_work_dir("w11-ssh-drain-stall").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let ssh = holder.join("chatty-stalling-ssh");
        std::fs::write(
            &ssh,
            "#!/bin/sh\ndd if=/dev/zero bs=1024 count=1 2>/dev/null\nsleep 30\n",
        )
        .expect("write fake ssh");
        set_path_mode(&ssh, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-ssh-drain-stall-ctx",
            &identity,
            Some(&pinned),
            ssh.clone(),
            ssh,
        )
        .expect("context")
        .with_ssh_call_timeout(Duration::from_secs(1));
        let started = Instant::now();
        let err = ctx
            .run("debian@192.0.2.10:22", &["true"])
            .expect_err("a child that writes then stalls must time out");
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "the bound must still cut the stall, took {:?}",
            started.elapsed()
        );
        assert!(err.starts_with(SSH_TIMEOUT_TOKEN), "{err}");
    }

    /// L7: a group kill that cannot run (missing/broken `kill`) must not
    /// restore the unbounded wait. The unconditional `child.kill()` fallback
    /// plus the bounded reap still terminate and reap the direct child.
    #[cfg(unix)]
    #[test]
    fn a_failed_group_kill_still_reaps_the_child_through_the_direct_kill_fallback() {
        use std::os::unix::process::CommandExt;
        let mut command = std::process::Command::new("sleep");
        command.arg("30").process_group(0);
        let mut child = command.spawn().expect("spawn sleep");
        let started = Instant::now();
        terminate_process_group(&mut child, "/definitely/not/a/kill/program");
        let status = child.try_wait().expect("try_wait after terminate");
        assert!(
            status.is_some(),
            "the direct child must be killed and reaped even without a working group kill"
        );
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the fallback reap must be bounded, took {:?}",
            started.elapsed()
        );
    }

    /// TEST GAP (process-group property): a fake ssh that forks a grandchild
    /// must have BOTH killed. Replacing the group kill with `child.kill()`
    /// alone leaves the grandchild alive and fails this test.
    #[cfg(unix)]
    #[test]
    fn the_wall_clock_kills_the_whole_process_group_including_a_grandchild() {
        let holder = create_unique_work_dir("w11-ssh-group-kill").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let pid_file = holder.join("grandchild.pid");
        let ssh = holder.join("forking-ssh");
        std::fs::write(
            &ssh,
            format!(
                "#!/bin/sh\nsleep 30 &\necho $! > '{}'\nwait\n",
                pid_file.display()
            ),
        )
        .expect("write fake ssh");
        set_path_mode(&ssh, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-ssh-group-kill-ctx",
            &identity,
            Some(&pinned),
            ssh.clone(),
            ssh,
        )
        .expect("context")
        .with_ssh_call_timeout(Duration::from_secs(1));
        let err = ctx
            .run("debian@192.0.2.10:22", &["true"])
            .expect_err("the forking transport must time out");
        assert!(err.starts_with(SSH_TIMEOUT_TOKEN), "{err}");
        let grandchild_pid: u32 = std::fs::read_to_string(&pid_file)
            .expect("grandchild pid file")
            .trim()
            .parse()
            .expect("grandchild pid");
        let alive = |pid: u32| {
            std::process::Command::new("kill")
                .arg("-0")
                .arg(pid.to_string())
                .status()
                .is_ok_and(|status| status.success())
        };
        let mut still_alive = true;
        for _ in 0..20 {
            if !alive(grandchild_pid) {
                still_alive = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if still_alive {
            let _ = std::process::Command::new("kill")
                .arg("-9")
                .arg(grandchild_pid.to_string())
                .status();
        }
        assert!(
            !still_alive,
            "grandchild {grandchild_pid} survived the process-group kill"
        );
    }

    /// M5: when the context opts in, scp runs under the same wall clock, a
    /// timed-out attempt is retried through the existing budget, and the
    /// terminal error still starts with the timeout token.
    #[cfg(unix)]
    #[test]
    fn opt_in_scp_is_bounded_and_retried_then_returns_the_timeout_token() {
        let holder = create_unique_work_dir("w11-scp-bounded").expect("holder dir");
        let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
        let counter = holder.join("scp-calls");
        let scp = holder.join("stalling-scp");
        std::fs::write(
            &scp,
            format!("#!/bin/sh\nprintf x >> '{}'\nsleep 30\n", counter.display()),
        )
        .expect("write fake scp");
        set_path_mode(&scp, 0o700).expect("mode");
        let ctx = LiveLabContext::with_transport_programs_for_tests(
            "w11-scp-bounded-ctx",
            &identity,
            Some(&pinned),
            scp.clone(),
            scp,
        )
        .expect("context")
        .with_ssh_call_timeout(Duration::from_secs(1));
        let src = holder.join("payload");
        std::fs::write(&src, "payload\n").expect("write payload");
        let started = Instant::now();
        let err = ctx
            .scp_to(&src, "debian@192.0.2.10:22", "/tmp/payload")
            .expect_err("a stalling scp must be cut by the bound");
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "the bound must cut every attempt, took {:?}",
            started.elapsed()
        );
        assert!(
            err.starts_with(SSH_TIMEOUT_TOKEN),
            "the terminal scp error must keep the timeout token: {err}"
        );
        let calls = std::fs::read_to_string(&counter).expect("scp call counter");
        assert_eq!(
            calls.len(),
            3,
            "the existing SCP_RETRY_ATTEMPTS budget must be used, got {calls:?}"
        );
    }

    /// TEST GAP: end-to-end classification through the retry wrapper. A
    /// transport timeout is retried exactly once and the terminal error keeps
    /// the token; an ssh exit 255 is also retried once.
    #[cfg(unix)]
    #[test]
    fn run_root_idempotent_retry_classifies_timeout_and_exit_255_end_to_end() {
        for (script, expected_token) in [
            ("#!/bin/sh\nprintf x >> CALLS_PLACEHOLDER\nsleep 30\n", true),
            (
                "#!/bin/sh\nprintf x >> CALLS_PLACEHOLDER\nexit 255\n",
                false,
            ),
        ] {
            // The counter path is embedded rather than passed through the
            // environment (the harness never mutates env in these tests).
            let holder = create_unique_work_dir("w11-retry-e2e").expect("holder dir");
            let (identity, pinned) = write_test_identity_and_pinned(&holder).expect("test files");
            let counter = holder.join("calls");
            let ssh = holder.join("fake-ssh");
            let script = script.replace("CALLS_PLACEHOLDER", &format!("'{}'", counter.display()));
            std::fs::write(&ssh, script).expect("write fake ssh");
            set_path_mode(&ssh, 0o700).expect("mode");
            let ctx = LiveLabContext::with_transport_programs_for_tests(
                "w11-retry-e2e-ctx",
                &identity,
                Some(&pinned),
                ssh.clone(),
                ssh,
            )
            .expect("context")
            .with_ssh_call_timeout(Duration::from_secs(1));
            let started = Instant::now();
            let err = ctx
                .run_root_idempotent_retry(
                    "debian@192.0.2.10:22",
                    &["systemctl", "restart", "rustynetd.service"],
                )
                .expect_err("both attempts fail");
            assert!(
                started.elapsed() < Duration::from_secs(15),
                "the bound must cap the retry path, took {:?}",
                started.elapsed()
            );
            let calls = std::fs::read_to_string(&counter).expect("call counter");
            assert_eq!(calls.len(), 2, "exactly one retry: {calls}");
            if expected_token {
                assert!(err.starts_with(SSH_TIMEOUT_TOKEN), "{err}");
            } else {
                assert!(
                    err.starts_with("remote command failed on"),
                    "exit 255 is a transport failure with the normal message: {err}"
                );
            }
        }
    }

    #[test]
    fn timeout_error_names_the_target_elapsed_and_each_argv_element() {
        let rendered = render_remote_argv(&["systemctl", "restart", "rustynetd.service"])
            .expect("render argv");
        let err = ssh_timeout_error("debian@192.168.123.222:22", &rendered, 60);
        assert!(
            err.starts_with(&format!(
                "{SSH_TIMEOUT_TOKEN} target=debian@192.168.123.222:22 elapsed=60s "
            )),
            "{err}"
        );
        assert!(
            err.contains("'systemctl' 'restart' 'rustynetd.service'"),
            "each argv element stays separately quoted: {err}"
        );
        assert!(is_ssh_timeout_error(&err));
        assert!(!is_ssh_timeout_error("harness_ssh_timeoutx"));
        assert!(!is_ssh_timeout_error(
            "remote command exited non-zero without output"
        ));
    }
}
