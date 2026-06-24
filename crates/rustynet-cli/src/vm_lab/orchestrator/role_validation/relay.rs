#![allow(dead_code)]
//! Cross-OS relay-service-lifecycle validation.
//!
//! This is the orchestrator-native port of the Linux-only
//! `live_linux_relay_test` bin's per-OS relay checks (Linux / macOS /
//! Windows), refitted to drive every probe through the hardened
//! [`RemoteShellHost`] seam instead of the bin's raw
//! `capture_root` / `capture_remote_stdout` shell-out. The bin built a
//! shell body string per probe; here every probe is an explicit argv +
//! Rust-side parsing of [`RemoteExitStatus::stdout`], so no shell string
//! is ever constructed from a non-constant value.
//!
//! The lifecycle proof is identical on all three platforms:
//!
//! 1. Capture a "during-run" snapshot: service active + datapath UDP
//!    port bound + health TCP port bound + `/healthz` returns `ok`.
//! 2. Stop the service via the canonical per-OS stop verb. Sleep so the
//!    daemon releases its sockets.
//! 3. Capture an "after-stop" snapshot and assert the inverse: service
//!    NOT active, both ports unbound, `/healthz` NOT ok.
//! 4. Restart the service so subsequent stages inherit a serving relay;
//!    a restart failure surfaces as a lifecycle failure rather than a
//!    silent pass (the orchestrator hands the host back to later stages).
//!
//! Constants come from the reviewed `rustynetd` service-hardening
//! modules; the datapath/health ports differ per OS (Linux/macOS bind
//! the health endpoint on 4501; Windows on
//! [`REVIEWED_WINDOWS_RELAY_HEALTH_PORT`]).
//!
//! Security posture (per `CLAUDE.md` / `documents/SecurityMinimumBar.md`):
//!
//! * Argv-only: every probe is a fixed argument vector with no untrusted
//!   interpolation. The POSIX backend wraps argv in `sudo -n`; the
//!   Windows backend forwards it via PowerShell `-EncodedCommand`.
//! * Read-only: the during/after captures only read service + socket +
//!   health state. The only state-mutating calls are the canonical
//!   stop/start verbs, exactly as the bin performed them.
//! * Fail closed: any unmet invariant collects a failure string and the
//!   validator returns `Err(joined failures)`.

use std::thread::sleep;
use std::time::Duration;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use rustynetd::macos_service_hardening::{
    REVIEWED_MACOS_RELAY_LAUNCHD_LABEL, REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH,
};
use rustynetd::windows_service_hardening::{
    REVIEWED_WINDOWS_RELAY_BIND_PORT, REVIEWED_WINDOWS_RELAY_HEALTH_PORT,
    REVIEWED_WINDOWS_RELAY_SERVICE_NAME,
};

/// Whether the Relay role's lab *runtime* — deploying the `rustynet-relay`
/// sibling service onto a node and driving its live lifecycle validators — is
/// implemented for `platform`.
///
/// This is deliberately distinct from [`NodeRole::is_supported_for_platform`],
/// which is the conservative posture / promotion flag flipped only once a green
/// cross-OS run is archived. The `deploy_relay_service` and `relay_validation`
/// stages gate on THIS predicate so a platform whose relay adapter can actually
/// deploy + validate the service runs the live loop that *produces* the evidence
/// `is_supported_for_platform` later promotes on — instead of being skipped
/// before it can generate that evidence. Platforms without a relay-deploy
/// adapter implementation are reported-skipped (named, never a silent pass).
///
/// Implemented today: Linux (`linux_install::deploy_relay_service`) and macOS
/// (`macos_install::deploy_relay_service`). Windows is pending its SCM relay
/// install; iOS / Android do not host a relay service.
pub fn relay_lab_runtime_implemented(platform: VmGuestPlatform) -> bool {
    matches!(platform, VmGuestPlatform::Linux | VmGuestPlatform::Macos)
}

/// Canonical systemd unit for the Linux relay (matches the unit the
/// `ops install-systemd-relay` role-installation stage deploys).
const SYSTEMD_RELAY_UNIT: &str = "rustynet-relay.service";
/// Reviewed UDP bind port for the relay datapath (Linux + macOS). The
/// daemon binds the datapath via `UdpSocket::bind`, so socket captures
/// MUST include UDP or a healthy relay is misclassified as down.
const RELAY_BIND_PORT: u16 = 4500;
/// Reviewed TCP bind port for the relay health/metrics endpoint on
/// Linux + macOS (loopback by default). TCP-LISTEN — distinct from
/// [`RELAY_BIND_PORT`]. Windows uses
/// [`REVIEWED_WINDOWS_RELAY_HEALTH_PORT`] instead.
const RELAY_HEALTH_PORT: u16 = 4501;
/// Health-check path served by the relay daemon on every platform.
const RELAY_HEALTH_PATH: &str = "/healthz";
/// How long to wait after the stop verb for the daemon to release its
/// listener sockets before the after-stop capture.
const STOP_SETTLE: Duration = Duration::from_secs(3);

/// Cross-OS relay lifecycle observation. Mirrors the shared snapshot the
/// `live_linux_relay_test` bin captures on every platform: the
/// active/inactive service word, whether the datapath + health listeners
/// are bound, and the parsed `/healthz` status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayLifecycleSnapshot {
    /// `"active"` / `"inactive"` — normalized across systemd / launchd /
    /// SCM so the assertions are platform-agnostic.
    pub unit_state: String,
    /// Datapath UDP listener bound on the reviewed bind port.
    pub listener_bound_datapath: bool,
    /// Health/metrics TCP listener bound on the reviewed health port.
    pub listener_bound_health: bool,
    /// `/healthz` body status — `"ok"` when the daemon answers healthy,
    /// `"unreachable"` / `"malformed: …"` / a missing-field word otherwise.
    pub health_status: String,
}

/// Capture a relay lifecycle snapshot for `platform`, dispatching to the
/// per-OS probe stack. Every probe runs through `shell.run_argv`.
pub fn capture_snapshot(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
) -> Result<RelayLifecycleSnapshot, String> {
    match platform {
        VmGuestPlatform::Linux => capture_linux_snapshot(shell),
        VmGuestPlatform::Macos => capture_macos_snapshot(shell),
        VmGuestPlatform::Windows => capture_windows_snapshot(shell),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "relay lifecycle validation is only implemented for Linux, macOS, and Windows (got {platform:?})"
        )),
    }
}

/// Drive the full relay-service-lifecycle proof for `platform`:
/// during-run capture → stop → after-stop capture → restart, asserting
/// every invariant. Returns `Ok(())` when all invariants hold and the
/// restart succeeds; otherwise `Err` with the joined failure list.
pub fn validate_relay_lifecycle(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
) -> Result<(), String> {
    let (datapath_port, health_port) = relay_ports(platform);

    let during = capture_snapshot(shell, platform)
        .map_err(|err| format!("during-run capture failed: {err}"))?;

    stop_relay_service(shell, platform)?;
    sleep(STOP_SETTLE);

    let after = capture_snapshot(shell, platform)
        .map_err(|err| format!("after-stop capture failed: {err}"))?;

    // Restart so later stages inherit a serving relay. A restart failure
    // is part of the lifecycle contract: the orchestrator hands the host
    // back to subsequent stages, so a silent restart failure must surface
    // as a failed result rather than hide under a pass.
    let restart_status = start_relay_service(shell, platform);

    let mut failures: Vec<String> = Vec::new();

    // ── During-run invariants ──
    if !during.unit_state.eq_ignore_ascii_case("active") {
        failures.push(format!(
            "during-run unit_state {:?} expected 'active' — relay role not deployed?",
            during.unit_state
        ));
    }
    if !during.listener_bound_datapath {
        failures.push(format!(
            "during-run relay datapath listener on :{datapath_port} was NOT bound"
        ));
    }
    if !during.listener_bound_health {
        failures.push(format!(
            "during-run health listener on :{health_port} was NOT bound"
        ));
    }
    if !during.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "during-run /healthz returned status {:?} expected 'ok'",
            during.health_status
        ));
    }

    // ── After-stop invariants (the inverse) ──
    if after.unit_state.eq_ignore_ascii_case("active") {
        failures.push(
            "after-stop unit_state still 'active' — stop verb did not take effect".to_owned(),
        );
    }
    if after.listener_bound_datapath {
        failures.push(format!(
            "after-stop relay datapath listener on :{datapath_port} was STILL bound (teardown leaked it)"
        ));
    }
    if after.listener_bound_health {
        failures.push(format!(
            "after-stop health listener on :{health_port} was STILL bound (teardown leaked it)"
        ));
    }
    if after.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "after-stop /healthz still answers with status {:?} — daemon socket was not released",
            after.health_status
        ));
    }

    // ── Restart invariant ──
    if let Err(err) = restart_status {
        failures.push(format!(
            "post-test relay restart failed; relay role is OFFLINE — {err}"
        ));
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

/// Per-OS (datapath, health) listener ports. Linux + macOS bind the
/// health endpoint on 4501; Windows binds it on
/// [`REVIEWED_WINDOWS_RELAY_HEALTH_PORT`].
fn relay_ports(platform: VmGuestPlatform) -> (u16, u16) {
    match platform {
        VmGuestPlatform::Windows => (
            REVIEWED_WINDOWS_RELAY_BIND_PORT,
            REVIEWED_WINDOWS_RELAY_HEALTH_PORT,
        ),
        _ => (RELAY_BIND_PORT, RELAY_HEALTH_PORT),
    }
}

// ── Linux probes ──────────────────────────────────────────────────────

fn capture_linux_snapshot(shell: &dyn RemoteShellHost) -> Result<RelayLifecycleSnapshot, String> {
    // `systemctl is-active` exits non-zero when the unit is not active;
    // the state word is still printed to stdout, so we read stdout and
    // ignore the exit code.
    let unit_state = run_stdout_trimmed(
        shell,
        &["systemctl", "is-active", SYSTEMD_RELAY_UNIT],
        "systemctl is-active",
    )?;

    // The relay datapath binds UDP on :4500 and the health/metrics
    // endpoint binds TCP on :4501. `ss -tlnp` would miss the UDP
    // listener — capture both protocols separately so each port is
    // checked against the right parser.
    let udp_summary = run_stdout_trimmed(shell, &["ss", "-ulnp"], "ss -ulnp")?;
    let tcp_summary = run_stdout_trimmed(shell, &["ss", "-tlnp"], "ss -tlnp")?;
    let listener_bound_datapath = linux_udp_summary_contains_port(&udp_summary, RELAY_BIND_PORT);
    let listener_bound_health =
        linux_tcp_summary_contains_listen_port(&tcp_summary, RELAY_HEALTH_PORT);

    let health_url = format!("http://127.0.0.1:{RELAY_HEALTH_PORT}{RELAY_HEALTH_PATH}");
    let health_body =
        run_stdout_lossy(shell, &["curl", "--silent", "--max-time", "5", &health_url]);
    let (health_status, _) = parse_relay_health_body(&health_body);

    Ok(RelayLifecycleSnapshot {
        unit_state,
        listener_bound_datapath,
        listener_bound_health,
        health_status,
    })
}

fn stop_linux_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    run_expect_success(
        shell,
        &["systemctl", "stop", SYSTEMD_RELAY_UNIT],
        "systemctl stop",
    )
}

fn start_linux_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    run_expect_success(
        shell,
        &["systemctl", "start", SYSTEMD_RELAY_UNIT],
        "systemctl start",
    )
}

// ── macOS probes ──────────────────────────────────────────────────────

fn capture_macos_snapshot(shell: &dyn RemoteShellHost) -> Result<RelayLifecycleSnapshot, String> {
    // `launchctl print system/<label>` exits non-zero when the service
    // is not loaded — we read stdout (the backend captures stderr
    // separately) so the diagnostic still drives the parser.
    let print_target = format!("system/{REVIEWED_MACOS_RELAY_LAUNCHD_LABEL}");
    let launchctl_print = run_stdout_combined(shell, &["launchctl", "print", &print_target]);
    let unit_state = parse_macos_launchctl_print_state(&launchctl_print);

    // Mirror the Linux path: capture UDP and TCP separately. lsof has no
    // LISTEN state for UDP — a bound UDP socket prints without
    // `(LISTEN)`, so the UDP matcher must NOT require it.
    let udp_listeners = run_stdout_lossy(shell, &["lsof", "-nP", "-iUDP"]);
    let tcp_listeners = run_stdout_lossy(shell, &["lsof", "-nP", "-iTCP", "-sTCP:LISTEN"]);
    let listener_bound_datapath =
        macos_udp_listener_summary_contains_port(&udp_listeners, RELAY_BIND_PORT);
    let listener_bound_health =
        macos_tcp_listener_summary_contains_port(&tcp_listeners, RELAY_HEALTH_PORT);

    let health_url = format!("http://127.0.0.1:{RELAY_HEALTH_PORT}{RELAY_HEALTH_PATH}");
    let health_body =
        run_stdout_lossy(shell, &["curl", "--silent", "--max-time", "5", &health_url]);
    let (health_status, _) = parse_relay_health_body(&health_body);

    Ok(RelayLifecycleSnapshot {
        unit_state,
        listener_bound_datapath,
        listener_bound_health,
        health_status,
    })
}

fn stop_macos_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    // launchctl bootout is the canonical macOS daemon-stop verb. Accept a
    // non-zero exit (the daemon may be loaded under a different domain or
    // already absent); the after-stop listener capture proves the cleanup
    // actually happened, so we never trust the stop verb's exit alone.
    let target = format!("system/{REVIEWED_MACOS_RELAY_LAUNCHD_LABEL}");
    let _ = run_argv_capture(
        shell,
        &["launchctl", "bootout", &target],
        "launchctl bootout",
    );
    Ok(())
}

fn start_macos_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    // bootstrap is the modern load verb; fall back to legacy `load` if
    // bootstrap is rejected. Either succeeding restores a serving relay.
    let bootstrap = run_argv_capture(
        shell,
        &[
            "launchctl",
            "bootstrap",
            "system",
            REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH,
        ],
        "launchctl bootstrap",
    );
    if matches!(&bootstrap, Ok(status) if status.code == 0) {
        return Ok(());
    }
    run_expect_success(
        shell,
        &["launchctl", "load", REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH],
        "launchctl load",
    )
}

// ── Windows probes ────────────────────────────────────────────────────
//
// Windows binds the relay datapath on UDP :4500 and the health/metrics
// endpoint on TCP :REVIEWED_WINDOWS_RELAY_HEALTH_PORT. The probe stack is
// PowerShell cmdlets, not standalone executables, so each probe is a
// single fixed `powershell -Command <cmdlet>` argv. The cmdlet strings
// are compile-time constants with no untrusted interpolation, so this is
// argv-only with no shell-injection surface.

fn capture_windows_snapshot(shell: &dyn RemoteShellHost) -> Result<RelayLifecycleSnapshot, String> {
    // Get-Service exposes a Status property; ExpandProperty yields the
    // bare status word the parser maps to active/inactive.
    let svc_cmd = format!(
        "(Get-Service -Name '{REVIEWED_WINDOWS_RELAY_SERVICE_NAME}' -ErrorAction SilentlyContinue).Status"
    );
    let svc_status = run_powershell_stdout(shell, &svc_cmd);
    let unit_state = parse_windows_get_service_status(&svc_status);

    // Get-NetUDPEndpoint / Get-NetTCPConnection print zero rows (empty
    // stdout) when no socket is bound and a tabular block when one is.
    // `-Width 32767` keeps Format-Table from wrapping the listener row at
    // the terminal width, which would break the non-empty-line detector.
    let udp_cmd = format!(
        "Get-NetUDPEndpoint -LocalPort {REVIEWED_WINDOWS_RELAY_BIND_PORT} -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders | Out-String -Width 32767"
    );
    let udp_summary = run_powershell_stdout(shell, &udp_cmd);
    let tcp_cmd = format!(
        "Get-NetTCPConnection -LocalPort {REVIEWED_WINDOWS_RELAY_HEALTH_PORT} -State Listen -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders | Out-String -Width 32767"
    );
    let tcp_summary = run_powershell_stdout(shell, &tcp_cmd);
    let listener_bound_datapath = windows_endpoint_summary_has_row(&udp_summary);
    let listener_bound_health = windows_endpoint_summary_has_row(&tcp_summary);

    // Invoke-WebRequest -UseBasicParsing emits the body of a successful
    // response; on connection refused PowerShell errors, so a try/catch
    // collapses a failed probe to empty stdout (parsed as `unreachable`).
    let health_cmd = format!(
        "try {{ (Invoke-WebRequest -UseBasicParsing -Uri http://127.0.0.1:{REVIEWED_WINDOWS_RELAY_HEALTH_PORT}{RELAY_HEALTH_PATH} -TimeoutSec 5).Content }} catch {{ '' }}"
    );
    let health_body = run_powershell_stdout(shell, &health_cmd);
    let (health_status, _) = parse_relay_health_body(&health_body);

    Ok(RelayLifecycleSnapshot {
        unit_state,
        listener_bound_datapath,
        listener_bound_health,
        health_status,
    })
}

fn stop_windows_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    // Stop the SCM service. -Force handles dependent-service cleanup. We
    // tolerate a non-zero result (the service may already be stopped);
    // the after-stop capture proves teardown.
    let cmd = format!("Stop-Service -Name '{REVIEWED_WINDOWS_RELAY_SERVICE_NAME}' -Force");
    let _ = run_powershell_capture(shell, &cmd);
    Ok(())
}

fn start_windows_relay(shell: &dyn RemoteShellHost) -> Result<(), String> {
    let cmd = format!("Start-Service -Name '{REVIEWED_WINDOWS_RELAY_SERVICE_NAME}'");
    let status = run_powershell_capture(shell, &cmd)?;
    if status.code == 0 {
        Ok(())
    } else {
        Err(format!(
            "Start-Service exited {} (stderr: {})",
            status.code,
            stderr_snippet(&status.stderr)
        ))
    }
}

// ── Per-platform stop/start dispatch ──────────────────────────────────

fn stop_relay_service(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
) -> Result<(), String> {
    match platform {
        VmGuestPlatform::Linux => stop_linux_relay(shell),
        VmGuestPlatform::Macos => stop_macos_relay(shell),
        VmGuestPlatform::Windows => stop_windows_relay(shell),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "relay stop is only implemented for Linux, macOS, and Windows (got {platform:?})"
        )),
    }
}

fn start_relay_service(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
) -> Result<(), String> {
    match platform {
        VmGuestPlatform::Linux => start_linux_relay(shell),
        VmGuestPlatform::Macos => start_macos_relay(shell),
        VmGuestPlatform::Windows => start_windows_relay(shell),
        VmGuestPlatform::Ios | VmGuestPlatform::Android => Err(format!(
            "relay start is only implemented for Linux, macOS, and Windows (got {platform:?})"
        )),
    }
}

// ── run_argv helpers ──────────────────────────────────────────────────

/// Run `argv` and return the full [`RemoteExitStatus`], mapping a
/// transport error to a `String` with the labelled probe name.
fn run_argv_capture(
    shell: &dyn RemoteShellHost,
    argv: &[&str],
    label: &str,
) -> Result<crate::vm_lab::orchestrator::remote_shell::RemoteExitStatus, String> {
    shell
        .run_argv(argv, &[], &[])
        .map_err(|err| format!("{label} run_argv failed: {err}"))
}

/// Run `argv`, requiring exit 0; surface the exit code + stderr snippet
/// on failure. Used for the state-mutating stop/start verbs that must
/// succeed (systemctl, Start-Service).
fn run_expect_success(
    shell: &dyn RemoteShellHost,
    argv: &[&str],
    label: &str,
) -> Result<(), String> {
    let status = run_argv_capture(shell, argv, label)?;
    if status.code == 0 {
        Ok(())
    } else {
        Err(format!(
            "{label} exited {} (stderr: {})",
            status.code,
            stderr_snippet(&status.stderr)
        ))
    }
}

/// Run `argv`, requiring transport success but tolerating any exit code
/// (the program's state word is on stdout even on non-zero exit, e.g.
/// `systemctl is-active`). Returns trimmed stdout.
fn run_stdout_trimmed(
    shell: &dyn RemoteShellHost,
    argv: &[&str],
    label: &str,
) -> Result<String, String> {
    let status = run_argv_capture(shell, argv, label)?;
    Ok(String::from_utf8_lossy(&status.stdout).trim().to_owned())
}

/// Run `argv`, returning lossy-UTF8 stdout, and collapsing ANY error
/// (transport or non-zero) to an empty string. Used for best-effort
/// probes whose absence is itself a signal (curl, lsof, ss listings) —
/// matches the bin's `|| true` shell-suffix semantics.
fn run_stdout_lossy(shell: &dyn RemoteShellHost, argv: &[&str]) -> String {
    match shell.run_argv(argv, &[], &[]) {
        Ok(status) => String::from_utf8_lossy(&status.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

/// Like [`run_stdout_lossy`] but concatenates stdout + stderr — the
/// macOS `launchctl print` diagnostic ("Could not find service …") is
/// emitted on stderr, and the parser needs to see it.
fn run_stdout_combined(shell: &dyn RemoteShellHost, argv: &[&str]) -> String {
    match shell.run_argv(argv, &[], &[]) {
        Ok(status) => {
            let mut out = String::from_utf8_lossy(&status.stdout).into_owned();
            let err = String::from_utf8_lossy(&status.stderr);
            if !err.trim().is_empty() {
                out.push('\n');
                out.push_str(&err);
            }
            out
        }
        Err(_) => String::new(),
    }
}

/// Run a fixed PowerShell cmdlet via `powershell -Command`, returning the
/// full [`RemoteExitStatus`]. `command` MUST be a compile-time-constant
/// cmdlet string (no untrusted interpolation) — the only interpolations
/// in this module are reviewed `rustynetd` constants.
fn run_powershell_capture(
    shell: &dyn RemoteShellHost,
    command: &str,
) -> Result<crate::vm_lab::orchestrator::remote_shell::RemoteExitStatus, String> {
    shell
        .run_argv(
            &[
                "powershell",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command,
            ],
            &[],
            &[],
        )
        .map_err(|err| format!("powershell run_argv failed: {err}"))
}

/// Run a fixed PowerShell cmdlet and return lossy stdout, collapsing any
/// error to empty (the empty/`unreachable` path is a valid signal).
fn run_powershell_stdout(shell: &dyn RemoteShellHost, command: &str) -> String {
    match shell.run_argv(
        &[
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            command,
        ],
        &[],
        &[],
    ) {
        Ok(status) => String::from_utf8_lossy(&status.stdout).into_owned(),
        Err(_) => String::new(),
    }
}

/// First 200 bytes of a stderr blob, single-lined, for embedding in a
/// failure string without flooding the report.
fn stderr_snippet(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_owned()
}

// ── Pure parsers (copied verbatim from `live_linux_relay_test`) ───────

/// `ss -ulnp` lines for UDP look like
/// `UNCONN 0 0 127.0.0.1:4500 0.0.0.0:* users:(("rustynet-relay",...))`.
/// A bound UDP socket is reported as state `UNCONN` (UDP is
/// connectionless, so there is no LISTEN state). Match on `UNCONN`
/// plus the explicit port suffix preceded by an interface or
/// wildcard so an outbound UDP socket on the same port number
/// cannot be confused for a bound listener.
fn linux_udp_summary_contains_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{port}"),
        format!("0.0.0.0:{port}"),
        format!("*:{port}"),
        format!("[::1]:{port}"),
        format!("[::]:{port}"),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("UNCONN") && needles.iter().any(|needle| trimmed.contains(needle))
    })
}

/// `ss -tlnp` TCP-LISTEN lines start with `LISTEN`. Require the
/// LISTEN state so an ESTABLISHED outbound socket on the same port
/// number cannot satisfy the check.
fn linux_tcp_summary_contains_listen_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{port}"),
        format!("0.0.0.0:{port}"),
        format!("*:{port}"),
        format!("[::1]:{port}"),
        format!("[::]:{port}"),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("LISTEN") && needles.iter().any(|needle| trimmed.contains(needle))
    })
}

/// Parse `launchctl print system/<label>` stdout into a state word
/// that mirrors `systemctl is-active` ("active" / "inactive").
///
/// launchctl reports daemon state two complementary ways:
///   * a `state = <word>` line — `running` is live; `waiting` and
///     `spawn scheduled` are KeepAlive cooldown intermediates and
///     classify as `active` (the daemon will respawn imminently);
///     every other word (`exited`, `not running`, ...) classifies
///     as `inactive`.
///   * a `pid = <N>` line — used as a fallback when the truncated
///     output omits the explicit `state =` line. A non-zero pid is
///     classified as `active`.
///
/// When the service is not loaded launchctl writes
/// `Could not find service` to stderr (the caller merges stderr).
fn parse_macos_launchctl_print_state(stdout: &str) -> String {
    let lower = stdout.to_ascii_lowercase();
    if lower.contains("could not find service") || lower.contains("service not loaded") {
        return "inactive".to_owned();
    }
    for line in stdout.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("state =") {
            let word = rest.trim().to_ascii_lowercase();
            return match word.as_str() {
                "running" | "waiting" | "spawn scheduled" => "active".to_owned(),
                _ => "inactive".to_owned(),
            };
        }
    }
    // No `state =` line — fall back to the pid heuristic.
    if stdout.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("pid =")
            && trimmed
                .split_once('=')
                .and_then(|(_, rest)| rest.trim().parse::<u32>().ok())
                .is_some_and(|pid| pid != 0)
    }) {
        return "active".to_owned();
    }
    "inactive".to_owned()
}

/// lsof `-iTCP -sTCP:LISTEN` lines look like
/// `rustynet-r  1234 rustynetd   10u  IPv4 0xabc      0t0  TCP 127.0.0.1:4501 (LISTEN)`.
/// Match on `(LISTEN)` plus the explicit port suffix so an ephemeral
/// outbound TCP connection on the same port cannot satisfy the check.
fn macos_tcp_listener_summary_contains_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{port}"),
        format!("*:{port}"),
        format!("[::1]:{port}"),
        format!("[::]:{port}"),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.contains("(LISTEN)") && needles.iter().any(|needle| trimmed.contains(needle))
    })
}

/// lsof `-iUDP` lines look like
/// `rustynet-r  1234 rustynetd   11u  IPv4 0xabd      0t0  UDP 127.0.0.1:4500`.
/// Bound UDP sockets have no `(LISTEN)` state — they are
/// connectionless — and lsof does not print one for them. Match on
/// the `UDP` protocol token plus the port suffix. We also require
/// the line NOT to contain `->` so an outbound UDP socket that has
/// learnt a peer endpoint (`127.0.0.1:4500->10.0.0.1:5555`) cannot
/// satisfy the bound-listener check.
fn macos_udp_listener_summary_contains_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{port}"),
        format!("*:{port}"),
        format!("[::1]:{port}"),
        format!("[::]:{port}"),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        // `contains` (not `ends_with`) so trailing whitespace or
        // platform-specific zone-id suffixes don't break the match.
        // The `->` exclusion still rules out outbound sockets that
        // share the port number.
        trimmed.contains(" UDP ")
            && !trimmed.contains("->")
            && needles.iter().any(|needle| trimmed.contains(needle))
    })
}

/// Map the PowerShell Get-Service status word to the cross-platform
/// active/inactive value. `Running` is the live SCM state; every
/// other published value (Stopped, Paused, StartPending, ...) is
/// classified as `inactive` so a half-started service is not
/// reported as live.
fn parse_windows_get_service_status(stdout: &str) -> String {
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        return "inactive".to_owned();
    }
    if trimmed.eq_ignore_ascii_case("running") {
        return "active".to_owned();
    }
    "inactive".to_owned()
}

/// `Get-NetUDPEndpoint` / `Get-NetTCPConnection` with
/// `-ErrorAction SilentlyContinue` returns ZERO rows when no socket
/// is bound — the pipeline produces empty stdout. Any non-empty
/// non-whitespace line indicates a returned object, i.e. a bound
/// listener. `Format-Table -HideTableHeaders` keeps the output
/// machine-parseable without a leading column header that might
/// otherwise be mistaken for a row.
fn windows_endpoint_summary_has_row(summary: &str) -> bool {
    summary.lines().any(|line| !line.trim().is_empty())
}

/// Parse the relay `/healthz` JSON body into a `(status, active_sessions)`
/// pair. An empty body is `unreachable`; non-JSON is `malformed: <token>`;
/// a JSON object yields its `status` field (or `missing`).
fn parse_relay_health_body(body: &str) -> (String, Option<u64>) {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return ("unreachable".to_owned(), None);
    }
    let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return (format!("malformed: {}", first_token(trimmed)), None);
    };
    let status = value
        .get("status")
        .and_then(|v| v.as_str())
        .unwrap_or("missing")
        .to_owned();
    let sessions = value.get("active_sessions").and_then(|v| v.as_u64());
    (status, sessions)
}

fn first_token(input: &str) -> String {
    input
        .chars()
        .take(48)
        .collect::<String>()
        .replace('\n', " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};

    fn ok(stdout: &str) -> RemoteExitStatus {
        RemoteExitStatus {
            code: 0,
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        }
    }

    // ── Linux listener parser coverage (copied) ──

    #[test]
    fn linux_tcp_summary_matches_loopback_listen_for_health_port() {
        let body = "State        Recv-Q Send-Q Local Address:Port   Peer Address:Port\n\
                    LISTEN       0      128    127.0.0.1:4501       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=11))\n";
        assert!(linux_tcp_summary_contains_listen_port(body, 4501));
        assert!(!linux_tcp_summary_contains_listen_port(body, 4502));
    }

    #[test]
    fn linux_tcp_summary_rejects_non_listen_lines_for_same_port() {
        // ESTAB lines must not satisfy the LISTEN check — the daemon
        // could have an outbound socket on the port without binding.
        let body = "ESTAB        0      0      127.0.0.1:4501       127.0.0.1:55512     users:((\"curl\",pid=4321,fd=4))\n";
        assert!(!linux_tcp_summary_contains_listen_port(body, 4501));
    }

    #[test]
    fn linux_udp_summary_matches_unconn_bound_socket_for_relay_port() {
        // `ss -ulnp` prints UDP bound sockets with state `UNCONN`
        // since UDP has no LISTEN state. The matcher must accept
        // UNCONN + the explicit port suffix.
        let body = "State        Recv-Q Send-Q Local Address:Port   Peer Address:Port\n\
                    UNCONN       0      0      127.0.0.1:4500       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=10))\n";
        assert!(linux_udp_summary_contains_port(body, 4500));
    }

    #[test]
    fn linux_udp_summary_rejects_tcp_listen_lines() {
        // A TCP LISTEN on the same port number must NOT satisfy the
        // UDP check (defense-in-depth — the validator captures
        // protocols separately, but if the captures are crossed by
        // mistake the parser should still refuse).
        let body = "LISTEN       0      128    127.0.0.1:4500       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=10))\n";
        assert!(!linux_udp_summary_contains_port(body, 4500));
    }

    // ── Health-body parser coverage (copied) ──

    #[test]
    fn parse_relay_health_body_parses_ok_status_and_session_count() {
        let body = r#"{"status":"ok","active_sessions":3,"allocated_ports":3,"max_sessions_per_node":8,"max_total_sessions":4096}"#;
        let (status, sessions) = parse_relay_health_body(body);
        assert_eq!(status, "ok");
        assert_eq!(sessions, Some(3));
    }

    #[test]
    fn parse_relay_health_body_returns_unreachable_for_empty_body() {
        let (status, sessions) = parse_relay_health_body("");
        assert_eq!(status, "unreachable");
        assert!(sessions.is_none());
    }

    #[test]
    fn parse_relay_health_body_returns_malformed_token_for_non_json() {
        let (status, _) =
            parse_relay_health_body("curl: (7) Failed to connect to 127.0.0.1 port 4501");
        assert!(status.starts_with("malformed: "), "got: {status}");
    }

    // ── macOS launchctl parser coverage (copied) ──

    #[test]
    fn parse_macos_launchctl_print_state_recognises_running_daemon() {
        let stdout = "system/com.rustynet.relay = {\n\
                      \tpid = 12345\n\
                      \tstate = running\n\
                      \tprogram = /usr/local/bin/rustynet-relay\n\
                      }\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "active");
    }

    #[test]
    fn parse_macos_launchctl_print_state_recognises_unloaded_service() {
        // launchctl writes "Could not find service" to stderr when
        // the label is not loaded; the caller merges stderr. Must
        // classify as `inactive`.
        let stdout = "Could not find service \"com.rustynet.relay\" in domain for system\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "inactive");
    }

    #[test]
    fn parse_macos_launchctl_print_state_recognises_pid_only_form() {
        // Some launchctl print outputs omit the explicit `state =
        // running` line and only carry the `pid = ` field. A live
        // pid must still be classified as `active`.
        let stdout = "system/com.rustynet.relay = {\n\
                      \tpid = 5678\n\
                      \tprogram = /usr/local/bin/rustynet-relay\n\
                      }\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "active");
    }

    #[test]
    fn parse_macos_launchctl_print_state_returns_inactive_for_empty_stdout() {
        assert_eq!(parse_macos_launchctl_print_state(""), "inactive");
    }

    #[test]
    fn parse_macos_launchctl_print_state_treats_waiting_as_active() {
        // launchd `waiting` is the KeepAlive cooldown state — the
        // daemon will respawn imminently. The cross-platform
        // contract treats it as `active` so a brief restart hiccup
        // does not flap the live-lab assertion.
        let stdout = "system/com.rustynet.relay = {\n\tstate = waiting\n}\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "active");
    }

    #[test]
    fn parse_macos_launchctl_print_state_treats_exited_as_inactive() {
        let stdout = "system/com.rustynet.relay = {\n\tstate = exited\n\tlast exit code = 1\n}\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "inactive");
    }

    #[test]
    fn parse_macos_launchctl_print_state_treats_not_running_as_inactive() {
        let stdout = "system/com.rustynet.relay = {\n\tstate = not running\n}\n";
        assert_eq!(parse_macos_launchctl_print_state(stdout), "inactive");
    }

    // ── macOS lsof listener parser coverage (copied) ──

    #[test]
    fn macos_tcp_listener_summary_matches_loopback_listen_for_health_port() {
        let body = "COMMAND  PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                    rustynet 123 r    11u IPv4 0xabd      0t0  TCP 127.0.0.1:4501 (LISTEN)\n";
        assert!(macos_tcp_listener_summary_contains_port(body, 4501));
        assert!(!macos_tcp_listener_summary_contains_port(body, 4502));
    }

    #[test]
    fn macos_tcp_listener_summary_rejects_established_connections_on_same_port() {
        let body = "rustynet 123 r    20u IPv4 0xfff      0t0  TCP 127.0.0.1:4501->127.0.0.1:55512 (ESTABLISHED)\n";
        assert!(!macos_tcp_listener_summary_contains_port(body, 4501));
    }

    #[test]
    fn macos_tcp_listener_summary_accepts_wildcard_bind_form() {
        let body = "rustynet 123 r    11u IPv4 0xabd      0t0  TCP *:4501 (LISTEN)\n";
        assert!(macos_tcp_listener_summary_contains_port(body, 4501));
    }

    #[test]
    fn macos_udp_listener_summary_matches_bound_relay_port() {
        // macOS lsof prints bound UDP sockets WITHOUT `(LISTEN)`.
        let body = "rustynet 123 r    10u IPv4 0xabc      0t0  UDP 127.0.0.1:4500\n";
        assert!(macos_udp_listener_summary_contains_port(body, 4500));
    }

    #[test]
    fn macos_udp_listener_summary_rejects_outbound_with_peer_endpoint() {
        // lsof prints outbound UDP sockets with a learnt peer as
        // `local->remote`. Must NOT satisfy the bound-listener check.
        let body = "rustynet 123 r    20u IPv4 0xfff      0t0  UDP 127.0.0.1:4500->10.0.0.1:5555\n";
        assert!(!macos_udp_listener_summary_contains_port(body, 4500));
    }

    #[test]
    fn macos_udp_listener_summary_rejects_tcp_listen_for_same_port() {
        // Defense-in-depth: TCP LISTEN on the same port number must
        // NOT satisfy the UDP matcher.
        let body = "rustynet 123 r    11u IPv4 0xabd      0t0  TCP 127.0.0.1:4500 (LISTEN)\n";
        assert!(!macos_udp_listener_summary_contains_port(body, 4500));
    }

    #[test]
    fn macos_listener_summary_accepts_ipv6_wildcard_bind() {
        // Operator widens --bind to all interfaces including IPv6;
        // lsof prints `[::]:4500`. Both TCP and UDP matchers must
        // accept it — Linux already does (`[::]:` is in its needle
        // list); this keeps the cross-platform contract symmetric.
        let tcp = "rustynet 123 r    11u IPv6 0xabd      0t0  TCP [::]:4501 (LISTEN)\n";
        assert!(macos_tcp_listener_summary_contains_port(tcp, 4501));
        let udp = "rustynet 123 r    10u IPv6 0xabc      0t0  UDP [::]:4500\n";
        assert!(macos_udp_listener_summary_contains_port(udp, 4500));
    }

    // ── Windows parser coverage (copied) ──

    #[test]
    fn parse_windows_get_service_status_recognises_running() {
        assert_eq!(parse_windows_get_service_status("Running\r\n"), "active");
        assert_eq!(parse_windows_get_service_status("Running"), "active");
        assert_eq!(parse_windows_get_service_status("running"), "active");
    }

    #[test]
    fn parse_windows_get_service_status_classifies_non_running_as_inactive() {
        for word in ["Stopped", "Paused", "StartPending", "StopPending", ""] {
            assert_eq!(
                parse_windows_get_service_status(word),
                "inactive",
                "{word:?} must classify as inactive"
            );
        }
    }

    #[test]
    fn windows_endpoint_summary_has_row_detects_bound_listener() {
        // Get-NetUDPEndpoint emits non-empty tabular output when a
        // socket is bound. Any non-whitespace line counts.
        let body = "\n0.0.0.0                                       4500\n\n";
        assert!(windows_endpoint_summary_has_row(body));
    }

    #[test]
    fn windows_endpoint_summary_has_row_returns_false_for_empty() {
        // ErrorAction SilentlyContinue + no matching endpoint => zero
        // rows, empty stdout. Must be classified as no listener.
        assert!(!windows_endpoint_summary_has_row(""));
        assert!(!windows_endpoint_summary_has_row("   \n\n\t"));
    }

    // ── Constant + port-mapping pins ──

    #[test]
    fn relay_ports_are_per_os_reviewed_constants() {
        // Linux + macOS bind health on 4501; Windows on the reviewed
        // 9100. A drift in the rustynetd constants surfaces here.
        assert_eq!(relay_ports(VmGuestPlatform::Linux), (4500, 4501));
        assert_eq!(relay_ports(VmGuestPlatform::Macos), (4500, 4501));
        assert_eq!(
            relay_ports(VmGuestPlatform::Windows),
            (
                REVIEWED_WINDOWS_RELAY_BIND_PORT,
                REVIEWED_WINDOWS_RELAY_HEALTH_PORT
            )
        );
        assert_eq!(REVIEWED_WINDOWS_RELAY_BIND_PORT, 4500);
        assert_eq!(REVIEWED_WINDOWS_RELAY_HEALTH_PORT, 9100);
    }

    #[test]
    fn relay_lab_runtime_implemented_for_linux_and_macos_only() {
        // The deploy_relay_service + relay_validation stages gate on this
        // predicate. Linux + macOS have a relay-deploy adapter and run live;
        // Windows (no SCM relay install yet) and the mobile platforms are
        // reported-skipped — named, never a silent pass.
        assert!(relay_lab_runtime_implemented(VmGuestPlatform::Linux));
        assert!(relay_lab_runtime_implemented(VmGuestPlatform::Macos));
        assert!(!relay_lab_runtime_implemented(VmGuestPlatform::Windows));
        assert!(!relay_lab_runtime_implemented(VmGuestPlatform::Ios));
        assert!(!relay_lab_runtime_implemented(VmGuestPlatform::Android));
    }

    // ── End-to-end validator over the in-process mock shell ──

    /// One captured phase of the Linux lifecycle (during-run or
    /// after-stop): the `systemctl is-active` word plus the `ss` /
    /// `curl` stdout the snapshot capture will parse.
    struct LinuxPhase {
        state: &'static str,
        udp: &'static str,
        tcp: &'static str,
        health: &'static str,
    }

    impl LinuxPhase {
        /// A fully-serving relay: active unit, datapath UDP + health TCP
        /// bound, `/healthz` ok.
        fn serving() -> Self {
            LinuxPhase {
                state: "active",
                udp: "UNCONN 0 0 127.0.0.1:4500 0.0.0.0:* users:((\"rustynet-relay\",pid=1,fd=10))",
                tcp: "LISTEN 0 128 127.0.0.1:4501 0.0.0.0:* users:((\"rustynet-relay\",pid=1,fd=11))",
                health: r#"{"status":"ok","active_sessions":0}"#,
            }
        }

        /// A cleanly-torn-down relay: inactive unit, no listeners, no
        /// health response.
        fn torn_down() -> Self {
            LinuxPhase {
                state: "inactive",
                udp: "",
                tcp: "",
                health: "",
            }
        }
    }

    /// Program a Linux mock shell with a during-run + after-stop phase
    /// and the stop/start exit codes. The mock keys responses by exact
    /// argv, FIFO, so we push two responses per repeated probe (during,
    /// then after).
    fn program_linux_lifecycle(
        mock: &MockShellHost,
        during: &LinuxPhase,
        after: &LinuxPhase,
        stop_ok: bool,
        start_ok: bool,
    ) {
        let is_active = ["systemctl", "is-active", SYSTEMD_RELAY_UNIT];
        mock.program_run_response(&is_active, ok(during.state));
        mock.program_run_response(&is_active, ok(after.state));

        let ss_udp = ["ss", "-ulnp"];
        mock.program_run_response(&ss_udp, ok(during.udp));
        mock.program_run_response(&ss_udp, ok(after.udp));

        let ss_tcp = ["ss", "-tlnp"];
        mock.program_run_response(&ss_tcp, ok(during.tcp));
        mock.program_run_response(&ss_tcp, ok(after.tcp));

        let health_url = format!("http://127.0.0.1:{RELAY_HEALTH_PORT}{RELAY_HEALTH_PATH}");
        let curl = ["curl", "--silent", "--max-time", "5", health_url.as_str()];
        mock.program_run_response(&curl, ok(during.health));
        mock.program_run_response(&curl, ok(after.health));

        let stop = ["systemctl", "stop", SYSTEMD_RELAY_UNIT];
        mock.program_run_response(
            &stop,
            RemoteExitStatus {
                code: if stop_ok { 0 } else { 1 },
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
        let start = ["systemctl", "start", SYSTEMD_RELAY_UNIT];
        mock.program_run_response(
            &start,
            RemoteExitStatus {
                code: if start_ok { 0 } else { 1 },
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
        );
    }

    #[test]
    fn validate_linux_lifecycle_passes_when_all_invariants_hold() {
        let mock = MockShellHost::new();
        program_linux_lifecycle(
            &mock,
            &LinuxPhase::serving(),
            &LinuxPhase::torn_down(),
            true,
            true,
        );
        let result = validate_relay_lifecycle(&mock, VmGuestPlatform::Linux);
        assert!(result.is_ok(), "expected pass, got: {result:?}");
    }

    #[test]
    fn validate_linux_lifecycle_fails_when_after_stop_still_bound() {
        // Teardown leaks: after-stop is still serving (active, bound,
        // healthy) → the after-stop invariants must fail closed.
        let mock = MockShellHost::new();
        program_linux_lifecycle(
            &mock,
            &LinuxPhase::serving(),
            &LinuxPhase::serving(),
            true,
            true,
        );
        let err = validate_relay_lifecycle(&mock, VmGuestPlatform::Linux)
            .expect_err("leaked teardown must fail");
        assert!(err.contains("after-stop"), "got: {err}");
    }

    #[test]
    fn validate_linux_lifecycle_fails_when_during_run_not_serving() {
        // Service inactive + ports unbound during the run → the
        // during-run invariants must fail closed.
        let mock = MockShellHost::new();
        program_linux_lifecycle(
            &mock,
            &LinuxPhase::torn_down(),
            &LinuxPhase::torn_down(),
            true,
            true,
        );
        let err = validate_relay_lifecycle(&mock, VmGuestPlatform::Linux)
            .expect_err("non-serving relay must fail");
        assert!(err.contains("during-run"), "got: {err}");
    }

    #[test]
    fn validate_linux_lifecycle_fails_when_restart_fails() {
        // Even with a clean during/after, a failed restart leaves the
        // relay OFFLINE for later stages and must fail the lifecycle.
        let mock = MockShellHost::new();
        program_linux_lifecycle(
            &mock,
            &LinuxPhase::serving(),
            &LinuxPhase::torn_down(),
            true,
            false,
        );
        let err = validate_relay_lifecycle(&mock, VmGuestPlatform::Linux)
            .expect_err("failed restart must fail");
        assert!(err.contains("restart failed"), "got: {err}");
    }

    #[test]
    fn capture_snapshot_fails_closed_on_mobile_platform() {
        let mock = MockShellHost::new();
        assert!(capture_snapshot(&mock, VmGuestPlatform::Ios).is_err());
        assert!(validate_relay_lifecycle(&mock, VmGuestPlatform::Android).is_err());
    }
}
