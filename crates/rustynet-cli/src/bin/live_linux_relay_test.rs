#![forbid(unsafe_code)]
#![allow(clippy::uninlined_format_args)]

//! Track B Phase 6 — real Linux relay-service-lifecycle live validator.
//!
//! Replaces the Phase 3 scaffold. Drives an end-to-end proof against
//! the canonical `rustynet-relay.service` systemd unit on the relay
//! host:
//!
//! 1. Preflight: SSH identity + passwordless sudo + the unit must
//!    be present and active. The orchestrator's role-installation
//!    stage has already deployed `ops install-systemd-relay` against
//!    this host.
//! 2. During-run capture: `systemctl is-active rustynet-relay`,
//!    `ss -tlnp` showing the relay + health listeners bound, and an
//!    HTTP GET against `/healthz` to prove the daemon answers.
//! 3. Stop the service via `systemctl stop` (the canonical teardown
//!    verb). Sleep 3 s for the daemon to release sockets.
//! 4. After-stop capture: service `inactive`, listeners gone, /healthz
//!    refused.
//! 5. Restart via `systemctl start` so subsequent stages inherit a
//!    running relay. Capture the restart outcome and surface it in
//!    the report rather than swallowing failures.
//! 6. Assert invariants and emit a typed JSON report mirroring the
//!    exit-handoff envelope (`phase`, `mode`, `evidence_mode`,
//!    `captured_at`, `captured_at_unix`, `git_commit`, `lifecycle`,
//!    `source_artifacts`, `status`).
//!
//! macOS + Windows fail closed at the dispatcher until Phase 7 / 8.

mod live_lab_bin_support;

use std::env;
use std::path::{Path, PathBuf};

use live_lab_bin_support::{
    LiveLabPlatform, capture_remote_stdout, capture_root, create_workspace,
    enforce_linux_only_until_validator_lands, ensure_pinned_known_hosts_file, ensure_safe_token,
    git_head_commit, load_home_known_hosts_path, repo_root, require_command, run_root,
    seed_known_hosts, verify_passwordless_sudo, verify_sudo, write_file,
};
use rustynetd::macos_service_hardening::{
    REVIEWED_MACOS_RELAY_LAUNCHD_LABEL, REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH,
};
use serde::Serialize;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    let config = Config::parse(args)?;
    match config.platform {
        LiveLabPlatform::Linux => run_linux_relay(&config),
        LiveLabPlatform::MacOs => run_macos_relay(&config),
        LiveLabPlatform::Windows => {
            // Track B Phase 8 lands the Windows SCM relay installer
            // and the real validator. Until then, fail closed at the
            // dispatcher so a misconfigured run cannot silently
            // report success.
            enforce_linux_only_until_validator_lands(
                LiveLabPlatform::Windows,
                STAGE_NAME,
                PHASE_NOTE,
            )
        }
    }
}

const STAGE_NAME: &str = "relay-service-lifecycle";
const PHASE_NOTE: &str =
    "Windows lands in Track B Phase 8 (needs SCM-driven rustynet-relay installer first)";

const SYSTEMD_RELAY_UNIT: &str = "rustynet-relay.service";
/// Reviewed UDP bind port for the relay datapath. The rustynet-relay
/// daemon binds the datapath via `UdpSocket::bind`
/// (`crates/rustynet-relay/src/main.rs`) so `ss` and `lsof` listener
/// captures MUST include UDP, otherwise the during-run check is
/// guaranteed to misclassify a healthy relay as down.
const RELAY_BIND_PORT: u16 = 4500;
/// Reviewed TCP bind port for the relay health/metrics endpoint
/// (loopback by default). TCP-LISTEN — distinct from `RELAY_BIND_PORT`.
const RELAY_HEALTH_PORT: u16 = 4501;
const RELAY_HEALTH_PATH: &str = "/healthz";

#[derive(Debug)]
struct Config {
    platform: LiveLabPlatform,
    ssh_identity_file: PathBuf,
    relay_host: String,
    relay_node_id: String,
    peer_host: String,
    peer_node_id: String,
    ssh_allow_cidrs: String,
    report_path: PathBuf,
    log_path: PathBuf,
    pinned_known_hosts_file: Option<PathBuf>,
    git_commit: Option<String>,
}

impl Config {
    fn parse(args: Vec<String>) -> Result<Self, String> {
        let mut config = Self {
            platform: LiveLabPlatform::Linux,
            ssh_identity_file: PathBuf::new(),
            relay_host: "debian@192.168.18.49".to_owned(),
            relay_node_id: "relay-49".to_owned(),
            peer_host: "debian@192.168.18.65".to_owned(),
            peer_node_id: "client-65".to_owned(),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            report_path: PathBuf::from("artifacts/phase10/live_linux_relay_report.json"),
            log_path: PathBuf::from("artifacts/phase10/source/live_linux_relay.log"),
            pinned_known_hosts_file: None,
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT").ok(),
        };

        let mut iter = args.into_iter();
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "--platform" => {
                    config.platform =
                        LiveLabPlatform::parse(next_value(&mut iter, &arg)?.as_str())?;
                }
                "--ssh-identity-file" => {
                    config.ssh_identity_file = PathBuf::from(next_value(&mut iter, &arg)?);
                }
                "--relay-host" => config.relay_host = next_value(&mut iter, &arg)?,
                "--relay-node-id" => config.relay_node_id = next_value(&mut iter, &arg)?,
                "--peer-host" => config.peer_host = next_value(&mut iter, &arg)?,
                "--peer-node-id" => config.peer_node_id = next_value(&mut iter, &arg)?,
                "--ssh-allow-cidrs" => config.ssh_allow_cidrs = next_value(&mut iter, &arg)?,
                "--report-path" => config.report_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--log-path" => config.log_path = PathBuf::from(next_value(&mut iter, &arg)?),
                "--known-hosts" => {
                    config.pinned_known_hosts_file =
                        Some(PathBuf::from(next_value(&mut iter, &arg)?));
                }
                "--git-commit" => config.git_commit = Some(next_value(&mut iter, &arg)?),
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                unknown => return Err(format!("unknown argument: {unknown}")),
            }
        }

        if config.ssh_identity_file.as_os_str().is_empty() {
            return Err(
                "usage: live_linux_relay_test --ssh-identity-file <path> [options]".to_owned(),
            );
        }
        for (label, value) in [
            ("relay-host", config.relay_host.as_str()),
            ("relay-node-id", config.relay_node_id.as_str()),
            ("peer-host", config.peer_host.as_str()),
            ("peer-node-id", config.peer_node_id.as_str()),
            ("ssh-allow-cidrs", config.ssh_allow_cidrs.as_str()),
        ] {
            ensure_safe_token(label, value)?;
        }
        Ok(config)
    }
}

fn next_value(iter: &mut std::vec::IntoIter<String>, flag: &str) -> Result<String, String> {
    iter.next()
        .ok_or_else(|| format!("missing value for {flag}"))
}

fn print_usage() {
    println!(
        "usage: live_linux_relay_test --ssh-identity-file <path> [options]\n\
         \n\
         Track B Phase 6 — real Linux relay-service-lifecycle live\n\
         validator. macOS + Windows fail closed at the dispatcher\n\
         until Phases 7 + 8.\n\
         \n\
         options:\n\
         \x20\x20--platform <linux|macos|windows>      default linux\n\
         \x20\x20--relay-host <user@host>              SSH target hosting the relay service\n\
         \x20\x20--relay-node-id <id>                  signed-membership node id of the relay host\n\
         \x20\x20--peer-host <user@host>               SSH target acting as the relay client\n\
         \x20\x20--peer-node-id <id>                   node id of the relay client\n\
         \x20\x20--ssh-allow-cidrs <cidr>              management CIDR\n\
         \x20\x20--report-path <path>                  JSON report output\n\
         \x20\x20--log-path <path>                     human-readable log output\n\
         \x20\x20--known-hosts <path>                  pinned SSH known_hosts (else $HOME default)\n\
         \x20\x20--git-commit <sha>                    override RUSTYNET_EXPECTED_GIT_COMMIT"
    );
}

// ─── Real Linux relay validator ───────────────────────────────────

#[derive(Debug, Serialize)]
struct RelayLifecycleSnapshot {
    captured_at_unix: i64,
    unit_state: String,
    listener_bound_4500: bool,
    listener_bound_4501: bool,
    health_status: String,
    health_active_sessions: Option<u64>,
    listener_summary: String,
}

#[derive(Debug, Serialize)]
struct RelayLifecycleArtifact<'a> {
    schema_version: u32,
    unit_name: &'static str,
    bind_port: u16,
    health_port: u16,
    during_run: &'a RelayLifecycleSnapshot,
    after_stop: &'a RelayLifecycleSnapshot,
    teardown_complete: bool,
}

#[derive(Debug, Serialize)]
struct RelayLifecycleReport {
    schema_version: u32,
    phase: &'static str,
    mode: &'static str,
    evidence_mode: &'static str,
    status: &'static str,
    platform: &'static str,
    captured_at: String,
    captured_at_unix: u64,
    git_commit: String,
    relay_host: String,
    relay_node_id: String,
    peer_host: String,
    peer_node_id: String,
    unit_name: &'static str,
    daemon_restart_status: String,
    lifecycle: serde_json::Value,
    source_artifacts: Vec<String>,
    detail: String,
}

fn run_linux_relay(config: &Config) -> Result<(), String> {
    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;
    let workspace = create_workspace("linux-relay-lifecycle")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let relay_target = config.relay_host.as_str();
    verify_sudo(&config.ssh_identity_file, &work_known_hosts, relay_target)?;

    // Phase 2 — during-run captures.
    let during_snapshot = capture_relay_lifecycle_snapshot(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
    )
    .map_err(|err| format!("linux relay: during-run capture failed: {err}"))?;

    // Phase 3 — stop the service via systemctl. The canonical
    // teardown verb releases listener sockets + drops sessions.
    run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
        &format!("/bin/systemctl stop {}", SYSTEMD_RELAY_UNIT),
    )
    .map_err(|err| format!("linux relay: systemctl stop failed: {err}"))?;
    std::thread::sleep(std::time::Duration::from_secs(3));

    // Phase 4 — after-stop captures.
    let after_snapshot = capture_relay_lifecycle_snapshot(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
    )
    .map_err(|err| format!("linux relay: after-stop capture failed: {err}"))?;

    // Phase 5 — restart so subsequent lab stages inherit a serving
    // relay. Capture the outcome and surface it in the report.
    let daemon_restart_status = match run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
        &format!("/bin/systemctl start {}", SYSTEMD_RELAY_UNIT),
    ) {
        Ok(()) => "restarted".to_owned(),
        Err(err) => format!("restart_failed: {err}"),
    };

    // Phase 6 — assertions.
    let mut failures: Vec<String> = Vec::new();
    if !during_snapshot.unit_state.eq_ignore_ascii_case("active") {
        failures.push(format!(
            "during-run unit_state {:?} expected 'active' — relay role not deployed?",
            during_snapshot.unit_state
        ));
    }
    if !during_snapshot.listener_bound_4500 {
        failures.push(format!(
            "during-run relay listener on :{} was NOT bound",
            RELAY_BIND_PORT
        ));
    }
    if !during_snapshot.listener_bound_4501 {
        failures.push(format!(
            "during-run health listener on :{} was NOT bound",
            RELAY_HEALTH_PORT
        ));
    }
    if !during_snapshot.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "during-run /healthz returned status {:?} expected 'ok'",
            during_snapshot.health_status
        ));
    }
    if after_snapshot.unit_state.eq_ignore_ascii_case("active") {
        failures.push(
            "after-stop unit_state still 'active' — systemctl stop did not take effect".to_owned(),
        );
    }
    if after_snapshot.listener_bound_4500 {
        failures.push(format!(
            "after-stop relay listener on :{} was STILL bound (teardown leaked it)",
            RELAY_BIND_PORT
        ));
    }
    if after_snapshot.listener_bound_4501 {
        failures.push(format!(
            "after-stop health listener on :{} was STILL bound (teardown leaked it)",
            RELAY_HEALTH_PORT
        ));
    }
    if after_snapshot.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "after-stop /healthz still answers with status {:?} — daemon socket was not released",
            after_snapshot.health_status
        ));
    }
    // The restart phase is part of the contract: the orchestrator
    // hands the host back to subsequent stages, so a silent restart
    // failure must surface as a failed report rather than hide
    // under a passing status.
    if daemon_restart_status.starts_with("restart_failed:") {
        failures.push(format!(
            "post-test {} restart failed; relay role is OFFLINE — {}",
            SYSTEMD_RELAY_UNIT, daemon_restart_status
        ));
    }

    let teardown_complete = !after_snapshot.listener_bound_4500
        && !after_snapshot.listener_bound_4501
        && !after_snapshot.unit_state.eq_ignore_ascii_case("active");
    let status = if failures.is_empty() { "pass" } else { "fail" };
    let detail = if failures.is_empty() {
        "all invariants held".to_owned()
    } else {
        failures.join("; ")
    };

    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        repo_root()?.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        repo_root()?.join(&config.report_path)
    };
    let root = repo_root()?;
    let git_commit = config
        .git_commit
        .clone()
        .unwrap_or_else(|| git_head_commit(&root).unwrap_or_else(|_| "unknown".to_owned()));
    let lifecycle = serde_json::to_value(RelayLifecycleArtifact {
        schema_version: 1,
        unit_name: SYSTEMD_RELAY_UNIT,
        bind_port: RELAY_BIND_PORT,
        health_port: RELAY_HEALTH_PORT,
        during_run: &during_snapshot,
        after_stop: &after_snapshot,
        teardown_complete,
    })
    .map_err(|err| format!("serialize relay lifecycle artifact failed: {err}"))?;

    let report = RelayLifecycleReport {
        schema_version: 1,
        phase: "phase10",
        mode: "live_linux_relay_lifecycle",
        evidence_mode: "measured",
        status,
        platform: "linux",
        captured_at: utc_now_string(),
        captured_at_unix: after_snapshot.captured_at_unix.max(0) as u64,
        git_commit,
        relay_host: config.relay_host.clone(),
        relay_node_id: config.relay_node_id.clone(),
        peer_host: config.peer_host.clone(),
        peer_node_id: config.peer_node_id.clone(),
        unit_name: SYSTEMD_RELAY_UNIT,
        daemon_restart_status,
        lifecycle,
        source_artifacts: vec![log_path.display().to_string()],
        detail: detail.clone(),
    };
    let mut body = serde_json::to_string(&report)
        .map_err(|err| format!("serialize linux relay report failed: {err}"))?;
    body.push('\n');
    write_file(&report_path, body.as_str())?;

    let log_body = format!(
        "[linux-relay-lifecycle] status={status} relay_host={} relay_node_id={} peer_host={} peer_node_id={} detail={}\n",
        config.relay_host, config.relay_node_id, config.peer_host, config.peer_node_id, detail
    );
    write_file(&log_path, log_body.as_str())?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "linux relay lifecycle invariants failed: {}",
            failures.join("; ")
        ))
    }
}

// ─── Track B Phase 7: macOS relay-service-lifecycle validator ─────
//
// Mirrors `run_linux_relay` but uses launchctl + the macOS-native
// listener / health probe stack. The shared snapshot type
// `RelayLifecycleSnapshot` and the orchestrator-visible report
// envelope `RelayLifecycleReport` keep both platforms in lockstep so
// a future schema change forces an update on both.
fn run_macos_relay(config: &Config) -> Result<(), String> {
    for command in ["ssh", "ssh-keygen"] {
        require_command(command)?;
    }
    validate_identity(&config.ssh_identity_file)?;
    let pinned_known_hosts = match config.pinned_known_hosts_file.as_ref() {
        Some(path) => path.clone(),
        None => load_home_known_hosts_path()?,
    };
    ensure_pinned_known_hosts_file(&pinned_known_hosts)?;
    let workspace = create_workspace("macos-relay-lifecycle")?;
    let work_known_hosts = workspace.path().join("known_hosts");
    seed_known_hosts(&pinned_known_hosts, &work_known_hosts)?;

    let relay_target = config.relay_host.as_str();
    // verify_sudo's /etc/hosts grep is Linux-PAM-specific; macOS uses
    // verify_passwordless_sudo so a healthy macOS host without its
    // hostname in /etc/hosts is not rejected spuriously.
    verify_passwordless_sudo(&config.ssh_identity_file, &work_known_hosts, relay_target)?;

    let during_snapshot = capture_macos_relay_lifecycle_snapshot(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
    )
    .map_err(|err| format!("macos relay: during-run capture failed: {err}"))?;

    // launchctl bootout is the canonical macOS daemon-stop verb.
    // Accept a non-zero exit (the daemon may be loaded under a
    // different domain) but require the subsequent listener capture
    // to prove the cleanup happened — we never trust the stop verb's
    // success on its own.
    let _ = run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
        &format!(
            "/bin/launchctl bootout system/{} 2>/dev/null || /bin/launchctl unload {} 2>/dev/null || true",
            REVIEWED_MACOS_RELAY_LAUNCHD_LABEL, REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH
        ),
    );
    std::thread::sleep(std::time::Duration::from_secs(3));

    let after_snapshot = capture_macos_relay_lifecycle_snapshot(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
    )
    .map_err(|err| format!("macos relay: after-stop capture failed: {err}"))?;

    let daemon_restart_status = match run_root(
        &config.ssh_identity_file,
        &work_known_hosts,
        relay_target,
        &format!(
            "/bin/launchctl bootstrap system {} 2>/dev/null || /bin/launchctl load {}",
            REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH, REVIEWED_MACOS_RELAY_LAUNCHD_PLIST_PATH
        ),
    ) {
        Ok(()) => "restarted".to_owned(),
        Err(err) => format!("restart_failed: {err}"),
    };

    let mut failures: Vec<String> = Vec::new();
    if !during_snapshot.unit_state.eq_ignore_ascii_case("active") {
        failures.push(format!(
            "during-run unit_state {:?} expected 'active' — launchd PID not found?",
            during_snapshot.unit_state
        ));
    }
    if !during_snapshot.listener_bound_4500 {
        failures.push(format!(
            "during-run relay listener on :{} was NOT bound",
            RELAY_BIND_PORT
        ));
    }
    if !during_snapshot.listener_bound_4501 {
        failures.push(format!(
            "during-run health listener on :{} was NOT bound",
            RELAY_HEALTH_PORT
        ));
    }
    if !during_snapshot.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "during-run /healthz returned status {:?} expected 'ok'",
            during_snapshot.health_status
        ));
    }
    if after_snapshot.unit_state.eq_ignore_ascii_case("active") {
        failures.push(
            "after-stop unit_state still 'active' — launchctl bootout did not take effect"
                .to_owned(),
        );
    }
    if after_snapshot.listener_bound_4500 {
        failures.push(format!(
            "after-stop relay listener on :{} was STILL bound (teardown leaked it)",
            RELAY_BIND_PORT
        ));
    }
    if after_snapshot.listener_bound_4501 {
        failures.push(format!(
            "after-stop health listener on :{} was STILL bound (teardown leaked it)",
            RELAY_HEALTH_PORT
        ));
    }
    if after_snapshot.health_status.eq_ignore_ascii_case("ok") {
        failures.push(format!(
            "after-stop /healthz still answers with status {:?} — daemon socket was not released",
            after_snapshot.health_status
        ));
    }
    if daemon_restart_status.starts_with("restart_failed:") {
        failures.push(format!(
            "post-test launchctl bootstrap failed; macOS relay is OFFLINE — {}",
            daemon_restart_status
        ));
    }

    let teardown_complete = !after_snapshot.listener_bound_4500
        && !after_snapshot.listener_bound_4501
        && !after_snapshot.unit_state.eq_ignore_ascii_case("active");
    let status = if failures.is_empty() { "pass" } else { "fail" };
    let detail = if failures.is_empty() {
        "all invariants held".to_owned()
    } else {
        failures.join("; ")
    };

    let log_path = if config.log_path.is_absolute() {
        config.log_path.clone()
    } else {
        repo_root()?.join(&config.log_path)
    };
    let report_path = if config.report_path.is_absolute() {
        config.report_path.clone()
    } else {
        repo_root()?.join(&config.report_path)
    };
    let root = repo_root()?;
    let git_commit = config
        .git_commit
        .clone()
        .unwrap_or_else(|| git_head_commit(&root).unwrap_or_else(|_| "unknown".to_owned()));
    let lifecycle = serde_json::to_value(RelayLifecycleArtifact {
        schema_version: 1,
        unit_name: REVIEWED_MACOS_RELAY_LAUNCHD_LABEL,
        bind_port: RELAY_BIND_PORT,
        health_port: RELAY_HEALTH_PORT,
        during_run: &during_snapshot,
        after_stop: &after_snapshot,
        teardown_complete,
    })
    .map_err(|err| format!("serialize relay lifecycle artifact failed: {err}"))?;

    let report = RelayLifecycleReport {
        schema_version: 1,
        phase: "phase10",
        mode: "live_macos_relay_lifecycle",
        evidence_mode: "measured",
        status,
        platform: "macos",
        captured_at: utc_now_string(),
        captured_at_unix: after_snapshot.captured_at_unix.max(0) as u64,
        git_commit,
        relay_host: config.relay_host.clone(),
        relay_node_id: config.relay_node_id.clone(),
        peer_host: config.peer_host.clone(),
        peer_node_id: config.peer_node_id.clone(),
        unit_name: REVIEWED_MACOS_RELAY_LAUNCHD_LABEL,
        daemon_restart_status,
        lifecycle,
        source_artifacts: vec![log_path.display().to_string()],
        detail: detail.clone(),
    };
    let mut body = serde_json::to_string(&report)
        .map_err(|err| format!("serialize macos relay report failed: {err}"))?;
    body.push('\n');
    write_file(&report_path, body.as_str())?;

    let log_body = format!(
        "[macos-relay-lifecycle] status={status} relay_host={} relay_node_id={} peer_host={} peer_node_id={} detail={}\n",
        config.relay_host, config.relay_node_id, config.peer_host, config.peer_node_id, detail
    );
    write_file(&log_path, log_body.as_str())?;

    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "macos relay lifecycle invariants failed: {}",
            failures.join("; ")
        ))
    }
}

fn capture_macos_relay_lifecycle_snapshot(
    identity: &Path,
    known_hosts: &Path,
    relay_target: &str,
) -> Result<RelayLifecycleSnapshot, String> {
    // `launchctl print system/<label>` exits non-zero when the
    // service is not loaded — pipe through `|| true` so the captured
    // stdout carries the diagnostic (or stays empty for absent
    // services) rather than triggering a shell error.
    let launchctl_print = capture_root(
        identity,
        known_hosts,
        relay_target,
        &format!(
            "/bin/launchctl print system/{} 2>&1 || true",
            REVIEWED_MACOS_RELAY_LAUNCHD_LABEL
        ),
    )?;
    let unit_state = parse_macos_launchctl_print_state(launchctl_print.as_str());
    // Mirror the Linux path: capture UDP and TCP separately so each
    // port is matched against the right protocol. lsof has no LISTEN
    // state for UDP — a bound UDP socket prints without `(LISTEN)`,
    // so the UDP matcher must NOT require it.
    let udp_listeners = capture_root(
        identity,
        known_hosts,
        relay_target,
        "/usr/sbin/lsof -nP -iUDP 2>/dev/null || true",
    )?;
    let tcp_listeners = capture_root(
        identity,
        known_hosts,
        relay_target,
        "/usr/sbin/lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null || true",
    )?;
    let listener_bound_4500 =
        macos_udp_listener_summary_contains_port(udp_listeners.as_str(), RELAY_BIND_PORT);
    let listener_bound_4501 =
        macos_tcp_listener_summary_contains_port(tcp_listeners.as_str(), RELAY_HEALTH_PORT);
    let health_body = capture_remote_stdout(
        identity,
        known_hosts,
        relay_target,
        &format!(
            "/usr/bin/curl --silent --max-time 2 http://127.0.0.1:{}{} || true",
            RELAY_HEALTH_PORT, RELAY_HEALTH_PATH
        ),
    )
    .unwrap_or_default();
    let (health_status, health_active_sessions) = parse_relay_health_body(health_body.as_str());

    let mut listener_summary = String::new();
    for (label, body) in [
        ("udp", udp_listeners.as_str()),
        ("tcp", tcp_listeners.as_str()),
    ] {
        for line in body
            .lines()
            .filter(|line| {
                line.contains(&format!(":{}", RELAY_BIND_PORT))
                    || line.contains(&format!(":{}", RELAY_HEALTH_PORT))
            })
            .take(4)
        {
            listener_summary.push_str(label);
            listener_summary.push(' ');
            listener_summary.push_str(line);
            listener_summary.push('\n');
        }
    }
    Ok(RelayLifecycleSnapshot {
        captured_at_unix: unix_now_secs(),
        unit_state,
        listener_bound_4500,
        listener_bound_4501,
        health_status,
        health_active_sessions,
        listener_summary: listener_summary.trim_end().to_owned(),
    })
}

/// Parse `launchctl print system/<label>` stdout into a state word
/// that mirrors `systemctl is-active` ("active" / "inactive" /
/// "failed"). launchctl returns multi-line output containing a `pid`
/// field when the daemon is running and a `state = running` line.
/// When the service is not loaded launchctl writes
/// "Could not find service" to stderr (which we redirect to stdout
/// via `2>&1`).
fn parse_macos_launchctl_print_state(stdout: &str) -> String {
    let lower = stdout.to_ascii_lowercase();
    if lower.contains("could not find service") || lower.contains("service not loaded") {
        return "inactive".to_owned();
    }
    // launchctl uses `state = running` (with surrounding whitespace).
    if stdout
        .lines()
        .any(|line| line.trim().starts_with("state =") && line.contains("running"))
    {
        return "active".to_owned();
    }
    // A pid field with a non-zero numeric value implies the daemon
    // is up. launchctl prints `pid = <NNN>` for live daemons.
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
    if stdout.trim().is_empty() {
        return "inactive".to_owned();
    }
    "inactive".to_owned()
}

/// lsof `-iTCP -sTCP:LISTEN` lines look like
/// `rustynet-r  1234 rustynetd   10u  IPv4 0xabc      0t0  TCP 127.0.0.1:4501 (LISTEN)`.
/// Match on `(LISTEN)` plus the explicit port suffix so an ephemeral
/// outbound TCP connection on the same port cannot satisfy the check.
fn macos_tcp_listener_summary_contains_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{}", port),
        format!("*:{}", port),
        format!("[::1]:{}", port),
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
        format!("127.0.0.1:{}", port),
        format!("*:{}", port),
        format!("[::1]:{}", port),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.contains(" UDP ")
            && !trimmed.contains("->")
            && needles.iter().any(|needle| trimmed.ends_with(needle))
    })
}

fn capture_relay_lifecycle_snapshot(
    identity: &Path,
    known_hosts: &Path,
    relay_target: &str,
) -> Result<RelayLifecycleSnapshot, String> {
    // systemctl is-active returns non-zero when the unit is not
    // active, so use `|| true` so the captured stdout still carries
    // the state word (`active|inactive|failed|...`) instead of a
    // shell error.
    let unit_state = capture_root(
        identity,
        known_hosts,
        relay_target,
        &format!(
            "/bin/systemctl is-active {} 2>/dev/null || true",
            SYSTEMD_RELAY_UNIT
        ),
    )?;
    // The relay datapath binds UDP on :4500 and the health/metrics
    // endpoint binds TCP on :4501. `ss -tlnp` would miss the UDP
    // listener entirely — capture both protocols separately so each
    // port is checked against the right parser.
    let udp_summary = capture_root(
        identity,
        known_hosts,
        relay_target,
        "/usr/sbin/ss -ulnp 2>/dev/null || /bin/ss -ulnp 2>/dev/null || /usr/bin/ss -ulnp 2>/dev/null || true",
    )?;
    let tcp_summary = capture_root(
        identity,
        known_hosts,
        relay_target,
        "/usr/sbin/ss -tlnp 2>/dev/null || /bin/ss -tlnp 2>/dev/null || /usr/bin/ss -tlnp 2>/dev/null || true",
    )?;
    let listener_bound_4500 =
        linux_udp_summary_contains_port(udp_summary.as_str(), RELAY_BIND_PORT);
    let listener_bound_4501 =
        linux_tcp_summary_contains_listen_port(tcp_summary.as_str(), RELAY_HEALTH_PORT);
    let health_body = capture_remote_stdout(
        identity,
        known_hosts,
        relay_target,
        &format!(
            "curl --silent --max-time 2 http://127.0.0.1:{}{} || true",
            RELAY_HEALTH_PORT, RELAY_HEALTH_PATH
        ),
    )
    .unwrap_or_default();
    let (health_status, health_active_sessions) = parse_relay_health_body(health_body.as_str());

    let mut listener_summary = String::new();
    for (label, body) in [("udp", udp_summary.as_str()), ("tcp", tcp_summary.as_str())] {
        for line in body
            .lines()
            .filter(|line| {
                line.contains(&format!(":{}", RELAY_BIND_PORT))
                    || line.contains(&format!(":{}", RELAY_HEALTH_PORT))
            })
            .take(4)
        {
            listener_summary.push_str(label);
            listener_summary.push(' ');
            listener_summary.push_str(line);
            listener_summary.push('\n');
        }
    }

    Ok(RelayLifecycleSnapshot {
        captured_at_unix: unix_now_secs(),
        unit_state: unit_state.trim().to_owned(),
        listener_bound_4500,
        listener_bound_4501,
        health_status,
        health_active_sessions,
        listener_summary: listener_summary.trim_end().to_owned(),
    })
}

/// `ss -ulnp` lines for UDP look like
/// `UNCONN 0 0 127.0.0.1:4500 0.0.0.0:* users:(("rustynet-relay",...))`.
/// A bound UDP socket is reported as state `UNCONN` (UDP is
/// connectionless, so there is no LISTEN state). Match on `UNCONN`
/// plus the explicit port suffix preceded by an interface or
/// wildcard so an outbound UDP socket on the same port number
/// cannot be confused for a bound listener.
fn linux_udp_summary_contains_port(summary: &str, port: u16) -> bool {
    let needles = [
        format!("127.0.0.1:{}", port),
        format!("0.0.0.0:{}", port),
        format!("*:{}", port),
        format!("[::1]:{}", port),
        format!("[::]:{}", port),
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
        format!("127.0.0.1:{}", port),
        format!("0.0.0.0:{}", port),
        format!("*:{}", port),
        format!("[::1]:{}", port),
        format!("[::]:{}", port),
    ];
    summary.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("LISTEN") && needles.iter().any(|needle| trimmed.contains(needle))
    })
}

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

fn validate_identity(path: &Path) -> Result<(), String> {
    if !path.is_file() {
        return Err(format!("missing ssh identity file: {}", path.display()));
    }
    if path.is_symlink() {
        return Err(format!(
            "ssh identity file must not be a symlink: {}",
            path.display()
        ));
    }
    Ok(())
}

fn unix_now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn utc_now_string() -> String {
    let output = std::process::Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok();
    if let Some(output) = output
        && output.status.success()
    {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !text.is_empty() {
            return text;
        }
    }
    "1970-01-01T00:00:00Z".to_owned()
}

#[cfg(test)]
mod tests {
    use super::Config;
    use super::live_lab_bin_support::LiveLabPlatform;

    fn base_args() -> Vec<String> {
        vec!["--ssh-identity-file".to_owned(), "/tmp/id".to_owned()]
    }

    #[test]
    fn config_parse_defaults_to_linux_for_backward_compat() {
        let config = Config::parse(base_args()).expect("default parse");
        assert_eq!(config.platform, LiveLabPlatform::Linux);
        assert_eq!(config.relay_host, "debian@192.168.18.49");
    }

    #[test]
    fn config_parse_accepts_explicit_platform() {
        let mut args = base_args();
        args.push("--platform".to_owned());
        args.push("macos".to_owned());
        let config = Config::parse(args).expect("macos parse");
        assert_eq!(config.platform, LiveLabPlatform::MacOs);
    }

    #[test]
    fn config_parse_rejects_unknown_argument_fail_closed() {
        let mut args = base_args();
        args.push("--bogus-flag".to_owned());
        let err = Config::parse(args).expect_err("unknown flag must fail");
        assert!(err.contains("unknown argument"));
    }

    #[test]
    fn config_parse_requires_ssh_identity_file() {
        let err = Config::parse(Vec::new()).expect_err("missing identity must fail");
        assert!(err.contains("--ssh-identity-file"));
    }

    #[test]
    fn config_parse_rejects_unsafe_token_in_relay_host() {
        let mut args = base_args();
        args.push("--relay-host".to_owned());
        args.push("debian@host;rm -rf /".to_owned());
        let err = Config::parse(args).expect_err("shell metacharacters must fail closed");
        assert!(err.contains("unsupported characters"));
    }

    #[test]
    fn config_parse_accepts_git_commit_override() {
        let mut args = base_args();
        args.push("--git-commit".to_owned());
        args.push("deadbeefcafebabedeadbeefcafebabedeadbeef".to_owned());
        let config = Config::parse(args).expect("git_commit parse");
        assert_eq!(
            config.git_commit.as_deref(),
            Some("deadbeefcafebabedeadbeefcafebabedeadbeef")
        );
    }

    // Defense-in-depth gate wiring tests — same idiom as the Phase 3
    // scaffold so the dispatch arms in run() cannot be silently
    // dropped without a compile or test break.

    #[test]
    fn platform_gate_fails_closed_for_windows_with_phase_8_note() {
        // Track B Phase 7 ships macOS; Windows still fails closed
        // until Phase 8 lands the SCM-driven installer + validator.
        let err = super::enforce_linux_only_until_validator_lands(
            LiveLabPlatform::Windows,
            super::STAGE_NAME,
            super::PHASE_NOTE,
        )
        .expect_err("Windows must fail closed in Phase 7");
        assert!(err.contains("Windows"));
        assert!(err.contains(super::STAGE_NAME));
        assert!(err.contains("Phase 8"));
    }

    // Parser / pure-input helper coverage.

    #[test]
    fn linux_tcp_summary_matches_loopback_listen_for_health_port() {
        let body = "State        Recv-Q Send-Q Local Address:Port   Peer Address:Port\n\
                    LISTEN       0      128    127.0.0.1:4501       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=11))\n";
        assert!(super::linux_tcp_summary_contains_listen_port(body, 4501));
        assert!(!super::linux_tcp_summary_contains_listen_port(body, 4502));
    }

    #[test]
    fn linux_tcp_summary_rejects_non_listen_lines_for_same_port() {
        // ESTAB lines must not satisfy the LISTEN check — the daemon
        // could have an outbound socket on the port without binding.
        let body = "ESTAB        0      0      127.0.0.1:4501       127.0.0.1:55512     users:((\"curl\",pid=4321,fd=4))\n";
        assert!(!super::linux_tcp_summary_contains_listen_port(body, 4501));
    }

    #[test]
    fn linux_udp_summary_matches_unconn_bound_socket_for_relay_port() {
        // `ss -ulnp` prints UDP bound sockets with state `UNCONN`
        // since UDP has no LISTEN state. The matcher must accept
        // UNCONN + the explicit port suffix.
        let body = "State        Recv-Q Send-Q Local Address:Port   Peer Address:Port\n\
                    UNCONN       0      0      127.0.0.1:4500       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=10))\n";
        assert!(super::linux_udp_summary_contains_port(body, 4500));
    }

    #[test]
    fn linux_udp_summary_rejects_tcp_listen_lines() {
        // A TCP LISTEN on the same port number must NOT satisfy the
        // UDP check (defense-in-depth — the validator captures
        // protocols separately, but if the captures are crossed by
        // mistake the parser should still refuse).
        let body = "LISTEN       0      128    127.0.0.1:4500       0.0.0.0:*           users:((\"rustynet-relay\",pid=1234,fd=10))\n";
        assert!(!super::linux_udp_summary_contains_port(body, 4500));
    }

    #[test]
    fn parse_relay_health_body_parses_ok_status_and_session_count() {
        let body = r#"{"status":"ok","active_sessions":3,"allocated_ports":3,"max_sessions_per_node":8,"max_total_sessions":4096}"#;
        let (status, sessions) = super::parse_relay_health_body(body);
        assert_eq!(status, "ok");
        assert_eq!(sessions, Some(3));
    }

    #[test]
    fn parse_relay_health_body_returns_unreachable_for_empty_body() {
        let (status, sessions) = super::parse_relay_health_body("");
        assert_eq!(status, "unreachable");
        assert!(sessions.is_none());
    }

    #[test]
    fn parse_relay_health_body_returns_malformed_token_for_non_json() {
        let (status, _) =
            super::parse_relay_health_body("curl: (7) Failed to connect to 127.0.0.1 port 4501");
        assert!(status.starts_with("malformed: "), "got: {status}");
    }

    #[test]
    fn relay_lifecycle_report_serializes_with_serde_envelope() {
        // The canonical live-lab envelope shape must round-trip
        // through serde_json so an operator-supplied host string
        // with embedded quotes/newlines cannot break the report
        // parser downstream.
        let during = super::RelayLifecycleSnapshot {
            captured_at_unix: 100,
            unit_state: "active".to_owned(),
            listener_bound_4500: true,
            listener_bound_4501: true,
            health_status: "ok".to_owned(),
            health_active_sessions: Some(2),
            listener_summary: "LISTEN 0 128 127.0.0.1:4500 0.0.0.0:*".to_owned(),
        };
        let after = super::RelayLifecycleSnapshot {
            captured_at_unix: 200,
            unit_state: "inactive".to_owned(),
            listener_bound_4500: false,
            listener_bound_4501: false,
            health_status: "unreachable".to_owned(),
            health_active_sessions: None,
            listener_summary: String::new(),
        };
        let lifecycle = serde_json::to_value(super::RelayLifecycleArtifact {
            schema_version: 1,
            unit_name: super::SYSTEMD_RELAY_UNIT,
            bind_port: super::RELAY_BIND_PORT,
            health_port: super::RELAY_HEALTH_PORT,
            during_run: &during,
            after_stop: &after,
            teardown_complete: true,
        })
        .expect("artifact serialize");
        let report = super::RelayLifecycleReport {
            schema_version: 1,
            phase: "phase10",
            mode: "live_linux_relay_lifecycle",
            evidence_mode: "measured",
            status: "fail",
            platform: "linux",
            captured_at: "1970-01-01T00:00:00Z".to_owned(),
            captured_at_unix: 200,
            git_commit: "deadbeef".to_owned(),
            relay_host: "debian@192.168.18.49 \" inject \n more".to_owned(),
            relay_node_id: "relay-49".to_owned(),
            peer_host: "debian@192.168.18.65".to_owned(),
            peer_node_id: "client-65".to_owned(),
            unit_name: super::SYSTEMD_RELAY_UNIT,
            daemon_restart_status: "restart_failed: ssh down".to_owned(),
            lifecycle,
            source_artifacts: vec!["live-lab/linux-relay.log".to_owned()],
            detail: "all invariants held".to_owned(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: serde_json::Value =
            serde_json::from_str(&json).expect("must produce valid JSON round-trip");
        assert_eq!(parsed["status"], "fail");
        assert_eq!(parsed["platform"], "linux");
        assert_eq!(parsed["mode"], "live_linux_relay_lifecycle");
        assert_eq!(parsed["phase"], "phase10");
        assert_eq!(parsed["evidence_mode"], "measured");
        assert_eq!(parsed["unit_name"], super::SYSTEMD_RELAY_UNIT);
        assert_eq!(
            parsed["lifecycle"]["during_run"]["listener_bound_4500"],
            true
        );
        assert_eq!(
            parsed["lifecycle"]["after_stop"]["listener_bound_4500"],
            false
        );
        assert_eq!(parsed["lifecycle"]["teardown_complete"], true);
        assert_eq!(
            parsed["daemon_restart_status"], "restart_failed: ssh down",
            "restart failure must be visible in the report"
        );
        assert_eq!(
            parsed["relay_host"], "debian@192.168.18.49 \" inject \n more",
            "embedded quote/newline must survive serde escaping"
        );
    }

    // ─── Track B Phase 7: macOS parser coverage ────────────────────

    #[test]
    fn parse_macos_launchctl_print_state_recognises_running_daemon() {
        let stdout = "system/com.rustynet.relay = {\n\
                      \tpid = 12345\n\
                      \tstate = running\n\
                      \tprogram = /usr/local/bin/rustynet-relay\n\
                      }\n";
        assert_eq!(super::parse_macos_launchctl_print_state(stdout), "active");
    }

    #[test]
    fn parse_macos_launchctl_print_state_recognises_unloaded_service() {
        // launchctl writes "Could not find service" to stderr when
        // the label is not loaded; the validator redirects 2>&1 so
        // we see it on stdout. Must classify as `inactive`.
        let stdout = "Could not find service \"com.rustynet.relay\" in domain for system\n";
        assert_eq!(super::parse_macos_launchctl_print_state(stdout), "inactive");
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
        assert_eq!(super::parse_macos_launchctl_print_state(stdout), "active");
    }

    #[test]
    fn parse_macos_launchctl_print_state_returns_inactive_for_empty_stdout() {
        assert_eq!(super::parse_macos_launchctl_print_state(""), "inactive");
    }

    #[test]
    fn macos_tcp_listener_summary_matches_loopback_listen_for_health_port() {
        let body = "COMMAND  PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n\
                    rustynet 123 r    11u IPv4 0xabd      0t0  TCP 127.0.0.1:4501 (LISTEN)\n";
        assert!(super::macos_tcp_listener_summary_contains_port(body, 4501));
        assert!(!super::macos_tcp_listener_summary_contains_port(body, 4502));
    }

    #[test]
    fn macos_tcp_listener_summary_rejects_established_connections_on_same_port() {
        let body = "rustynet 123 r    20u IPv4 0xfff      0t0  TCP 127.0.0.1:4501->127.0.0.1:55512 (ESTABLISHED)\n";
        assert!(!super::macos_tcp_listener_summary_contains_port(body, 4501));
    }

    #[test]
    fn macos_tcp_listener_summary_accepts_wildcard_bind_form() {
        let body = "rustynet 123 r    11u IPv4 0xabd      0t0  TCP *:4501 (LISTEN)\n";
        assert!(super::macos_tcp_listener_summary_contains_port(body, 4501));
    }

    #[test]
    fn macos_udp_listener_summary_matches_bound_relay_port() {
        // macOS lsof prints bound UDP sockets WITHOUT `(LISTEN)`.
        let body = "rustynet 123 r    10u IPv4 0xabc      0t0  UDP 127.0.0.1:4500\n";
        assert!(super::macos_udp_listener_summary_contains_port(body, 4500));
    }

    #[test]
    fn macos_udp_listener_summary_rejects_outbound_with_peer_endpoint() {
        // lsof prints outbound UDP sockets with a learnt peer as
        // `local->remote`. Must NOT satisfy the bound-listener check.
        let body = "rustynet 123 r    20u IPv4 0xfff      0t0  UDP 127.0.0.1:4500->10.0.0.1:5555\n";
        assert!(!super::macos_udp_listener_summary_contains_port(body, 4500));
    }

    #[test]
    fn macos_udp_listener_summary_rejects_tcp_listen_for_same_port() {
        // Defense-in-depth: TCP LISTEN on the same port number must
        // NOT satisfy the UDP matcher.
        let body = "rustynet 123 r    11u IPv4 0xabd      0t0  TCP 127.0.0.1:4500 (LISTEN)\n";
        assert!(!super::macos_udp_listener_summary_contains_port(body, 4500));
    }
}
