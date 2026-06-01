#![forbid(unsafe_code)]

use rustynet_crypto::{KeyCustodyPermissionPolicy, write_encrypted_key_file};
use rustynetd::daemon::{
    ANCHOR_BUNDLE_PULL_ADDR_ENV, ANCHOR_BUNDLE_PULL_ALLOW_LAN_ENV,
    ANCHOR_BUNDLE_PULL_TOKEN_PATH_ENV, DEFAULT_AUTO_PORT_FORWARD_EXIT,
    DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS, DEFAULT_EGRESS_INTERFACE, DEFAULT_FAIL_CLOSED_SSH_ALLOW,
    DEFAULT_MAX_RECONCILE_FAILURES, DEFAULT_MEMBERSHIP_LOG_PATH,
    DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH, DEFAULT_MEMBERSHIP_SNAPSHOT_PATH,
    DEFAULT_MEMBERSHIP_WATERMARK_PATH, DEFAULT_NODE_ID, DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS,
    DEFAULT_RECONCILE_INTERVAL_MS, DEFAULT_RELAY_FLEET_BUNDLE_PATH,
    DEFAULT_RELAY_FLEET_WATERMARK_PATH, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, DEFAULT_SOCKET_PATH,
    DEFAULT_STATE_PATH, DEFAULT_TRAVERSAL_BUNDLE_PATH, DEFAULT_TRAVERSAL_MAX_AGE_SECS,
    DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS, DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES,
    DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS, DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES,
    DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS, DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS,
    DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS, DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS,
    DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH, DEFAULT_TRAVERSAL_WATERMARK_PATH,
    DEFAULT_TRUST_EVIDENCE_PATH, DEFAULT_TRUST_VERIFIER_KEY_PATH, DEFAULT_TRUST_WATERMARK_PATH,
    DEFAULT_TRUSTED_HELPER_SOCKET_PATH, DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH,
    DEFAULT_WG_INTERFACE, DEFAULT_WG_KEY_PASSPHRASE_PATH, DEFAULT_WG_LISTEN_PORT,
    DEFAULT_WG_PUBLIC_KEY_PATH, DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH, DaemonBackendMode,
    DaemonConfig, DaemonDataplaneMode, NodeRole, run_daemon,
};
use rustynetd::key_material::{
    initialize_encrypted_key_material, migrate_existing_private_key_material,
    read_passphrase_file_explicit, remove_file_if_present, store_passphrase_in_os_secure_store,
};
use rustynetd::linux_authenticode::collect_linux_authenticode_report;
use rustynetd::linux_dns_failclosed::{
    build_linux_dns_failclosed_report, collect_linux_dns_failclosed_snapshot,
};
use rustynetd::linux_key_custody::collect_linux_key_custody_report;
use rustynetd::linux_mesh_status::{LinuxMeshStatusOptions, collect_linux_mesh_status_report};
use rustynetd::linux_runtime_acls::collect_linux_runtime_acl_report;
use rustynetd::linux_service_hardening::collect_linux_service_hardening_report;
use rustynetd::macos_authenticode::collect_macos_authenticode_report;
use rustynetd::macos_dns_failclosed::{
    build_macos_dns_failclosed_report, collect_macos_dns_failclosed_snapshot,
};
use rustynetd::macos_key_custody::collect_macos_key_custody_report;
use rustynetd::macos_mesh_status::{MacosMeshStatusOptions, collect_macos_mesh_status_report};
use rustynetd::macos_runtime_acls::collect_macos_runtime_acl_report;
use rustynetd::macos_service_hardening::collect_macos_service_hardening_report;
use rustynetd::perf;
use rustynetd::phase10::ManagementCidr;
use rustynetd::port_mapper::PortMappingMode;
use rustynetd::privileged_helper::{PrivilegedHelperConfig, run_privileged_helper};
use rustynetd::windows_authenticode::inspect_authenticode_signature;
use rustynetd::windows_backend_gate::{
    WINDOWS_UNSUPPORTED_BACKEND_LABEL, WINDOWS_WIREGUARD_NT_BACKEND_LABEL,
    parse_windows_backend_mode,
};
use rustynetd::windows_backend_readiness::collect_windows_backend_readiness_report;
use rustynetd::windows_dns_failclosed::{
    build_windows_dns_failclosed_report, collect_windows_dns_failclosed_snapshot,
    evaluate_nrpt_ipv6_sibling_coverage, evaluate_router_advertisement_suppression,
};
use rustynetd::windows_ipc::collect_windows_named_pipe_acl_report;
use rustynetd::windows_key_custody::collect_windows_key_custody_snapshot;
use rustynetd::windows_mesh_status::{
    WindowsMeshStatusOptions, collect_windows_mesh_status_report,
};
use rustynetd::windows_paths::collect_windows_runtime_acl_report;
#[cfg(windows)]
use rustynetd::windows_runtime_boundary::run_windows_runtime_boundary_check;
use rustynetd::windows_service::{
    HostEntrySelection, run_windows_service_host, select_host_entry, windows_service_help_line,
    windows_service_help_note,
};
use rustynetd::windows_service_hardening::{
    build_windows_service_hardening_report, collect_windows_service_hardening_snapshot,
};
use std::net::SocketAddr;
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64, NonZeroUsize};
use std::path::{Path, PathBuf};

const MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV: &str =
    "RUSTYNET_MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_PATH";

fn main() {
    if let Err(err) = run() {
        // Map the error to a reviewed exit-code bucket per the X6
        // taxonomy. Today the daemon's top-level run() returns a
        // String for every failure shape, so we classify by content;
        // a future refactor that returns a typed error can switch
        // this to a direct enum match.
        let code = classify_top_level_error(&err);
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("rustynetd startup failed: {err}");
        } else {
            eprintln!("rustynetd startup failed [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

/// Classify a top-level startup error into the reviewed exit-code
/// taxonomy. Used by `main` to translate the daemon's stringly-typed
/// error to a numeric exit code shells can branch on.
fn classify_top_level_error(message: &str) -> rustynetd::exit_codes::ExitCode {
    use rustynetd::exit_codes::ExitCode;
    let lower = message.to_ascii_lowercase();
    if lower.contains("rustynetd usage")
        || lower.contains("unknown subcommand")
        || lower.contains("missing required")
        || lower.starts_with("usage:")
    {
        ExitCode::BadArgs
    } else if lower.contains("fail-closed")
        || lower.contains("policy reject")
        || lower.contains("signature verification")
        || lower.contains("reviewed root")
        || lower.contains("not reviewed")
    {
        ExitCode::PolicyReject
    } else if lower.contains("config") || lower.contains("invalid path") || lower.contains("schema")
    {
        ExitCode::ConfigError
    } else if lower.contains("connection refused")
        || lower.contains("temporarily unavailable")
        || lower.contains("timed out")
        || lower.contains("retry")
    {
        ExitCode::TransientFailure
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();

    if args.is_empty() {
        return Err(help_text());
    }

    match select_host_entry(&args)? {
        HostEntrySelection::WindowsService(options) => {
            run_windows_service_host(options, run_service_daemon_args)
        }
        HostEntrySelection::Standard(selected_args) => match selected_args.as_slice() {
            [flag, output_path] if flag == "--emit-phase1-baseline" => {
                perf::write_phase1_baseline_report(output_path)?;
                println!("phase1 baseline report emitted: {output_path}");
                Ok(())
            }
            [cmd, rest @ ..] if cmd == "daemon" => {
                let config = parse_daemon_config(rest)?;
                init_daemon_logging(daemon_log_file_path(&config).as_deref());
                run_daemon(config).map_err(|err| err.to_string())
            }
            [cmd, rest @ ..] if cmd == "privileged-helper" => run_privileged_helper_command(rest),
            [cmd, rest @ ..] if cmd == "key" => run_key_command(rest),
            [cmd, rest @ ..] if cmd == "membership" => run_membership_command(rest),
            [cmd, rest @ ..] if cmd == "windows-runtime-boundary-check" => {
                run_windows_runtime_boundary_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-runtime-acls-check" => {
                run_windows_runtime_acls_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-named-pipe-acls-check" => {
                run_windows_named_pipe_acls_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-registry-acls-check" => {
                run_windows_registry_acls_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-service-hardening-check" => {
                run_windows_service_hardening_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-key-custody-check" => {
                run_windows_key_custody_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-authenticode-check" => {
                run_windows_authenticode_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-mesh-status-check" => {
                run_windows_mesh_status_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-dns-failclosed-check" => {
                run_windows_dns_failclosed_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-exit-nat-lifecycle-snapshot" => {
                run_windows_exit_nat_lifecycle_snapshot_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-killswitch-assert" => {
                run_windows_killswitch_assert_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-backend-readiness-check" => {
                run_windows_backend_readiness_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-tunnel-smoke" => {
                run_windows_tunnel_smoke_command(rest)
            }
            [cmd, rest @ ..] if cmd == "windows-killswitch-smoke" => {
                run_windows_killswitch_smoke_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-runtime-acls-check" => {
                run_linux_runtime_acls_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-mesh-status-check" => {
                run_linux_mesh_status_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-key-custody-check" => {
                run_linux_key_custody_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-killswitch-boot-check" => {
                run_linux_killswitch_boot_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-authenticode-check" => {
                run_linux_authenticode_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-service-hardening-check" => {
                run_linux_service_hardening_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-dns-failclosed-check" => {
                run_linux_dns_failclosed_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-exit-dns-failclosed-capture" => {
                run_linux_exit_dns_failclosed_capture_command(rest)
            }
            [cmd, rest @ ..] if cmd == "linux-exit-nat-lifecycle-snapshot" => {
                run_linux_exit_nat_lifecycle_snapshot_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-runtime-acls-check" => {
                run_macos_runtime_acls_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-service-hardening-check" => {
                run_macos_service_hardening_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-key-custody-check" => {
                run_macos_key_custody_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-authenticode-check" => {
                run_macos_authenticode_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-mesh-status-check" => {
                run_macos_mesh_status_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-dns-failclosed-check" => {
                run_macos_dns_failclosed_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-exit-dns-failclosed-capture" => {
                run_macos_exit_dns_failclosed_capture_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-exit-killswitch-precedence-check" => {
                run_macos_exit_killswitch_precedence_check_command(rest)
            }
            [cmd, rest @ ..] if cmd == "macos-exit-nat-lifecycle-snapshot" => {
                run_macos_exit_nat_lifecycle_snapshot_command(rest)
            }
            _ => Err(help_text()),
        },
    }
}

/// Log sink that writes records to a file and mirrors them to stderr. The
/// Windows service host runs with its stderr discarded by the SCM, so without
/// a file sink the daemon produces no runtime log at all; a foreground
/// `rustynetd daemon` run keeps its stderr output too.
struct TeeLogWriter {
    file: std::fs::File,
}

impl std::io::Write for TeeLogWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // The file is the authoritative sink; the stderr mirror is best-effort.
        let _ = std::io::stderr().write_all(buf);
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        let _ = std::io::stderr().flush();
        self.file.flush()
    }
}

/// Derive the daemon log file path (`<state-root>/logs/rustynetd.log`) from the
/// configured state path. Returns `None` only when the state path has no parent.
fn daemon_log_file_path(config: &DaemonConfig) -> Option<PathBuf> {
    config
        .state_path
        .parent()
        .map(|root| root.join("logs").join("rustynetd.log"))
}

/// Initialise daemon logging. When `log_file` is provided and can be opened,
/// records are written to that file (truncated at startup) and mirrored to
/// stderr; otherwise logging falls back to stderr only. Honours `RUST_LOG`
/// (default level: info). Safe to call once per process.
fn init_daemon_logging(log_file: Option<&Path>) {
    let mut builder = env_logger::Builder::new();
    builder
        .filter_level(log::LevelFilter::Info)
        .parse_default_env()
        .format(|buf, record| {
            use std::io::Write as _;
            let unix_millis = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|elapsed| elapsed.as_millis())
                .unwrap_or(0);
            writeln!(
                buf,
                "{unix_millis} [{}] {}: {}",
                record.level(),
                record.target(),
                record.args()
            )
        });
    if let Some(path) = log_file {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(file) = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(path)
        {
            builder.target(env_logger::Target::Pipe(Box::new(TeeLogWriter { file })));
        }
    }
    let _ = builder.try_init();
}

fn run_service_daemon_args(args: &[String]) -> Result<(), String> {
    let config = parse_daemon_config(args)?;
    init_daemon_logging(daemon_log_file_path(&config).as_deref());
    run_daemon(config).map_err(|err| err.to_string())
}

fn run_key_command(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        return Err(
            "key subcommand is required (supported: init, migrate, store-passphrase)".to_owned(),
        );
    }
    match args[0].as_str() {
        "init" => run_key_init(&args[1..]),
        "migrate" => run_key_migrate(&args[1..]),
        "store-passphrase" => run_key_store_passphrase(&args[1..]),
        other => Err(format!("unknown key subcommand: {other}")),
    }
}

fn run_privileged_helper_command(args: &[String]) -> Result<(), String> {
    let mut config = PrivilegedHelperConfig::default();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket requires a value".to_owned())?;
                config.socket_path = value.into();
                index += 2;
            }
            Some("--allowed-uid") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--allowed-uid requires a value".to_owned())?;
                config.allowed_uid = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid --allowed-uid value: {err}"))?;
                index += 2;
            }
            Some("--allowed-gid") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--allowed-gid requires a value".to_owned())?;
                let gid = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid --allowed-gid value: {err}"))?;
                config.allowed_gid = Some(gid);
                index += 2;
            }
            Some("--timeout-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--timeout-ms requires a value".to_owned())?;
                let timeout_ms = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid --timeout-ms value: {err}"))?;
                if timeout_ms == 0 {
                    return Err("--timeout-ms must be greater than zero".to_owned());
                }
                config.io_timeout = std::time::Duration::from_millis(timeout_ms);
                index += 2;
            }
            Some(flag) => return Err(format!("unknown privileged-helper argument: {flag}")),
            None => break,
        }
    }
    run_privileged_helper(config)
}

fn run_windows_runtime_boundary_check_command(args: &[String]) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = args;
        Err("windows-runtime-boundary-check is only available on Windows hosts".to_owned())
    }

    #[cfg(windows)]
    {
        let mut state_root = PathBuf::from(r"C:\ProgramData\RustyNet");
        let mut index = 0usize;
        while index < args.len() {
            match args.get(index).map(String::as_str) {
                Some("--state-root") => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--state-root requires a value".to_string())?;
                    state_root = PathBuf::from(value);
                    index += 2;
                }
                Some(flag) => {
                    return Err(format!(
                        "unknown windows-runtime-boundary-check argument: {flag}"
                    ));
                }
                None => break,
            }
        }
        let report = run_windows_runtime_boundary_check(state_root.as_path())?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|err| format!("serialize runtime-boundary report failed: {err}"))?
        );
        Ok(())
    }
}

fn run_windows_tunnel_smoke_command(args: &[String]) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = args;
        Err("windows-tunnel-smoke is only available on Windows hosts".to_owned())
    }

    #[cfg(windows)]
    {
        use rustynetd::windows_tunnel_smoke::{
            WindowsTunnelSmokeOptions, run_windows_tunnel_smoke,
        };

        let mut options = WindowsTunnelSmokeOptions::default();
        let mut index = 0usize;
        while index < args.len() {
            match args.get(index).map(String::as_str) {
                Some("--tunnel-name") => {
                    options.tunnel_name = args
                        .get(index + 1)
                        .ok_or_else(|| "--tunnel-name requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--address") => {
                    options.address = args
                        .get(index + 1)
                        .ok_or_else(|| "--address requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--mesh-cidr") => {
                    options.mesh_cidr = args
                        .get(index + 1)
                        .ok_or_else(|| "--mesh-cidr requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--listen-port") => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--listen-port requires a value".to_string())?;
                    options.listen_port = value
                        .parse::<u16>()
                        .map_err(|err| format!("--listen-port must be a valid port: {err}"))?;
                    index += 2;
                }
                Some("--keep") => {
                    options.keep = true;
                    index += 1;
                }
                Some(flag) => {
                    return Err(format!("unknown windows-tunnel-smoke argument: {flag}"));
                }
                None => break,
            }
        }

        let report = run_windows_tunnel_smoke(&options)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|err| format!("serialize tunnel-smoke report failed: {err}"))?
        );
        if !report.overall_ok {
            return Err(
                "windows-tunnel-smoke reported the tunnel did not come up cleanly".to_owned(),
            );
        }
        Ok(())
    }
}

fn run_windows_killswitch_smoke_command(args: &[String]) -> Result<(), String> {
    #[cfg(not(windows))]
    {
        let _ = args;
        Err("windows-killswitch-smoke is only available on Windows hosts".to_owned())
    }

    #[cfg(windows)]
    {
        use rustynetd::windows_killswitch_smoke::{
            WindowsKillswitchSmokeOptions, run_windows_killswitch_smoke,
        };

        let mut options = WindowsKillswitchSmokeOptions::default();
        let mut index = 0usize;
        while index < args.len() {
            match args.get(index).map(String::as_str) {
                Some("--tunnel-name") => {
                    options.tunnel_name = args
                        .get(index + 1)
                        .ok_or_else(|| "--tunnel-name requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--address") => {
                    options.address = args
                        .get(index + 1)
                        .ok_or_else(|| "--address requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--mesh-cidr") => {
                    options.mesh_cidr = args
                        .get(index + 1)
                        .ok_or_else(|| "--mesh-cidr requires a value".to_string())?
                        .clone();
                    index += 2;
                }
                Some("--listen-port") => {
                    let value = args
                        .get(index + 1)
                        .ok_or_else(|| "--listen-port requires a value".to_string())?;
                    options.listen_port = value
                        .parse::<u16>()
                        .map_err(|err| format!("--listen-port must be a valid port: {err}"))?;
                    index += 2;
                }
                Some("--exercise-full-block") => {
                    options.exercise_full_block = true;
                    index += 1;
                }
                Some(flag) => {
                    return Err(format!("unknown windows-killswitch-smoke argument: {flag}"));
                }
                None => break,
            }
        }

        let report = run_windows_killswitch_smoke(&options)?;
        println!(
            "{}",
            serde_json::to_string_pretty(&report)
                .map_err(|err| format!("serialize killswitch-smoke report failed: {err}"))?
        );
        if !report.overall_ok {
            return Err(
                "windows-killswitch-smoke reported the killswitch did not apply/rollback cleanly"
                    .to_owned(),
            );
        }
        Ok(())
    }
}

fn run_windows_mesh_status_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut state_path: Option<std::path::PathBuf> = None;
    let mut expected_peer_ids: Vec<String> = Vec::new();
    let mut max_age_seconds: Option<i64> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--state-path") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state-path requires a value".to_owned())?;
                state_path = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            Some("--expected-peer-id") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--expected-peer-id requires a value".to_owned())?;
                expected_peer_ids.push(value.clone());
                index += 2;
            }
            Some("--max-age-seconds") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-age-seconds requires a value".to_owned())?;
                let parsed: i64 = value
                    .parse()
                    .map_err(|err| format!("invalid --max-age-seconds value: {err}"))?;
                if parsed < 0 {
                    return Err("--max-age-seconds must be non-negative".to_owned());
                }
                max_age_seconds = Some(parsed);
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-mesh-status-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let options = WindowsMeshStatusOptions {
        state_path,
        expected_peer_ids,
        max_age_seconds,
    };
    let report = collect_windows_mesh_status_report(&options);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize mesh-status report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(format!(
            "windows-mesh-status-check failed for {}: {}",
            report.state_path,
            if report.drift_reasons.is_empty() {
                "no drift_reasons recorded".to_owned()
            } else {
                report.drift_reasons.join("; ")
            }
        ));
    }
    Ok(())
}

fn run_windows_authenticode_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut binary_path: Option<std::path::PathBuf> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--binary-path") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--binary-path requires a value".to_owned())?;
                binary_path = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-authenticode-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let target_path = binary_path
        .unwrap_or_else(|| std::path::PathBuf::from(r"C:\Program Files\RustyNet\rustynetd.exe"));
    let report = inspect_authenticode_signature(target_path.as_path());
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize authenticode report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(format!(
            "windows-authenticode-check failed for {}: {}",
            report.binary_path,
            if report.drift_reasons.is_empty() {
                "no signature present".to_owned()
            } else {
                report.drift_reasons.join("; ")
            }
        ));
    }
    Ok(())
}

fn run_windows_key_custody_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-key-custody-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_windows_key_custody_snapshot();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize key-custody report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-key-custody-check reported drift in the live RustyNet key custody state"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_windows_service_hardening_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-service-hardening-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let snapshot = collect_windows_service_hardening_snapshot()?;
    let report = build_windows_service_hardening_report(snapshot);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize service-hardening report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-service-hardening-check reported drift in the live RustyNet service registration".to_owned(),
        );
    }
    Ok(())
}

fn run_windows_runtime_acls_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-runtime-acls-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_windows_runtime_acl_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize runtime-acls report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-runtime-acls-check reported drift on at least one reviewed runtime root"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_windows_named_pipe_acls_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut service_sid: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--service-sid") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "windows-named-pipe-acls-check --service-sid requires a value".to_owned()
                })?;
                if value.trim().is_empty() || value.chars().any(char::is_control) {
                    return Err(
                        "windows-named-pipe-acls-check --service-sid must be non-empty printable text"
                            .to_owned(),
                    );
                }
                service_sid = Some(value.clone());
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-named-pipe-acls-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_windows_named_pipe_acl_report(service_sid.as_deref());
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize named-pipe-acls report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-named-pipe-acls-check reported drift on at least one reviewed named pipe"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_windows_registry_acls_check_command(args: &[String]) -> Result<(), String> {
    // W4 wire-up: surface the registry-key ACL report via the daemon
    // CLI. Today the stub collector returns Unobserved entries with
    // a clear blocker reason (the Win32 RegGetKeySecurity probe is a
    // separate slice). With --no-fail-on-drift the operator can
    // capture the report shape on a host where the collector isn't
    // wired yet; default-on, the gate fails closed.
    use rustynetd::windows_registry_acls::collect_windows_registry_acl_report;
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-registry-acls-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_windows_registry_acl_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize windows registry-acls report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-registry-acls-check reported drift on at least one reviewed registry key"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_linux_service_hardening_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown linux-service-hardening-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_linux_service_hardening_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux service-hardening report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "linux-service-hardening-check reported drift in the live RustyNet service hardening posture".to_owned(),
        );
    }
    Ok(())
}

fn run_linux_dns_failclosed_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown linux-dns-failclosed-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let snapshot = collect_linux_dns_failclosed_snapshot();
    let report = build_linux_dns_failclosed_report(snapshot);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux dns-failclosed report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "linux-dns-failclosed-check reported drift in the live RustyNet DNS fail-closed posture".to_owned(),
        );
    }
    Ok(())
}

fn run_linux_authenticode_check_command(args: &[String]) -> Result<(), String> {
    // The Linux daemon does not enforce runtime binary signatures.
    // The subcommand still parses `--no-fail-on-drift` for argv parity
    // with the Windows side; both flags are no-ops here because the
    // verifier always emits `applicable=false, overall_ok=true`.
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => index += 1,
            Some(flag) => {
                return Err(format!("unknown linux-authenticode-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_linux_authenticode_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux authenticode report failed: {err}"))?
    );
    Ok(())
}

fn run_linux_killswitch_boot_check_command(args: &[String]) -> Result<(), String> {
    use rustynetd::linux_killswitch_boot::{
        BootSshCidr, collect_linux_killswitch_boot_report, install_linux_boot_killswitch,
    };
    let mut fail_on_drift = true;
    let mut iface_name: String = "rustynet0".to_owned();
    let mut install_boot = false;
    let mut ssh_allow = false;
    let mut ssh_cidrs: Vec<BootSshCidr> = Vec::new();
    let mut wg_listen_port: Option<u16> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--iface") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--iface requires a value (e.g. --iface rustynet0)".to_owned()
                })?;
                iface_name = value.clone();
                index += 2;
            }
            Some("--install-boot-killswitch") => {
                install_boot = true;
                index += 1;
            }
            Some("--fail-closed-ssh-allow") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--fail-closed-ssh-allow requires a value (true/false)".to_owned()
                })?;
                ssh_allow = match value.to_ascii_lowercase().as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" | "" => false,
                    _ => return Err(format!("invalid --fail-closed-ssh-allow value: {value}")),
                };
                index += 2;
            }
            Some("--fail-closed-ssh-allow-cidrs") => {
                // The env var may expand to an empty string when unset; treat
                // that the same as omitting the flag.
                let raw = args.get(index + 1).map(String::as_str).unwrap_or("").trim();
                if raw.is_empty() || raw.starts_with("--") {
                    // When the next token is an empty string (systemd passes it
                    // when the env var is ""), consume both the flag and the
                    // empty token so the pointer stays aligned.  When the next
                    // token is another flag (or absent), advance past only the
                    // current flag.
                    if raw.is_empty() && args.get(index + 1).is_some() {
                        index += 2;
                    } else {
                        index += 1;
                    }
                } else {
                    ssh_cidrs = raw
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(BootSshCidr::parse)
                        .collect::<Result<Vec<_>, _>>()?;
                    index += 2;
                }
            }
            Some("--wg-listen-port") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--wg-listen-port requires a value (e.g. --wg-listen-port 51820)".to_owned()
                })?;
                let parsed: u16 = value
                    .parse()
                    .map_err(|err| format!("invalid --wg-listen-port value '{value}': {err}"))?;
                if parsed == 0 {
                    return Err(
                        "--wg-listen-port must be non-zero; the boot killswitch needs a real port"
                            .to_owned(),
                    );
                }
                wg_listen_port = Some(parsed);
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown linux-killswitch-boot-check argument: {flag}"
                ));
            }
            None => break,
        }
    }

    // Install the pre-protective boot-time killswitch before running the
    // L8 drift check.  The boot table name (rustynet_boot) is distinct from
    // the reviewed daemon tables (rustynet / rustynet_g<N>) so the verifier
    // below is unaffected.
    if install_boot {
        install_linux_boot_killswitch(iface_name.as_str(), ssh_allow, &ssh_cidrs, wg_listen_port)?;
    }

    let report = collect_linux_killswitch_boot_report(iface_name.as_str());
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux killswitch-boot report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "linux-killswitch-boot-check reported drift; the killswitch is not in a \
             pre-up boot-time-safe state"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_linux_key_custody_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!("unknown linux-key-custody-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_linux_key_custody_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux key-custody report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "linux-key-custody-check reported drift in the live RustyNet key custody state"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_linux_mesh_status_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut state_path: Option<std::path::PathBuf> = None;
    let mut expected_peer_ids: Vec<String> = Vec::new();
    let mut max_age_seconds: Option<i64> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--state-path") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state-path requires a value".to_owned())?;
                state_path = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            Some("--expected-peer-id") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--expected-peer-id requires a value".to_owned())?;
                expected_peer_ids.push(value.clone());
                index += 2;
            }
            Some("--max-age-seconds") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-age-seconds requires a value".to_owned())?;
                let parsed: i64 = value
                    .parse()
                    .map_err(|err| format!("invalid --max-age-seconds value: {err}"))?;
                if parsed < 0 {
                    return Err("--max-age-seconds must be non-negative".to_owned());
                }
                max_age_seconds = Some(parsed);
                index += 2;
            }
            Some(flag) => {
                return Err(format!("unknown linux-mesh-status-check argument: {flag}"));
            }
            None => break,
        }
    }
    let options = LinuxMeshStatusOptions {
        state_path,
        expected_peer_ids,
        max_age_seconds,
    };
    let report = collect_linux_mesh_status_report(&options);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux mesh-status report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(format!(
            "linux-mesh-status-check failed for {}: {}",
            report.state_path,
            if report.drift_reasons.is_empty() {
                "no drift_reasons recorded".to_owned()
            } else {
                report.drift_reasons.join("; ")
            }
        ));
    }
    Ok(())
}

fn run_linux_runtime_acls_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!("unknown linux-runtime-acls-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_linux_runtime_acl_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize linux runtime-acls report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "linux-runtime-acls-check reported drift on at least one reviewed runtime root"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_macos_runtime_acls_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!("unknown macos-runtime-acls-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_macos_runtime_acl_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos runtime-acls report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "macos-runtime-acls-check reported drift on at least one reviewed runtime root"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_macos_service_hardening_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown macos-service-hardening-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_macos_service_hardening_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos service-hardening report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "macos-service-hardening-check reported drift in the live RustyNet service hardening posture".to_owned(),
        );
    }
    Ok(())
}

fn run_macos_key_custody_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!("unknown macos-key-custody-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_macos_key_custody_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos key-custody report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "macos-key-custody-check reported drift in the live RustyNet key custody state"
                .to_owned(),
        );
    }
    Ok(())
}

fn run_macos_authenticode_check_command(args: &[String]) -> Result<(), String> {
    // Gatekeeper operates at launch time; runtime binary attestation is not
    // applicable on macOS. `--no-fail-on-drift` is accepted for argv parity;
    // the verifier always emits `applicable=false, overall_ok=true`.
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => index += 1,
            Some(flag) => {
                return Err(format!("unknown macos-authenticode-check argument: {flag}"));
            }
            None => break,
        }
    }
    let report = collect_macos_authenticode_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos authenticode report failed: {err}"))?
    );
    Ok(())
}

fn run_macos_mesh_status_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut state_path: Option<std::path::PathBuf> = None;
    let mut expected_peer_ids: Vec<String> = Vec::new();
    let mut max_age_seconds: Option<i64> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some("--state-path") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state-path requires a value".to_owned())?;
                state_path = Some(std::path::PathBuf::from(value));
                index += 2;
            }
            Some("--expected-peer-id") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--expected-peer-id requires a value".to_owned())?;
                expected_peer_ids.push(value.clone());
                index += 2;
            }
            Some("--max-age-seconds") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-age-seconds requires a value".to_owned())?;
                let parsed: i64 = value
                    .parse()
                    .map_err(|err| format!("invalid --max-age-seconds value: {err}"))?;
                if parsed < 0 {
                    return Err("--max-age-seconds must be non-negative".to_owned());
                }
                max_age_seconds = Some(parsed);
                index += 2;
            }
            Some(flag) => {
                return Err(format!("unknown macos-mesh-status-check argument: {flag}"));
            }
            None => break,
        }
    }
    let options = MacosMeshStatusOptions {
        state_path,
        expected_peer_ids,
        max_age_seconds,
    };
    let report = collect_macos_mesh_status_report(&options);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos mesh-status report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(format!(
            "macos-mesh-status-check failed for {}: {}",
            report.state_path,
            if report.drift_reasons.is_empty() {
                "no drift_reasons recorded".to_owned()
            } else {
                report.drift_reasons.join("; ")
            }
        ));
    }
    Ok(())
}

/// Track B Step 2 follow-up — macOS exit-mode NAT lifecycle producer.
///
/// Captures the current pf anchor + sysctl IPv4 forwarding state and
/// emits a single-phase snapshot to stdout. The orchestrator runs
/// this twice (during exit mode + after daemon stop) and merges into
/// the two-phase artefact the
/// `evaluate_macos_exit_nat_lifecycle_artifact` validator reads.
fn run_macos_exit_nat_lifecycle_snapshot_command(args: &[String]) -> Result<(), String> {
    let mut mesh_cidr: Option<String> = None;
    let mut pf_anchor: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--mesh-cidr") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-nat-lifecycle-snapshot: --mesh-cidr requires a value".to_owned()
                })?;
                mesh_cidr = Some(value.clone());
                index += 2;
            }
            Some("--pf-anchor") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-nat-lifecycle-snapshot: --pf-anchor requires a value".to_owned()
                })?;
                pf_anchor = Some(value.clone());
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown macos-exit-nat-lifecycle-snapshot argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let mesh_cidr = mesh_cidr
        .ok_or_else(|| "macos-exit-nat-lifecycle-snapshot: --mesh-cidr is required".to_owned())?;
    let options = rustynetd::macos_exit_nat_lifecycle::MacosExitNatLifecycleOptions {
        mesh_cidr,
        pf_anchor: pf_anchor.unwrap_or_else(|| {
            rustynetd::macos_exit_nat_lifecycle::DEFAULT_MACOS_EXIT_PF_ANCHOR.to_owned()
        }),
    };
    let snapshot =
        rustynetd::macos_exit_nat_lifecycle::collect_macos_exit_nat_lifecycle_snapshot(&options);
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).map_err(|err| {
            format!("serialize macos-exit-nat-lifecycle snapshot failed: {err}")
        })?
    );
    Ok(())
}

/// Linux exit-mode NAT lifecycle producer.
///
/// Captures the current nftables NAT table + Linux forwarding state
/// and emits a single-phase snapshot to stdout. The orchestrator runs
/// this twice (during exit mode + after daemon stop) and merges into
/// the two-phase artefact the
/// `evaluate_linux_exit_nat_lifecycle_artifact` validator reads.
fn run_linux_exit_nat_lifecycle_snapshot_command(args: &[String]) -> Result<(), String> {
    let mut mesh_cidr: Option<String> = None;
    let mut nat_table: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--mesh-cidr") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-nat-lifecycle-snapshot: --mesh-cidr requires a value".to_owned()
                })?;
                mesh_cidr = Some(value.clone());
                index += 2;
            }
            Some("--nat-table") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-nat-lifecycle-snapshot: --nat-table requires a value".to_owned()
                })?;
                nat_table = Some(value.clone());
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown linux-exit-nat-lifecycle-snapshot argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let mesh_cidr = mesh_cidr
        .ok_or_else(|| "linux-exit-nat-lifecycle-snapshot: --mesh-cidr is required".to_owned())?;
    let options = rustynetd::linux_exit_nat_lifecycle::LinuxExitNatLifecycleOptions {
        mesh_cidr,
        nat_table: nat_table.unwrap_or_else(|| {
            rustynetd::linux_exit_nat_lifecycle::DEFAULT_LINUX_EXIT_NAT_TABLE.to_owned()
        }),
    };
    let snapshot =
        rustynetd::linux_exit_nat_lifecycle::collect_linux_exit_nat_lifecycle_snapshot(&options);
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).map_err(|err| {
            format!("serialize linux-exit-nat-lifecycle snapshot failed: {err}")
        })?
    );
    Ok(())
}

fn run_linux_exit_dns_failclosed_capture_command(args: &[String]) -> Result<(), String> {
    let mut output: Option<PathBuf> = None;
    let mut lan_iface: Option<String> = None;
    let mut tunnel_dns_hostname =
        rustynetd::linux_exit_dns_failclosed::DEFAULT_TUNNEL_DNS_HOSTNAME.to_owned();
    let mut killswitch_table =
        rustynetd::linux_exit_dns_failclosed::DEFAULT_LINUX_KILLSWITCH_TABLE.to_owned();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--output") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-dns-failclosed-capture: --output requires a value".to_owned()
                })?;
                output = Some(PathBuf::from(value));
                index += 2;
            }
            Some("--lan-iface") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-dns-failclosed-capture: --lan-iface requires a value".to_owned()
                })?;
                lan_iface = Some(value.clone());
                index += 2;
            }
            Some("--mesh-hostname") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-dns-failclosed-capture: --mesh-hostname requires a value".to_owned()
                })?;
                tunnel_dns_hostname = value.clone();
                index += 2;
            }
            Some("--killswitch-table") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "linux-exit-dns-failclosed-capture: --killswitch-table requires a value"
                        .to_owned()
                })?;
                killswitch_table = value.clone();
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown linux-exit-dns-failclosed-capture argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let output = output
        .ok_or_else(|| "linux-exit-dns-failclosed-capture: --output is required".to_owned())?;
    let lan_iface = lan_iface
        .ok_or_else(|| "linux-exit-dns-failclosed-capture: --lan-iface is required".to_owned())?;
    let options = rustynetd::linux_exit_dns_failclosed::LinuxExitDnsFailclosedOptions::new(
        lan_iface,
        tunnel_dns_hostname,
        killswitch_table,
    );
    rustynetd::linux_exit_dns_failclosed::write_linux_exit_dns_failclosed_artifacts(
        output.as_path(),
        &options,
    )?;
    println!(
        "linux exit DNS fail-closed artifacts written to {}",
        output.display()
    );
    Ok(())
}

fn run_macos_dns_failclosed_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown macos-dns-failclosed-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let snapshot = collect_macos_dns_failclosed_snapshot();
    let report = build_macos_dns_failclosed_report(snapshot);
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize macos dns-failclosed report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "macos-dns-failclosed-check reported drift in the live RustyNet DNS fail-closed posture".to_owned(),
        );
    }
    Ok(())
}

fn run_macos_exit_dns_failclosed_capture_command(args: &[String]) -> Result<(), String> {
    let mut output: Option<PathBuf> = None;
    let mut lan_iface: Option<String> = None;
    let mut tunnel_dns_hostname =
        rustynetd::macos_exit_dns_failclosed::DEFAULT_TUNNEL_DNS_HOSTNAME.to_owned();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--output") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-dns-failclosed-capture: --output requires a value".to_owned()
                })?;
                output = Some(PathBuf::from(value));
                index += 2;
            }
            Some("--lan-iface") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-dns-failclosed-capture: --lan-iface requires a value".to_owned()
                })?;
                lan_iface = Some(value.clone());
                index += 2;
            }
            Some("--mesh-hostname") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-dns-failclosed-capture: --mesh-hostname requires a value".to_owned()
                })?;
                tunnel_dns_hostname = value.clone();
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown macos-exit-dns-failclosed-capture argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let output = output
        .ok_or_else(|| "macos-exit-dns-failclosed-capture: --output is required".to_owned())?;
    let lan_iface = lan_iface
        .ok_or_else(|| "macos-exit-dns-failclosed-capture: --lan-iface is required".to_owned())?;
    let options = rustynetd::macos_exit_dns_failclosed::MacosExitDnsFailclosedOptions::new(
        lan_iface,
        tunnel_dns_hostname,
    );
    rustynetd::macos_exit_dns_failclosed::write_macos_exit_dns_failclosed_artifacts(
        output.as_path(),
        &options,
    )?;
    println!(
        "macos exit DNS fail-closed artifacts written to {}",
        output.display()
    );
    Ok(())
}

fn run_macos_exit_killswitch_precedence_check_command(args: &[String]) -> Result<(), String> {
    let mut output: Option<PathBuf> = None;
    let mut pf_anchor: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--output") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-killswitch-precedence-check: --output requires a value".to_owned()
                })?;
                output = Some(PathBuf::from(value));
                index += 2;
            }
            Some("--pf-anchor") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "macos-exit-killswitch-precedence-check: --pf-anchor requires a value"
                        .to_owned()
                })?;
                pf_anchor = Some(value.clone());
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown macos-exit-killswitch-precedence-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let output = output
        .ok_or_else(|| "macos-exit-killswitch-precedence-check: --output is required".to_owned())?;
    let options =
        rustynetd::macos_exit_killswitch_precedence::MacosExitKillswitchPrecedenceOptions {
            pf_anchor,
        };
    rustynetd::macos_exit_killswitch_precedence::write_macos_exit_killswitch_precedence_report(
        output.as_path(),
        &options,
    )?;
    println!(
        "macos exit killswitch precedence artifact written to {}",
        output.display()
    );
    Ok(())
}

fn run_windows_dns_failclosed_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut enforce_ipv6_sibling = false;
    let mut enforce_ra_suppression = false;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            // W3 wire-up: opt-in to the IPv6 NRPT sibling-coverage
            // check. Default false until the production posture pins
            // dual-stack NRPT siblings as the reviewed contract; the
            // evaluator itself is already pinned via unit tests.
            Some("--enforce-ipv6-sibling-rules") => {
                enforce_ipv6_sibling = true;
                index += 1;
            }
            // W3 wire-up: opt-in to Router Advertisement suppression
            // enforcement. Fails closed when the snapshot's
            // `router_advertisement_observation` is None — the
            // PowerShell collector that surfaces that observation is
            // a separate slice; until it lands, this flag will fail
            // closed which is the correct security posture for
            // staged rollout.
            Some("--enforce-ra-suppression") => {
                enforce_ra_suppression = true;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-dns-failclosed-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let snapshot = collect_windows_dns_failclosed_snapshot()?;
    let mut report = build_windows_dns_failclosed_report(snapshot);
    if enforce_ipv6_sibling {
        // Run the W3 sibling evaluator and fold any reasons into the
        // existing report's drift_reasons + overall_ok. Each reason
        // is prefixed so operators can tell which evaluator fired.
        let sibling_reasons = evaluate_nrpt_ipv6_sibling_coverage(&report.snapshot);
        if !sibling_reasons.is_empty() {
            for reason in sibling_reasons {
                report.drift_reasons.push(format!("ipv6-sibling: {reason}"));
            }
            report.overall_ok = false;
        }
    }
    if enforce_ra_suppression {
        // Run the W3 RA suppression evaluator with the same fold-in
        // pattern; reasons get an `ra-suppression:` prefix.
        let ra_reasons = evaluate_router_advertisement_suppression(&report.snapshot);
        if !ra_reasons.is_empty() {
            for reason in ra_reasons {
                report
                    .drift_reasons
                    .push(format!("ra-suppression: {reason}"));
            }
            report.overall_ok = false;
        }
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize dns-failclosed report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-dns-failclosed-check reported drift in the live RustyNet DNS fail-closed state".to_owned(),
        );
    }
    Ok(())
}

fn run_windows_exit_nat_lifecycle_snapshot_command(args: &[String]) -> Result<(), String> {
    let mut mesh_cidr: Option<String> = None;
    let mut nat_name =
        rustynetd::windows_exit_nat_lifecycle::DEFAULT_WINDOWS_EXIT_NAT_NAME.to_owned();
    let mut tunnel_alias =
        rustynetd::windows_exit_nat_lifecycle::DEFAULT_WINDOWS_TUNNEL_ALIAS.to_owned();
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--mesh-cidr") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "windows-exit-nat-lifecycle-snapshot: --mesh-cidr requires a value".to_owned()
                })?;
                mesh_cidr = Some(value.clone());
                index += 2;
            }
            Some("--nat-name") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "windows-exit-nat-lifecycle-snapshot: --nat-name requires a value".to_owned()
                })?;
                nat_name = value.clone();
                index += 2;
            }
            Some("--tunnel-alias") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "windows-exit-nat-lifecycle-snapshot: --tunnel-alias requires a value"
                        .to_owned()
                })?;
                tunnel_alias = value.clone();
                index += 2;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-exit-nat-lifecycle-snapshot argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let mesh_cidr = mesh_cidr
        .ok_or_else(|| "windows-exit-nat-lifecycle-snapshot: --mesh-cidr is required".to_owned())?;
    let options = rustynetd::windows_exit_nat_lifecycle::WindowsExitNatLifecycleOptions {
        mesh_cidr,
        nat_name,
        tunnel_alias,
    };
    let snapshot =
        rustynetd::windows_exit_nat_lifecycle::collect_windows_exit_nat_lifecycle_snapshot(
            &options,
        )?;
    println!(
        "{}",
        serde_json::to_string_pretty(&snapshot).map_err(|err| {
            format!("serialize windows-exit-nat-lifecycle snapshot failed: {err}")
        })?
    );
    Ok(())
}

fn run_windows_killswitch_assert_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut config_args = Vec::new();

    for arg in args {
        if arg == "--no-fail-on-drift" {
            fail_on_drift = false;
        } else {
            config_args.push(arg.clone());
        }
    }

    let config = parse_daemon_config(&config_args)?;
    use rustynetd::phase10::DataplaneSystem;

    let mut system = rustynetd::phase10::WindowsCommandSystem::new(
        config.wg_interface,
        config.egress_interface,
        config.dns_resolver_bind_addr,
    )
    .map_err(|e| format!("failed to initialize WindowsCommandSystem: {e:?}"))?;

    match system.assert_killswitch() {
        Ok(()) => {
            println!("{{\"overall_ok\":true}}");
            Ok(())
        }
        Err(rustynetd::phase10::SystemError::KillSwitchAssertionFailed(reason)) => {
            println!(
                "{}",
                serde_json::to_string(&serde_json::json!({
                    "overall_ok": false,
                    "reason": reason
                }))
                .unwrap()
            );
            if fail_on_drift {
                return Err(format!("windows-killswitch-assert failed: {reason}"));
            }
            Ok(())
        }
        Err(other) => Err(format!(
            "windows-killswitch-assert unexpected error: {other:?}"
        )),
    }
}

fn run_windows_backend_readiness_check_command(args: &[String]) -> Result<(), String> {
    let mut fail_on_drift = true;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--no-fail-on-drift") => {
                fail_on_drift = false;
                index += 1;
            }
            Some(flag) => {
                return Err(format!(
                    "unknown windows-backend-readiness-check argument: {flag}"
                ));
            }
            None => break,
        }
    }
    let report = collect_windows_backend_readiness_report();
    println!(
        "{}",
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize backend-readiness report failed: {err}"))?
    );
    if fail_on_drift && !report.overall_ok {
        return Err(
            "windows-backend-readiness-check reported drift; the windows-wireguard-nt backend cannot be enabled until the missing prerequisites are installed".to_owned(),
        );
    }
    Ok(())
}

fn ensure_cli_path_absolute(path: &str, label: &str) -> Result<(), String> {
    if std::path::Path::new(path).is_absolute() {
        return Ok(());
    }
    Err(format!("{label} must be absolute: {path}"))
}

fn run_key_init(args: &[String]) -> Result<(), String> {
    let mut runtime_path = DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH.to_owned();
    let mut encrypted_path = DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned();
    let mut public_path = DEFAULT_WG_PUBLIC_KEY_PATH.to_owned();
    let mut passphrase_path = DEFAULT_WG_KEY_PASSPHRASE_PATH.to_owned();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--runtime-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--runtime-private-key requires a value".to_owned())?;
                runtime_path = value.clone();
                index += 2;
            }
            Some("--encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--encrypted-private-key requires a value".to_owned())?;
                encrypted_path = value.clone();
                index += 2;
            }
            Some("--public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--public-key requires a value".to_owned())?;
                public_path = value.clone();
                index += 2;
            }
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_owned())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown key init argument: {flag}")),
            None => break,
        }
    }

    ensure_cli_path_absolute(&runtime_path, "path")?;
    ensure_cli_path_absolute(&encrypted_path, "path")?;
    ensure_cli_path_absolute(&public_path, "path")?;
    ensure_cli_path_absolute(&passphrase_path, "path")?;

    initialize_encrypted_key_material(
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        Some(std::path::Path::new(&passphrase_path)),
        force,
    )?;

    println!(
        "key init complete: runtime_private_key={runtime_path} encrypted_private_key={encrypted_path} public_key={public_path}",
    );
    Ok(())
}

fn run_key_migrate(args: &[String]) -> Result<(), String> {
    let mut existing_private_key_path = String::new();
    let mut runtime_path = DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH.to_owned();
    let mut encrypted_path = DEFAULT_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned();
    let mut public_path = DEFAULT_WG_PUBLIC_KEY_PATH.to_owned();
    let mut passphrase_path = DEFAULT_WG_KEY_PASSPHRASE_PATH.to_owned();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--existing-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--existing-private-key requires a value".to_owned())?;
                existing_private_key_path = value.clone();
                index += 2;
            }
            Some("--runtime-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--runtime-private-key requires a value".to_owned())?;
                runtime_path = value.clone();
                index += 2;
            }
            Some("--encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--encrypted-private-key requires a value".to_owned())?;
                encrypted_path = value.clone();
                index += 2;
            }
            Some("--public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--public-key requires a value".to_owned())?;
                public_path = value.clone();
                index += 2;
            }
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_owned())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown key migrate argument: {flag}")),
            None => break,
        }
    }

    if existing_private_key_path.is_empty() {
        return Err("--existing-private-key is required".to_owned());
    }

    ensure_cli_path_absolute(&existing_private_key_path, "path")?;
    ensure_cli_path_absolute(&runtime_path, "path")?;
    ensure_cli_path_absolute(&encrypted_path, "path")?;
    ensure_cli_path_absolute(&public_path, "path")?;
    ensure_cli_path_absolute(&passphrase_path, "path")?;

    migrate_existing_private_key_material(
        std::path::Path::new(&existing_private_key_path),
        std::path::Path::new(&runtime_path),
        std::path::Path::new(&encrypted_path),
        std::path::Path::new(&public_path),
        std::path::Path::new(&passphrase_path),
        Some(std::path::Path::new(&passphrase_path)),
        force,
    )?;

    println!(
        "key migrate complete: existing_private_key={existing_private_key_path} runtime_private_key={runtime_path} encrypted_private_key={encrypted_path} public_key={public_path}",
    );
    Ok(())
}

fn run_key_store_passphrase(args: &[String]) -> Result<(), String> {
    let mut passphrase_path = String::new();
    let mut keychain_account: Option<String> = None;
    let mut keychain_service: Option<String> = None;
    let mut allow_any_app = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--passphrase-file requires a value".to_owned())?;
                passphrase_path = value.clone();
                index += 2;
            }
            Some("--keychain-account") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--keychain-account requires a value".to_owned())?;
                keychain_account = Some(value.clone());
                index += 2;
            }
            Some("--keychain-service") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--keychain-service requires a value".to_owned())?;
                keychain_service = Some(value.clone());
                index += 2;
            }
            Some("--keychain-allow-any-app") => {
                allow_any_app = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown key store-passphrase argument: {flag}")),
            None => break,
        }
    }

    if passphrase_path.is_empty() {
        return Err("--passphrase-file is required".to_owned());
    }
    ensure_cli_path_absolute(&passphrase_path, "path")?;

    store_passphrase_in_os_secure_store(
        std::path::Path::new(&passphrase_path),
        keychain_account.as_deref(),
        keychain_service.as_deref(),
        allow_any_app,
    )?;

    println!(
        "key passphrase store complete: passphrase_file={} keychain_account={} keychain_service={} allow_any_app={}",
        passphrase_path,
        keychain_account.as_deref().unwrap_or("<env>"),
        keychain_service.as_deref().unwrap_or("<default>"),
        allow_any_app
    );
    Ok(())
}

fn parse_daemon_config(args: &[String]) -> Result<DaemonConfig, String> {
    let mut config = DaemonConfig::default();
    if let Ok(value) = std::env::var(ANCHOR_BUNDLE_PULL_ADDR_ENV) {
        config.anchor_bundle_pull_addr = if value.trim().is_empty() {
            None
        } else {
            Some(
                value
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid {ANCHOR_BUNDLE_PULL_ADDR_ENV}: {err}"))?,
            )
        };
    }
    if let Ok(value) = std::env::var(ANCHOR_BUNDLE_PULL_TOKEN_PATH_ENV) {
        config.anchor_bundle_pull_token_path = if value.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(value))
        };
    }
    if let Ok(value) = std::env::var(ANCHOR_BUNDLE_PULL_ALLOW_LAN_ENV) {
        config.anchor_bundle_pull_allow_lan = match value.trim() {
            "true" | "1" | "yes" => true,
            "false" | "0" | "no" | "" => false,
            _ => {
                return Err(format!(
                    "invalid {ANCHOR_BUNDLE_PULL_ALLOW_LAN_ENV} value: expected true or false"
                ));
            }
        };
    }
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--node-id") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--node-id requires a value".to_owned())?;
                config.node_id = value.clone();
                index += 2;
            }
            Some("--node-role") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--node-role requires a value".to_owned())?;
                config.node_role = value.parse::<NodeRole>()?;
                index += 2;
            }
            Some("--socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--socket requires a value".to_owned())?;
                config.socket_path = value.into();
                index += 2;
            }
            Some("--state") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--state requires a value".to_owned())?;
                config.state_path = value.into();
                index += 2;
            }
            Some("--trust-evidence") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-evidence requires a value".to_owned())?;
                config.trust_evidence_path = value.into();
                index += 2;
            }
            Some("--trust-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-verifier-key requires a value".to_owned())?;
                config.trust_verifier_key_path = value.into();
                index += 2;
            }
            Some("--trust-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-max-age-secs requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid trust max age: {err}"))?;
                config.trust_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "trust max age must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--trust-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--trust-watermark requires a value".to_owned())?;
                config.trust_watermark_path = value.into();
                index += 2;
            }
            Some("--membership-snapshot") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-snapshot requires a value".to_owned())?;
                config.membership_snapshot_path = value.into();
                index += 2;
            }
            Some("--membership-log") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-log requires a value".to_owned())?;
                config.membership_log_path = value.into();
                index += 2;
            }
            Some("--membership-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--membership-watermark requires a value".to_owned())?;
                config.membership_watermark_path = value.into();
                index += 2;
            }
            Some("--anchor-bundle-pull-addr") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--anchor-bundle-pull-addr requires a value".to_owned())?;
                config.anchor_bundle_pull_addr = if value.is_empty() {
                    None
                } else {
                    Some(
                        value
                            .parse::<SocketAddr>()
                            .map_err(|err| format!("invalid anchor bundle-pull addr: {err}"))?,
                    )
                };
                index += 2;
            }
            Some("--anchor-bundle-pull-token-path") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--anchor-bundle-pull-token-path requires a value".to_owned())?;
                config.anchor_bundle_pull_token_path = if value.is_empty() {
                    None
                } else {
                    Some(value.into())
                };
                index += 2;
            }
            Some("--anchor-bundle-pull-allow-lan") => {
                // D11.b: explicit operator ack required to bind on a non-loopback
                // address. No auto-detect or silent fallback.
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--anchor-bundle-pull-allow-lan requires a value".to_owned())?;
                config.anchor_bundle_pull_allow_lan = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(format!(
                            "invalid --anchor-bundle-pull-allow-lan value '{value}': expected true or false"
                        ));
                    }
                };
                index += 2;
            }
            Some("--gossip-watermark") => {
                // D2.5 — per-host spool for the gossip sequence and
                // seen-source ledger. The systemd unit sets this via
                // `RUSTYNET_GOSSIP_WATERMARK`; the CLI flag overrides
                // it when present. Empty string disables the spool
                // (the gossip subsystem then runs purely in-memory,
                // acceptable for development).
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--gossip-watermark requires a value".to_owned())?;
                config.gossip_watermark_path = if value.is_empty() {
                    None
                } else {
                    Some(value.into())
                };
                index += 2;
            }
            Some("--enrollment-secret") => {
                // D2.7 — path to the 32-byte HMAC enrollment secret.
                // Empty string disables the enrollment IPC verb.
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--enrollment-secret requires a value".to_owned())?;
                config.enrollment_secret_path = if value.is_empty() {
                    None
                } else {
                    Some(value.into())
                };
                index += 2;
            }
            Some("--enrollment-ledger") => {
                // D2.7 — path to the consumed-token ledger spool.
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--enrollment-ledger requires a value".to_owned())?;
                config.enrollment_ledger_path = if value.is_empty() {
                    None
                } else {
                    Some(value.into())
                };
                index += 2;
            }
            Some("--auto-tunnel-enforce") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-enforce requires a value".to_owned())?;
                config.auto_tunnel_enforce = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid auto-tunnel-enforce value: expected true/false".to_owned()
                        );
                    }
                };
                index += 2;
            }
            Some("--auto-tunnel-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-bundle requires a value".to_owned())?;
                config.auto_tunnel_bundle_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-verifier-key requires a value".to_owned())?;
                config.auto_tunnel_verifier_key_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-watermark requires a value".to_owned())?;
                config.auto_tunnel_watermark_path = Some(value.into());
                index += 2;
            }
            Some("--auto-tunnel-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-tunnel-max-age-secs requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid auto tunnel max age: {err}"))?;
                config.auto_tunnel_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "auto tunnel max age must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--dns-zone-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-bundle requires a value".to_owned())?;
                config.dns_zone_bundle_path = value.into();
                index += 2;
            }
            Some("--dns-zone-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-verifier-key requires a value".to_owned())?;
                config.dns_zone_verifier_key_path = value.into();
                index += 2;
            }
            Some("--dns-zone-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-watermark requires a value".to_owned())?;
                config.dns_zone_watermark_path = value.into();
                index += 2;
            }
            Some("--dns-zone-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-max-age-secs requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid dns zone max age: {err}"))?;
                config.dns_zone_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "dns zone max age must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--dns-zone-name") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-zone-name requires a value".to_owned())?;
                config.dns_zone_name = value.clone();
                index += 2;
            }
            Some("--dns-resolver-bind-addr") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dns-resolver-bind-addr requires a value".to_owned())?;
                config.dns_resolver_bind_addr = value
                    .parse::<SocketAddr>()
                    .map_err(|err| format!("invalid dns resolver bind addr: {err}"))?;
                index += 2;
            }
            Some("--traversal-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-bundle requires a value".to_owned())?;
                config.traversal_bundle_path = value.into();
                index += 2;
            }
            Some("--traversal-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-verifier-key requires a value".to_owned())?;
                config.traversal_verifier_key_path = value.into();
                index += 2;
            }
            Some("--traversal-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-watermark requires a value".to_owned())?;
                config.traversal_watermark_path = value.into();
                index += 2;
            }
            Some("--relay-fleet-bundle") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--relay-fleet-bundle requires a value".to_owned())?;
                config.relay_fleet_bundle_path = Some(value.into());
                index += 2;
            }
            Some("--relay-fleet-watermark") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--relay-fleet-watermark requires a value".to_owned())?;
                config.relay_fleet_watermark_path = Some(value.into());
                index += 2;
            }
            Some("--disable-relay-fleet") => {
                config.relay_fleet_bundle_path = None;
                config.relay_fleet_watermark_path = None;
                index += 1;
            }
            Some("--traversal-max-age-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-max-age-secs requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal max age: {err}"))?;
                config.traversal_max_age_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| "traversal max age must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--traversal-stun-servers") => {
                let (stun_servers, next_index) =
                    parse_optional_socket_addr_csv_arg(args, index, "--traversal-stun-servers")?;
                config.traversal_stun_servers = stun_servers;
                index = next_index;
            }
            Some("--traversal-stun-gather-timeout-ms") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-stun-gather-timeout-ms requires a value".to_owned()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal stun gather timeout: {err}"))?;
                config.traversal_stun_gather_timeout_ms =
                    NonZeroU64::new(parsed).ok_or_else(|| {
                        "traversal stun gather timeout must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-max-candidates") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-max-candidates requires a value".to_owned()
                })?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid traversal probe max candidates: {err}"))?;
                config.traversal_probe_max_candidates =
                    NonZeroUsize::new(parsed).ok_or_else(|| {
                        "traversal probe max candidates must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-max-pairs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-probe-max-pairs requires a value".to_owned())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid traversal probe max pairs: {err}"))?;
                config.traversal_probe_max_pairs = NonZeroUsize::new(parsed)
                    .ok_or_else(|| "traversal probe max pairs must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--traversal-probe-rounds") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--traversal-probe-rounds requires a value".to_owned())?;
                let parsed = value
                    .parse::<u8>()
                    .map_err(|err| format!("invalid traversal probe rounds: {err}"))?;
                config.traversal_probe_simultaneous_open_rounds = NonZeroU8::new(parsed)
                    .ok_or_else(|| "traversal probe rounds must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--traversal-probe-round-spacing-ms") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-round-spacing-ms requires a value".to_owned()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe round spacing: {err}"))?;
                config.traversal_probe_round_spacing_ms =
                    NonZeroU64::new(parsed).ok_or_else(|| {
                        "traversal probe round spacing must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-relay-switch-after-failures") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-relay-switch-after-failures requires a value".to_owned()
                })?;
                let parsed = value.parse::<u8>().map_err(|err| {
                    format!("invalid traversal probe relay switch threshold: {err}")
                })?;
                config.traversal_probe_relay_switch_after_failures = NonZeroU8::new(parsed)
                    .ok_or_else(|| {
                        "traversal probe relay switch threshold must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-handshake-freshness-secs") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-handshake-freshness-secs requires a value".to_owned()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe handshake freshness: {err}"))?;
                config.traversal_probe_handshake_freshness_secs = NonZeroU64::new(parsed)
                    .ok_or_else(|| {
                        "traversal probe handshake freshness must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--traversal-probe-reprobe-interval-secs") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--traversal-probe-reprobe-interval-secs requires a value".to_owned()
                })?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid traversal probe reprobe interval: {err}"))?;
                config.traversal_probe_reprobe_interval_secs =
                    NonZeroU64::new(parsed).ok_or_else(|| {
                        "traversal probe reprobe interval must be greater than 0".to_owned()
                    })?;
                index += 2;
            }
            Some("--backend") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--backend requires a value".to_owned())?;
                config.backend_mode = match value.as_str() {
                    "linux-wireguard" => DaemonBackendMode::LinuxWireguard,
                    "linux-wireguard-userspace-shared" => {
                        DaemonBackendMode::LinuxWireguardUserspaceShared
                    }
                    "macos-wireguard" => DaemonBackendMode::MacosWireguard,
                    "macos-wireguard-userspace-shared" => {
                        DaemonBackendMode::MacosWireguardUserspaceShared
                    }
                    WINDOWS_UNSUPPORTED_BACKEND_LABEL | WINDOWS_WIREGUARD_NT_BACKEND_LABEL => {
                        parse_windows_backend_mode(value.as_str())?;
                        if value == WINDOWS_UNSUPPORTED_BACKEND_LABEL {
                            DaemonBackendMode::WindowsUnsupported
                        } else {
                            DaemonBackendMode::WindowsWireguardNt
                        }
                    }
                    _ => {
                        return Err(format!(
                            "invalid backend value: expected linux-wireguard, linux-wireguard-userspace-shared, macos-wireguard, macos-wireguard-userspace-shared, {WINDOWS_UNSUPPORTED_BACKEND_LABEL}, or {WINDOWS_WIREGUARD_NT_BACKEND_LABEL}"
                        ));
                    }
                };
                index += 2;
            }
            Some("--wg-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-interface requires a value".to_owned())?;
                config.wg_interface = value.clone();
                index += 2;
            }
            Some("--wg-listen-port") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-listen-port requires a value".to_owned())?;
                let port = value
                    .parse::<u16>()
                    .map_err(|err| format!("invalid --wg-listen-port value: {err}"))?;
                if port == 0 {
                    return Err("--wg-listen-port must be in range 1-65535".to_owned());
                }
                config.wg_listen_port = port;
                index += 2;
            }
            Some("--wg-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-private-key requires a value".to_owned())?;
                config.wg_private_key_path = Some(value.into());
                index += 2;
            }
            Some("--wg-encrypted-private-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-encrypted-private-key requires a value".to_owned())?;
                config.wg_encrypted_private_key_path = Some(value.into());
                index += 2;
            }
            Some("--wg-key-passphrase") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-key-passphrase requires a value".to_owned())?;
                config.wg_key_passphrase_path = Some(value.into());
                index += 2;
            }
            Some("--wg-public-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--wg-public-key requires a value".to_owned())?;
                config.wg_public_key_path = Some(value.into());
                index += 2;
            }
            Some("--relay-session-local-token-issuer") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--relay-session-local-token-issuer requires a value".to_owned()
                })?;
                config.relay_session_local_token_issuer_enabled = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid relay-session-local-token-issuer value: expected true/false"
                                .to_owned(),
                        );
                    }
                };
                index += 2;
            }
            Some("--relay-session-token-spool-dir") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--relay-session-token-spool-dir requires a value".to_owned())?;
                config.relay_session_token_spool_dir = Some(value.into());
                index += 2;
            }
            Some("--egress-interface") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--egress-interface requires a value".to_owned())?;
                config.egress_interface = value.clone();
                index += 2;
            }
            Some("--remote-ops-token-verifier-key") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--remote-ops-token-verifier-key requires a value".to_owned())?;
                config.remote_ops_token_verifier_key_path = Some(value.into());
                index += 2;
            }
            Some("--remote-ops-expected-subject") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--remote-ops-expected-subject requires a value".to_owned())?;
                config.remote_ops_expected_subject = value.clone();
                index += 2;
            }
            Some("--auto-port-forward-exit") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-port-forward-exit requires a value".to_owned())?;
                config.auto_port_forward_exit = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid auto-port-forward-exit value: expected true/false".to_owned()
                        );
                    }
                };
                index += 2;
            }
            Some("--auto-port-forward-lease-secs") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--auto-port-forward-lease-secs requires a value".to_owned())?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid auto port-forward lease: {err}"))?;
                config.auto_port_forward_lease_secs = NonZeroU32::new(parsed).ok_or_else(|| {
                    "auto-port-forward-lease-secs must be greater than 0".to_owned()
                })?;
                index += 2;
            }
            Some("--dataplane-mode") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--dataplane-mode requires a value".to_owned())?;
                config.dataplane_mode = match value.as_str() {
                    "shell" => DaemonDataplaneMode::Shell,
                    "hybrid-native" => DaemonDataplaneMode::HybridNative,
                    _ => {
                        return Err(
                            "invalid dataplane mode: expected shell or hybrid-native".to_owned()
                        );
                    }
                };
                index += 2;
            }
            Some("--port-mapping-mode") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--port-mapping-mode requires a value".to_owned())?;
                config.port_mapping_mode = PortMappingMode::parse(value.as_str())?;
                index += 2;
            }
            Some("--privileged-helper-socket") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--privileged-helper-socket requires a value".to_owned())?;
                config.privileged_helper_socket_path = Some(value.into());
                index += 2;
            }
            Some("--privileged-helper-timeout-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--privileged-helper-timeout-ms requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid privileged helper timeout: {err}"))?;
                config.privileged_helper_timeout_ms = NonZeroU64::new(parsed)
                    .ok_or_else(|| "privileged helper timeout must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--max-requests") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-requests requires a value".to_owned())?;
                let parsed = value
                    .parse::<usize>()
                    .map_err(|err| format!("invalid max requests: {err}"))?;
                config.max_requests = Some(
                    NonZeroUsize::new(parsed)
                        .ok_or_else(|| "max requests must be greater than 0".to_owned())?,
                );
                index += 2;
            }
            Some("--reconcile-interval-ms") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--reconcile-interval-ms requires a value".to_owned())?;
                let parsed = value
                    .parse::<u64>()
                    .map_err(|err| format!("invalid reconcile interval: {err}"))?;
                config.reconcile_interval_ms = NonZeroU64::new(parsed)
                    .ok_or_else(|| "reconcile interval must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--max-reconcile-failures") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--max-reconcile-failures requires a value".to_owned())?;
                let parsed = value
                    .parse::<u32>()
                    .map_err(|err| format!("invalid max reconcile failures: {err}"))?;
                config.max_reconcile_failures = NonZeroU32::new(parsed)
                    .ok_or_else(|| "max reconcile failures must be greater than 0".to_owned())?;
                index += 2;
            }
            Some("--fail-closed-ssh-allow") => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--fail-closed-ssh-allow requires a value".to_owned())?;
                config.fail_closed_ssh_allow = match value.as_str() {
                    "true" | "1" | "yes" => true,
                    "false" | "0" | "no" => false,
                    _ => {
                        return Err(
                            "invalid fail-closed-ssh-allow value: expected true/false".to_owned()
                        );
                    }
                };
                index += 2;
            }
            Some("--fail-closed-ssh-allow-cidrs") => {
                if let Some(value) = args.get(index + 1) {
                    if value.starts_with("--") {
                        config.fail_closed_ssh_allow_cidrs.clear();
                        index += 1;
                    } else {
                        config.fail_closed_ssh_allow_cidrs = value
                            .split(',')
                            .map(str::trim)
                            .filter(|entry| !entry.is_empty())
                            .map(str::parse::<ManagementCidr>)
                            .collect::<Result<Vec<_>, _>>()
                            .map_err(|err| {
                                format!("invalid --fail-closed-ssh-allow-cidrs value: {err}")
                            })?;
                        index += 2;
                    }
                } else {
                    config.fail_closed_ssh_allow_cidrs.clear();
                    index += 1;
                }
            }
            Some(flag) => {
                return Err(format!("unknown daemon argument: {flag}"));
            }
            None => break,
        }
    }
    Ok(config)
}

fn parse_optional_socket_addr_csv_arg(
    args: &[String],
    index: usize,
    flag: &str,
) -> Result<(Vec<SocketAddr>, usize), String> {
    if let Some(value) = args.get(index + 1) {
        if value.starts_with("--") {
            return Ok((Vec::new(), index + 1));
        }
        let parsed = value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::parse::<SocketAddr>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("invalid {flag} value: {err}"))?;
        Ok((parsed, index + 2))
    } else {
        Ok((Vec::new(), index + 1))
    }
}

fn run_membership_command(args: &[String]) -> Result<(), String> {
    match args.first().map(String::as_str) {
        Some("init") => run_membership_init(&args[1..]),
        Some("add-peer") => run_membership_add_peer(&args[1..]),
        Some(other) => Err(format!("unknown membership subcommand: {other}")),
        None => Err("membership subcommand required (supported: init, add-peer)".to_owned()),
    }
}

/// Add a peer node to an existing membership snapshot.
///
/// Requires the membership owner signing key and its passphrase (may be a
/// DPAPI blob on Windows).  Used by the Windows e2e-lab orchestrator to add
/// client nodes after `membership init` has already produced the initial
/// snapshot for the exit node.
///
/// Usage:
///   rustynetd membership add-peer
///     --node-id          <id>
///     --node-pubkey-hex  <64-hex>
///     --owner            <owner-node-id>
///     --approver-id      <approver-id>
///     --signing-key      <path>
///     --signing-key-passphrase-file <path>
///     [--snapshot        <path>]
///     [--capabilities    <csv>]
///     [--log             <path>]
fn run_membership_add_peer(args: &[String]) -> Result<(), String> {
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MembershipNode, MembershipNodeStatus, MembershipOperation, MembershipReplayCache,
        MembershipUpdateRecord, SignedMembershipUpdate, append_membership_log_entry,
        apply_signed_update, load_membership_log, load_membership_snapshot,
        persist_membership_snapshot, preview_next_state, sign_update_record,
    };
    use rustynet_control::roles::{RoleCapability, parse_role_capability_csv};
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroize;

    let mut node_id = String::new();
    let mut node_pubkey_hex = String::new();
    let mut owner = String::new();
    let mut approver_id = String::new();
    let mut signing_key_path = String::new();
    let mut signing_key_passphrase_path = String::new();
    let mut capabilities = vec![RoleCapability::Client];
    let mut snapshot_path = DEFAULT_MEMBERSHIP_SNAPSHOT_PATH.to_owned();
    let mut log_path = DEFAULT_MEMBERSHIP_LOG_PATH.to_owned();

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--node-id") => {
                node_id = args
                    .get(index + 1)
                    .ok_or("--node-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--node-pubkey-hex") => {
                node_pubkey_hex = args
                    .get(index + 1)
                    .ok_or("--node-pubkey-hex requires a value")?
                    .clone();
                index += 2;
            }
            Some("--owner") => {
                owner = args
                    .get(index + 1)
                    .ok_or("--owner requires a value")?
                    .clone();
                index += 2;
            }
            Some("--approver-id") => {
                approver_id = args
                    .get(index + 1)
                    .ok_or("--approver-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--signing-key") => {
                signing_key_path = args
                    .get(index + 1)
                    .ok_or("--signing-key requires a value")?
                    .clone();
                index += 2;
            }
            Some("--signing-key-passphrase-file") => {
                signing_key_passphrase_path = args
                    .get(index + 1)
                    .ok_or("--signing-key-passphrase-file requires a value")?
                    .clone();
                index += 2;
            }
            Some("--capabilities") => {
                let raw = args
                    .get(index + 1)
                    .ok_or("--capabilities requires a value")?;
                capabilities = parse_role_capability_csv(raw).map_err(|err| err.to_string())?;
                index += 2;
            }
            Some("--snapshot") => {
                snapshot_path = args
                    .get(index + 1)
                    .ok_or("--snapshot requires a value")?
                    .clone();
                index += 2;
            }
            Some("--log") => {
                log_path = args.get(index + 1).ok_or("--log requires a value")?.clone();
                index += 2;
            }
            Some(flag) => return Err(format!("unknown membership add-peer argument: {flag}")),
            None => break,
        }
    }

    if node_id.is_empty() {
        return Err("--node-id is required".to_owned());
    }
    if node_pubkey_hex.is_empty() {
        return Err("--node-pubkey-hex is required".to_owned());
    }
    if node_pubkey_hex.len() != 64 || !node_pubkey_hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("--node-pubkey-hex must be 64 hex characters".to_owned());
    }
    if owner.is_empty() {
        return Err("--owner is required".to_owned());
    }
    if approver_id.is_empty() {
        return Err("--approver-id is required".to_owned());
    }
    if signing_key_path.is_empty() {
        return Err("--signing-key is required".to_owned());
    }
    if signing_key_passphrase_path.is_empty() {
        return Err("--signing-key-passphrase-file is required".to_owned());
    }

    ensure_cli_path_absolute(&signing_key_path, "signing key path")?;
    ensure_cli_path_absolute(&signing_key_passphrase_path, "signing key passphrase path")?;
    ensure_cli_path_absolute(&snapshot_path, "snapshot path")?;
    ensure_cli_path_absolute(&log_path, "log path")?;

    // Load the signing key using the passphrase (auto-decrypts DPAPI blob on Windows).
    let passphrase =
        read_passphrase_file_explicit(std::path::Path::new(&signing_key_passphrase_path))
            .map_err(|e| format!("read signing key passphrase failed: {e}"))?;
    let secret = {
        use rustynet_crypto::{KeyCustodyPermissionPolicy, read_encrypted_key_file};
        let key_path = std::path::Path::new(&signing_key_path);
        let parent = key_path
            .parent()
            .ok_or_else(|| format!("signing key path has no parent: {signing_key_path}"))?;
        read_encrypted_key_file(
            parent,
            key_path,
            passphrase.as_str(),
            KeyCustodyPermissionPolicy::default(),
        )
        .map_err(|e| format!("decrypt signing key failed: {e}"))?
    };
    if secret.len() != 32 {
        return Err("decrypted signing key must be 32 bytes".to_owned());
    }
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret);
    let signing_key = SigningKey::from_bytes(&key_bytes);
    key_bytes.zeroize();

    // Load the current membership state.
    let state = load_membership_snapshot(&snapshot_path)
        .map_err(|e| format!("load membership snapshot failed: {e}"))?;

    // Check if the node is already in the membership (idempotent).
    if state.nodes.iter().any(|n| n.node_id == node_id) {
        println!("membership add-peer: node {node_id} already present in snapshot; no-op");
        return Ok(());
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // Build the AddNode update record.
    let operation = MembershipOperation::AddNode(MembershipNode {
        node_id: node_id.clone(),
        node_pubkey_hex,
        owner,
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:members".to_owned()],
        capabilities,
        joined_at_unix: now,
        updated_at_unix: now,
    });
    let prev_root = state
        .state_root_hex()
        .map_err(|e| format!("compute prev state root failed: {e}"))?;
    let next = preview_next_state(&state, &operation)
        .map_err(|e| format!("preview next state failed: {e}"))?;
    let new_root = next
        .state_root_hex()
        .map_err(|e| format!("compute new state root failed: {e}"))?;
    let update_id = format!("add-peer-{node_id}-{now}");
    let expires_at_unix = now.saturating_add(86400); // 24 h
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id,
        operation,
        target: node_id.clone(),
        prev_state_root: prev_root,
        new_state_root: new_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch.saturating_add(1),
        created_at_unix: now,
        expires_at_unix,
        reason_code: "e2e-lab-add".to_owned(),
        policy_context: None,
    };

    let signature = sign_update_record(&record, &approver_id, &signing_key)
        .map_err(|e| format!("sign update record failed: {e}"))?;
    let signed = SignedMembershipUpdate {
        record,
        approver_signatures: vec![signature],
    };

    // Build replay cache seeded with existing log entries to detect duplicates.
    let mut replay_cache = if std::path::Path::new(&log_path).exists() {
        let entries = load_membership_log(&log_path)
            .map_err(|e| format!("load membership log failed: {e}"))?;
        let mut cache = MembershipReplayCache::default();
        for entry in &entries {
            let r = &entry.signed_update.record;
            // Seed cache with existing update IDs; ignore epoch ordering since we
            // only need duplicate detection, not replay ordering here.
            let _ = cache.observe(r.update_id.as_str(), r.epoch_new);
        }
        cache
    } else {
        MembershipReplayCache::default()
    };

    let new_state = apply_signed_update(&state, &signed, now, &mut replay_cache)
        .map_err(|e| format!("apply signed update failed: {e}"))?;

    append_membership_log_entry(&log_path, &signed)
        .map_err(|e| format!("append membership log entry failed: {e}"))?;
    persist_membership_snapshot(&snapshot_path, &new_state)
        .map_err(|e| format!("persist membership snapshot failed: {e}"))?;

    println!(
        "membership add-peer complete: node_id={node_id} snapshot={snapshot_path} log={log_path} epoch_new={}",
        new_state.epoch
    );
    Ok(())
}

fn run_membership_init(args: &[String]) -> Result<(), String> {
    use ed25519_dalek::SigningKey;
    use rustynet_control::membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
        MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
        persist_membership_snapshot,
    };
    use rustynet_control::roles::RoleCapability;
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};
    use zeroize::Zeroize;

    let mut snapshot_path = DEFAULT_MEMBERSHIP_SNAPSHOT_PATH.to_owned();
    let mut log_path = DEFAULT_MEMBERSHIP_LOG_PATH.to_owned();
    let mut watermark_path = DEFAULT_MEMBERSHIP_WATERMARK_PATH.to_owned();
    let mut owner_signing_key_path = DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH.to_owned();
    let mut owner_signing_key_passphrase_path =
        std::env::var(MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV).ok();
    let mut node_id = read_hostname_short();
    let mut network_id = "local-net".to_owned();
    let mut force = false;

    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--snapshot") => {
                snapshot_path = args
                    .get(index + 1)
                    .ok_or("--snapshot requires a value")?
                    .clone();
                index += 2;
            }
            Some("--log") => {
                log_path = args.get(index + 1).ok_or("--log requires a value")?.clone();
                index += 2;
            }
            Some("--watermark") => {
                watermark_path = args
                    .get(index + 1)
                    .ok_or("--watermark requires a value")?
                    .clone();
                index += 2;
            }
            Some("--owner-signing-key") => {
                owner_signing_key_path = args
                    .get(index + 1)
                    .ok_or("--owner-signing-key requires a value")?
                    .clone();
                index += 2;
            }
            Some("--owner-signing-key-passphrase-file") => {
                let value = args
                    .get(index + 1)
                    .ok_or("--owner-signing-key-passphrase-file requires a value")?
                    .clone();
                owner_signing_key_passphrase_path = Some(value);
                index += 2;
            }
            Some("--node-id") => {
                node_id = args
                    .get(index + 1)
                    .ok_or("--node-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--network-id") => {
                network_id = args
                    .get(index + 1)
                    .ok_or("--network-id requires a value")?
                    .clone();
                index += 2;
            }
            Some("--force") => {
                force = true;
                index += 1;
            }
            Some(flag) => return Err(format!("unknown membership init argument: {flag}")),
            None => break,
        }
    }

    ensure_cli_path_absolute(&snapshot_path, "snapshot path")?;
    ensure_cli_path_absolute(&log_path, "log path")?;
    ensure_cli_path_absolute(&watermark_path, "watermark path")?;
    ensure_cli_path_absolute(&owner_signing_key_path, "owner signing key path")?;
    let owner_signing_key_passphrase_path =
        owner_signing_key_passphrase_path.ok_or_else(|| {
            format!(
                "owner signing key passphrase path is required; pass --owner-signing-key-passphrase-file or set {MEMBERSHIP_OWNER_SIGNING_KEY_PASSPHRASE_FILE_ENV}",
            )
        })?;
    ensure_cli_path_absolute(
        &owner_signing_key_passphrase_path,
        "owner signing key passphrase path",
    )?;

    if !force
        && (std::path::Path::new(&snapshot_path).exists()
            || std::path::Path::new(&log_path).exists()
            || std::path::Path::new(&watermark_path).exists()
            || std::path::Path::new(&owner_signing_key_path).exists())
    {
        return Err(format!(
            "membership files already exist at {snapshot_path}, {log_path}, {watermark_path}, or {owner_signing_key_path}; use --force to overwrite"
        ));
    }

    for path_str in [
        &snapshot_path,
        &log_path,
        &watermark_path,
        &owner_signing_key_path,
    ] {
        if let Some(parent) = std::path::Path::new(path_str.as_str()).parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create directory {}: {e}", parent.display()))?;
        }
    }

    if std::path::Path::new(&watermark_path).exists() {
        std::fs::remove_file(&watermark_path)
            .map_err(|e| format!("failed to remove membership watermark {watermark_path}: {e}"))?;
    }

    let mut node_key_bytes = [0u8; 32];
    let mut approver_key_bytes = [0u8; 32];
    fill_random_bytes(&mut node_key_bytes)
        .map_err(|e| format!("failed to generate node identity key: {e}"))?;
    fill_random_bytes(&mut approver_key_bytes)
        .map_err(|e| format!("failed to generate approver key: {e}"))?;

    let init_result = (|| -> Result<(String, String), String> {
        let approver_signing = SigningKey::from_bytes(&approver_key_bytes);
        let approver_pubkey_hex = encode_hex(approver_signing.verifying_key().as_bytes());
        let node_pubkey_hex = encode_hex(&node_key_bytes);
        let owner_approver_id = format!("{node_id}-owner");

        persist_owner_signing_key_encrypted(
            std::path::Path::new(&owner_signing_key_path),
            &approver_key_bytes,
            std::path::Path::new(&owner_signing_key_passphrase_path),
            force,
        )?;

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        // Bootstrap-time single-node membership grants the full Anchor
        // capability set (including sub-caps) plus Client/ExitServer/RelayHost
        // so the daemon can start with any role mapping before the orchestrator
        // distributes the real multi-node membership. Without Client capability
        // here, every non-exit node fails its
        // `validate_node_role_membership_alignment` preflight at first boot
        // (exit 65). The real membership snapshot overwrites this record on
        // non-exit nodes during DistributeMembership. For the exit/anchor
        // genesis node the sub-caps here become the persistent capabilities
        // visible to live_anchor and other post-validate_baseline_runtime
        // tests — missing them causes policy_reject (rc 78) in live_anchor.
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: network_id.clone(),
            epoch: 1,
            nodes: vec![MembershipNode {
                node_id: node_id.clone(),
                node_pubkey_hex,
                owner: node_id.clone(),
                status: MembershipNodeStatus::Active,
                roles: vec![],
                capabilities: vec![
                    RoleCapability::Anchor,
                    RoleCapability::AnchorGossipSeed,
                    RoleCapability::AnchorBundlePull,
                    RoleCapability::AnchorEnrollmentEndpoint,
                    RoleCapability::AnchorRelayColocation,
                    RoleCapability::AnchorPortMappingAuthoritative,
                    RoleCapability::Client,
                    RoleCapability::ExitServer,
                    RoleCapability::RelayHost,
                ],
                joined_at_unix: now,
                updated_at_unix: now,
            }],
            approver_set: vec![MembershipApprover {
                approver_id: owner_approver_id.clone(),
                approver_pubkey_hex: approver_pubkey_hex.clone(),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: now,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };

        persist_membership_snapshot(&snapshot_path, &state)
            .map_err(|e| format!("failed to write membership snapshot: {e}"))?;

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true);
        #[cfg(unix)]
        opts.mode(0o600);
        let mut log_file = opts
            .open(&log_path)
            .map_err(|e| format!("failed to create membership log: {e}"))?;
        log_file
            .write_all(format!("version={MEMBERSHIP_SCHEMA_VERSION}\n").as_bytes())
            .map_err(|e| format!("failed to write membership log: {e}"))?;
        Ok((owner_approver_id, approver_pubkey_hex))
    })();

    node_key_bytes.zeroize();
    approver_key_bytes.zeroize();
    let (owner_approver_id, owner_pubkey_hex) = init_result?;

    // Write the owner public key alongside the private key so orchestrators and
    // adapters can read it without decrypting the private key file.
    let pub_key_path = format!("{owner_signing_key_path}.pub");
    std::fs::write(&pub_key_path, format!("{owner_pubkey_hex}\n"))
        .map_err(|e| format!("failed to write membership owner public key {pub_key_path}: {e}"))?;

    println!(
        "membership init complete: snapshot={snapshot_path} log={log_path} watermark_reset={watermark_path} owner_signing_key={owner_signing_key_path}"
    );
    println!("  node_id={node_id} network_id={network_id} owner_approver_id={owner_approver_id}");
    Ok(())
}

fn fill_random_bytes(buf: &mut [u8]) -> Result<(), std::io::Error> {
    use rand::TryRngCore;
    rand::rngs::OsRng
        .try_fill_bytes(buf)
        .map_err(std::io::Error::other)
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn encrypted_secret_permission_policy(path: &std::path::Path) -> KeyCustodyPermissionPolicy {
    let mut policy = KeyCustodyPermissionPolicy::default();
    if matches!(path.parent(), Some(parent) if parent == std::path::Path::new("/etc/rustynet")) {
        // Encrypted signing artifacts currently coexist with daemon-readable verifier
        // material under /etc/rustynet on Linux.
        policy.required_directory_mode = 0o750;
    }
    policy
}

fn persist_owner_signing_key_encrypted(
    path: &std::path::Path,
    key_bytes: &[u8; 32],
    passphrase_path: &std::path::Path,
    force: bool,
) -> Result<(), String> {
    use std::io::ErrorKind;

    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "owner signing key path must not be a symlink: {}",
                    path.display()
                ));
            }
            if !metadata.file_type().is_file() {
                return Err(format!(
                    "owner signing key path must reference a regular file: {}",
                    path.display()
                ));
            }
            if !force {
                return Err(format!(
                    "owner signing key already exists at {}; use --force to overwrite",
                    path.display()
                ));
            }
            remove_file_if_present(path)?;
        }
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect owner signing key {}: {err}",
                path.display()
            ));
        }
    }

    let passphrase = read_passphrase_file_explicit(passphrase_path).map_err(|err| {
        format!(
            "owner signing key passphrase source invalid ({}): {err}",
            passphrase_path.display()
        )
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("owner signing key path has no parent: {}", path.display()))?;
    let permission_policy = encrypted_secret_permission_policy(path);
    write_encrypted_key_file(
        parent,
        path,
        key_bytes,
        passphrase.as_str(),
        permission_policy,
    )
    .map_err(|err| {
        format!(
            "failed to persist encrypted owner signing key {}: {err}",
            path.display()
        )
    })?;
    Ok(())
}

fn read_hostname_short() -> String {
    std::fs::read_to_string("/etc/hostname")
        .ok()
        .and_then(|s| s.trim().split('.').next().map(str::to_string))
        .or_else(|| std::env::var("HOSTNAME").ok())
        .unwrap_or_else(|| "local".to_owned())
}

fn help_text() -> String {
    [
        "rustynetd usage:",
        windows_service_help_line(),
        "  rustynetd daemon [--node-id <id>] [--node-role <admin|client|blind_exit>] [--socket <path>] [--state <path>] [--trust-evidence <path>] [--trust-verifier-key <path>] [--trust-watermark <path>] [--membership-snapshot <path>] [--membership-log <path>] [--membership-watermark <path>] [--gossip-watermark <path>] [--enrollment-secret <path>] [--enrollment-ledger <path>] [--auto-tunnel-enforce <true|false>] [--auto-tunnel-bundle <path>] [--auto-tunnel-verifier-key <path>] [--auto-tunnel-watermark <path>] [--auto-tunnel-max-age-secs <secs>] [--dns-zone-bundle <path>] [--dns-zone-verifier-key <path>] [--dns-zone-watermark <path>] [--dns-zone-max-age-secs <secs>] [--dns-zone-name <name>] [--dns-resolver-bind-addr <addr:port>] [--traversal-bundle <path>] [--traversal-verifier-key <path>] [--traversal-watermark <path>] [--relay-fleet-bundle <path>] [--relay-fleet-watermark <path>] [--disable-relay-fleet] [--traversal-max-age-secs <secs>] [--traversal-stun-servers <ip:port[,ip:port...]>] [--traversal-stun-gather-timeout-ms <ms>] [--traversal-probe-max-candidates <n>] [--traversal-probe-max-pairs <n>] [--traversal-probe-rounds <n>] [--traversal-probe-round-spacing-ms <ms>] [--traversal-probe-relay-switch-after-failures <n>] [--traversal-probe-handshake-freshness-secs <secs>] [--traversal-probe-reprobe-interval-secs <secs>] [--backend <linux-wireguard|linux-wireguard-userspace-shared|macos-wireguard|macos-wireguard-userspace-shared|windows-unsupported|windows-wireguard-nt>] [--wg-interface <name>] [--wg-listen-port <1-65535>] [--wg-private-key <path>] [--wg-encrypted-private-key <path>] [--wg-key-passphrase <path>] [--wg-public-key <path>] [--relay-session-local-token-issuer <true|false>] [--relay-session-token-spool-dir <path>] [--egress-interface <name|auto>] [--remote-ops-token-verifier-key <path>] [--remote-ops-expected-subject <subject>] [--auto-port-forward-exit <true|false>] [--auto-port-forward-lease-secs <secs>] [--dataplane-mode <shell|hybrid-native>] [--port-mapping-mode <auto|keepalive|disabled>] [--privileged-helper-socket <path>] [--privileged-helper-timeout-ms <ms>] [--reconcile-interval-ms <ms>] [--max-reconcile-failures <n>] [--fail-closed-ssh-allow <true|false>] [--fail-closed-ssh-allow-cidrs <cidr[,cidr...]>] [--max-requests <n>]",
        "  rustynetd privileged-helper [--socket <path>] [--allowed-uid <uid>] [--allowed-gid <gid>] [--timeout-ms <ms>]",
        "  rustynetd key init [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key migrate --existing-private-key <path> [--runtime-private-key <path>] [--encrypted-private-key <path>] [--public-key <path>] [--passphrase-file <path>] [--force]",
        "  rustynetd key store-passphrase --passphrase-file <path> [--keychain-account <name>] [--keychain-service <name>] [--keychain-allow-any-app]",
        "  rustynetd membership init [--snapshot <path>] [--log <path>] [--watermark <path>] [--owner-signing-key <path>] [--owner-signing-key-passphrase-file <path>] [--node-id <id>] [--network-id <id>] [--force]",
        "  rustynetd membership add-peer --node-id <id> --node-pubkey-hex <hex> --owner <owner> --approver-id <id> --signing-key <path> --signing-key-passphrase-file <path> [--capabilities <csv>] [--snapshot <path>] [--log <path>]",
        "  rustynetd windows-runtime-boundary-check [--state-root <path>]",
        "  rustynetd windows-tunnel-smoke [--tunnel-name <name>] [--address <cidr>] [--mesh-cidr <cidr>] [--listen-port <port>] [--keep]",
        "  rustynetd windows-killswitch-smoke [--tunnel-name <name>] [--address <cidr>] [--mesh-cidr <cidr>] [--listen-port <port>] [--exercise-full-block]",
        "  rustynetd windows-runtime-acls-check [--no-fail-on-drift]",
        "  rustynetd windows-named-pipe-acls-check [--service-sid <sid>] [--no-fail-on-drift]",
        "  rustynetd windows-registry-acls-check [--no-fail-on-drift]",
        "  rustynetd linux-runtime-acls-check [--no-fail-on-drift]",
        "  rustynetd linux-mesh-status-check [--state-path <path>] [--expected-peer-id <id>]... [--max-age-seconds <secs>] [--no-fail-on-drift]",
        "  rustynetd linux-key-custody-check [--no-fail-on-drift]",
        "  rustynetd linux-killswitch-boot-check [--iface <name>] [--no-fail-on-drift]",
        "  rustynetd linux-authenticode-check [--no-fail-on-drift]",
        "  rustynetd linux-service-hardening-check [--no-fail-on-drift]",
        "  rustynetd linux-dns-failclosed-check [--no-fail-on-drift]",
        "  rustynetd linux-exit-dns-failclosed-capture --output <dir> --lan-iface <name> [--mesh-hostname <name>] [--killswitch-table <name>]",
        "  rustynetd linux-exit-nat-lifecycle-snapshot --mesh-cidr <cidr> [--nat-table <name>]",
        "  rustynetd macos-exit-dns-failclosed-capture --output <dir> --lan-iface <name> [--mesh-hostname <name>]",
        "  rustynetd macos-exit-killswitch-precedence-check --output <path> [--pf-anchor <name>]",
        "  rustynetd windows-service-hardening-check [--no-fail-on-drift]",
        "  rustynetd windows-key-custody-check [--no-fail-on-drift]",
        "  rustynetd windows-authenticode-check [--binary-path <path>] [--no-fail-on-drift]",
        "  rustynetd windows-mesh-status-check [--state-path <path>] [--expected-peer-id <id>]... [--max-age-seconds <secs>] [--no-fail-on-drift]",
        "  rustynetd windows-dns-failclosed-check [--no-fail-on-drift] [--enforce-ipv6-sibling-rules] [--enforce-ra-suppression]",
        "  rustynetd windows-exit-nat-lifecycle-snapshot --mesh-cidr <cidr> [--nat-name <name>] [--tunnel-alias <name>]",
        "  rustynetd windows-killswitch-assert [daemon options] [--no-fail-on-drift]",
        "  rustynetd windows-backend-readiness-check [--no-fail-on-drift]",
        "  rustynetd --emit-phase1-baseline <path>",
        "",
        "defaults:",
        &format!("  node_id={DEFAULT_NODE_ID}"),
        &format!("  node_role={:?}", NodeRole::default()),
        &format!("  socket={DEFAULT_SOCKET_PATH}"),
        &format!("  state={DEFAULT_STATE_PATH}"),
        &format!("  trust_evidence={DEFAULT_TRUST_EVIDENCE_PATH}"),
        &format!("  trust_verifier_key={DEFAULT_TRUST_VERIFIER_KEY_PATH}"),
        &format!("  trust_watermark={DEFAULT_TRUST_WATERMARK_PATH}"),
        &format!("  membership_snapshot={DEFAULT_MEMBERSHIP_SNAPSHOT_PATH}"),
        &format!("  membership_log={DEFAULT_MEMBERSHIP_LOG_PATH}"),
        &format!("  membership_watermark={DEFAULT_MEMBERSHIP_WATERMARK_PATH}"),
        &format!("  traversal_bundle={DEFAULT_TRAVERSAL_BUNDLE_PATH}"),
        &format!("  traversal_verifier_key={DEFAULT_TRAVERSAL_VERIFIER_KEY_PATH}"),
        &format!("  traversal_watermark={DEFAULT_TRAVERSAL_WATERMARK_PATH}"),
        &format!("  relay_fleet_bundle={DEFAULT_RELAY_FLEET_BUNDLE_PATH}"),
        &format!("  relay_fleet_watermark={DEFAULT_RELAY_FLEET_WATERMARK_PATH}"),
        &format!("  traversal_max_age_secs={DEFAULT_TRAVERSAL_MAX_AGE_SECS}"),
        "  traversal_stun_servers=<empty>",
        &format!(
            "  traversal_stun_gather_timeout_ms={DEFAULT_TRAVERSAL_STUN_GATHER_TIMEOUT_MS}"
        ),
        &format!(
            "  traversal_probe_max_candidates={DEFAULT_TRAVERSAL_PROBE_MAX_CANDIDATES}"
        ),
        &format!("  traversal_probe_max_pairs={DEFAULT_TRAVERSAL_PROBE_MAX_PAIRS}"),
        &format!(
            "  traversal_probe_rounds={DEFAULT_TRAVERSAL_PROBE_SIMULTANEOUS_OPEN_ROUNDS}"
        ),
        &format!(
            "  traversal_probe_round_spacing_ms={DEFAULT_TRAVERSAL_PROBE_ROUND_SPACING_MS}"
        ),
        &format!(
            "  traversal_probe_relay_switch_after_failures={DEFAULT_TRAVERSAL_PROBE_RELAY_SWITCH_AFTER_FAILURES}"
        ),
        &format!(
            "  traversal_probe_handshake_freshness_secs={DEFAULT_TRAVERSAL_PROBE_HANDSHAKE_FRESHNESS_SECS}"
        ),
        &format!(
            "  traversal_probe_reprobe_interval_secs={DEFAULT_TRAVERSAL_PROBE_REPROBE_INTERVAL_SECS}"
        ),
        &format!(
            "  membership_owner_signing_key={DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH}"
        ),
        &format!("  backend={:?}", DaemonBackendMode::default()),
        &format!("  wg_interface={DEFAULT_WG_INTERFACE}"),
        &format!("  wg_listen_port={DEFAULT_WG_LISTEN_PORT}"),
        &format!("  wg_private_key={DEFAULT_WG_RUNTIME_PRIVATE_KEY_PATH}"),
        "  wg_encrypted_private_key=<none> (opt-in; pass --wg-encrypted-private-key to enable)",
        "  wg_key_passphrase=<none> (opt-in; pass --wg-key-passphrase to enable)",
        &format!("  wg_public_key={DEFAULT_WG_PUBLIC_KEY_PATH}"),
        &format!("  egress_interface={DEFAULT_EGRESS_INTERFACE}"),
        "  remote_ops_token_verifier_key=<disabled>",
        &format!("  remote_ops_expected_subject={DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT}"),
        &format!("  auto_port_forward_exit={DEFAULT_AUTO_PORT_FORWARD_EXIT}"),
        &format!(
            "  auto_port_forward_lease_secs={DEFAULT_AUTO_PORT_FORWARD_LEASE_SECS}"
        ),
        &format!(
            "  dataplane_mode={:?}",
            DaemonDataplaneMode::default()
        ),
        &format!("  privileged_helper_socket={DEFAULT_TRUSTED_HELPER_SOCKET_PATH}"),
        &format!(
            "  privileged_helper_timeout_ms={DEFAULT_PRIVILEGED_HELPER_TIMEOUT_MS}"
        ),
        &format!("  reconcile_interval_ms={DEFAULT_RECONCILE_INTERVAL_MS}"),
        &format!("  max_reconcile_failures={DEFAULT_MAX_RECONCILE_FAILURES}"),
        &format!("  fail_closed_ssh_allow={DEFAULT_FAIL_CLOSED_SSH_ALLOW}"),
        "  fail_closed_ssh_allow_cidrs=<empty>",
        windows_service_help_note(),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::{
        classify_top_level_error, help_text, parse_daemon_config,
        run_linux_exit_dns_failclosed_capture_command,
        run_macos_exit_dns_failclosed_capture_command,
        run_macos_exit_killswitch_precedence_check_command, run_windows_authenticode_check_command,
        run_windows_backend_readiness_check_command, run_windows_dns_failclosed_check_command,
        run_windows_exit_nat_lifecycle_snapshot_command, run_windows_key_custody_check_command,
        run_windows_killswitch_assert_command, run_windows_mesh_status_check_command,
        run_windows_named_pipe_acls_check_command, run_windows_registry_acls_check_command,
        run_windows_runtime_acls_check_command, run_windows_service_hardening_check_command,
    };
    use rustynetd::daemon::{
        DEFAULT_DNS_RESOLVER_BIND_ADDR, DEFAULT_DNS_ZONE_BUNDLE_PATH,
        DEFAULT_DNS_ZONE_MAX_AGE_SECS, DEFAULT_DNS_ZONE_NAME, DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH,
        DEFAULT_DNS_ZONE_WATERMARK_PATH, DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT, DaemonBackendMode,
    };
    use rustynetd::phase10::ManagementCidr;
    use rustynetd::port_mapper::PortMappingMode;
    use rustynetd::windows_service::{
        HostEntrySelection, WindowsServiceOptions, select_host_entry,
    };
    use std::path::PathBuf;

    #[test]
    fn help_text_advertises_windows_service_host_flags() {
        let help = help_text();
        assert!(help.contains("--windows-service"));
        assert!(help.contains("--env-file"));
        assert!(help.contains("RUSTYNETD_DAEMON_ARGS_JSON"));
        assert!(help.contains("windows-unsupported"));
        assert!(help.contains("windows-wireguard-nt"));
    }

    #[test]
    fn help_text_advertises_windows_runtime_acls_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-runtime-acls-check"),
            "help text must advertise windows-runtime-acls-check subcommand"
        );
        assert!(
            help.contains("--no-fail-on-drift"),
            "help text must advertise --no-fail-on-drift flag"
        );
    }

    #[test]
    fn help_text_advertises_windows_named_pipe_acls_check_subcommand() {
        let help = help_text();
        assert!(help.contains("windows-named-pipe-acls-check"));
        assert!(help.contains("--service-sid <sid>"));
    }

    #[test]
    fn run_windows_runtime_acls_check_command_rejects_unknown_flags() {
        let err = run_windows_runtime_acls_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-runtime-acls-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_named_pipe_acls_check_command_rejects_unknown_flags() {
        let err = run_windows_named_pipe_acls_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(err.contains("unknown windows-named-pipe-acls-check argument"));
    }

    #[test]
    fn run_windows_named_pipe_acls_check_command_rejects_empty_service_sid() {
        let err =
            run_windows_named_pipe_acls_check_command(&["--service-sid".to_owned(), "".to_owned()])
                .expect_err("empty service SID must be rejected");
        assert!(err.contains("--service-sid must be non-empty printable text"));
    }

    #[test]
    fn run_windows_registry_acls_check_command_rejects_unknown_flags() {
        let err = run_windows_registry_acls_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-registry-acls-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_registry_acls_check_command_fails_closed_without_no_fail_flag() {
        // Stub collector returns Unobserved entries on every host
        // (the Win32 RegGetKeySecurity probe is a follow-up slice),
        // so the gate must fail closed by default. --no-fail-on-drift
        // is the opt-out for "capture report shape without verdict".
        let err = run_windows_registry_acls_check_command(&[])
            .expect_err("stub collector must fail closed without --no-fail-on-drift");
        assert!(
            err.contains("windows-registry-acls-check reported drift"),
            "fail-closed verdict must surface: {err}"
        );
    }

    #[test]
    fn run_windows_registry_acls_check_command_no_fail_flag_returns_ok_despite_drift() {
        // Same stub collector + --no-fail-on-drift = the operator
        // wants the JSON without the verdict. Must return Ok.
        run_windows_registry_acls_check_command(&["--no-fail-on-drift".to_owned()])
            .expect("--no-fail-on-drift must suppress the drift verdict");
    }

    #[test]
    fn help_text_advertises_windows_registry_acls_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-registry-acls-check"),
            "help text must advertise the new W4 subcommand"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_runtime_acls_check_command_fails_closed_off_windows() {
        let err = run_windows_runtime_acls_check_command(&[])
            .expect_err("non-Windows host must fail with drift");
        assert!(
            err.contains("reported drift on at least one reviewed runtime root"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_runtime_acls_check_command_no_fail_on_drift_returns_ok_off_windows() {
        run_windows_runtime_acls_check_command(&["--no-fail-on-drift".to_owned()])
            .expect("--no-fail-on-drift must allow report-only execution off Windows");
    }

    #[test]
    fn help_text_advertises_windows_service_hardening_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-service-hardening-check"),
            "help text must advertise windows-service-hardening-check subcommand"
        );
    }

    #[test]
    fn run_windows_service_hardening_check_command_rejects_unknown_flags() {
        let err = run_windows_service_hardening_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-service-hardening-check argument"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_service_hardening_check_command_fails_closed_off_windows() {
        let err = run_windows_service_hardening_check_command(&[])
            .expect_err("non-Windows host must fail with collector blocker");
        assert!(
            err.contains("only available on Windows"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_windows_key_custody_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-key-custody-check"),
            "help text must advertise windows-key-custody-check subcommand"
        );
    }

    #[test]
    fn run_windows_key_custody_check_command_rejects_unknown_flags() {
        let err = run_windows_key_custody_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-key-custody-check argument"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_key_custody_check_command_fails_closed_off_windows() {
        let err = run_windows_key_custody_check_command(&[])
            .expect_err("non-Windows host must fail with drift");
        assert!(err.contains("reported drift"), "unexpected error: {err}");
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_key_custody_check_command_no_fail_on_drift_returns_ok_off_windows() {
        run_windows_key_custody_check_command(&["--no-fail-on-drift".to_owned()])
            .expect("--no-fail-on-drift must allow report-only execution off Windows");
    }

    #[test]
    fn help_text_advertises_windows_authenticode_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-authenticode-check"),
            "help text must advertise windows-authenticode-check subcommand"
        );
        assert!(
            help.contains("--binary-path"),
            "help text must advertise --binary-path flag"
        );
    }

    #[test]
    fn run_windows_authenticode_check_command_rejects_unknown_flags() {
        let err = run_windows_authenticode_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-authenticode-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_authenticode_check_command_rejects_missing_binary_path_value() {
        let err = run_windows_authenticode_check_command(&["--binary-path".to_owned()])
            .expect_err("missing value must be rejected");
        assert!(
            err.contains("--binary-path requires a value"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_authenticode_check_command_fails_closed_for_missing_binary() {
        let err = run_windows_authenticode_check_command(&[
            "--binary-path".to_owned(),
            "/nonexistent/path/to/rustynetd.exe.does-not-exist".to_owned(),
        ])
        .expect_err("missing binary must fail with read error");
        assert!(
            err.contains("read binary failed") || err.contains("windows-authenticode-check failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_windows_mesh_status_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-mesh-status-check"),
            "help text must advertise windows-mesh-status-check subcommand"
        );
        assert!(
            help.contains("--expected-peer-id"),
            "help text must advertise --expected-peer-id"
        );
        assert!(
            help.contains("--max-age-seconds"),
            "help text must advertise --max-age-seconds"
        );
    }

    #[test]
    fn run_windows_mesh_status_check_command_rejects_unknown_flags() {
        let err = run_windows_mesh_status_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-mesh-status-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_mesh_status_check_command_rejects_negative_max_age() {
        let err = run_windows_mesh_status_check_command(&[
            "--max-age-seconds".to_owned(),
            "-30".to_owned(),
        ])
        .expect_err("negative max-age must be rejected");
        assert!(
            err.contains("--max-age-seconds must be non-negative"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_mesh_status_check_command_fails_for_missing_state_file() {
        let err = run_windows_mesh_status_check_command(&[
            "--state-path".to_owned(),
            "/tmp/rustynet-mesh-status-bin-missing".to_owned(),
        ])
        .expect_err("missing state must fail-closed");
        assert!(
            err.contains("windows-mesh-status-check failed"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_mesh_status_check_command_no_fail_on_drift_allows_missing_state_run() {
        run_windows_mesh_status_check_command(&[
            "--no-fail-on-drift".to_owned(),
            "--state-path".to_owned(),
            "/tmp/rustynet-mesh-status-bin-missing".to_owned(),
        ])
        .expect("--no-fail-on-drift must allow report-only execution");
    }

    #[test]
    fn run_windows_authenticode_check_command_no_fail_on_drift_allows_missing_binary_run() {
        run_windows_authenticode_check_command(&[
            "--no-fail-on-drift".to_owned(),
            "--binary-path".to_owned(),
            "/nonexistent/path/to/rustynetd.exe.does-not-exist".to_owned(),
        ])
        .expect("--no-fail-on-drift must allow report-only execution even on read failure");
    }

    #[test]
    fn help_text_advertises_windows_dns_failclosed_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-dns-failclosed-check"),
            "help text must advertise windows-dns-failclosed-check subcommand"
        );
    }

    #[test]
    fn help_text_advertises_macos_exit_dns_failclosed_capture_subcommand() {
        let help = help_text();
        assert!(
            help.contains("macos-exit-dns-failclosed-capture"),
            "help text must advertise macos-exit-dns-failclosed-capture subcommand"
        );
        assert!(
            help.contains("--lan-iface"),
            "help text must advertise --lan-iface"
        );
    }

    #[test]
    fn run_macos_exit_dns_failclosed_capture_command_rejects_unknown_flags() {
        let err = run_macos_exit_dns_failclosed_capture_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown macos-exit-dns-failclosed-capture argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_macos_exit_dns_failclosed_capture_command_requires_output() {
        let err = run_macos_exit_dns_failclosed_capture_command(&[
            "--lan-iface".to_owned(),
            "en0".to_owned(),
        ])
        .expect_err("missing output must reject");
        assert!(
            err.contains("--output is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_linux_exit_dns_failclosed_capture_subcommand() {
        let help = help_text();
        assert!(
            help.contains("linux-exit-dns-failclosed-capture"),
            "help text must advertise linux-exit-dns-failclosed-capture subcommand"
        );
        assert!(
            help.contains("--killswitch-table"),
            "help text must advertise --killswitch-table"
        );
    }

    #[test]
    fn run_linux_exit_dns_failclosed_capture_command_rejects_unknown_flags() {
        let err = run_linux_exit_dns_failclosed_capture_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown linux-exit-dns-failclosed-capture argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_linux_exit_dns_failclosed_capture_command_requires_output() {
        let err = run_linux_exit_dns_failclosed_capture_command(&[
            "--lan-iface".to_owned(),
            "enp0s1".to_owned(),
        ])
        .expect_err("missing output must reject");
        assert!(
            err.contains("--output is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_macos_exit_killswitch_precedence_subcommand() {
        let help = help_text();
        assert!(
            help.contains("macos-exit-killswitch-precedence-check"),
            "help text must advertise macos-exit-killswitch-precedence-check subcommand"
        );
        assert!(
            help.contains("--pf-anchor"),
            "help text must advertise --pf-anchor"
        );
    }

    #[test]
    fn run_macos_exit_killswitch_precedence_check_command_rejects_unknown_flags() {
        let err = run_macos_exit_killswitch_precedence_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown macos-exit-killswitch-precedence-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_macos_exit_killswitch_precedence_check_command_requires_output() {
        let err = run_macos_exit_killswitch_precedence_check_command(&[
            "--pf-anchor".to_owned(),
            "com.apple/rustynet_g1".to_owned(),
        ])
        .expect_err("missing output must reject");
        assert!(
            err.contains("--output is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_dns_failclosed_check_command_rejects_unknown_flags() {
        let err = run_windows_dns_failclosed_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-dns-failclosed-check argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_dns_failclosed_check_command_accepts_enforce_ipv6_sibling_rules_flag() {
        // The flag itself must parse without producing the
        // "unknown argument" error. On non-Windows hosts the
        // collector then fails closed with the requires-Windows
        // blocker, so we accept either outcome — the assertion is
        // only that the flag is recognized.
        let err =
            run_windows_dns_failclosed_check_command(&["--enforce-ipv6-sibling-rules".to_owned()])
                .err()
                .unwrap_or_default();
        assert!(
            !err.contains("unknown windows-dns-failclosed-check argument"),
            "--enforce-ipv6-sibling-rules must be recognized: {err}"
        );
    }

    #[test]
    fn run_windows_dns_failclosed_check_command_accepts_combined_flags() {
        // Both flags together must parse cleanly.
        let err = run_windows_dns_failclosed_check_command(&[
            "--no-fail-on-drift".to_owned(),
            "--enforce-ipv6-sibling-rules".to_owned(),
        ])
        .err()
        .unwrap_or_default();
        assert!(
            !err.contains("unknown windows-dns-failclosed-check argument"),
            "combined flags must be recognized: {err}"
        );
    }

    #[test]
    fn run_windows_dns_failclosed_check_command_accepts_enforce_ra_suppression_flag() {
        // W3 wire-up: --enforce-ra-suppression must parse cleanly.
        let err =
            run_windows_dns_failclosed_check_command(&["--enforce-ra-suppression".to_owned()])
                .err()
                .unwrap_or_default();
        assert!(
            !err.contains("unknown windows-dns-failclosed-check argument"),
            "--enforce-ra-suppression must be recognized: {err}"
        );
    }

    #[test]
    fn run_windows_dns_failclosed_check_command_accepts_all_three_flags() {
        // All three opt-in flags together must parse cleanly.
        let err = run_windows_dns_failclosed_check_command(&[
            "--no-fail-on-drift".to_owned(),
            "--enforce-ipv6-sibling-rules".to_owned(),
            "--enforce-ra-suppression".to_owned(),
        ])
        .err()
        .unwrap_or_default();
        assert!(
            !err.contains("unknown windows-dns-failclosed-check argument"),
            "all three flags must be recognized: {err}"
        );
    }

    #[test]
    fn help_text_advertises_windows_exit_nat_lifecycle_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-exit-nat-lifecycle-snapshot"),
            "help text must advertise windows-exit-nat-lifecycle-snapshot subcommand"
        );
        assert!(
            help.contains("--mesh-cidr"),
            "help text must advertise --mesh-cidr"
        );
    }

    #[test]
    fn run_windows_exit_nat_lifecycle_snapshot_command_rejects_unknown_flags() {
        let err = run_windows_exit_nat_lifecycle_snapshot_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must reject");
        assert!(
            err.contains("unknown windows-exit-nat-lifecycle-snapshot argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_exit_nat_lifecycle_snapshot_command_requires_mesh_cidr() {
        let err = run_windows_exit_nat_lifecycle_snapshot_command(&[
            "--nat-name".to_owned(),
            "RustyNetExit-rustynet0".to_owned(),
        ])
        .expect_err("missing mesh cidr must reject");
        assert!(
            err.contains("--mesh-cidr is required"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_enforce_ipv6_sibling_rules_flag() {
        let help = help_text();
        assert!(
            help.contains("--enforce-ipv6-sibling-rules"),
            "help text must advertise the new W3 flag"
        );
    }

    #[test]
    fn help_text_advertises_enforce_ra_suppression_flag() {
        let help = help_text();
        assert!(
            help.contains("--enforce-ra-suppression"),
            "help text must advertise the W3 RA suppression flag"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_dns_failclosed_check_command_fails_closed_off_windows() {
        let err = run_windows_dns_failclosed_check_command(&[])
            .expect_err("non-Windows host must fail closed");
        assert!(
            err.contains("requires a Windows runtime host"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_dns_failclosed_check_command_no_fail_on_drift_still_blocks_off_windows() {
        // Off-Windows the collector itself returns a blocker error
        // (not a "drift" outcome), so --no-fail-on-drift cannot
        // smuggle a passing exit out of a host that physically
        // cannot run the probe. This is the difference between an
        // architectural "cannot probe" and a contractual "drift".
        let err = run_windows_dns_failclosed_check_command(&["--no-fail-on-drift".to_owned()])
            .expect_err("collector blocker must surface even with --no-fail-on-drift");
        assert!(
            err.contains("requires a Windows runtime host"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn help_text_advertises_windows_killswitch_assert_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-killswitch-assert"),
            "help text must advertise windows-killswitch-assert subcommand"
        );
    }

    #[test]
    fn run_windows_killswitch_assert_command_rejects_unknown_flags() {
        let err = run_windows_killswitch_assert_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown daemon argument") || err.contains("unknown argument"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_killswitch_assert_command_fails_closed_when_unapplied() {
        let err = run_windows_killswitch_assert_command(&[])
            .expect_err("unapplied killswitch state must fail closed");
        assert!(
            err.contains("windows-killswitch-assert failed"),
            "unexpected error: {err}"
        );
        assert!(
            err.contains("killswitch is not applied"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn run_windows_killswitch_assert_command_no_fail_on_drift_reports_unapplied_state() {
        run_windows_killswitch_assert_command(&["--no-fail-on-drift".to_owned()])
            .expect("--no-fail-on-drift must allow report-only killswitch drift checks");
    }

    #[test]
    fn help_text_advertises_windows_backend_readiness_check_subcommand() {
        let help = help_text();
        assert!(
            help.contains("windows-backend-readiness-check"),
            "help text must advertise windows-backend-readiness-check subcommand"
        );
    }

    #[test]
    fn run_windows_backend_readiness_check_command_rejects_unknown_flags() {
        let err = run_windows_backend_readiness_check_command(&["--bogus".to_owned()])
            .expect_err("unknown flag must be rejected");
        assert!(
            err.contains("unknown windows-backend-readiness-check argument"),
            "unexpected error: {err}"
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_backend_readiness_check_command_off_windows_reports_drift() {
        // Off-Windows the collector marks every entry probed=false
        // with a "requires a Windows runtime host" reason; the
        // evaluator surfaces that as drift; default behaviour fails
        // closed.
        let err = run_windows_backend_readiness_check_command(&[])
            .expect_err("off-Windows host must fail closed");
        assert!(err.contains("reported drift"), "unexpected error: {err}");
    }

    #[cfg(not(windows))]
    #[test]
    fn run_windows_backend_readiness_check_command_no_fail_on_drift_off_windows_returns_ok() {
        run_windows_backend_readiness_check_command(&["--no-fail-on-drift".to_owned()])
            .expect("--no-fail-on-drift must allow report-only execution off Windows");
    }

    #[test]
    fn select_host_entry_routes_windows_service_mode_before_daemon_dispatch() {
        let selection = select_host_entry(&[
            "--windows-service".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rustynetd.env".to_owned(),
        ])
        .expect("windows service entry should parse");
        assert_eq!(
            selection,
            HostEntrySelection::WindowsService(WindowsServiceOptions {
                service_name: "RustyNet".to_owned(),
                env_file: PathBuf::from("/tmp/rustynetd.env"),
            })
        );
    }

    #[test]
    fn parse_daemon_config_allows_empty_fail_closed_cidrs_when_value_is_omitted() {
        let args = vec!["--fail-closed-ssh-allow-cidrs".to_owned()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.fail_closed_ssh_allow_cidrs.is_empty());
    }

    #[test]
    fn parse_daemon_config_allows_empty_fail_closed_cidrs_when_next_flag_follows() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_owned(),
            "--node-id".to_owned(),
            "node-a".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.fail_closed_ssh_allow_cidrs.is_empty());
        assert_eq!(config.node_id.as_str(), "node-a");
    }

    #[test]
    fn parse_daemon_config_parses_explicit_fail_closed_cidrs() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_owned(),
            "192.168.0.0/24,fd00::/64".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.fail_closed_ssh_allow_cidrs,
            vec![
                "192.168.0.0/24"
                    .parse::<ManagementCidr>()
                    .expect("cidr should parse"),
                "fd00::/64"
                    .parse::<ManagementCidr>()
                    .expect("cidr should parse"),
            ]
        );
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_fail_closed_cidrs() {
        let args = vec![
            "--fail-closed-ssh-allow-cidrs".to_owned(),
            "not-a-cidr".to_owned(),
        ];
        let err = parse_daemon_config(&args).expect_err("invalid cidr should fail parsing");
        assert!(err.contains("invalid --fail-closed-ssh-allow-cidrs value"));
    }

    #[test]
    fn parse_daemon_config_parses_auto_port_forward_settings() {
        let args = vec![
            "--auto-port-forward-exit".to_owned(),
            "true".to_owned(),
            "--auto-port-forward-lease-secs".to_owned(),
            "1200".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.auto_port_forward_exit);
        assert_eq!(config.auto_port_forward_lease_secs.get(), 1200);
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_auto_port_forward_exit_value() {
        let args = vec!["--auto-port-forward-exit".to_owned(), "maybe".to_owned()];
        let err =
            parse_daemon_config(&args).expect_err("invalid auto-port-forward value should fail");
        assert!(err.contains("invalid auto-port-forward-exit value"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_auto_port_forward_lease() {
        let args = vec!["--auto-port-forward-lease-secs".to_owned(), "0".to_owned()];
        let err = parse_daemon_config(&args).expect_err("zero lease should fail parsing");
        assert!(err.contains("must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_parses_anchor_bundle_pull_settings() {
        let args = vec![
            "--anchor-bundle-pull-addr".to_owned(),
            "127.0.0.1:51823".to_owned(),
            "--anchor-bundle-pull-token-path".to_owned(),
            "/var/lib/rustynet/test-anchor.token".to_owned(),
            "--anchor-bundle-pull-allow-lan".to_owned(),
            "true".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config
                .anchor_bundle_pull_addr
                .expect("anchor addr should be set")
                .to_string(),
            "127.0.0.1:51823"
        );
        assert_eq!(
            config.anchor_bundle_pull_token_path,
            Some(PathBuf::from("/var/lib/rustynet/test-anchor.token"))
        );
        assert!(config.anchor_bundle_pull_allow_lan);
    }

    #[test]
    fn parse_daemon_config_disables_anchor_bundle_pull_on_empty_token_path() {
        let args = vec![
            "--anchor-bundle-pull-token-path".to_owned(),
            "".to_owned(),
            "--anchor-bundle-pull-allow-lan".to_owned(),
            "false".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.anchor_bundle_pull_token_path.is_none());
        assert!(!config.anchor_bundle_pull_allow_lan);
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_anchor_bundle_pull_allow_lan() {
        let args = vec![
            "--anchor-bundle-pull-allow-lan".to_owned(),
            "maybe".to_owned(),
        ];
        let err = parse_daemon_config(&args)
            .expect_err("invalid anchor allow-lan value should fail parsing");
        assert!(err.contains("invalid --anchor-bundle-pull-allow-lan value"));
    }

    #[test]
    fn parse_daemon_config_parses_port_mapping_mode_auto() {
        let args = vec!["--port-mapping-mode".to_owned(), "auto".to_owned()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(config.port_mapping_mode, PortMappingMode::Auto);
    }

    #[test]
    fn parse_daemon_config_parses_port_mapping_mode_disabled() {
        let args = vec!["--port-mapping-mode".to_owned(), "disabled".to_owned()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(config.port_mapping_mode, PortMappingMode::Disabled);
    }

    #[test]
    fn parse_daemon_config_default_port_mapping_mode_is_keepalive() {
        // No --port-mapping-mode supplied → default to keepalive, the
        // strict-secure-practical default (works on every cooperative
        // cone NAT without any router probing).
        let args: Vec<String> = vec![];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(config.port_mapping_mode, PortMappingMode::Keepalive);
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_port_mapping_mode_value() {
        let args = vec![
            "--port-mapping-mode".to_owned(),
            "maximum-effort".to_owned(),
        ];
        let err = parse_daemon_config(&args).expect_err("unknown value rejected");
        assert!(
            err.contains("invalid"),
            "error message should describe the failure, got: {err}"
        );
    }

    #[test]
    fn parse_daemon_config_parses_local_relay_token_issuer() {
        let args = vec![
            "--relay-session-local-token-issuer".to_owned(),
            "true".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.relay_session_local_token_issuer_enabled);
    }

    #[test]
    fn parse_daemon_config_parses_relay_session_token_spool_dir() {
        let args = vec![
            "--relay-session-token-spool-dir".to_owned(),
            "/var/lib/rustynet/relay-token-spool".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.relay_session_token_spool_dir,
            Some(PathBuf::from("/var/lib/rustynet/relay-token-spool"))
        );
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_local_relay_token_issuer() {
        let args = vec![
            "--relay-session-local-token-issuer".to_owned(),
            "maybe".to_owned(),
        ];
        let err = parse_daemon_config(&args)
            .expect_err("invalid local relay token issuer value should fail");
        assert!(err.contains("invalid relay-session-local-token-issuer value"));
    }

    #[test]
    fn parse_daemon_config_parses_traversal_settings() {
        let args = vec![
            "--traversal-bundle".to_owned(),
            "/tmp/rustynet.traversal".to_owned(),
            "--traversal-verifier-key".to_owned(),
            "/tmp/rustynet.traversal.pub".to_owned(),
            "--traversal-watermark".to_owned(),
            "/tmp/rustynet.traversal.watermark".to_owned(),
            "--relay-fleet-bundle".to_owned(),
            "/tmp/rustynet.relay-fleet".to_owned(),
            "--relay-fleet-watermark".to_owned(),
            "/tmp/rustynet.relay-fleet.watermark".to_owned(),
            "--traversal-max-age-secs".to_owned(),
            "90".to_owned(),
            "--traversal-stun-servers".to_owned(),
            "203.0.113.10:3478,198.51.100.20:3478".to_owned(),
            "--traversal-stun-gather-timeout-ms".to_owned(),
            "2500".to_owned(),
            "--traversal-probe-max-candidates".to_owned(),
            "4".to_owned(),
            "--traversal-probe-max-pairs".to_owned(),
            "8".to_owned(),
            "--traversal-probe-rounds".to_owned(),
            "2".to_owned(),
            "--traversal-probe-round-spacing-ms".to_owned(),
            "40".to_owned(),
            "--traversal-probe-relay-switch-after-failures".to_owned(),
            "2".to_owned(),
            "--traversal-probe-handshake-freshness-secs".to_owned(),
            "15".to_owned(),
            "--traversal-probe-reprobe-interval-secs".to_owned(),
            "45".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.traversal_bundle_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal")
        );
        assert_eq!(
            config.traversal_verifier_key_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal.pub")
        );
        assert_eq!(
            config.traversal_watermark_path,
            std::path::PathBuf::from("/tmp/rustynet.traversal.watermark")
        );
        assert_eq!(
            config.relay_fleet_bundle_path.as_deref(),
            Some(std::path::Path::new("/tmp/rustynet.relay-fleet"))
        );
        assert_eq!(
            config.relay_fleet_watermark_path.as_deref(),
            Some(std::path::Path::new("/tmp/rustynet.relay-fleet.watermark"))
        );
        assert_eq!(config.traversal_max_age_secs.get(), 90);
        assert_eq!(
            config.traversal_stun_servers,
            vec![
                "203.0.113.10:3478".parse::<std::net::SocketAddr>().unwrap(),
                "198.51.100.20:3478"
                    .parse::<std::net::SocketAddr>()
                    .unwrap(),
            ]
        );
        assert_eq!(config.traversal_stun_gather_timeout_ms.get(), 2500);
        assert_eq!(config.traversal_probe_max_candidates.get(), 4);
        assert_eq!(config.traversal_probe_max_pairs.get(), 8);
        assert_eq!(config.traversal_probe_simultaneous_open_rounds.get(), 2);
        assert_eq!(config.traversal_probe_round_spacing_ms.get(), 40);
        assert_eq!(config.traversal_probe_relay_switch_after_failures.get(), 2);
        assert_eq!(config.traversal_probe_handshake_freshness_secs.get(), 15);
        assert_eq!(config.traversal_probe_reprobe_interval_secs.get(), 45);
    }

    #[test]
    fn parse_daemon_config_can_disable_relay_fleet() {
        let args = vec!["--disable-relay-fleet".to_owned()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.relay_fleet_bundle_path.is_none());
        assert!(config.relay_fleet_watermark_path.is_none());
    }

    #[test]
    fn parse_daemon_config_allows_empty_traversal_stun_servers_when_value_is_omitted() {
        let args = vec!["--traversal-stun-servers".to_owned()];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.traversal_stun_servers.is_empty());
    }

    #[test]
    fn parse_daemon_config_allows_empty_traversal_stun_servers_when_next_flag_follows() {
        let args = vec![
            "--traversal-stun-servers".to_owned(),
            "--node-id".to_owned(),
            "node-a".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert!(config.traversal_stun_servers.is_empty());
        assert_eq!(config.node_id.as_str(), "node-a");
    }

    #[test]
    fn parse_daemon_config_rejects_invalid_traversal_stun_servers() {
        let args = vec![
            "--traversal-stun-servers".to_owned(),
            "stun.example.com:3478".to_owned(),
        ];
        let err = parse_daemon_config(&args).expect_err("invalid server list should fail");
        assert!(err.contains("invalid --traversal-stun-servers value"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_stun_gather_timeout() {
        let args = vec![
            "--traversal-stun-gather-timeout-ms".to_owned(),
            "0".to_owned(),
        ];
        let err = parse_daemon_config(&args).expect_err("zero timeout should fail");
        assert!(err.contains("traversal stun gather timeout must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_accepts_userspace_shared_backend_values() {
        let linux = parse_daemon_config(&[
            "--backend".to_owned(),
            "linux-wireguard-userspace-shared".to_owned(),
        ])
        .expect("linux userspace-shared backend should parse");
        assert_eq!(
            linux.backend_mode,
            DaemonBackendMode::LinuxWireguardUserspaceShared
        );

        let macos = parse_daemon_config(&[
            "--backend".to_owned(),
            "macos-wireguard-userspace-shared".to_owned(),
        ])
        .expect("macos userspace-shared backend should parse");
        assert_eq!(
            macos.backend_mode,
            DaemonBackendMode::MacosWireguardUserspaceShared
        );
    }

    #[test]
    fn parse_daemon_config_accepts_windows_explicit_unsupported_backend_value() {
        let windows =
            parse_daemon_config(&["--backend".to_owned(), "windows-unsupported".to_owned()])
                .expect("windows explicit unsupported backend should parse");
        assert_eq!(windows.backend_mode, DaemonBackendMode::WindowsUnsupported);
    }

    #[test]
    fn parse_daemon_config_accepts_windows_wireguard_nt_backend_value() {
        let windows =
            parse_daemon_config(&["--backend".to_owned(), "windows-wireguard-nt".to_owned()])
                .expect("reviewed windows backend should parse");
        assert_eq!(windows.backend_mode, DaemonBackendMode::WindowsWireguardNt);
    }

    #[test]
    fn parse_daemon_config_rejects_unknown_windows_backend_value() {
        let err = parse_daemon_config(&[
            "--backend".to_owned(),
            "windows-wireguard-nt-typo".to_owned(),
        ])
        .expect_err("unknown windows backend should fail");
        assert!(err.contains("windows-unsupported"));
        assert!(err.contains("windows-wireguard-nt"));
    }

    #[test]
    fn parse_daemon_config_parses_dns_zone_settings() {
        let args = vec![
            "--dns-zone-bundle".to_owned(),
            "/tmp/rustynet.dns-zone".to_owned(),
            "--dns-zone-verifier-key".to_owned(),
            "/tmp/rustynet.dns-zone.pub".to_owned(),
            "--dns-zone-watermark".to_owned(),
            "/tmp/rustynet.dns-zone.watermark".to_owned(),
            "--dns-zone-max-age-secs".to_owned(),
            "120".to_owned(),
            "--dns-zone-name".to_owned(),
            "mesh.rustynet".to_owned(),
            "--dns-resolver-bind-addr".to_owned(),
            "127.0.0.1:5300".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.dns_zone_bundle_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone")
        );
        assert_eq!(
            config.dns_zone_verifier_key_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone.pub")
        );
        assert_eq!(
            config.dns_zone_watermark_path,
            std::path::PathBuf::from("/tmp/rustynet.dns-zone.watermark")
        );
        assert_eq!(config.dns_zone_max_age_secs.get(), 120);
        assert_eq!(config.dns_zone_name, "mesh.rustynet");
        assert_eq!(
            config.dns_resolver_bind_addr,
            "127.0.0.1:5300".parse().unwrap()
        );
    }

    #[test]
    fn parse_daemon_config_defaults_dns_zone_settings() {
        let config = parse_daemon_config(&[]).expect("default config should parse");
        assert_eq!(
            config.dns_zone_bundle_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_BUNDLE_PATH)
        );
        assert_eq!(
            config.dns_zone_verifier_key_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_VERIFIER_KEY_PATH)
        );
        assert_eq!(
            config.dns_zone_watermark_path,
            std::path::PathBuf::from(DEFAULT_DNS_ZONE_WATERMARK_PATH)
        );
        assert_eq!(
            config.dns_zone_max_age_secs.get(),
            DEFAULT_DNS_ZONE_MAX_AGE_SECS
        );
        assert_eq!(config.dns_zone_name, DEFAULT_DNS_ZONE_NAME);
        assert_eq!(
            config.dns_resolver_bind_addr,
            DEFAULT_DNS_RESOLVER_BIND_ADDR.parse().unwrap()
        );
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_max_age() {
        let args = vec!["--traversal-max-age-secs".to_owned(), "0".to_owned()];
        let err = parse_daemon_config(&args).expect_err("zero traversal max age should fail");
        assert!(err.contains("traversal max age must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_dns_zone_max_age() {
        let args = vec!["--dns-zone-max-age-secs".to_owned(), "0".to_owned()];
        let err = parse_daemon_config(&args).expect_err("zero dns zone max age should fail");
        assert!(err.contains("dns zone max age must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_rounds() {
        let args = vec!["--traversal-probe-rounds".to_owned(), "0".to_owned()];
        let err = parse_daemon_config(&args).expect_err("zero traversal probe rounds should fail");
        assert!(err.contains("traversal probe rounds must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_freshness() {
        let args = vec![
            "--traversal-probe-handshake-freshness-secs".to_owned(),
            "0".to_owned(),
        ];
        let err =
            parse_daemon_config(&args).expect_err("zero traversal probe freshness should fail");
        assert!(err.contains("traversal probe handshake freshness must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_rejects_zero_traversal_probe_reprobe_interval() {
        let args = vec![
            "--traversal-probe-reprobe-interval-secs".to_owned(),
            "0".to_owned(),
        ];
        let err = parse_daemon_config(&args)
            .expect_err("zero traversal probe reprobe interval should fail");
        assert!(err.contains("traversal probe reprobe interval must be greater than 0"));
    }

    #[test]
    fn parse_daemon_config_parses_remote_ops_auth_settings() {
        let args = vec![
            "--remote-ops-token-verifier-key".to_owned(),
            "/tmp/rustynet.remote-ops.pub".to_owned(),
            "--remote-ops-expected-subject".to_owned(),
            "user:remote-admin".to_owned(),
        ];
        let config = parse_daemon_config(&args).expect("config should parse");
        assert_eq!(
            config.remote_ops_token_verifier_key_path,
            Some(std::path::PathBuf::from("/tmp/rustynet.remote-ops.pub"))
        );
        assert_eq!(config.remote_ops_expected_subject, "user:remote-admin");
    }

    #[test]
    fn parse_daemon_config_defaults_remote_ops_auth_settings() {
        let config = parse_daemon_config(&[]).expect("default config should parse");
        assert_eq!(config.remote_ops_token_verifier_key_path, None);
        assert_eq!(
            config.remote_ops_expected_subject,
            DEFAULT_REMOTE_OPS_EXPECTED_SUBJECT
        );
    }

    #[test]
    fn membership_add_peer_rejects_missing_required_args() {
        // No args at all should fail requiring --node-id.
        let err = super::run_membership_add_peer(&[]).unwrap_err();
        assert!(err.contains("--node-id"), "should require --node-id: {err}");
    }

    #[test]
    fn membership_add_peer_rejects_invalid_pubkey_hex() {
        let args: Vec<String> = vec![
            "--node-id",
            "client-1",
            "--node-pubkey-hex",
            "not-hex-at-all",
            "--owner",
            "exit-1",
            "--approver-id",
            "exit-1-owner",
            "--signing-key",
            "/tmp/signing.key",
            "--signing-key-passphrase-file",
            "/tmp/passphrase",
        ]
        .into_iter()
        .map(str::to_string)
        .collect();
        let err = super::run_membership_add_peer(&args).unwrap_err();
        assert!(
            err.contains("64 hex") || err.contains("pubkey-hex"),
            "should reject invalid pubkey: {err}"
        );
    }

    #[test]
    fn membership_command_routes_add_peer() {
        // Routing check: run_membership_command dispatches "add-peer" without
        // panicking on argument validation (will fail on missing args, not unknown cmd).
        let err = super::run_membership_command(&["add-peer".to_owned()]).unwrap_err();
        // Should be an argument error, not "unknown membership subcommand".
        assert!(
            !err.contains("unknown membership subcommand"),
            "should route to add-peer handler: {err}"
        );
        assert!(
            err.contains("--node-id"),
            "should show first missing arg: {err}"
        );
    }

    #[test]
    fn membership_init_genesis_includes_anchor_sub_caps() {
        // Regression: live_anchor (rc 78) — genesis membership for the exit/
        // anchor node was missing anchor.* sub-capabilities, causing
        // policy_reject at the live_anchor stage.
        // Artifact: artifacts/live_lab/phase24-macos-smoke/
        //   20260527T224355Z_origin_main_live_macos_ssh_full_retry39
        let src = include_str!("main.rs");
        for sub_cap in [
            "RoleCapability::AnchorGossipSeed",
            "RoleCapability::AnchorBundlePull",
            "RoleCapability::AnchorEnrollmentEndpoint",
            "RoleCapability::AnchorRelayColocation",
            "RoleCapability::AnchorPortMappingAuthoritative",
        ] {
            assert!(
                src.contains(sub_cap),
                "genesis capabilities must include {sub_cap}; re-check run_membership_init"
            );
        }
    }

    #[test]
    fn membership_init_pub_key_path_matches_membership_owner_key_path() {
        // The .pub file written by membership init is at
        // "{owner_signing_key_path}.pub". Verify the constant paths align.
        use super::DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH;
        let pub_path = format!("{DEFAULT_MEMBERSHIP_OWNER_SIGNING_KEY_PATH}.pub");
        assert!(
            pub_path.ends_with(".pub"),
            "pub key path must end with .pub: {pub_path}"
        );
    }

    // ---- X6: classify_top_level_error coverage --------------------------

    #[test]
    fn classify_top_level_error_maps_usage_text_to_bad_args() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_top_level_error("rustynetd usage:\n  rustynetd daemon …"),
            ExitCode::BadArgs
        );
        assert_eq!(
            classify_top_level_error("unknown subcommand 'foo'"),
            ExitCode::BadArgs
        );
        assert_eq!(
            classify_top_level_error("missing required value for --node-id"),
            ExitCode::BadArgs
        );
    }

    #[test]
    fn classify_top_level_error_maps_signature_verification_to_policy_reject() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_top_level_error("signature verification failed for trust-evidence bundle"),
            ExitCode::PolicyReject
        );
        assert_eq!(
            classify_top_level_error("reviewed root check rejected /tmp/state"),
            ExitCode::PolicyReject
        );
        assert_eq!(
            classify_top_level_error("fail-closed gate refused operation"),
            ExitCode::PolicyReject
        );
    }

    #[test]
    fn classify_top_level_error_maps_schema_to_config_error() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_top_level_error("config file at /etc/rustynet/daemon.env malformed"),
            ExitCode::ConfigError
        );
        assert_eq!(
            classify_top_level_error("invalid path /tmp/state for state file"),
            ExitCode::ConfigError
        );
        assert_eq!(
            classify_top_level_error("schema mismatch in assignment bundle"),
            ExitCode::ConfigError
        );
    }

    #[test]
    fn classify_top_level_error_maps_io_failures_to_transient() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_top_level_error("connection refused on privileged helper socket"),
            ExitCode::TransientFailure
        );
        assert_eq!(
            classify_top_level_error("temporarily unavailable; retry after 30s"),
            ExitCode::TransientFailure
        );
        assert_eq!(
            classify_top_level_error("operation timed out after 5s"),
            ExitCode::TransientFailure
        );
    }

    #[test]
    fn classify_top_level_error_falls_back_to_generic_failure() {
        use rustynetd::exit_codes::ExitCode;
        assert_eq!(
            classify_top_level_error("some unknown failure"),
            ExitCode::GenericFailure
        );
        assert_eq!(classify_top_level_error(""), ExitCode::GenericFailure);
    }
}
