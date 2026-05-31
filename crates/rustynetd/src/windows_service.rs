#![allow(clippy::result_large_err)]

use crate::windows_backend_gate::{
    WINDOWS_UNSUPPORTED_BACKEND_LABEL, WINDOWS_WIREGUARD_NT_BACKEND_LABEL, WindowsBackendMode,
    parse_windows_backend_mode, require_supported_windows_backend,
};
use crate::windows_backend_readiness::{
    WindowsBackendReadinessReport, auto_select_windows_backend_mode,
    collect_windows_backend_readiness_report,
};
use crate::windows_paths::validate_windows_runtime_file_path;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

const DEFAULT_WINDOWS_SERVICE_NAME: &str = "RustyNet";
const WINDOWS_SERVICE_DAEMON_ARGS_ENV: &str = "RUSTYNETD_DAEMON_ARGS_JSON";
const MAX_WINDOWS_ENV_FILE_BYTES: usize = 64 * 1024;
#[cfg_attr(not(windows), allow(dead_code))]
static WINDOWS_SERVICE_STOP_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn reset_windows_service_stop_requested() {
    WINDOWS_SERVICE_STOP_REQUESTED.store(false, Ordering::SeqCst);
}

#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn request_windows_service_stop() {
    WINDOWS_SERVICE_STOP_REQUESTED.store(true, Ordering::SeqCst);
}

pub fn windows_service_stop_requested() -> bool {
    WINDOWS_SERVICE_STOP_REQUESTED.load(Ordering::SeqCst)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceOptions {
    pub service_name: String,
    pub env_file: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostEntrySelection {
    Standard(Vec<String>),
    WindowsService(WindowsServiceOptions),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsServiceRuntimeInput {
    pub env_file: PathBuf,
    pub variables: BTreeMap<String, String>,
    pub daemon_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WindowsBackendRequest {
    Missing,
    NonWindows(String),
    ExplicitUnsupported(WindowsBackendMode),
    AutoSelected(WindowsBackendMode),
    Reviewed(WindowsBackendMode),
    ReadinessBlocked {
        requested_label: String,
        drift_reasons: Vec<String>,
    },
    Unknown(String),
}

impl WindowsBackendRequest {
    pub fn blocker_reason(&self) -> Option<String> {
        match self {
            Self::Missing => Some("windows-runtime-backend-not-configured: Windows service host loaded reviewed config, but the env-file did not specify --backend in RUSTYNETD_DAEMON_ARGS_JSON. Windows backend/dataplane support remains unavailable until an operator selects a reviewed Windows backend label.".to_owned()),
            Self::NonWindows(label) => Some(format!(
                "windows-runtime-backend-not-supported: backend '{label}' is not valid for the Windows service host. Linux and macOS backend modes remain platform-specific and Windows dataplane support is still unavailable on the current branch."
            )),
            Self::ExplicitUnsupported(mode) => Some(
                require_supported_windows_backend(*mode)
                    .expect_err("explicit Windows unsupported mode must fail closed"),
            ),
            Self::AutoSelected(_) => None,
            Self::Reviewed(_) => None,
            Self::ReadinessBlocked {
                requested_label,
                drift_reasons,
            } => Some(format!(
                "windows-runtime-backend-readiness-blocked: requested backend '{requested_label}' cannot start because reviewed windows-wireguard-nt prerequisites failed: {}",
                drift_reasons.join("; ")
            )),
            Self::Unknown(label) => Some(format!(
                "windows-runtime-backend-not-recognized: backend '{label}' is not a reviewed Windows backend label on the current branch. Expected {WINDOWS_UNSUPPORTED_BACKEND_LABEL} or {WINDOWS_WIREGUARD_NT_BACKEND_LABEL}."
            )),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedWindowsServiceHost {
    pub service_name: String,
    pub env_file: PathBuf,
    pub daemon_args: Vec<String>,
    pub backend_request: WindowsBackendRequest,
}

pub type WindowsDaemonArgsRunner = fn(&[String]) -> Result<(), String>;

pub fn select_host_entry(args: &[String]) -> Result<HostEntrySelection, String> {
    let (remaining, service) = strip_windows_service_args(args)?;
    if let Some(service) = service {
        if !remaining.is_empty() {
            return Err(
                "--windows-service does not accept daemon subcommands or inline daemon flags; use --env-file with RUSTYNETD_DAEMON_ARGS_JSON".to_owned(),
            );
        }
        return Ok(HostEntrySelection::WindowsService(service));
    }
    Ok(HostEntrySelection::Standard(remaining))
}

pub fn strip_windows_service_args(
    args: &[String],
) -> Result<(Vec<String>, Option<WindowsServiceOptions>), String> {
    let mut remaining = Vec::new();
    let mut windows_service = false;
    let mut service_name: Option<String> = None;
    let mut env_file: Option<PathBuf> = None;
    let mut index = 0usize;

    while let Some(arg) = args.get(index) {
        match arg.as_str() {
            "--windows-service" => {
                windows_service = true;
                index += 1;
            }
            "--service-name" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--service-name requires a value".to_owned())?;
                service_name = Some(value.clone());
                index += 2;
            }
            "--env-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--env-file requires a value".to_owned())?;
                env_file = Some(PathBuf::from(value));
                index += 2;
            }
            _ => {
                remaining.push(arg.clone());
                index += 1;
            }
        }
    }

    if !windows_service {
        if service_name.is_some() {
            return Err("--service-name requires --windows-service".to_owned());
        }
        if env_file.is_some() {
            return Err("--env-file requires --windows-service".to_owned());
        }
        return Ok((remaining, None));
    }

    let env_file = env_file.ok_or_else(|| {
        "--windows-service requires --env-file so the Windows SCM host loads reviewed config input".to_owned()
    })?;

    Ok((
        remaining,
        Some(WindowsServiceOptions {
            service_name: service_name.unwrap_or_else(|| DEFAULT_WINDOWS_SERVICE_NAME.to_owned()),
            env_file,
        }),
    ))
}

pub fn prepare_windows_service_host(
    options: &WindowsServiceOptions,
) -> Result<PreparedWindowsServiceHost, String> {
    validate_windows_runtime_file_path(&options.env_file, "windows service env-file")?;

    let runtime_input = load_windows_service_runtime_input(&options.env_file)?;
    let readiness = collect_windows_backend_readiness_report();
    let (daemon_args, backend_request) =
        resolve_windows_backend_request(runtime_input.daemon_args, readiness)?;

    Ok(PreparedWindowsServiceHost {
        service_name: options.service_name.clone(),
        env_file: runtime_input.env_file,
        daemon_args,
        backend_request,
    })
}

pub fn load_windows_service_runtime_input(
    env_file: &Path,
) -> Result<WindowsServiceRuntimeInput, String> {
    let bytes = fs::read(env_file).map_err(|err| {
        format!(
            "failed to read Windows service env-file {}: {err}",
            env_file.display()
        )
    })?;
    if bytes.len() > MAX_WINDOWS_ENV_FILE_BYTES {
        return Err(format!(
            "Windows service env-file is too large ({} bytes > {MAX_WINDOWS_ENV_FILE_BYTES})",
            bytes.len()
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|err| format!("Windows service env-file must be UTF-8: {err}"))?;
    let variables = parse_windows_env_file(text)?;
    let daemon_args_json = variables
        .get(WINDOWS_SERVICE_DAEMON_ARGS_ENV)
        .ok_or_else(|| {
            format!(
                "Windows service env-file must define {WINDOWS_SERVICE_DAEMON_ARGS_ENV} as a JSON array of daemon flags"
            )
        })?;
    let daemon_args: Vec<String> = serde_json::from_str(daemon_args_json).map_err(|err| {
        format!("{WINDOWS_SERVICE_DAEMON_ARGS_ENV} must be a JSON array of strings: {err}")
    })?;
    if daemon_args.is_empty() {
        return Err(format!(
            "{WINDOWS_SERVICE_DAEMON_ARGS_ENV} must include at least one daemon flag"
        ));
    }
    Ok(WindowsServiceRuntimeInput {
        env_file: env_file.to_path_buf(),
        variables,
        daemon_args,
    })
}

pub fn classify_windows_backend_request(args: &[String]) -> Result<WindowsBackendRequest, String> {
    let mut backend: Option<String> = None;
    let mut index = 0usize;
    while index < args.len() {
        match args.get(index).map(String::as_str) {
            Some("--backend") => {
                let value = args.get(index + 1).ok_or_else(|| {
                    "--backend in RUSTYNETD_DAEMON_ARGS_JSON requires a value".to_owned()
                })?;
                if backend.is_some() {
                    return Err(
                        "RUSTYNETD_DAEMON_ARGS_JSON must not specify --backend more than once"
                            .to_owned(),
                    );
                }
                backend = Some(value.clone());
                index += 2;
            }
            Some(_) => {
                index += 1;
            }
            None => break,
        }
    }

    let Some(backend) = backend else {
        return Ok(WindowsBackendRequest::Missing);
    };

    if matches!(
        backend.as_str(),
        "linux-wireguard"
            | "linux-wireguard-userspace-shared"
            | "macos-wireguard"
            | "macos-wireguard-userspace-shared"
    ) {
        return Ok(WindowsBackendRequest::NonWindows(backend));
    }

    match parse_windows_backend_mode(backend.as_str()) {
        Ok(WindowsBackendMode::Unsupported) => Ok(WindowsBackendRequest::ExplicitUnsupported(
            WindowsBackendMode::Unsupported,
        )),
        Ok(mode) => Ok(WindowsBackendRequest::Reviewed(mode)),
        Err(_) => Ok(WindowsBackendRequest::Unknown(backend)),
    }
}

pub fn resolve_windows_backend_request(
    daemon_args: Vec<String>,
    readiness: WindowsBackendReadinessReport,
) -> Result<(Vec<String>, WindowsBackendRequest), String> {
    let request = classify_windows_backend_request(&daemon_args)?;
    match request {
        WindowsBackendRequest::Missing => match auto_select_windows_backend_mode(&readiness) {
            Ok(mode) => Ok((
                with_single_windows_backend_arg(daemon_args, WINDOWS_WIREGUARD_NT_BACKEND_LABEL),
                WindowsBackendRequest::AutoSelected(mode),
            )),
            Err(_) => Ok((
                daemon_args,
                WindowsBackendRequest::ReadinessBlocked {
                    requested_label: "(missing --backend)".to_owned(),
                    drift_reasons: readiness.drift_reasons,
                },
            )),
        },
        WindowsBackendRequest::ExplicitUnsupported(_) => {
            match auto_select_windows_backend_mode(&readiness) {
                Ok(mode) => Ok((
                    with_single_windows_backend_arg(
                        daemon_args,
                        WINDOWS_WIREGUARD_NT_BACKEND_LABEL,
                    ),
                    WindowsBackendRequest::AutoSelected(mode),
                )),
                Err(_) => Ok((
                    daemon_args,
                    WindowsBackendRequest::ReadinessBlocked {
                        requested_label: WINDOWS_UNSUPPORTED_BACKEND_LABEL.to_owned(),
                        drift_reasons: readiness.drift_reasons,
                    },
                )),
            }
        }
        WindowsBackendRequest::Reviewed(mode) => {
            if readiness.overall_ok {
                Ok((daemon_args, WindowsBackendRequest::Reviewed(mode)))
            } else {
                Ok((
                    daemon_args,
                    WindowsBackendRequest::ReadinessBlocked {
                        requested_label: WINDOWS_WIREGUARD_NT_BACKEND_LABEL.to_owned(),
                        drift_reasons: readiness.drift_reasons,
                    },
                ))
            }
        }
        WindowsBackendRequest::NonWindows(_)
        | WindowsBackendRequest::Unknown(_)
        | WindowsBackendRequest::AutoSelected(_)
        | WindowsBackendRequest::ReadinessBlocked { .. } => Ok((daemon_args, request)),
    }
}

fn with_single_windows_backend_arg(mut args: Vec<String>, label: &str) -> Vec<String> {
    let mut index = 0usize;
    while index < args.len() {
        if args[index] == "--backend" {
            if let Some(value) = args.get_mut(index + 1) {
                *value = label.to_owned();
                return args;
            }
            break;
        }
        index += 1;
    }
    args.push("--backend".to_owned());
    args.push(label.to_owned());
    args
}

fn parse_windows_env_file(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut variables = BTreeMap::new();
    for (line_number, raw_line) in text.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            format!(
                "invalid Windows service env-file line {}: expected KEY=VALUE",
                line_number + 1
            )
        })?;
        let key = key.trim();
        if !is_valid_env_key(key) {
            return Err(format!(
                "invalid Windows service env-file key '{}' on line {}",
                key,
                line_number + 1
            ));
        }
        if variables.contains_key(key) {
            return Err(format!(
                "duplicate Windows service env-file key '{}' on line {}",
                key,
                line_number + 1
            ));
        }
        let value = strip_optional_quotes(value.trim())?;
        variables.insert(key.to_owned(), value);
    }
    Ok(variables)
}

fn is_valid_env_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(first) if first == '_' || first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn strip_optional_quotes(value: &str) -> Result<String, String> {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return Ok(value[1..value.len() - 1].to_string());
        }
        if first == b'"' || first == b'\'' || last == b'"' || last == b'\'' {
            return Err("mismatched quotes in Windows service env-file value".to_owned());
        }
    }
    Ok(value.to_owned())
}

pub fn windows_service_help_line() -> &'static str {
    "  rustynetd --windows-service --env-file <path> [--service-name <name>]"
}

pub fn windows_service_help_note() -> &'static str {
    "  windows_service_env=requires RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-unsupported\"|\"windows-wireguard-nt\",...] in the reviewed env-file; windows-unsupported remains the explicit fail-closed label, while windows-wireguard-nt is opt-in and still outside release-gated support until measured evidence exists"
}

pub fn run_windows_service_host(
    options: WindowsServiceOptions,
    daemon_runner: WindowsDaemonArgsRunner,
) -> Result<(), String> {
    let prepared = prepare_windows_service_host(&options)?;
    run_windows_service_host_impl(prepared, daemon_runner)
}

#[cfg(not(windows))]
fn run_windows_service_host_impl(
    _prepared: PreparedWindowsServiceHost,
    _daemon_runner: WindowsDaemonArgsRunner,
) -> Result<(), String> {
    Err("--windows-service is only supported on Windows SCM hosts".to_owned())
}

#[cfg(windows)]
fn run_windows_service_host_impl(
    prepared: PreparedWindowsServiceHost,
    daemon_runner: WindowsDaemonArgsRunner,
) -> Result<(), String> {
    windows_only::dispatch(prepared, daemon_runner)
}

#[cfg(windows)]
mod windows_only {
    use super::{PreparedWindowsServiceHost, WindowsDaemonArgsRunner};
    use std::ffi::OsString;
    use std::sync::OnceLock;
    use std::time::Duration;
    use windows_service::define_windows_service;
    use windows_service::service::{
        ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus, ServiceType,
    };
    use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
    use windows_service::service_dispatcher;

    struct WindowsServiceHostState {
        prepared: PreparedWindowsServiceHost,
        daemon_runner: WindowsDaemonArgsRunner,
    }

    static WINDOWS_SERVICE_HOST: OnceLock<WindowsServiceHostState> = OnceLock::new();

    define_windows_service!(ffi_windows_service_main, windows_service_main);

    pub(super) fn dispatch(
        prepared: PreparedWindowsServiceHost,
        daemon_runner: WindowsDaemonArgsRunner,
    ) -> Result<(), String> {
        let service_name = prepared.service_name.clone();
        WINDOWS_SERVICE_HOST
            .set(WindowsServiceHostState {
                prepared,
                daemon_runner,
            })
            .map_err(|_| "windows service host already initialized in this process".to_string())?;
        service_dispatcher::start(service_name.as_str(), ffi_windows_service_main)
            .map_err(|err| format!("failed to dispatch Windows service host: {err}"))
    }

    fn windows_service_main(_arguments: Vec<OsString>) {
        if let Err(err) = run_service_main() {
            eprintln!("rustynetd Windows service host failed: {err}");
        }
    }

    fn run_service_main() -> Result<(), String> {
        let state = WINDOWS_SERVICE_HOST
            .get()
            .ok_or_else(|| "missing Windows service host configuration".to_string())?;
        let prepared = &state.prepared;
        super::reset_windows_service_stop_requested();
        let status_handle = service_control_handler::register(
            prepared.service_name.as_str(),
            move |control_event| match control_event {
                windows_service::service::ServiceControl::Interrogate => {
                    ServiceControlHandlerResult::NoError
                }
                windows_service::service::ServiceControl::Stop
                | windows_service::service::ServiceControl::Shutdown => {
                    super::request_windows_service_stop();
                    ServiceControlHandlerResult::NoError
                }
                _ => ServiceControlHandlerResult::NotImplemented,
            },
        )
        .map_err(|err| format!("failed to register Windows service control handler: {err}"))?;

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::StartPending,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 1,
                wait_hint: Duration::from_secs(10),
                process_id: None,
            })
            .map_err(|err| {
                format!("failed to report Windows service start-pending status: {err}")
            })?;

        if let Some(blocker) = prepared.backend_request.blocker_reason() {
            status_handle
                .set_service_status(ServiceStatus {
                    service_type: ServiceType::OWN_PROCESS,
                    current_state: ServiceState::Stopped,
                    controls_accepted: ServiceControlAccept::empty(),
                    exit_code: ServiceExitCode::Win32(1),
                    checkpoint: 0,
                    wait_hint: Duration::default(),
                    process_id: None,
                })
                .map_err(|err| format!("failed to report Windows service stopped status: {err}"))?;
            return Err(blocker);
        }

        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Running,
                controls_accepted: ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN,
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|err| format!("failed to report Windows service running status: {err}"))?;

        let daemon_runner = state.daemon_runner;
        let daemon_args = prepared.daemon_args.clone();
        let daemon_thread = std::thread::spawn(move || daemon_runner(&daemon_args));
        let mut stop_pending_reported = false;
        while !daemon_thread.is_finished() {
            if super::windows_service_stop_requested() && !stop_pending_reported {
                status_handle
                    .set_service_status(ServiceStatus {
                        service_type: ServiceType::OWN_PROCESS,
                        current_state: ServiceState::StopPending,
                        controls_accepted: ServiceControlAccept::empty(),
                        exit_code: ServiceExitCode::Win32(0),
                        checkpoint: 1,
                        wait_hint: Duration::from_secs(20),
                        process_id: None,
                    })
                    .map_err(|err| {
                        format!("failed to report Windows service stop-pending status: {err}")
                    })?;
                stop_pending_reported = true;
            }
            std::thread::sleep(Duration::from_millis(200));
        }

        let result = daemon_thread
            .join()
            .map_err(|_| "rustynetd Windows service daemon thread panicked".to_string())?;
        let exit_code = if result.is_ok() { 0 } else { 1 };
        status_handle
            .set_service_status(ServiceStatus {
                service_type: ServiceType::OWN_PROCESS,
                current_state: ServiceState::Stopped,
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(exit_code),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|err| format!("failed to report Windows service stopped status: {err}"))?;

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_backend_readiness::{
        REVIEWED_NETSH_EXE_PATH, REVIEWED_POWERSHELL_EXE_PATH, REVIEWED_SC_EXE_PATH,
        REVIEWED_WG_EXE_PATH, REVIEWED_WIREGUARD_EXE_PATH, WindowsBackendReadinessEntry,
        build_windows_backend_readiness_report,
    };

    fn good_backend_readiness_report() -> WindowsBackendReadinessReport {
        build_windows_backend_readiness_report(vec![
            WindowsBackendReadinessEntry {
                label: "wireguard.exe".to_owned(),
                path: REVIEWED_WIREGUARD_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "wg.exe".to_owned(),
                path: REVIEWED_WG_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "netsh.exe".to_owned(),
                path: REVIEWED_NETSH_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "sc.exe".to_owned(),
                path: REVIEWED_SC_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "PowerShell.exe".to_owned(),
                path: REVIEWED_POWERSHELL_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "Windows version".to_owned(),
                path: "Environment.OSVersion.Version".to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "elevated administrator token".to_owned(),
                path: REVIEWED_POWERSHELL_EXE_PATH.to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
            WindowsBackendReadinessEntry {
                label: "required Win32 API surface".to_owned(),
                path: "CryptProtectData/CryptUnprotectData".to_owned(),
                present: true,
                probed: true,
                reason: None,
            },
        ])
    }

    fn bad_backend_readiness_report() -> WindowsBackendReadinessReport {
        let mut report = good_backend_readiness_report();
        report.overall_ok = false;
        report.drift_reasons = vec![
            "wg.exe not present at reviewed path C:\\Program Files\\WireGuard\\wg.exe".to_owned(),
        ];
        report
    }

    #[test]
    fn strip_windows_service_args_returns_standard_args_when_mode_not_requested() {
        let args = vec![
            "daemon".to_owned(),
            "--backend".to_owned(),
            "linux-wireguard".to_owned(),
        ];
        let (remaining, options) = strip_windows_service_args(&args).expect("args should parse");
        assert_eq!(remaining, args);
        assert!(options.is_none());
    }

    #[test]
    fn strip_windows_service_args_requires_env_file() {
        let err = strip_windows_service_args(&["--windows-service".to_owned()])
            .expect_err("missing env-file should fail");
        assert!(err.contains("--windows-service requires --env-file"));
    }

    #[test]
    fn strip_windows_service_args_rejects_env_file_without_service_mode() {
        let err =
            strip_windows_service_args(&["--env-file".to_owned(), "/tmp/rustynetd.env".to_owned()])
                .expect_err("env-file without service mode should fail");
        assert!(err.contains("--env-file requires --windows-service"));
    }

    #[test]
    fn select_host_entry_prefers_windows_service_mode() {
        let selection = select_host_entry(&[
            "--windows-service".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rustynetd.env".to_owned(),
        ])
        .expect("service mode should parse");
        assert_eq!(
            selection,
            HostEntrySelection::WindowsService(WindowsServiceOptions {
                service_name: "RustyNet".to_owned(),
                env_file: PathBuf::from("/tmp/rustynetd.env"),
            })
        );
    }

    #[test]
    fn select_host_entry_rejects_inline_daemon_subcommands_for_windows_service() {
        let err = select_host_entry(&[
            "daemon".to_owned(),
            "--windows-service".to_owned(),
            "--env-file".to_owned(),
            "/tmp/rustynetd.env".to_owned(),
        ])
        .expect_err("inline daemon args must be rejected");
        assert!(err.contains("does not accept daemon subcommands"));
    }

    #[test]
    fn load_windows_service_runtime_input_parses_json_daemon_args() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let env_path = dir.path().join("rustynetd.env");
        fs::write(
            &env_path,
            concat!(
                "# reviewed Windows service config\n",
                "RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-unsupported\"]\n",
            ),
        )
        .expect("env file should be written");
        let input = load_windows_service_runtime_input(&env_path).expect("env file should parse");
        assert_eq!(
            input.daemon_args,
            vec!["--backend".to_owned(), "windows-unsupported".to_owned()]
        );
    }

    #[test]
    fn load_windows_service_runtime_input_rejects_duplicate_keys() {
        let dir = tempfile::tempdir().expect("tempdir should be created");
        let env_path = dir.path().join("rustynetd.env");
        fs::write(
            &env_path,
            concat!(
                "RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-unsupported\"]\n",
                "RUSTYNETD_DAEMON_ARGS_JSON=[\"--backend\",\"windows-wireguard-nt\"]\n",
            ),
        )
        .expect("env file should be written");
        let err = load_windows_service_runtime_input(&env_path)
            .expect_err("duplicate env keys should fail");
        assert!(err.contains("duplicate Windows service env-file key"));
    }

    #[test]
    fn classify_windows_backend_request_rejects_linux_backend_labels() {
        let request = classify_windows_backend_request(&[
            "--backend".to_owned(),
            "linux-wireguard".to_owned(),
        ])
        .expect("backend classification should parse");
        assert_eq!(
            request,
            WindowsBackendRequest::NonWindows("linux-wireguard".to_owned())
        );
    }

    #[test]
    fn classify_windows_backend_request_accepts_explicit_unsupported_windows_label() {
        let request = classify_windows_backend_request(&[
            "--backend".to_owned(),
            "windows-unsupported".to_owned(),
        ])
        .expect("backend classification should parse");
        assert_eq!(
            request,
            WindowsBackendRequest::ExplicitUnsupported(WindowsBackendMode::Unsupported)
        );
    }

    #[test]
    fn classify_windows_backend_request_accepts_reviewed_wireguard_nt_label() {
        let request = classify_windows_backend_request(&[
            "--backend".to_owned(),
            "windows-wireguard-nt".to_owned(),
        ])
        .expect("backend classification should parse");
        assert_eq!(
            request,
            WindowsBackendRequest::Reviewed(WindowsBackendMode::WireguardNt)
        );
    }

    #[test]
    fn classify_windows_backend_request_marks_missing_backend_as_blocked() {
        let request =
            classify_windows_backend_request(&["--node-id".to_owned(), "node-a".to_owned()])
                .expect("backend classification should parse");
        assert_eq!(request, WindowsBackendRequest::Missing);
    }

    #[test]
    fn resolve_windows_backend_request_auto_selects_when_backend_missing_and_ready() {
        let (args, request) = resolve_windows_backend_request(
            vec!["--node-id".to_owned(), "node-a".to_owned()],
            good_backend_readiness_report(),
        )
        .expect("selection should succeed");
        assert_eq!(
            request,
            WindowsBackendRequest::AutoSelected(WindowsBackendMode::WireguardNt)
        );
        assert_eq!(
            args,
            vec![
                "--node-id".to_owned(),
                "node-a".to_owned(),
                "--backend".to_owned(),
                WINDOWS_WIREGUARD_NT_BACKEND_LABEL.to_owned(),
            ]
        );
    }

    #[test]
    fn resolve_windows_backend_request_replaces_explicit_unsupported_when_ready() {
        let (args, request) = resolve_windows_backend_request(
            vec![
                "--backend".to_owned(),
                WINDOWS_UNSUPPORTED_BACKEND_LABEL.to_owned(),
                "--node-id".to_owned(),
                "node-a".to_owned(),
            ],
            good_backend_readiness_report(),
        )
        .expect("selection should succeed");
        assert_eq!(
            request,
            WindowsBackendRequest::AutoSelected(WindowsBackendMode::WireguardNt)
        );
        assert_eq!(args[1], WINDOWS_WIREGUARD_NT_BACKEND_LABEL);
    }

    #[test]
    fn resolve_windows_backend_request_blocks_reviewed_mode_when_readiness_drifts() {
        let (_args, request) = resolve_windows_backend_request(
            vec![
                "--backend".to_owned(),
                WINDOWS_WIREGUARD_NT_BACKEND_LABEL.to_owned(),
            ],
            bad_backend_readiness_report(),
        )
        .expect("resolution should return structured blocker");
        match request {
            WindowsBackendRequest::ReadinessBlocked {
                requested_label,
                drift_reasons,
            } => {
                assert_eq!(requested_label, WINDOWS_WIREGUARD_NT_BACKEND_LABEL);
                assert!(drift_reasons.iter().any(|reason| reason.contains("wg.exe")));
            }
            other => panic!("expected readiness blocker, got {other:?}"),
        }
    }

    #[test]
    fn readiness_blocker_reason_surfaces_structured_drift() {
        let request = WindowsBackendRequest::ReadinessBlocked {
            requested_label: WINDOWS_WIREGUARD_NT_BACKEND_LABEL.to_owned(),
            drift_reasons: vec!["not elevated".to_owned()],
        };
        let reason = request
            .blocker_reason()
            .expect("readiness blocker should produce reason");
        assert!(reason.contains("windows-runtime-backend-readiness-blocked"));
        assert!(reason.contains("not elevated"));
    }

    #[test]
    fn prepare_windows_service_host_requires_absolute_env_file_path() {
        let err = prepare_windows_service_host(&WindowsServiceOptions {
            service_name: "RustyNet".to_owned(),
            env_file: PathBuf::from("relative.env"),
        })
        .expect_err("relative env-file path should fail");
        assert!(err.contains("absolute Windows path"));
    }

    #[test]
    fn windows_service_help_strings_are_present() {
        assert!(windows_service_help_line().contains("--windows-service"));
        assert!(windows_service_help_note().contains(WINDOWS_SERVICE_DAEMON_ARGS_ENV));
    }

    #[test]
    fn windows_service_stop_flag_round_trips() {
        reset_windows_service_stop_requested();
        assert!(!windows_service_stop_requested());
        request_windows_service_stop();
        assert!(windows_service_stop_requested());
        reset_windows_service_stop_requested();
        assert!(!windows_service_stop_requested());
    }
}
