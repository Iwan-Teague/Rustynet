#![allow(clippy::result_large_err)]

use crate::windows_backend_gate::{
    WINDOWS_UNSUPPORTED_BACKEND_LABEL, WINDOWS_WIREGUARD_NT_BACKEND_LABEL, WindowsBackendMode,
    parse_windows_backend_mode, require_supported_windows_backend,
};
use crate::windows_paths::validate_windows_runtime_file_path;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

const DEFAULT_WINDOWS_SERVICE_NAME: &str = "RustyNet";
const WINDOWS_SERVICE_DAEMON_ARGS_ENV: &str = "RUSTYNETD_DAEMON_ARGS_JSON";
const MAX_WINDOWS_ENV_FILE_BYTES: usize = 64 * 1024;

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
    Reviewed(WindowsBackendMode),
    Unknown(String),
}

impl WindowsBackendRequest {
    pub fn blocker_reason(&self) -> Option<String> {
        match self {
            Self::Missing => Some("windows-runtime-backend-not-configured: Windows service host loaded reviewed config, but the env-file did not specify --backend in RUSTYNETD_DAEMON_ARGS_JSON. Windows backend/dataplane support remains unavailable until an operator selects a reviewed Windows backend label.".to_string()),
            Self::NonWindows(label) => Some(format!(
                "windows-runtime-backend-not-supported: backend '{label}' is not valid for the Windows service host. Linux and macOS backend modes remain platform-specific and Windows dataplane support is still unavailable on the current branch."
            )),
            Self::ExplicitUnsupported(mode) => Some(
                require_supported_windows_backend(*mode)
                    .expect_err("explicit Windows unsupported mode must fail closed"),
            ),
            Self::Reviewed(_) => None,
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
                "--windows-service does not accept daemon subcommands or inline daemon flags; use --env-file with RUSTYNETD_DAEMON_ARGS_JSON"
                    .to_string(),
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
                    .ok_or_else(|| "--service-name requires a value".to_string())?;
                service_name = Some(value.clone());
                index += 2;
            }
            "--env-file" => {
                let value = args
                    .get(index + 1)
                    .ok_or_else(|| "--env-file requires a value".to_string())?;
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
            return Err("--service-name requires --windows-service".to_string());
        }
        if env_file.is_some() {
            return Err("--env-file requires --windows-service".to_string());
        }
        return Ok((remaining, None));
    }

    let env_file = env_file.ok_or_else(|| {
        "--windows-service requires --env-file so the Windows SCM host loads reviewed config input"
            .to_string()
    })?;

    Ok((
        remaining,
        Some(WindowsServiceOptions {
            service_name: service_name.unwrap_or_else(|| DEFAULT_WINDOWS_SERVICE_NAME.to_string()),
            env_file,
        }),
    ))
}

pub fn prepare_windows_service_host(
    options: &WindowsServiceOptions,
) -> Result<PreparedWindowsServiceHost, String> {
    validate_windows_runtime_file_path(&options.env_file, "windows service env-file")?;

    let runtime_input = load_windows_service_runtime_input(&options.env_file)?;
    let backend_request = classify_windows_backend_request(&runtime_input.daemon_args)?;

    Ok(PreparedWindowsServiceHost {
        service_name: options.service_name.clone(),
        env_file: runtime_input.env_file,
        daemon_args: runtime_input.daemon_args,
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
                    "--backend in RUSTYNETD_DAEMON_ARGS_JSON requires a value".to_string()
                })?;
                if backend.is_some() {
                    return Err(
                        "RUSTYNETD_DAEMON_ARGS_JSON must not specify --backend more than once"
                            .to_string(),
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
        variables.insert(key.to_string(), value);
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
            return Err("mismatched quotes in Windows service env-file value".to_string());
        }
    }
    Ok(value.to_string())
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
    Err("--windows-service is only supported on Windows SCM hosts".to_string())
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
        let status_handle = service_control_handler::register(
            prepared.service_name.as_str(),
            move |control_event| match control_event {
                windows_service::service::ServiceControl::Interrogate => {
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
                controls_accepted: ServiceControlAccept::empty(),
                exit_code: ServiceExitCode::Win32(0),
                checkpoint: 0,
                wait_hint: Duration::default(),
                process_id: None,
            })
            .map_err(|err| format!("failed to report Windows service running status: {err}"))?;

        let result = (state.daemon_runner)(&prepared.daemon_args);
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

    #[test]
    fn strip_windows_service_args_returns_standard_args_when_mode_not_requested() {
        let args = vec![
            "daemon".to_string(),
            "--backend".to_string(),
            "linux-wireguard".to_string(),
        ];
        let (remaining, options) = strip_windows_service_args(&args).expect("args should parse");
        assert_eq!(remaining, args);
        assert!(options.is_none());
    }

    #[test]
    fn strip_windows_service_args_requires_env_file() {
        let err = strip_windows_service_args(&["--windows-service".to_string()])
            .expect_err("missing env-file should fail");
        assert!(err.contains("--windows-service requires --env-file"));
    }

    #[test]
    fn strip_windows_service_args_rejects_env_file_without_service_mode() {
        let err = strip_windows_service_args(&[
            "--env-file".to_string(),
            "/tmp/rustynetd.env".to_string(),
        ])
        .expect_err("env-file without service mode should fail");
        assert!(err.contains("--env-file requires --windows-service"));
    }

    #[test]
    fn select_host_entry_prefers_windows_service_mode() {
        let selection = select_host_entry(&[
            "--windows-service".to_string(),
            "--env-file".to_string(),
            "/tmp/rustynetd.env".to_string(),
        ])
        .expect("service mode should parse");
        assert_eq!(
            selection,
            HostEntrySelection::WindowsService(WindowsServiceOptions {
                service_name: "RustyNet".to_string(),
                env_file: PathBuf::from("/tmp/rustynetd.env"),
            })
        );
    }

    #[test]
    fn select_host_entry_rejects_inline_daemon_subcommands_for_windows_service() {
        let err = select_host_entry(&[
            "daemon".to_string(),
            "--windows-service".to_string(),
            "--env-file".to_string(),
            "/tmp/rustynetd.env".to_string(),
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
            vec!["--backend".to_string(), "windows-unsupported".to_string()]
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
            "--backend".to_string(),
            "linux-wireguard".to_string(),
        ])
        .expect("backend classification should parse");
        assert_eq!(
            request,
            WindowsBackendRequest::NonWindows("linux-wireguard".to_string())
        );
    }

    #[test]
    fn classify_windows_backend_request_accepts_explicit_unsupported_windows_label() {
        let request = classify_windows_backend_request(&[
            "--backend".to_string(),
            "windows-unsupported".to_string(),
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
            "--backend".to_string(),
            "windows-wireguard-nt".to_string(),
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
            classify_windows_backend_request(&["--node-id".to_string(), "node-a".to_string()])
                .expect("backend classification should parse");
        assert_eq!(request, WindowsBackendRequest::Missing);
    }

    #[test]
    fn prepare_windows_service_host_requires_absolute_env_file_path() {
        let err = prepare_windows_service_host(&WindowsServiceOptions {
            service_name: "RustyNet".to_string(),
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
}
