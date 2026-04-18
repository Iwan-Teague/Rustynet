use crate::windows_paths::{is_linux_runtime_root_text, validate_windows_runtime_file_path};
use rustynet_windows_native::{call_named_pipe, serve_named_pipe_one_message};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_WINDOWS_DAEMON_PIPE_PATH: &str = r"\\.\pipe\RustyNet\rustynetd";
pub const DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH: &str =
    r"\\.\pipe\RustyNet\rustynetd-privileged";
pub const WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION: u16 = 1;
const MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsLocalIpcRole {
    DaemonControl,
    PrivilegedHelper,
}

impl WindowsLocalIpcRole {
    fn label(self) -> &'static str {
        match self {
            Self::DaemonControl => "daemon control pipe",
            Self::PrivilegedHelper => "privileged helper pipe",
        }
    }

    fn pipe_leaf(self) -> &'static str {
        match self {
            Self::DaemonControl => "rustynetd",
            Self::PrivilegedHelper => "rustynetd-privileged",
        }
    }

    fn reviewed_self_check_leaf_prefix(self) -> String {
        format!("{}.check-", self.pipe_leaf())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowsNamedPipeSecurityPolicy {
    pub allow_local_system: bool,
    pub allow_builtin_administrators: bool,
    pub allow_service_identity: bool,
    pub deny_remote_clients: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowsNamedPipeClientFacts {
    pub is_local_system: bool,
    pub is_builtin_administrator: bool,
    pub matches_service_identity: bool,
    pub is_remote_client: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WindowsPrivilegedRequest {
    Probe { protocol_version: u16 },
    InspectRuntimePathAcl { path: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum WindowsPrivilegedResponse {
    ProbeAck { protocol_version: u16 },
    RuntimePathAcl { path: String, sddl: String },
}

pub fn default_security_policy(role: WindowsLocalIpcRole) -> WindowsNamedPipeSecurityPolicy {
    match role {
        WindowsLocalIpcRole::DaemonControl => WindowsNamedPipeSecurityPolicy {
            allow_local_system: true,
            allow_builtin_administrators: true,
            allow_service_identity: true,
            deny_remote_clients: true,
        },
        WindowsLocalIpcRole::PrivilegedHelper => WindowsNamedPipeSecurityPolicy {
            allow_local_system: true,
            allow_builtin_administrators: true,
            allow_service_identity: true,
            deny_remote_clients: true,
        },
    }
}

pub fn is_client_authorized(
    policy: &WindowsNamedPipeSecurityPolicy,
    facts: WindowsNamedPipeClientFacts,
) -> bool {
    if policy.deny_remote_clients && facts.is_remote_client {
        return false;
    }
    if policy.allow_service_identity && facts.matches_service_identity {
        return true;
    }
    if policy.allow_local_system && facts.is_local_system {
        return true;
    }
    if policy.allow_builtin_administrators && facts.is_builtin_administrator {
        return true;
    }
    false
}

pub fn validate_windows_pipe_path(path: &Path, role: WindowsLocalIpcRole) -> Result<(), String> {
    let text = path.to_string_lossy();
    if text.is_empty() {
        return Err(format!("{} path must not be empty", role.label()));
    }
    if is_linux_runtime_root_text(text.as_ref()) {
        return Err(format!(
            "{} must not use Linux runtime roots on Windows: {}",
            role.label(),
            path.display()
        ));
    }
    if text.starts_with(r"\\") && !text.starts_with(r"\\.\pipe\") {
        return Err(format!(
            "{} must not use a remote UNC path: {}",
            role.label(),
            path.display()
        ));
    }
    if !text.starts_with(r"\\.\pipe\") {
        return Err(format!(
            "{} must use a local Windows named pipe path under \\\\.\\pipe\\: {}",
            role.label(),
            path.display()
        ));
    }
    let suffix = &text[r"\\.\pipe\".len()..];
    if !suffix.starts_with("RustyNet\\") {
        return Err(format!(
            "{} must stay under the RustyNet named-pipe namespace: {}",
            role.label(),
            path.display()
        ));
    }
    if suffix.ends_with('\\') {
        return Err(format!(
            "{} must include a concrete pipe leaf name: {}",
            role.label(),
            path.display()
        ));
    }
    if !suffix
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '\\' | '-' | '_' | '.'))
    {
        return Err(format!(
            "{} contains invalid characters; allowed characters are [A-Za-z0-9._-\\\\]: {}",
            role.label(),
            path.display()
        ));
    }
    let expected_leaf = role.pipe_leaf().to_ascii_lowercase();
    let expected_self_check_prefix = role.reviewed_self_check_leaf_prefix().to_ascii_lowercase();
    let lowered_suffix = suffix.to_ascii_lowercase();
    let is_reviewed_leaf = lowered_suffix == format!("rustynet\\{expected_leaf}")
        || lowered_suffix == format!("rustynet\\{expected_self_check_prefix}");
    let is_reviewed_self_check =
        lowered_suffix.starts_with(&format!("rustynet\\{expected_self_check_prefix}"));
    if !is_reviewed_leaf && !is_reviewed_self_check {
        return Err(format!(
            "{} must pin the reviewed pipe leaf '{}' or a reviewed self-check leaf: {}",
            role.label(),
            role.pipe_leaf(),
            path.display()
        ));
    }
    Ok(())
}

pub fn build_named_pipe_security_sddl(
    role: WindowsLocalIpcRole,
    service_sid: Option<&str>,
) -> String {
    let policy = default_security_policy(role);
    let mut aces = Vec::new();
    if policy.allow_local_system {
        aces.push("(A;;GA;;;SY)".to_string());
    }
    if policy.allow_builtin_administrators {
        aces.push("(A;;GA;;;BA)".to_string());
    }
    if policy.allow_service_identity {
        if let Some(sid) = service_sid {
            aces.push(format!("(A;;GA;;;{sid})"));
        }
    }
    format!("O:SYG:SYD:P{}", aces.join(""))
}

pub fn validate_windows_privileged_request(
    request: &WindowsPrivilegedRequest,
) -> Result<(), String> {
    match request {
        WindowsPrivilegedRequest::Probe { protocol_version } => {
            if *protocol_version != WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION {
                return Err(format!(
                    "unsupported Windows privileged IPC protocol version {}; expected {}",
                    protocol_version, WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION
                ));
            }
        }
        WindowsPrivilegedRequest::InspectRuntimePathAcl { path } => {
            if path.trim().is_empty() {
                return Err("inspect-runtime-path-acl path must not be empty".to_string());
            }
            validate_windows_runtime_file_path(Path::new(path), "inspect-runtime-path-acl path")?;
        }
    }
    Ok(())
}

pub fn encode_windows_privileged_request(
    request: &WindowsPrivilegedRequest,
) -> Result<Vec<u8>, String> {
    validate_windows_privileged_request(request)?;
    let bytes =
        serde_json::to_vec(request).map_err(|err| format!("request encode failed: {err}"))?;
    if bytes.is_empty() || bytes.len() > MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES {
        return Err(format!(
            "request payload must be between 1 and {MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

pub fn decode_windows_privileged_request(bytes: &[u8]) -> Result<WindowsPrivilegedRequest, String> {
    if bytes.is_empty() || bytes.len() > MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES {
        return Err(format!(
            "request payload must be between 1 and {MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES} bytes"
        ));
    }
    let request: WindowsPrivilegedRequest =
        serde_json::from_slice(bytes).map_err(|err| format!("request decode failed: {err}"))?;
    validate_windows_privileged_request(&request)?;
    Ok(request)
}

pub fn encode_windows_privileged_response(
    response: &WindowsPrivilegedResponse,
) -> Result<Vec<u8>, String> {
    let bytes =
        serde_json::to_vec(response).map_err(|err| format!("response encode failed: {err}"))?;
    if bytes.is_empty() || bytes.len() > MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES {
        return Err(format!(
            "response payload must be between 1 and {MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES} bytes"
        ));
    }
    Ok(bytes)
}

pub fn decode_windows_privileged_response(
    bytes: &[u8],
) -> Result<WindowsPrivilegedResponse, String> {
    if bytes.is_empty() || bytes.len() > MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES {
        return Err(format!(
            "response payload must be between 1 and {MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES} bytes"
        ));
    }
    serde_json::from_slice(bytes).map_err(|err| format!("response decode failed: {err}"))
}

pub fn serve_windows_privileged_request_once<F>(
    pipe_path: &Path,
    role: WindowsLocalIpcRole,
    service_sid: Option<&str>,
    handler: F,
) -> Result<(), String>
where
    F: FnOnce(WindowsPrivilegedRequest) -> Result<WindowsPrivilegedResponse, String>,
{
    validate_windows_pipe_path(pipe_path, role)?;
    let sddl = build_named_pipe_security_sddl(role, service_sid);
    serve_named_pipe_one_message(
        pipe_path.to_string_lossy().as_ref(),
        sddl.as_str(),
        MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES,
        |bytes| {
            let request = decode_windows_privileged_request(&bytes)?;
            let response = handler(request)?;
            encode_windows_privileged_response(&response)
        },
    )
}

pub fn call_windows_privileged_request(
    pipe_path: &Path,
    role: WindowsLocalIpcRole,
    request: &WindowsPrivilegedRequest,
    timeout: Duration,
) -> Result<WindowsPrivilegedResponse, String> {
    validate_windows_pipe_path(pipe_path, role)?;
    let request_bytes = encode_windows_privileged_request(request)?;
    let response_bytes = call_named_pipe(
        pipe_path.to_string_lossy().as_ref(),
        request_bytes.as_slice(),
        MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES,
        timeout,
    )?;
    decode_windows_privileged_response(&response_bytes)
}

pub fn windows_ipc_probe(
    pipe_path: &Path,
    role: WindowsLocalIpcRole,
    timeout: Duration,
) -> Result<(), String> {
    let response = call_windows_privileged_request(
        pipe_path,
        role,
        &WindowsPrivilegedRequest::Probe {
            protocol_version: WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION,
        },
        timeout,
    )?;
    match response {
        WindowsPrivilegedResponse::ProbeAck { protocol_version }
            if protocol_version == WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION =>
        {
            Ok(())
        }
        other => Err(format!(
            "unexpected Windows privileged probe response over {}: {other:?}",
            pipe_path.display()
        )),
    }
}

pub fn windows_ipc_blocker_reason(role: WindowsLocalIpcRole) -> String {
    match role {
        WindowsLocalIpcRole::DaemonControl => "daemon control pipe remains unimplemented on Windows; windows-wireguard-nt now provides an opt-in reviewed backend label, but local daemon-control IPC still stays fail-closed until a reviewed named-pipe control server exists".to_string(),
        WindowsLocalIpcRole::PrivilegedHelper => "privileged helper shell-command execution remains blocked on Windows; use the reviewed named-pipe probe and ACL inspection request shapes only until a real Windows backend defines native privileged operations".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn validate_windows_pipe_path_accepts_rustynet_named_pipe_namespace() {
        let result = validate_windows_pipe_path(
            Path::new(DEFAULT_WINDOWS_DAEMON_PIPE_PATH),
            WindowsLocalIpcRole::DaemonControl,
        );
        assert!(
            result.is_ok(),
            "rustynet named pipe path should validate: {result:?}"
        );
    }

    #[test]
    fn validate_windows_pipe_path_rejects_linux_runtime_roots() {
        let err = validate_windows_pipe_path(
            Path::new("/run/rustynet/rustynetd.sock"),
            WindowsLocalIpcRole::DaemonControl,
        )
        .expect_err("linux root must fail");
        assert!(err.contains("must not use Linux runtime roots on Windows"));
    }

    #[test]
    fn validate_windows_pipe_path_rejects_remote_unc_paths() {
        let err = validate_windows_pipe_path(
            Path::new(r"\\server\pipe\rustynetd"),
            WindowsLocalIpcRole::PrivilegedHelper,
        )
        .expect_err("remote UNC must fail");
        assert!(err.contains("must not use a remote UNC path"));
    }

    #[test]
    fn validate_windows_pipe_path_rejects_unreviewed_leaf_name() {
        let err = validate_windows_pipe_path(
            Path::new(r"\\.\pipe\RustyNet\other"),
            WindowsLocalIpcRole::PrivilegedHelper,
        )
        .expect_err("unexpected pipe leaf should fail");
        assert!(err.contains("must pin the reviewed pipe leaf"));
    }

    #[test]
    fn validate_windows_pipe_path_accepts_reviewed_self_check_leaf_name() {
        let result = validate_windows_pipe_path(
            Path::new(r"\\.\pipe\RustyNet\rustynetd-privileged.check-1234"),
            WindowsLocalIpcRole::PrivilegedHelper,
        );
        assert!(
            result.is_ok(),
            "reviewed self-check leaf should validate: {result:?}"
        );
    }

    #[test]
    fn default_security_policy_denies_remote_and_unknown_clients() {
        let policy = default_security_policy(WindowsLocalIpcRole::PrivilegedHelper);
        assert!(!is_client_authorized(
            &policy,
            WindowsNamedPipeClientFacts {
                is_remote_client: true,
                ..WindowsNamedPipeClientFacts::default()
            },
        ));
        assert!(!is_client_authorized(
            &policy,
            WindowsNamedPipeClientFacts::default(),
        ));
    }

    #[test]
    fn default_security_policy_allows_service_identity() {
        let policy = default_security_policy(WindowsLocalIpcRole::DaemonControl);
        assert!(is_client_authorized(
            &policy,
            WindowsNamedPipeClientFacts {
                matches_service_identity: true,
                ..WindowsNamedPipeClientFacts::default()
            },
        ));
    }

    #[test]
    fn encode_decode_windows_probe_request_round_trips() {
        let request = WindowsPrivilegedRequest::Probe {
            protocol_version: WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION,
        };
        let bytes = encode_windows_privileged_request(&request).expect("encode should succeed");
        let decoded = decode_windows_privileged_request(&bytes).expect("decode should succeed");
        assert_eq!(decoded, request);
    }

    #[test]
    fn inspect_runtime_path_request_rejects_non_reviewed_roots() {
        let err =
            validate_windows_privileged_request(&WindowsPrivilegedRequest::InspectRuntimePathAcl {
                path: r"C:\Temp\rustynetd.env".to_string(),
            })
            .expect_err("unreviewed runtime path should fail");
        assert!(err.contains("reviewed RustyNet Windows runtime roots"));
    }

    #[test]
    fn build_named_pipe_security_sddl_includes_required_well_known_sids() {
        let sddl = build_named_pipe_security_sddl(WindowsLocalIpcRole::PrivilegedHelper, None);
        assert!(sddl.contains("(A;;GA;;;SY)"));
        assert!(sddl.contains("(A;;GA;;;BA)"));
        assert!(sddl.starts_with("O:SYG:SYD:P"));
    }
}
