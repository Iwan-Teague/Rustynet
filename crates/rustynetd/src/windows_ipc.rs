use crate::windows_paths::{is_linux_runtime_root_text, validate_windows_runtime_file_path};
use rustynet_windows_native::{call_named_pipe, serve_named_pipe_one_message_authorized};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

pub const DEFAULT_WINDOWS_DAEMON_PIPE_PATH: &str = r"\\.\pipe\RustyNet\rustynetd";
pub const DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH: &str =
    r"\\.\pipe\RustyNet\rustynetd-privileged";
pub const WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION: u16 = 1;
const MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES: usize = 16 * 1024;
const WINDOWS_NAMED_PIPE_ACL_SCHEMA_VERSION: u8 = 1;
const FORBIDDEN_PIPE_SDDL_PRINCIPALS: &[&str] = &["WD", "AU", "BU", "NU", "AN"];

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
}

// Remote-client rejection is enforced by the server-side
// `PIPE_REJECT_REMOTE_CLIENTS` flag passed to `CreateNamedPipeW`
// inside `rustynet-windows-native::serve_named_pipe_one_message_authorized`.
// The Windows kernel refuses remote connections at handle creation, so
// no runtime allowlist flag is needed here. The dropped fields
// (`WindowsNamedPipeClientFacts::is_remote_client` and
// `WindowsNamedPipeSecurityPolicy::deny_remote_clients`) misled
// readers into believing there was a second runtime check; there
// never was, and adding one would duplicate the kernel-enforced
// rejection without strengthening it.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WindowsNamedPipeClientFacts {
    pub is_local_system: bool,
    pub is_builtin_administrator: bool,
    pub matches_service_identity: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsNamedPipeAclReport {
    pub schema_version: u8,
    pub overall_ok: bool,
    pub pipes: Vec<WindowsNamedPipeAclEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WindowsNamedPipeAclEntry {
    pub label: String,
    pub path: String,
    pub role: String,
    pub status: WindowsNamedPipeAclStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WindowsNamedPipeAclStatus {
    Ok { acl_sddl: String },
    Missing { reason: String },
    Drifted { reason: String, acl_sddl: String },
    Unobserved { reason: String },
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
        },
        WindowsLocalIpcRole::PrivilegedHelper => WindowsNamedPipeSecurityPolicy {
            allow_local_system: true,
            allow_builtin_administrators: true,
            allow_service_identity: true,
        },
    }
}

pub fn is_client_authorized(
    policy: &WindowsNamedPipeSecurityPolicy,
    facts: WindowsNamedPipeClientFacts,
) -> bool {
    // Remote-client rejection happens at handle creation via
    // `PIPE_REJECT_REMOTE_CLIENTS`. By the time a connected-client
    // facts struct exists, the connection is already local.
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
        aces.push("(A;;GA;;;SY)".to_owned());
    }
    if policy.allow_builtin_administrators {
        aces.push("(A;;GA;;;BA)".to_owned());
    }
    if policy.allow_service_identity
        && let Some(sid) = service_sid
    {
        aces.push(format!("(A;;GA;;;{sid})"));
    }
    format!("O:SYG:SYD:P{}", aces.join(""))
}

pub fn evaluate_named_pipe_security_sddl(
    label: &str,
    sddl: &str,
    expected_service_sid: Option<&str>,
) -> Result<(), String> {
    if sddl.trim().is_empty() {
        return Err(format!("{label} ACL SDDL is empty"));
    }
    if !sddl.contains("D:") {
        return Err(format!(
            "{label} ACL must expose a Windows DACL in SDDL form"
        ));
    }
    if !sddl.contains("D:P") {
        return Err(format!(
            "{label} ACL must use a protected DACL with inheritance disabled"
        ));
    }
    let owner = parse_sddl_field(sddl, "O:")
        .ok_or_else(|| format!("{label} ACL must expose an owner entry in SDDL form"))?;
    if owner != "SY" {
        return Err(format!(
            "{label} ACL owner must be LocalSystem; found {owner}"
        ));
    }
    let group = parse_sddl_field(sddl, "G:")
        .ok_or_else(|| format!("{label} ACL must expose a group entry in SDDL form"))?;
    if group != "SY" {
        return Err(format!(
            "{label} ACL group must be LocalSystem; found {group}"
        ));
    }
    let allow_principals = allow_ace_principals(sddl);
    if !allow_principals.contains(&"SY") {
        return Err(format!("{label} ACL must grant LocalSystem access"));
    }
    if !allow_principals.contains(&"BA") {
        return Err(format!(
            "{label} ACL must grant Builtin Administrators access"
        ));
    }
    if let Some(service_sid) = expected_service_sid
        && !allow_principals.contains(&service_sid)
    {
        return Err(format!(
            "{label} ACL must grant configured RustyNet service SID access"
        ));
    }
    for forbidden in FORBIDDEN_PIPE_SDDL_PRINCIPALS {
        if allow_principals
            .iter()
            .any(|principal| principal == forbidden)
        {
            return Err(format!(
                "{label} ACL grants a broader-than-reviewed Windows principal ({forbidden})"
            ));
        }
    }
    for principal in allow_principals {
        let allowed = principal == "SY"
            || principal == "BA"
            || expected_service_sid.is_some_and(|service_sid| principal == service_sid);
        if !allowed {
            return Err(format!(
                "{label} ACL grants unreviewed Windows principal ({principal})"
            ));
        }
    }
    Ok(())
}

pub fn collect_windows_named_pipe_acl_report(
    expected_service_sid: Option<&str>,
) -> WindowsNamedPipeAclReport {
    let specs = [
        (
            "daemon control pipe",
            DEFAULT_WINDOWS_DAEMON_PIPE_PATH,
            WindowsLocalIpcRole::DaemonControl,
        ),
        (
            "privileged helper pipe",
            DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH,
            WindowsLocalIpcRole::PrivilegedHelper,
        ),
    ];
    let pipes = specs
        .into_iter()
        .map(|(label, path, role)| {
            collect_named_pipe_acl_entry(label, path, role, expected_service_sid)
        })
        .collect::<Vec<_>>();
    let overall_ok = pipes
        .iter()
        .all(|entry| matches!(entry.status, WindowsNamedPipeAclStatus::Ok { .. }));
    WindowsNamedPipeAclReport {
        schema_version: WINDOWS_NAMED_PIPE_ACL_SCHEMA_VERSION,
        overall_ok,
        pipes,
    }
}

fn collect_named_pipe_acl_entry(
    label: &str,
    path: &str,
    role: WindowsLocalIpcRole,
    expected_service_sid: Option<&str>,
) -> WindowsNamedPipeAclEntry {
    let status = match validate_windows_pipe_path(Path::new(path), role) {
        Err(reason) => WindowsNamedPipeAclStatus::Drifted {
            reason,
            acl_sddl: String::new(),
        },
        Ok(()) => match rustynet_windows_native::inspect_named_pipe_sddl(path) {
            Ok(acl_sddl) => match evaluate_named_pipe_security_sddl(
                label,
                acl_sddl.as_str(),
                expected_service_sid,
            ) {
                Ok(()) => WindowsNamedPipeAclStatus::Ok { acl_sddl },
                Err(reason) => WindowsNamedPipeAclStatus::Drifted { reason, acl_sddl },
            },
            Err(reason) if named_pipe_missing_error(reason.as_str()) => {
                WindowsNamedPipeAclStatus::Missing { reason }
            }
            Err(reason) => WindowsNamedPipeAclStatus::Unobserved { reason },
        },
    };
    WindowsNamedPipeAclEntry {
        label: label.to_owned(),
        path: path.to_owned(),
        role: role.label().to_owned(),
        status,
    }
}

/// Detect the "named pipe does not exist" error shape that
/// `inspect_named_pipe_sddl` produces when the pipe handle has not
/// been created yet (typical at install time before the daemon has
/// started). Match the literal Windows error code with word
/// boundaries so a substring like "Windows error 2" does NOT also
/// match "Windows error 20" (ERROR_BAD_ENVIRONMENT) or "Windows
/// error 32" (ERROR_SHARING_VIOLATION).
fn named_pipe_missing_error(reason: &str) -> bool {
    // Tokenised match against the canonical "Windows error <code>"
    // shape that `rustynet_windows_native` errors use. The error
    // code is always the last token on its segment of the string,
    // so we scan whitespace-separated tokens once and only accept
    // an exact "2" alongside a literal "error" predecessor.
    let tokens: Vec<&str> = reason
        .split(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_')
        .filter(|t| !t.is_empty())
        .collect();
    for window in tokens.windows(2) {
        if window[0].eq_ignore_ascii_case("error") && window[1] == "2" {
            return true;
        }
    }
    // Symbolic form (in case a future error string includes the
    // Windows constant name directly) and the long-form English
    // text also count as "missing".
    reason.contains("ERROR_FILE_NOT_FOUND") || reason.contains("not found")
}

fn parse_sddl_field<'a>(sddl: &'a str, marker: &str) -> Option<&'a str> {
    let start = sddl.find(marker)? + marker.len();
    let tail = &sddl[start..];
    let end = ["O:", "G:", "D:", "S:"]
        .into_iter()
        .filter_map(|next_marker| tail.find(next_marker))
        .filter(|idx| *idx > 0)
        .min()
        .unwrap_or(tail.len());
    Some(&tail[..end])
}

fn allow_ace_principals(sddl: &str) -> Vec<&str> {
    let mut principals = Vec::new();
    for segment in sddl.split('(').skip(1) {
        let Some(ace) = segment.split(')').next() else {
            continue;
        };
        let fields = ace.split(';').collect::<Vec<_>>();
        if fields.len() >= 6 && fields[0] == "A" {
            principals.push(fields[5]);
        }
    }
    principals
}

pub fn validate_windows_privileged_request(
    request: &WindowsPrivilegedRequest,
) -> Result<(), String> {
    match request {
        WindowsPrivilegedRequest::Probe { protocol_version } => {
            if *protocol_version != WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION {
                return Err(format!(
                    "unsupported Windows privileged IPC protocol version {protocol_version}; expected {WINDOWS_PRIVILEGED_IPC_PROTOCOL_VERSION}",
                ));
            }
        }
        WindowsPrivilegedRequest::InspectRuntimePathAcl { path } => {
            if path.trim().is_empty() {
                return Err("inspect-runtime-path-acl path must not be empty".to_owned());
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
    serve_named_pipe_one_message_authorized(
        pipe_path.to_string_lossy().as_ref(),
        sddl.as_str(),
        MAX_WINDOWS_PRIVILEGED_MESSAGE_BYTES,
        service_sid,
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

/// Maximum bytes for a single daemon control pipe message.
/// Matches `MAX_COMMAND_BYTES` in `ipc.rs` so that the full command wire format always fits.
pub const MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES: usize = 4096;

/// Serve exactly one daemon control pipe connection.
///
/// The handler receives the raw request bytes (newline-terminated command wire format, e.g.
/// `b"status\n"`) and must return raw response bytes (newline-terminated response wire format,
/// e.g. `b"ok|...\n"`).
///
/// Path validation and SDDL construction are applied on every call so the server loop thread
/// can call this in a tight loop without holding external state between iterations.
pub fn serve_windows_daemon_control_request_once<F>(
    pipe_path: &Path,
    service_sid: Option<&str>,
    handler: F,
) -> Result<(), String>
where
    F: FnOnce(Vec<u8>) -> Result<Vec<u8>, String>,
{
    validate_windows_pipe_path(pipe_path, WindowsLocalIpcRole::DaemonControl)?;
    let sddl = build_named_pipe_security_sddl(WindowsLocalIpcRole::DaemonControl, service_sid);
    serve_named_pipe_one_message_authorized(
        pipe_path.to_string_lossy().as_ref(),
        sddl.as_str(),
        MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES,
        service_sid,
        handler,
    )
}

/// Send a daemon control command over the named pipe and return the raw response wire string.
///
/// `request_wire` is the IPC command in wire format (e.g. `"status"` or `"state refresh"`).
/// A trailing newline is appended automatically if absent.
/// The returned string is the response wire format (e.g. `"ok|..."` or `"err|..."`).
///
/// This is the low-level client call used by the CLI on Windows.
pub fn call_windows_daemon_control_raw(
    pipe_path: &Path,
    request_wire: &str,
    timeout: Duration,
) -> Result<String, String> {
    validate_windows_pipe_path(pipe_path, WindowsLocalIpcRole::DaemonControl)?;
    let mut request_bytes = request_wire.as_bytes().to_vec();
    if !request_bytes.ends_with(b"\n") {
        request_bytes.push(b'\n');
    }
    if request_bytes.len() > MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES {
        return Err(format!(
            "daemon control request exceeds maximum size ({} > {MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES} bytes)",
            request_bytes.len()
        ));
    }
    let response_bytes = call_named_pipe(
        pipe_path.to_string_lossy().as_ref(),
        &request_bytes,
        MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES,
        timeout,
    )?;
    String::from_utf8(response_bytes)
        .map_err(|err| format!("daemon control response is not valid UTF-8: {err}"))
}

pub fn windows_ipc_blocker_reason(role: WindowsLocalIpcRole) -> String {
    match role {
        WindowsLocalIpcRole::DaemonControl => {
            // Daemon control is now implemented via serve_windows_daemon_control_request_once /
            // call_windows_daemon_control_raw. This path is retained only as a fallback message
            // for callers that still reference the blocker API directly.
            "daemon control pipe is implemented on Windows; use serve_windows_daemon_control_request_once and call_windows_daemon_control_raw instead of this legacy blocker path".to_owned()
        }
        WindowsLocalIpcRole::PrivilegedHelper => "privileged helper shell-command execution remains blocked on Windows; use the reviewed named-pipe probe and ACL inspection request shapes only until a real Windows backend defines native privileged operations".to_owned(),
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
    fn default_security_policy_denies_unknown_clients() {
        // Note: remote-client rejection is enforced by the
        // PIPE_REJECT_REMOTE_CLIENTS server-side flag in
        // CreateNamedPipeW (see `rustynet-windows-native`), so the
        // policy struct itself only has to deny "client matches none
        // of the allow rules".
        let policy = default_security_policy(WindowsLocalIpcRole::PrivilegedHelper);
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
                path: r"C:\Temp\rustynetd.env".to_owned(),
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

    #[test]
    fn evaluate_named_pipe_security_sddl_accepts_canonical_acl() {
        evaluate_named_pipe_security_sddl(
            "daemon pipe",
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
            None,
        )
        .expect("canonical pipe ACL must validate");
    }

    #[test]
    fn evaluate_named_pipe_security_sddl_accepts_service_sid_acl() {
        evaluate_named_pipe_security_sddl(
            "daemon pipe",
            "O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-80-123)",
            Some("S-1-5-80-123"),
        )
        .expect("service SID pipe ACL must validate");
    }

    #[test]
    fn evaluate_named_pipe_security_sddl_rejects_broad_principals() {
        for principal in ["WD", "AU", "BU", "NU", "AN"] {
            let sddl = format!("O:SYG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;{principal})");
            let err = evaluate_named_pipe_security_sddl("daemon pipe", sddl.as_str(), None)
                .expect_err("broad principal must fail");
            assert!(err.contains("broader-than-reviewed"));
        }
    }

    #[test]
    fn evaluate_named_pipe_security_sddl_rejects_missing_protected_dacl() {
        let err = evaluate_named_pipe_security_sddl(
            "daemon pipe",
            "O:SYG:SYD:(A;;GA;;;SY)(A;;GA;;;BA)",
            None,
        )
        .expect_err("inherited DACL must fail");
        assert!(err.contains("protected DACL"));
    }

    #[test]
    fn evaluate_named_pipe_security_sddl_rejects_wrong_owner_or_missing_grants() {
        let wrong_owner = evaluate_named_pipe_security_sddl(
            "daemon pipe",
            "O:BAG:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)",
            None,
        )
        .expect_err("wrong owner must fail");
        assert!(wrong_owner.contains("owner must be LocalSystem"));

        let missing_admin =
            evaluate_named_pipe_security_sddl("daemon pipe", "O:SYG:SYD:P(A;;GA;;;SY)", None)
                .expect_err("missing BA must fail");
        assert!(missing_admin.contains("Builtin Administrators"));
    }

    #[test]
    fn max_windows_daemon_control_message_bytes_is_nonzero() {
        // Compile-time guard: the constant must be positive so pipe I/O is never attempted
        // with a zero-size buffer. The value is a compile-time constant so the runtime
        // assertion would always be true — use const { assert! } to catch regressions at
        // compile time instead.
        const _: () = assert!(
            MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES > 0,
            "max daemon control message size must be positive"
        );
    }

    #[test]
    fn call_windows_daemon_control_raw_rejects_invalid_pipe_path() {
        let err = call_windows_daemon_control_raw(
            Path::new("/run/rustynet/rustynetd.sock"),
            "status",
            std::time::Duration::from_secs(1),
        )
        .expect_err("linux path must be rejected before any I/O attempt");
        assert!(err.contains("must not use Linux runtime roots on Windows"));
    }

    #[test]
    fn call_windows_daemon_control_raw_rejects_oversized_request() {
        let huge = "x".repeat(MAX_WINDOWS_DAEMON_CONTROL_MESSAGE_BYTES + 1);
        let err = call_windows_daemon_control_raw(
            Path::new(DEFAULT_WINDOWS_DAEMON_PIPE_PATH),
            &huge,
            std::time::Duration::from_secs(1),
        )
        .expect_err("oversized request must be rejected before I/O");
        assert!(err.contains("exceeds maximum size"));
    }

    #[test]
    fn serve_windows_daemon_control_request_once_rejects_invalid_pipe_path() {
        let err = serve_windows_daemon_control_request_once(
            Path::new(r"\\.\pipe\RustyNet\other"),
            None,
            Ok,
        )
        .expect_err("unreviewed leaf must be rejected before I/O");
        assert!(err.contains("must pin the reviewed pipe leaf"));
    }

    #[test]
    fn daemon_control_blocker_reason_reflects_implementation_status() {
        let reason = super::windows_ipc_blocker_reason(WindowsLocalIpcRole::DaemonControl);
        // The message must acknowledge that the pipe IS now implemented.
        assert!(
            reason.contains("implemented"),
            "blocker reason should acknowledge implemented status: {reason}"
        );
    }

    #[test]
    fn canonical_pipe_paths_pin_rustynet_namespace() {
        // M2 — pin the canonical pipe path constants so the doc
        // and the code can never drift again without test failure.
        // Phase 26 reviewer caught a drift where docs said
        // `\\.\pipe\rustynet` but code used `\\.\pipe\RustyNet\rustynetd`;
        // the code path is the correct security-hardened form
        // (namespaced sub-pipe), so the doc has been updated to match.
        assert_eq!(
            DEFAULT_WINDOWS_DAEMON_PIPE_PATH,
            r"\\.\pipe\RustyNet\rustynetd"
        );
        assert_eq!(
            DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH,
            r"\\.\pipe\RustyNet\rustynetd-privileged"
        );
    }

    #[test]
    fn named_pipe_missing_error_matches_only_error_code_two() {
        // Positive cases: real Win32 errors from
        // `rustynet-windows-native::inspect_named_pipe_sddl` use the
        // shape "...failed with Windows error N".
        assert!(super::named_pipe_missing_error(
            "GetNamedSecurityInfoW failed for named pipe \\\\.\\pipe\\rustynetd with Windows error 2"
        ));
        assert!(super::named_pipe_missing_error("ERROR_FILE_NOT_FOUND"));
        assert!(super::named_pipe_missing_error("pipe handle not found"));

        // Negative cases: substring "Windows error 2" used to match
        // any 2-prefixed code. These MUST now be rejected.
        assert!(!super::named_pipe_missing_error(
            "GetNamedSecurityInfoW failed with Windows error 20"
        ));
        assert!(!super::named_pipe_missing_error(
            "GetNamedSecurityInfoW failed with Windows error 32"
        ));
        assert!(!super::named_pipe_missing_error(
            "GetNamedSecurityInfoW failed with Windows error 234"
        ));
        assert!(!super::named_pipe_missing_error(
            "GetNamedSecurityInfoW failed with Windows error 1234"
        ));
    }
}
