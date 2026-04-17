use crate::windows_paths::is_linux_runtime_root_text;
use std::path::Path;

pub const DEFAULT_WINDOWS_DAEMON_PIPE_PATH: &str = r"\\.\pipe\RustyNet\rustynetd";
pub const DEFAULT_WINDOWS_PRIVILEGED_HELPER_PIPE_PATH: &str =
    r"\\.\pipe\RustyNet\rustynetd-privileged";

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

pub fn default_security_policy(_role: WindowsLocalIpcRole) -> WindowsNamedPipeSecurityPolicy {
    WindowsNamedPipeSecurityPolicy {
        allow_local_system: true,
        allow_builtin_administrators: true,
        allow_service_identity: true,
        deny_remote_clients: true,
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
    if text.starts_with(r"\\") && !text.starts_with(r"\\.\pipe\") && !text.starts_with(r"\\?\") {
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
    Ok(())
}

pub fn windows_ipc_blocker_reason(role: WindowsLocalIpcRole) -> String {
    format!(
        "{} is not yet implemented with reviewed Windows named-pipe creation and ACL enforcement; refusing to fall back to Unix sockets on Windows",
        role.label()
    )
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
}
