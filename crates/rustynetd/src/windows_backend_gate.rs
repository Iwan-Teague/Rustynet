#![forbid(unsafe_code)]

pub const WINDOWS_UNSUPPORTED_BACKEND_LABEL: &str = "windows-unsupported";
pub const WINDOWS_WIREGUARD_NT_BACKEND_LABEL: &str = "windows-wireguard-nt";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsBackendMode {
    Unsupported,
    WireguardNt,
}

pub fn parse_windows_backend_mode(value: &str) -> Result<WindowsBackendMode, String> {
    match value {
        WINDOWS_UNSUPPORTED_BACKEND_LABEL => Ok(WindowsBackendMode::Unsupported),
        WINDOWS_WIREGUARD_NT_BACKEND_LABEL => Ok(WindowsBackendMode::WireguardNt),
        _ => Err(format!(
            "invalid Windows backend value: expected {WINDOWS_UNSUPPORTED_BACKEND_LABEL} or {WINDOWS_WIREGUARD_NT_BACKEND_LABEL}"
        )),
    }
}

pub fn require_supported_windows_backend(mode: WindowsBackendMode) -> Result<(), String> {
    match mode {
        WindowsBackendMode::Unsupported => Err(
            "windows-runtime-backend-explicitly-unsupported: Windows service/config host is present, but this build does not yet provide an enabled reviewed Windows dataplane/backend for the selected label. 'windows-unsupported' remains the explicit fail-closed backend label and must keep blocking until an operator deliberately selects a reviewed backend."
                .to_string(),
        ),
        WindowsBackendMode::WireguardNt => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_windows_backend_mode_accepts_explicit_unsupported_label() {
        let mode = parse_windows_backend_mode(WINDOWS_UNSUPPORTED_BACKEND_LABEL)
            .expect("explicit unsupported Windows backend should parse");
        assert_eq!(mode, WindowsBackendMode::Unsupported);
    }

    #[test]
    fn parse_windows_backend_mode_accepts_wireguard_nt_label() {
        let mode = parse_windows_backend_mode(WINDOWS_WIREGUARD_NT_BACKEND_LABEL)
            .expect("reviewed Windows backend should parse");
        assert_eq!(mode, WindowsBackendMode::WireguardNt);
    }

    #[test]
    fn parse_windows_backend_mode_rejects_unknown_windows_backend_label() {
        let err = parse_windows_backend_mode("windows-wireguard-nt-typo")
            .expect_err("unknown Windows backend label should fail");
        assert!(err.contains(WINDOWS_UNSUPPORTED_BACKEND_LABEL));
        assert!(err.contains(WINDOWS_WIREGUARD_NT_BACKEND_LABEL));
    }

    #[test]
    fn require_supported_windows_backend_fails_closed_for_unsupported_mode() {
        let err = require_supported_windows_backend(WindowsBackendMode::Unsupported)
            .expect_err("unsupported Windows backend must fail closed");
        assert!(err.contains("windows-runtime-backend-explicitly-unsupported"));
    }

    #[test]
    fn require_supported_windows_backend_accepts_wireguard_nt_mode() {
        require_supported_windows_backend(WindowsBackendMode::WireguardNt)
            .expect("reviewed Windows backend should pass the support gate");
    }
}
