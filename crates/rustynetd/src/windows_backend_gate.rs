#![forbid(unsafe_code)]

pub const WINDOWS_UNSUPPORTED_BACKEND_LABEL: &str = "windows-unsupported";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsBackendMode {
    Unsupported,
}

pub fn parse_windows_backend_mode(value: &str) -> Result<WindowsBackendMode, String> {
    match value {
        WINDOWS_UNSUPPORTED_BACKEND_LABEL => Ok(WindowsBackendMode::Unsupported),
        _ => Err(format!(
            "invalid Windows backend value: expected {WINDOWS_UNSUPPORTED_BACKEND_LABEL}"
        )),
    }
}

pub fn require_supported_windows_backend(mode: WindowsBackendMode) -> Result<(), String> {
    match mode {
        WindowsBackendMode::Unsupported => Err(
            "windows-runtime-backend-explicitly-unsupported: Windows service/config host is present, but this build does not yet provide a reviewed Windows dataplane/backend. The only reviewed Windows backend label on the current branch is 'windows-unsupported', and it exists only to keep backend truth explicit and fail closed."
                .to_string(),
        ),
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
    fn parse_windows_backend_mode_rejects_unknown_windows_backend_label() {
        let err = parse_windows_backend_mode("windows-wireguard-nt")
            .expect_err("unknown Windows backend label should fail");
        assert!(err.contains(WINDOWS_UNSUPPORTED_BACKEND_LABEL));
    }

    #[test]
    fn require_supported_windows_backend_fails_closed_for_unsupported_mode() {
        let err = require_supported_windows_backend(WindowsBackendMode::Unsupported)
            .expect_err("unsupported Windows backend must fail closed");
        assert!(err.contains("windows-runtime-backend-explicitly-unsupported"));
    }
}
