use std::path::Path;

pub const DEFAULT_WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
pub const DEFAULT_WINDOWS_STATE_ROOT: &str = r"C:\ProgramData\RustyNet";
pub const DEFAULT_WINDOWS_STATE_PATH: &str = r"C:\ProgramData\RustyNet\rustynetd.state";
pub const DEFAULT_WINDOWS_TRUST_EVIDENCE_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.trust";
pub const DEFAULT_WINDOWS_TRUST_VERIFIER_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\trust-evidence.pub";
pub const DEFAULT_WINDOWS_TRUST_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.trust.watermark";
pub const DEFAULT_WINDOWS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.snapshot";
pub const DEFAULT_WINDOWS_MEMBERSHIP_LOG_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.log";
pub const DEFAULT_WINDOWS_MEMBERSHIP_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.watermark";
pub const DEFAULT_WINDOWS_MEMBERSHIP_OWNER_SIGNING_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\membership\membership.owner.key";
pub const DEFAULT_WINDOWS_AUTO_TUNNEL_BUNDLE_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.assignment";
pub const DEFAULT_WINDOWS_AUTO_TUNNEL_VERIFIER_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\assignment.pub";
pub const DEFAULT_WINDOWS_AUTO_TUNNEL_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.assignment.watermark";
pub const DEFAULT_WINDOWS_TRAVERSAL_BUNDLE_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.traversal";
pub const DEFAULT_WINDOWS_TRAVERSAL_VERIFIER_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\traversal.pub";
pub const DEFAULT_WINDOWS_TRAVERSAL_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.traversal.watermark";
pub const DEFAULT_WINDOWS_DNS_ZONE_BUNDLE_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.dns-zone";
pub const DEFAULT_WINDOWS_DNS_ZONE_VERIFIER_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\dns-zone.pub";
pub const DEFAULT_WINDOWS_DNS_ZONE_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.dns-zone.watermark";
pub const DEFAULT_WINDOWS_WG_RUNTIME_PRIVATE_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\keys\wireguard.key";
pub const DEFAULT_WINDOWS_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str =
    r"C:\ProgramData\RustyNet\keys\wireguard.key.enc";
pub const DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH: &str =
    r"C:\ProgramData\RustyNet\keys\wireguard.passphrase";
pub const DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH: &str = r"C:\ProgramData\RustyNet\keys\wireguard.pub";

const LINUX_RUNTIME_ROOTS: [&str; 4] = [
    "/run/rustynet",
    "/var/lib/rustynet",
    "/etc/rustynet",
    "/var/log/rustynet",
];

pub fn validate_windows_runtime_file_path(path: &Path, label: &str) -> Result<(), String> {
    let text = path.to_string_lossy();
    let normalized = text.replace('/', "\\");
    if normalized.is_empty() {
        return Err(format!("{label} path must not be empty"));
    }
    if is_linux_runtime_root_text(text.as_ref()) {
        return Err(format!(
            "{label} must not use Linux runtime roots on Windows: {}",
            path.display()
        ));
    }
    if normalized.starts_with(r"\\.\pipe\") {
        return Err(format!(
            "{label} must use a filesystem path, not a Windows named pipe: {}",
            path.display()
        ));
    }
    if !looks_like_windows_absolute_path(&normalized) {
        return Err(format!(
            "{label} must use an absolute Windows path: {}",
            path.display()
        ));
    }
    Ok(())
}

pub fn is_linux_runtime_root_text(text: &str) -> bool {
    LINUX_RUNTIME_ROOTS
        .iter()
        .any(|prefix| text == *prefix || text.starts_with(&format!("{prefix}/")))
}

fn looks_like_windows_absolute_path(text: &str) -> bool {
    if text.starts_with(r"\\?\") {
        return true;
    }
    let bytes = text.as_bytes();
    bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn validate_windows_runtime_file_path_accepts_program_data_paths() {
        let result =
            validate_windows_runtime_file_path(Path::new(DEFAULT_WINDOWS_STATE_PATH), "state path");
        assert!(
            result.is_ok(),
            "program data path should validate: {result:?}"
        );
    }

    #[test]
    fn validate_windows_runtime_file_path_rejects_linux_runtime_roots() {
        let err = validate_windows_runtime_file_path(
            Path::new("/var/lib/rustynet/rustynetd.state"),
            "state path",
        )
        .expect_err("linux root should fail");
        assert!(err.contains("must not use Linux runtime roots on Windows"));
    }

    #[test]
    fn validate_windows_runtime_file_path_rejects_named_pipe_paths() {
        let err = validate_windows_runtime_file_path(
            Path::new(r"\\.\pipe\RustyNet\rustynetd"),
            "state path",
        )
        .expect_err("named pipe should fail for file path");
        assert!(err.contains("must use a filesystem path"));
    }
}
