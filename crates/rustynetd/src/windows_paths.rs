use rustynet_windows_native::inspect_file_sddl;
use std::path::{Path, PathBuf};

pub const DEFAULT_WINDOWS_INSTALL_ROOT: &str = r"C:\Program Files\RustyNet";
pub const DEFAULT_WINDOWS_STATE_ROOT: &str = r"C:\ProgramData\RustyNet";
pub const DEFAULT_WINDOWS_CONFIG_ROOT: &str = r"C:\ProgramData\RustyNet\config";
pub const DEFAULT_WINDOWS_LOG_ROOT: &str = r"C:\ProgramData\RustyNet\logs";
pub const DEFAULT_WINDOWS_TRUST_ROOT: &str = r"C:\ProgramData\RustyNet\trust";
pub const DEFAULT_WINDOWS_MEMBERSHIP_ROOT: &str = r"C:\ProgramData\RustyNet\membership";
pub const DEFAULT_WINDOWS_KEYS_ROOT: &str = r"C:\ProgramData\RustyNet\keys";
pub const DEFAULT_WINDOWS_SECRET_ROOT: &str = r"C:\ProgramData\RustyNet\secrets";
pub const DEFAULT_WINDOWS_KEY_CUSTODY_ROOT: &str = r"C:\ProgramData\RustyNet\secrets\key-custody";
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
    r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi";
pub const DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH: &str = r"C:\ProgramData\RustyNet\keys\wireguard.pub";

const LINUX_RUNTIME_ROOTS: [&str; 4] = [
    "/run/rustynet",
    "/var/lib/rustynet",
    "/etc/rustynet",
    "/var/log/rustynet",
];

const FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS: [&str; 3] = ["WD", "AU", "BU"];

pub fn validate_windows_runtime_file_path(path: &Path, label: &str) -> Result<(), String> {
    let normalized = normalize_windows_path(path, label)?;
    if !is_reviewed_runtime_path(normalized.as_str()) {
        return Err(format!(
            "{label} must stay under reviewed RustyNet Windows runtime roots: {}",
            path.display()
        ));
    }
    Ok(())
}

pub fn default_windows_tunnel_service_config_path(interface_name: &str) -> PathBuf {
    PathBuf::from(DEFAULT_WINDOWS_CONFIG_ROOT).join(format!("{interface_name}.conf.dpapi"))
}

pub fn validate_windows_local_secret_input_path(path: &Path, label: &str) -> Result<(), String> {
    let _ = normalize_windows_path(path, label)?;
    Ok(())
}

pub fn validate_windows_secret_blob_path(path: &Path, label: &str) -> Result<(), String> {
    validate_windows_runtime_file_path(path, label)?;
    let normalized = path.to_string_lossy().replace('/', "\\");
    let lowered = normalized.to_ascii_lowercase();
    if !lowered.starts_with(&format!(
        "{}\\",
        DEFAULT_WINDOWS_SECRET_ROOT.to_ascii_lowercase()
    )) {
        return Err(format!(
            "{label} must stay under the reviewed Windows secret root {}: {}",
            DEFAULT_WINDOWS_SECRET_ROOT,
            path.display()
        ));
    }
    if !lowered.ends_with(".dpapi") {
        return Err(format!(
            "{label} must use the reviewed DPAPI blob extension '.dpapi': {}",
            path.display()
        ));
    }
    Ok(())
}

pub fn validate_windows_runtime_acl(path: &Path, label: &str) -> Result<(), String> {
    let sddl = inspect_file_sddl(path)
        .map_err(|err| format!("{label} ACL inspection failed ({}): {err}", path.display()))?;
    validate_windows_sddl_has_protected_dacl(path, label, sddl.as_str())?;
    if !sddl_contains_principal(sddl.as_str(), "SY") {
        return Err(format!(
            "{label} ACL must grant LocalSystem access: {}",
            path.display()
        ));
    }
    if !sddl_contains_principal(sddl.as_str(), "BA") {
        return Err(format!(
            "{label} ACL must grant Builtin Administrators access: {}",
            path.display()
        ));
    }
    let owner = extract_sddl_owner(sddl.as_str()).ok_or_else(|| {
        format!(
            "{label} ACL must expose an owner entry in SDDL form: {}",
            path.display()
        )
    })?;
    if !matches!(owner, "SY" | "BA") && !owner.starts_with("S-1-5-80-") {
        return Err(format!(
            "{label} ACL owner must be LocalSystem, Builtin Administrators, or a service SID; found {owner} for {}",
            path.display()
        ));
    }
    Ok(())
}

pub fn validate_windows_local_secret_acl(path: &Path, label: &str) -> Result<(), String> {
    let sddl = inspect_file_sddl(path)
        .map_err(|err| format!("{label} ACL inspection failed ({}): {err}", path.display()))?;
    validate_windows_sddl_has_protected_dacl(path, label, sddl.as_str())?;
    if extract_sddl_owner(sddl.as_str()).is_none() {
        return Err(format!(
            "{label} ACL must expose an owner entry in SDDL form: {}",
            path.display()
        ));
    }
    Ok(())
}

fn validate_windows_sddl_has_protected_dacl(
    path: &Path,
    label: &str,
    sddl: &str,
) -> Result<(), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|err| format!("{label} metadata read failed ({}): {err}", path.display()))?;
    if !sddl.contains("D:") {
        return Err(format!(
            "{label} must expose a Windows DACL in SDDL form: {}",
            path.display()
        ));
    }
    if metadata.is_dir() && !sddl.contains("D:P") {
        return Err(format!(
            "{label} must use a protected DACL with inheritance disabled: {}",
            path.display()
        ));
    }
    for principal in FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS {
        if sddl_contains_principal(sddl, principal) {
            return Err(format!(
                "{label} ACL grants a broader-than-reviewed Windows principal ({principal}): {}",
                path.display()
            ));
        }
    }
    Ok(())
}

pub fn is_linux_runtime_root_text(text: &str) -> bool {
    LINUX_RUNTIME_ROOTS
        .iter()
        .any(|prefix| text == *prefix || text.starts_with(&format!("{prefix}/")))
}

fn normalize_windows_path(path: &Path, label: &str) -> Result<String, String> {
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
    if normalized.starts_with(r"\\") {
        return Err(format!(
            "{label} must not use a remote or UNC filesystem path on Windows: {}",
            path.display()
        ));
    }
    if !looks_like_windows_absolute_path(normalized.as_str()) {
        return Err(format!(
            "{label} must use an absolute Windows path: {}",
            path.display()
        ));
    }
    if normalized
        .split('\\')
        .skip(1)
        .any(|segment| segment == ".." || segment == ".")
    {
        return Err(format!(
            "{label} must not contain parent-directory traversal on Windows: {}",
            path.display()
        ));
    }
    Ok(normalized)
}

fn looks_like_windows_absolute_path(text: &str) -> bool {
    let candidate = text.strip_prefix(r"\\?\").unwrap_or(text);
    let bytes = candidate.as_bytes();
    bytes.len() >= 3 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' && bytes[2] == b'\\'
}

fn is_reviewed_runtime_path(normalized: &str) -> bool {
    let lowered = normalized.to_ascii_lowercase();
    lowered == DEFAULT_WINDOWS_STATE_PATH.to_ascii_lowercase()
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_CONFIG_ROOT)
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_LOG_ROOT)
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_TRUST_ROOT)
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_MEMBERSHIP_ROOT)
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_KEYS_ROOT)
        || under_reviewed_root(lowered.as_str(), DEFAULT_WINDOWS_SECRET_ROOT)
}

fn under_reviewed_root(lowered: &str, root: &str) -> bool {
    let root = root.to_ascii_lowercase();
    lowered == root || lowered.starts_with(&format!("{root}\\"))
}

fn extract_sddl_owner(sddl: &str) -> Option<&str> {
    let owner_start = sddl.strip_prefix("O:")?;
    let mut owner_len = owner_start.len();
    for marker in ["G:", "D:", "S:"] {
        if let Some(index) = owner_start.find(marker) {
            owner_len = owner_len.min(index);
        }
    }
    Some(&owner_start[..owner_len])
}

fn sddl_contains_principal(sddl: &str, principal: &str) -> bool {
    let marker = format!(";;;{principal})");
    sddl.contains(&marker)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn validate_windows_runtime_file_path_accepts_reviewed_program_data_paths() {
        let result =
            validate_windows_runtime_file_path(Path::new(DEFAULT_WINDOWS_STATE_PATH), "state path");
        assert!(
            result.is_ok(),
            "reviewed program data path should validate: {result:?}"
        );
    }

    #[test]
    fn validate_windows_runtime_file_path_accepts_reviewed_secret_blob_paths() {
        let result = validate_windows_secret_blob_path(
            Path::new(DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH),
            "wg key passphrase path",
        );
        assert!(
            result.is_ok(),
            "reviewed secret blob path should validate: {result:?}"
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

    #[test]
    fn validate_windows_runtime_file_path_rejects_unreviewed_program_data_roots() {
        let err = validate_windows_runtime_file_path(
            Path::new(r"C:\ProgramData\OtherVendor\rustynetd.state"),
            "state path",
        )
        .expect_err("non-reviewed program data root should fail");
        assert!(err.contains("reviewed RustyNet Windows runtime roots"));
    }

    #[test]
    fn validate_windows_runtime_file_path_rejects_parent_directory_traversal() {
        let err = validate_windows_runtime_file_path(
            Path::new(r"C:\ProgramData\RustyNet\config\..\secrets\wireguard.passphrase.dpapi"),
            "passphrase path",
        )
        .expect_err("parent traversal should fail");
        assert!(err.contains("must not contain parent-directory traversal"));
    }

    #[test]
    fn validate_windows_secret_blob_path_rejects_plaintext_extension() {
        let err = validate_windows_secret_blob_path(
            Path::new(r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase"),
            "wg key passphrase path",
        )
        .expect_err("non-dpapi extension should fail");
        assert!(err.contains("reviewed DPAPI blob extension"));
    }

    #[test]
    fn sddl_owner_parser_accepts_service_sids() {
        let owner = extract_sddl_owner("O:S-1-5-80-1234G:SYD:P(A;;FA;;;SY)");
        assert_eq!(owner, Some("S-1-5-80-1234"));
    }

    #[test]
    fn sddl_principal_match_is_ace_scoped() {
        assert!(sddl_contains_principal("D:P(A;;FA;;;SY)(A;;FA;;;BA)", "SY"));
        assert!(!sddl_contains_principal("O:SYG:SYD:P", "SY"));
    }
}
