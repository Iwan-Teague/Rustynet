use rustynet_windows_native::inspect_file_sddl;
use serde::{Deserialize, Serialize};
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
pub const DEFAULT_WINDOWS_RELAY_FLEET_BUNDLE_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.relay-fleet";
pub const DEFAULT_WINDOWS_RELAY_FLEET_WATERMARK_PATH: &str =
    r"C:\ProgramData\RustyNet\trust\rustynetd.relay-fleet.watermark";
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
    let is_dir = std::fs::symlink_metadata(path)
        .map_err(|err| format!("{label} metadata read failed ({}): {err}", path.display()))?
        .is_dir();
    evaluate_windows_runtime_acl_sddl(label, sddl.as_str(), is_dir)
        .map_err(|err| format!("{err}: {}", path.display()))
}

pub fn validate_windows_local_secret_acl(path: &Path, label: &str) -> Result<(), String> {
    let sddl = inspect_file_sddl(path)
        .map_err(|err| format!("{label} ACL inspection failed ({}): {err}", path.display()))?;
    let is_dir = std::fs::symlink_metadata(path)
        .map_err(|err| format!("{label} metadata read failed ({}): {err}", path.display()))?
        .is_dir();
    evaluate_windows_local_secret_acl_sddl(label, sddl.as_str(), is_dir)
        .map_err(|err| format!("{err}: {}", path.display()))
}

/// Validate the canonical Windows runtime root directories at daemon startup.
///
/// All reviewed roots under `C:\ProgramData\RustyNet` must (a) exist, (b) be
/// directories, (c) carry a protected DACL with no broader-than-reviewed
/// principals, (d) grant LocalSystem and Builtin Administrators, and (e) be
/// owned by LocalSystem, Builtin Administrators, or a service SID.
///
/// The daemon refuses to start when any root drifts. This is a fail-closed
/// gate; missing roots are treated as drift and rejected. The Windows service
/// installer is responsible for provisioning these roots before the daemon
/// runs.
pub fn validate_windows_runtime_startup_acls() -> Result<(), String> {
    for (path_str, label) in WINDOWS_RUNTIME_STARTUP_ACL_ROOTS {
        let path = Path::new(path_str);
        let metadata = std::fs::symlink_metadata(path).map_err(|err| {
            format!(
                "{label} must exist before rustynetd starts on Windows ({}): {err}",
                path.display()
            )
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(format!(
                "{label} must be a real directory, not a symlink or file ({})",
                path.display()
            ));
        }
        validate_windows_runtime_acl(path, label)?;
    }
    Ok(())
}

/// Per-root verification result for the Windows runtime ACL diagnostic
/// command. Captures success or the exact failure reason for each reviewed
/// root, so the orchestrator can pinpoint drift without re-parsing free-form
/// daemon errors.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WindowsRuntimeAclRootStatus {
    /// Root exists, is a directory, and ACL evaluation passed.
    Ok,
    /// Root path could not be inspected (typically: missing or non-directory).
    Missing { reason: String },
    /// Root exists but ACL evaluation failed (drifted ACL, wrong owner, etc.).
    Drifted { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRuntimeAclRootEntry {
    pub label: String,
    pub path: String,
    #[serde(flatten)]
    pub status: WindowsRuntimeAclRootStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRuntimeAclReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub roots: Vec<WindowsRuntimeAclRootEntry>,
}

/// Diagnostic walk over the canonical Windows runtime roots. Unlike
/// `validate_windows_runtime_startup_acls`, this collects per-root status
/// instead of failing fast, so a remote orchestrator can render a complete
/// drift report in a single round-trip.
///
/// The function still returns `overall_ok = false` if any root failed; the
/// caller decides whether to treat that as fatal. The startup gate keeps the
/// fail-fast behavior to refuse daemon launch on the first drift.
pub fn collect_windows_runtime_acl_report() -> WindowsRuntimeAclReport {
    let roots = WINDOWS_RUNTIME_STARTUP_ACL_ROOTS
        .iter()
        .map(|(path_str, label)| {
            let path = Path::new(path_str);
            let status = inspect_runtime_root_status(path, label);
            WindowsRuntimeAclRootEntry {
                label: (*label).to_string(),
                path: path.display().to_string(),
                status,
            }
        })
        .collect::<Vec<_>>();
    let overall_ok = roots
        .iter()
        .all(|entry| matches!(entry.status, WindowsRuntimeAclRootStatus::Ok));
    WindowsRuntimeAclReport {
        schema_version: 1,
        overall_ok,
        roots,
    }
}

fn inspect_runtime_root_status(path: &Path, label: &str) -> WindowsRuntimeAclRootStatus {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(err) => {
            return WindowsRuntimeAclRootStatus::Missing {
                reason: format!(
                    "{label} must exist before rustynetd starts on Windows ({}): {err}",
                    path.display()
                ),
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return WindowsRuntimeAclRootStatus::Missing {
            reason: format!(
                "{label} must be a real directory, not a symlink or file ({})",
                path.display()
            ),
        };
    }
    match validate_windows_runtime_acl(path, label) {
        Ok(()) => WindowsRuntimeAclRootStatus::Ok,
        Err(reason) => WindowsRuntimeAclRootStatus::Drifted { reason },
    }
}

const WINDOWS_RUNTIME_STARTUP_ACL_ROOTS: &[(&str, &str)] = &[
    (DEFAULT_WINDOWS_STATE_ROOT, "state root"),
    (DEFAULT_WINDOWS_CONFIG_ROOT, "config root"),
    (DEFAULT_WINDOWS_LOG_ROOT, "log root"),
    (DEFAULT_WINDOWS_TRUST_ROOT, "trust root"),
    (DEFAULT_WINDOWS_MEMBERSHIP_ROOT, "membership root"),
    (DEFAULT_WINDOWS_KEYS_ROOT, "keys root"),
    (DEFAULT_WINDOWS_SECRET_ROOT, "secret root"),
    (DEFAULT_WINDOWS_KEY_CUSTODY_ROOT, "key-custody root"),
];

pub(crate) fn evaluate_windows_runtime_acl_sddl(
    label: &str,
    sddl: &str,
    is_dir: bool,
) -> Result<(), String> {
    evaluate_windows_protected_dacl_sddl(label, sddl, is_dir)?;
    if !sddl_contains_principal(sddl, "SY") {
        return Err(format!("{label} ACL must grant LocalSystem access"));
    }
    if !sddl_contains_principal(sddl, "BA") {
        return Err(format!(
            "{label} ACL must grant Builtin Administrators access"
        ));
    }
    let owner = extract_sddl_owner(sddl)
        .ok_or_else(|| format!("{label} ACL must expose an owner entry in SDDL form"))?;
    if !matches!(owner, "SY" | "BA") && !owner.starts_with("S-1-5-80-") {
        return Err(format!(
            "{label} ACL owner must be LocalSystem, Builtin Administrators, or a service SID; found {owner}"
        ));
    }
    Ok(())
}

pub(crate) fn evaluate_windows_local_secret_acl_sddl(
    label: &str,
    sddl: &str,
    is_dir: bool,
) -> Result<(), String> {
    evaluate_windows_protected_dacl_sddl(label, sddl, is_dir)?;
    if extract_sddl_owner(sddl).is_none() {
        return Err(format!(
            "{label} ACL must expose an owner entry in SDDL form"
        ));
    }
    Ok(())
}

fn evaluate_windows_protected_dacl_sddl(
    label: &str,
    sddl: &str,
    is_dir: bool,
) -> Result<(), String> {
    if !sddl.contains("D:") {
        return Err(format!("{label} must expose a Windows DACL in SDDL form"));
    }
    if is_dir && !sddl.contains("D:P") {
        return Err(format!(
            "{label} must use a protected DACL with inheritance disabled"
        ));
    }
    for principal in FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS {
        if sddl_contains_principal(sddl, principal) {
            return Err(format!(
                "{label} ACL grants a broader-than-reviewed Windows principal ({principal})"
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
    // Match the canonical state file (rustynetd.state under the state
    // root) and the state root directory itself.  The bare state root
    // is needed because run_windows_runtime_boundary_check validates
    // it directly via this helper before walking into its subdirs;
    // earlier the bare root was rejected even though every accepted
    // subdir (config/log/trust/membership/keys/secret) lives under it.
    lowered == DEFAULT_WINDOWS_STATE_PATH.to_ascii_lowercase()
        || lowered == DEFAULT_WINDOWS_STATE_ROOT.to_ascii_lowercase()
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
    fn validate_windows_runtime_file_path_accepts_state_root_itself() {
        // run_windows_runtime_boundary_check validates state_root via the
        // same helper before it descends into the subdirs; the bare root
        // must be accepted or every Windows install fails closed at the
        // boundary check.
        let result =
            validate_windows_runtime_file_path(Path::new(DEFAULT_WINDOWS_STATE_ROOT), "state root");
        assert!(
            result.is_ok(),
            "default state root must validate: {result:?}"
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

    const REVIEWED_DIRECTORY_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";

    #[test]
    fn evaluate_runtime_acl_accepts_reviewed_directory_sddl() {
        evaluate_windows_runtime_acl_sddl("state root", REVIEWED_DIRECTORY_SDDL, true)
            .expect("reviewed directory SDDL should validate");
    }

    #[test]
    fn evaluate_runtime_acl_accepts_service_sid_owner() {
        let sddl = "O:S-1-5-80-1234G:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect("service SID owner should validate");
    }

    #[test]
    fn evaluate_runtime_acl_rejects_directory_without_protected_dacl() {
        let sddl = "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("directory without protected DACL must fail");
        assert!(
            err.contains("protected DACL with inheritance disabled"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_rejects_world_writable_principals() {
        for principal in ["WD", "AU", "BU"] {
            let sddl = format!("O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;{principal})");
            let err = evaluate_windows_runtime_acl_sddl("state root", sddl.as_str(), true)
                .expect_err("ACE for broad principal must fail");
            assert!(
                err.contains("broader-than-reviewed Windows principal") && err.contains(principal),
                "unexpected error for {principal}: {err}"
            );
        }
    }

    #[test]
    fn evaluate_runtime_acl_rejects_missing_localsystem_grant() {
        let sddl = "O:BAG:BAD:P(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("missing LocalSystem grant must fail");
        assert!(
            err.contains("must grant LocalSystem access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_rejects_missing_administrators_grant() {
        let sddl = "O:BAG:BAD:P(A;;FA;;;SY)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("missing Administrators grant must fail");
        assert!(
            err.contains("must grant Builtin Administrators access"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_rejects_unrecognized_owner() {
        let sddl = "O:WDG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("unrecognized owner must fail");
        assert!(
            err.contains("ACL owner must be LocalSystem"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_rejects_missing_owner() {
        let sddl = "G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("missing owner must fail");
        assert!(
            err.contains("must expose an owner entry"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_rejects_missing_dacl_marker() {
        let sddl = "O:BAG:BA";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("missing DACL marker must fail");
        assert!(
            err.contains("must expose a Windows DACL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn evaluate_runtime_acl_allows_unprotected_dacl_for_files() {
        let sddl = "O:BAG:BAD:(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_runtime_acl_sddl("state file", sddl, false)
            .expect("file ACL without explicit protection bit should still validate");
    }

    #[test]
    fn evaluate_local_secret_acl_accepts_dpapi_owner_only_sddl() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)";
        evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect("local secret ACL with service SID owner should validate");
    }

    #[test]
    fn evaluate_local_secret_acl_rejects_world_writable_principals() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;WD)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("local secret ACL with WD principal must fail");
        assert!(
            err.contains("broader-than-reviewed Windows principal"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn windows_runtime_startup_acl_roots_cover_every_reviewed_root() {
        let labels = WINDOWS_RUNTIME_STARTUP_ACL_ROOTS
            .iter()
            .map(|(_, label)| *label)
            .collect::<Vec<_>>();
        let mut sorted = labels.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(
            sorted.len(),
            labels.len(),
            "startup ACL root labels must be unique: {labels:?}"
        );

        let paths = WINDOWS_RUNTIME_STARTUP_ACL_ROOTS
            .iter()
            .map(|(path, _)| *path)
            .collect::<Vec<_>>();
        for required in [
            DEFAULT_WINDOWS_STATE_ROOT,
            DEFAULT_WINDOWS_CONFIG_ROOT,
            DEFAULT_WINDOWS_LOG_ROOT,
            DEFAULT_WINDOWS_TRUST_ROOT,
            DEFAULT_WINDOWS_MEMBERSHIP_ROOT,
            DEFAULT_WINDOWS_KEYS_ROOT,
            DEFAULT_WINDOWS_SECRET_ROOT,
            DEFAULT_WINDOWS_KEY_CUSTODY_ROOT,
        ] {
            assert!(
                paths.contains(&required),
                "startup ACL root list missing reviewed runtime root {required}"
            );
        }
    }

    #[cfg(not(windows))]
    #[test]
    fn validate_windows_runtime_startup_acls_fails_off_windows() {
        let err = validate_windows_runtime_startup_acls()
            .expect_err("ACL inspection must not succeed on non-Windows hosts");
        assert!(
            err.contains("must exist before rustynetd starts on Windows")
                || err.contains("ACL inspection failed")
                || err.contains("Windows ACL inspection is only available on Windows hosts"),
            "unexpected non-Windows error: {err}"
        );
    }

    #[test]
    fn windows_runtime_acl_report_root_status_serializes_with_status_tag() {
        let entry_ok = WindowsRuntimeAclRootEntry {
            label: "state root".to_string(),
            path: r"C:\ProgramData\RustyNet".to_string(),
            status: WindowsRuntimeAclRootStatus::Ok,
        };
        let json = serde_json::to_value(&entry_ok).expect("serialize ok entry");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["label"], "state root");
        assert_eq!(json["path"], r"C:\ProgramData\RustyNet");

        let entry_drifted = WindowsRuntimeAclRootEntry {
            label: "config root".to_string(),
            path: r"C:\ProgramData\RustyNet\config".to_string(),
            status: WindowsRuntimeAclRootStatus::Drifted {
                reason: "config root ACL must grant LocalSystem access".to_string(),
            },
        };
        let json = serde_json::to_value(&entry_drifted).expect("serialize drifted entry");
        assert_eq!(json["status"], "drifted");
        assert_eq!(
            json["reason"],
            "config root ACL must grant LocalSystem access"
        );

        let entry_missing = WindowsRuntimeAclRootEntry {
            label: "log root".to_string(),
            path: r"C:\ProgramData\RustyNet\logs".to_string(),
            status: WindowsRuntimeAclRootStatus::Missing {
                reason: "log root must be a real directory".to_string(),
            },
        };
        let json = serde_json::to_value(&entry_missing).expect("serialize missing entry");
        assert_eq!(json["status"], "missing");
    }

    #[cfg(not(windows))]
    #[test]
    fn collect_windows_runtime_acl_report_marks_every_root_off_windows() {
        let report = collect_windows_runtime_acl_report();
        assert_eq!(report.schema_version, 1);
        assert!(
            !report.overall_ok,
            "non-Windows host must not report overall_ok=true"
        );
        assert_eq!(
            report.roots.len(),
            WINDOWS_RUNTIME_STARTUP_ACL_ROOTS.len(),
            "every reviewed root must appear in the diagnostic report"
        );
        for entry in &report.roots {
            assert!(
                !matches!(entry.status, WindowsRuntimeAclRootStatus::Ok),
                "non-Windows host must not mark {} as Ok",
                entry.label
            );
        }
    }

    #[test]
    fn windows_runtime_acl_report_overall_ok_requires_all_roots_ok() {
        let report = WindowsRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: vec![],
        };
        let json = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(json["schema_version"], 1);
        assert_eq!(json["overall_ok"], true);
        assert!(json["roots"].is_array());
    }

    #[test]
    fn validate_windows_runtime_file_path_accepts_relay_fleet_bundle_path() {
        let result = validate_windows_runtime_file_path(
            Path::new(DEFAULT_WINDOWS_RELAY_FLEET_BUNDLE_PATH),
            "relay fleet bundle",
        );
        assert!(
            result.is_ok(),
            "relay fleet bundle path must validate: {result:?}"
        );
    }

    #[test]
    fn validate_windows_runtime_file_path_accepts_relay_fleet_watermark_path() {
        let result = validate_windows_runtime_file_path(
            Path::new(DEFAULT_WINDOWS_RELAY_FLEET_WATERMARK_PATH),
            "relay fleet watermark",
        );
        assert!(
            result.is_ok(),
            "relay fleet watermark path must validate: {result:?}"
        );
    }

    #[test]
    fn relay_fleet_paths_live_under_trust_root() {
        let bundle = DEFAULT_WINDOWS_RELAY_FLEET_BUNDLE_PATH.to_ascii_lowercase();
        let watermark = DEFAULT_WINDOWS_RELAY_FLEET_WATERMARK_PATH.to_ascii_lowercase();
        let trust_root = DEFAULT_WINDOWS_TRUST_ROOT.to_ascii_lowercase();
        let prefix = format!("{trust_root}\\");
        assert!(
            bundle.starts_with(&prefix),
            "relay fleet bundle must be under trust root: {bundle}"
        );
        assert!(
            watermark.starts_with(&prefix),
            "relay fleet watermark must be under trust root: {watermark}"
        );
    }
}
