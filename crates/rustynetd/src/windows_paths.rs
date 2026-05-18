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
                label: (*label).to_owned(),
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
    if !sddl_grants_principal(sddl, "SY") {
        return Err(format!("{label} ACL must grant LocalSystem access"));
    }
    if !sddl_grants_principal(sddl, "BA") {
        return Err(format!(
            "{label} ACL must grant Builtin Administrators access"
        ));
    }
    // A deny ACE for an allowed principal short-circuits the allow
    // ACE (Windows evaluates ACEs in order; an inserted deny would
    // halt the service). Treat such ACEs as drift.
    if sddl_denies_principal(sddl, "SY") {
        return Err(format!(
            "{label} ACL denies LocalSystem (deny ACE present); the daemon cannot start without LocalSystem access"
        ));
    }
    if sddl_denies_principal(sddl, "BA") {
        return Err(format!(
            "{label} ACL denies Builtin Administrators (deny ACE present); operators lose remediation access"
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
        if sddl_grants_principal(sddl, principal) {
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

/// True iff the SDDL contains an allow-type ACE for `principal`. A
/// SDDL ACE has the form `(ace_type;ace_flags;rights;...;sid)`. We
/// scan for the trailing `;;;principal)` segment that anchors the
/// ACE end, then walk back to the opening parenthesis to confirm the
/// ACE type is `A` (allow). Deny ACEs (`D;...`) intentionally do NOT
/// match — see `sddl_denies_principal`.
fn sddl_grants_principal(sddl: &str, principal: &str) -> bool {
    sddl_ace_matches(sddl, principal, 'A')
}

/// True iff the SDDL contains a deny-type ACE for `principal`. A deny
/// ACE for an allowed principal (e.g. `(D;;FA;;;SY)`) would override
/// any allow ACE that follows it in evaluation order, which means an
/// attacker who can append a deny ACE silently disables access for
/// the daemon's own service identity.
fn sddl_denies_principal(sddl: &str, principal: &str) -> bool {
    sddl_ace_matches(sddl, principal, 'D')
}

fn sddl_ace_matches(sddl: &str, principal: &str, expected_type: char) -> bool {
    let marker = format!(";;;{principal})");
    let expected_token: &str = match expected_type {
        'A' => "A",
        'D' => "D",
        other => {
            debug_assert!(false, "unsupported ACE type {other}");
            return false;
        }
    };
    let mut search_from = 0usize;
    while let Some(local) = sddl[search_from..].find(&marker) {
        let absolute = search_from + local;
        // Walk back from the marker's start to the opening '(' of
        // this ACE. The ACE type token is the substring between '('
        // and the first ';' — needs to match EXACTLY (so `A` !=
        // `AU` audit, `D` != `XD` callback-deny, etc.).
        if let Some(paren) = sddl[..absolute].rfind('(') {
            let ace_body_start = paren + 1;
            if let Some(semi) = sddl[ace_body_start..absolute].find(';') {
                let token = &sddl[ace_body_start..ace_body_start + semi];
                if token == expected_token {
                    return true;
                }
            }
        }
        search_from = absolute + marker.len();
    }
    false
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
        assert!(sddl_grants_principal("D:P(A;;FA;;;SY)(A;;FA;;;BA)", "SY"));
        assert!(!sddl_grants_principal("O:SYG:SYD:P", "SY"));
    }

    #[test]
    fn sddl_grants_principal_distinguishes_allow_from_deny() {
        assert!(sddl_grants_principal("D:P(A;;FA;;;SY)", "SY"));
        assert!(
            !sddl_grants_principal("D:P(D;;FA;;;SY)", "SY"),
            "deny ACE must not register as a grant"
        );
    }

    #[test]
    fn sddl_denies_principal_detects_deny_aces() {
        assert!(sddl_denies_principal("D:P(D;;FA;;;SY)", "SY"));
        assert!(
            !sddl_denies_principal("D:P(A;;FA;;;SY)", "SY"),
            "allow ACE must not register as a deny"
        );
    }

    #[test]
    fn sddl_grants_principal_handles_mixed_allow_and_deny_aces() {
        // Daemon DACL with both an allow grant and a deny ACE for the
        // same principal: deny wins at Windows evaluation time but
        // both flags must register correctly in our helpers.
        let sddl = "D:P(A;;FA;;;SY)(D;;FA;;;SY)(A;;FA;;;BA)";
        assert!(sddl_grants_principal(sddl, "SY"));
        assert!(sddl_denies_principal(sddl, "SY"));
        assert!(sddl_grants_principal(sddl, "BA"));
        assert!(!sddl_denies_principal(sddl, "BA"));
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
            label: "state root".to_owned(),
            path: r"C:\ProgramData\RustyNet".to_owned(),
            status: WindowsRuntimeAclRootStatus::Ok,
        };
        let json = serde_json::to_value(&entry_ok).expect("serialize ok entry");
        assert_eq!(json["status"], "ok");
        assert_eq!(json["label"], "state root");
        assert_eq!(json["path"], r"C:\ProgramData\RustyNet");

        let entry_drifted = WindowsRuntimeAclRootEntry {
            label: "config root".to_owned(),
            path: r"C:\ProgramData\RustyNet\config".to_owned(),
            status: WindowsRuntimeAclRootStatus::Drifted {
                reason: "config root ACL must grant LocalSystem access".to_owned(),
            },
        };
        let json = serde_json::to_value(&entry_drifted).expect("serialize drifted entry");
        assert_eq!(json["status"], "drifted");
        assert_eq!(
            json["reason"],
            "config root ACL must grant LocalSystem access"
        );

        let entry_missing = WindowsRuntimeAclRootEntry {
            label: "log root".to_owned(),
            path: r"C:\ProgramData\RustyNet\logs".to_owned(),
            status: WindowsRuntimeAclRootStatus::Missing {
                reason: "log root must be a real directory".to_owned(),
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

    // ---- W4: runtime-ACL drift extension -----------------------------

    /// Deny ACE for LocalSystem must reject: even with a paired allow
    /// ACE, the deny halts service start because Windows evaluates
    /// ACEs in order and short-circuits on the first match. Before
    /// this slice the verifier silently passed.
    #[test]
    fn evaluate_runtime_acl_rejects_deny_ace_for_localsystem() {
        let sddl = "O:BAG:BAD:P(D;;FA;;;SY)(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("deny ACE for LocalSystem must fail");
        assert!(
            err.contains("denies LocalSystem"),
            "unexpected error: {err}"
        );
    }

    /// Deny ACE for Builtin Administrators must reject for the same
    /// reason — even though SY still has access, admins lose
    /// remediation paths (Restart-Service, registry cleanup, etc).
    #[test]
    fn evaluate_runtime_acl_rejects_deny_ace_for_builtin_admins() {
        let sddl = "O:BAG:BAD:P(A;;FA;;;SY)(D;;FA;;;BA)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("deny ACE for Builtin Administrators must fail");
        assert!(
            err.contains("denies Builtin Administrators"),
            "unexpected error: {err}"
        );
    }

    /// Explicit deny ACE for `WD` (World) is acceptable — it
    /// strengthens the protection rather than weakening it. Confirms
    /// the WD-forbidden check is allow-only and does not over-trigger.
    #[test]
    fn evaluate_runtime_acl_accepts_explicit_deny_ace_for_world() {
        let sddl = "O:BAG:BAD:P(D;;FA;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect("explicit Deny for World must validate");
    }

    /// `D:PAI` (protected + auto-inherit) is acceptable: the `D:P`
    /// substring is still present so the protection bit check passes.
    /// Pin this so a future tightening to exact-match `D:P` doesn't
    /// silently break common SDDL forms.
    #[test]
    fn evaluate_runtime_acl_accepts_pai_inheritance_flag() {
        let sddl = "O:BAG:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect("D:PAI form must validate");
    }

    /// Empty SDDL string fails on the DACL-marker check first.
    #[test]
    fn evaluate_runtime_acl_rejects_empty_sddl() {
        let err = evaluate_windows_runtime_acl_sddl("state root", "", true)
            .expect_err("empty SDDL must fail");
        assert!(
            err.contains("must expose a Windows DACL"),
            "unexpected error: {err}"
        );
    }

    /// SDDL that is only the owner field (no DACL) must fail.
    #[test]
    fn evaluate_runtime_acl_rejects_owner_only_sddl() {
        let err = evaluate_windows_runtime_acl_sddl("state root", "O:SY", true)
            .expect_err("owner-only SDDL must fail");
        assert!(
            err.contains("must expose a Windows DACL"),
            "unexpected error: {err}"
        );
    }

    /// SACL present + a clean DACL: SACL audit ACEs must NOT interfere
    /// with the DACL evaluation. A WD principal inside the SACL audit
    /// path is benign — auditing world access is fine.
    #[test]
    fn evaluate_runtime_acl_accepts_sacl_audit_for_world() {
        let sddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(AU;;FA;;;WD)";
        evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect("SACL audit for WD must not trip the DACL drift check");
    }

    /// Inverse case: SACL omitted entirely is also acceptable — we do
    /// not require auditing as part of the runtime contract.
    #[test]
    fn evaluate_runtime_acl_accepts_sddl_without_sacl_section() {
        let sddl = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect("SDDL without SACL must validate");
    }

    /// Anonymous-owner SID (S-1-5-7) must reject. Only LocalSystem,
    /// Builtin Administrators, or a service SID (S-1-5-80-*) are
    /// reviewed owners. Anonymous would allow ownership transfer.
    #[test]
    fn evaluate_runtime_acl_rejects_anonymous_owner() {
        let sddl = "O:S-1-5-7G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("anonymous owner must fail");
        assert!(
            err.contains("ACL owner must be LocalSystem"),
            "unexpected error: {err}"
        );
    }

    /// Generic user SID (S-1-5-21-*) as owner must reject — only
    /// administrative or service identities are reviewed.
    #[test]
    fn evaluate_runtime_acl_rejects_user_sid_owner() {
        let sddl = "O:S-1-5-21-1111-2222-3333-1001G:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("local user SID owner must fail");
        assert!(
            err.contains("ACL owner must be LocalSystem"),
            "unexpected error: {err}"
        );
    }

    /// Local secret ACL evaluator must reject the same deny-ACE
    /// shape — DPAPI blobs need uniform deny-ACE handling.
    #[test]
    fn evaluate_local_secret_acl_passes_through_protected_dacl_checks() {
        // Local secret evaluator only invokes the protected-DACL
        // helper + owner-present check; the DACL helper still uses
        // the allow-only grants matcher under the hood. Confirm a
        // WD allow ACE on a DPAPI blob still trips drift.
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;WD)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("WD allow ACE on dpapi blob must fail");
        assert!(
            err.contains("broader-than-reviewed Windows principal"),
            "unexpected error: {err}"
        );
    }

    /// Snapshot test: pin the exact 8-entry reviewed-root list so
    /// silent removal of a root (e.g. dropping `key-custody root` by
    /// accident) trips a named failure.
    #[test]
    fn windows_runtime_startup_acl_roots_snapshot_pinned_at_eight_entries() {
        let paths: Vec<&str> = WINDOWS_RUNTIME_STARTUP_ACL_ROOTS
            .iter()
            .map(|(p, _)| *p)
            .collect();
        let expected: Vec<&str> = vec![
            DEFAULT_WINDOWS_STATE_ROOT,
            DEFAULT_WINDOWS_CONFIG_ROOT,
            DEFAULT_WINDOWS_LOG_ROOT,
            DEFAULT_WINDOWS_TRUST_ROOT,
            DEFAULT_WINDOWS_MEMBERSHIP_ROOT,
            DEFAULT_WINDOWS_KEYS_ROOT,
            DEFAULT_WINDOWS_SECRET_ROOT,
            DEFAULT_WINDOWS_KEY_CUSTODY_ROOT,
        ];
        assert_eq!(
            paths, expected,
            "reviewed runtime-root list shape drifted (W4 snapshot)"
        );
    }

    /// schema_version on the diagnostic report must stay at 1.
    /// Bumping it must be a deliberate change with a paired migration.
    #[test]
    fn windows_runtime_acl_report_schema_version_pinned_at_one() {
        let report = collect_windows_runtime_acl_report();
        assert_eq!(
            report.schema_version, 1,
            "schema_version bump must be deliberate"
        );
    }

    // ---- X4: SDDL + path-validator coverage parity sweep -------------

    /// Simple allow ACE for World registers as a grant. Baseline
    /// positive case anchors the matcher against silent regression
    /// where the allow-token recognition stops working.
    #[test]
    fn sddl_grants_principal_returns_true_for_simple_allow_ace_for_wd() {
        assert!(sddl_grants_principal("D:P(A;;FA;;;WD)", "WD"));
    }

    /// Deny ACE for World does NOT register as a grant. Pins the
    /// allow-vs-deny split that the broader-principal drift check
    /// depends on (a deny WD ACE strengthens the ACL and must not
    /// trip the forbidden-grant rejection).
    #[test]
    fn sddl_grants_principal_returns_false_for_deny_ace_for_wd() {
        assert!(
            !sddl_grants_principal("D:P(D;;FA;;;WD)", "WD"),
            "deny ACE for WD must not register as a grant"
        );
    }

    /// Deny ACE for World registers as a deny. Mirror of the grant
    /// positive — confirms the deny-matcher works against the same
    /// principal so the deny-LocalSystem / deny-Admins guards have
    /// teeth.
    #[test]
    fn sddl_denies_principal_returns_true_for_deny_ace_for_wd() {
        assert!(sddl_denies_principal("D:P(D;;FA;;;WD)", "WD"));
    }

    /// Allow ACE for World does NOT register as a deny. Inverse of
    /// the grant positive; protects against a future refactor that
    /// collapses both checks into one and over-triggers.
    #[test]
    fn sddl_denies_principal_returns_false_for_allow_ace_for_wd() {
        assert!(
            !sddl_denies_principal("D:P(A;;FA;;;WD)", "WD"),
            "allow ACE for WD must not register as a deny"
        );
    }

    /// Substring-only principal match must NOT trip. A SID-string
    /// that happens to contain "WD" as a substring (e.g. a custom
    /// SID with `WDXY`) must not be flagged. The matcher anchors on
    /// the `;;;principal)` terminator, so the trailing `)` after the
    /// exact principal token is load-bearing.
    #[test]
    fn sddl_grants_principal_exact_matches_only_wd_not_substring_match() {
        assert!(
            !sddl_grants_principal("D:P(A;;FA;;;WDXY)", "WD"),
            "principal substring match must not register as a grant"
        );
    }

    /// Authenticated Users (`AU`) allow ACE on a DPAPI blob must
    /// trip the broader-principal guard inside the local secret
    /// evaluator. Pins parity with the runtime evaluator's
    /// forbidden-principal coverage.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_authenticated_users_grant() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;AU)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("AU allow ACE on dpapi blob must fail");
        assert!(
            err.contains("broader-than-reviewed Windows principal") && err.contains("AU"),
            "unexpected error: {err}"
        );
    }

    /// Anonymous (`AN`) allow ACE on the *runtime* evaluator must
    /// be rejected via the owner whitelist: even though `AN` is not
    /// in FORBIDDEN_WELL_KNOWN_SDDL_PRINCIPALS today (so the
    /// protected-DACL helper does not flag the allow ACE itself),
    /// the runtime evaluator's owner check rejects any owner that
    /// is not LocalSystem / Builtin Administrators / service SID.
    /// Pin that the anonymous-owner shape is rejected end-to-end so
    /// any future refactor that softens the owner whitelist trips
    /// a named drift failure.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_anonymous_grant() {
        // Runtime evaluator path: `AN` owner + AN allow ACE fails
        // at the owner whitelist. The local-secret evaluator does
        // NOT enforce the owner whitelist (DPAPI blobs may live
        // under per-user accounts), so this assertion lives on the
        // runtime evaluator — that is where the reviewed-contract
        // anonymous-owner guard exists.
        let sddl = "O:ANG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_runtime_acl_sddl("state root", sddl, true)
            .expect_err("anonymous owner must fail at runtime evaluator");
        assert!(
            err.contains("ACL owner must be LocalSystem"),
            "unexpected error: {err}"
        );
    }

    /// Builtin Users (`BU`) allow ACE on a DPAPI blob must trip
    /// the broader-principal guard. Pins parity with the runtime
    /// evaluator forbidden-principal coverage.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_builtin_users_grant() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;BU)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("BU allow ACE on dpapi blob must fail");
        assert!(
            err.contains("broader-than-reviewed Windows principal") && err.contains("BU"),
            "unexpected error: {err}"
        );
    }

    /// Explicit World (`WD`) allow ACE on a DPAPI blob must trip
    /// the broader-principal guard. Named drift case so removing
    /// WD from the forbidden list ever in future is loud.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_world_grant() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;WD)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("WD allow ACE on dpapi blob must fail");
        assert!(
            err.contains("broader-than-reviewed Windows principal") && err.contains("WD"),
            "unexpected error: {err}"
        );
    }

    /// Reviewed posture: service SID owner + LocalSystem and
    /// Builtin Administrators allow ACEs validate cleanly on a
    /// DPAPI blob (file, not directory). Anchors the happy path so
    /// any future tightening that breaks the canonical secret-ACL
    /// posture is caught by name.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_accepts_service_sid_owner_and_localsystem_grant() {
        let sddl = "O:S-1-5-80-9999D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect("service SID owner + SY + BA must validate on a DPAPI blob");
    }

    /// SDDL missing the `O:` owner prefix must fail. The local
    /// secret evaluator demands an owner entry to prevent untrusted
    /// owner takeover.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_when_owner_entry_missing() {
        let sddl = "D:P(A;;FA;;;SY)(A;;FA;;;BA)";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("missing owner entry must fail");
        assert!(
            err.contains("must expose an owner entry"),
            "unexpected error: {err}"
        );
    }

    /// SDDL missing the `D:` DACL marker must fail before owner
    /// inspection. The protected-DACL helper is the first guard
    /// inside the local-secret evaluator.
    #[test]
    fn evaluate_windows_local_secret_acl_sddl_rejects_when_dacl_marker_missing() {
        let sddl = "O:S-1-5-80-9999";
        let err = evaluate_windows_local_secret_acl_sddl("dpapi blob", sddl, false)
            .expect_err("missing DACL marker must fail");
        assert!(
            err.contains("must expose a Windows DACL"),
            "unexpected error: {err}"
        );
    }

    /// UNC paths (`\\fileserver\share\foo`) must reject. Remote
    /// filesystems can be repointed by an attacker controlling the
    /// share, breaking the reviewed-root contract.
    #[test]
    fn validate_windows_runtime_file_path_rejects_unc_paths() {
        let err = validate_windows_runtime_file_path(
            Path::new(r"\\fileserver\share\RustyNet\rustynetd.state"),
            "state path",
        )
        .expect_err("UNC path must fail");
        assert!(
            err.contains("must not use a remote or UNC filesystem path"),
            "unexpected error: {err}"
        );
    }

    /// User Temp paths under `C:\Users\...\AppData\Local\Temp` are
    /// writable by low-privilege users and must reject. The
    /// reviewed runtime roots live under `C:\ProgramData\RustyNet`;
    /// any user-temp location is per-definition outside that root.
    #[test]
    fn validate_windows_runtime_file_path_rejects_user_temp_paths() {
        let err = validate_windows_runtime_file_path(
            Path::new(r"C:\Users\Public\AppData\Local\Temp\rustynetd.state"),
            "state path",
        )
        .expect_err("user-temp path must fail");
        assert!(
            err.contains("reviewed RustyNet Windows runtime roots"),
            "unexpected error: {err}"
        );
    }

    /// Canonical state file under `C:\ProgramData\RustyNet` must
    /// validate. Mirror of the existing reviewed-path positive but
    /// named explicitly to anchor the X4 parity sweep.
    #[test]
    fn validate_windows_runtime_file_path_accepts_canonical_program_data_paths() {
        let result = validate_windows_runtime_file_path(
            Path::new(r"C:\ProgramData\RustyNet\rustynetd.state"),
            "state path",
        );
        assert!(
            result.is_ok(),
            "canonical ProgramData state path must validate: {result:?}"
        );
    }
}
