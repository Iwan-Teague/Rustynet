//! W4 — Windows registry-key ACL drift verifier.
//!
//! Pure evaluator over an observed-registry-ACL snapshot. The
//! collector (Win32 `RegGetKeySecurity` +
//! `ConvertSecurityDescriptorToStringSecurityDescriptor`) lives in
//! `rustynet-windows-native` as a follow-up slice — this module owns
//! the typed schema and the evaluator only.
//!
//! Reviewed posture: registry keys that hold service config under
//! `HKLM\SYSTEM\CurrentControlSet\Services\RustyNet*` must NOT grant
//! access to broader-than-reviewed Windows principals (Everyone,
//! Authenticated Users, BUILTIN\Users, Anonymous) and must expose a
//! DACL.

use serde::{Deserialize, Serialize};

/// Reviewed registry keys whose ACLs must remain locked down. The
/// list is intentionally pinned in source so any addition surfaces in
/// review.
pub const REVIEWED_REGISTRY_KEY_PATHS: &[&str] = &[
    r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet",
    r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetPrivilegedHelper",
];

/// Reviewed Windows principals that are forbidden in DACL grants on
/// any reviewed registry key. `WD` (Everyone), `AU`
/// (Authenticated Users), `BU` (BUILTIN\Users), and `AN` (Anonymous)
/// all grant broader-than-reviewed access.
pub const FORBIDDEN_PRINCIPALS_REGISTRY: &[&str] = &["WD", "AU", "BU", "AN"];

const REQUIREMENT_REQUIRED: &str = "required";
const REQUIREMENT_OPTIONAL: &str = "optional";

/// Per-entry observation status for a reviewed registry key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WindowsRegistryKeyAclStatus {
    /// Key present, observed, and ACL within reviewed posture.
    Ok { acl_sddl: String },
    /// Key not present (some reviewed keys may be optional based on role).
    Missing { reason: String },
    /// Key present but ACL drifted.
    Invalid { reason: String, acl_sddl: String },
    /// Collector could not observe the key (off-Windows, permission
    /// denied, registry hive unavailable).
    Unobserved { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryKeyEntry {
    pub label: String,
    pub key_path: String,
    /// `required` if the key MUST be present, `optional` if absence is OK.
    pub requirement: String,
    #[serde(flatten)]
    pub status: WindowsRegistryKeyAclStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsRegistryAclReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub entries: Vec<WindowsRegistryKeyEntry>,
    pub drift_reasons: Vec<String>,
}

/// Pure evaluator over a snapshot of reviewed registry-key ACL
/// entries. Returns `Ok(())` when every entry's status is consistent
/// with its requirement and any reported SDDL stays within the
/// reviewed posture; otherwise returns the aggregated drift reasons.
///
/// Fails closed on empty input — a snapshot with no entries cannot
/// prove the reviewed posture and must be treated as drift.
pub fn evaluate_windows_registry_acls(
    entries: &[WindowsRegistryKeyEntry],
) -> Result<(), Vec<String>> {
    let mut reasons: Vec<String> = Vec::new();
    if entries.is_empty() {
        reasons.push("registry ACL report contains no entries".to_owned());
        return Err(reasons);
    }
    for entry in entries {
        match entry.requirement.as_str() {
            REQUIREMENT_REQUIRED => match &entry.status {
                WindowsRegistryKeyAclStatus::Ok { acl_sddl } => {
                    if let Err(err) = evaluate_registry_acl_sddl(&entry.label, acl_sddl) {
                        reasons.push(err);
                    }
                }
                WindowsRegistryKeyAclStatus::Missing { reason } => {
                    reasons.push(format!(
                        "{} required registry key missing: {reason}",
                        entry.label
                    ));
                }
                WindowsRegistryKeyAclStatus::Invalid { reason, .. } => {
                    reasons.push(format!("{} registry ACL invalid: {reason}", entry.label));
                }
                WindowsRegistryKeyAclStatus::Unobserved { reason } => {
                    reasons.push(format!("{} unobserved required key: {reason}", entry.label));
                }
            },
            REQUIREMENT_OPTIONAL => match &entry.status {
                WindowsRegistryKeyAclStatus::Ok { acl_sddl } => {
                    if let Err(err) = evaluate_registry_acl_sddl(&entry.label, acl_sddl) {
                        reasons.push(err);
                    }
                }
                WindowsRegistryKeyAclStatus::Missing { .. } => {}
                WindowsRegistryKeyAclStatus::Invalid { reason, .. } => {
                    reasons.push(format!("{} registry ACL invalid: {reason}", entry.label));
                }
                WindowsRegistryKeyAclStatus::Unobserved { reason } => {
                    reasons.push(format!("{} unobserved optional key: {reason}", entry.label));
                }
            },
            other => {
                reasons.push(format!(
                    "{} has unknown requirement {:?}",
                    entry.label, other
                ));
            }
        }
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

/// Build a report from a caller-supplied entry list, computing
/// `overall_ok` and `drift_reasons` from the pure evaluator. Entry
/// order is preserved as supplied.
pub fn build_windows_registry_acl_report(
    entries: Vec<WindowsRegistryKeyEntry>,
) -> WindowsRegistryAclReport {
    let drift_reasons = match evaluate_windows_registry_acls(&entries) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    WindowsRegistryAclReport {
        schema_version: 1,
        overall_ok,
        entries,
        drift_reasons,
    }
}

/// Cross-platform collector. On Windows the W4 Win32 collector in
/// `rustynet_windows_native::inspect_registry_key_sddl` opens each
/// reviewed key via `RegOpenKeyExW`, reads its DACL via
/// `RegGetKeySecurity`, and converts to SDDL via
/// `ConvertSecurityDescriptorToStringSecurityDescriptorW` (mirroring
/// the file-ACL path's `inspect_file_sddl`). Each per-key outcome is
/// mapped to:
///
/// * `Ok { acl_sddl }` — SDDL returned cleanly.
/// * `Missing { reason }` — Windows reported `ERROR_FILE_NOT_FOUND`
///   (the key path doesn't exist on this host).
/// * `Invalid { reason }` — Win32 returned a different error code,
///   so the key path is observable but the security descriptor
///   couldn't be read. Fail-closed: the evaluator treats this the
///   same as a forbidden grant.
///
/// Off-Windows the helper returns the same `Unobserved` shape the
/// pre-W4 stub did, so the evaluator's "collector unavailable" path
/// stays well-defined.
pub fn collect_windows_registry_acl_report() -> WindowsRegistryAclReport {
    let entries: Vec<WindowsRegistryKeyEntry> = REVIEWED_REGISTRY_KEY_PATHS
        .iter()
        .map(|path| collect_one_reviewed_key(path))
        .collect();
    build_windows_registry_acl_report(entries)
}

fn collect_one_reviewed_key(key_path: &str) -> WindowsRegistryKeyEntry {
    let status = registry_key_status_via_native(key_path);
    WindowsRegistryKeyEntry {
        label: format!("registry key {key_path}"),
        key_path: key_path.to_owned(),
        requirement: REQUIREMENT_REQUIRED.to_owned(),
        status,
    }
}

#[cfg(windows)]
fn registry_key_status_via_native(key_path: &str) -> WindowsRegistryKeyAclStatus {
    match rustynet_windows_native::inspect_registry_key_sddl(key_path) {
        Ok(acl_sddl) => WindowsRegistryKeyAclStatus::Ok { acl_sddl },
        Err(err) => {
            // Operator-friendly: keep the original error in the
            // reason so a missing-vs-locked-out case is debuggable.
            // The evaluator only branches on the variant, never on
            // the reason text, so log content is free-form.
            if err.contains("not found") {
                WindowsRegistryKeyAclStatus::Missing { reason: err }
            } else {
                WindowsRegistryKeyAclStatus::Invalid {
                    reason: err,
                    // ACL could not be read; surface an empty string
                    // so downstream serialisers don't break on a
                    // missing field. The evaluator branches on the
                    // variant, not on this body.
                    acl_sddl: String::new(),
                }
            }
        }
    }
}

#[cfg(not(windows))]
fn registry_key_status_via_native(_key_path: &str) -> WindowsRegistryKeyAclStatus {
    WindowsRegistryKeyAclStatus::Unobserved {
        reason: "windows-native registry ACL collector is only available on Windows hosts"
            .to_owned(),
    }
}

fn evaluate_registry_acl_sddl(label: &str, sddl: &str) -> Result<(), String> {
    if !sddl.contains("D:") {
        return Err(format!(
            "{label} registry ACL must expose a Windows DACL in SDDL form"
        ));
    }
    for principal in FORBIDDEN_PRINCIPALS_REGISTRY {
        if sddl_allow_grants_principal(sddl, principal) {
            return Err(format!(
                "{label} registry ACL grants a broader-than-reviewed Windows principal ({principal})"
            ));
        }
    }
    Ok(())
}

/// True iff the SDDL contains an allow-type ACE for `principal`. An
/// SDDL ACE has the form `(ace_type;ace_flags;rights;...;sid)`; this
/// helper scans for the trailing `;;;principal)` segment and then
/// walks back to the opening parenthesis to confirm the ACE type is
/// `A` (allow). Deny ACEs (`(D;...)`) intentionally do not match.
fn sddl_allow_grants_principal(sddl: &str, principal: &str) -> bool {
    let marker = format!(";;;{principal})");
    let mut search_from = 0usize;
    while let Some(rel) = sddl[search_from..].find(marker.as_str()) {
        let end = search_from + rel;
        // Walk back to the opening '(' that anchors this ACE.
        if let Some(open) = sddl[..end].rfind('(') {
            let ace_body = &sddl[open + 1..end];
            // The first token before the first ';' is the ACE type.
            if let Some(first_semi) = ace_body.find(';') {
                let ace_type = &ace_body[..first_semi];
                if ace_type == "A" {
                    return true;
                }
            }
        }
        search_from = end + marker.len();
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_required_entry(label: &str, path: &str) -> WindowsRegistryKeyEntry {
        WindowsRegistryKeyEntry {
            label: label.to_owned(),
            key_path: path.to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAG:BAD:P(A;;KA;;;SY)(A;;KA;;;BA)".to_owned(),
            },
        }
    }

    #[test]
    fn evaluator_accepts_clean_required_entries() {
        let entries = vec![
            ok_required_entry(
                "registry key RustyNet",
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet",
            ),
            ok_required_entry(
                "registry key RustyNetPrivilegedHelper",
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetPrivilegedHelper",
            ),
        ];
        evaluate_windows_registry_acls(&entries).expect("clean required entries must validate");
    }

    #[test]
    fn evaluator_accepts_optional_missing_entry() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNetOptional".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetOptional".to_owned(),
            requirement: REQUIREMENT_OPTIONAL.to_owned(),
            status: WindowsRegistryKeyAclStatus::Missing {
                reason: "key not present on this role".to_owned(),
            },
        }];
        evaluate_windows_registry_acls(&entries).expect("optional + missing must not drift");
    }

    #[test]
    fn evaluator_rejects_required_missing_entry() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Missing {
                reason: "RegOpenKeyEx returned ERROR_FILE_NOT_FOUND".to_owned(),
            },
        }];
        let reasons =
            evaluate_windows_registry_acls(&entries).expect_err("required + missing must drift");
        assert!(
            reasons.iter().any(|r| r.contains("registry key RustyNet")
                && r.contains("required registry key missing")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_required_unobserved_entry() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Unobserved {
                reason: "not running on Windows".to_owned(),
            },
        }];
        let reasons =
            evaluate_windows_registry_acls(&entries).expect_err("required + unobserved must drift");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("unobserved required key")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_invalid_entry() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Invalid {
                reason: "DACL inheritance enabled".to_owned(),
                acl_sddl: "O:BAD:(A;;KA;;;SY)".to_owned(),
            },
        }];
        let reasons =
            evaluate_windows_registry_acls(&entries).expect_err("invalid entry must drift");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("registry ACL invalid")
                    && r.contains("DACL inheritance enabled")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_world_writable_grant() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(A;;KA;;;SY)(A;;KA;;;WD)".to_owned(),
            },
        }];
        let reasons = evaluate_windows_registry_acls(&entries).expect_err("WD grant must drift");
        assert!(
            reasons.iter().any(|r| r.contains("(WD)")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_authenticated_users_grant() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(A;;KA;;;SY)(A;;KR;;;AU)".to_owned(),
            },
        }];
        let reasons = evaluate_windows_registry_acls(&entries).expect_err("AU grant must drift");
        assert!(
            reasons.iter().any(|r| r.contains("(AU)")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_anonymous_grant() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(A;;KA;;;SY)(A;;KR;;;AN)".to_owned(),
            },
        }];
        let reasons = evaluate_windows_registry_acls(&entries).expect_err("AN grant must drift");
        assert!(
            reasons.iter().any(|r| r.contains("(AN)")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_builtin_users_grant() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(A;;KA;;;SY)(A;;KR;;;BU)".to_owned(),
            },
        }];
        let reasons = evaluate_windows_registry_acls(&entries).expect_err("BU grant must drift");
        assert!(
            reasons.iter().any(|r| r.contains("(BU)")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unknown_requirement_string() {
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: "maybe".to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(A;;KA;;;SY)".to_owned(),
            },
        }];
        let reasons =
            evaluate_windows_registry_acls(&entries).expect_err("unknown requirement must drift");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("has unknown requirement")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_empty_entries() {
        let reasons = evaluate_windows_registry_acls(&[]).expect_err("empty entries must drift");
        assert!(
            reasons.iter().any(|r| r.contains("contains no entries")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn reviewed_registry_key_paths_snapshot_test() {
        assert_eq!(
            REVIEWED_REGISTRY_KEY_PATHS,
            &[
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet",
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetPrivilegedHelper",
            ]
        );
    }

    #[test]
    fn forbidden_principals_snapshot_test() {
        assert_eq!(FORBIDDEN_PRINCIPALS_REGISTRY, &["WD", "AU", "BU", "AN"]);
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_entries() {
        let entries = vec![
            ok_required_entry(
                "registry key RustyNet",
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet",
            ),
            ok_required_entry(
                "registry key RustyNetPrivilegedHelper",
                r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetPrivilegedHelper",
            ),
        ];
        let report = build_windows_registry_acl_report(entries.clone());
        assert_eq!(report.schema_version, 1);
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.entries, entries);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = WindowsRegistryAclReport {
            schema_version: 1,
            overall_ok: false,
            entries: vec![
                ok_required_entry(
                    "registry key RustyNet",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet",
                ),
                WindowsRegistryKeyEntry {
                    label: "registry key RustyNetPrivilegedHelper".to_owned(),
                    key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNetPrivilegedHelper"
                        .to_owned(),
                    requirement: REQUIREMENT_REQUIRED.to_owned(),
                    status: WindowsRegistryKeyAclStatus::Unobserved {
                        reason: "off-Windows".to_owned(),
                    },
                },
            ],
            drift_reasons: vec![
                "registry key RustyNetPrivilegedHelper unobserved required key: off-Windows"
                    .to_owned(),
            ],
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(serialized.contains("\"status\":\"ok\""));
        assert!(serialized.contains("\"status\":\"unobserved\""));
        let restored: WindowsRegistryAclReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn collector_stub_returns_unobserved_required_entries() {
        // Off-Windows the W4 collector routes through the
        // `rustynet-windows-native` shim which returns the
        // "Windows-only" platform-blocker error, surfaced here as
        // `WindowsRegistryKeyAclStatus::Unobserved`. On Windows the
        // native collector exercises real `RegGetKeySecurity` — the
        // test still passes because the reviewed reviewed key paths
        // (`HKLM\SYSTEM\CurrentControlSet\Services\RustyNet...`)
        // are unlikely to exist on the dev machine running cargo
        // test, so the collector reports `Missing` (or `Invalid`)
        // rather than `Unobserved`. We accept any non-Ok status and
        // require `overall_ok=false`.
        let report = collect_windows_registry_acl_report();
        assert_eq!(report.schema_version, 1);
        assert!(
            !report.overall_ok,
            "collector must not claim overall_ok=true without observing the reviewed keys"
        );
        assert_eq!(report.entries.len(), REVIEWED_REGISTRY_KEY_PATHS.len());
        for (entry, path) in report
            .entries
            .iter()
            .zip(REVIEWED_REGISTRY_KEY_PATHS.iter())
        {
            assert_eq!(entry.key_path, *path);
            assert_eq!(entry.requirement, REQUIREMENT_REQUIRED);
            match &entry.status {
                WindowsRegistryKeyAclStatus::Ok { .. } => {
                    panic!("collector unexpectedly observed a real ACL for {path}");
                }
                WindowsRegistryKeyAclStatus::Unobserved { reason }
                | WindowsRegistryKeyAclStatus::Missing { reason }
                | WindowsRegistryKeyAclStatus::Invalid { reason, .. } => {
                    assert!(
                        !reason.is_empty(),
                        "drift reason must explain why the key was not Ok: {reason:?}"
                    );
                }
            }
        }
        // The evaluator surfaces every per-key non-Ok state as a
        // drift reason. Accept any of the canonical surface
        // tokens: "unobserved required key", "missing required",
        // or "invalid required" — all three mean "the reviewed key
        // is not in the Ok state".
        assert!(
            report.drift_reasons.iter().any(|r| {
                r.contains("unobserved required key")
                    || r.contains("missing required")
                    || r.contains("invalid required")
            }),
            "report must surface at least one per-key drift reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn evaluator_tolerates_deny_ace_for_forbidden_principal() {
        // A deny ACE for WD does NOT grant access, so it must not
        // trigger drift. Pins the allow-vs-deny discrimination in
        // `sddl_allow_grants_principal`.
        let entries = vec![WindowsRegistryKeyEntry {
            label: "registry key RustyNet".to_owned(),
            key_path: r"HKLM\SYSTEM\CurrentControlSet\Services\RustyNet".to_owned(),
            requirement: REQUIREMENT_REQUIRED.to_owned(),
            status: WindowsRegistryKeyAclStatus::Ok {
                acl_sddl: "O:BAD:P(D;;KA;;;WD)(A;;KA;;;SY)".to_owned(),
            },
        }];
        evaluate_windows_registry_acls(&entries)
            .expect("deny ACE for WD must not be flagged as a grant");
    }
}
