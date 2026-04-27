#![allow(clippy::result_large_err)]

//! Windows key-custody verifier.
//!
//! Validates that the on-disk key material on a Windows runtime host matches
//! the reviewed custody contract:
//!
//! * the WireGuard runtime passphrase is stored as a DPAPI-protected blob at
//!   the reviewed `.dpapi` path and is ACL-locked;
//! * the encrypted WireGuard private key file exists at the reviewed path
//!   and is ACL-locked;
//! * the plaintext WireGuard private key file is absent at rest (Phase E
//!   migrated runtime key custody to encrypted-at-rest);
//! * the WireGuard public key file exists at the reviewed path and is
//!   ACL-locked.
//!
//! The pure `evaluate_windows_key_custody` aggregator returns every drift
//! reason in a single pass; the daemon-side collector
//! (`collect_windows_key_custody_snapshot`) walks the canonical paths and
//! captures each entry's status. Together they back the
//! `windows-key-custody-check` subcommand the orchestrator dispatches over
//! the existing argv-only PowerShell-encoded SSH channel.

use crate::windows_paths::{
    DEFAULT_WINDOWS_WG_ENCRYPTED_PRIVATE_KEY_PATH, DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH,
    DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH, DEFAULT_WINDOWS_WG_RUNTIME_PRIVATE_KEY_PATH,
    evaluate_windows_local_secret_acl_sddl,
};
use rustynet_windows_native::inspect_file_sddl;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Per-entry presence + ACL status for a key-custody artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WindowsKeyCustodyEntryStatus {
    /// Required artifact present, valid, and ACL-locked.
    Ok { acl_sddl: String },
    /// Required artifact missing.
    Missing { reason: String },
    /// Required artifact present but ACL drifted, format wrong, or otherwise
    /// failed validation.
    Invalid { reason: String, acl_sddl: String },
    /// Forbidden artifact present (e.g. plaintext key file at rest).
    Forbidden { reason: String },
    /// Forbidden artifact correctly absent.
    AbsentAsExpected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsKeyCustodyEntry {
    pub label: String,
    pub path: String,
    /// `present` | `absent` requirement. Drives how the status is interpreted.
    pub requirement: String,
    #[serde(flatten)]
    pub status: WindowsKeyCustodyEntryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsKeyCustodyReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub entries: Vec<WindowsKeyCustodyEntry>,
    pub drift_reasons: Vec<String>,
}

const REQUIREMENT_PRESENT: &str = "present";
const REQUIREMENT_ABSENT: &str = "absent";

/// Pure evaluator over a custody report. Recomputes drift reasons from the
/// per-entry statuses; returns `Ok(())` when every entry's status is
/// consistent with its requirement, otherwise returns the aggregated drift
/// reasons.
pub fn evaluate_windows_key_custody(entries: &[WindowsKeyCustodyEntry]) -> Result<(), Vec<String>> {
    let mut reasons: Vec<String> = Vec::new();
    if entries.is_empty() {
        reasons.push("key custody report contains no entries".to_string());
        return Err(reasons);
    }
    for entry in entries {
        match (entry.requirement.as_str(), &entry.status) {
            (REQUIREMENT_PRESENT, WindowsKeyCustodyEntryStatus::Ok { .. }) => {}
            (REQUIREMENT_ABSENT, WindowsKeyCustodyEntryStatus::AbsentAsExpected) => {}
            (REQUIREMENT_PRESENT, WindowsKeyCustodyEntryStatus::Missing { reason }) => {
                reasons.push(format!("{} missing: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, WindowsKeyCustodyEntryStatus::Invalid { reason, .. }) => {
                reasons.push(format!("{} invalid: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, WindowsKeyCustodyEntryStatus::AbsentAsExpected) => {
                reasons.push(format!(
                    "{} required but reported absent (collector bug or missing artifact)",
                    entry.label
                ));
            }
            (REQUIREMENT_PRESENT, WindowsKeyCustodyEntryStatus::Forbidden { reason }) => {
                reasons.push(format!(
                    "{} marked forbidden but requirement is present: {reason}",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, WindowsKeyCustodyEntryStatus::Forbidden { reason }) => {
                reasons.push(format!(
                    "{} present but must be absent: {reason}",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, WindowsKeyCustodyEntryStatus::Ok { .. }) => {
                reasons.push(format!(
                    "{} reported Ok but requirement is absent; collector treated forbidden artifact as required",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, WindowsKeyCustodyEntryStatus::Missing { .. })
            | (REQUIREMENT_ABSENT, WindowsKeyCustodyEntryStatus::Invalid { .. }) => {
                reasons.push(format!(
                    "{} requirement is absent but collector returned a present-style status",
                    entry.label
                ));
            }
            (other, _) => {
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

/// Build the live custody report by inspecting the canonical Windows key
/// material paths. Cross-platform: on non-Windows hosts the SDDL inspector
/// returns a clear blocker error so the report records `Missing`/`Invalid`
/// entries rather than fabricating success.
pub fn collect_windows_key_custody_snapshot() -> WindowsKeyCustodyReport {
    let mut entries = vec![
        inspect_required_secret_blob(
            "wg key passphrase blob",
            DEFAULT_WINDOWS_WG_KEY_PASSPHRASE_PATH,
            ".dpapi",
        ),
        inspect_required_secret_blob(
            "wg encrypted private key",
            DEFAULT_WINDOWS_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            ".enc",
        ),
        inspect_required_secret_blob("wg public key", DEFAULT_WINDOWS_WG_PUBLIC_KEY_PATH, ".pub"),
        inspect_forbidden_artifact(
            "wg plaintext runtime private key",
            DEFAULT_WINDOWS_WG_RUNTIME_PRIVATE_KEY_PATH,
        ),
    ];
    let drift_reasons = match evaluate_windows_key_custody(&entries) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    // Sort entries by label for deterministic JSON output across runs.
    entries.sort_by(|a, b| a.label.cmp(&b.label));
    WindowsKeyCustodyReport {
        schema_version: 1,
        overall_ok,
        entries,
        drift_reasons,
    }
}

fn inspect_required_secret_blob(
    label: &str,
    path_str: &str,
    expected_extension: &str,
) -> WindowsKeyCustodyEntry {
    let path = Path::new(path_str);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) => {
            return WindowsKeyCustodyEntry {
                label: label.to_string(),
                path: path.display().to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: format!("{label} must exist on Windows runtime host: {err}"),
                },
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} must be a regular file, not a symlink or directory"),
                acl_sddl: String::new(),
            },
        };
    }
    if !path
        .to_string_lossy()
        .to_ascii_lowercase()
        .ends_with(expected_extension)
    {
        return WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} must use the reviewed extension {expected_extension}"),
                acl_sddl: String::new(),
            },
        };
    }
    let sddl = match inspect_file_sddl(path) {
        Ok(sddl) => sddl,
        Err(err) => {
            return WindowsKeyCustodyEntry {
                label: label.to_string(),
                path: path.display().to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: format!("{label} ACL inspection failed: {err}"),
                    acl_sddl: String::new(),
                },
            };
        }
    };
    if let Err(err) = evaluate_windows_local_secret_acl_sddl(label, sddl.as_str(), false) {
        return WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} ACL drift: {err}"),
                acl_sddl: sddl,
            },
        };
    }
    WindowsKeyCustodyEntry {
        label: label.to_string(),
        path: path.display().to_string(),
        requirement: REQUIREMENT_PRESENT.to_string(),
        status: WindowsKeyCustodyEntryStatus::Ok { acl_sddl: sddl },
    }
}

fn inspect_forbidden_artifact(label: &str, path_str: &str) -> WindowsKeyCustodyEntry {
    let path = Path::new(path_str);
    match std::fs::symlink_metadata(path) {
        Ok(_) => WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "{label} must not exist at rest; encrypted-at-rest custody requires the plaintext form to be absent"
                ),
            },
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
        },
        Err(err) => WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "{label} stat returned an unexpected error; cannot prove absence: {err}"
                ),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_entry(label: &str) -> WindowsKeyCustodyEntry {
        WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: format!(r"C:\ProgramData\RustyNet\secrets\{label}.dpapi"),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::Ok {
                acl_sddl: "O:S-1-5-80-9999D:P(A;;FA;;;SY)".to_string(),
            },
        }
    }

    fn absent_forbidden_entry(label: &str) -> WindowsKeyCustodyEntry {
        WindowsKeyCustodyEntry {
            label: label.to_string(),
            path: format!(r"C:\ProgramData\RustyNet\keys\{label}"),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
        }
    }

    #[test]
    fn evaluator_accepts_all_required_present_and_forbidden_absent() {
        let entries = vec![
            ok_entry("wg key passphrase blob"),
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        evaluate_windows_key_custody(&entries).expect("clean snapshot must validate");
    }

    #[test]
    fn evaluator_rejects_empty_entries() {
        let reasons = evaluate_windows_key_custody(&[]).expect_err("empty entries must fail");
        assert!(
            reasons.iter().any(|r| r.contains("contains no entries")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_required_artifact_missing() {
        let mut entries = vec![
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        entries.insert(
            0,
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_string(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "file not found".to_string(),
                },
            },
        );
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("missing required artifact must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob missing")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_required_artifact_invalid_acl() {
        let entries = vec![
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_string(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "ACL drift: world-writable principal".to_string(),
                    acl_sddl: "O:WDD:(A;;FA;;;WD)".to_string(),
                },
            },
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("invalid required artifact must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob invalid")
                    && r.contains("world-writable principal")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_forbidden_artifact_present() {
        let entries = vec![
            ok_entry("wg key passphrase blob"),
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            WindowsKeyCustodyEntry {
                label: "wg plaintext runtime private key".to_string(),
                path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_string(),
                requirement: REQUIREMENT_ABSENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Forbidden {
                    reason: "plaintext key file present at rest".to_string(),
                },
            },
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("forbidden present must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg plaintext runtime private key present but must be absent")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_inconsistent_required_with_absent_status() {
        let entries = vec![
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_string(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
            },
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("inconsistent requirement/status must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob required but reported absent")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_inconsistent_absent_with_ok_status() {
        let entries = vec![
            ok_entry("wg key passphrase blob"),
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            WindowsKeyCustodyEntry {
                label: "wg plaintext runtime private key".to_string(),
                path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_string(),
                requirement: REQUIREMENT_ABSENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Ok {
                    acl_sddl: "O:SYD:(A;;FA;;;SY)".to_string(),
                },
            },
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("inconsistent absent-with-ok must fail");
        assert!(
            reasons.iter().any(|r| r.contains(
                "wg plaintext runtime private key reported Ok but requirement is absent"
            )),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_unknown_requirement_string() {
        let entries = vec![WindowsKeyCustodyEntry {
            label: "wg key passphrase blob".to_string(),
            path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_string(),
            requirement: "maybe".to_string(),
            status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
        }];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("unknown requirement must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("has unknown requirement")),
            "unexpected reasons: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_string(),
                path: "p1".to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "missing".to_string(),
                },
            },
            WindowsKeyCustodyEntry {
                label: "wg encrypted private key".to_string(),
                path: "p2".to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "acl bad".to_string(),
                    acl_sddl: String::new(),
                },
            },
            WindowsKeyCustodyEntry {
                label: "wg plaintext runtime private key".to_string(),
                path: "p3".to_string(),
                requirement: REQUIREMENT_ABSENT.to_string(),
                status: WindowsKeyCustodyEntryStatus::Forbidden {
                    reason: "found".to_string(),
                },
            },
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("aggregated drifts must fail");
        assert!(reasons.len() >= 3, "expected >=3 reasons: {reasons:?}");
    }

    #[cfg(not(windows))]
    #[test]
    fn collect_snapshot_marks_required_artifacts_missing_off_windows() {
        let report = collect_windows_key_custody_snapshot();
        assert_eq!(report.schema_version, 1);
        assert!(
            !report.overall_ok,
            "non-Windows host must not report overall_ok=true"
        );
        assert!(
            !report.entries.is_empty(),
            "snapshot must contain at least the canonical entries"
        );
        // The forbidden plaintext key entry should be `AbsentAsExpected` on
        // non-Windows hosts (the path doesn't exist), but the required
        // artifacts should be `Missing`. So overall_ok must be false purely
        // because of the missing required artifacts.
        let plaintext = report
            .entries
            .iter()
            .find(|e| e.label == "wg plaintext runtime private key")
            .expect("plaintext entry must be present");
        assert_eq!(plaintext.requirement, REQUIREMENT_ABSENT);
        assert!(matches!(
            plaintext.status,
            WindowsKeyCustodyEntryStatus::AbsentAsExpected
        ));
    }

    #[test]
    fn snapshot_serializes_with_status_tag_and_round_trips() {
        let report = WindowsKeyCustodyReport {
            schema_version: 1,
            overall_ok: false,
            entries: vec![
                ok_entry("wg key passphrase blob"),
                WindowsKeyCustodyEntry {
                    label: "wg plaintext runtime private key".to_string(),
                    path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_string(),
                    requirement: REQUIREMENT_ABSENT.to_string(),
                    status: WindowsKeyCustodyEntryStatus::Forbidden {
                        reason: "present".to_string(),
                    },
                },
            ],
            drift_reasons: vec![
                "wg plaintext runtime private key present but must be absent: present".to_string(),
            ],
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(serialized.contains("\"status\":\"ok\""));
        assert!(serialized.contains("\"status\":\"forbidden\""));
        let restored: WindowsKeyCustodyReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }
}
