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
        reasons.push("key custody report contains no entries".to_owned());
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
                label: label.to_owned(),
                path: path.display().to_string(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: format!("{label} must exist on Windows runtime host: {err}"),
                },
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
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
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
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
                label: label.to_owned(),
                path: path.display().to_string(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: format!("{label} ACL inspection failed: {err}"),
                    acl_sddl: String::new(),
                },
            };
        }
    };
    if let Err(err) = evaluate_windows_local_secret_acl_sddl(label, sddl.as_str(), false) {
        return WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} ACL drift: {err}"),
                acl_sddl: sddl,
            },
        };
    }
    WindowsKeyCustodyEntry {
        label: label.to_owned(),
        path: path.display().to_string(),
        requirement: REQUIREMENT_PRESENT.to_owned(),
        status: WindowsKeyCustodyEntryStatus::Ok { acl_sddl: sddl },
    }
}

fn inspect_forbidden_artifact(label: &str, path_str: &str) -> WindowsKeyCustodyEntry {
    let path = Path::new(path_str);
    match std::fs::symlink_metadata(path) {
        Ok(_) => WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "{label} must not exist at rest; encrypted-at-rest custody requires the plaintext form to be absent"
                ),
            },
        },
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
        },
        Err(err) => WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: path.display().to_string(),
            requirement: REQUIREMENT_ABSENT.to_owned(),
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
            label: label.to_owned(),
            path: format!(r"C:\ProgramData\RustyNet\secrets\{label}.dpapi"),
            requirement: REQUIREMENT_PRESENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Ok {
                acl_sddl: "O:S-1-5-80-9999D:P(A;;FA;;;SY)".to_owned(),
            },
        }
    }

    fn absent_forbidden_entry(label: &str) -> WindowsKeyCustodyEntry {
        WindowsKeyCustodyEntry {
            label: label.to_owned(),
            path: format!(r"C:\ProgramData\RustyNet\keys\{label}"),
            requirement: REQUIREMENT_ABSENT.to_owned(),
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
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "file not found".to_owned(),
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
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "ACL drift: world-writable principal".to_owned(),
                    acl_sddl: "O:WDD:(A;;FA;;;WD)".to_owned(),
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
                label: "wg plaintext runtime private key".to_owned(),
                path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_owned(),
                requirement: REQUIREMENT_ABSENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Forbidden {
                    reason: "plaintext key file present at rest".to_owned(),
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
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
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
                label: "wg plaintext runtime private key".to_owned(),
                path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_owned(),
                requirement: REQUIREMENT_ABSENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Ok {
                    acl_sddl: "O:SYD:(A;;FA;;;SY)".to_owned(),
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
            label: "wg key passphrase blob".to_owned(),
            path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
            requirement: "maybe".to_owned(),
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
                label: "wg key passphrase blob".to_owned(),
                path: "p1".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "missing".to_owned(),
                },
            },
            WindowsKeyCustodyEntry {
                label: "wg encrypted private key".to_owned(),
                path: "p2".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "acl bad".to_owned(),
                    acl_sddl: String::new(),
                },
            },
            WindowsKeyCustodyEntry {
                label: "wg plaintext runtime private key".to_owned(),
                path: "p3".to_owned(),
                requirement: REQUIREMENT_ABSENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Forbidden {
                    reason: "found".to_owned(),
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

    // ---- W6: DPAPI LocalMachine rotation tests ----------------------

    /// Helper: produce a reviewed DPAPI blob ACL — service-SID owner,
    /// LocalSystem and BUILTIN\Administrators granted, protected DACL.
    fn reviewed_dpapi_sddl() -> &'static str {
        "O:S-1-5-80-1234567890D:P(A;;FA;;;SY)(A;;FA;;;BA)"
    }

    /// Helper: produce an entry as if a rotation just replaced the
    /// passphrase blob — same path, same ACL shape, fresh DPAPI bytes
    /// (the verifier only checks shape, not content).
    fn rotated_passphrase_entry() -> WindowsKeyCustodyEntry {
        WindowsKeyCustodyEntry {
            label: "wg key passphrase blob".to_owned(),
            path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Ok {
                acl_sddl: reviewed_dpapi_sddl().to_owned(),
            },
        }
    }

    /// Rotation success path: post-rotation snapshot with all three
    /// secret blobs present + reviewed ACLs and the plaintext-key path
    /// still absent. Must validate.
    #[test]
    fn evaluator_accepts_post_rotation_snapshot_with_reviewed_acls() {
        let entries = vec![
            rotated_passphrase_entry(),
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        evaluate_windows_key_custody(&entries)
            .expect("rotated blob with reviewed ACL must validate");
    }

    /// Rotation that lost the protected-DACL bit: the new file landed
    /// with a non-protected DACL ("D:" without "D:P"). For a regular
    /// secret-blob *file* the helper does NOT require D:P (file-level
    /// non-protected DACLs are tolerated as long as no forbidden
    /// principal is granted), but any forbidden well-known principal
    /// on the rotated file must still fail. Pin both cases.
    #[test]
    fn evaluator_rejects_rotation_with_world_writable_principal() {
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "ACL drift: world-writable principal (Everyone) on rotated blob"
                        .to_owned(),
                    acl_sddl: "O:S-1-5-80-1234567890D:(A;;FA;;;WD)".to_owned(),
                },
            },
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("world-writable post-rotation must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob invalid")
                    && r.contains("world-writable")),
            "post-rotation world-writable must surface: {reasons:?}"
        );
    }

    /// Rotation that broke ownership: the rotator process ran as a
    /// user other than the service SID, so the new file's owner is
    /// wrong. Even with a clean DACL this is drift — the service-SID
    /// principal is part of the reviewed contract.
    #[test]
    fn evaluator_rejects_rotation_with_unreviewed_owner() {
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "owner drift: rotation completed as wrong principal".to_owned(),
                    acl_sddl: "O:S-1-5-21-1111-2222-3333-1001D:P(A;;FA;;;SY)".to_owned(),
                },
            },
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("wrong owner post-rotation must fail");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob invalid") && r.contains("owner drift")),
            "owner-drift must surface: {reasons:?}"
        );
    }

    /// Partial rotation: passphrase blob rotated successfully but the
    /// encrypted-key path is mid-rotation and reported `Missing`. Even
    /// though one entry is fresh, the partial state must fail-closed —
    /// a half-rotated key set cannot unwrap the runtime key.
    #[test]
    fn evaluator_rejects_partial_rotation_with_missing_encrypted_key() {
        let entries = vec![
            rotated_passphrase_entry(),
            WindowsKeyCustodyEntry {
                label: "wg encrypted private key".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.key.enc".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "atomic rename mid-rotation; file briefly missing".to_owned(),
                },
            },
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("partial rotation must fail-closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg encrypted private key missing")),
            "missing post-rotation must surface: {reasons:?}"
        );
    }

    /// Rotation that left the plaintext-key path populated (e.g. the
    /// rotation tool wrote the unwrapped key to disk by mistake). The
    /// forbidden-artifact-present case is a Phase-E migration violator
    /// at any moment, but is especially likely as a transient artifact
    /// during a buggy rotation.
    #[test]
    fn evaluator_rejects_rotation_that_left_plaintext_key_present() {
        let entries = vec![
            rotated_passphrase_entry(),
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            WindowsKeyCustodyEntry {
                label: "wg plaintext runtime private key".to_owned(),
                path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_owned(),
                requirement: REQUIREMENT_ABSENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Forbidden {
                    reason: "rotation tool dropped a plaintext key by mistake".to_owned(),
                },
            },
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("plaintext at rest must fail-closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg plaintext runtime private key")
                    && r.contains("present but must be absent")),
            "post-rotation plaintext-at-rest must surface: {reasons:?}"
        );
    }

    /// Rotation atomicity: simulate a multi-stage rotation that flips
    /// only the passphrase blob to a fresh DPAPI ciphertext but leaves
    /// the encrypted-key blob still under the OLD passphrase. The
    /// custody verifier cannot detect crypto-content mismatch (that
    /// would require attempting an unwrap), but it CAN catch the
    /// mode/ACL drift that often accompanies a partial rotation, e.g.
    /// the passphrase blob ending with a non-reviewed extension after
    /// the rotation tool wrote a `.dpapi.tmp` and forgot to rename.
    #[test]
    fn evaluator_rejects_rotation_with_temp_suffix_extension_drift() {
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi.tmp".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "extension drift: post-rotation file ends with .dpapi.tmp not .dpapi"
                        .to_owned(),
                    acl_sddl: reviewed_dpapi_sddl().to_owned(),
                },
            },
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons = evaluate_windows_key_custody(&entries)
            .expect_err("post-rotation temp-suffix must fail-closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob invalid")
                    && r.contains("extension drift")),
            "rotation temp-suffix must surface: {reasons:?}"
        );
    }

    /// LocalMachine scope marker: a reviewed DPAPI-protected blob's
    /// SDDL exposes ONLY service-SID + SY + BA principals. If a future
    /// refactor accidentally widens the DACL to include
    /// Authenticated Users (AU), the verifier must catch it — that
    /// shape grants any logged-on user read access to the encrypted
    /// blob and breaks the LocalMachine-scope assumption.
    #[test]
    fn evaluator_rejects_rotation_that_widened_dacl_to_authenticated_users() {
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_owned(),
                path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Invalid {
                    reason: "ACL drift: rotation tool added Authenticated Users (AU) to DACL"
                        .to_owned(),
                    acl_sddl: "O:S-1-5-80-1234567890D:P(A;;FA;;;SY)(A;;FR;;;AU)".to_owned(),
                },
            },
            ok_entry("wg encrypted private key"),
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("AU-widened DACL must fail-closed");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("wg key passphrase blob invalid")
                    && r.contains("Authenticated Users")),
            "AU-widened DACL must surface: {reasons:?}"
        );
    }

    #[test]
    fn snapshot_serializes_with_status_tag_and_round_trips() {
        let report = WindowsKeyCustodyReport {
            schema_version: 1,
            overall_ok: false,
            entries: vec![
                ok_entry("wg key passphrase blob"),
                WindowsKeyCustodyEntry {
                    label: "wg plaintext runtime private key".to_owned(),
                    path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_owned(),
                    requirement: REQUIREMENT_ABSENT.to_owned(),
                    status: WindowsKeyCustodyEntryStatus::Forbidden {
                        reason: "present".to_owned(),
                    },
                },
            ],
            drift_reasons: vec![
                "wg plaintext runtime private key present but must be absent: present".to_owned(),
            ],
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(serialized.contains("\"status\":\"ok\""));
        assert!(serialized.contains("\"status\":\"forbidden\""));
        let restored: WindowsKeyCustodyReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn report_schema_version_pinned_at_one() {
        // Pin the wire-format schema_version so an accidental bump
        // forces a deliberate code change + commit-message rationale.
        let report = WindowsKeyCustodyReport {
            schema_version: 1,
            overall_ok: true,
            entries: vec![ok_entry("wg key passphrase blob")],
            drift_reasons: Vec::new(),
        };
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape must be int=1: {body}"
        );
    }

    #[test]
    fn entry_status_missing_round_trips_through_serde() {
        // Pre-existing snapshot_serializes_with_status_tag_and_round_trips
        // only covered Ok + Forbidden together. Pin the Missing variant
        // explicitly so a future #[serde(rename)] on reason trips this.
        let entry = WindowsKeyCustodyEntry {
            label: "wg key passphrase blob".to_owned(),
            path: r"C:\ProgramData\RustyNet\secrets\wireguard.passphrase.dpapi".to_owned(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Missing {
                reason: "file not found".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"missing\""), "tag: {body}");
        assert!(
            body.contains("\"reason\":\"file not found\""),
            "reason: {body}"
        );
        let parsed: WindowsKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_invalid_round_trips_through_serde() {
        // Invalid carries reason + acl_sddl; pin both through serde.
        let entry = WindowsKeyCustodyEntry {
            label: "wg encrypted private key".to_owned(),
            path: r"C:\ProgramData\RustyNet\secrets\wireguard.key.enc".to_owned(),
            requirement: REQUIREMENT_PRESENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::Invalid {
                reason: "ACL drift".to_owned(),
                acl_sddl: "O:WDD:(A;;FA;;;WD)".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"invalid\""), "tag: {body}");
        assert!(
            body.contains("\"acl_sddl\":\"O:WDD:(A;;FA;;;WD)\""),
            "acl shape: {body}"
        );
        let parsed: WindowsKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_absent_as_expected_round_trips_through_serde() {
        // The forbidden-but-correctly-absent path; round-trip the
        // unit variant explicitly so a future addition of a field
        // (e.g. confirmed_at_unix) trips the test.
        let entry = WindowsKeyCustodyEntry {
            label: "wg plaintext runtime private key".to_owned(),
            path: r"C:\ProgramData\RustyNet\keys\wireguard.key".to_owned(),
            requirement: REQUIREMENT_ABSENT.to_owned(),
            status: WindowsKeyCustodyEntryStatus::AbsentAsExpected,
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(
            body.contains("\"status\":\"absent_as_expected\""),
            "tag: {body}"
        );
        let parsed: WindowsKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_rejects_unknown_tag() {
        // #[serde(tag = "status", rename_all = "snake_case")] — an
        // unknown tag must fail closed.
        let body = r#"{"label":"wg key passphrase blob","path":"C:\\ProgramData\\RustyNet\\secrets\\wireguard.passphrase.dpapi","requirement":"present","status":"rotating","reason":"placeholder"}"#;
        let err = serde_json::from_str::<WindowsKeyCustodyEntry>(body)
            .expect_err("unknown tag must fail closed");
        assert!(
            err.to_string().contains("rotating") || err.to_string().contains("unknown variant"),
            "error must reference unknown tag or 'unknown variant': {err}"
        );
    }

    #[test]
    fn evaluator_does_not_dedupe_repeated_drift_reasons_across_entries() {
        // Two entries with the same drift shape must surface as two
        // reasons, not one. Pin so a future HashSet-based dedup
        // refactor would silently collapse the operator-facing count.
        let entries = vec![
            WindowsKeyCustodyEntry {
                label: "wg key passphrase blob".to_owned(),
                path: "p1".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "ENOENT".to_owned(),
                },
            },
            WindowsKeyCustodyEntry {
                label: "wg encrypted private key".to_owned(),
                path: "p2".to_owned(),
                requirement: REQUIREMENT_PRESENT.to_owned(),
                status: WindowsKeyCustodyEntryStatus::Missing {
                    reason: "ENOENT".to_owned(),
                },
            },
            ok_entry("wg public key"),
            absent_forbidden_entry("wg plaintext runtime private key"),
        ];
        let reasons =
            evaluate_windows_key_custody(&entries).expect_err("two missing entries must fail");
        // exactly two reasons surfaced — one per missing entry, no dedup.
        let missing_reasons: Vec<&String> =
            reasons.iter().filter(|r| r.contains("missing")).collect();
        assert_eq!(
            missing_reasons.len(),
            2,
            "expected 2 missing reasons (no dedup), got: {reasons:?}"
        );
    }
}
