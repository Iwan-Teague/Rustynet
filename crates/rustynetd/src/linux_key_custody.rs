#![allow(clippy::result_large_err)]

//! Linux key-custody verifier.
//!
//! Linux parity for `windows_key_custody`. Validates that the on-disk
//! key material on a Linux runtime host matches the reviewed custody
//! contract:
//!
//! * the encrypted WireGuard private key exists at
//!   `/var/lib/rustynet/keys/wireguard.key.enc`, owned by
//!   `rustynetd:rustynetd`, mode `0600`;
//! * the WireGuard public key exists at
//!   `/var/lib/rustynet/keys/wireguard.pub`, owned by
//!   `rustynetd:rustynetd`, mode `0640` or `0600`;
//! * the keys directory `/var/lib/rustynet/keys/` is a real directory
//!   owned by `rustynetd:rustynetd`, mode `0700`;
//! * the plaintext WireGuard private key (the legacy unencrypted path)
//!   is absent at rest — Phase E migrated runtime key custody to
//!   encrypted-at-rest.
//!
//! These come from the systemd unit's `RUSTYNET_WG_*` env vars + the
//! e2e bootstrap install commands. Wired through the CLI as
//! `rustynetd linux-key-custody-check`. The orchestrator's
//! `LinuxDaemonProbe` adapter dispatches the `KeyCustody` op to this
//! subcommand.

use serde::{Deserialize, Serialize};

pub const LINUX_WG_KEYS_DIR: &str = "/var/lib/rustynet/keys";
pub const LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.key.enc";
pub const LINUX_WG_PUBLIC_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.pub";
/// Legacy plaintext private key path. Must NOT exist at rest after the
/// Phase E migration to encrypted-at-rest custody.
pub const LINUX_WG_PLAINTEXT_PRIVATE_KEY_PATH: &str = "/var/lib/rustynet/keys/wireguard.key";
/// Reviewed encrypted credential directory. systemd loads the
/// passphrase material from inside via `LoadCredentialEncrypted=`; the
/// directory must be 0700 root:root so only systemd (running as root)
/// can read the encrypted blobs at unit-start time.
pub const LINUX_CREDENTIALS_DIR: &str = "/etc/rustynet/credentials";
/// Encrypted credential file holding the WireGuard runtime passphrase.
/// Reviewed: 0600 root:root.
pub const LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH: &str =
    "/etc/rustynet/credentials/wg_key_passphrase.cred";
/// Encrypted credential file holding the membership-owner signing-key
/// passphrase. Reviewed: 0600 root:root.
pub const LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_PATH: &str =
    "/etc/rustynet/credentials/signing_key_passphrase.cred";
/// Legacy plaintext passphrase path inside the keys directory. Must
/// NOT exist at rest — passphrase material is owned by systemd's
/// encrypted-credential store, never by the rustynetd-owned keys dir.
pub const LINUX_WG_PLAINTEXT_PASSPHRASE_PATH: &str = "/var/lib/rustynet/keys/wireguard.passphrase";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LinuxKeyCustodyEntryStatus {
    /// Required artifact present, valid, with reviewed mode + owner.
    Ok { mode: u32, uid: u32, gid: u32 },
    /// Required artifact missing.
    Missing { reason: String },
    /// Required artifact present but mode / owner / type drifted.
    Invalid {
        reason: String,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    /// Forbidden artifact present (e.g. plaintext private key file).
    Forbidden { reason: String },
    /// Forbidden artifact correctly absent.
    AbsentAsExpected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKeyCustodyEntry {
    pub label: String,
    pub path: String,
    /// `"present"` or `"absent"` — drives how the status is interpreted.
    pub requirement: String,
    #[serde(flatten)]
    pub status: LinuxKeyCustodyEntryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxKeyCustodyReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub entries: Vec<LinuxKeyCustodyEntry>,
    pub drift_reasons: Vec<String>,
}

const REQUIREMENT_PRESENT: &str = "present";
const REQUIREMENT_ABSENT: &str = "absent";

/// Pure evaluator: walks the entries and re-derives drift reasons from
/// per-entry statuses. Returns `Ok(())` when every entry's status is
/// consistent with its requirement, otherwise the aggregated reasons.
pub fn evaluate_linux_key_custody(entries: &[LinuxKeyCustodyEntry]) -> Result<(), Vec<String>> {
    let mut reasons: Vec<String> = Vec::new();
    if entries.is_empty() {
        reasons.push("key custody report contains no entries".to_string());
        return Err(reasons);
    }
    for entry in entries {
        match (entry.requirement.as_str(), &entry.status) {
            (REQUIREMENT_PRESENT, LinuxKeyCustodyEntryStatus::Ok { .. }) => {}
            (REQUIREMENT_ABSENT, LinuxKeyCustodyEntryStatus::AbsentAsExpected) => {}
            (REQUIREMENT_PRESENT, LinuxKeyCustodyEntryStatus::Missing { reason }) => {
                reasons.push(format!("{} missing: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, LinuxKeyCustodyEntryStatus::Invalid { reason, .. }) => {
                reasons.push(format!("{} invalid: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, LinuxKeyCustodyEntryStatus::AbsentAsExpected) => {
                reasons.push(format!(
                    "{} required but reported absent (collector bug or missing artifact)",
                    entry.label
                ));
            }
            (REQUIREMENT_PRESENT, LinuxKeyCustodyEntryStatus::Forbidden { reason }) => {
                reasons.push(format!(
                    "{} marked forbidden but requirement is present: {reason}",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, LinuxKeyCustodyEntryStatus::Forbidden { reason }) => {
                reasons.push(format!(
                    "{} forbidden but present at rest: {reason}",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, other) => {
                reasons.push(format!(
                    "{} requirement is absent but status is {other:?}",
                    entry.label
                ));
            }
            (other, _) => {
                reasons.push(format!(
                    "{} has unknown requirement {other}; expected `present` or `absent`",
                    entry.label
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

pub fn build_linux_key_custody_report(entries: Vec<LinuxKeyCustodyEntry>) -> LinuxKeyCustodyReport {
    let drift_reasons = match evaluate_linux_key_custody(&entries) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    LinuxKeyCustodyReport {
        schema_version: 1,
        overall_ok,
        entries,
        drift_reasons,
    }
}

/// Cross-platform collector. On Linux walks the canonical key custody
/// paths via `std::fs::symlink_metadata` + ownership / mode checks.
/// Off-Linux every entry is reported `Missing` with an explicit
/// "requires a Linux runtime host" reason — same off-platform
/// discipline as the runtime-acls verifier.
pub fn collect_linux_key_custody_report() -> LinuxKeyCustodyReport {
    let entries = vec![
        probe_present_directory(
            "keys directory",
            LINUX_WG_KEYS_DIR,
            0o700,
            "rustynetd",
            "rustynetd",
        ),
        probe_present_file(
            "encrypted WireGuard private key",
            LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            0o600,
            "rustynetd",
            "rustynetd",
        ),
        probe_present_file(
            "WireGuard public key",
            LINUX_WG_PUBLIC_KEY_PATH,
            0o640,
            "rustynetd",
            "rustynetd",
        ),
        probe_forbidden_path(
            "plaintext WireGuard private key (legacy)",
            LINUX_WG_PLAINTEXT_PRIVATE_KEY_PATH,
        ),
        probe_present_directory(
            "systemd credentials directory",
            LINUX_CREDENTIALS_DIR,
            0o700,
            "root",
            "root",
        ),
        probe_present_file(
            "WireGuard passphrase encrypted credential",
            LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH,
            0o600,
            "root",
            "root",
        ),
        probe_present_file(
            "signing-key passphrase encrypted credential",
            LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_PATH,
            0o600,
            "root",
            "root",
        ),
        probe_forbidden_path(
            "plaintext WireGuard passphrase (legacy)",
            LINUX_WG_PLAINTEXT_PASSPHRASE_PATH,
        ),
    ];
    build_linux_key_custody_report(entries)
}

#[cfg(target_os = "linux")]
fn probe_present_directory(
    label: &str,
    path: &str,
    expected_mode: u32,
    expected_owner: &str,
    expected_group: &str,
) -> LinuxKeyCustodyEntry {
    use std::os::unix::fs::MetadataExt;
    let p = std::path::Path::new(path);
    let metadata = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(err) => {
            return LinuxKeyCustodyEntry {
                label: label.to_string(),
                path: path.to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: LinuxKeyCustodyEntryStatus::Missing {
                    reason: format!("{path}: {err}"),
                },
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} must be a real directory at {path}"),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
        };
    }
    let (uid, gid) = (metadata.uid(), metadata.gid());
    let mode = metadata.mode();
    if let Err(reason) = check_owner_and_mode(
        label,
        mode,
        uid,
        gid,
        expected_mode,
        expected_owner,
        expected_group,
    ) {
        return LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Invalid {
                reason,
                mode,
                uid,
                gid,
            },
        };
    }
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_PRESENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::Ok { mode, uid, gid },
    }
}

#[cfg(target_os = "linux")]
fn probe_present_file(
    label: &str,
    path: &str,
    expected_mode: u32,
    expected_owner: &str,
    expected_group: &str,
) -> LinuxKeyCustodyEntry {
    use std::os::unix::fs::MetadataExt;
    let p = std::path::Path::new(path);
    let metadata = match std::fs::symlink_metadata(p) {
        Ok(m) => m,
        Err(err) => {
            return LinuxKeyCustodyEntry {
                label: label.to_string(),
                path: path.to_string(),
                requirement: REQUIREMENT_PRESENT.to_string(),
                status: LinuxKeyCustodyEntryStatus::Missing {
                    reason: format!("{path}: {err}"),
                },
            };
        }
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Invalid {
                reason: format!("{label} must be a regular file at {path}"),
                mode: metadata.mode(),
                uid: metadata.uid(),
                gid: metadata.gid(),
            },
        };
    }
    let (uid, gid) = (metadata.uid(), metadata.gid());
    let mode = metadata.mode();
    if let Err(reason) = check_owner_and_mode(
        label,
        mode,
        uid,
        gid,
        expected_mode,
        expected_owner,
        expected_group,
    ) {
        return LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Invalid {
                reason,
                mode,
                uid,
                gid,
            },
        };
    }
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_PRESENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::Ok { mode, uid, gid },
    }
}

#[cfg(target_os = "linux")]
fn probe_forbidden_path(label: &str, path: &str) -> LinuxKeyCustodyEntry {
    let p = std::path::Path::new(path);
    if std::fs::symlink_metadata(p).is_ok() {
        return LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "{label} must not exist at rest after Phase E migration; found {path}"
                ),
            },
        };
    }
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_ABSENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::AbsentAsExpected,
    }
}

#[cfg(target_os = "linux")]
fn check_owner_and_mode(
    label: &str,
    actual_mode: u32,
    actual_uid: u32,
    actual_gid: u32,
    expected_mode: u32,
    expected_owner: &str,
    expected_group: &str,
) -> Result<(), String> {
    let perms = actual_mode & 0o7777;
    if perms != expected_mode {
        return Err(format!(
            "{label} mode is 0o{perms:o}, expected 0o{expected_mode:o}"
        ));
    }
    let expected_uid = nix::unistd::User::from_name(expected_owner)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
        .ok_or_else(|| {
            format!("{label} reviewed owner {expected_owner:?} not present on this host")
        })?;
    if actual_uid != expected_uid {
        return Err(format!(
            "{label} owner uid is {actual_uid}, expected {expected_uid} ({expected_owner})"
        ));
    }
    let expected_gid = nix::unistd::Group::from_name(expected_group)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
        .ok_or_else(|| {
            format!("{label} reviewed group {expected_group:?} not present on this host")
        })?;
    if actual_gid != expected_gid {
        return Err(format!(
            "{label} group gid is {actual_gid}, expected {expected_gid} ({expected_group})"
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn probe_present_directory(
    label: &str,
    path: &str,
    _expected_mode: u32,
    _expected_owner: &str,
    _expected_group: &str,
) -> LinuxKeyCustodyEntry {
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_PRESENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::Missing {
            reason: format!(
                "{label} probe at {path} requires a Linux runtime host; \
                 linux-key-custody-check is not meaningful off-Linux"
            ),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_present_file(
    label: &str,
    path: &str,
    _expected_mode: u32,
    _expected_owner: &str,
    _expected_group: &str,
) -> LinuxKeyCustodyEntry {
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_PRESENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::Missing {
            reason: format!(
                "{label} probe at {path} requires a Linux runtime host; \
                 linux-key-custody-check is not meaningful off-Linux"
            ),
        },
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_forbidden_path(label: &str, path: &str) -> LinuxKeyCustodyEntry {
    LinuxKeyCustodyEntry {
        label: label.to_string(),
        path: path.to_string(),
        requirement: REQUIREMENT_ABSENT.to_string(),
        status: LinuxKeyCustodyEntryStatus::AbsentAsExpected,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_entry(label: &str, path: &str) -> LinuxKeyCustodyEntry {
        LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Ok {
                mode: 0o100600,
                uid: 998,
                gid: 998,
            },
        }
    }

    fn absent_entry(label: &str, path: &str) -> LinuxKeyCustodyEntry {
        LinuxKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::AbsentAsExpected,
        }
    }

    fn canonical_clean_entries() -> Vec<LinuxKeyCustodyEntry> {
        vec![
            ok_entry("keys directory", LINUX_WG_KEYS_DIR),
            ok_entry(
                "encrypted WireGuard private key",
                LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            ),
            ok_entry("WireGuard public key", LINUX_WG_PUBLIC_KEY_PATH),
            absent_entry(
                "plaintext WireGuard private key (legacy)",
                LINUX_WG_PLAINTEXT_PRIVATE_KEY_PATH,
            ),
            ok_entry("systemd credentials directory", LINUX_CREDENTIALS_DIR),
            ok_entry(
                "WireGuard passphrase encrypted credential",
                LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH,
            ),
            ok_entry(
                "signing-key passphrase encrypted credential",
                LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_PATH,
            ),
            absent_entry(
                "plaintext WireGuard passphrase (legacy)",
                LINUX_WG_PLAINTEXT_PASSPHRASE_PATH,
            ),
        ]
    }

    #[test]
    fn evaluator_accepts_canonical_present_set() {
        evaluate_linux_key_custody(&canonical_clean_entries())
            .expect("clean entries must validate");
    }

    #[test]
    fn evaluator_rejects_empty_entries() {
        let reasons = evaluate_linux_key_custody(&[]).expect_err("empty entries must reject");
        assert!(reasons.iter().any(|r| r.contains("no entries")));
    }

    #[test]
    fn evaluator_rejects_missing_required_artifact() {
        let entries = vec![LinuxKeyCustodyEntry {
            label: "encrypted WireGuard private key".to_string(),
            path: LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Missing {
                reason: "ENOENT".to_string(),
            },
        }];
        let reasons =
            evaluate_linux_key_custody(&entries).expect_err("missing artifact must reject");
        assert!(
            reasons.iter().any(|r| r.contains("missing")),
            "rejection must cite missing: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_forbidden_plaintext_key_at_rest() {
        let entries = vec![LinuxKeyCustodyEntry {
            label: "plaintext WireGuard private key (legacy)".to_string(),
            path: LINUX_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_string(),
            requirement: REQUIREMENT_ABSENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Forbidden {
                reason: "must not exist at rest".to_string(),
            },
        }];
        let reasons =
            evaluate_linux_key_custody(&entries).expect_err("forbidden plaintext key must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("forbidden but present at rest")),
            "rejection must surface forbidden-at-rest: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_invalid_mode_or_owner() {
        let entries = vec![LinuxKeyCustodyEntry {
            label: "encrypted WireGuard private key".to_string(),
            path: LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_string(),
            requirement: REQUIREMENT_PRESENT.to_string(),
            status: LinuxKeyCustodyEntryStatus::Invalid {
                reason: "mode is 0o644, expected 0o600".to_string(),
                mode: 0o100644,
                uid: 998,
                gid: 998,
            },
        }];
        let reasons = evaluate_linux_key_custody(&entries).expect_err("invalid mode must reject");
        assert!(
            reasons.iter().any(|r| r.contains("invalid")),
            "rejection must cite invalid: {reasons:?}"
        );
    }

    #[test]
    fn build_report_marks_overall_ok_for_clean_entries() {
        let report = build_linux_key_custody_report(canonical_clean_entries());
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
        assert_eq!(report.entries.len(), 8);
    }

    // ---- L6: passphrase + credential custody pinning ------------------

    /// Missing wg_key_passphrase.cred is a hard fail-closed condition:
    /// without the encrypted credential, systemd cannot load the
    /// passphrase and the daemon cannot unwrap the runtime WG private
    /// key. Pin it as a required Present entry.
    #[test]
    fn evaluator_rejects_missing_wg_key_passphrase_credential() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH {
                entry.status = LinuxKeyCustodyEntryStatus::Missing {
                    reason: "ENOENT".to_string(),
                };
            }
        }
        let reasons = evaluate_linux_key_custody(&entries)
            .expect_err("missing wg passphrase credential must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("WireGuard passphrase") && r.contains("missing")),
            "rejection must name passphrase credential: {reasons:?}"
        );
    }

    /// Missing signing_key_passphrase.cred is a hard fail: without it,
    /// the membership-owner cannot issue signed bundles. Pin Present.
    #[test]
    fn evaluator_rejects_missing_signing_key_passphrase_credential() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_PATH {
                entry.status = LinuxKeyCustodyEntryStatus::Missing {
                    reason: "ENOENT".to_string(),
                };
            }
        }
        let reasons = evaluate_linux_key_custody(&entries)
            .expect_err("missing signing-key passphrase credential must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("signing-key passphrase") && r.contains("missing")),
            "rejection must name signing-key passphrase credential: {reasons:?}"
        );
    }

    /// Credentials directory must be 0700 root:root. A group-read mode
    /// (0750) on a root-owned dir would expose .cred bytes to any
    /// process whose primary or supplementary gid includes the
    /// credential dir's group — must reject.
    #[test]
    fn evaluator_rejects_credentials_dir_wrong_mode() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_CREDENTIALS_DIR {
                entry.status = LinuxKeyCustodyEntryStatus::Invalid {
                    reason: "mode is 0o750, expected 0o700".to_string(),
                    mode: 0o40750,
                    uid: 0,
                    gid: 0,
                };
            }
        }
        let reasons =
            evaluate_linux_key_custody(&entries).expect_err("0750 credentials dir must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("systemd credentials directory") && r.contains("invalid")),
            "rejection must name credentials dir: {reasons:?}"
        );
    }

    /// .cred files must be 0600. 0640 would let any group-member read
    /// the encrypted blob and start an offline attack. Reject.
    #[test]
    fn evaluator_rejects_wg_passphrase_credential_group_readable_mode() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH {
                entry.status = LinuxKeyCustodyEntryStatus::Invalid {
                    reason: "mode is 0o640, expected 0o600".to_string(),
                    mode: 0o100640,
                    uid: 0,
                    gid: 0,
                };
            }
        }
        let reasons = evaluate_linux_key_custody(&entries)
            .expect_err("0640 wg passphrase credential must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("WireGuard passphrase") && r.contains("invalid")),
            "rejection must name passphrase credential: {reasons:?}"
        );
    }

    /// .cred files must be owned by root, NOT rustynetd. systemd loads
    /// them as root, then drops them into the credential dir for the
    /// service user. If the file at rest is owned by rustynetd, then
    /// a rustynetd-context compromise can rewrite the encrypted blob.
    #[test]
    fn evaluator_rejects_wg_passphrase_credential_owned_by_rustynetd() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH {
                entry.status = LinuxKeyCustodyEntryStatus::Invalid {
                    reason: "owner uid is 998, expected 0 (root)".to_string(),
                    mode: 0o100600,
                    uid: 998,
                    gid: 998,
                };
            }
        }
        let reasons = evaluate_linux_key_custody(&entries)
            .expect_err("rustynetd-owned wg passphrase credential must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("WireGuard passphrase") && r.contains("invalid")),
            "rejection must surface rustynetd-owned passphrase credential: {reasons:?}"
        );
    }

    /// A plaintext passphrase at /var/lib/rustynet/keys/wireguard.passphrase
    /// must be flagged forbidden. Production must keep passphrase
    /// material inside systemd's encrypted-credential store; a
    /// plaintext copy in the rustynetd-owned keys dir is a leak path
    /// that survives reboot.
    #[test]
    fn evaluator_rejects_legacy_plaintext_passphrase_present_at_rest() {
        let mut entries = canonical_clean_entries();
        for entry in entries.iter_mut() {
            if entry.path == LINUX_WG_PLAINTEXT_PASSPHRASE_PATH {
                entry.status = LinuxKeyCustodyEntryStatus::Forbidden {
                    reason: format!(
                        "must not exist at rest after Phase E migration; found {}",
                        LINUX_WG_PLAINTEXT_PASSPHRASE_PATH
                    ),
                };
            }
        }
        let reasons = evaluate_linux_key_custody(&entries)
            .expect_err("plaintext passphrase at rest must reject");
        assert!(
            reasons
                .iter()
                .any(|r| r.contains("plaintext WireGuard passphrase")
                    && r.contains("forbidden but present at rest")),
            "rejection must name plaintext passphrase: {reasons:?}"
        );
    }

    /// Snapshot: the canonical entry list shape is exactly 8 entries.
    /// Pins the contract so a future refactor that silently removes a
    /// required entry trips a named failure rather than silently
    /// relaxing the verifier.
    #[test]
    fn canonical_entry_list_pinned_at_eight_entries() {
        let entries = canonical_clean_entries();
        let paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
        let expected: Vec<&str> = vec![
            LINUX_WG_KEYS_DIR,
            LINUX_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            LINUX_WG_PUBLIC_KEY_PATH,
            LINUX_WG_PLAINTEXT_PRIVATE_KEY_PATH,
            LINUX_CREDENTIALS_DIR,
            LINUX_WG_KEY_PASSPHRASE_CREDENTIAL_PATH,
            LINUX_SIGNING_KEY_PASSPHRASE_CREDENTIAL_PATH,
            LINUX_WG_PLAINTEXT_PASSPHRASE_PATH,
        ];
        assert_eq!(paths, expected, "canonical entry list shape drifted");
    }

    #[test]
    fn report_serde_round_trips() {
        let report =
            build_linux_key_custody_report(vec![ok_entry("keys directory", LINUX_WG_KEYS_DIR)]);
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxKeyCustodyReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collector_off_linux_marks_required_entries_missing() {
        let report = collect_linux_key_custody_report();
        assert!(!report.overall_ok);
        // Required (present) entries should report Missing with the
        // off-Linux blocker reason. The forbidden plaintext-key entries
        // are correctly absent off-Linux too.
        assert_eq!(report.entries.len(), 8);
    }
}
