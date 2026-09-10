#![allow(clippy::result_large_err)]

//! macOS key-custody verifier.
//!
//! macOS parity for `linux_key_custody`. Validates that on-disk key
//! material on a macOS runtime host matches the reviewed custody contract:
//!
//! * the encrypted `WireGuard` private key exists at
//!   `/usr/local/var/rustynet/keys/wireguard.key.enc`, owned by
//!   `rustynetd:rustynetd`, mode `0600`;
//! * the `WireGuard` public key exists at
//!   `/usr/local/var/rustynet/keys/wireguard.pub`, owned by
//!   `rustynetd:rustynetd`, mode `0640` or `0600`;
//! * the keys directory is a real directory owned by `rustynetd:rustynetd`,
//!   mode `0700`;
//! * the plaintext private key must be absent at rest.
//! * the plaintext passphrase file must be absent at rest; passphrase custody
//!   must use the reviewed macOS Keychain account path.
//! * the passphrase Keychain item itself is PRESENT: the System keychain holds
//!   a generic-password item for the reviewed service and the account the
//!   launchd plist hands the daemon (B5, 2026-09-10 — before this the report
//!   was keychain-blind: five file paths, and the Keychain claim above was
//!   never probed). The probe is attribute-only; no secret is loaded.
//!
//! Wired through the CLI as `rustynetd macos-key-custody-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches the `KeyCustody` op here.

use serde::{Deserialize, Serialize};

pub const MACOS_WG_KEYS_DIR: &str = "/usr/local/var/rustynet/keys";
pub const MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH: &str =
    "/usr/local/var/rustynet/keys/wireguard.key.enc";
pub const MACOS_WG_PUBLIC_KEY_PATH: &str = "/usr/local/var/rustynet/keys/wireguard.pub";
/// Legacy plaintext private key — must NOT exist at rest after migration.
pub const MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH: &str = "/usr/local/var/rustynet/keys/wireguard.key";
/// Legacy plaintext passphrase — must NOT exist at rest after migration.
pub const MACOS_WG_PLAINTEXT_PASSPHRASE_PATH: &str =
    "/usr/local/var/rustynet/keys/wireguard.passphrase";
/// The reviewed Keychain service under which the daemon stores/reads the
/// WireGuard key passphrase (mirrors `key_material::MACOS_PASSPHRASE_KEYCHAIN_SERVICE`
/// and the launchd `RUSTYNET_MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE` value the
/// service-hardening check pins).
pub const MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE: &str = "net.rustynet.wg-key-passphrase";
/// Launchd environment key naming the Keychain account; the same key
/// `macos_service_hardening` requires in the reviewed plist.
pub const MACOS_WG_PASSPHRASE_KEYCHAIN_ACCOUNT_ENV: &str =
    "RUSTYNET_WG_KEY_PASSPHRASE_KEYCHAIN_ACCOUNT";
/// Label of the Keychain entry in the report (stable: the orchestrator's
/// evaluator pins it).
pub const MACOS_WG_PASSPHRASE_KEYCHAIN_ENTRY_LABEL: &str = "keychain passphrase item";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MacosKeyCustodyEntryStatus {
    Ok {
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Missing {
        reason: String,
    },
    Invalid {
        reason: String,
        mode: u32,
        uid: u32,
        gid: u32,
    },
    Forbidden {
        reason: String,
    },
    AbsentAsExpected,
    /// A Keychain item (not a file) was found for the reviewed service and
    /// account. Attribute-only: the secret was never loaded.
    KeychainPresent {
        service: String,
        account: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosKeyCustodyEntry {
    pub label: String,
    pub path: String,
    pub expected: String,
    #[serde(flatten)]
    pub status: MacosKeyCustodyEntryStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosKeyCustodyReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub entries: Vec<MacosKeyCustodyEntry>,
    pub drift_reasons: Vec<String>,
}

const REQUIREMENT_PRESENT: &str = "present";
const REQUIREMENT_ABSENT: &str = "absent";

/// Pure evaluator: re-derives drift reasons from per-entry statuses and
/// requirements. This deliberately aggregates every drift in one pass so a
/// macOS operator sees the whole custody problem set instead of the first
/// failure only.
pub fn evaluate_macos_key_custody(entries: &[MacosKeyCustodyEntry]) -> Result<(), Vec<String>> {
    let mut reasons = Vec::new();
    if entries.is_empty() {
        reasons.push("key custody report contains no entries".to_owned());
        return Err(reasons);
    }

    for entry in entries {
        match (entry.expected.as_str(), &entry.status) {
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::Ok { .. }) => {}
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::KeychainPresent { .. }) => {}
            (REQUIREMENT_ABSENT, MacosKeyCustodyEntryStatus::AbsentAsExpected) => {}
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::Missing { reason }) => {
                reasons.push(format!("{} missing: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::Invalid { reason, .. }) => {
                reasons.push(format!("{} invalid: {reason}", entry.label));
            }
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::AbsentAsExpected) => {
                reasons.push(format!(
                    "{} required but reported absent (collector bug or missing artifact)",
                    entry.label
                ));
            }
            (REQUIREMENT_PRESENT, MacosKeyCustodyEntryStatus::Forbidden { reason }) => {
                reasons.push(format!(
                    "{} marked forbidden but requirement is present: {reason}",
                    entry.label
                ));
            }
            (REQUIREMENT_ABSENT, MacosKeyCustodyEntryStatus::Forbidden { reason }) => {
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
                    "{} has unknown expected requirement {other}; expected `present` or `absent`",
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

pub fn build_macos_key_custody_report(entries: Vec<MacosKeyCustodyEntry>) -> MacosKeyCustodyReport {
    let drift_reasons = match evaluate_macos_key_custody(&entries) {
        Ok(()) => Vec::new(),
        Err(reasons) => reasons,
    };
    let overall_ok = drift_reasons.is_empty();
    MacosKeyCustodyReport {
        schema_version: 1,
        overall_ok,
        entries,
        drift_reasons,
    }
}

pub fn collect_macos_key_custody_report() -> MacosKeyCustodyReport {
    build_macos_key_custody_report(build_entries())
}

#[cfg(target_os = "macos")]
fn build_entries() -> Vec<MacosKeyCustodyEntry> {
    vec![
        probe_required_dir(
            MACOS_WG_KEYS_DIR,
            "keys dir",
            0o700,
            "rustynetd",
            "rustynetd",
        ),
        probe_required_file(
            MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            "encrypted private key",
            &[0o600],
            "rustynetd",
            "rustynetd",
        ),
        probe_required_file(
            MACOS_WG_PUBLIC_KEY_PATH,
            "public key",
            &[0o640, 0o600],
            "rustynetd",
            "rustynetd",
        ),
        probe_forbidden_file(
            MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH,
            "plaintext private key (forbidden)",
        ),
        probe_forbidden_file(
            MACOS_WG_PLAINTEXT_PASSPHRASE_PATH,
            "plaintext key passphrase (forbidden)",
        ),
        probe_passphrase_keychain_item(),
    ]
}

/// Where the daemon is told its Keychain account: the reviewed launchd plist
/// first (that is what the running daemon sees), the probe's own environment
/// second (an operator running the check by hand under the same env).
#[cfg(target_os = "macos")]
fn resolve_passphrase_keychain_account() -> Result<String, String> {
    let from_plist =
        std::fs::read_to_string(crate::macos_service_hardening::REVIEWED_LAUNCHDAEMON_PLIST)
            .ok()
            .and_then(|xml| {
                crate::macos_service_hardening::parse_plist_string_dict(
                    &xml,
                    "EnvironmentVariables",
                )
                .remove(MACOS_WG_PASSPHRASE_KEYCHAIN_ACCOUNT_ENV)
            });
    let account = match from_plist {
        Some(account) => account,
        None => std::env::var(MACOS_WG_PASSPHRASE_KEYCHAIN_ACCOUNT_ENV).map_err(|_| {
            format!(
                "no Keychain account: {} has no {MACOS_WG_PASSPHRASE_KEYCHAIN_ACCOUNT_ENV} and the \
                 probe environment does not set it",
                crate::macos_service_hardening::REVIEWED_LAUNCHDAEMON_PLIST
            )
        })?,
    };
    keychain_entry_for_account(&account)
}

/// Validates the account the same way `key_material` does before it reaches
/// the Keychain API (non-empty, trimmed, bounded, no control characters).
fn keychain_entry_for_account(raw: &str) -> Result<String, String> {
    let account = raw.trim();
    if account.is_empty() || account != raw {
        return Err("Keychain account must be non-empty with no surrounding whitespace".to_owned());
    }
    if account.len() > 128 {
        return Err("Keychain account exceeds max length (128)".to_owned());
    }
    if account.chars().any(|c| c.is_control()) {
        return Err("Keychain account must not contain control characters".to_owned());
    }
    Ok(account.to_owned())
}

/// The entry's `path` is a locator, not a filesystem path.
fn keychain_entry_path(account: &str) -> String {
    format!("keychain:System/{MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}/{account}")
}

#[cfg(target_os = "macos")]
fn probe_passphrase_keychain_item() -> MacosKeyCustodyEntry {
    let label = MACOS_WG_PASSPHRASE_KEYCHAIN_ENTRY_LABEL;
    let account = match resolve_passphrase_keychain_account() {
        Ok(account) => account,
        Err(reason) => {
            return MacosKeyCustodyEntry {
                label: label.to_owned(),
                path: keychain_entry_path("<unresolved>"),
                expected: "present".to_owned(),
                status: MacosKeyCustodyEntryStatus::Missing { reason },
            };
        }
    };
    keychain_probe_entry(
        &account,
        rustynet_crypto::macos_system_keychain_generic_password_present(
            MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE,
            &account,
        )
        .map_err(|err| err.to_string()),
    )
}

/// Pure mapping from a probe result to an entry, so the shape is testable
/// off-macOS: `Ok(true)` → present, `Ok(false)` → missing, `Err` → missing
/// naming the keychain failure (never "present" on an unreadable keychain).
fn keychain_probe_entry(account: &str, probe: Result<bool, String>) -> MacosKeyCustodyEntry {
    let label = MACOS_WG_PASSPHRASE_KEYCHAIN_ENTRY_LABEL.to_owned();
    let path = keychain_entry_path(account);
    let expected = "present".to_owned();
    let status = match probe {
        Ok(true) => MacosKeyCustodyEntryStatus::KeychainPresent {
            service: MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE.to_owned(),
            account: account.to_owned(),
        },
        Ok(false) => MacosKeyCustodyEntryStatus::Missing {
            reason: format!(
                "no generic-password item for service '{MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}' \
                 account '{account}' in the System keychain"
            ),
        },
        Err(err) => MacosKeyCustodyEntryStatus::Missing {
            reason: format!(
                "System keychain probe for service '{MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE}' \
                 account '{account}' failed: {err}"
            ),
        },
    };
    MacosKeyCustodyEntry {
        label,
        path,
        expected,
        status,
    }
}

#[cfg(not(target_os = "macos"))]
fn build_entries() -> Vec<MacosKeyCustodyEntry> {
    let off_platform_reason = "requires a macOS runtime host; macos-key-custody-check \
                               is not meaningful off-macOS";
    vec![
        MacosKeyCustodyEntry {
            label: "keys dir".to_string(),
            path: MACOS_WG_KEYS_DIR.to_string(),
            expected: "present".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
        MacosKeyCustodyEntry {
            label: "encrypted private key".to_string(),
            path: MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_string(),
            expected: "present".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
        MacosKeyCustodyEntry {
            label: "public key".to_string(),
            path: MACOS_WG_PUBLIC_KEY_PATH.to_string(),
            expected: "present".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
        MacosKeyCustodyEntry {
            label: "plaintext private key (forbidden)".to_string(),
            path: MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_string(),
            expected: "absent".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
        MacosKeyCustodyEntry {
            label: "plaintext key passphrase (forbidden)".to_string(),
            path: MACOS_WG_PLAINTEXT_PASSPHRASE_PATH.to_string(),
            expected: "absent".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
        MacosKeyCustodyEntry {
            label: MACOS_WG_PASSPHRASE_KEYCHAIN_ENTRY_LABEL.to_string(),
            path: keychain_entry_path("<off-platform>"),
            expected: "present".to_string(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: off_platform_reason.to_string(),
            },
        },
    ]
}

#[cfg(target_os = "macos")]
fn resolve_uid(username: &str) -> Option<u32> {
    nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|u| u.uid.as_raw())
}

#[cfg(target_os = "macos")]
fn resolve_gid(groupname: &str) -> Option<u32> {
    nix::unistd::Group::from_name(groupname)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

#[cfg(target_os = "macos")]
fn probe_required_dir(
    path: &'static str,
    label: &'static str,
    mode: u32,
    owner: &str,
    group: &str,
) -> MacosKeyCustodyEntry {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) => {
            return MacosKeyCustodyEntry {
                label: label.to_owned(),
                path: path.to_owned(),
                expected: "present".to_owned(),
                status: MacosKeyCustodyEntryStatus::Missing {
                    reason: format!("{label} not found at {path}: {err}"),
                },
            };
        }
    };
    let uid = meta.uid();
    let gid = meta.gid();
    let actual_mode = meta.mode() & 0o7777;
    let expected_uid = resolve_uid(owner).unwrap_or(u32::MAX);
    let expected_gid = resolve_gid(group).unwrap_or(u32::MAX);
    if meta.file_type().is_symlink()
        || !meta.is_dir()
        || actual_mode != mode
        || uid != expected_uid
        || gid != expected_gid
    {
        return MacosKeyCustodyEntry {
            label: label.to_owned(),
            path: path.to_owned(),
            expected: "present".to_owned(),
            status: MacosKeyCustodyEntryStatus::Invalid {
                reason: format!(
                    "{label} mode/owner/type mismatch: mode=0o{actual_mode:o} uid={uid} gid={gid}"
                ),
                mode: actual_mode,
                uid,
                gid,
            },
        };
    }
    MacosKeyCustodyEntry {
        label: label.to_owned(),
        path: path.to_owned(),
        expected: "present".to_owned(),
        status: MacosKeyCustodyEntryStatus::Ok {
            mode: actual_mode,
            uid,
            gid,
        },
    }
}

#[cfg(target_os = "macos")]
fn probe_required_file(
    path: &'static str,
    label: &'static str,
    allowed_modes: &[u32],
    owner: &str,
    group: &str,
) -> MacosKeyCustodyEntry {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) => {
            return MacosKeyCustodyEntry {
                label: label.to_owned(),
                path: path.to_owned(),
                expected: "present".to_owned(),
                status: MacosKeyCustodyEntryStatus::Missing {
                    reason: format!("{label} not found at {path}: {err}"),
                },
            };
        }
    };
    let uid = meta.uid();
    let gid = meta.gid();
    let actual_mode = meta.mode() & 0o7777;
    let expected_uid = resolve_uid(owner).unwrap_or(u32::MAX);
    let expected_gid = resolve_gid(group).unwrap_or(u32::MAX);
    let mode_ok = allowed_modes.contains(&actual_mode);
    if meta.file_type().is_symlink()
        || !meta.is_file()
        || !mode_ok
        || uid != expected_uid
        || gid != expected_gid
    {
        return MacosKeyCustodyEntry {
            label: label.to_owned(),
            path: path.to_owned(),
            expected: "present".to_owned(),
            status: MacosKeyCustodyEntryStatus::Invalid {
                reason: format!(
                    "{label} mode/owner/type mismatch: mode=0o{actual_mode:o} uid={uid} gid={gid}"
                ),
                mode: actual_mode,
                uid,
                gid,
            },
        };
    }
    MacosKeyCustodyEntry {
        label: label.to_owned(),
        path: path.to_owned(),
        expected: "present".to_owned(),
        status: MacosKeyCustodyEntryStatus::Ok {
            mode: actual_mode,
            uid,
            gid,
        },
    }
}

#[cfg(target_os = "macos")]
fn probe_forbidden_file(path: &'static str, label: &'static str) -> MacosKeyCustodyEntry {
    match std::fs::symlink_metadata(path) {
        Err(_) => MacosKeyCustodyEntry {
            label: label.to_owned(),
            path: path.to_owned(),
            expected: REQUIREMENT_ABSENT.to_owned(),
            status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
        },
        Ok(_) => MacosKeyCustodyEntry {
            label: label.to_owned(),
            path: path.to_owned(),
            expected: REQUIREMENT_ABSENT.to_owned(),
            status: MacosKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "plaintext key material at {path} must not exist at rest — \
                     Phase E migrated runtime key custody to encrypted-at-rest"
                ),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // B5: the Keychain entry is part of the contract — a report where every
    // FILE entry is healthy but the passphrase item is absent must not pass.
    #[test]
    fn keychain_probe_present_is_healthy_and_absent_or_failed_is_missing() {
        let present = keychain_probe_entry("wg-passphrase-daemon-local", Ok(true));
        assert_eq!(present.label, MACOS_WG_PASSPHRASE_KEYCHAIN_ENTRY_LABEL);
        assert_eq!(present.expected, "present");
        assert_eq!(
            present.path,
            "keychain:System/net.rustynet.wg-key-passphrase/wg-passphrase-daemon-local"
        );
        assert!(matches!(
            &present.status,
            MacosKeyCustodyEntryStatus::KeychainPresent { service, account }
                if service == MACOS_WG_PASSPHRASE_KEYCHAIN_SERVICE
                    && account == "wg-passphrase-daemon-local"
        ));
        assert!(evaluate_macos_key_custody(std::slice::from_ref(&present)).is_ok());

        let absent = keychain_probe_entry("wg-passphrase-daemon-local", Ok(false));
        assert!(matches!(
            &absent.status,
            MacosKeyCustodyEntryStatus::Missing { reason } if reason.contains("no generic-password item")
        ));
        let reasons = evaluate_macos_key_custody(std::slice::from_ref(&absent))
            .expect_err("an absent Keychain item is custody drift");
        assert!(
            reasons[0].contains("keychain passphrase item missing"),
            "{reasons:?}"
        );

        // An unreadable keychain is "unknown", and unknown is never "present".
        let failed = keychain_probe_entry("acct", Err("keychain locked".to_owned()));
        assert!(matches!(
            &failed.status,
            MacosKeyCustodyEntryStatus::Missing { reason }
                if reason.contains("probe") && reason.contains("keychain locked")
        ));
        assert!(evaluate_macos_key_custody(std::slice::from_ref(&failed)).is_err());
    }

    #[test]
    fn keychain_present_under_an_absent_requirement_is_drift() {
        let mut entry = keychain_probe_entry("acct", Ok(true));
        entry.expected = "absent".to_owned();
        let reasons = evaluate_macos_key_custody(std::slice::from_ref(&entry))
            .expect_err("KeychainPresent only satisfies a present requirement");
        assert!(
            reasons[0].contains("requirement is absent but status is"),
            "{reasons:?}"
        );
    }

    #[test]
    fn keychain_account_validation_matches_key_material_rules() {
        assert_eq!(
            keychain_entry_for_account("wg-passphrase-daemon-local").as_deref(),
            Ok("wg-passphrase-daemon-local")
        );
        assert!(keychain_entry_for_account("").is_err());
        assert!(keychain_entry_for_account(" padded").is_err());
        assert!(keychain_entry_for_account("ctl\u{7}char").is_err());
        assert!(keychain_entry_for_account(&"a".repeat(129)).is_err());
    }

    #[test]
    fn keychain_entry_survives_serde_round_trip() {
        let report = build_macos_key_custody_report(vec![keychain_probe_entry("acct", Ok(true))]);
        assert!(report.overall_ok);
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"status\":\"keychain_present\""), "{json}");
        let parsed: MacosKeyCustodyReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = MacosKeyCustodyReport {
            schema_version: 1,
            overall_ok: true,
            entries: vec![MacosKeyCustodyEntry {
                label: "keys dir".to_owned(),
                path: MACOS_WG_KEYS_DIR.to_owned(),
                expected: "present".to_owned(),
                status: MacosKeyCustodyEntryStatus::Ok {
                    mode: 0o700,
                    uid: 500,
                    gid: 500,
                },
            }],
            drift_reasons: Vec::new(),
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosKeyCustodyReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn collect_off_macos_marks_entries_missing() {
        let report = collect_macos_key_custody_report();
        assert!(!report.overall_ok);
        assert_eq!(report.entries.len(), 6);
        assert_eq!(report.drift_reasons.len(), 6);
        for entry in &report.entries {
            assert!(
                matches!(
                    &entry.status,
                    MacosKeyCustodyEntryStatus::Missing { reason } if reason.contains("macOS runtime host")
                ),
                "off-macOS entry must be Missing with runtime-host reason: {entry:?}"
            );
        }
    }

    #[test]
    fn paths_are_under_state_root() {
        assert!(MACOS_WG_KEYS_DIR.starts_with("/usr/local/var/rustynet"));
        assert!(MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
        assert!(MACOS_WG_PUBLIC_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
        assert!(MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
        assert!(MACOS_WG_PLAINTEXT_PASSPHRASE_PATH.starts_with(MACOS_WG_KEYS_DIR));
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    fn keys_dir_entry() -> MacosKeyCustodyEntry {
        MacosKeyCustodyEntry {
            label: "keys dir".to_owned(),
            path: MACOS_WG_KEYS_DIR.to_owned(),
            expected: "present".to_owned(),
            status: MacosKeyCustodyEntryStatus::Ok {
                mode: 0o700,
                uid: 500,
                gid: 500,
            },
        }
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        // Pin the wire-format schema_version so an accidental bump
        // forces a deliberate review.
        let report = MacosKeyCustodyReport {
            schema_version: 1,
            overall_ok: true,
            entries: vec![keys_dir_entry()],
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
    fn reviewed_entry_paths_pinned_in_canonical_order() {
        // Snapshot the five reviewed entries that the (off-platform)
        // collector emits today. A future refactor that drops one,
        // reorders the set, or adds a new reviewed artifact has to
        // update this snapshot in the same commit.
        #[cfg(not(target_os = "macos"))]
        {
            let report = collect_macos_key_custody_report();
            let observed: Vec<(&str, &str)> = report
                .entries
                .iter()
                .map(|e| (e.label.as_str(), e.path.as_str()))
                .collect();
            assert_eq!(
                observed,
                vec![
                    ("keys dir", MACOS_WG_KEYS_DIR),
                    ("encrypted private key", MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH),
                    ("public key", MACOS_WG_PUBLIC_KEY_PATH),
                    (
                        "plaintext private key (forbidden)",
                        MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH
                    ),
                    (
                        "plaintext key passphrase (forbidden)",
                        MACOS_WG_PLAINTEXT_PASSPHRASE_PATH,
                    ),
                ]
            );
        }
        // The path-constants snapshot (label-independent) is unconditional
        // so the assertion runs on macOS too.
        let canonical_paths = [
            MACOS_WG_KEYS_DIR,
            MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH,
            MACOS_WG_PUBLIC_KEY_PATH,
            MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH,
            MACOS_WG_PLAINTEXT_PASSPHRASE_PATH,
        ];
        for path in canonical_paths {
            assert!(
                path.starts_with("/usr/local/var/rustynet"),
                "all reviewed paths must live under the reviewed state root: {path}"
            );
        }
    }

    #[test]
    fn entry_status_missing_round_trips_through_serde() {
        let entry = MacosKeyCustodyEntry {
            label: "keys dir".to_owned(),
            path: MACOS_WG_KEYS_DIR.to_owned(),
            expected: "present".to_owned(),
            status: MacosKeyCustodyEntryStatus::Missing {
                reason: "stat failed: ENOENT".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"missing\""), "tag: {body}");
        let parsed: MacosKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_invalid_round_trips_through_serde() {
        let entry = MacosKeyCustodyEntry {
            label: "encrypted private key".to_owned(),
            path: MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned(),
            expected: "present".to_owned(),
            status: MacosKeyCustodyEntryStatus::Invalid {
                reason: "mode 0o644, expected 0o600".to_owned(),
                mode: 0o100644,
                uid: 500,
                gid: 500,
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"invalid\""), "tag: {body}");
        let parsed: MacosKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_forbidden_round_trips_through_serde() {
        let entry = MacosKeyCustodyEntry {
            label: "plaintext private key (forbidden)".to_owned(),
            path: MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_owned(),
            expected: "absent".to_owned(),
            status: MacosKeyCustodyEntryStatus::Forbidden {
                reason: "must not exist at rest after Phase E".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"forbidden\""), "tag: {body}");
        let parsed: MacosKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_absent_as_expected_round_trips_through_serde() {
        let entry = MacosKeyCustodyEntry {
            label: "plaintext private key (forbidden)".to_owned(),
            path: MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_owned(),
            expected: "absent".to_owned(),
            status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(
            body.contains("\"status\":\"absent_as_expected\""),
            "tag: {body}"
        );
        let parsed: MacosKeyCustodyEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn entry_status_rejects_unknown_tag() {
        // #[serde(tag = "status", rename_all = "snake_case")] — an
        // unknown tag must fail closed.
        let body = r#"{"label":"keys dir","path":"/usr/local/var/rustynet/keys","expected":"present","status":"observe_only","reason":"placeholder"}"#;
        let err = serde_json::from_str::<MacosKeyCustodyEntry>(body)
            .expect_err("unknown tag must fail closed");
        assert!(
            err.to_string().contains("observe_only") || err.to_string().contains("unknown variant"),
            "error must reference unknown tag or 'unknown variant': {err}"
        );
    }

    #[test]
    fn report_overall_ok_is_false_when_any_entry_is_invalid() {
        let report = build_macos_key_custody_report(vec![
            keys_dir_entry(),
            MacosKeyCustodyEntry {
                label: "encrypted private key".to_owned(),
                path: MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned(),
                expected: "present".to_owned(),
                status: MacosKeyCustodyEntryStatus::Invalid {
                    reason: "mode drift".to_owned(),
                    mode: 0o100644,
                    uid: 500,
                    gid: 500,
                },
            },
        ]);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("encrypted private key invalid")),
            "invalid key drift must be reported: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn report_overall_ok_is_true_when_only_ok_and_absent_as_expected_present() {
        let report = build_macos_key_custody_report(vec![
            keys_dir_entry(),
            MacosKeyCustodyEntry {
                label: "plaintext private key (forbidden)".to_owned(),
                path: MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_owned(),
                expected: "absent".to_owned(),
                status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
            },
        ]);
        assert!(report.overall_ok);
        assert!(report.drift_reasons.is_empty());
    }

    #[test]
    fn evaluator_rejects_empty_entry_set() {
        let reasons =
            evaluate_macos_key_custody(&[]).expect_err("empty key custody report must reject");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("contains no entries")),
            "empty report rejection must be explicit: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_plaintext_passphrase_present_at_rest() {
        let entries = vec![
            keys_dir_entry(),
            MacosKeyCustodyEntry {
                label: "plaintext key passphrase (forbidden)".to_owned(),
                path: MACOS_WG_PLAINTEXT_PASSPHRASE_PATH.to_owned(),
                expected: REQUIREMENT_ABSENT.to_owned(),
                status: MacosKeyCustodyEntryStatus::Forbidden {
                    reason: "plaintext passphrase found".to_owned(),
                },
            },
        ];
        let reasons =
            evaluate_macos_key_custody(&entries).expect_err("plaintext passphrase must reject");
        assert!(
            reasons.iter().any(|reason| {
                reason.contains("plaintext key passphrase")
                    && reason.contains("forbidden but present at rest")
            }),
            "plaintext passphrase rejection must be named: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let entries = vec![
            MacosKeyCustodyEntry {
                label: "encrypted private key".to_owned(),
                path: MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned(),
                expected: REQUIREMENT_PRESENT.to_owned(),
                status: MacosKeyCustodyEntryStatus::Invalid {
                    reason: "mode is 0o644".to_owned(),
                    mode: 0o100644,
                    uid: 500,
                    gid: 500,
                },
            },
            MacosKeyCustodyEntry {
                label: "public key".to_owned(),
                path: MACOS_WG_PUBLIC_KEY_PATH.to_owned(),
                expected: REQUIREMENT_PRESENT.to_owned(),
                status: MacosKeyCustodyEntryStatus::Missing {
                    reason: "ENOENT".to_owned(),
                },
            },
            MacosKeyCustodyEntry {
                label: "plaintext key passphrase (forbidden)".to_owned(),
                path: MACOS_WG_PLAINTEXT_PASSPHRASE_PATH.to_owned(),
                expected: REQUIREMENT_ABSENT.to_owned(),
                status: MacosKeyCustodyEntryStatus::Forbidden {
                    reason: "plaintext passphrase found".to_owned(),
                },
            },
        ];
        let reasons = evaluate_macos_key_custody(&entries).expect_err("three drifts must reject");
        assert_eq!(
            reasons.len(),
            3,
            "must report one reason per drift: {reasons:?}"
        );
        assert!(reasons.iter().any(|reason| reason.contains("invalid")));
        assert!(reasons.iter().any(|reason| reason.contains("missing")));
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("forbidden but present"))
        );
    }

    #[test]
    fn evaluator_rejects_unknown_expected_requirement() {
        let entries = vec![MacosKeyCustodyEntry {
            label: "encrypted private key".to_owned(),
            path: MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.to_owned(),
            expected: "present-but-optional".to_owned(),
            status: MacosKeyCustodyEntryStatus::Ok {
                mode: 0o100600,
                uid: 500,
                gid: 500,
            },
        }];
        let reasons =
            evaluate_macos_key_custody(&entries).expect_err("unknown requirement must reject");
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("unknown expected requirement")),
            "unknown requirement rejection must be explicit: {reasons:?}"
        );
    }
}
