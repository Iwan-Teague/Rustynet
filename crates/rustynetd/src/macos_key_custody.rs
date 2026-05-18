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
}

pub fn collect_macos_key_custody_report() -> MacosKeyCustodyReport {
    let entries = build_entries();
    let overall_ok = entries.iter().all(|e| {
        matches!(
            e.status,
            MacosKeyCustodyEntryStatus::Ok { .. } | MacosKeyCustodyEntryStatus::AbsentAsExpected
        )
    });
    MacosKeyCustodyReport {
        schema_version: 1,
        overall_ok,
        entries,
    }
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
    ]
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
            expected: "absent".to_owned(),
            status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
        },
        Ok(_) => MacosKeyCustodyEntry {
            label: label.to_owned(),
            path: path.to_owned(),
            expected: "absent".to_owned(),
            status: MacosKeyCustodyEntryStatus::Forbidden {
                reason: format!(
                    "plaintext private key at {path} must not exist at rest — \
                     Phase E migrated runtime key custody to encrypted-at-rest"
                ),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert_eq!(report.entries.len(), 4);
        for entry in &report.entries {
            assert!(
                matches!(
                    &entry.status,
                    MacosKeyCustodyEntryStatus::Missing { reason } if reason.contains("macOS runtime host")
                ),
                "off-macOS entry must be Missing with runtime-host reason: {:?}",
                entry
            );
        }
    }

    #[test]
    fn paths_are_under_state_root() {
        assert!(MACOS_WG_KEYS_DIR.starts_with("/usr/local/var/rustynet"));
        assert!(MACOS_WG_ENCRYPTED_PRIVATE_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
        assert!(MACOS_WG_PUBLIC_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
        assert!(MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.starts_with(MACOS_WG_KEYS_DIR));
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
        // Snapshot the four reviewed entries that the (off-platform)
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
                        MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH,
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
        // The collector derives overall_ok via an all() walk over
        // entry statuses, accepting Ok + AbsentAsExpected only. Pin
        // the contract by constructing a mixed report manually and
        // re-deriving the verdict the same way.
        let report = MacosKeyCustodyReport {
            schema_version: 1,
            overall_ok: false,
            entries: vec![
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
            ],
        };
        let derived = report.entries.iter().all(|e| {
            matches!(
                e.status,
                MacosKeyCustodyEntryStatus::Ok { .. }
                    | MacosKeyCustodyEntryStatus::AbsentAsExpected
            )
        });
        assert!(
            !derived,
            "overall_ok must be false when any entry is Invalid"
        );
        assert_eq!(report.overall_ok, derived);
    }

    #[test]
    fn report_overall_ok_is_true_when_only_ok_and_absent_as_expected_present() {
        // The acceptance contract on the collector: only Ok +
        // AbsentAsExpected count toward overall_ok=true. Pin from
        // the positive side too.
        let report = MacosKeyCustodyReport {
            schema_version: 1,
            overall_ok: true,
            entries: vec![
                keys_dir_entry(),
                MacosKeyCustodyEntry {
                    label: "plaintext private key (forbidden)".to_owned(),
                    path: MACOS_WG_PLAINTEXT_PRIVATE_KEY_PATH.to_owned(),
                    expected: "absent".to_owned(),
                    status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
                },
            ],
        };
        let derived = report.entries.iter().all(|e| {
            matches!(
                e.status,
                MacosKeyCustodyEntryStatus::Ok { .. }
                    | MacosKeyCustodyEntryStatus::AbsentAsExpected
            )
        });
        assert!(
            derived,
            "overall_ok must be true when entries are Ok or AbsentAsExpected"
        );
        assert_eq!(report.overall_ok, derived);
    }
}
