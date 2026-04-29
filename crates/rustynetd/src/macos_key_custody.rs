#![allow(clippy::result_large_err)]

//! macOS key-custody verifier.
//!
//! macOS parity for `linux_key_custody`. Validates that on-disk key
//! material on a macOS runtime host matches the reviewed custody contract:
//!
//! * the encrypted WireGuard private key exists at
//!   `/usr/local/var/rustynet/keys/wireguard.key.enc`, owned by
//!   `rustynetd:rustynetd`, mode `0600`;
//! * the WireGuard public key exists at
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
                label: label.to_string(),
                path: path.to_string(),
                expected: "present".to_string(),
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
            label: label.to_string(),
            path: path.to_string(),
            expected: "present".to_string(),
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
        label: label.to_string(),
        path: path.to_string(),
        expected: "present".to_string(),
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
                label: label.to_string(),
                path: path.to_string(),
                expected: "present".to_string(),
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
            label: label.to_string(),
            path: path.to_string(),
            expected: "present".to_string(),
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
        label: label.to_string(),
        path: path.to_string(),
        expected: "present".to_string(),
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
            label: label.to_string(),
            path: path.to_string(),
            expected: "absent".to_string(),
            status: MacosKeyCustodyEntryStatus::AbsentAsExpected,
        },
        Ok(_) => MacosKeyCustodyEntry {
            label: label.to_string(),
            path: path.to_string(),
            expected: "absent".to_string(),
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
                label: "keys dir".to_string(),
                path: MACOS_WG_KEYS_DIR.to_string(),
                expected: "present".to_string(),
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
}
