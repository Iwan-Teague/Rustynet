#![allow(clippy::result_large_err)]

//! macOS runtime ACL verifier.
//!
//! macOS parity for `linux_runtime_acls`. Walks the canonical macOS
//! runtime roots used by the daemon's launchd unit, and confirms each
//! root exists, is a real directory, has the reviewed owner / group,
//! and matches the reviewed mode.
//!
//! Reviewed posture from `scripts/launchd/com.rustynet.daemon.plist`
//! + `scripts/bootstrap/macos/Install-RustyNetMacosService.sh`:
//!   install -d -m 0700 -o rustynetd -g rustynetd /usr/local/var/rustynet
//!   install -d -m 0750 -o root      -g rustynetd /usr/local/etc/rustynet
//!
//! Off-macOS the report's per-root status is `Missing` with an explicit
//! "requires a macOS runtime host" reason.
//!
//! Wired through the CLI as `rustynetd macos-runtime-acls-check`. The
//! orchestrator's `MacosDaemonProbe` adapter dispatches the
//! `RuntimeAcls` op to this subcommand.

use serde::{Deserialize, Serialize};

const MACOS_RUNTIME_ACL_ROOTS: &[(&str, &str, u32, &str, &str)] = &[
    (
        "/usr/local/var/rustynet",
        "state root",
        0o700,
        "rustynetd",
        "rustynetd",
    ),
    (
        "/usr/local/etc/rustynet",
        "config root",
        0o750,
        "root",
        "rustynetd",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum MacosRuntimeAclRootStatus {
    Ok,
    Missing { reason: String },
    Drifted { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosRuntimeAclRootEntry {
    pub label: String,
    pub path: String,
    #[serde(flatten)]
    pub status: MacosRuntimeAclRootStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosRuntimeAclReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub roots: Vec<MacosRuntimeAclRootEntry>,
}

/// Diagnostic walk over the canonical macOS runtime roots.
pub fn collect_macos_runtime_acl_report() -> MacosRuntimeAclReport {
    let roots = MACOS_RUNTIME_ACL_ROOTS
        .iter()
        .map(|(path_str, label, mode, owner, group)| {
            let status = inspect_runtime_root_status(path_str, label, *mode, owner, group);
            MacosRuntimeAclRootEntry {
                label: (*label).to_owned(),
                path: (*path_str).to_owned(),
                status,
            }
        })
        .collect::<Vec<_>>();
    let overall_ok = roots
        .iter()
        .all(|entry| matches!(entry.status, MacosRuntimeAclRootStatus::Ok));
    MacosRuntimeAclReport {
        schema_version: 1,
        overall_ok,
        roots,
    }
}

/// Reviewed posture expectation for one runtime root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosRuntimeAclExpectation {
    pub mode: u32,
    pub owner_uid: u32,
    pub group_gid: u32,
}

/// Live metadata snapshot for one runtime root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacosRuntimeAclSnapshot {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Pure evaluator: confirms snapshot matches reviewed posture.
pub fn evaluate_macos_runtime_acl_metadata(
    label: &str,
    expected: MacosRuntimeAclExpectation,
    actual: MacosRuntimeAclSnapshot,
) -> Result<(), String> {
    if actual.is_symlink {
        return Err(format!("{label} must be a real directory, not a symlink"));
    }
    if !actual.is_dir {
        return Err(format!("{label} must be a directory, not a file"));
    }
    let actual_perms = actual.mode & 0o7777;
    if actual_perms != expected.mode {
        return Err(format!(
            "{label} mode is 0o{actual_perms:o}, expected 0o{:o}",
            expected.mode
        ));
    }
    if actual.uid != expected.owner_uid {
        return Err(format!(
            "{label} owner uid is {}, expected {}",
            actual.uid, expected.owner_uid
        ));
    }
    if actual.gid != expected.group_gid {
        return Err(format!(
            "{label} group gid is {}, expected {}",
            actual.gid, expected.group_gid
        ));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn inspect_runtime_root_status(
    path_str: &str,
    label: &str,
    expected_mode: u32,
    expected_owner: &str,
    expected_group: &str,
) -> MacosRuntimeAclRootStatus {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(path_str);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) => {
            return MacosRuntimeAclRootStatus::Missing {
                reason: format!(
                    "{label} must exist before rustynetd starts on macOS ({path_str}): {err}"
                ),
            };
        }
    };
    let is_symlink = metadata.file_type().is_symlink();
    let is_dir = metadata.is_dir();

    let expected_owner_uid = match resolve_uid_for_username(expected_owner) {
        Some(uid) => uid,
        None => {
            return MacosRuntimeAclRootStatus::Drifted {
                reason: format!(
                    "{label} reviewed owner {expected_owner:?} is not present on this host"
                ),
            };
        }
    };
    let expected_group_gid = match resolve_gid_for_groupname(expected_group) {
        Some(gid) => gid,
        None => {
            return MacosRuntimeAclRootStatus::Drifted {
                reason: format!(
                    "{label} reviewed group {expected_group:?} is not present on this host"
                ),
            };
        }
    };

    match evaluate_macos_runtime_acl_metadata(
        label,
        MacosRuntimeAclExpectation {
            mode: expected_mode,
            owner_uid: expected_owner_uid,
            group_gid: expected_group_gid,
        },
        MacosRuntimeAclSnapshot {
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            is_dir,
            is_symlink,
        },
    ) {
        Ok(()) => MacosRuntimeAclRootStatus::Ok,
        Err(reason) => MacosRuntimeAclRootStatus::Drifted { reason },
    }
}

#[cfg(not(target_os = "macos"))]
fn inspect_runtime_root_status(
    path_str: &str,
    label: &str,
    _expected_mode: u32,
    _expected_owner: &str,
    _expected_group: &str,
) -> MacosRuntimeAclRootStatus {
    MacosRuntimeAclRootStatus::Missing {
        reason: format!(
            "{label} probe at {path_str} requires a macOS runtime host; \
             macos-runtime-acls-check is not meaningful off-macOS"
        ),
    }
}

#[cfg(target_os = "macos")]
fn resolve_uid_for_username(username: &str) -> Option<u32> {
    nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

#[cfg(target_os = "macos")]
fn resolve_gid_for_groupname(groupname: &str) -> Option<u32> {
    nix::unistd::Group::from_name(groupname)
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_root_expectation() -> MacosRuntimeAclExpectation {
        MacosRuntimeAclExpectation {
            mode: 0o700,
            owner_uid: 500,
            group_gid: 500,
        }
    }

    fn config_root_expectation() -> MacosRuntimeAclExpectation {
        MacosRuntimeAclExpectation {
            mode: 0o750,
            owner_uid: 0,
            group_gid: 500,
        }
    }

    fn good_state_root_snapshot() -> MacosRuntimeAclSnapshot {
        MacosRuntimeAclSnapshot {
            mode: 0o40700,
            uid: 500,
            gid: 500,
            is_dir: true,
            is_symlink: false,
        }
    }

    #[test]
    fn evaluator_accepts_matching_posture() {
        evaluate_macos_runtime_acl_metadata(
            "state root",
            state_root_expectation(),
            good_state_root_snapshot(),
        )
        .expect("matching posture must validate");
    }

    #[test]
    fn evaluator_rejects_symlink() {
        let mut snap = good_state_root_snapshot();
        snap.is_symlink = true;
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink must reject");
        assert!(
            err.contains("symlink"),
            "rejection must cite symlink: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_file_instead_of_dir() {
        let snap = MacosRuntimeAclSnapshot {
            mode: 0o100644,
            uid: 500,
            gid: 500,
            is_dir: false,
            is_symlink: false,
        };
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("non-dir must reject");
        assert!(
            err.contains("directory"),
            "rejection must cite directory: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_world_readable_state_root() {
        let mut snap = good_state_root_snapshot();
        snap.mode = 0o40755;
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("0755 must reject when 0700 is reviewed");
        assert!(
            err.contains("0o755"),
            "rejection must cite actual mode: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_wrong_owner() {
        let mut snap = good_state_root_snapshot();
        snap.uid = 0;
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("uid mismatch must reject");
        assert!(err.contains("owner"), "rejection must cite owner: {err}");
    }

    #[test]
    fn evaluator_rejects_wrong_group() {
        let snap = MacosRuntimeAclSnapshot {
            mode: 0o40750,
            uid: 0,
            gid: 0,
            is_dir: true,
            is_symlink: false,
        };
        let err =
            evaluate_macos_runtime_acl_metadata("config root", config_root_expectation(), snap)
                .expect_err("gid mismatch must reject");
        assert!(err.contains("group"), "rejection must cite group: {err}");
    }

    #[test]
    fn evaluator_ignores_high_bits_above_mode_mask() {
        let snap = MacosRuntimeAclSnapshot {
            mode: 0o40750,
            uid: 0,
            gid: 500,
            is_dir: true,
            is_symlink: false,
        };
        evaluate_macos_runtime_acl_metadata("config root", config_root_expectation(), snap)
            .expect("high bits must be masked out");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
    fn collect_off_macos_marks_every_root_missing() {
        let report = collect_macos_runtime_acl_report();
        assert!(!report.overall_ok);
        for entry in &report.roots {
            match &entry.status {
                MacosRuntimeAclRootStatus::Missing { reason } => {
                    assert!(
                        reason.contains("requires a macOS runtime host"),
                        "off-macOS blocker reason expected: {reason}"
                    );
                }
                other => panic!("expected Missing off-macOS, got {other:?}"),
            }
        }
        assert_eq!(report.roots.len(), 2);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = MacosRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: vec![MacosRuntimeAclRootEntry {
                label: "state root".to_owned(),
                path: "/usr/local/var/rustynet".to_owned(),
                status: MacosRuntimeAclRootStatus::Ok,
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosRuntimeAclReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn reviewed_roots_snapshot_pins_two_entries_with_exact_posture() {
        // Pin MACOS_RUNTIME_ACL_ROOTS shape: any silent edit to a
        // reviewed mode/owner/group has to update this snapshot
        // alongside the constant.
        let canonical = [
            (
                "/usr/local/var/rustynet",
                "state root",
                0o700_u32,
                "rustynetd",
                "rustynetd",
            ),
            (
                "/usr/local/etc/rustynet",
                "config root",
                0o750_u32,
                "root",
                "rustynetd",
            ),
        ];
        assert_eq!(
            MACOS_RUNTIME_ACL_ROOTS.len(),
            canonical.len(),
            "reviewed roots list grew or shrank — update snapshot + security review together"
        );
        for ((path, label, mode, owner, group), expected) in
            MACOS_RUNTIME_ACL_ROOTS.iter().zip(canonical.iter())
        {
            assert_eq!(*path, expected.0);
            assert_eq!(*label, expected.1);
            assert_eq!(*mode, expected.2);
            assert_eq!(*owner, expected.3);
            assert_eq!(*group, expected.4);
        }
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        let report = MacosRuntimeAclReport {
            schema_version: 1,
            overall_ok: false,
            roots: Vec::new(),
        };
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape: {body}"
        );
    }

    #[test]
    fn root_status_drifted_round_trips_through_serde() {
        // Pre-existing report_serde_round_trips only covered Ok. Pin
        // the Drifted variant so a future rename on `reason` trips.
        let entry = MacosRuntimeAclRootEntry {
            label: "state root".to_owned(),
            path: "/usr/local/var/rustynet".to_owned(),
            status: MacosRuntimeAclRootStatus::Drifted {
                reason: "mode is 0o755, expected 0o700".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"drifted\""), "tag: {body}");
        let parsed: MacosRuntimeAclRootEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn root_status_missing_round_trips_through_serde() {
        let entry = MacosRuntimeAclRootEntry {
            label: "state root".to_owned(),
            path: "/usr/local/var/rustynet".to_owned(),
            status: MacosRuntimeAclRootStatus::Missing {
                reason: "off-macOS probe stub".to_owned(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"missing\""), "tag: {body}");
        let parsed: MacosRuntimeAclRootEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn root_status_rejects_unknown_status_tag() {
        // Fail-closed parser: unknown tag must error rather than
        // coerce.
        let body = r#"{"label":"state root","path":"/usr/local/var/rustynet","status":"observe_only","reason":"placeholder"}"#;
        let err = serde_json::from_str::<MacosRuntimeAclRootEntry>(body)
            .expect_err("unknown tag must fail closed");
        assert!(
            err.to_string().contains("observe_only") || err.to_string().contains("unknown variant"),
            "error must reference unknown tag: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_symlink_before_dir_check() {
        // Symlink pointing at a real dir still must reject — pin the
        // structural check order (symlink wins over is_dir).
        let snap = MacosRuntimeAclSnapshot {
            mode: 0o40700,
            uid: 500,
            gid: 500,
            is_dir: true, // target is a dir; irrelevant
            is_symlink: true,
        };
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink must reject even with is_dir=true");
        assert!(
            err.contains("symlink") && !err.contains("file"),
            "first reason must be symlink, not file-vs-dir: {err}"
        );
    }

    #[test]
    fn evaluator_first_fault_is_symlink_before_mode_drift() {
        // Symlink + mode drift simultaneously must surface symlink
        // first — the structural check takes precedence over the
        // logical drift.
        let snap = MacosRuntimeAclSnapshot {
            mode: 0o40755, // drifted
            uid: 500,
            gid: 500,
            is_dir: false,
            is_symlink: true,
        };
        let err = evaluate_macos_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink + mode drift must reject");
        assert!(
            err.contains("symlink") && !err.contains("0o755"),
            "first reason must be symlink, not mode: {err}"
        );
    }

    #[test]
    fn report_with_empty_roots_yields_vacuously_true_overall_ok() {
        // Document the Iterator::all() vacuous-truth semantics on
        // empty input. Production cannot hit this path (the collector
        // iterates a 2-entry const array) but the test pins the
        // current behavior.
        let report = MacosRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: Vec::new(),
        };
        let derived = report
            .roots
            .iter()
            .all(|entry| matches!(entry.status, MacosRuntimeAclRootStatus::Ok));
        assert!(derived, "empty roots is vacuously all-Ok");
    }
}
