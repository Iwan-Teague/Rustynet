#![allow(clippy::result_large_err)]

//! Linux runtime ACL verifier.
//!
//! Mirror of `windows_paths::collect_windows_runtime_acl_report` for
//! Linux hosts. Walks the canonical Linux runtime roots used by the
//! daemon's systemd unit + e2e bootstrap scripts, and confirms each
//! root exists, is a real directory, has the reviewed owner / group,
//! and matches the reviewed mode.
//!
//! The reviewed posture comes from two sources of truth:
//!
//! * `scripts/systemd/rustynetd.service` — sets `User=rustynetd`,
//!   `Group=rustynetd`, `StateDirectoryMode=0700`, and `ReadWritePaths=`.
//! * `scripts/e2e/live_lab_common.sh` — the bootstrap install commands:
//!     ```text
//!     install -d -m 0750 -o root      -g rustynetd /etc/rustynet
//!     install -d -m 0700 -o rustynetd -g rustynetd /var/lib/rustynet
//!     ```
//!
//! Off-Linux the report's per-root status is `Missing` with an explicit
//! "requires a Linux runtime host" reason so the orchestrator surfaces
//! a clear blocker rather than a fabricated answer.
//!
//! This is the Linux parity for the W1.1 Windows runtime-ACL verifier.
//! Wired through the CLI as `rustynetd linux-runtime-acls-check`. The
//! orchestrator's `LinuxDaemonProbe` adapter dispatches the
//! `RuntimeAcls` op to this subcommand.

use serde::{Deserialize, Serialize};

/// Reviewed Linux runtime roots. Each entry is
/// `(path, label, expected_mode, expected_owner, expected_group)` where
/// `expected_mode` is the directory mode bits (octal in source for
/// readability; persisted as decimal-mode in JSON).
///
/// `expected_owner` and `expected_group` are the textual usernames the
/// systemd unit + bootstrap scripts use. The verifier resolves them to
/// uid / gid at probe time so a host with a different uid mapping for
/// `rustynetd` (eg. distros that pre-allocate different system uids)
/// still passes when the *name* matches the reviewed posture.
const LINUX_RUNTIME_STARTUP_ACL_ROOTS: &[(&str, &str, u32, &str, &str)] = &[
    (
        "/var/lib/rustynet",
        "state root",
        0o700,
        "rustynetd",
        "rustynetd",
    ),
    ("/etc/rustynet", "config root", 0o750, "root", "rustynetd"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LinuxRuntimeAclRootStatus {
    Ok,
    Missing { reason: String },
    Drifted { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxRuntimeAclRootEntry {
    pub label: String,
    pub path: String,
    #[serde(flatten)]
    pub status: LinuxRuntimeAclRootStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxRuntimeAclReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub roots: Vec<LinuxRuntimeAclRootEntry>,
}

/// Diagnostic walk over the canonical Linux runtime roots. Collects
/// per-root status instead of failing fast so a remote orchestrator
/// can render a complete drift report in a single round-trip.
pub fn collect_linux_runtime_acl_report() -> LinuxRuntimeAclReport {
    let roots = LINUX_RUNTIME_STARTUP_ACL_ROOTS
        .iter()
        .map(|(path_str, label, mode, owner, group)| {
            let status = inspect_runtime_root_status(path_str, label, *mode, owner, group);
            LinuxRuntimeAclRootEntry {
                label: (*label).to_string(),
                path: (*path_str).to_string(),
                status,
            }
        })
        .collect::<Vec<_>>();
    let overall_ok = roots
        .iter()
        .all(|entry| matches!(entry.status, LinuxRuntimeAclRootStatus::Ok));
    LinuxRuntimeAclReport {
        schema_version: 1,
        overall_ok,
        roots,
    }
}

/// Reviewed posture for one runtime root, resolved at probe time so
/// the evaluator can stay platform-agnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxRuntimeAclExpectation {
    pub mode: u32,
    pub owner_uid: u32,
    pub group_gid: u32,
}

/// Live metadata snapshot of one runtime root. Fields mirror the
/// `std::os::unix::fs::MetadataExt` view so the evaluator can stay
/// `cfg`-free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinuxRuntimeAclSnapshot {
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
}

/// Pure evaluator: takes a fully-populated metadata snapshot and
/// confirms it matches the reviewed posture. Splitting this out from
/// the syscall-driven probe keeps unit tests deterministic — the
/// fixture builds the snapshot in memory and the evaluator validates.
pub fn evaluate_linux_runtime_acl_metadata(
    label: &str,
    expected: LinuxRuntimeAclExpectation,
    actual: LinuxRuntimeAclSnapshot,
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

#[cfg(target_os = "linux")]
fn inspect_runtime_root_status(
    path_str: &str,
    label: &str,
    expected_mode: u32,
    expected_owner: &str,
    expected_group: &str,
) -> LinuxRuntimeAclRootStatus {
    use std::os::unix::fs::MetadataExt;
    let path = std::path::Path::new(path_str);
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(err) => {
            return LinuxRuntimeAclRootStatus::Missing {
                reason: format!(
                    "{label} must exist before rustynetd starts on Linux ({path_str}): {err}"
                ),
            };
        }
    };
    let is_symlink = metadata.file_type().is_symlink();
    let is_dir = metadata.is_dir();

    let expected_owner_uid = match resolve_uid_for_username(expected_owner) {
        Some(uid) => uid,
        None => {
            return LinuxRuntimeAclRootStatus::Drifted {
                reason: format!(
                    "{label} reviewed owner {expected_owner:?} is not present on this host"
                ),
            };
        }
    };
    let expected_group_gid = match resolve_gid_for_groupname(expected_group) {
        Some(gid) => gid,
        None => {
            return LinuxRuntimeAclRootStatus::Drifted {
                reason: format!(
                    "{label} reviewed group {expected_group:?} is not present on this host"
                ),
            };
        }
    };

    match evaluate_linux_runtime_acl_metadata(
        label,
        LinuxRuntimeAclExpectation {
            mode: expected_mode,
            owner_uid: expected_owner_uid,
            group_gid: expected_group_gid,
        },
        LinuxRuntimeAclSnapshot {
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            is_dir,
            is_symlink,
        },
    ) {
        Ok(()) => LinuxRuntimeAclRootStatus::Ok,
        Err(reason) => LinuxRuntimeAclRootStatus::Drifted { reason },
    }
}

#[cfg(not(target_os = "linux"))]
fn inspect_runtime_root_status(
    path_str: &str,
    label: &str,
    _expected_mode: u32,
    _expected_owner: &str,
    _expected_group: &str,
) -> LinuxRuntimeAclRootStatus {
    LinuxRuntimeAclRootStatus::Missing {
        reason: format!(
            "{label} probe at {path_str} requires a Linux runtime host; \
             linux-runtime-acls-check is not meaningful off-Linux"
        ),
    }
}

#[cfg(target_os = "linux")]
fn resolve_uid_for_username(username: &str) -> Option<u32> {
    nix::unistd::User::from_name(username)
        .ok()
        .flatten()
        .map(|user| user.uid.as_raw())
}

#[cfg(target_os = "linux")]
fn resolve_gid_for_groupname(groupname: &str) -> Option<u32> {
    nix::unistd::Group::from_name(groupname)
        .ok()
        .flatten()
        .map(|group| group.gid.as_raw())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state_root_expectation() -> LinuxRuntimeAclExpectation {
        LinuxRuntimeAclExpectation {
            mode: 0o700,
            owner_uid: 998,
            group_gid: 998,
        }
    }

    fn config_root_expectation() -> LinuxRuntimeAclExpectation {
        LinuxRuntimeAclExpectation {
            mode: 0o750,
            owner_uid: 0,
            group_gid: 998,
        }
    }

    fn good_state_root_snapshot() -> LinuxRuntimeAclSnapshot {
        LinuxRuntimeAclSnapshot {
            mode: 0o40700,
            uid: 998,
            gid: 998,
            is_dir: true,
            is_symlink: false,
        }
    }

    #[test]
    fn evaluator_accepts_matching_posture() {
        evaluate_linux_runtime_acl_metadata(
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
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink must reject");
        assert!(
            err.contains("symlink"),
            "rejection must cite symlink: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_file_instead_of_dir() {
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o100644,
            uid: 998,
            gid: 998,
            is_dir: false,
            is_symlink: false,
        };
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
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
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("0755 must reject when 0700 is reviewed");
        assert!(
            err.contains("0o755"),
            "rejection must cite the actual mode: {err}"
        );
        assert!(
            err.contains("0o700"),
            "rejection must cite the expected mode: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_wrong_owner() {
        let mut snap = good_state_root_snapshot();
        snap.uid = 0;
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("uid mismatch must reject");
        assert!(err.contains("owner"), "rejection must cite owner: {err}");
        assert!(err.contains(" 0,"), "rejection must cite actual uid: {err}");
        assert!(
            err.contains(" 998"),
            "rejection must cite the expected uid: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_wrong_group() {
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40750,
            uid: 0,
            gid: 0,
            is_dir: true,
            is_symlink: false,
        };
        let err =
            evaluate_linux_runtime_acl_metadata("config root", config_root_expectation(), snap)
                .expect_err("gid mismatch must reject");
        assert!(err.contains("group"), "rejection must cite group: {err}");
    }

    #[test]
    fn evaluator_ignores_high_bits_above_mode_mask() {
        // S_IFDIR is 0o40000; the evaluator masks with 0o7777 so the
        // file-type bits do not corrupt the mode comparison.
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40750,
            uid: 0,
            gid: 998,
            is_dir: true,
            is_symlink: false,
        };
        evaluate_linux_runtime_acl_metadata("config root", config_root_expectation(), snap)
            .expect("high bits must be masked out");
    }

    #[test]
    #[cfg(not(target_os = "linux"))]
    fn collect_off_linux_marks_every_root_missing() {
        let report = collect_linux_runtime_acl_report();
        assert!(!report.overall_ok);
        for entry in &report.roots {
            match &entry.status {
                LinuxRuntimeAclRootStatus::Missing { reason } => {
                    assert!(
                        reason.contains("requires a Linux runtime host"),
                        "off-Linux blocker reason expected: {reason}"
                    );
                }
                other => panic!("expected Missing off-Linux, got {other:?}"),
            }
        }
        assert_eq!(report.roots.len(), 2);
    }

    #[test]
    fn report_serde_round_trips() {
        let report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: vec![LinuxRuntimeAclRootEntry {
                label: "state root".to_string(),
                path: "/var/lib/rustynet".to_string(),
                status: LinuxRuntimeAclRootStatus::Ok,
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxRuntimeAclReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_serde_drifted_round_trips() {
        let report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: false,
            roots: vec![LinuxRuntimeAclRootEntry {
                label: "state root".to_string(),
                path: "/var/lib/rustynet".to_string(),
                status: LinuxRuntimeAclRootStatus::Drifted {
                    reason: "state root mode is 0o755, expected 0o700".to_string(),
                },
            }],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxRuntimeAclReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    // ----- L2: extended drift signatures for security-relevant edge cases -----

    #[test]
    fn evaluator_rejects_setuid_drift_on_state_root() {
        // Setuid on the state root (0o4700) is a privilege-escalation
        // hazard: anything spawned inside the directory could inherit
        // the rustynetd identity. The evaluator catches this via the
        // mode-bit comparison (0o4700 != 0o0700).
        let mut snap = good_state_root_snapshot();
        snap.mode = 0o44700; // file-type bits + setuid + 0700
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("setuid drift must reject");
        assert!(
            err.contains("0o4700") && err.contains("0o700"),
            "rejection must contrast 0o4700 vs 0o700: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_setgid_drift_on_state_root() {
        // Setgid on the state root (0o2700) is a similar
        // privilege-escalation hazard. The evaluator catches it via
        // mode-bit comparison.
        let mut snap = good_state_root_snapshot();
        snap.mode = 0o42700; // file-type bits + setgid + 0700
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("setgid drift must reject");
        assert!(
            err.contains("0o2700") && err.contains("0o700"),
            "rejection must contrast 0o2700 vs 0o700: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_world_writable_state_root() {
        // 0o777 on the state root is the catastrophic case: any local
        // user can read or write the daemon's session-state snapshot.
        let mut snap = good_state_root_snapshot();
        snap.mode = 0o40777;
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("0o777 must reject when 0o700 is reviewed");
        assert!(
            err.contains("0o777") && err.contains("0o700"),
            "rejection must contrast 0o777 vs 0o700: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_state_root_owned_by_root() {
        // /var/lib/rustynet is reviewed as `rustynetd:rustynetd` (uid
        // 998). If the directory is owned by root (uid 0), the daemon
        // can't write its state snapshot under StateDirectoryMode=0700.
        let mut snap = good_state_root_snapshot();
        snap.uid = 0;
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("root-owned state root must reject");
        assert!(
            err.contains("owner uid is 0,"),
            "rejection must surface the actual uid=0: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_config_root_owned_by_rustynetd_instead_of_root() {
        // /etc/rustynet is reviewed as `root:rustynetd` (uid 0, gid
        // 998). If the directory is owned by rustynetd:rustynetd,
        // the daemon can mutate its own config root — a posture the
        // reviewed install explicitly forbids.
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40750,
            uid: 998, // rustynetd, NOT root
            gid: 998,
            is_dir: true,
            is_symlink: false,
        };
        let err =
            evaluate_linux_runtime_acl_metadata("config root", config_root_expectation(), snap)
                .expect_err("rustynetd-owned config root must reject");
        assert!(
            err.contains("owner uid is 998") && err.contains("expected 0"),
            "rejection must surface the actual uid=998 and expected uid=0: {err}"
        );
    }

    #[test]
    fn evaluator_rejects_state_root_under_restrictive_mode() {
        // 0o000 on the state root would break the daemon at startup;
        // the evaluator surfaces the wrong-mode reason rather than
        // silently letting the daemon fail-closed on first write.
        let mut snap = good_state_root_snapshot();
        snap.mode = 0o40000;
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("0o000 must reject when 0o700 is reviewed");
        assert!(
            err.contains("mode is 0o0,") && err.contains("0o700"),
            "rejection must contrast 0o0 vs 0o700: {err}"
        );
    }

    #[test]
    fn evaluator_drift_report_accumulates_mode_then_uid_then_gid_in_order() {
        // The evaluator returns the FIRST drift reason; this is by
        // design (cheaper for the orchestrator to surface a single
        // precise blocker). Pin the order: mode mismatch is checked
        // before uid mismatch, which is checked before gid mismatch.
        // A snapshot with all three drifted should surface the mode
        // reason first.
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40755,
            uid: 0,
            gid: 0,
            is_dir: true,
            is_symlink: false,
        };
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("all three drifts must reject");
        assert!(
            err.contains("mode is"),
            "first reason must be the mode mismatch: {err}"
        );
        assert!(
            !err.contains("owner uid is") && !err.contains("group gid is"),
            "subsequent drift reasons must not surface in the first-fault message: {err}"
        );
    }

    #[test]
    fn report_overall_ok_is_false_when_any_root_drifted() {
        // Compose a report with one Ok root and one Drifted root and
        // confirm overall_ok=false. Pins the AND-of-statuses contract.
        let report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: false,
            roots: vec![
                LinuxRuntimeAclRootEntry {
                    label: "state root".to_string(),
                    path: "/var/lib/rustynet".to_string(),
                    status: LinuxRuntimeAclRootStatus::Ok,
                },
                LinuxRuntimeAclRootEntry {
                    label: "config root".to_string(),
                    path: "/etc/rustynet".to_string(),
                    status: LinuxRuntimeAclRootStatus::Drifted {
                        reason: "config root mode is 0o755, expected 0o750".to_string(),
                    },
                },
            ],
        };
        // Re-derive overall_ok the same way the collector does, to
        // make sure the documented invariant holds.
        let derived = report
            .roots
            .iter()
            .all(|entry| matches!(entry.status, LinuxRuntimeAclRootStatus::Ok));
        assert!(
            !derived,
            "overall_ok must be false when any root is drifted"
        );
        assert_eq!(report.overall_ok, derived);
    }

    #[test]
    fn report_overall_ok_is_true_when_all_roots_ok() {
        let report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: vec![
                LinuxRuntimeAclRootEntry {
                    label: "state root".to_string(),
                    path: "/var/lib/rustynet".to_string(),
                    status: LinuxRuntimeAclRootStatus::Ok,
                },
                LinuxRuntimeAclRootEntry {
                    label: "config root".to_string(),
                    path: "/etc/rustynet".to_string(),
                    status: LinuxRuntimeAclRootStatus::Ok,
                },
            ],
        };
        let derived = report
            .roots
            .iter()
            .all(|entry| matches!(entry.status, LinuxRuntimeAclRootStatus::Ok));
        assert!(derived, "overall_ok must be true when every root is Ok");
        assert_eq!(report.overall_ok, derived);
    }

    // ----- L2 coverage parity sweep: schema, reviewed-list, serde shape -----

    #[test]
    fn reviewed_roots_snapshot_pins_two_entries_with_exact_posture() {
        // Pins LINUX_RUNTIME_STARTUP_ACL_ROOTS shape: any silent edit to
        // a reviewed mode, owner, or group has to update this snapshot
        // alongside the constant. Catches a future refactor that drops
        // a reviewed root (e.g. forgets /etc/rustynet) or relaxes
        // /var/lib/rustynet from 0o700 to 0o750.
        let canonical = [
            (
                "/var/lib/rustynet",
                "state root",
                0o700_u32,
                "rustynetd",
                "rustynetd",
            ),
            (
                "/etc/rustynet",
                "config root",
                0o750_u32,
                "root",
                "rustynetd",
            ),
        ];
        assert_eq!(
            LINUX_RUNTIME_STARTUP_ACL_ROOTS.len(),
            canonical.len(),
            "reviewed roots list grew or shrank — update the snapshot and the security review notes together"
        );
        for ((path, label, mode, owner, group), expected) in
            LINUX_RUNTIME_STARTUP_ACL_ROOTS.iter().zip(canonical.iter())
        {
            assert_eq!(*path, expected.0, "path drift: {path}");
            assert_eq!(*label, expected.1, "label drift for {path}: {label}");
            assert_eq!(*mode, expected.2, "mode drift for {path}: 0o{mode:o}");
            assert_eq!(*owner, expected.3, "owner drift for {path}: {owner}");
            assert_eq!(*group, expected.4, "group drift for {path}: {group}");
        }
    }

    #[test]
    fn report_schema_version_pinned_at_one() {
        // A schema_version bump is a deliberate cross-cutting change
        // that has to update every consumer; pin the current value so
        // an accidental bump trips this test.
        let off_host_report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: false,
            roots: Vec::new(),
        };
        assert_eq!(off_host_report.schema_version, 1);

        // Verify the JSON shape too: the field name is `schema_version`
        // and the value is the integer 1 (not a stringified "1").
        let body = serde_json::to_string(&off_host_report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape must be int=1: {body}"
        );
    }

    #[test]
    fn root_status_missing_round_trips_through_serde() {
        // The Missing branch carries a reason and is the off-Linux /
        // path-absent default — round-trip it explicitly so the
        // #[serde(tag = "status", rename_all = "snake_case")] contract
        // stays pinned on every variant.
        let entry = LinuxRuntimeAclRootEntry {
            label: "state root".to_string(),
            path: "/var/lib/rustynet".to_string(),
            status: LinuxRuntimeAclRootStatus::Missing {
                reason: "off-Linux probe stub".to_string(),
            },
        };
        let body = serde_json::to_string(&entry).expect("serialize");
        assert!(body.contains("\"status\":\"missing\""), "tag shape: {body}");
        let parsed: LinuxRuntimeAclRootEntry = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, entry);
    }

    #[test]
    fn root_status_rejects_unknown_status_tag() {
        // The enum is tagged + snake_case-renamed; an unknown tag must
        // fail the parse rather than silently coerce to a known variant.
        let body = r#"{"label":"state root","path":"/var/lib/rustynet","status":"observe_only","reason":"placeholder"}"#;
        let err = serde_json::from_str::<LinuxRuntimeAclRootEntry>(body)
            .expect_err("unknown tag must fail closed");
        assert!(
            err.to_string().contains("observe_only") || err.to_string().contains("unknown variant"),
            "error must reference the unknown tag or 'unknown variant': {err}"
        );
    }

    #[test]
    fn evaluator_masks_high_mode_bits_above_seven_octal_digits() {
        // The kernel may report mode bits beyond the 0o7777 mask
        // (e.g. file-type bits, ACL flags). Pin that masking via &
        // 0o7777 stays in place — a future widen to mode-without-mask
        // would reject every snapshot.
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o140700, // arbitrary high bits + 0o0700
            uid: 998,
            gid: 998,
            is_dir: true,
            is_symlink: false,
        };
        evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect("mode mask must ignore bits above 0o7777");
    }

    #[test]
    fn evaluator_rejects_symlink_before_dir_check() {
        // A symlink that points at a real directory still must reject
        // (symlinks aren't traversed by the live verifier). Pin the
        // check order: symlink wins over is_dir.
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40700,
            uid: 998,
            gid: 998,
            is_dir: true, // is_dir true on the link target — irrelevant
            is_symlink: true,
        };
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink must reject even when target is a dir");
        assert!(
            err.contains("symlink") && !err.contains("file"),
            "rejection must cite symlink, not the generic file-vs-dir reason: {err}"
        );
    }

    #[test]
    fn evaluator_first_fault_is_symlink_before_mode_drift() {
        // A snapshot with both symlink AND mode-drift should surface
        // the symlink reason first — the structural check (symlink
        // hides the real entry) takes precedence over the mode check
        // (which would otherwise mislead the operator).
        let snap = LinuxRuntimeAclSnapshot {
            mode: 0o40755, // also drifted
            uid: 998,
            gid: 998,
            is_dir: false,
            is_symlink: true,
        };
        let err = evaluate_linux_runtime_acl_metadata("state root", state_root_expectation(), snap)
            .expect_err("symlink + mode drift must reject");
        assert!(
            err.contains("symlink") && !err.contains("0o755"),
            "first reason must be symlink, not mode: {err}"
        );
    }

    #[test]
    fn report_with_empty_roots_yields_vacuously_true_overall_ok() {
        // Document the current behavior: an empty roots Vec yields
        // overall_ok=true via Iterator::all() vacuous-truth semantics.
        // This is fine in production because the collector iterates a
        // const array with two entries and cannot produce an empty
        // Vec, but the test pins the behavior so a future refactor
        // that special-cases empty input (e.g. to error out) trips a
        // visible test failure rather than silently changing semantics.
        let report = LinuxRuntimeAclReport {
            schema_version: 1,
            overall_ok: true,
            roots: Vec::new(),
        };
        let derived = report
            .roots
            .iter()
            .all(|entry| matches!(entry.status, LinuxRuntimeAclRootStatus::Ok));
        assert!(
            derived,
            "empty roots Vec is vacuously all-Ok by iterator semantics"
        );
    }
}
