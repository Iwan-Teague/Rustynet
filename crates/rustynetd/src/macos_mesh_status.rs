#![allow(clippy::result_large_err)]

//! macOS mesh-status verifier.
//!
//! macOS parity for `linux_mesh_status`. Reads the daemon's persisted
//! session snapshot at the canonical macOS state path
//! (`/usr/local/var/rustynet/rustynetd.state`) and emits a typed JSON
//! report the orchestrator can parse to confirm the macOS peer joined
//! the mesh and observes the expected peers.
//!
//! Re-uses `windows_mesh_status::evaluate_windows_mesh_status` as the
//! pure evaluator — the snapshot-load enum + drift-rules are
//! platform-neutral. Only the default state path differs.
//!
//! Wired through the CLI as `rustynetd macos-mesh-status-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches the `MeshStatus` op here.

use crate::resilience::{ResilienceError, load_session_snapshot};
use crate::windows_mesh_status::{WindowsMeshSnapshotLoad, evaluate_windows_mesh_status};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MACOS_STATE_PATH: &str = "/usr/local/var/rustynet/rustynetd.state";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosMeshStatusReport {
    pub schema_version: u32,
    pub state_path: String,
    pub overall_ok: bool,
    pub snapshot: WindowsMeshSnapshotLoad,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
    pub drift_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacosMeshStatusOptions {
    pub state_path: Option<PathBuf>,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
}

pub fn collect_macos_mesh_status_report(options: &MacosMeshStatusOptions) -> MacosMeshStatusReport {
    let state_path: PathBuf = options
        .state_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MACOS_STATE_PATH));
    let state_path_str = state_path.display().to_string();
    let now_unix = current_unix_seconds();
    let snapshot = match load_session_snapshot(state_path.as_path()) {
        Ok(snap) => {
            let age = now_unix.saturating_sub(snap.timestamp_unix as i64);
            WindowsMeshSnapshotLoad::Ok {
                timestamp_unix: snap.timestamp_unix,
                age_seconds: age,
                peer_ids: snap.peer_ids,
                selected_exit_node: snap.selected_exit_node,
                lan_access_enabled: snap.lan_access_enabled,
            }
        }
        Err(ResilienceError::Io) => WindowsMeshSnapshotLoad::Missing {
            reason: format!("runtime state path is unreadable on this host: {state_path_str}"),
        },
        Err(ResilienceError::IntegrityMismatch) => WindowsMeshSnapshotLoad::IntegrityMismatch {
            reason: format!("runtime state file failed integrity verification: {state_path_str}"),
        },
        Err(ResilienceError::InvalidFormat) => WindowsMeshSnapshotLoad::InvalidFormat {
            reason: format!(
                "runtime state file does not match the expected on-disk format: {state_path_str}"
            ),
        },
    };
    let drift_reasons = evaluate_windows_mesh_status(
        &snapshot,
        options.expected_peer_ids.as_slice(),
        options.max_age_seconds,
    );
    let overall_ok = drift_reasons.is_empty();
    MacosMeshStatusReport {
        schema_version: 1,
        state_path: state_path_str,
        overall_ok,
        snapshot,
        expected_peer_ids: options.expected_peer_ids.clone(),
        max_age_seconds: options.max_age_seconds,
        drift_reasons,
    }
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_state_file_reports_drift() {
        let options = MacosMeshStatusOptions {
            state_path: Some(PathBuf::from("/nonexistent/macos/rustynetd.state")),
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_macos_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(
            matches!(report.snapshot, WindowsMeshSnapshotLoad::Missing { .. }),
            "missing state file must yield Missing snapshot"
        );
    }

    #[test]
    fn report_serde_round_trips() {
        let report = MacosMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_MACOS_STATE_PATH.to_owned(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::Missing {
                reason: "not found".to_owned(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state file missing".to_owned()],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn default_state_path_is_under_state_root() {
        assert!(DEFAULT_MACOS_STATE_PATH.starts_with("/usr/local/var/rustynet"));
    }

    /// The validator's default state path MUST equal the daemon's default
    /// state path on macOS (QH-40 / QH-39 regression guard).
    ///
    /// These two constants live in different modules and drifted once: before
    /// QH-40 (8f9e7f5a) the daemon's `#[cfg(target_os = "macos")]` arm silently
    /// leaked the Linux `/var/lib` path, so the anchor daemon persisted its
    /// snapshot somewhere the `macos-mesh-status-check` validator never looked
    /// and the check red with `state file missing` on an otherwise healthy
    /// node. The anchor6c run (livelab-1787984750-81a71286960e, 2026-08-29)
    /// ran with both fixes already landed and still red, which is why the
    /// disposition landed in `MacCellsHarvest_2026-08-28.md` §14.4 is "honest
    /// fail-closed red, not a path defect" — but nothing pinned the agreement,
    /// so this test closes the drift class for good. On non-macOS builds the
    /// daemon arm holds the Linux path, so the equality is only assertable
    /// (and only meaningful) on macOS.
    #[cfg(target_os = "macos")]
    #[test]
    fn validator_default_path_matches_daemon_default_state_path() {
        assert_eq!(
            PathBuf::from(crate::daemon::default_state_path()),
            PathBuf::from(DEFAULT_MACOS_STATE_PATH),
            "the macOS daemon must persist its snapshot where macos-mesh-status-check reads it"
        );
    }

    /// A healthy macOS anchor must produce a snapshot the validator accepts:
    /// the daemon's reconcile-tick heartbeat
    /// (`maybe_heartbeat_persist_state`, 30s) keeps the snapshot fresh while
    /// the node is unrestricted, and the anchor's passive unix runloop drives
    /// the same `reconcile()` every second. This test pins the contract the
    /// anchor6c MeshStatus red was originally attributed to: given a snapshot
    /// written at the DEFAULT path within the heartbeat interval, the
    /// validator's drift list is empty at the orchestrator's 180s bound.
    ///
    /// The companion honesty guarantee (stale/missing MUST red) is pinned by
    /// `missing_state_file_reports_drift` above.
    #[test]
    fn fresh_snapshot_at_default_path_passes_the_orchestrator_bound() {
        let dir = std::env::temp_dir().join(format!("macos-mesh-fresh-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let state_path = dir.join("rustynetd.state");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        crate::resilience::persist_session_snapshot(
            &crate::resilience::SessionStateSnapshot {
                timestamp_unix: now,
                peer_ids: Vec::new(),
                selected_exit_node: None,
                lan_access_enabled: false,
            },
            &state_path,
        )
        .expect("plant a fresh snapshot");
        let report = collect_macos_mesh_status_report(&MacosMeshStatusOptions {
            state_path: Some(state_path),
            expected_peer_ids: vec![],
            max_age_seconds: Some(180),
        });
        assert!(
            report.drift_reasons.is_empty(),
            "a heartbeat-fresh snapshot at the default path must pass the orchestrator's \
             180s bound: drift = {:?}",
            report.drift_reasons
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn report_schema_version_pinned_at_one() {
        // Pin the wire-format schema_version so an accidental bump
        // forces a deliberate review.
        let options = MacosMeshStatusOptions {
            state_path: Some(PathBuf::from("/nonexistent/macos/rustynetd.state")),
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_macos_mesh_status_report(&options);
        assert_eq!(report.schema_version, 1);
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"schema_version\":1"),
            "schema_version JSON shape must be int=1: {body}"
        );
    }

    #[test]
    fn collect_uses_default_state_path_when_options_state_path_is_none() {
        // Pin the default-fallback path so a future change has to
        // update this test deliberately + document why the macOS
        // state location moved.
        let options = MacosMeshStatusOptions {
            state_path: None,
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_macos_mesh_status_report(&options);
        assert_eq!(report.state_path, DEFAULT_MACOS_STATE_PATH);
    }

    #[test]
    fn collect_echoes_custom_state_path_in_report() {
        // Pin that the custom path round-trips into the report
        // (used by the orchestrator to confirm which file was
        // probed against in the verbose drift block).
        let custom = "/nonexistent/macos/custom-state.bin";
        let options = MacosMeshStatusOptions {
            state_path: Some(PathBuf::from(custom)),
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_macos_mesh_status_report(&options);
        assert_eq!(report.state_path, custom);
    }

    #[test]
    fn report_ok_snapshot_round_trips_through_serde() {
        // Pre-existing report_serde_round_trips covered Missing only;
        // pin the Ok variant explicitly so a future field-shape
        // change on WindowsMeshSnapshotLoad::Ok trips this test.
        let report = MacosMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_MACOS_STATE_PATH.to_owned(),
            overall_ok: true,
            snapshot: WindowsMeshSnapshotLoad::Ok {
                timestamp_unix: 1_700_000_000,
                age_seconds: 30,
                peer_ids: vec!["peer-a".to_owned()],
                selected_exit_node: Some("peer-a".to_owned()),
                lan_access_enabled: false,
            },
            expected_peer_ids: vec!["peer-a".to_owned()],
            max_age_seconds: Some(300),
            drift_reasons: Vec::new(),
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"ok\""),
            "Ok variant tag shape: {body}"
        );
        let parsed: MacosMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_integrity_mismatch_snapshot_round_trips_through_serde() {
        let report = MacosMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_MACOS_STATE_PATH.to_owned(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::IntegrityMismatch {
                reason: "checksum mismatch".to_owned(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot integrity mismatch: checksum mismatch".to_owned()],
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"integrity_mismatch\""),
            "IntegrityMismatch variant tag shape: {body}"
        );
        let parsed: MacosMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn report_invalid_format_snapshot_round_trips_through_serde() {
        let report = MacosMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_MACOS_STATE_PATH.to_owned(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::InvalidFormat {
                reason: "missing required field".to_owned(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot invalid format: missing required field".to_owned()],
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"invalid_format\""),
            "InvalidFormat variant tag shape: {body}"
        );
        let parsed: MacosMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }
}
