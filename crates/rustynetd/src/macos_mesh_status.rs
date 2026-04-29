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
            state_path: DEFAULT_MACOS_STATE_PATH.to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::Missing {
                reason: "not found".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state file missing".to_string()],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn default_state_path_is_under_state_root() {
        assert!(DEFAULT_MACOS_STATE_PATH.starts_with("/usr/local/var/rustynet"));
    }
}
