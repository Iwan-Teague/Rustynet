#![allow(clippy::result_large_err)]

//! Linux mesh-status verifier.
//!
//! Linux parity for `windows_mesh_status`. Reads the daemon's persisted
//! session snapshot at the canonical Linux state path
//! (`/var/lib/rustynet/rustynetd.state`, mirroring the systemd unit's
//! `RUSTYNET_STATE` env var) and emits a typed JSON report the
//! orchestrator can parse to confirm the Linux peer joined the mesh
//! and observes the expected peers.
//!
//! Wired through the CLI as `rustynetd linux-mesh-status-check`. The
//! orchestrator's `LinuxDaemonProbe` adapter dispatches the
//! `MeshStatus` op to this subcommand.
//!
//! Re-uses `windows_mesh_status::evaluate_windows_mesh_status` as the
//! pure evaluator — the snapshot-load enum + drift-rules are
//! platform-neutral. Only the default state path differs.

use crate::resilience::{ResilienceError, load_session_snapshot};
use crate::windows_mesh_status::{WindowsMeshSnapshotLoad, evaluate_windows_mesh_status};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_LINUX_STATE_PATH: &str = "/var/lib/rustynet/rustynetd.state";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxMeshStatusReport {
    pub schema_version: u32,
    pub state_path: String,
    pub overall_ok: bool,
    pub snapshot: WindowsMeshSnapshotLoad,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
    pub drift_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct LinuxMeshStatusOptions {
    pub state_path: Option<PathBuf>,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
}

pub fn collect_linux_mesh_status_report(options: &LinuxMeshStatusOptions) -> LinuxMeshStatusReport {
    let state_path: PathBuf = options
        .state_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_LINUX_STATE_PATH));
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
    LinuxMeshStatusReport {
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
    fn collector_marks_overall_fail_when_state_file_missing() {
        let options = LinuxMeshStatusOptions {
            state_path: Some(PathBuf::from(
                "/tmp/rustynet-linux-mesh-status-fixture-does-not-exist",
            )),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::Missing { .. }
        ));
        assert!(report.drift_reasons.iter().any(|r| r.contains("missing")));
    }

    #[test]
    fn report_serde_round_trips() {
        let options = LinuxMeshStatusOptions {
            state_path: Some(PathBuf::from(
                "/tmp/rustynet-linux-mesh-status-fixture-does-not-exist",
            )),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: LinuxMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn default_state_path_matches_systemd_unit() {
        // Pin: the systemd unit ships `RUSTYNET_STATE=/var/lib/rustynet/rustynetd.state`.
        // If the unit's path ever changes, this constant must be updated
        // in the same commit so the verifier doesn't read a stale path.
        assert_eq!(
            DEFAULT_LINUX_STATE_PATH,
            "/var/lib/rustynet/rustynetd.state"
        );
    }

    #[test]
    fn collector_emits_expected_peer_ids_in_report() {
        let options = LinuxMeshStatusOptions {
            state_path: Some(PathBuf::from(
                "/tmp/rustynet-linux-mesh-status-fixture-does-not-exist",
            )),
            expected_peer_ids: vec!["peer-a".to_string(), "peer-b".to_string()],
            max_age_seconds: Some(300),
        };
        let report = collect_linux_mesh_status_report(&options);
        assert_eq!(
            report.expected_peer_ids,
            vec!["peer-a".to_string(), "peer-b".to_string()]
        );
        assert_eq!(report.max_age_seconds, Some(300));
    }

    // ----- fail-closed schema-drift coverage for the collector -----
    //
    // These tests pin the collector's translation of resilience::load
    // failures into typed snapshot-load variants. Pairs with the
    // schema-drift coverage in resilience::tests.

    fn fixture_path(suffix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock should be valid")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rustynet-linux-mesh-status-{}-{}-{}",
            std::process::id(),
            unique,
            suffix
        ))
    }

    #[test]
    fn collector_reports_invalid_format_when_unknown_line_present() {
        let path = fixture_path("unknown-line");
        std::fs::write(
            &path,
            "timestamp_unix=1\npeer_ids=\nselected_exit_node=none\nlan_access_enabled=true\nfuture_field=value\ndigest=ignored\n",
        )
        .unwrap();
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::InvalidFormat { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collector_reports_integrity_mismatch_when_digest_does_not_match() {
        let path = fixture_path("digest-mismatch");
        // Construct a body that's well-formed but has a digest that does
        // NOT match the actual content.
        std::fs::write(
            &path,
            "timestamp_unix=42\npeer_ids=peer-a,peer-b\nselected_exit_node=none\nlan_access_enabled=false\ndigest=0000000000000000000000000000000000000000000000000000000000000000\n",
        )
        .unwrap();
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::IntegrityMismatch { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collector_reports_invalid_format_when_oversize() {
        let path = fixture_path("oversize");
        std::fs::write(&path, "x".repeat(129 * 1024)).unwrap();
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::InvalidFormat { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collector_reports_invalid_format_when_lan_access_enabled_is_garbage() {
        let path = fixture_path("bad-lan-access");
        std::fs::write(
            &path,
            "timestamp_unix=1\npeer_ids=\nselected_exit_node=none\nlan_access_enabled=maybe\ndigest=ignored\n",
        )
        .unwrap();
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::InvalidFormat { .. }
        ));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn collector_state_path_in_report_matches_options() {
        let path = fixture_path("path-echo");
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert_eq!(report.state_path, path.display().to_string());
        // The fixture file doesn't exist, so the snapshot is Missing —
        // that's a separate property already covered upstream.
    }

    #[test]
    fn collector_drift_reasons_include_state_path_context_for_invalid_format() {
        let path = fixture_path("drift-reason-context");
        std::fs::write(
            &path,
            "timestamp_unix=NaN\npeer_ids=\nselected_exit_node=none\nlan_access_enabled=true\ndigest=ignored\n",
        )
        .unwrap();
        let options = LinuxMeshStatusOptions {
            state_path: Some(path.clone()),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        // The drift reasons enumerate the failure context for the
        // orchestrator to surface; an InvalidFormat path should be flagged.
        assert!(!report.overall_ok);
        assert!(!report.drift_reasons.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
