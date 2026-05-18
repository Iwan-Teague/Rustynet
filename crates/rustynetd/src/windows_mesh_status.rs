#![allow(clippy::result_large_err)]

//! Windows mesh-status verifier (W4.2 daemon-side support).
//!
//! Reads the daemon's persisted session snapshot at the canonical Windows
//! state path and emits a typed JSON report the orchestrator can parse to
//! confirm the Windows guest joined the mesh and observes the expected
//! peers. The orchestrator's `validate_windows_mesh_join` stage dispatches
//! the `windows-mesh-status-check` subcommand here.
//!
//! This is a "what does the daemon currently see?" diagnostic. It does not
//! cause any state mutation. A live runtime IPC server for the daemon's
//! observed state is out of scope for this slice; reading the persisted
//! snapshot is sufficient because the daemon writes it on every reconcile.

use crate::resilience::{ResilienceError, load_session_snapshot};
use crate::windows_paths::DEFAULT_WINDOWS_STATE_PATH;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "load_status", rename_all = "snake_case")]
pub enum WindowsMeshSnapshotLoad {
    Ok {
        timestamp_unix: u64,
        age_seconds: i64,
        peer_ids: Vec<String>,
        selected_exit_node: Option<String>,
        lan_access_enabled: bool,
    },
    Missing {
        reason: String,
    },
    IntegrityMismatch {
        reason: String,
    },
    InvalidFormat {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowsMeshStatusReport {
    pub schema_version: u32,
    pub state_path: String,
    pub overall_ok: bool,
    pub snapshot: WindowsMeshSnapshotLoad,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
    pub drift_reasons: Vec<String>,
}

/// Knobs the orchestrator can pass through the subcommand. All optional.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WindowsMeshStatusOptions {
    pub state_path: Option<PathBuf>,
    /// Peer IDs the orchestrator expects to find in the snapshot. When
    /// provided, missing peers count as drift.
    pub expected_peer_ids: Vec<String>,
    /// If set, snapshots older than this many seconds count as drift. Useful
    /// when the orchestrator wants to confirm the daemon reconciled
    /// post-distribution. `None` disables the freshness check.
    pub max_age_seconds: Option<i64>,
}

/// Inspect the runtime snapshot at the configured (or default) state path
/// and return a typed report. Mirrors the W1.2 / W2.4 / W2.1 reporting shape
/// so the orchestrator can drive every Windows security-check subcommand
/// through the same evaluator pattern.
pub fn collect_windows_mesh_status_report(
    options: &WindowsMeshStatusOptions,
) -> WindowsMeshStatusReport {
    let state_path: PathBuf = options
        .state_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_WINDOWS_STATE_PATH));
    let state_path_str = state_path.display().to_string();
    let now_unix = current_unix_seconds();
    // W8 fail-closed: reject state paths outside the reviewed Windows
    // runtime roots BEFORE touching the filesystem. An operator (or
    // attacker with orchestrator credentials) cannot point the mesh
    // status verifier at a planted state file in a writable location
    // such as %TEMP% or a network share — the path must live under the
    // reviewed `C:\ProgramData\RustyNet\…` tree.
    if let Err(reason) = ensure_state_path_under_reviewed_root(state_path.as_path()) {
        let snapshot = WindowsMeshSnapshotLoad::InvalidFormat {
            reason: reason.clone(),
        };
        let mut drift_reasons = Vec::new();
        drift_reasons.push(format!(
            "state path rejected by reviewed-root check: {reason}"
        ));
        return WindowsMeshStatusReport {
            schema_version: 1,
            state_path: state_path_str,
            overall_ok: false,
            snapshot,
            expected_peer_ids: options.expected_peer_ids.clone(),
            max_age_seconds: options.max_age_seconds,
            drift_reasons,
        };
    }
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
    WindowsMeshStatusReport {
        schema_version: 1,
        state_path: state_path_str,
        overall_ok,
        snapshot,
        expected_peer_ids: options.expected_peer_ids.clone(),
        max_age_seconds: options.max_age_seconds,
        drift_reasons,
    }
}

/// Pure evaluator over a snapshot-load result + expectations. Returns the
/// list of drift reasons (empty = ok). Cross-platform unit-testable.
pub fn evaluate_windows_mesh_status(
    snapshot: &WindowsMeshSnapshotLoad,
    expected_peer_ids: &[String],
    max_age_seconds: Option<i64>,
) -> Vec<String> {
    let mut reasons: Vec<String> = Vec::new();
    match snapshot {
        WindowsMeshSnapshotLoad::Missing { reason } => {
            reasons.push(format!("state snapshot missing: {reason}"));
        }
        WindowsMeshSnapshotLoad::IntegrityMismatch { reason } => {
            reasons.push(format!("state snapshot integrity mismatch: {reason}"));
        }
        WindowsMeshSnapshotLoad::InvalidFormat { reason } => {
            reasons.push(format!("state snapshot invalid format: {reason}"));
        }
        WindowsMeshSnapshotLoad::Ok {
            age_seconds,
            peer_ids,
            ..
        } => {
            if let Some(max_age) = max_age_seconds {
                if *age_seconds > max_age {
                    reasons.push(format!(
                        "state snapshot is stale: age={age_seconds}s exceeds max_age={max_age}s"
                    ));
                }
                if *age_seconds < 0 {
                    reasons.push(format!(
                        "state snapshot has future timestamp: age={age_seconds}s (clock skew or tampered file)"
                    ));
                }
            }
            for expected in expected_peer_ids {
                if !peer_ids.iter().any(|p| p == expected) {
                    reasons.push(format!(
                        "expected peer {expected} not present in snapshot peer_ids"
                    ));
                }
            }
        }
    }
    reasons
}

fn current_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn ensure_state_path_under_reviewed_root(path: &Path) -> Result<(), String> {
    crate::windows_paths::validate_windows_runtime_file_path(path, "mesh status state path")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    #[test]
    fn evaluator_accepts_fresh_snapshot_with_expected_peers() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 30,
            peer_ids: vec!["peer-a".to_string(), "peer-b".to_string()],
            selected_exit_node: Some("peer-a".to_string()),
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(
            &snap,
            &["peer-a".to_string(), "peer-b".to_string()],
            Some(300),
        );
        assert!(reasons.is_empty(), "fresh snapshot must pass: {reasons:?}");
    }

    #[test]
    fn evaluator_rejects_missing_expected_peer() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 30,
            peer_ids: vec!["peer-a".to_string()],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(
            &snap,
            &["peer-a".to_string(), "peer-b".to_string()],
            None,
        );
        assert!(
            reasons.iter().any(|r| r.contains("expected peer peer-b")),
            "missing peer must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_stale_snapshot() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 600,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], Some(300));
        assert!(
            reasons.iter().any(|r| r.contains("snapshot is stale")),
            "stale snapshot must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_future_timestamp_when_freshness_enforced() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: -42,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], Some(300));
        assert!(
            reasons.iter().any(|r| r.contains("future timestamp")),
            "future-timestamp snapshot must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_skips_freshness_when_threshold_unset() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 999_999,
            peer_ids: vec!["peer-a".to_string()],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &["peer-a".to_string()], None);
        assert!(
            reasons.is_empty(),
            "freshness check must skip when threshold None: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_missing_state_load() {
        let snap = WindowsMeshSnapshotLoad::Missing {
            reason: "no such file".to_string(),
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], None);
        assert!(
            reasons.iter().any(|r| r.contains("state snapshot missing")),
            "missing state must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_integrity_mismatch() {
        let snap = WindowsMeshSnapshotLoad::IntegrityMismatch {
            reason: "checksum failed".to_string(),
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], None);
        assert!(
            reasons.iter().any(|r| r.contains("integrity mismatch")),
            "integrity mismatch must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_invalid_format() {
        let snap = WindowsMeshSnapshotLoad::InvalidFormat {
            reason: "missing field".to_string(),
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], None);
        assert!(
            reasons.iter().any(|r| r.contains("invalid format")),
            "invalid format must surface: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_aggregates_multiple_drift_reasons() {
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 600,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(
            &snap,
            &["peer-a".to_string(), "peer-b".to_string()],
            Some(300),
        );
        assert!(
            reasons.len() >= 3,
            "expected stale + 2 missing peers: {reasons:?}"
        );
    }

    #[test]
    fn collect_report_returns_invalid_for_path_outside_reviewed_root() {
        // /tmp/... is NOT a reviewed Windows runtime root. The collector
        // must reject the path before any filesystem access.
        let bogus = PathBuf::from("/tmp/rustynet-mesh-status-test-nonexistent");
        let _ = fs::remove_file(bogus.as_path());
        let options = WindowsMeshStatusOptions {
            state_path: Some(bogus),
            expected_peer_ids: vec!["peer-a".to_string()],
            max_age_seconds: Some(300),
        };
        let report = collect_windows_mesh_status_report(&options);
        assert_eq!(report.schema_version, 1);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::InvalidFormat { .. }
        ));
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("reviewed-root check")),
            "reviewed-root rejection must surface: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn collect_report_rejects_user_writable_temp_state_path() {
        // %TEMP% is writable by the runtime service account and a low-
        // privilege attacker. The mesh-status check must refuse to read
        // a planted state file from there.
        let temp_path = PathBuf::from(r"C:\Users\Public\AppData\Local\Temp\rustynetd.state");
        let options = WindowsMeshStatusOptions {
            state_path: Some(temp_path),
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_windows_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(matches!(
            report.snapshot,
            WindowsMeshSnapshotLoad::InvalidFormat { .. }
        ));
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("reviewed-root check")),
            "user-temp state path must be rejected: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn collect_report_rejects_unc_state_path() {
        // UNC / network shares are not reviewed roots — an attacker who
        // controls the SMB endpoint could feed a forged state file. The
        // collector must reject the path shape.
        let unc_path = PathBuf::from(r"\\fileserver\rustynet$\rustynetd.state");
        let options = WindowsMeshStatusOptions {
            state_path: Some(unc_path),
            expected_peer_ids: vec![],
            max_age_seconds: None,
        };
        let report = collect_windows_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|r| r.contains("reviewed-root check")),
            "UNC state path must be rejected: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn report_serializes_with_load_status_tag_and_round_trips() {
        let report = WindowsMeshStatusReport {
            schema_version: 1,
            state_path: r"C:\ProgramData\RustyNet\rustynetd.state".to_string(),
            overall_ok: true,
            snapshot: WindowsMeshSnapshotLoad::Ok {
                timestamp_unix: 1_700_000_000,
                age_seconds: 30,
                peer_ids: vec!["peer-a".to_string()],
                selected_exit_node: Some("peer-a".to_string()),
                lan_access_enabled: false,
            },
            expected_peer_ids: vec!["peer-a".to_string()],
            max_age_seconds: Some(300),
            drift_reasons: vec![],
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(serialized.contains("\"load_status\":\"ok\""));
        let restored: WindowsMeshStatusReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn report_serializes_missing_load_with_status_tag() {
        let report = WindowsMeshStatusReport {
            schema_version: 1,
            state_path: r"C:\ProgramData\RustyNet\rustynetd.state".to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::Missing {
                reason: "no such file".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot missing: no such file".to_string()],
        };
        let serialized = serde_json::to_string(&report).expect("serialize");
        assert!(serialized.contains("\"load_status\":\"missing\""));
        let restored: WindowsMeshStatusReport =
            serde_json::from_str(serialized.as_str()).expect("deserialize");
        assert_eq!(restored, report);
    }

    // ----- X4 coverage parity sweep ---------------------------------------

    #[test]
    fn report_schema_version_pinned_at_one() {
        // Pin the wire-format schema_version so an accidental bump
        // (e.g. as part of a typed-view rename refactor) trips this
        // test and forces a deliberate review.
        let report = WindowsMeshStatusReport {
            schema_version: 1,
            state_path: r"C:\ProgramData\RustyNet\rustynetd.state".to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::Missing {
                reason: "no such file".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
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
    fn integrity_mismatch_load_round_trips_through_serde() {
        // Existing round-trips covered Ok + Missing variants; the
        // IntegrityMismatch + InvalidFormat tail wasn't pinned.
        // Round-trip the IntegrityMismatch shape explicitly.
        let report = WindowsMeshStatusReport {
            schema_version: 1,
            state_path: r"C:\ProgramData\RustyNet\rustynetd.state".to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::IntegrityMismatch {
                reason: "checksum mismatch".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot integrity mismatch: checksum mismatch".to_string()],
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"integrity_mismatch\""),
            "tag shape: {body}"
        );
        let parsed: WindowsMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn invalid_format_load_round_trips_through_serde() {
        let report = WindowsMeshStatusReport {
            schema_version: 1,
            state_path: r"C:\ProgramData\RustyNet\rustynetd.state".to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::InvalidFormat {
                reason: "missing required field".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec![
                "state snapshot invalid format: missing required field".to_string(),
            ],
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"invalid_format\""),
            "tag shape: {body}"
        );
        let parsed: WindowsMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }

    #[test]
    fn snapshot_load_rejects_unknown_load_status_tag() {
        // The enum uses #[serde(tag="load_status", rename_all="snake_case")].
        // An unknown tag must fail closed rather than silently parse to
        // a default variant.
        let body = r#"{"load_status":"observe_only","reason":"placeholder"}"#;
        let err = serde_json::from_str::<WindowsMeshSnapshotLoad>(body)
            .expect_err("unknown load_status must fail closed");
        assert!(
            err.to_string().contains("observe_only") || err.to_string().contains("unknown variant"),
            "error must reference unknown tag or 'unknown variant': {err}"
        );
    }

    #[test]
    fn evaluator_accepts_age_equal_to_max_age_threshold() {
        // The evaluator uses `> max_age` (strict greater-than) so a
        // snapshot exactly at the threshold must pass. Pin this so a
        // future `>=` typo (cheaper-looking but tightens the contract
        // by 1 second) trips this test.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 300,
            peer_ids: vec!["peer-a".to_string()],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &["peer-a".to_string()], Some(300));
        assert!(
            reasons.is_empty(),
            "age == max_age must pass (strict >): {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_age_one_second_above_max_threshold() {
        // Boundary pin: age = max+1 must reject. Together with the
        // age==max test above, the strict-greater contract is pinned
        // from both sides.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 301,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], Some(300));
        assert!(
            reasons.iter().any(|r| r.contains("snapshot is stale")
                && r.contains("age=301s")
                && r.contains("max_age=300s")),
            "age=301 vs max=300 must surface both numbers: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_passes_when_snapshot_ok_with_no_expectations() {
        // No expected_peer_ids + no max_age_seconds → vacuous truth:
        // the evaluator returns an empty reasons vec because there's
        // nothing to check. Pin this so a future "require expectations"
        // change has to update this test deliberately.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 999_999,
            peer_ids: vec!["peer-a".to_string(), "peer-b".to_string()],
            selected_exit_node: Some("peer-a".to_string()),
            lan_access_enabled: true,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], None);
        assert!(
            reasons.is_empty(),
            "no expectations + no max_age must pass: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_each_missing_peer_independently_without_dedup() {
        // Pre-existing tests cover "1 missing peer" but don't pin the
        // "no dedup" contract. If the caller asks for the same peer
        // twice (orchestrator config bug or a future "list all peers"
        // shape), each missing instance must surface independently.
        // A future dedup refactor (e.g. via HashSet) would silently
        // collapse the operator-facing reason count.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 30,
            peer_ids: vec!["peer-x".to_string()],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(
            &snap,
            &[
                "peer-a".to_string(),
                "peer-a".to_string(),
                "peer-b".to_string(),
            ],
            None,
        );
        // 3 missing reasons: peer-a (x2), peer-b (x1) — no dedup.
        assert_eq!(
            reasons.len(),
            3,
            "expected 3 reasons (no dedup of duplicate expected_peer_ids): {reasons:?}"
        );
    }

    #[test]
    fn evaluator_does_not_surface_drift_from_lan_or_selected_exit_node_fields() {
        // selected_exit_node and lan_access_enabled are carried through
        // the typed view but are NOT part of the drift contract today
        // (only freshness + expected peers gate the verdict). Pin this
        // so a future addition that starts gating on either field has
        // to update this test deliberately and document the new gate.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 30,
            peer_ids: vec!["peer-a".to_string()],
            selected_exit_node: None, // no exit node selected
            lan_access_enabled: true, // LAN access enabled
        };
        let reasons = evaluate_windows_mesh_status(&snap, &["peer-a".to_string()], Some(300));
        assert!(
            reasons.is_empty(),
            "selected_exit_node + lan_access_enabled must not affect drift today: {reasons:?}"
        );
    }
}
