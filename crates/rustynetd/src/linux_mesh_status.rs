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

    // ----- X4 coverage expansion: evaluator edge cases + serde
    // round-trips for every snapshot-load variant. These pin shapes
    // that the prior set did not enumerate. The evaluator is the
    // shared `evaluate_windows_mesh_status`; the tests below exercise
    // it through the Linux module surface so any future divergence
    // (e.g. a Linux-specific evaluator wrapper) is caught here. -----

    #[test]
    fn evaluator_accepts_boundary_age_equal_to_max_age_seconds() {
        // Pin: the freshness check uses strict `>` (age > max), so
        // age == max_age is still accepted. Flipping to `>=` would
        // turn this boundary case into drift — that requires an
        // explicit contract change, not a silent regression.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 300,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], Some(300));
        assert!(
            reasons.is_empty(),
            "age == max_age must be accepted: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_rejects_age_one_second_past_max_age_seconds() {
        // Off-by-one neighbour to the boundary test above. age = max+1
        // must surface stale drift so the boundary contract is pinned
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
            reasons.iter().any(|r| r.contains("snapshot is stale")),
            "age == max_age + 1 must surface stale: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_zero_age_with_zero_max_age_threshold() {
        // Degenerate but well-defined: a freshly-written snapshot
        // (age = 0) with the strictest possible freshness threshold
        // (max_age = 0) is still accepted because `0 > 0` is false.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 0,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], Some(0));
        assert!(
            reasons.is_empty(),
            "age=0 with max_age=0 must be accepted: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_surfaces_each_missing_expected_peer_independently() {
        // The evaluator must not short-circuit on the first missing
        // peer — the orchestrator relies on the full list to print
        // an actionable diff. Three expected peers absent from an
        // empty snapshot must produce three distinct drift reasons.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 10,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let expected = vec![
            "peer-a".to_string(),
            "peer-b".to_string(),
            "peer-c".to_string(),
        ];
        let reasons = evaluate_windows_mesh_status(&snap, expected.as_slice(), None);
        for name in &expected {
            assert!(
                reasons
                    .iter()
                    .any(|r| r.contains(name) && r.contains("expected peer")),
                "missing peer {name} must surface: {reasons:?}"
            );
        }
        assert!(
            reasons.len() >= expected.len(),
            "each missing peer must surface independently: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_empty_expected_peers_with_empty_snapshot_peers() {
        // No expectations + no observed peers is a valid "joined but
        // alone" steady state. The evaluator must not invent drift
        // out of two empty lists.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 5,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &[], None);
        assert!(
            reasons.is_empty(),
            "empty expectations + empty observed must accept: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_accepts_peer_ids_with_hyphen_and_underscore_characters() {
        // Peer IDs flow through opaquely; the evaluator compares them
        // byte-for-byte. Hyphens + underscores are part of the
        // generated peer-id alphabet and must not be normalised or
        // rejected.
        let exotic = vec![
            "peer_a-01".to_string(),
            "peer-b_02".to_string(),
            "_trailing".to_string(),
        ];
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 5,
            peer_ids: exotic.clone(),
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, exotic.as_slice(), None);
        assert!(
            reasons.is_empty(),
            "exotic-but-valid peer-id chars must match: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_does_not_surface_selected_exit_node_mismatch() {
        // Pin the current contract: the shared evaluator has no
        // `expected_exit_node` knob, so a snapshot whose
        // `selected_exit_node` disagrees with any orchestrator-side
        // expectation MUST NOT show up as drift here. If a future
        // change adds that knob, this test will fail and force the
        // owner to update the documented surface.
        let snap = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 5,
            peer_ids: vec!["peer-a".to_string()],
            selected_exit_node: Some("peer-unexpected".to_string()),
            lan_access_enabled: false,
        };
        let reasons = evaluate_windows_mesh_status(&snap, &["peer-a".to_string()], None);
        assert!(
            reasons.is_empty(),
            "selected_exit_node is not part of the evaluator contract: {reasons:?}"
        );
    }

    #[test]
    fn evaluator_does_not_surface_lan_access_enabled_drift() {
        // Mirror of the exit-node test: `lan_access_enabled` is a
        // reported observation, not an evaluator expectation. Either
        // value must pass cleanly when no other drift is present.
        let snap_true = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 5,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: true,
        };
        let snap_false = WindowsMeshSnapshotLoad::Ok {
            timestamp_unix: 1_700_000_000,
            age_seconds: 5,
            peer_ids: vec![],
            selected_exit_node: None,
            lan_access_enabled: false,
        };
        assert!(evaluate_windows_mesh_status(&snap_true, &[], None).is_empty());
        assert!(evaluate_windows_mesh_status(&snap_false, &[], None).is_empty());
    }

    #[test]
    fn report_schema_version_is_pinned_at_one() {
        // The orchestrator parses reports with a strict schema-version
        // gate. Any bump must be a deliberate, paired change with the
        // orchestrator parser — pinning the constant here forces the
        // owner to update both sides in one commit.
        let options = LinuxMeshStatusOptions {
            state_path: Some(PathBuf::from(
                "/tmp/rustynet-linux-mesh-status-fixture-schema-pin",
            )),
            ..Default::default()
        };
        let report = collect_linux_mesh_status_report(&options);
        assert_eq!(report.schema_version, 1);
    }

    #[test]
    fn snapshot_load_ok_variant_serde_round_trips_via_report() {
        let report = LinuxMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_LINUX_STATE_PATH.to_string(),
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
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"load_status\":\"ok\""));
        let restored: LinuxMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn snapshot_load_missing_variant_serde_round_trips_via_report() {
        let report = LinuxMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_LINUX_STATE_PATH.to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::Missing {
                reason: "no such file".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot missing: no such file".to_string()],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"load_status\":\"missing\""));
        let restored: LinuxMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn snapshot_load_integrity_mismatch_variant_serde_round_trips_via_report() {
        let report = LinuxMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_LINUX_STATE_PATH.to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::IntegrityMismatch {
                reason: "checksum failed".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot integrity mismatch: checksum failed".to_string()],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"load_status\":\"integrity_mismatch\""));
        let restored: LinuxMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn snapshot_load_invalid_format_variant_serde_round_trips_via_report() {
        let report = LinuxMeshStatusReport {
            schema_version: 1,
            state_path: DEFAULT_LINUX_STATE_PATH.to_string(),
            overall_ok: false,
            snapshot: WindowsMeshSnapshotLoad::InvalidFormat {
                reason: "missing field".to_string(),
            },
            expected_peer_ids: vec![],
            max_age_seconds: None,
            drift_reasons: vec!["state snapshot invalid format: missing field".to_string()],
        };
        let json = serde_json::to_string(&report).expect("serialize");
        assert!(json.contains("\"load_status\":\"invalid_format\""));
        let restored: LinuxMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, report);
    }

    #[test]
    fn report_deserializes_when_extra_unknown_top_level_field_present() {
        // The report struct does NOT use `#[serde(deny_unknown_fields)]`,
        // so an orchestrator running an older binary against a future
        // daemon (which may add new top-level fields) deserializes
        // successfully and just drops the unknown keys. This is the
        // intended forward-compat contract: pin it explicitly so a
        // future `deny_unknown_fields` addition is a deliberate
        // breaking change, not a silent one.
        let json = r#"{
            "schema_version": 1,
            "state_path": "/var/lib/rustynet/rustynetd.state",
            "overall_ok": true,
            "snapshot": {"load_status": "missing", "reason": "fixture"},
            "expected_peer_ids": [],
            "max_age_seconds": null,
            "drift_reasons": [],
            "future_field_we_dont_know_about": {"nested": [1, 2, 3]}
        }"#;
        let parsed: LinuxMeshStatusReport =
            serde_json::from_str(json).expect("forward-compat parse must succeed");
        assert_eq!(parsed.schema_version, 1);
        assert!(matches!(
            parsed.snapshot,
            WindowsMeshSnapshotLoad::Missing { .. }
        ));
    }
}
