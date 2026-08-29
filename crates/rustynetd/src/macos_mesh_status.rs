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
//! ## Verified membership node ids (additive, STRICT)
//!
//! The session snapshot's `peer_ids` hold ADVERTISED ROUTE CIDRS, not node
//! ids, so a peer-visibility assertion over them can only prove "some routes
//! exist". `member_node_ids` is a SEPARATE, ADDITIVE field populated from the
//! SIGNED membership snapshot (rustynet-control `load_membership_snapshot` —
//! file-permission security checks, digest integrity verification, and full
//! state validation, before any node id is read; the same verify-before-read
//! primitive the anchor port-mapping status check uses). The daemon persists
//! that snapshot only after verifying the anchor's signed membership bundle,
//! making rustynet-control membership the authoritative node-id source.
//! Only `MembershipNodeStatus::Active` nodes are reported; revoked or
//! quarantined roster rows never satisfy a peer-visibility assertion.
//!
//! Fail-closed contract: if the membership snapshot is missing, unreadable,
//! or fails verification, the report carries a drift reason and
//! `overall_ok=false` EVEN WHEN no node-id expectations were requested — a
//! membership read failure is never silently reported as "no peers".
//! Roster `updated_at_unix` measures the last membership CHANGE, not node
//! liveness, so no time-based staleness is applied here; the freshness of
//! the node's view stays enforced by `max_age_seconds` on the session
//! snapshot. Expected-node-id assertions are checked against the VERIFIED
//! list: each `--expected-node-id` absent from it is a named drift reason.
//!
//! Serialization is additive and backward-compatible: the new fields carry
//! `#[serde(default)]`, so a report produced before this addition still
//! deserializes — with `member_node_ids` defaulting to `Invalid`, which the
//! orchestrator-side evaluator treats as a hard failure (never as "empty
//! roster").
//!
//! Wired through the CLI as `rustynetd macos-mesh-status-check`. The
//! orchestrator's `MacosDaemonProbe` dispatches the `MeshStatus` op here.

use crate::resilience::{ResilienceError, load_session_snapshot};
use crate::windows_mesh_status::{WindowsMeshSnapshotLoad, evaluate_windows_mesh_status};
use rustynet_control::membership::{MembershipNodeStatus, load_membership_snapshot};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

pub const DEFAULT_MACOS_STATE_PATH: &str = "/usr/local/var/rustynet/rustynetd.state";

/// Default signed-membership snapshot path on macOS. MUST equal the daemon's
/// membership snapshot location (`DEFAULT_MEMBERSHIP_SNAPSHOT_PATH` under the
/// same state root); pinned by
/// `validator_default_membership_path_is_under_state_root` below.
pub const DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";

/// Outcome of the verify-signed-membership-before-read step backing the
/// report's `member_node_ids` field. Tagged `membership_load_status` so the
/// tag namespace stays disjoint from the session snapshot's `load_status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "membership_load_status", rename_all = "snake_case")]
pub enum MembershipNodeIdsLoad {
    /// The membership snapshot verified; node ids are the ACTIVE members,
    /// sorted for deterministic output.
    Verified { node_ids: Vec<String> },
    /// The membership snapshot file does not exist.
    Missing { reason: String },
    /// The membership snapshot exists but could not be verified (permissions,
    /// digest, or state validation failure). Reports produced before this
    /// field existed deserialize to this variant via `Default`, so a stale
    /// report can never be read as an empty roster.
    Invalid { reason: String },
}

impl Default for MembershipNodeIdsLoad {
    fn default() -> Self {
        Self::Invalid {
            reason: "member_node_ids field absent from this report (pre-addition producer); \
                     failing closed"
                .to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacosMeshStatusReport {
    pub schema_version: u32,
    pub state_path: String,
    pub overall_ok: bool,
    pub snapshot: WindowsMeshSnapshotLoad,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
    pub drift_reasons: Vec<String>,
    /// Path of the signed-membership snapshot the node ids were verified
    /// against. `#[serde(default)]` keeps pre-addition reports deserializable.
    #[serde(default)]
    pub membership_snapshot_path: String,
    /// Node-id expectations echoed back for audit parity with
    /// `expected_peer_ids`.
    #[serde(default)]
    pub expected_node_ids: Vec<String>,
    /// Verified membership node ids (STRICT: unavailable membership is a
    /// drift, never an empty roster — see the module docs).
    #[serde(default)]
    pub member_node_ids: MembershipNodeIdsLoad,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MacosMeshStatusOptions {
    pub state_path: Option<PathBuf>,
    pub expected_peer_ids: Vec<String>,
    pub max_age_seconds: Option<i64>,
    /// Node ids the reporter must find among the VERIFIED membership members.
    pub expected_node_ids: Vec<String>,
    /// Override for the signed-membership snapshot location (tests, custom
    /// state roots). Defaults to [`DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH`].
    pub membership_snapshot_path: Option<PathBuf>,
}

pub fn collect_macos_mesh_status_report(options: &MacosMeshStatusOptions) -> MacosMeshStatusReport {
    let state_path: PathBuf = options
        .state_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MACOS_STATE_PATH));
    let state_path_str = state_path.display().to_string();
    let membership_snapshot_path: PathBuf = options
        .membership_snapshot_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH));
    let membership_snapshot_path_str = membership_snapshot_path.display().to_string();
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
    // Verify the signed membership state BEFORE deriving any node id from it,
    // then assert the node-id expectations against the VERIFIED member list.
    let (member_node_ids, membership_drift_reasons) =
        match load_membership_snapshot(membership_snapshot_path.as_path()) {
            Ok(state) => {
                let mut node_ids: Vec<String> = state
                    .nodes
                    .iter()
                    .filter(|node| node.status == MembershipNodeStatus::Active)
                    .map(|node| node.node_id.clone())
                    .collect();
                node_ids.sort();
                let mut drift = Vec::new();
                for expected in &options.expected_node_ids {
                    if !node_ids.iter().any(|id| id == expected) {
                        drift.push(format!(
                            "expected node {expected} not present in verified membership node \
                             ids at {membership_snapshot_path_str}"
                        ));
                    }
                }
                (MembershipNodeIdsLoad::Verified { node_ids }, drift)
            }
            Err(err) => {
                let reason = format!(
                    "membership snapshot unreadable at {membership_snapshot_path_str}: {err}"
                );
                // Fail closed ALWAYS — with or without node-id expectations.
                // An unavailable membership read must surface as drift, never
                // as an implicitly empty roster.
                let load = if membership_snapshot_path.exists() {
                    MembershipNodeIdsLoad::Invalid {
                        reason: reason.clone(),
                    }
                } else {
                    MembershipNodeIdsLoad::Missing {
                        reason: reason.clone(),
                    }
                };
                (
                    load,
                    vec![format!(
                        "membership node ids unavailable (fail-closed): {reason}"
                    )],
                )
            }
        };
    let mut drift_reasons = evaluate_windows_mesh_status(
        &snapshot,
        options.expected_peer_ids.as_slice(),
        options.max_age_seconds,
    );
    // Membership drift is appended AFTER the session-snapshot drift so the
    // existing reason ordering (staleness, CIDR expectations) is unchanged.
    drift_reasons.extend(membership_drift_reasons);
    let overall_ok = drift_reasons.is_empty();
    MacosMeshStatusReport {
        schema_version: 1,
        state_path: state_path_str,
        overall_ok,
        snapshot,
        expected_peer_ids: options.expected_peer_ids.clone(),
        max_age_seconds: options.max_age_seconds,
        drift_reasons,
        membership_snapshot_path: membership_snapshot_path_str,
        expected_node_ids: options.expected_node_ids.clone(),
        member_node_ids,
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

    /// Options with the membership knobs defaulted; individual tests override.
    fn test_options(state_path: Option<PathBuf>) -> MacosMeshStatusOptions {
        MacosMeshStatusOptions {
            state_path,
            expected_peer_ids: vec![],
            max_age_seconds: None,
            expected_node_ids: vec![],
            membership_snapshot_path: None,
        }
    }

    /// Persist a minimal valid signed-membership snapshot whose ACTIVE
    /// roster is exactly `node_ids`, and return its path.
    fn plant_membership_snapshot(dir: &std::path::Path, node_ids: &[&str]) -> PathBuf {
        use rustynet_control::membership::{
            MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
            MembershipApproverStatus, MembershipNode, MembershipState, persist_membership_snapshot,
        };
        let hex64 = |byte: u8| format!("{byte:02x}").repeat(32);
        let nodes = node_ids
            .iter()
            .enumerate()
            .map(|(index, node_id)| MembershipNode {
                node_id: (*node_id).to_owned(),
                node_pubkey_hex: hex64(0xBB),
                owner: "owner@example.local".to_owned(),
                status: MembershipNodeStatus::Active,
                roles: Vec::new(),
                // State validation requires every ACTIVE node to hold at
                // least one capability; the specific one is irrelevant to
                // node-id visibility.
                capabilities: vec![rustynet_control::roles::RoleCapability::AnchorGossipSeed],
                joined_at_unix: 100 + index as u64 * 10,
                updated_at_unix: 100 + index as u64 * 10,
            })
            .collect();
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-macos-mesh-status".to_owned(),
            epoch: 1,
            nodes,
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex64(0xAA),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 50,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        let snapshot = dir.join("membership.snapshot");
        persist_membership_snapshot(&snapshot, &state).expect("persist membership fixture");
        snapshot
    }

    fn unique_temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        std::env::temp_dir().join(format!("{label}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn missing_state_file_reports_drift() {
        let options = MacosMeshStatusOptions {
            state_path: Some(PathBuf::from("/nonexistent/macos/rustynetd.state")),
            ..test_options(None)
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
            membership_snapshot_path: DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            expected_node_ids: vec!["node-1".to_owned()],
            member_node_ids: MembershipNodeIdsLoad::Missing {
                reason: "unreadable".to_owned(),
            },
        };
        let json = serde_json::to_string(&report).expect("serialize");
        let parsed: MacosMeshStatusReport = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(parsed, report);
        // Pin the additive tag namespace: disjoint from the snapshot's
        // `load_status` so the two enum blocks cannot collide in JSON.
        assert!(
            json.contains("\"membership_load_status\":\"missing\""),
            "member_node_ids tag shape: {json}"
        );
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
        let membership_snapshot_path = plant_membership_snapshot(&dir, &["node-a", "node-b"]);
        let report = collect_macos_mesh_status_report(&MacosMeshStatusOptions {
            state_path: Some(state_path),
            membership_snapshot_path: Some(membership_snapshot_path),
            max_age_seconds: Some(180),
            ..test_options(None)
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
            ..test_options(None)
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
        let options = test_options(None);
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
            ..test_options(None)
        };
        let report = collect_macos_mesh_status_report(&options);
        assert_eq!(report.state_path, custom);
        // The membership path is echoed too, so the drift block can name
        // exactly which signed-membership file was verified.
        assert_eq!(
            report.membership_snapshot_path,
            DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH
        );
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
            membership_snapshot_path: DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            expected_node_ids: vec!["node-a".to_owned()],
            member_node_ids: MembershipNodeIdsLoad::Verified {
                node_ids: vec!["node-a".to_owned()],
            },
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"ok\""),
            "Ok variant tag shape: {body}"
        );
        assert!(
            body.contains("\"membership_load_status\":\"verified\""),
            "Verified membership tag shape: {body}"
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
            membership_snapshot_path: DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            expected_node_ids: vec![],
            member_node_ids: MembershipNodeIdsLoad::Invalid {
                reason: "digest mismatch".to_owned(),
            },
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
            membership_snapshot_path: DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.to_owned(),
            expected_node_ids: vec![],
            member_node_ids: MembershipNodeIdsLoad::Invalid {
                reason: "unverifiable".to_owned(),
            },
        };
        let body = serde_json::to_string(&report).expect("serialize");
        assert!(
            body.contains("\"load_status\":\"invalid_format\""),
            "InvalidFormat variant tag shape: {body}"
        );
        let parsed: MacosMeshStatusReport = serde_json::from_str(&body).expect("deserialize");
        assert_eq!(parsed, report);
    }

    // ----- Verified membership node ids (STRICT peer visibility) ----------

    /// The core STRICT assertion: with a fresh session snapshot AND a valid
    /// signed-membership snapshot, the report carries the VERIFIED active
    /// member node ids and an expected-node-id assertion passes.
    #[test]
    fn verified_membership_populates_node_ids_and_satisfies_expected_node_assertion() {
        let dir = unique_temp_dir("macos-mesh-membership-ok");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let state_path = dir.join("rustynetd.state");
        crate::resilience::persist_session_snapshot(
            &crate::resilience::SessionStateSnapshot {
                timestamp_unix: now,
                peer_ids: vec!["10.7.0.0/24".to_owned()],
                selected_exit_node: None,
                lan_access_enabled: false,
            },
            &state_path,
        )
        .expect("plant a fresh snapshot");
        // Planted out of roster order to pin the sorted output.
        let membership_snapshot_path = plant_membership_snapshot(&dir, &["node-b", "node-a"]);
        let options = MacosMeshStatusOptions {
            state_path: Some(state_path),
            membership_snapshot_path: Some(membership_snapshot_path.clone()),
            expected_node_ids: vec!["node-a".to_owned()],
            ..test_options(None)
        };
        let report = collect_macos_mesh_status_report(&options);
        assert!(
            report.drift_reasons.is_empty(),
            "expected node present in verified membership must pass: drift = {:?}",
            report.drift_reasons
        );
        assert!(report.overall_ok);
        assert_eq!(
            report.member_node_ids,
            MembershipNodeIdsLoad::Verified {
                // Sorted, not roster order.
                node_ids: vec!["node-a".to_owned(), "node-b".to_owned()],
            },
            "member_node_ids must carry the verified ACTIVE roster, sorted"
        );
        assert_eq!(
            report.membership_snapshot_path,
            membership_snapshot_path.display().to_string()
        );
        assert_eq!(report.expected_node_ids, vec!["node-a".to_owned()]);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The strong peer-visibility assertion must FAIL when an expected node id
    /// is absent from the verified membership roster.
    #[test]
    fn missing_expected_node_id_is_a_named_drift() {
        let dir = unique_temp_dir("macos-mesh-membership-missing-node");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let membership_snapshot_path = plant_membership_snapshot(&dir, &["node-a"]);
        let options = MacosMeshStatusOptions {
            membership_snapshot_path: Some(membership_snapshot_path),
            expected_node_ids: vec!["node-a".to_owned(), "node-intruder".to_owned()],
            ..test_options(None)
        };
        let report = collect_macos_mesh_status_report(&options);
        assert!(!report.overall_ok);
        assert!(
            report.drift_reasons.iter().any(|reason| reason.contains(
                "expected node node-intruder not present in \
                                                  verified membership node ids"
            )),
            "the drift must name the absent node id: {:?}",
            report.drift_reasons
        );
        // The node that IS present must not be flagged.
        assert!(
            !report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("node-a not present")),
            "a present expected node must not drift: {:?}",
            report.drift_reasons
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// FAIL-CLOSED: an unreadable membership snapshot is a drift reason EVEN
    /// WHEN no node-id expectations were requested. A membership read failure
    /// must never be silently reported as an (empty) roster.
    #[test]
    fn membership_unavailable_fails_closed_even_without_expectations() {
        let dir = unique_temp_dir("macos-mesh-membership-unavailable");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let state_path = dir.join("rustynetd.state");
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
        let options = MacosMeshStatusOptions {
            state_path: Some(state_path),
            membership_snapshot_path: Some(dir.join("absent-membership.snapshot")),
            max_age_seconds: Some(180),
            ..test_options(None)
        };
        let report = collect_macos_mesh_status_report(&options);
        assert!(
            !report.overall_ok,
            "membership unavailable must fail closed"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.starts_with("membership node ids unavailable (fail-closed)")),
            "drift must name the fail-closed membership read: {:?}",
            report.drift_reasons
        );
        assert!(
            matches!(
                report.member_node_ids,
                MembershipNodeIdsLoad::Missing { .. }
            ),
            "an absent membership file must read as Missing, never as an empty Verified roster"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A revoked roster row keeps its node id in the file; only ACTIVE
    /// members may satisfy a peer-visibility assertion.
    #[test]
    fn revoked_member_excluded_from_verified_node_ids() {
        use rustynet_control::membership::{
            MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
            MembershipApproverStatus, MembershipNode, MembershipState, persist_membership_snapshot,
        };
        let dir = unique_temp_dir("macos-mesh-membership-revoked");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let hex64 = |byte: u8| format!("{byte:02x}").repeat(32);
        let mk_node = |node_id: &str, status: MembershipNodeStatus| MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex64(0xBB),
            owner: "owner@example.local".to_owned(),
            status,
            roles: Vec::new(),
            // Only ACTIVE nodes require a capability to pass validation.
            capabilities: if status == MembershipNodeStatus::Active {
                vec![rustynet_control::roles::RoleCapability::AnchorGossipSeed]
            } else {
                Vec::new()
            },
            joined_at_unix: 100,
            updated_at_unix: 200,
        };
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-macos-mesh-status-revoked".to_owned(),
            epoch: 1,
            nodes: vec![
                mk_node("node-live", MembershipNodeStatus::Active),
                mk_node("node-gone", MembershipNodeStatus::Revoked),
            ],
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex64(0xAA),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 50,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        let membership_snapshot_path = dir.join("membership.snapshot");
        persist_membership_snapshot(&membership_snapshot_path, &state)
            .expect("persist membership fixture");
        let options = MacosMeshStatusOptions {
            membership_snapshot_path: Some(membership_snapshot_path),
            expected_node_ids: vec!["node-gone".to_owned()],
            ..test_options(None)
        };
        let report = collect_macos_mesh_status_report(&options);
        assert!(
            !report.overall_ok,
            "a revoked node must NOT satisfy the assertion"
        );
        assert!(
            report
                .drift_reasons
                .iter()
                .any(|reason| reason.contains("node-gone not present")),
            "revoked node must be reported absent: {:?}",
            report.drift_reasons
        );
        match &report.member_node_ids {
            MembershipNodeIdsLoad::Verified { node_ids } => {
                assert_eq!(node_ids, &vec!["node-live".to_owned()]);
            }
            other => panic!("expected Verified roster, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Serialization is additive + backward-compatible: a report produced
    /// before the member_node_ids field existed still deserializes — but the
    /// field defaults to `Invalid` (fail-closed), never to an empty roster.
    #[test]
    fn pre_addition_report_without_member_node_ids_deserializes_fail_closed() {
        let legacy = serde_json::json!({
            "schema_version": 1,
            "state_path": "/usr/local/var/rustynet/rustynetd.state",
            "overall_ok": true,
            "snapshot": {
                "load_status": "ok",
                "timestamp_unix": 1_700_000_000u64,
                "age_seconds": 5,
                "peer_ids": [],
                "selected_exit_node": null,
                "lan_access_enabled": false
            },
            "expected_peer_ids": [],
            "max_age_seconds": 180,
            "drift_reasons": []
        });
        let parsed: MacosMeshStatusReport =
            serde_json::from_str(&legacy.to_string()).expect("legacy report must deserialize");
        assert_eq!(
            parsed.member_node_ids,
            MembershipNodeIdsLoad::Invalid {
                reason: "member_node_ids field absent from this report (pre-addition producer); \
                         failing closed"
                    .to_owned()
            },
            "a legacy report must read as Invalid, never as an empty Verified roster"
        );
        assert_eq!(parsed.expected_node_ids, Vec::<String>::new());
        assert_eq!(parsed.membership_snapshot_path, "");
    }

    /// The membership snapshot default MUST live under the same state root
    /// the daemon uses on macOS, mirroring the state-path pin above.
    #[test]
    fn validator_default_membership_path_is_under_state_root() {
        assert!(
            DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.starts_with("/usr/local/var/rustynet"),
            "membership snapshot default must sit under the macOS state root"
        );
        assert!(
            DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH.ends_with("membership.snapshot"),
            "membership snapshot default must name the snapshot file"
        );
    }
}
