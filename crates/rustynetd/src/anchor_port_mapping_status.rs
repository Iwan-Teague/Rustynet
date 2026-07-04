//! Anchor port-mapping-authority status check.
//!
//! `anchor_runtime_view_from_membership` (`gossip_runtime.rs`) already
//! computes the Pin-then-Seniority `port_mapping_authority_node_id`
//! election from signed membership, but that view was previously only
//! consumed internally by `daemon.rs::port_mapping_bring_up_skip_reason` —
//! there was no way to observe the election result from outside the running
//! daemon process. This module reads the persisted membership snapshot
//! fresh (the same file the daemon itself loads at startup) and reports the
//! election result as typed JSON, so a live-lab stage can assert which node
//! actually holds `anchor.port_mapping_authoritative` authority.
//!
//! Wired through the CLI as `rustynetd anchor-port-mapping-status-check`.

use rustynet_control::membership::load_membership_snapshot;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::gossip_runtime::anchor_runtime_view_from_membership;

pub const DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH: &str =
    "/usr/local/var/rustynet/membership/membership.snapshot";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorPortMappingStatusReport {
    pub schema_version: u32,
    pub membership_snapshot_path: String,
    pub self_node_id: String,
    pub authority_node_id: Option<String>,
    pub is_self_authority: bool,
    pub overall_ok: bool,
    pub drift_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorPortMappingStatusOptions {
    pub snapshot_path: Option<PathBuf>,
    pub self_node_id: String,
    pub expect_self_authority: bool,
}

pub fn collect_anchor_port_mapping_status_report(
    options: &AnchorPortMappingStatusOptions,
) -> AnchorPortMappingStatusReport {
    let snapshot_path: PathBuf = options
        .snapshot_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH));
    let snapshot_path_str = snapshot_path.display().to_string();

    let (authority_node_id, mut drift_reasons) =
        match load_membership_snapshot(snapshot_path.as_path()) {
            Ok(state) => {
                let view = anchor_runtime_view_from_membership(&state);
                (view.port_mapping_authority_node_id, Vec::new())
            }
            Err(err) => (
                None,
                vec![format!(
                    "membership snapshot unreadable at {snapshot_path_str}: {err}"
                )],
            ),
        };
    let is_self_authority = authority_node_id.as_deref() == Some(options.self_node_id.as_str());
    if options.expect_self_authority && !is_self_authority {
        drift_reasons.push(format!(
            "expected {} to hold port-mapping authority, but the election resolved to {:?}",
            options.self_node_id, authority_node_id
        ));
    }
    let overall_ok = drift_reasons.is_empty();
    AnchorPortMappingStatusReport {
        schema_version: 1,
        membership_snapshot_path: snapshot_path_str,
        self_node_id: options.self_node_id.clone(),
        authority_node_id,
        is_self_authority,
        overall_ok,
        drift_reasons,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_snapshot_file_reports_drift() {
        let options = AnchorPortMappingStatusOptions {
            snapshot_path: Some(PathBuf::from("/nonexistent/membership.snapshot")),
            self_node_id: "node-1".to_owned(),
            expect_self_authority: false,
        };
        let report = collect_anchor_port_mapping_status_report(&options);
        assert!(!report.overall_ok);
        assert!(report.authority_node_id.is_none());
        assert!(!report.is_self_authority);
        assert!(
            report.drift_reasons[0].contains("unreadable"),
            "unexpected drift reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn expect_self_authority_flags_drift_when_election_resolves_elsewhere() {
        // Missing snapshot -> authority_node_id is None, so a caller
        // asserting expect_self_authority must see a drift reason distinct
        // from the plain unreadable-snapshot case.
        let options = AnchorPortMappingStatusOptions {
            snapshot_path: Some(PathBuf::from("/nonexistent/membership.snapshot")),
            self_node_id: "node-1".to_owned(),
            expect_self_authority: true,
        };
        let report = collect_anchor_port_mapping_status_report(&options);
        assert!(!report.overall_ok);
        assert_eq!(report.drift_reasons.len(), 2);
        assert!(report.drift_reasons[1].contains("expected node-1 to hold port-mapping authority"));
    }
}
