//! Anchor port-mapping-authority status check.
//!
//! `anchor_runtime_view_from_membership` (`gossip_runtime.rs`) already
//! computes the Pin-then-Seniority `port_mapping_authority_node_id`
//! election from signed membership, but that view was previously only
//! consumed internally by `daemon.rs::port_mapping_bring_up_skip_reason` —
//! there was no way to observe the election result from outside the running
//! daemon process. This module reads the persisted membership snapshot
//! fresh (the same file the daemon itself loads at startup) and reports
//! both the global election result AND whether `self_node_id` itself holds
//! the `anchor.port_mapping_authoritative` capability, as typed JSON.
//!
//! Deliberately does NOT assert "self wins the global election" as the
//! drift condition: the genesis/founding node is unconditionally granted
//! every anchor.* sub-capability (`run_membership_init`, regression-guarded
//! by `membership_init_genesis_includes_anchor_sub_caps`), and being the
//! most senior member it always wins Pin-then-Seniority over a later-joined
//! node — a live-lab caller would never legitimately assert "the newly
//! elected anchor wins" while the genesis node holds the same capability
//! and is unpinned. What the live-lab stage actually proves is the
//! end-to-end integration: does a capability granted via membership
//! amendment reach the daemon's persisted state and get correctly read
//! back — `self_holds_capability` is that assertion. `authority_node_id`
//! stays informational (who currently wins is a whole-topology property,
//! not this node's to prove).
//!
//! Wired through the CLI as `rustynetd anchor-port-mapping-status-check`.

use rustynet_control::membership::load_membership_snapshot;
use rustynet_control::roles::RoleCapability;
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
    pub self_holds_capability: bool,
    pub authority_node_id: Option<String>,
    pub is_self_authority: bool,
    pub overall_ok: bool,
    pub drift_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnchorPortMappingStatusOptions {
    pub snapshot_path: Option<PathBuf>,
    pub self_node_id: String,
    pub expect_self_capability: bool,
}

pub fn collect_anchor_port_mapping_status_report(
    options: &AnchorPortMappingStatusOptions,
) -> AnchorPortMappingStatusReport {
    let snapshot_path: PathBuf = options
        .snapshot_path
        .clone()
        .unwrap_or_else(|| PathBuf::from(DEFAULT_MACOS_MEMBERSHIP_SNAPSHOT_PATH));
    let snapshot_path_str = snapshot_path.display().to_string();

    let (self_holds_capability, authority_node_id, mut drift_reasons) =
        match load_membership_snapshot(snapshot_path.as_path()) {
            Ok(state) => {
                let holds = state
                    .nodes
                    .iter()
                    .find(|node| node.node_id == options.self_node_id)
                    .map(|node| {
                        node.capabilities
                            .contains(&RoleCapability::AnchorPortMappingAuthoritative)
                    })
                    .unwrap_or(false);
                let view = anchor_runtime_view_from_membership(&state);
                (holds, view.port_mapping_authority_node_id, Vec::new())
            }
            Err(err) => (
                false,
                None,
                vec![format!(
                    "membership snapshot unreadable at {snapshot_path_str}: {err}"
                )],
            ),
        };
    let is_self_authority = authority_node_id.as_deref() == Some(options.self_node_id.as_str());
    if options.expect_self_capability && !self_holds_capability {
        drift_reasons.push(format!(
            "expected {} to hold anchor.port_mapping_authoritative in its membership entry, but it does not",
            options.self_node_id
        ));
    }
    let overall_ok = drift_reasons.is_empty();
    AnchorPortMappingStatusReport {
        schema_version: 1,
        membership_snapshot_path: snapshot_path_str,
        self_node_id: options.self_node_id.clone(),
        self_holds_capability,
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
    fn anchor_status_overall_ok_when_self_holds_capability_and_leads() {
        // Happy path: a persisted snapshot in which SELF holds
        // anchor.port_mapping_authoritative and wins Pin-then-Seniority
        // must report overall_ok with empty drift. A LATER-JOINED node
        // holding the same capability still reports its own capability
        // truthfully while is_self_authority stays false (authority is
        // informational).
        use rustynet_control::membership::{
            MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
            MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
            load_membership_snapshot, persist_membership_snapshot,
        };
        use rustynet_control::roles::RoleCapability;

        let hex64 = |byte: u8| format!("{byte:02x}").repeat(32);
        let anchor_caps = || {
            vec![
                RoleCapability::AnchorGossipSeed,
                RoleCapability::AnchorBundlePull,
                RoleCapability::AnchorEnrollmentEndpoint,
                RoleCapability::AnchorRelayColocation,
                RoleCapability::AnchorPortMappingAuthoritative,
                // relay_colocation implies the relay host capability
                // (validate requires the pairing to be consistent).
                RoleCapability::RelayHost,
            ]
        };
        let mk_node = |node_id: &str, joined_at: u64| MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex64(0xBB),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: Vec::new(),
            capabilities: anchor_caps(),
            joined_at_unix: joined_at,
            updated_at_unix: joined_at,
        };

        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-anchor-status".to_owned(),
            epoch: 1,
            nodes: vec![mk_node("genesis", 100), mk_node("junior", 200)],
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

        let unique = format!(
            "anchor-status-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let snapshot = dir.join("membership.snapshot");
        persist_membership_snapshot(&snapshot, &state).expect("persist");

        // Genesis (earliest join) leads the election and reports ok.
        let report = collect_anchor_port_mapping_status_report(&AnchorPortMappingStatusOptions {
            snapshot_path: Some(snapshot.clone()),
            self_node_id: "genesis".to_owned(),
            expect_self_capability: false,
        });
        assert!(report.overall_ok, "drift: {:?}", report.drift_reasons);
        assert!(report.self_holds_capability);
        assert_eq!(report.authority_node_id.as_deref(), Some("genesis"));
        assert!(report.is_self_authority);

        // Junior holds the same capability but loses Pin-then-Seniority:
        // capability expectation satisfied, yet it is NOT the authority.
        let junior_report =
            collect_anchor_port_mapping_status_report(&AnchorPortMappingStatusOptions {
                snapshot_path: Some(snapshot.clone()),
                self_node_id: "junior".to_owned(),
                expect_self_capability: false,
            });
        assert!(junior_report.self_holds_capability);
        assert!(!junior_report.is_self_authority);
        assert!(junior_report.overall_ok);

        // Sanity: the persisted snapshot still loads through the
        // control-plane reader.
        assert!(load_membership_snapshot(&snapshot).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn capability_drift_reported_when_snapshot_loads_but_self_lacks_cap() {
        // Distinct arm: the snapshot LOADS fine, but SELF does not
        // hold anchor.port_mapping_authoritative while
        // expect_self_capability=true. The drift must name the
        // capability expectation specifically.
        use rustynet_control::membership::{
            MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
            MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
            persist_membership_snapshot,
        };
        use rustynet_control::roles::RoleCapability;

        let hex64 = |byte: u8| format!("{byte:02x}").repeat(32);
        let mk_node = |node_id: &str, joined_at: u64| MembershipNode {
            node_id: node_id.to_owned(),
            node_pubkey_hex: hex64(0xBB),
            owner: "owner@example.local".to_owned(),
            status: MembershipNodeStatus::Active,
            roles: Vec::new(),
            capabilities: vec![RoleCapability::AnchorGossipSeed],
            joined_at_unix: joined_at,
            updated_at_unix: joined_at,
        };

        let mut state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "net-anchor-drift".to_owned(),
            epoch: 1,
            nodes: vec![mk_node("genesis", 100), mk_node("junior", 200)],
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
        let _ = &mut state;

        let unique = format!(
            "anchor-status-drift-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let dir = std::env::temp_dir().join(unique);
        std::fs::create_dir_all(&dir).expect("tmp dir");
        let snapshot = dir.join("membership.snapshot");
        persist_membership_snapshot(&snapshot, &state).expect("persist");

        // Neither node holds the capability; junior expects it.
        let options = AnchorPortMappingStatusOptions {
            snapshot_path: Some(snapshot.clone()),
            self_node_id: "junior".to_owned(),
            expect_self_capability: true,
        };
        let report = collect_anchor_port_mapping_status_report(&options);
        assert!(!report.overall_ok);
        assert!(!report.self_holds_capability);
        assert_eq!(report.drift_reasons.len(), 1);
        assert!(
            report.drift_reasons[0]
                .contains("expected junior to hold anchor.port_mapping_authoritative"),
            "unexpected drift reason: {:?}",
            report.drift_reasons
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn missing_snapshot_file_reports_drift() {
        let options = AnchorPortMappingStatusOptions {
            snapshot_path: Some(PathBuf::from("/nonexistent/membership.snapshot")),
            self_node_id: "node-1".to_owned(),
            expect_self_capability: false,
        };
        let report = collect_anchor_port_mapping_status_report(&options);
        assert!(!report.overall_ok);
        assert!(report.authority_node_id.is_none());
        assert!(!report.is_self_authority);
        assert!(!report.self_holds_capability);
        assert!(
            report.drift_reasons[0].contains("unreadable"),
            "unexpected drift reason: {:?}",
            report.drift_reasons
        );
    }

    #[test]
    fn expect_self_capability_flags_drift_when_snapshot_missing() {
        // Missing snapshot -> self_holds_capability is false, so a caller
        // asserting expect_self_capability must see a drift reason distinct
        // from the plain unreadable-snapshot case.
        let options = AnchorPortMappingStatusOptions {
            snapshot_path: Some(PathBuf::from("/nonexistent/membership.snapshot")),
            self_node_id: "node-1".to_owned(),
            expect_self_capability: true,
        };
        let report = collect_anchor_port_mapping_status_report(&options);
        assert!(!report.overall_ok);
        assert_eq!(report.drift_reasons.len(), 2);
        assert!(
            report.drift_reasons[1]
                .contains("expected node-1 to hold anchor.port_mapping_authoritative")
        );
    }
}
