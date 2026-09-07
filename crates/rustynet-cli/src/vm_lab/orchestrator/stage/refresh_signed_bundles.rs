#![allow(dead_code)]
//! RefreshSignedBundles: re-mint and redistribute the signed traversal and
//! dns_zone bundles immediately before the disruptive relay-forwards-frame
//! proof (HP-3). Long live-lab runs can outlive the bundles' configured TTL,
//! after which the HP-3 stage would prove frame forwarding against an expired
//! bundle and fail for freshness reasons rather than dataplane reasons.
//! This stage closes that freshness gap by driving the exact same mint +
//! distribute path the setup stages use (`distribute_bundle_kind` through the
//! exit adapter and the verifier-key barrier), so both HP-3 and the nodes
//! receive freshly signed bundles with the configured (never lengthened) TTL.
//!
//! Gated: only runs when relay-forwarding validation is elected for the run;
//! otherwise it is Skipped (fail-closed) so the default plan is unchanged.

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{BundleKind, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct RefreshSignedBundlesStage {
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl RefreshSignedBundlesStage {
    pub fn new(
        max_parallel_node_workers: usize,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

impl OrchestrationStage for RefreshSignedBundlesStage {
    fn id(&self) -> StageId {
        StageId::RefreshSignedBundles
    }
    fn name(&self) -> &str {
        "refresh_signed_bundles"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DeployRelayService, StageId::RelayValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if !ctx.relay_forwarding_validation_elected {
            return StageOutcome::Skipped(
                "relay forwarding validation not enabled for this run".to_owned(),
            );
        }
        use crate::vm_lab::orchestrator::stage::distribute_assignments::distribute_bundle_kind;
        let traversal = distribute_bundle_kind(
            ctx,
            BundleKind::Traversal,
            "rn-traversal",
            "traversal",
            self.max_parallel_node_workers,
            &self.shutdown_flag,
        );
        // Fail loud on the first failed re-mint: continuing on an expired or
        // absent traversal bundle would only move the failure into HP-3 with
        // a misleading dataplane-shaped error.
        if let StageOutcome::Failed(_) = traversal {
            return traversal;
        }
        let dns_zone = distribute_bundle_kind(
            ctx,
            BundleKind::DnsZone,
            "rn-dns-zone",
            "dns_zone",
            self.max_parallel_node_workers,
            &self.shutdown_flag,
        );
        if let StageOutcome::Failed(_) = dns_zone {
            return dns_zone;
        }
        // NOTE: no Skipped arm on dns_zone (or traversal) by design —
        // distribute_bundle_kind only ever returns Passed or Failed (a
        // missing exit node is Failed, never Skipped), so a Skipped outcome
        // here would be unreachable defensive code.
        traversal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        }
    }

    #[test]
    fn metadata_matches_catalog_entry() {
        let stage = RefreshSignedBundlesStage::new(
            1,
            std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
        );
        assert_eq!(stage.id(), StageId::RefreshSignedBundles);
        assert_eq!(stage.name(), "refresh_signed_bundles");
        assert_eq!(
            stage.dependencies(),
            &[StageId::DeployRelayService, StageId::RelayValidation]
        );
        assert!(stage.applies_to_roles().is_empty());
        assert!(matches!(stage.fanout(), StageFanout::Once));
    }

    #[test]
    fn skips_when_relay_forwarding_validation_not_elected() {
        let mut ctx = empty_ctx();
        ctx.relay_forwarding_validation_elected = false;
        assert!(matches!(
            RefreshSignedBundlesStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Skipped(_)
        ));
    }

    #[test]
    fn fail_closed_without_assignments_when_elected() {
        // With the election on but no assignments (no Exit node), the first
        // distribute call must Fail loudly rather than pass a skip downstream.
        let mut ctx = empty_ctx();
        ctx.relay_forwarding_validation_elected = true;
        assert!(matches!(
            RefreshSignedBundlesStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
