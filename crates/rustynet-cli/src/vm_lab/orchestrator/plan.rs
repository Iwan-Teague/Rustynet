#![allow(dead_code)]
use crate::vm_lab::orchestrator::stage::OrchestrationStage;
use crate::vm_lab::orchestrator::stage::active_exit::ActiveExitStage;
use crate::vm_lab::orchestrator::stage::anchor_validation::AnchorValidationStage;
use crate::vm_lab::orchestrator::stage::cleanup::CleanupHostsStage;
use crate::vm_lab::orchestrator::stage::collect_pubkeys::CollectPubkeysStage;
use crate::vm_lab::orchestrator::stage::distribute_assignments::DistributeAssignmentsStage;
use crate::vm_lab::orchestrator::stage::distribute_dns_zone::DistributeDnsZoneStage;
use crate::vm_lab::orchestrator::stage::distribute_membership::DistributeMembershipStage;
use crate::vm_lab::orchestrator::stage::distribute_traversal::DistributeTraversalStage;
use crate::vm_lab::orchestrator::stage::enforce_runtime::EnforceBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::exit_handoff::ExitHandoffStage;
use crate::vm_lab::orchestrator::stage::final_cleanup::FinalCleanupStage;
use crate::vm_lab::orchestrator::stage::install::BootstrapHostsStage;
use crate::vm_lab::orchestrator::stage::membership_init::MembershipInitStage;
use crate::vm_lab::orchestrator::stage::preflight::PreflightStage;
use crate::vm_lab::orchestrator::stage::relay_validation::RelayValidationStage;
use crate::vm_lab::orchestrator::stage::role_switch_matrix::RoleSwitchMatrixStage;
use crate::vm_lab::orchestrator::stage::source_archive::{
    ArchiveSourceMode, PrepareSourceArchiveStage,
};
use crate::vm_lab::orchestrator::stage::traffic_test_matrix::TrafficTestMatrixStage;
use crate::vm_lab::orchestrator::stage::validate_runtime::ValidateBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::verify_ssh::VerifySshReachabilityStage;

/// Builds the ordered list of stages for a lab run.
#[derive(Default)]
pub struct PlanBuilder {
    /// `--rebuild-nodes`: when `Some`, only these aliases rebuild in
    /// `bootstrap_hosts`; `None` rebuilds every node (the default).
    rebuild_only: Option<Vec<String>>,
    /// `--source-mode`: which tree the shipped source archive is built from.
    source_mode: ArchiveSourceMode,
}

impl PlanBuilder {
    pub fn new() -> Self {
        PlanBuilder::default()
    }

    /// Limit `bootstrap_hosts` rebuilds to the named aliases (fast single-node
    /// iteration). `None` keeps the default rebuild-all behaviour.
    pub fn with_rebuild_only(mut self, rebuild_only: Option<Vec<String>>) -> Self {
        self.rebuild_only = rebuild_only;
        self
    }

    /// Select the source archive mode (committed `HEAD` vs working tree).
    pub fn with_source_mode(mut self, source_mode: ArchiveSourceMode) -> Self {
        self.source_mode = source_mode;
        self
    }

    pub fn build(self) -> Vec<Box<dyn OrchestrationStage>> {
        let PlanBuilder {
            rebuild_only,
            source_mode,
        } = self;
        vec![
            Box::new(PreflightStage),
            Box::new(PrepareSourceArchiveStage::new(source_mode)),
            Box::new(VerifySshReachabilityStage),
            // cleanup + bootstrap must share the same rebuild set: a node we
            // refuse to clean must also be refused a rebuild (and vice versa).
            Box::new(CleanupHostsStage::new(rebuild_only.clone())),
            Box::new(BootstrapHostsStage::new(rebuild_only)),
            Box::new(CollectPubkeysStage),
            Box::new(MembershipInitStage),
            Box::new(DistributeMembershipStage),
            // Anchor capability-advertisement proof for any Anchor node —
            // folds the capability-advertisement surface of the formerly
            // Linux-only anchor test bin in, cross-OS. Runs after the
            // membership snapshot is distributed (so the daemon can derive
            // the anchor view) and before assignments are distributed.
            Box::new(AnchorValidationStage),
            Box::new(DistributeAssignmentsStage),
            Box::new(DistributeTraversalStage),
            Box::new(DistributeDnsZoneStage),
            Box::new(EnforceBaselineRuntimeStage),
            Box::new(ValidateBaselineRuntimeStage),
            // Relay-service-lifecycle proof for any Relay node — folds the
            // formerly Linux-only relay test bin in, cross-OS. Runs after
            // baseline-runtime validation, before the traffic matrix.
            Box::new(RelayValidationStage),
            Box::new(TrafficTestMatrixStage),
            Box::new(RoleSwitchMatrixStage),
            Box::new(ExitHandoffStage),
            Box::new(ActiveExitStage),
            Box::new(FinalCleanupStage),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_returns_20_stages() {
        let stages = PlanBuilder::new().build();
        assert_eq!(stages.len(), 20, "plan must contain exactly 20 stages");
    }

    #[test]
    fn active_exit_runs_after_exit_handoff_and_before_cleanup() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::ActiveExit) > pos(StageId::ExitHandoff));
        assert!(pos(StageId::ActiveExit) < pos(StageId::Cleanup));
    }

    #[test]
    fn anchor_validation_runs_after_distribute_membership_and_before_distribute_assignments() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::AnchorValidation) > pos(StageId::DistributeMembership));
        assert!(pos(StageId::AnchorValidation) < pos(StageId::DistributeAssignments));
    }

    #[test]
    fn relay_validation_runs_after_baseline_runtime_and_before_traffic_matrix() {
        use crate::vm_lab::orchestrator::stage::StageId;
        let stages = PlanBuilder::new().build();
        let pos = |id: StageId| stages.iter().position(|s| s.id() == id).unwrap();
        assert!(pos(StageId::RelayValidation) > pos(StageId::ValidateBaselineRuntime));
        assert!(pos(StageId::RelayValidation) < pos(StageId::TrafficTestMatrix));
    }

    #[test]
    fn stage_ids_are_unique() {
        use std::collections::HashSet;
        let stages = PlanBuilder::new().build();
        let ids: HashSet<_> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(ids.len(), stages.len(), "all stage IDs must be unique");
    }
}
