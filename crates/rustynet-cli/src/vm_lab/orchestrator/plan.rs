#![allow(dead_code)]
use crate::vm_lab::orchestrator::stage::OrchestrationStage;
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
use crate::vm_lab::orchestrator::stage::role_switch_matrix::RoleSwitchMatrixStage;
use crate::vm_lab::orchestrator::stage::source_archive::PrepareSourceArchiveStage;
use crate::vm_lab::orchestrator::stage::traffic_test_matrix::TrafficTestMatrixStage;
use crate::vm_lab::orchestrator::stage::validate_runtime::ValidateBaselineRuntimeStage;
use crate::vm_lab::orchestrator::stage::verify_ssh::VerifySshReachabilityStage;

/// Builds the ordered list of stages for a lab run.
pub struct PlanBuilder;

impl PlanBuilder {
    pub fn new() -> Self {
        PlanBuilder
    }

    pub fn build(self) -> Vec<Box<dyn OrchestrationStage>> {
        vec![
            Box::new(PreflightStage),
            Box::new(PrepareSourceArchiveStage),
            Box::new(VerifySshReachabilityStage),
            Box::new(CleanupHostsStage),
            Box::new(BootstrapHostsStage),
            Box::new(CollectPubkeysStage),
            Box::new(MembershipInitStage),
            Box::new(DistributeMembershipStage),
            Box::new(DistributeAssignmentsStage),
            Box::new(DistributeTraversalStage),
            Box::new(DistributeDnsZoneStage),
            Box::new(EnforceBaselineRuntimeStage),
            Box::new(ValidateBaselineRuntimeStage),
            Box::new(TrafficTestMatrixStage),
            Box::new(RoleSwitchMatrixStage),
            Box::new(ExitHandoffStage),
            Box::new(FinalCleanupStage),
        ]
    }
}

impl Default for PlanBuilder {
    fn default() -> Self {
        PlanBuilder::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_returns_17_stages() {
        let stages = PlanBuilder::new().build();
        assert_eq!(stages.len(), 17, "plan must contain exactly 17 stages");
    }

    #[test]
    fn stage_ids_are_unique() {
        use std::collections::HashSet;
        let stages = PlanBuilder::new().build();
        let ids: HashSet<_> = stages.iter().map(|s| s.id()).collect();
        assert_eq!(ids.len(), stages.len(), "all stage IDs must be unique");
    }
}
