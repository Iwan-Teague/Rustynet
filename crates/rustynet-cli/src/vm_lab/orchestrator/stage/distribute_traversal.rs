#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct DistributeTraversalStage;

impl OrchestrationStage for DistributeTraversalStage {
    fn id(&self) -> StageId {
        StageId::DistributeTraversal
    }
    fn name(&self) -> &str {
        "distribute_traversal"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeAssignments]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }
    fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
        StageOutcome::Skipped
    }
}
