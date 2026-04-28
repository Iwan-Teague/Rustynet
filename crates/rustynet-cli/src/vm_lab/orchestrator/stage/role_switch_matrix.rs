#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct RoleSwitchMatrixStage;

impl OrchestrationStage for RoleSwitchMatrixStage {
    fn id(&self) -> StageId {
        StageId::RoleSwitchMatrix
    }
    fn name(&self) -> &str {
        "role_switch_matrix"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::TrafficTestMatrix]
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
