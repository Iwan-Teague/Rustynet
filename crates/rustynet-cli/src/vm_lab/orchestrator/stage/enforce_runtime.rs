#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct EnforceBaselineRuntimeStage;

impl OrchestrationStage for EnforceBaselineRuntimeStage {
    fn id(&self) -> StageId {
        StageId::EnforceBaselineRuntime
    }
    fn name(&self) -> &str {
        "enforce_baseline_runtime"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeDnsZone]
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
