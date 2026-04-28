#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct CleanupHostsStage;

impl OrchestrationStage for CleanupHostsStage {
    fn id(&self) -> StageId {
        StageId::CleanupHosts
    }
    fn name(&self) -> &str {
        "cleanup_hosts"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::VerifySshReachability]
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
