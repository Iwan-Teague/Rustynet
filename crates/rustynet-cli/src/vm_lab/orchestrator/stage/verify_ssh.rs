#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct VerifySshReachabilityStage;

impl OrchestrationStage for VerifySshReachabilityStage {
    fn id(&self) -> StageId {
        StageId::VerifySshReachability
    }
    fn name(&self) -> &str {
        "verify_ssh_reachability"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::PrepareSourceArchive]
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
