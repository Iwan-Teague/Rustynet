#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct PrepareSourceArchiveStage;

impl OrchestrationStage for PrepareSourceArchiveStage {
    fn id(&self) -> StageId {
        StageId::PrepareSourceArchive
    }
    fn name(&self) -> &str {
        "prepare_source_archive"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::Preflight]
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
