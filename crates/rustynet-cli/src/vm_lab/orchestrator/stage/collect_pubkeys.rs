#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct CollectPubkeysStage;

impl OrchestrationStage for CollectPubkeysStage {
    fn id(&self) -> StageId {
        StageId::CollectPubkeys
    }
    fn name(&self) -> &str {
        "collect_pubkeys"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::BootstrapHosts]
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
