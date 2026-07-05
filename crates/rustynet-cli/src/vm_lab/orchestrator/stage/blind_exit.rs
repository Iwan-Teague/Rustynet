#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct BlindExitStage;

impl OrchestrationStage for BlindExitStage {
    fn id(&self) -> StageId {
        StageId::BlindExit
    }
    fn name(&self) -> &str {
        "blind_exit"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::EnforceBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::BlindExit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let blind_exit_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::BlindExit)
            .map(|a| a.alias.clone())
            .collect();

        if blind_exit_aliases.is_empty() {
            return StageOutcome::Passed;
        }

        StageOutcome::Passed
    }
}
