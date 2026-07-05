#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct AdminIssueStage;

impl OrchestrationStage for AdminIssueStage {
    fn id(&self) -> StageId {
        StageId::AdminIssue
    }
    fn name(&self) -> &str {
        "admin_issue"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeMembership]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Admin]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let admin_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Admin)
            .map(|a| a.alias.clone())
            .collect();

        if admin_aliases.is_empty() {
            return StageOutcome::Passed;
        }

        StageOutcome::Passed
    }
}
