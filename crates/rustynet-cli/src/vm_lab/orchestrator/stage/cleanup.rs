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

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let errors: Vec<String> = aliases
            .iter()
            .filter_map(|alias| {
                match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter.cleanup_runtime_state().map_err(|e| e.to_string()),
                    None => Ok(()), // no adapter = nothing to clean
                }
                .err()
                .map(|e| format!("{alias}: {e}"))
            })
            .collect();
        if errors.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_assignments_passes() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        assert_eq!(CleanupHostsStage.execute(&mut ctx), StageOutcome::Passed);
    }
}
