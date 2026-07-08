#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::admin_issue::validate_admin_issue;
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
            return StageOutcome::Skipped;
        }

        let mut failures: Vec<String> = Vec::new();
        for alias in &admin_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for admin node"));
                    continue;
                }
            };
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            if let Err(e) = validate_admin_issue(&*shell, alias) {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if failures.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(failures.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_assignments_skips() {
        let mut ctx = OrchestrationContext {
            assignments: vec![],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        };
        assert_eq!(AdminIssueStage.execute(&mut ctx), StageOutcome::Skipped);
    }
}
