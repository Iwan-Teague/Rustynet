#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct BootstrapHostsStage;

impl OrchestrationStage for BootstrapHostsStage {
    fn id(&self) -> StageId {
        StageId::BootstrapHosts
    }
    fn name(&self) -> &str {
        "bootstrap_hosts"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::CleanupHosts]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let source = match ctx.source_archive.clone() {
            Some(s) => s,
            None => return StageOutcome::Failed("no source archive in context".to_owned()),
        };
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .install_daemon(&source, ctx)
                        .map(|_| ())
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                };
                (alias.clone(), r)
            })
            .collect();
        let errors: Vec<String> = results
            .into_iter()
            .filter_map(|(alias, r)| r.err().map(|e| format!("{alias}: {e}")))
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
    fn no_source_archive_fails() {
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
        };
        assert!(matches!(
            BootstrapHostsStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
