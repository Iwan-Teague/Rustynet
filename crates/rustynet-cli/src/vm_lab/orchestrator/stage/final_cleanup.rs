#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct FinalCleanupStage;

impl OrchestrationStage for FinalCleanupStage {
    fn id(&self) -> StageId {
        StageId::Cleanup
    }
    fn name(&self) -> &str {
        "cleanup"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitHandoff]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    /// Cleanup is a teardown `finally` block: it lists `ExitHandoff` as a
    /// dependency only for ORDERING (run last), but it must still run when an
    /// earlier stage failed — otherwise a mid-pipeline failure would
    /// skip-cascade cleanup and leave this run's killswitch + exit NAT residue
    /// on the guests (a release-blocker). `always_run` exempts it from the
    /// skip-cascade while preserving its last-in-order placement.
    fn always_run(&self) -> bool {
        true
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter.cleanup_runtime_state().map_err(|e| e.to_string()),
                    // An assigned node with no adapter is a construction bug, not
                    // "nothing to clean"; fail closed rather than leave prior
                    // runtime state (incl. a killswitch) in place.
                    None => Err(
                        "no adapter for assigned node; cannot clean prior runtime state".to_owned(),
                    ),
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
    fn empty_assignments_passes() {
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
        assert_eq!(FinalCleanupStage.execute(&mut ctx), StageOutcome::Passed);
    }
}
