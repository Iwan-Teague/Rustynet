#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::install::node_in_rebuild_set;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct FinalCleanupStage {
    /// `--rebuild-nodes`: when `Some`, only these aliases are torn down at
    /// final cleanup. Nodes outside the set were reused by this run, so their
    /// daemon must stay up for future partial-rebuild runs.
    /// `None` = clean every node (the default).
    rebuild_only: Option<Vec<String>>,
}

impl FinalCleanupStage {
    pub fn new(rebuild_only: Option<Vec<String>>) -> Self {
        FinalCleanupStage { rebuild_only }
    }
}

impl OrchestrationStage for FinalCleanupStage {
    fn id(&self) -> StageId {
        StageId::Cleanup
    }
    fn name(&self) -> &str {
        "cleanup"
    }
    fn dependencies(&self) -> &[StageId] {
        // PlanBuilder inserts cleanup last. Keeping this dependency-free makes
        // filtered setup/run-only plans valid without inventing a dependency
        // on an intentionally absent live stage.
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    /// Cleanup is a teardown `finally` block. It is inserted last for ordering
    /// and must still run when an earlier
    /// stage failed — otherwise a mid-pipeline failure would
    /// skip-cascade cleanup and leave this run's killswitch + exit NAT residue
    /// on the guests (a release-blocker). `always_run` exempts it from the
    /// skip-cascade while preserving its last-in-order placement.
    fn always_run(&self) -> bool {
        true
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let rebuild_only = self.rebuild_only.as_deref();
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .filter_map(|alias| {
                if !node_in_rebuild_set(rebuild_only, alias) {
                    return None;
                }
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => cleanup_then_assert(
                        || adapter.cleanup_runtime_state().map_err(|e| e.to_string()),
                        || adapter.assert_node_clean().map_err(|e| e.to_string()),
                    ),
                    // An assigned node with no adapter is a construction bug, not
                    // "nothing to clean"; fail closed rather than leave prior
                    // runtime state (incl. a killswitch) in place.
                    None => Err(
                        "no adapter for assigned node; cannot clean prior runtime state".to_owned(),
                    ),
                };
                Some((alias.clone(), r))
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

fn cleanup_then_assert<C, A>(cleanup: C, assert_clean: A) -> Result<(), String>
where
    C: FnOnce() -> Result<(), String>,
    A: FnOnce() -> Result<(), String>,
{
    cleanup().and_then(|()| assert_clean())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn ctx_with_assignment(alias: &str) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: alias.to_owned(),
                role: NodeRole::Client,
            }],
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
        }
    }

    #[test]
    fn node_outside_rebuild_set_is_skipped_not_failed() {
        let mut ctx = ctx_with_assignment("reused-node");
        let stage = FinalCleanupStage::new(Some(vec!["other-node".to_owned()]));
        assert_eq!(stage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn node_with_no_adapter_in_rebuild_set_fails_closed() {
        let mut ctx = ctx_with_assignment("reused-node");
        let stage = FinalCleanupStage::new(None);
        assert!(matches!(stage.execute(&mut ctx), StageOutcome::Failed(_)));
    }

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
            orchestrator_dialect: None,
        };
        assert_eq!(
            FinalCleanupStage::new(None).execute(&mut ctx),
            StageOutcome::Passed
        );
    }

    #[test]
    fn successful_cleanup_with_detected_residue_fails() {
        let result = cleanup_then_assert(
            || Ok(()),
            || Err("node still dirty: relay service running".to_owned()),
        );
        assert_eq!(
            result,
            Err("node still dirty: relay service running".to_owned())
        );
    }
}
