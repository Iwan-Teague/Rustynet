#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct EnforceBaselineRuntimeStage;

impl OrchestrationStage for EnforceBaselineRuntimeStage {
    fn id(&self) -> StageId {
        StageId::EnforceBaselineRuntime
    }
    fn name(&self) -> &str {
        "enforce_baseline_runtime"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeDnsZone]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter.enforce_runtime(ctx).map_err(|e| {
                        // The adapter's enforce wait reports only the symptom
                        // (e.g. "WireGuard adapter did not get an IPv4 address
                        // within 90s"). Append the daemon's own fail-closed
                        // reason from its log so the failure digest names the
                        // cause (e.g. a membership role mismatch). Best-effort.
                        match adapter.collect_daemon_failure_reason() {
                            Ok(Some(reason)) => format!("{e} | daemon: {reason}"),
                            _ => e.to_string(),
                        }
                    }),
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
            EnforceBaselineRuntimeStage.execute(&mut ctx),
            StageOutcome::Passed
        );
    }
}
