#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct ValidateBaselineRuntimeStage;

impl OrchestrationStage for ValidateBaselineRuntimeStage {
    fn id(&self) -> StageId {
        StageId::ValidateBaselineRuntime
    }
    fn name(&self) -> &str {
        "validate_baseline_runtime"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::EnforceBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        use crate::vm_lab::DaemonProbeOp;

        const OPS: &[DaemonProbeOp] = &[
            DaemonProbeOp::RuntimeAcls,
            DaemonProbeOp::ServiceHardening,
            DaemonProbeOp::KeyCustody,
            DaemonProbeOp::Authenticode,
            DaemonProbeOp::MeshStatus,
            DaemonProbeOp::DnsFailclosed,
        ];

        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        // Collect pass: gather all results before any mutation
        let all_results: Vec<(String, Vec<Result<bool, String>>)> = aliases
            .iter()
            .map(|alias| {
                let op_results: Vec<Result<bool, String>> = OPS
                    .iter()
                    .map(|&op| match ctx.adapters.get(alias.as_str()) {
                        Some(adapter) => adapter
                            .run_validator(op)
                            .map(|r| r.passed)
                            .map_err(|e| e.to_string()),
                        None => Err(format!("no adapter for '{alias}'")),
                    })
                    .collect();
                (alias.clone(), op_results)
            })
            .collect();

        let mut errors = Vec::new();
        for (alias, op_results) in all_results {
            for (op, r) in OPS.iter().zip(op_results) {
                match r {
                    Ok(false) => errors.push(format!("{alias}/{op:?}: validation not passed")),
                    Err(e) => errors.push(format!("{alias}/{op:?}: {e}")),
                    Ok(true) => {}
                }
            }
        }

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
        assert_eq!(
            ValidateBaselineRuntimeStage.execute(&mut ctx),
            StageOutcome::Passed
        );
    }
}
