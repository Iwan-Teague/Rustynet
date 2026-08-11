#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct ValidateBaselineRuntimeStage {
    max_parallel_node_workers: usize,
    shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl ValidateBaselineRuntimeStage {
    pub fn new(
        max_parallel_node_workers: usize,
        shutdown_flag: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        Self {
            max_parallel_node_workers: max_parallel_node_workers.max(1),
            shutdown_flag,
        }
    }
}

// MeshStatus deliberately ABSENT (QH-39). This path adjudicates a probe
// by substring-matching `"overall_ok": true` in the raw stdout
// (`adapter/ssh.rs:584-589`) — it never deserializes, so no evaluator-side
// guard can ever reach it. That made it a strictly WEAKER duplicate of the
// dedicated `mesh_status_validation` stage, which applies the typed
// evaluator AND the §4.7 identity challenge. Keeping both meant the weaker
// one minted `macos_stage_baseline_runtime = pass` for a node that reached
// no peer. The mesh verdict now comes from the dedicated stage only.
pub(crate) const BASELINE_PROBE_OPS: &[crate::vm_lab::DaemonProbeOp] = &[
    crate::vm_lab::DaemonProbeOp::RuntimeAcls,
    crate::vm_lab::DaemonProbeOp::ServiceHardening,
    crate::vm_lab::DaemonProbeOp::KeyCustody,
    crate::vm_lab::DaemonProbeOp::Authenticode,
    crate::vm_lab::DaemonProbeOp::DnsFailclosed,
];

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

        const OPS: &[DaemonProbeOp] = BASELINE_PROBE_OPS;

        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();

        // Collect pass: gather all results before any mutation
        let all_results = crate::vm_lab::orchestrator::parallel::bounded_parallel_map_cancellable(
            &aliases,
            self.max_parallel_node_workers,
            &self.shutdown_flag,
            |alias| {
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
            },
            |alias| {
                (
                    alias.clone(),
                    OPS.iter()
                        .map(|_| Err("cancelled before node work was admitted".to_owned()))
                        .collect(),
                )
            },
        );

        use crate::vm_lab::orchestrator::report::ValidatorResult;
        use std::collections::HashMap;

        let mut errors = Vec::new();
        // Record per-node, per-op results as machine-readable evidence so the
        // run report carries the actual validator detail rather than an empty
        // list. Written to report_dir and read back by build_live_lab_run_report.
        let mut records: HashMap<String, Vec<ValidatorResult>> = HashMap::new();
        for (alias, op_results) in all_results {
            let mut node_records: Vec<ValidatorResult> = Vec::new();
            for (op, r) in OPS.iter().zip(op_results) {
                let (passed, summary) = match &r {
                    Ok(true) => (true, "passed".to_owned()),
                    Ok(false) => (false, "validator reported not passed".to_owned()),
                    Err(e) => (false, e.clone()),
                };
                node_records.push(ValidatorResult {
                    op: format!("{op:?}"),
                    passed,
                    summary,
                });
                match r {
                    Ok(false) => errors.push(format!("{alias}/{op:?}: validation not passed")),
                    Err(e) => errors.push(format!("{alias}/{op:?}: {e}")),
                    Ok(true) => {}
                }
            }
            records.insert(alias, node_records);
        }

        // Best-effort: a write failure must not change the verdict (the actual
        // validation already happened above); it only means the report ships
        // without per-op detail, which is the prior behaviour.
        if let Ok(json) = serde_json::to_string_pretty(&records) {
            let path = ctx.report_dir.join("validator_results.json");
            let _ = std::fs::write(path, json);
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
    use crate::vm_lab::DaemonProbeOp;

    #[test]
    fn baseline_probe_ops_exclude_mesh_status() {
        // QH-39. This path adjudicates by substring-matching `"overall_ok": true`
        // in raw stdout, so it never deserializes and no evaluator guard can
        // reach it. It was a strictly weaker duplicate of the dedicated
        // mesh_status_validation stage, and its vacuous green minted
        // macos_stage_baseline_runtime = pass for a node that reached no peer.
        assert!(
            !super::BASELINE_PROBE_OPS.contains(&DaemonProbeOp::MeshStatus),
            "mesh verdict must come from the dedicated stage, not this weaker probe"
        );
        assert_eq!(super::BASELINE_PROBE_OPS.len(), 5);
    }

    #[test]
    fn baseline_probe_ops_have_no_duplicates() {
        // Re-adding MeshStatus by any route -- including a second entry under a
        // different name -- must break here rather than silently restore the
        // duplicate adjudication.
        let mut seen: Vec<String> = super::BASELINE_PROBE_OPS
            .iter()
            .map(|op| format!("{op:?}"))
            .collect();
        let before = seen.len();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), before, "duplicate probe op in the baseline set");
    }

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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        };
        assert_eq!(
            ValidateBaselineRuntimeStage::new(
                1,
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            )
            .execute(&mut ctx),
            StageOutcome::Passed
        );
    }
}
