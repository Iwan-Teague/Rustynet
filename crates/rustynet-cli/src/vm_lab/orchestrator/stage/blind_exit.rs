#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::blind_exit::{
    blind_exit_runtime_implemented, validate_blind_exit_runtime,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "blind_exit.reported_skips.json";

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
            return StageOutcome::Skipped;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &blind_exit_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for blind_exit node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !blind_exit_runtime_implemented(platform) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            if let Err(e) = validate_blind_exit_runtime(&*shell, platform, alias) {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !reported_skips.is_empty() {
            let skips_json = serde_json::json!({
                "stage": "blind_exit",
                "reported_skips": reported_skips.iter().map(|(a, p)| {
                    serde_json::json!({"alias": a, "platform": p})
                }).collect::<Vec<_>>()
            });
            let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
            let _ = std::fs::write(
                &path,
                serde_json::to_string_pretty(&skips_json).unwrap_or_default(),
            );
        }

        if !failures.is_empty() {
            StageOutcome::Failed(failures.join("; "))
        } else if !reported_skips.is_empty() {
            StageOutcome::Skipped
        } else {
            StageOutcome::Passed
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
        };
        assert_eq!(BlindExitStage.execute(&mut ctx), StageOutcome::Skipped);
    }
}
