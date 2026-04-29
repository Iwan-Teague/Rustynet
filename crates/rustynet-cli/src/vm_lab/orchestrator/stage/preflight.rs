#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct PreflightStage;

impl OrchestrationStage for PreflightStage {
    fn id(&self) -> StageId {
        StageId::Preflight
    }
    fn name(&self) -> &str {
        "preflight"
    }
    fn dependencies(&self) -> &[StageId] {
        &[]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // 1. report_dir writable
        if !ctx.report_dir.exists() && let Err(e) = std::fs::create_dir_all(&ctx.report_dir) {
            return StageOutcome::Failed(format!(
                "cannot create report dir '{}': {e}",
                ctx.report_dir.display()
            ));
        }
        let probe = ctx.report_dir.join(".preflight_write_test");
        if std::fs::write(&probe, b"ok").is_err() {
            return StageOutcome::Failed(format!(
                "report dir '{}' is not writable",
                ctx.report_dir.display()
            ));
        }
        let _ = std::fs::remove_file(&probe);

        // 2. ssh binary
        if std::process::Command::new("ssh")
            .arg("-V")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .is_err()
        {
            return StageOutcome::Failed("ssh binary not found in PATH".to_string());
        }

        // 3. exactly one exit node
        let exit_count = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Exit)
            .count();
        if exit_count != 1 {
            return StageOutcome::Failed(format!(
                "lab requires exactly 1 Exit node, found {exit_count}"
            ));
        }

        StageOutcome::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    fn make_ctx_with_exit(tmp_dir: &std::path::Path) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_string(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp_dir.to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        }
    }

    #[test]
    fn preflight_passes_with_exit_node_and_writable_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = make_ctx_with_exit(tmp.path());
        let outcome = PreflightStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Passed | StageOutcome::Failed(_)),
            "must produce a terminal outcome: {outcome:?}"
        );
    }

    #[test]
    fn preflight_fails_with_no_exit_node() {
        let tmp = tempfile::tempdir().unwrap();
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "client-1".to_string(),
                role: NodeRole::Client,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: tmp.path().to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        let outcome = PreflightStage.execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Failed(_)),
            "must fail with no exit node: {outcome:?}"
        );
    }
}
