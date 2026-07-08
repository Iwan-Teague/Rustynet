#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct ExitHandoffStage;

impl OrchestrationStage for ExitHandoffStage {
    fn id(&self) -> StageId {
        StageId::ExitHandoff
    }
    fn name(&self) -> &str {
        "exit_handoff"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::RoleSwitchMatrix]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(a) => a.alias.clone(),
            None => return StageOutcome::Failed("no Exit node in assignments".to_owned()),
        };
        use crate::vm_lab::orchestrator::stage::role_switch_matrix::verify_tunnels_active;
        let adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(a) => a,
            None => return StageOutcome::Failed(format!("no adapter for exit '{exit_alias}'")),
        };
        // 1. The exit must hold its membership owner key (it is the signer).
        if let Err(e) = adapter.issue_membership_owner_key() {
            return StageOutcome::Failed(format!(
                "exit handoff: membership owner key unavailable on '{exit_alias}': {e}"
            ));
        }
        // 2. Prove the exit is actually serving the mesh, not merely that the
        //    owner-key file exists: it must have at least one active tunnel.
        //    Fails closed if tunnels are absent or unverifiable.
        match adapter.collect_active_tunnels() {
            Ok(list) => match verify_tunnels_active(&list) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(format!("exit handoff: exit '{exit_alias}' {e}")),
            },
            Err(e) => StageOutcome::Failed(format!(
                "exit handoff: tunnel query failed on '{exit_alias}': {e}"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn no_exit_node_fails() {
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
        assert!(matches!(
            ExitHandoffStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
