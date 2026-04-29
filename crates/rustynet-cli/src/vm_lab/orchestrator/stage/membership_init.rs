#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct MembershipInitStage;

impl OrchestrationStage for MembershipInitStage {
    fn id(&self) -> StageId {
        StageId::MembershipInit
    }
    fn name(&self) -> &str {
        "membership_init"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::CollectPubkeys]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Exit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_alias = ctx
            .assignments
            .iter()
            .find(|a| a.role == NodeRole::Exit)
            .map(|a| a.alias.clone());
        let exit_alias = match exit_alias {
            Some(a) => a,
            None => return StageOutcome::Failed("no Exit node in assignments".to_string()),
        };

        // Clone peers before adapter borrow
        let peers = ctx.assignments.clone();

        let (owner_key_r, snapshot_r) = {
            let adapter = match ctx.adapters.get(exit_alias.as_str()) {
                Some(a) => a,
                None => return StageOutcome::Failed(format!("no adapter for exit '{exit_alias}'")),
            };
            let owner_key = adapter
                .issue_membership_owner_key()
                .map_err(|e| e.to_string());
            let snapshot = match &owner_key {
                Ok(k) => Some(
                    adapter
                        .init_membership_snapshot(k, &peers)
                        .map_err(|e| e.to_string()),
                ),
                Err(_) => None,
            };
            (owner_key, snapshot)
        };

        match (owner_key_r, snapshot_r) {
            (Err(e), _) => StageOutcome::Failed(format!("issue_membership_owner_key: {e}")),
            (_, None) => StageOutcome::Failed(
                "owner key fetch succeeded but no snapshot attempted".to_string(),
            ),
            (_, Some(Err(e))) => StageOutcome::Failed(format!("init_membership_snapshot: {e}")),
            (_, Some(Ok(snap))) => {
                ctx.membership_snapshot = Some(snap.data);
                StageOutcome::Passed
            }
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
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        assert!(matches!(
            MembershipInitStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
