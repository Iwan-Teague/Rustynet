#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{BundleKind, StageOutcome};
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct DistributeMembershipStage;

impl OrchestrationStage for DistributeMembershipStage {
    fn id(&self) -> StageId {
        StageId::DistributeMembership
    }
    fn name(&self) -> &str {
        "distribute_membership"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::MembershipInit]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let snapshot_data = match &ctx.membership_snapshot {
            Some(d) => d.clone(),
            None => {
                return StageOutcome::Failed(
                    "no membership snapshot in context (MembershipInit must run first)".to_string(),
                );
            }
        };

        let tmp_path = {
            let mut p = std::env::temp_dir();
            p.push(format!("rn_membership_{}.snapshot", std::process::id()));
            p
        };
        if let Err(e) = std::fs::write(&tmp_path, &snapshot_data) {
            return StageOutcome::Failed(format!("write membership snapshot tmp: {e}"));
        }

        let non_exit: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role != NodeRole::Exit)
            .map(|a| a.alias.clone())
            .collect();

        let results: Vec<(String, Result<(), String>)> = non_exit
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .distribute_signed_bundle(BundleKind::Membership, &tmp_path)
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                };
                (alias.clone(), r)
            })
            .collect();

        let _ = std::fs::remove_file(&tmp_path);

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
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    #[test]
    fn no_snapshot_fails() {
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
            DistributeMembershipStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn no_non_exit_nodes_passes_trivially() {
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_string(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_string(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: Some(vec![1, 2, 3]),
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
        };
        // Only exit node — nothing to distribute to
        assert_eq!(
            DistributeMembershipStage.execute(&mut ctx),
            StageOutcome::Passed
        );
    }
}
