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
                    "no membership snapshot in context (MembershipInit must run first)".to_owned(),
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
        // Setup provenance F3: a membership distribution that reaches no
        // node distributed nothing; the bundle family already fails closed
        // on a missing exit, and this stage must not pass vacuously.
        if non_exit.is_empty() {
            let _ = std::fs::remove_file(&tmp_path);
            return StageOutcome::Failed(
                "no non-exit node in assignments; membership snapshot reached nobody".to_owned(),
            );
        }

        let errors: Vec<String> = non_exit
            .iter()
            .filter_map(|alias| {
                match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter
                        .distribute_signed_bundle(BundleKind::Membership, &tmp_path)
                        .map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                }
                .err()
                .map(|e| format!("{alias}: {e}"))
            })
            .collect();

        let _ = std::fs::remove_file(&tmp_path);
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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        assert!(matches!(
            DistributeMembershipStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    /// Setup provenance F3: an exit-only topology distributes the snapshot to
    /// nobody, so the stage must fail closed. Mutation caught: reverting the
    /// empty-non-exit guard (the stage passes with zero distributions).
    fn no_non_exit_nodes_fails_closed() {
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: Some(vec![1, 2, 3]),
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        // Only exit node — nothing to distribute to
        assert!(matches!(
            DistributeMembershipStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
