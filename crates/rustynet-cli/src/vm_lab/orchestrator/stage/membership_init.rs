#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{NodeMembershipPeer, StageOutcome};
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
            None => return StageOutcome::Failed("no Exit node in assignments".to_owned()),
        };

        // Clone peers before adapter borrow
        let peers = match build_membership_peers(ctx) {
            Ok(peers) => peers,
            Err(err) => return StageOutcome::Failed(err),
        };

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
                "owner key fetch succeeded but no snapshot attempted".to_owned(),
            ),
            (_, Some(Err(e))) => StageOutcome::Failed(format!("init_membership_snapshot: {e}")),
            (_, Some(Ok(snap))) => {
                ctx.membership_snapshot = Some(snap.data);
                StageOutcome::Passed
            }
        }
    }
}

pub(crate) fn build_membership_peers(
    ctx: &OrchestrationContext,
) -> Result<Vec<NodeMembershipPeer>, String> {
    ctx.assignments
        .iter()
        .map(|assignment| {
            let node_id = ctx
                .node_ids
                .get(&assignment.alias)
                .ok_or_else(|| format!("missing node_id for '{}'", assignment.alias))?;
            if node_id.trim().is_empty() {
                return Err(format!("empty node_id for '{}'", assignment.alias));
            }

            let public_key_hex = ctx
                .collected_pubkeys
                .get(&assignment.alias)
                .ok_or_else(|| format!("missing WireGuard public key for '{}'", assignment.alias))?
                .0
                .clone();
            if !NodeMembershipPeer::is_valid_public_key_hex(&public_key_hex) {
                return Err(format!(
                    "invalid WireGuard public key for '{}': expected 64 hex chars",
                    assignment.alias
                ));
            }

            Ok(NodeMembershipPeer {
                alias: assignment.alias.clone(),
                role: assignment.role.clone(),
                node_id: node_id.clone(),
                public_key_hex,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::error::WireguardPublicKey;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
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
        };
        assert!(matches!(
            MembershipInitStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn build_membership_peers_threads_real_pubkeys_for_non_exit_peers() {
        let mut ctx = OrchestrationContext {
            assignments: vec![
                NodeRoleAssignment {
                    alias: "exit-1".to_owned(),
                    role: NodeRole::Exit,
                },
                NodeRoleAssignment {
                    alias: "client-1".to_owned(),
                    role: NodeRole::Client,
                },
            ],
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
        let exit_key = "a".repeat(64);
        let client_key = "b".repeat(64);
        ctx.collected_pubkeys
            .insert("exit-1".to_owned(), WireguardPublicKey(exit_key.clone()));
        ctx.collected_pubkeys.insert(
            "client-1".to_owned(),
            WireguardPublicKey(client_key.clone()),
        );
        ctx.node_ids
            .insert("exit-1".to_owned(), "exit-node-id".to_owned());
        ctx.node_ids
            .insert("client-1".to_owned(), "client-node-id".to_owned());

        let peers = build_membership_peers(&ctx).unwrap();
        let client = peers.iter().find(|p| p.alias == "client-1").unwrap();
        assert_eq!(client.node_id, "client-node-id");
        assert_eq!(client.public_key_hex, client_key);
        assert_eq!(client.public_key_hex.len(), 64);
    }

    #[test]
    fn build_membership_peers_rejects_missing_or_invalid_pubkey() {
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "client-1".to_owned(),
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
        };
        ctx.node_ids
            .insert("client-1".to_owned(), "client-node-id".to_owned());
        assert!(build_membership_peers(&ctx).is_err());

        ctx.collected_pubkeys.insert(
            "client-1".to_owned(),
            WireguardPublicKey("not-hex".to_owned()),
        );
        assert!(build_membership_peers(&ctx).is_err());
    }
}
