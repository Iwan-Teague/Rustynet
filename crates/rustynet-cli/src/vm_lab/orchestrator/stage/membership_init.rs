#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{GossipIdentity, NodeMembershipPeer, StageOutcome};
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
            let platform = ctx
                .adapters
                .get(&assignment.alias)
                .map(|adapter| adapter.platform())
                .unwrap_or(VmGuestPlatform::Linux);
            let capabilities = assignment
                .role
                .product_capabilities_for_platform(&platform)
                .map_err(|err| format!("membership capability mapping failed: {err}"))?;

            // Absence is an error for EVERY node, and a deferred identity is an
            // error specifically for Linux — which mints a gossip secret at
            // install, so "deferred" there means the collector failed rather
            // than the platform being unable.
            let gossip_identity = ctx
                .collected_gossip_identities
                .get(&assignment.alias)
                .ok_or_else(|| format!("missing gossip identity for '{}'", assignment.alias))?
                .clone();
            if platform == VmGuestPlatform::Linux
                && matches!(gossip_identity, GossipIdentity::DeferredPlatform)
            {
                return Err(format!(
                    "'{}' is Linux but reported no gossip identity; Linux mints one at install",
                    assignment.alias
                ));
            }

            Ok(NodeMembershipPeer {
                alias: assignment.alias.clone(),
                role: assignment.role.clone(),
                capabilities,
                node_id: node_id.clone(),
                public_key_hex,
                gossip_identity,
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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
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

        // Deliberately DIFFERENT from the WireGuard keys: the whole point of this
        // change is that membership publishes a second, distinct value.
        let exit_gossip = "c".repeat(64);
        let client_gossip = "d".repeat(64);
        ctx.collected_gossip_identities.insert(
            "exit-1".to_owned(),
            GossipIdentity::Published(exit_gossip.clone()),
        );
        ctx.collected_gossip_identities.insert(
            "client-1".to_owned(),
            GossipIdentity::Published(client_gossip.clone()),
        );

        let peers = build_membership_peers(&ctx).unwrap();
        let client = peers.iter().find(|p| p.alias == "client-1").unwrap();
        assert_eq!(client.node_id, "client-node-id");
        assert_eq!(client.public_key_hex, client_key);
        assert_eq!(client.public_key_hex.len(), 64);
        // The two keys must be threaded side by side, never conflated: the
        // WireGuard value still configures the real tunnel.
        assert_eq!(
            client.gossip_identity,
            GossipIdentity::Published(client_gossip),
            "membership must carry the gossip key, not the WireGuard key"
        );
    }

    /// Absence is an error, not a default. Without this the collector could fail
    /// silently and the node would join publishing whatever happened to be there.
    #[test]
    fn build_membership_peers_fails_when_gossip_identity_is_missing() {
        let mut ctx = base_ctx_with_one_client();
        ctx.collected_gossip_identities.remove("client-1");
        let err = match build_membership_peers(&ctx) {
            Ok(_) => panic!("a node with no collected gossip identity must fail closed"),
            Err(err) => err,
        };
        assert!(
            err.contains("missing gossip identity"),
            "error must name the cause, got: {err}"
        );
    }

    /// A Linux node reporting `DeferredPlatform` means the collector failed, not
    /// that the platform cannot mint — Linux mints at install. Accepting it would
    /// silently republish the WireGuard key, which is the original defect.
    #[test]
    fn build_membership_peers_rejects_a_deferred_identity_on_linux() {
        let mut ctx = base_ctx_with_one_client();
        ctx.collected_gossip_identities
            .insert("client-1".to_owned(), GossipIdentity::DeferredPlatform);
        let err = match build_membership_peers(&ctx) {
            Ok(_) => panic!("Linux must not be allowed to defer its gossip identity"),
            Err(err) => err,
        };
        assert!(
            err.contains("is Linux but reported no gossip identity"),
            "error must name the cause, got: {err}"
        );
    }

    fn base_ctx_with_one_client() -> OrchestrationContext {
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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
        };
        ctx.collected_pubkeys
            .insert("client-1".to_owned(), WireguardPublicKey("b".repeat(64)));
        ctx.node_ids
            .insert("client-1".to_owned(), "client-node-id".to_owned());
        ctx.collected_gossip_identities.insert(
            "client-1".to_owned(),
            GossipIdentity::Published("d".repeat(64)),
        );
        ctx
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
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
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
