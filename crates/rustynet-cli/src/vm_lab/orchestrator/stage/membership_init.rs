#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_OWNER_SIGNING_KEY_PATH;
use crate::vm_lab::orchestrator::adapter::validated_args::ValidatedArg;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{GossipIdentity, NodeMembershipPeer, StageOutcome};
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use rustynet_control::membership::snapshot_bytes_node_capabilities;
use rustynet_control::roles::{canonicalize_role_capabilities, role_capability_csv};

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

        let (owner_key_r, snapshot_r, macos_owner_probe) = {
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
            // macOS exit owner: record the F1 fact (is the owner signing key on
            // the blind_exit host?). Probed only after `init_membership_snapshot`
            // returned Ok — the macOS adapter runs genesis → capability rewrite →
            // peer adds synchronously inside that call, so the fact describes
            // the provisioned state the run leaves behind. A probe failure is a
            // stage failure below.
            let macos_owner_probe = if adapter.platform() == VmGuestPlatform::Macos
                && matches!(&snapshot, Some(Ok(_)))
            {
                Some(
                    adapter
                        .probe_membership_owner_signing_key_present()
                        .map_err(|e| e.to_string()),
                )
            } else {
                None
            };
            (owner_key, snapshot, macos_owner_probe)
        };

        match (owner_key_r, snapshot_r) {
            (Err(e), _) => StageOutcome::Failed(format!("issue_membership_owner_key: {e}")),
            (_, None) => StageOutcome::Failed(
                "owner key fetch succeeded but no snapshot attempted".to_owned(),
            ),
            (_, Some(Err(e))) => StageOutcome::Failed(format!("init_membership_snapshot: {e}")),
            (_, Some(Ok(snap))) => {
                if let Some(probe) = macos_owner_probe {
                    // FAIL-LOUD assertion (design §5.1 step 4 / §5.2 stage
                    // layer): the macOS exit's OWN signed record must be exactly
                    // the product grant. This is the live analogue of the
                    // daemon's own blind_exit+anchor rejection, one stage
                    // earlier — no skip-as-pass.
                    let exit_node_id = match ctx.node_ids.get(exit_alias.as_str()) {
                        Some(id) if !id.trim().is_empty() => id.trim().to_owned(),
                        _ => {
                            return StageOutcome::Failed(format!(
                                "no membership node id recorded for macOS exit '{exit_alias}'; \
                                 cannot assert its signed capability set"
                            ));
                        }
                    };
                    // The node id is written verbatim into the evidence line
                    // below; it must satisfy the seam's node-id class so a
                    // value that ever came from guest output cannot forge or
                    // split an evidence line (no whitespace, no control bytes).
                    if let Err(err) = ValidatedArg::node_id(&exit_node_id) {
                        return StageOutcome::Failed(format!(
                            "membership node id for macOS exit '{exit_alias}' is not a valid \
                             node id ({err}); refusing to record evidence with it"
                        ));
                    }
                    if let Err(err) =
                        assert_macos_exit_membership(&snap.data, &exit_alias, &exit_node_id)
                    {
                        return StageOutcome::Failed(err);
                    }
                    // REQUIRED evidence (design §5.3): the owner-key presence
                    // fact travels with the verdict in this stage's own log.
                    let present = match probe {
                        Ok(present) => present,
                        Err(err) => {
                            return StageOutcome::Failed(format!(
                                "owner signing key presence probe failed on macOS exit \
                                 '{exit_alias}': {err}"
                            ));
                        }
                    };
                    let line = owner_key_evidence_line(present, &exit_node_id);
                    if let Err(err) =
                        append_stage_evidence_line(&ctx.report_dir, "membership_init", &line)
                    {
                        return StageOutcome::Failed(format!(
                            "could not record required F1 evidence for macOS exit \
                             '{exit_alias}' ({line}): {err}"
                        ));
                    }
                    eprintln!("[stage:membership_init] {line}");
                }
                ctx.membership_snapshot = Some(snap.data);
                StageOutcome::Passed
            }
        }
    }
}

/// The exact-set assertion for a macOS exit's own signed membership record.
///
/// Expected set: the product grant for a macOS Exit
/// (`NodeRole::product_capabilities_for_platform`, macOS arm), canonicalized
/// — the same single source the adapter's rewrite derives its CSV from.
/// Actual set: read from the snapshot bytes the adapter returned (the state
/// `DistributeMembership` will ship). Any difference names both sets.
pub(crate) fn assert_macos_exit_membership(
    snapshot: &[u8],
    exit_alias: &str,
    exit_node_id: &str,
) -> Result<(), String> {
    let expected = canonicalize_role_capabilities(
        NodeRole::Exit
            .product_capabilities_for_platform(&VmGuestPlatform::Macos)
            .map_err(|err| format!("macOS exit product capability grant unavailable: {err}"))?,
    );
    let actual = snapshot_bytes_node_capabilities(snapshot, exit_node_id).ok_or_else(|| {
        format!(
            "macOS exit '{exit_alias}' (node_id={exit_node_id}) is missing, inactive, or \
             unreadable in the membership snapshot; refusing to distribute a record that \
             cannot be asserted"
        )
    })?;
    if actual != expected {
        return Err(format!(
            "macOS exit '{exit_alias}' (node_id={exit_node_id}) signed membership carries \
             {{{}}} but must be exactly {{{}}} (blind_exit alignment, \
             MacosExitMembershipRoleFixDesign_2026-08-31.md §5.1 step 4)",
            role_capability_csv(&actual),
            role_capability_csv(&expected)
        ));
    }
    Ok(())
}

/// The F1 evidence line (design §5.3), machine-greppable and single-line.
pub(crate) fn owner_key_evidence_line(present: bool, exit_node_id: &str) -> String {
    format!(
        "owner_signing_key_present={present} path={MACOS_OWNER_SIGNING_KEY_PATH} \
         node_id={exit_node_id}"
    )
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

    // ── Design §5.2 stage layer: the macOS exit's own signed record must be
    //    EXACTLY the product grant, asserted on the bytes that will be
    //    distributed — the live analogue of the daemon's rejection, one stage
    //    earlier. Snapshots are encoded through the real persist path so the
    //    assertion is exercised against the exact bytes the runtime reads.

    fn snapshot_bytes_with_exit_caps(
        tag: &str,
        capabilities: Vec<rustynet_control::roles::RoleCapability>,
    ) -> Vec<u8> {
        use rustynet_control::membership::{
            MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
            MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipState,
            render_membership_snapshot_body,
        };
        let state = MembershipState {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            network_id: "lab-net".to_owned(),
            epoch: 2,
            nodes: vec![MembershipNode {
                node_id: "macos-exit-node".to_owned(),
                node_pubkey_hex: "5".repeat(64),
                owner: "macos-exit-node".to_owned(),
                status: MembershipNodeStatus::Active,
                roles: vec![],
                capabilities,
                joined_at_unix: 100,
                updated_at_unix: 120,
            }],
            approver_set: vec![MembershipApprover {
                approver_id: "macos-exit-node-owner".to_owned(),
                approver_pubkey_hex: "7".repeat(64),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 100,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        // The exact bytes `persist_membership_snapshot` writes, rendered in
        // memory (the persist path chmods its parent directory, which the
        // test temp dir refuses; the encoding is what matters here).
        let _ = tag;
        render_membership_snapshot_body(&state, None)
            .expect("render snapshot")
            .into_bytes()
    }

    #[test]
    fn macos_exit_assertion_accepts_exactly_the_blind_exit_pair() {
        use rustynet_control::roles::RoleCapability;
        // Order on disk is irrelevant: the compare is canonical.
        let bytes = snapshot_bytes_with_exit_caps(
            "ok",
            vec![RoleCapability::ExitServer, RoleCapability::BlindExit],
        );
        assert_macos_exit_membership(&bytes, "macos-utm-1", "macos-exit-node")
            .expect("exact blind_exit pair must pass");
    }

    #[test]
    fn macos_exit_assertion_fails_loud_on_the_anchor_genesis_set_naming_both_sets() {
        use rustynet_control::roles::RoleCapability;
        // The pre-fix defect: the exit's record still carries genesis anchor.
        let bytes = snapshot_bytes_with_exit_caps(
            "anchor",
            vec![
                RoleCapability::Anchor,
                RoleCapability::AnchorBundlePull,
                RoleCapability::Client,
                RoleCapability::ExitServer,
                RoleCapability::RelayHost,
            ],
        );
        let err = assert_macos_exit_membership(&bytes, "macos-utm-1", "macos-exit-node")
            .expect_err("anchor-carrying record must fail the stage");
        assert!(err.contains("anchor"), "must name the offending set: {err}");
        let expected_csv =
            role_capability_csv(&[RoleCapability::BlindExit, RoleCapability::ExitServer]);
        assert!(
            err.contains(&format!("must be exactly {{{expected_csv}}}")),
            "must name the expected set: {err}"
        );
        assert!(err.contains("macos-exit-node"));
    }

    #[test]
    fn macos_exit_assertion_rejects_a_superset_that_still_contains_the_pair() {
        use rustynet_control::roles::RoleCapability;
        // QH-65 shape: a contains-check would pass this; the exact-set must not.
        let bytes = snapshot_bytes_with_exit_caps(
            "superset",
            vec![
                RoleCapability::BlindExit,
                RoleCapability::ExitServer,
                RoleCapability::RelayHost,
            ],
        );
        let err = assert_macos_exit_membership(&bytes, "macos-utm-1", "macos-exit-node")
            .expect_err("superset must fail");
        assert!(err.contains("relay_host"), "{err}");
    }

    #[test]
    fn macos_exit_assertion_fails_closed_when_the_exit_entry_is_missing_or_unreadable() {
        use rustynet_control::roles::RoleCapability;
        let bytes = snapshot_bytes_with_exit_caps(
            "missing",
            vec![RoleCapability::BlindExit, RoleCapability::ExitServer],
        );
        let err = assert_macos_exit_membership(&bytes, "macos-utm-1", "some-other-node")
            .expect_err("unknown node id must fail");
        assert!(err.contains("missing, inactive, or unreadable"), "{err}");
        let err = assert_macos_exit_membership(b"garbage", "macos-utm-1", "macos-exit-node")
            .expect_err("garbage must fail");
        assert!(err.contains("missing, inactive, or unreadable"), "{err}");
    }

    #[test]
    fn owner_key_evidence_line_is_single_line_greppable_and_names_the_path() {
        let line = owner_key_evidence_line(true, "macos-exit-node");
        assert_eq!(
            line,
            format!(
                "owner_signing_key_present=true path={MACOS_OWNER_SIGNING_KEY_PATH} \
                 node_id=macos-exit-node"
            )
        );
        assert!(!line.contains('\n'));
        assert!(
            owner_key_evidence_line(false, "x").starts_with("owner_signing_key_present=false ")
        );
    }
}
