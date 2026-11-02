#![allow(dead_code)]
use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::admin_issue::validate_admin_issue;
use crate::vm_lab::orchestrator::role_validation::identity_challenge::adjudicate_identity;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Writes the per-validated-node QH-83 witness line for an admin_issue PASS
/// (same shape as the blind_exit witness): the runner demotes a declared
/// StageLog stage whose log is empty, so every validated admin node must
/// leave a durable line behind.
fn write_admin_issue_witness(report_dir: &std::path::Path, alias: &str) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::AdminIssue.as_str(),
        &format!(
            "{alias}: admin confirmed; live identity matched; status role=admin; peer-list exit=0"
        ),
    )
}

/// QH-98: the admin role validator reads `rustynet status`, so on its own it
/// trusts the node's SELF-reported `node_role=admin` — a substituted or
/// crossed connection that answers `admin` would pass. Before that check the
/// stage runs the live identity challenge (NodeEngineAcceptanceSpec §4.7):
/// the live daemon's node id must equal the id recorded at CollectPubkeys.
/// Fail-closed: no recorded id, a gather error, a mismatch, or a non-live
/// (config-file) source all fail the node.
fn enforce_admin_live_identity(
    adapter: &dyn NodeAdapter,
    expected_node_id: Option<&str>,
    alias: &str,
) -> Result<(), String> {
    let evidence = adapter
        .collect_live_identity()
        .map_err(|e| format!("live node-identity challenge could not be gathered: {e}"))?;
    adjudicate_identity(expected_node_id, &evidence)
        .map_err(|e| format!("§4.7 node-identity challenge rejected admin_issue on {alias:?}: {e}"))
}

pub struct AdminIssueStage;

impl OrchestrationStage for AdminIssueStage {
    fn id(&self) -> StageId {
        StageId::AdminIssue
    }
    fn name(&self) -> &str {
        "admin_issue"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::DistributeMembership]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Admin]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let admin_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Admin)
            .map(|a| a.alias.clone())
            .collect();

        if admin_aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node in this topology is assigned the admin role".to_owned(),
            );
        }

        let mut failures: Vec<String> = Vec::new();
        for alias in &admin_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for admin node"));
                    continue;
                }
            };
            if let Err(e) = enforce_admin_live_identity(
                adapter.as_ref(),
                ctx.node_ids.get(alias.as_str()).map(String::as_str),
                alias,
            ) {
                failures.push(format!("{alias}: {e}"));
                continue;
            }
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            match validate_admin_issue(&*shell, alias) {
                Err(e) => failures.push(format!("{alias}: {e}")),
                // QH-83: the per-node witness write is part of the pass
                // path — a failure to land it fails the stage.
                Ok(()) => {
                    if let Err(e) = write_admin_issue_witness(&ctx.report_dir, alias) {
                        failures.push(format!("{alias}: admin_issue witness write failed: {e}"));
                    }
                }
            }
        }

        if failures.is_empty() {
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(failures.join("; "))
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
            relay_forward_candidate_endpoint: None,
        };
        assert!(matches!(
            AdminIssueStage.execute(&mut ctx),
            StageOutcome::Skipped(_)
        ));
    }

    // QH-83: every validated admin node must leave a durable stage-log line,
    // because the catalog declares this stage StageLog and the runner
    // demotes an unwitnessed PASS. Mutation caught: dropping the witness
    // write or demoting it to best-effort.
    #[test]
    fn admin_issue_witness_line_names_the_validated_node() {
        let dir = std::env::temp_dir().join(format!(
            "admin_issue_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        write_admin_issue_witness(&dir, "admin-1").expect("witness write");

        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::AdminIssue.as_str(),
            ),
        )
        .expect("stage log readable");
        assert!(
            log.contains("admin-1: admin confirmed; live identity matched; status role=admin; peer-list exit=0"),
            "{log}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as
    /// an error the stage turns into a failure (never a silent pass).
    #[test]
    fn admin_issue_witness_write_failure_is_propagated() {
        let blocker = std::env::temp_dir().join(format!(
            "admin_issue_witness_blocker_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let err = write_admin_issue_witness(&blocker, "admin-1")
            .expect_err("write into a regular file path must fail");
        assert!(!err.is_empty());

        let _ = std::fs::remove_file(&blocker);
    }

    // QH-98: the admin stage must run the live identity challenge before it
    // trusts the node's self-reported `node_role=admin`. The fake reports a
    // DIFFERENT live node id and has no shell host, so with the challenge in
    // place the failure names the identity rejection; with the call removed
    // the stage reaches `shell_host()` and fails with a different message.
    // Mutation caught: deleting the `enforce_admin_live_identity` call in
    // `execute` (or the mismatch/provenance adjudication behind it).
    mod identity_challenge {
        use super::super::*;
        use crate::vm_lab::VmGuestPlatform;
        use crate::vm_lab::orchestrator::error::{
            AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
            MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
            ValidatorReport, WireguardPublicKey,
        };
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use crate::vm_lab::orchestrator::role_validation::identity_challenge::IdentityEvidence;
        use crate::vm_lab::orchestrator::source_archive::SourceArchive;
        use std::collections::HashMap;
        use std::path::Path;

        #[derive(Debug)]
        struct FakeAdminAdapter {
            live: Result<IdentityEvidence, String>,
        }
        impl NodeAdapter for FakeAdminAdapter {
            fn platform(&self) -> VmGuestPlatform {
                VmGuestPlatform::Linux
            }
            fn alias(&self) -> &str {
                "admin-1"
            }
            fn collect_live_identity(&self) -> Result<IdentityEvidence, AdapterError> {
                self.live
                    .clone()
                    .map_err(|message| AdapterError::Protocol { message })
            }
            fn collect_artifacts(&self, _dst: &Path) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn start_daemon(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn stop_daemon(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn restart_daemon(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn uninstall_daemon(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
                unimplemented!()
            }
            fn collect_wireguard_public_key(&self) -> Result<WireguardPublicKey, AdapterError> {
                unimplemented!()
            }
            fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
                unimplemented!()
            }
            fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
                unimplemented!()
            }
            fn run_validator(
                &self,
                _op: crate::vm_lab::DaemonProbeOp,
                _extra_args: &[String],
            ) -> Result<ValidatorReport, AdapterError> {
                unimplemented!()
            }
            fn ping_mesh_peer(&self, _peer: &str) -> Result<TrafficTestResult, AdapterError> {
                unimplemented!()
            }
            fn probe_denied_peer(&self, _ip: &str) -> Result<TrafficTestResult, AdapterError> {
                unimplemented!()
            }
            fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
                unimplemented!()
            }
            fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn endpoint(&self) -> String {
                unimplemented!()
            }
            fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
                unimplemented!()
            }
            fn install_daemon(
                &self,
                _source: &SourceArchive,
                _ctx: &OrchestrationContext,
            ) -> Result<InstallReport, AdapterError> {
                unimplemented!()
            }
            fn init_membership_snapshot(
                &self,
                _owner_key: &MembershipOwnerKey,
                _peers: &[NodeMembershipPeer],
            ) -> Result<MembershipSnapshot, AdapterError> {
                unimplemented!()
            }
            fn distribute_signed_bundle(
                &self,
                _kind: BundleKind,
                _bundle_path: &Path,
            ) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn distribute_verifier_key(
                &self,
                _kind: BundleKind,
                _pub_key_path: &Path,
            ) -> Result<(), AdapterError> {
                unimplemented!()
            }
            fn issue_bundles_to_dir(
                &self,
                _kind: BundleKind,
                _env_content: &str,
                _local_out_dir: &Path,
            ) -> Result<(), AdapterError> {
                unimplemented!()
            }
        }

        fn run_stage(
            live: Result<IdentityEvidence, String>,
            recorded_id: Option<&str>,
        ) -> StageOutcome {
            let mut adapters: HashMap<String, Box<dyn NodeAdapter>> = HashMap::new();
            adapters.insert("admin-1".to_owned(), Box::new(FakeAdminAdapter { live }));
            let mut node_ids = HashMap::new();
            if let Some(id) = recorded_id {
                node_ids.insert("admin-1".to_owned(), id.to_owned());
            }
            let mut ctx = OrchestrationContext::new(
                vec![NodeRoleAssignment {
                    alias: "admin-1".to_owned(),
                    role: NodeRole::Admin,
                }],
                std::env::temp_dir(),
                "net".to_owned(),
            );
            ctx.adapters = adapters;
            ctx.node_ids = node_ids;
            AdminIssueStage.execute(&mut ctx)
        }

        fn failure_text(outcome: StageOutcome) -> String {
            match outcome {
                StageOutcome::Failed(m) => m,
                other => panic!("expected Failed, got {other:?}"),
            }
        }

        #[test]
        fn substituted_node_is_rejected_before_role_is_trusted() {
            let m = failure_text(run_stage(
                Ok(IdentityEvidence::live("node-B")),
                Some("node-A"),
            ));
            assert!(m.contains("node_id mismatch"), "{m}");
            assert!(
                m.contains("node-identity challenge rejected admin_issue"),
                "{m}"
            );
        }

        #[test]
        fn missing_recorded_id_is_unverifiable_and_fails() {
            let m = failure_text(run_stage(Ok(IdentityEvidence::live("node-A")), None));
            assert!(m.contains("unverifiable"), "{m}");
        }

        #[test]
        fn config_file_identity_is_not_a_live_assertion() {
            let m = failure_text(run_stage(
                Ok(IdentityEvidence::config_file("node-A")),
                Some("node-A"),
            ));
            assert!(m.contains("not a live assertion"), "{m}");
        }

        #[test]
        fn identity_gather_error_fails_closed() {
            let m = failure_text(run_stage(
                Err("daemon socket down".to_owned()),
                Some("node-A"),
            ));
            assert!(
                m.contains("live node-identity challenge could not be gathered"),
                "{m}"
            );
        }

        #[test]
        fn matching_live_identity_proceeds_to_the_role_check() {
            // The fake has no shell host, so a matching identity must get past
            // the challenge and fail LATER at `shell_host()` — proving the
            // challenge does not reject a correct node.
            let m = failure_text(run_stage(
                Ok(IdentityEvidence::live("node-A")),
                Some("node-A"),
            ));
            assert!(m.contains("shell host unavailable"), "{m}");
            assert!(!m.contains("node-identity challenge"), "{m}");
        }
    }
}
