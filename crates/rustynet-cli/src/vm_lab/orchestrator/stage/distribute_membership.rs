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

        // The tmp name carries an invocation-unique suffix: the pid alone
        // collides across concurrent invocations in one process (tests, or
        // a resume path), where one invocation's cleanup would delete
        // another's in-flight snapshot.
        let snapshot_file_name = format!(
            "rn_membership_{}_{}.snapshot",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        );
        let tmp_path = {
            let mut p = std::env::temp_dir();
            p.push(&snapshot_file_name);
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

        // Digest the exact tmp-file bytes that were distributed BEFORE the
        // tmp file is removed — the same digest every adapter verified on
        // the guest.
        let snapshot_sha256 =
            crate::vm_lab::orchestrator::adapter::verifier_key::sha256_hex_of_file(&tmp_path)
                .map_err(|err| format!("snapshot digest for witness: {err}"));
        let _ = std::fs::remove_file(&tmp_path);
        let snapshot_sha256 = match snapshot_sha256 {
            Ok(sha) => sha,
            Err(err) => return StageOutcome::Failed(err),
        };
        if errors.is_empty() {
            // QH-83 F1b: the pass witness is written on EVERY pass path and
            // a write failure fails the stage — a membership distribution
            // pass with no durable per-alias record must not stand (the
            // runner demotes it via the File declaration).
            match write_membership_bundle_evidence(
                ctx,
                &non_exit,
                snapshot_sha256,
                &snapshot_file_name,
            ) {
                Ok(()) => StageOutcome::Passed,
                Err(err) => {
                    StageOutcome::Failed(format!("membership bundle evidence write failed: {err}"))
                }
            }
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

/// Build and write the `distribute_membership` witness: one record per
/// receiving alias with the snapshot digest and the remote install path.
/// `snapshot_sha256` is taken over the exact tmp-file bytes that were
/// distributed — the same digest every adapter verified on the guest.
fn write_membership_bundle_evidence(
    ctx: &OrchestrationContext,
    non_exit: &[String],
    snapshot_sha256: String,
    snapshot_file_name: &str,
) -> Result<(), String> {
    let file = snapshot_file_name.to_owned();
    let mut entries = Vec::with_capacity(non_exit.len());
    for alias in non_exit {
        let node_id = ctx.node_ids.get(alias.as_str()).ok_or_else(|| {
            format!("no node_id for '{alias}'; membership witness cannot be written")
        })?;
        let platform = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter.platform(),
            None => return Err(format!("no adapter for '{alias}'")),
        };
        let install_dst = super::bundle_evidence::bundle_install_dst_for_platform(
            platform,
            &BundleKind::Membership,
        )
        .map_err(|err| format!("{alias}: {err}"))?;
        entries.push(super::bundle_evidence::BundleWitnessEntry {
            alias: alias.clone(),
            node_id: node_id.clone(),
            file: file.clone(),
            sha256: snapshot_sha256.clone(),
            install_dst,
        });
    }
    super::bundle_evidence::write_bundle_evidence(
        &ctx.report_dir,
        &BundleKind::Membership,
        super::bundle_evidence::BundleWitnessScope::Setup,
        &entries,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::orchestrator::adapter::node_adapter::NodeAdapter;
    use crate::vm_lab::orchestrator::error::{
        AdapterError, GossipIdentity, InstallReport, MembershipOwnerKey, NodeId, TrafficTestResult,
        TunnelsList, ValidatorReport, WireguardPublicKey,
    };
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;
    use std::collections::HashMap;
    use std::path::Path;

    /// Minimal adapter double: only platform/alias/distribute_signed_bundle
    /// matter for the witness test; everything else is `unimplemented!()`
    /// so an unexpected call fails loudly.
    #[derive(Debug)]
    struct FakeDistributingAdapter {
        alias: &'static str,
        platform: VmGuestPlatform,
        fail_distribution: bool,
    }

    impl NodeAdapter for FakeDistributingAdapter {
        fn platform(&self) -> VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            self.alias
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &Path,
        ) -> Result<(), AdapterError> {
            if self.fail_distribution {
                Err(AdapterError::Ssh {
                    message: "injected distribution failure".to_owned(),
                })
            } else {
                Ok(())
            }
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
        fn ping_mesh_peer(&self, _peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
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
            _peers: &[crate::vm_lab::orchestrator::error::NodeMembershipPeer],
        ) -> Result<crate::vm_lab::orchestrator::error::MembershipSnapshot, AdapterError> {
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

    fn ctx_for(report_dir: &std::path::Path, fail_distribution: bool) -> OrchestrationContext {
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
            report_dir: report_dir.to_path_buf(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: Some(vec![9, 8, 7]),
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
        ctx.node_ids
            .insert("client-1".to_owned(), "client-node-id-xyz".to_owned());
        ctx.adapters.insert(
            "client-1".to_owned(),
            Box::new(FakeDistributingAdapter {
                alias: "client-1",
                platform: VmGuestPlatform::Linux,
                fail_distribution,
            }),
        );
        ctx
    }

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

    // QH-83 F1b: a PASS verdict must be backed by the per-alias bundle
    // witness, because the catalog declares this stage
    // StageEvidence::File("logs/distribute_membership.bundle_evidence.json")
    // and the runner demotes an unwitnessed PASS. Mutation caught: dropping
    // the witness write (this test goes red) or demoting the write back to
    // best-effort (a write failure no longer fails the stage).
    #[test]
    fn passing_distribution_writes_the_bundle_evidence_witness() {
        let dir = std::env::temp_dir().join(format!(
            "distribute_membership_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp report dir");

        let mut ctx = ctx_for(&dir, false);
        assert_eq!(
            DistributeMembershipStage.execute(&mut ctx),
            StageOutcome::Passed
        );

        let path = dir.join(
            super::super::bundle_evidence::bundle_evidence_relative_path(
                &BundleKind::Membership,
                super::super::bundle_evidence::BundleWitnessScope::Setup,
            ),
        );
        let text = std::fs::read_to_string(&path).expect("witness artifact readable");
        assert!(text.contains("\"kind\": \"membership\""), "{text}");
        assert!(text.contains("\"alias\": \"client-1\""), "{text}");
        assert!(
            text.contains("\"node_id\": \"client-node-id-xyz\""),
            "{text}"
        );
        assert!(text.contains("rn_membership_"), "{text}");
        assert!(
            text.contains("\"install_dst\": \"/var/lib/rustynet/membership.snapshot\""),
            "the install destination must come from the adapter's own path table: {text}"
        );
        // The digest names the exact distributed bytes: 9,8,7.
        let expected_sha = {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(vec![9u8, 8, 7]);
            format!("{:x}", hasher.finalize())
        };
        assert!(
            text.contains(&expected_sha),
            "witness must carry the sha256 of the distributed bytes: {text}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Mutation caught: reverting the witness write to best-effort (a write
    /// failure ignored, the stage still passes) — the write failure must
    /// fail the stage instead.
    #[test]
    fn witness_write_failure_fails_the_pass() {
        let blocker = std::env::temp_dir().join(format!(
            "distribute_membership_blocker_{}",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let mut ctx = ctx_for(&blocker, false);
        match DistributeMembershipStage.execute(&mut ctx) {
            StageOutcome::Failed(detail) => {
                assert!(
                    detail.contains("membership bundle evidence write failed"),
                    "{detail}"
                );
            }
            other => panic!("unwitnessed pass must not stand, got: {other:?}"),
        }

        let _ = std::fs::remove_file(&blocker);
    }

    /// A node whose distribution failed is failed BEFORE the witness is
    /// written — the distribution failure itself must be the reported cause,
    /// not a missing witness.
    #[test]
    fn distribution_failure_still_fails_with_its_own_cause() {
        let dir =
            std::env::temp_dir().join(format!("distribute_membership_fail_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("temp report dir");

        let mut ctx = ctx_for(&dir, true);
        match DistributeMembershipStage.execute(&mut ctx) {
            StageOutcome::Failed(detail) => {
                assert!(detail.contains("injected distribution failure"), "{detail}");
            }
            other => panic!("failed distribution must fail the stage, got: {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
