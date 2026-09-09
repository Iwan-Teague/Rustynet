#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::install::node_in_rebuild_set;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Writes the QH-83 witness line for a cleanup_hosts PASS: the asserted-clean
/// node count travels with the verdict, so an empty or rebuild-only scope
/// stays auditable instead of passing invisibly.
fn write_cleanup_witness(
    report_dir: &std::path::Path,
    cleaned: &[String],
    rebuild_only: Option<&[String]>,
) -> Result<(), String> {
    let scope = match rebuild_only {
        Some(list) => list.join(","),
        None => "none".to_owned(),
    };
    append_stage_evidence_line(
        report_dir,
        StageId::CleanupHosts.as_str(),
        &format!(
            "cleanup_asserted_nodes={} ({}) rebuild_only={scope}",
            cleaned.len(),
            cleaned.join(",")
        ),
    )
}

pub struct CleanupHostsStage {
    /// `--rebuild-nodes`: when `Some`, only these aliases are reset; any node
    /// not in the set is left intact (its daemon stays up for reuse).
    /// `None` = clean every node (the default). Must mirror
    /// `BootstrapHostsStage`'s set: a node skipped here is also skipped there.
    rebuild_only: Option<Vec<String>>,
}

impl CleanupHostsStage {
    pub fn new(rebuild_only: Option<Vec<String>>) -> Self {
        CleanupHostsStage { rebuild_only }
    }
}

impl OrchestrationStage for CleanupHostsStage {
    fn id(&self) -> StageId {
        StageId::CleanupHosts
    }
    fn name(&self) -> &str {
        "cleanup_hosts"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::VerifySshReachability]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let rebuild_only = self.rebuild_only.as_deref();
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        let cleaned: Vec<String> = aliases
            .iter()
            .filter(|alias| node_in_rebuild_set(rebuild_only, alias))
            .cloned()
            .collect();
        let errors: Vec<String> = aliases
            .iter()
            .filter_map(|alias| {
                if !node_in_rebuild_set(rebuild_only, alias) {
                    // Not in --rebuild-nodes: leave this node untouched so its
                    // running daemon survives for reuse. bootstrap_hosts skips
                    // it too. Its leftover runtime state is intentional, so we
                    // do not assert_node_clean here.
                    return None;
                }
                match ctx.adapters.get(alias.as_str()) {
                    // Prime passwordless sudo before cleanup so that daemon-stop
                    // and pf-utun teardown do not block for a password prompt.
                    // An error here is NOT fatal (the node may already have
                    // sudo configured); we proceed to cleanup_runtime_state,
                    // which fails closed on its own if the daemon is still running.
                    // Reset the node, then assert it is actually clean — a reset
                    // that silently did not take (leftover killswitch / NRPT)
                    // must fail the stage here, not surface as a cargo DNS
                    // timeout in bootstrap five stages later.
                    Some(adapter) => {
                        let _ = adapter.prime_remote_access();
                        adapter
                            .cleanup_runtime_state()
                            .and_then(|()| adapter.assert_node_clean())
                            .map_err(|e| e.to_string())
                    }
                    // An assigned node with no adapter is a construction bug, not
                    // "nothing to clean": its prior runtime state (incl. a
                    // default-deny killswitch) would be left in place and could
                    // brick the next run. Fail closed.
                    None => Err(
                        "no adapter for assigned node; cannot clean prior runtime state".to_owned(),
                    ),
                }
                .err()
                .map(|e| format!("{alias}: {e}"))
            })
            .collect();
        if errors.is_empty() {
            // QH-83: the witness is written on EVERY pass path and a write
            // failure fails the stage — an unwitnessed cleanup pass must
            // not stand.
            match write_cleanup_witness(&ctx.report_dir, &cleaned, rebuild_only) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(format!("cleanup witness write failed: {e}")),
            }
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

    fn ctx_with_assignment(alias: &str) -> OrchestrationContext {
        OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: alias.to_owned(),
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
            relay_forwarding_validation_elected: false,
        }
    }

    #[test]
    fn node_outside_rebuild_set_is_skipped_not_failed() {
        // The node has no adapter, so the default path would fail with
        // "no adapter". Excluding it from --rebuild-nodes must skip it instead,
        // leaving its running daemon intact for reuse.
        let mut ctx = ctx_with_assignment("reused-node");
        let stage = CleanupHostsStage::new(Some(vec!["other-node".to_owned()]));
        assert_eq!(stage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn node_with_no_adapter_in_rebuild_set_fails_closed() {
        // A node we DO intend to rebuild but which has no adapter is a
        // construction bug — fail closed rather than silently skip its reset.
        let mut ctx = ctx_with_assignment("reused-node");
        let stage = CleanupHostsStage::new(None);
        assert!(matches!(stage.execute(&mut ctx), StageOutcome::Failed(_)));
    }

    #[test]
    fn empty_assignments_passes() {
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
        assert_eq!(
            CleanupHostsStage::new(None).execute(&mut ctx),
            StageOutcome::Passed
        );
    }

    // QH-83: a PASS verdict must leave a durable stage-log line naming the
    // asserted-clean node count (vacuity auditable). Mutation caught:
    // dropping the witness write or demoting it to best-effort.
    #[test]
    fn cleanup_witness_line_names_the_asserted_clean_count() {
        let dir = std::env::temp_dir().join(format!(
            "cleanup_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let cleaned = vec!["exit-1".to_owned(), "client-1".to_owned()];
        write_cleanup_witness(&dir, &cleaned, None).expect("witness write");

        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::CleanupHosts.as_str(),
            ),
        )
        .expect("stage log readable");
        assert!(
            log.contains("cleanup_asserted_nodes=2 (exit-1,client-1) rebuild_only=none"),
            "{log}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as
    /// an error the stage turns into a failure (never a silent pass).
    #[test]
    fn cleanup_witness_write_failure_is_propagated() {
        let blocker =
            std::env::temp_dir().join(format!("cleanup_witness_blocker_{}", std::process::id()));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let err = write_cleanup_witness(&blocker, &["exit-1".to_owned()], None)
            .expect_err("write into a regular file path must fail");
        assert!(!err.is_empty());

        let _ = std::fs::remove_file(&blocker);
    }
}
