#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::admin_issue::validate_admin_issue;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Writes the per-validated-node QH-83 witness line for an admin_issue PASS
/// (same shape as the blind_exit witness): the runner demotes a declared
/// StageLog stage whose log is empty, so every validated admin node must
/// leave a durable line behind.
fn write_admin_issue_witness(report_dir: &std::path::Path, alias: &str) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::AdminIssue.as_str(),
        &format!("{alias}: admin confirmed; status role=admin; peer-list exit=0"),
    )
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
            log.contains("admin-1: admin confirmed; status role=admin; peer-list exit=0"),
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
}
