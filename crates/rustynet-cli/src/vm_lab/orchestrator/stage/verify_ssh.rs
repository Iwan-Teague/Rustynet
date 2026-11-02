#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::cloud_node_safety::guard_dataplane_nodes;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Writes the QH-83 witness line for a verify_ssh_reachability PASS: the
/// runner demotes a declared StageLog stage whose log is empty, so the pass
/// must carry the reachable node count with it — an empty topology then
/// reads as `nodes=0` instead of passing invisibly.
fn write_ssh_reachability_witness(
    report_dir: &std::path::Path,
    aliases: &[String],
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::VerifySshReachability.as_str(),
        &format!(
            "ssh_reachable=yes nodes={} ({})",
            aliases.len(),
            aliases.join(",")
        ),
    )
}

/// Besides proving reachability, this is the earliest stage that touches the
/// nodes, so it is where the cloud-node safety guard (direct-path precondition
/// and node-side dead-man) is armed: the daemon is first started by the
/// bootstrap stage (`ops install-systemd` restarts rustynetd, whose
/// `ExecStartPre` installs the `rustynet_boot` killswitch), long before
/// `enforce_baseline_runtime`. Nodes that are not cloud nodes are untouched.
#[derive(Debug, Default)]
pub struct VerifySshReachabilityStage {
    /// Stage ids the plan elected (for the cloud-node reboot refusal).
    planned_stage_ids: Vec<StageId>,
}

impl VerifySshReachabilityStage {
    pub fn new(planned_stage_ids: Vec<StageId>) -> Self {
        Self { planned_stage_ids }
    }
}

impl OrchestrationStage for VerifySshReachabilityStage {
    fn id(&self) -> StageId {
        StageId::VerifySshReachability
    }
    fn name(&self) -> &str {
        "verify_ssh_reachability"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::PrepareSourceArchive]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        // QH-98: a topology with no nodes proved NO reachability. A pass here
        // would record a green ledger row for an unexercised control (the
        // vacuous-pass false green); skip so the run stays Partial and the gap
        // stays visible. Same precedent as mesh_status_validation.
        if aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node assignments in this topology; no SSH reachability was proven".to_owned(),
            );
        }
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => adapter.check_ssh_reachable().map_err(|e| e.to_string()),
                    None => Err(format!("no adapter for '{alias}'")),
                };
                (alias.clone(), r)
            })
            .collect();
        let errors: Vec<String> = results
            .into_iter()
            .filter_map(|(alias, r)| r.err().map(|e| format!("{alias}: {e}")))
            .collect();
        if errors.is_empty() {
            // Reachability is proven; arm the cloud-node safety net before any
            // later stage can start a daemon on those nodes.
            if let Err(e) = guard_dataplane_nodes(
                ctx,
                &StageId::VerifySshReachability,
                &self.planned_stage_ids,
            ) {
                return StageOutcome::Failed(format!(
                    "cloud-node safety guard refused the run: {e}"
                ));
            }
            // QH-83: the witness is written on EVERY pass path and a write
            // failure fails the stage — an unwitnessed reachability pass
            // must not stand.
            match write_ssh_reachability_witness(&ctx.report_dir, &aliases) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => {
                    StageOutcome::Failed(format!("ssh reachability witness write failed: {e}"))
                }
            }
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use std::collections::HashMap;

    // QH-98: an empty topology proved nothing, so it must skip, never pass.
    // Mutation caught: removing the `aliases.is_empty()` guard (the stage then
    // returns Passed with a `nodes=0` witness).
    #[test]
    fn empty_assignments_is_skipped_never_passed() {
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
        let outcome = VerifySshReachabilityStage::default().execute(&mut ctx);
        assert!(
            matches!(outcome, StageOutcome::Skipped(_)),
            "an empty topology must skip, never pass; got {outcome:?}"
        );
    }

    #[test]
    fn missing_adapter_fails() {
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
            VerifySshReachabilityStage::default().execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    // QH-83: a PASS verdict must leave a durable stage-log line, because the
    // catalog declares this stage StageLog and the runner demotes an
    // unwitnessed PASS. Mutation caught: dropping the witness write (this
    // test goes red) or demoting it back to best-effort.
    #[test]
    fn ssh_witness_line_names_the_reachable_node_count() {
        let dir = std::env::temp_dir().join(format!(
            "verify_ssh_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let aliases = vec!["exit-1".to_owned(), "client-1".to_owned()];
        write_ssh_reachability_witness(&dir, &aliases).expect("witness write");

        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::VerifySshReachability.as_str(),
            ),
        )
        .expect("stage log readable");
        assert!(
            log.contains("ssh_reachable=yes nodes=2 (exit-1,client-1)"),
            "{log}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as
    /// an error the stage turns into a failure (never a silent pass).
    #[test]
    fn ssh_witness_write_failure_is_propagated() {
        let blocker =
            std::env::temp_dir().join(format!("verify_ssh_blocker_{}", std::process::id()));
        let _ = std::fs::remove_file(&blocker);
        std::fs::write(&blocker, b"not a directory").expect("blocker file");

        let err = write_ssh_reachability_witness(&blocker, &["exit-1".to_owned()])
            .expect_err("write into a regular file path must fail");
        assert!(!err.is_empty());

        let _ = std::fs::remove_file(&blocker);
    }
}
