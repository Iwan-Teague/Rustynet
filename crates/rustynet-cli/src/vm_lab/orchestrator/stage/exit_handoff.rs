#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

pub struct ExitHandoffStage;

impl OrchestrationStage for ExitHandoffStage {
    fn id(&self) -> StageId {
        StageId::ExitHandoff
    }
    fn name(&self) -> &str {
        "exit_handoff"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::RoleSwitchMatrix]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(a) => a.alias.clone(),
            None => return StageOutcome::Failed("no Exit node in assignments".to_owned()),
        };
        use crate::vm_lab::orchestrator::stage::role_switch_matrix::verify_tunnels_active;
        let adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(a) => a,
            None => return StageOutcome::Failed(format!("no adapter for exit '{exit_alias}'")),
        };
        // 1. The exit must hold its membership owner key (it is the signer).
        if let Err(e) = adapter.issue_membership_owner_key() {
            return StageOutcome::Failed(format!(
                "exit handoff: membership owner key unavailable on '{exit_alias}': {e}"
            ));
        }
        // 2. Prove the exit is actually serving the mesh, not merely that the
        //    owner-key file exists: it must have at least one active tunnel.
        //    Fails closed if tunnels are absent or unverifiable.
        match adapter.collect_active_tunnels() {
            Ok(list) => match verify_tunnels_active(&list) {
                Ok(()) => {
                    // QH-83: the witness is written on the single pass path
                    // and a write failure fails the stage — an unwitnessed
                    // exit-handoff pass must never be recorded (the runner
                    // would demote it).
                    match write_exit_handoff_witness(&ctx.report_dir, &exit_alias) {
                        Ok(()) => StageOutcome::Passed,
                        Err(e) => {
                            StageOutcome::Failed(format!("exit-handoff witness write failed: {e}"))
                        }
                    }
                }
                Err(e) => StageOutcome::Failed(format!("exit handoff: exit '{exit_alias}' {e}")),
            },
            Err(e) => StageOutcome::Failed(format!(
                "exit handoff: tunnel query failed on '{exit_alias}': {e}"
            )),
        }
    }
}

/// Writes the QH-83 witness line for an exit-handoff PASS: the exit alias
/// whose owner key was issued and whose active tunnel proved it is actually
/// serving the mesh, so a bare PASS can never be recorded without the on-disk
/// evidence behind it. An unwritable witness fails the stage — fail closed.
fn write_exit_handoff_witness(
    report_dir: &std::path::Path,
    exit_alias: &str,
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::ExitHandoff.as_str(),
        &format!("exit_handoff=yes exit={exit_alias} tunnels_active=true"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
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
            relay_forwarding_validation_elected: false,
        };
        assert!(matches!(
            ExitHandoffStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }

    // QH-83: the pass witness must name the exit alias and the tunnel-active
    // verdict — a bare "pass" line would be appeasement, not evidence.
    // Mutation caught: dropping the witness write or demoting it to
    // best-effort.
    #[test]
    fn exit_handoff_witness_line_names_the_exit_alias() {
        let dir = std::env::temp_dir().join(format!(
            "handoff_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_exit_handoff_witness(&dir, "exit-a").expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::ExitHandoff.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("exit_handoff=yes"), "{log}");
        assert!(log.contains("exit=exit-a"), "{log}");
        assert!(log.contains("tunnels_active=true"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn exit_handoff_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "handoff_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_exit_handoff_witness(&dir, "exit-a")
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
