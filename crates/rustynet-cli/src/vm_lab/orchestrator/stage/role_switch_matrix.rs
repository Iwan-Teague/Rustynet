#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, TunnelsList};
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Verify a node's collected tunnel list actually proves active tunnels.
///
/// Fails closed: the stage's purpose is to confirm tunnels survived role
/// distribution, so neither an empty list nor an un-enumerable node may pass.
/// `wg-not-installed` is the sentinel emitted when the WireGuard enumeration
/// tool is absent — we cannot confirm tunnels there, so it is a failure, not a
/// silent pass (no-fake-pass: never report "verified" for an unverifiable node).
pub(crate) fn verify_tunnels_active(list: &TunnelsList) -> Result<(), String> {
    if list.tunnels.iter().any(|l| l.contains("wg-not-installed")) {
        return Err(
            "cannot verify active tunnels: WireGuard enumeration tool not present on node"
                .to_owned(),
        );
    }
    if list.tunnels.is_empty() {
        return Err(
            "daemon reports no active WireGuard tunnels after role distribution".to_owned(),
        );
    }
    Ok(())
}

pub struct RoleSwitchMatrixStage;

impl OrchestrationStage for RoleSwitchMatrixStage {
    fn id(&self) -> StageId {
        StageId::RoleSwitchMatrix
    }
    fn name(&self) -> &str {
        "role_switch_matrix"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::TrafficTestMatrix]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Verify each node's tunnels are active (daemon responsive after role distribution).
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        // An empty fleet exercises nothing: report a skip, never a witnessed
        // `nodes=0` pass (the same guard every other Live validator carries).
        if aliases.is_empty() {
            return StageOutcome::Skipped(
                "no assignments in scope; role-switch matrix has nothing to verify".to_owned(),
            );
        }
        let results: Vec<(String, Result<(), String>)> = aliases
            .iter()
            .map(|alias| {
                let r = match ctx.adapters.get(alias.as_str()) {
                    Some(adapter) => match adapter.collect_active_tunnels() {
                        Ok(list) => verify_tunnels_active(&list),
                        Err(e) => Err(e.to_string()),
                    },
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
            // QH-83: the witness is written on the single pass path and a
            // write failure fails the stage — an unwitnessed role-switch pass
            // must never be recorded (the runner would demote it). An empty
            // topology still writes its nodes=0 line rather than passing
            // silently.
            match write_role_switch_witness(&ctx.report_dir, &aliases) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(format!("role-switch witness write failed: {e}")),
            }
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

/// Writes the QH-83 witness line for a role-switch-matrix PASS: the validated
/// node count plus each alias whose tunnel enumeration proved the tunnels
/// survived role distribution, so a bare PASS can never be recorded without
/// the on-disk evidence behind it. An unwritable witness fails the stage —
/// fail closed.
fn write_role_switch_witness(
    report_dir: &std::path::Path,
    aliases: &[String],
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::RoleSwitchMatrix.as_str(),
        &format!(
            "role_switch=tunnels_active nodes={} ({})",
            aliases.len(),
            aliases.join(",")
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

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
        };
        assert!(
            matches!(
                RoleSwitchMatrixStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "an empty fleet must skip, never record a witnessed nodes=0 pass"
        );
    }

    #[test]
    fn verify_tunnels_active_requires_non_empty_real_tunnels() {
        // Active tunnels present → ok.
        assert!(
            verify_tunnels_active(&TunnelsList {
                tunnels: vec!["peer: ABC… latest-handshake: 12s ago".to_owned()],
            })
            .is_ok()
        );
        // Empty list → fail closed (no tunnels survived role distribution).
        assert!(verify_tunnels_active(&TunnelsList { tunnels: vec![] }).is_err());
        // Enumeration tool absent → unverifiable → fail closed, never a silent pass.
        assert!(
            verify_tunnels_active(&TunnelsList {
                tunnels: vec!["wg-not-installed".to_owned()],
            })
            .is_err()
        );
    }

    // QH-83: the pass witness must name the validated node count and the
    // aliases — a bare "pass" line would be appeasement, not evidence.
    // Mutation caught: dropping the witness write or demoting it to
    // best-effort.
    #[test]
    fn role_switch_witness_line_names_the_validated_node_count() {
        let dir = std::env::temp_dir().join(format!(
            "rsm_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_role_switch_witness(&dir, &["deb-1".to_owned(), "deb-2".to_owned()])
            .expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::RoleSwitchMatrix.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("role_switch=tunnels_active"), "{log}");
        assert!(log.contains("nodes=2"), "{log}");
        assert!(log.contains("deb-1") && log.contains("deb-2"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn role_switch_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "rsm_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_role_switch_witness(&dir, &["deb-1".to_owned()])
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
