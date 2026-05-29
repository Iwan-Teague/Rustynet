#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{StageOutcome, TunnelsList};
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
            StageOutcome::Passed
        } else {
            StageOutcome::Failed(errors.join("; "))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn empty_assignments_passes() {
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
        assert_eq!(
            RoleSwitchMatrixStage.execute(&mut ctx),
            StageOutcome::Passed
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
}
