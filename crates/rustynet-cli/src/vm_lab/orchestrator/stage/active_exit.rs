#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Prove the exit node ACTIVELY serves as a full-tunnel exit — not merely that
/// it holds the exit role.
///
/// The standard lab flow validates an exit node's role / posture / mesh in
/// SPLIT-TUNNEL only; it never drives active exit-serving, so the exit never
/// applies IP forwarding or NAT (live evidence: forwarding stays Disabled and no
/// NAT is created during a normal run). This stage closes that gap: it instructs
/// the exit daemon to advertise the default route `0.0.0.0/0` — the operator
/// "become an exit node" action, sent over the daemon's control named pipe —
/// which makes the daemon apply IP forwarding + source-NAT for client mesh
/// traffic, then asserts the dataplane actually came up as an active exit.
///
/// It runs after `exit_handoff` (mesh + roles already validated) and before
/// final cleanup tears the mesh down. A host lacking the WinNAT/HNS networking
/// stack fails closed here with a clear remediation message from the exit
/// preflight, rather than passing a split-tunnel-only run as if the exit served.
pub struct ActiveExitStage;

impl OrchestrationStage for ActiveExitStage {
    fn id(&self) -> StageId {
        StageId::ActiveExit
    }
    fn name(&self) -> &str {
        "active_exit"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitHandoff]
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
            None => {
                return StageOutcome::Failed("active_exit: no Exit node in assignments".to_owned());
            }
        };
        let adapter = match ctx.adapters.get(exit_alias.as_str()) {
            Some(a) => a,
            None => {
                return StageOutcome::Failed(format!(
                    "active_exit: no adapter for exit '{exit_alias}'"
                ));
            }
        };

        // 1. Activate exit-serving: instruct the daemon to advertise 0.0.0.0/0,
        //    which triggers apply IP forwarding + NAT. Fails closed (with the
        //    daemon's own reason) on a host that cannot serve — e.g. one missing
        //    the WinNAT/HNS stack reports a clear remediation message.
        if let Err(e) = adapter.activate_exit_serving() {
            let daemon = adapter
                .collect_daemon_failure_reason()
                .ok()
                .flatten()
                .map(|reason| format!(" (daemon: {reason})"))
                .unwrap_or_default();
            return StageOutcome::Failed(format!(
                "active_exit: activating exit-serving on '{exit_alias}' failed: {e}{daemon}"
            ));
        }

        // 2. Assert the exit is actually NATing client traffic: IP forwarding
        //    enabled on the tunnel adapter AND a RustyNet NAT instance present.
        if let Err(e) = adapter.assert_exit_actively_serving() {
            return StageOutcome::Failed(format!(
                "active_exit: exit '{exit_alias}' did not come up as an active full-tunnel exit: {e}"
            ));
        }

        StageOutcome::Passed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = ActiveExitStage;
        assert_eq!(stage.id(), StageId::ActiveExit);
        assert_eq!(stage.name(), "active_exit");
        assert_eq!(stage.id().as_str(), "active_exit");
        assert_eq!(stage.dependencies(), &[StageId::ExitHandoff]);
        assert!(matches!(stage.fanout(), StageFanout::Once));
        // Runs lab-wide (operates on the single exit + client), not per-node.
        assert!(stage.applies_to_roles().is_empty());
    }

    #[test]
    fn no_exit_node_fails_closed() {
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
        assert!(matches!(
            ActiveExitStage.execute(&mut ctx),
            StageOutcome::Failed(_)
        ));
    }
}
