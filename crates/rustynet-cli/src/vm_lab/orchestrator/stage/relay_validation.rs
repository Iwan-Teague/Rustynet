#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::relay::validate_relay_lifecycle;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// Prove every Relay node ACTIVELY serves the relay datapath + health
/// endpoint and tears them down cleanly — folding the formerly
/// Linux-only `live_linux_relay_test` lifecycle proof into the standard
/// orchestrator so it runs cross-OS (Linux, macOS, Windows).
///
/// For each `Relay`-role node it captures a during-run snapshot
/// (service active + datapath UDP port bound + health TCP port bound +
/// `/healthz` returns `ok`), stops the service, captures an after-stop
/// snapshot asserting the inverse (service inactive, both ports gone,
/// `/healthz` unreachable), then restarts the service so subsequent
/// stages inherit a serving relay. Everything is driven through the
/// adapter's cross-OS [`RemoteShellHost`] seam with argv-only probes.
///
/// It runs after `validate_baseline_runtime` (the relay daemon is up and
/// its role posture validated) and before the traffic matrix. A run with
/// no Relay nodes is a skip-noop: the stage passes without touching any
/// host, mirroring the empty-assignment case in `role_switch_matrix`.
pub struct RelayValidationStage;

impl OrchestrationStage for RelayValidationStage {
    fn id(&self) -> StageId {
        StageId::RelayValidation
    }
    fn name(&self) -> &str {
        "relay_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ValidateBaselineRuntime]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Relay]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Self-filter for Relay nodes (the runner ignores applies_to_roles).
        let relay_aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::Relay)
            .map(|a| a.alias.clone())
            .collect();

        // No Relay nodes in this lab → nothing to validate. Skip-noop:
        // pass without touching any host, like role_switch_matrix's
        // empty-assignment case.
        if relay_aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        for alias in &relay_aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for relay node"));
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
            if let Err(e) = validate_relay_lifecycle(&*shell, adapter.platform()) {
                failures.push(format!("{alias}: {e}"));
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

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext {
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
        }
    }

    #[test]
    fn stage_identity_and_dependencies() {
        let stage = RelayValidationStage;
        assert_eq!(stage.id(), StageId::RelayValidation);
        assert_eq!(stage.name(), "relay_validation");
        assert_eq!(stage.id().as_str(), "relay_validation");
        assert_eq!(stage.dependencies(), &[StageId::ValidateBaselineRuntime]);
        assert!(matches!(stage.fanout(), StageFanout::PerNode));
        assert_eq!(stage.applies_to_roles(), &[NodeRole::Relay]);
    }

    #[test]
    fn empty_assignments_passes_skip_noop() {
        let mut ctx = empty_ctx();
        assert_eq!(RelayValidationStage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn no_relay_role_among_non_relay_assignments_passes_skip_noop() {
        // Assignments present but none Relay → still a skip-noop pass:
        // the stage only validates Relay nodes.
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![
            NodeRoleAssignment {
                alias: "n1".to_owned(),
                role: NodeRole::Exit,
            },
            NodeRoleAssignment {
                alias: "n2".to_owned(),
                role: NodeRole::Client,
            },
        ];
        assert_eq!(RelayValidationStage.execute(&mut ctx), StageOutcome::Passed);
    }

    #[test]
    fn relay_role_without_adapter_fails_closed() {
        // A Relay assignment with no adapter wired must fail closed
        // (never silently skip an unvalidatable relay).
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let mut ctx = empty_ctx();
        ctx.assignments = vec![NodeRoleAssignment {
            alias: "relay-1".to_owned(),
            role: NodeRole::Relay,
        }];
        let outcome = RelayValidationStage.execute(&mut ctx);
        match outcome {
            StageOutcome::Failed(msg) => {
                assert!(msg.contains("relay-1"), "got: {msg}");
                assert!(msg.contains("no adapter"), "got: {msg}");
            }
            other => panic!("expected Failed, got {other:?}"),
        }
    }
}
