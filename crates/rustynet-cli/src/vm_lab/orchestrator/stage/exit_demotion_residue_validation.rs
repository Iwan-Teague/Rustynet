#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::exit_demotion_residue::{
    exit_demotion_residue_runtime_implemented, validate_linux_exit_demotion_residue,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "exit_demotion_residue_validation.reported_skips.json";

/// Prove the Linux exit node's demotion to client leaves no residue —
/// NAT table torn down, forwarding restored, daemon still running —
/// folding the formerly bash-only two-phase capture + evaluation into a
/// first-class OrchestrationStage.
///
/// Runs after `active_exit` (all exit lifecycle stages must complete
/// before demotion). Applies ONLY to the assigned exit node; a macOS / Windows
/// node is reported-skipped (named, never a silent pass) via
/// [`exit_demotion_residue_runtime_implemented`].
///
/// Side-effect: demotes the Linux exit to client through the public CLI
/// surface (`rustynet role set client`). The two-phase capture (before +
/// after snapshot) provides the anti-vacuous "was serving exit" guard.
pub struct ExitDemotionResidueValidationStage;

impl OrchestrationStage for ExitDemotionResidueValidationStage {
    fn id(&self) -> StageId {
        StageId::ExitDemotionResidueValidation
    }
    fn name(&self) -> &str {
        "exit_demotion_residue_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitNatLifecycleValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Exit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Failed(
                    "exit-demotion-residue: no Exit node in assignments".to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter for exit-demotion-residue node"
                ));
            }
        };
        let platform = adapter.platform();
        if !exit_demotion_residue_runtime_implemented(platform) {
            let reported_skips = vec![(alias, format!("{platform:?}"))];
            write_reported_skips_note(ctx, &reported_skips);
            return StageOutcome::Skipped;
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!("{alias}: shell host unavailable: {e}"));
            }
        };
        let daemon_path = match platform {
            VmGuestPlatform::Linux => LINUX_RUSTYNETD_PATH,
            VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
            VmGuestPlatform::Windows => WINDOWS_RUSTYNETD_PATH,
            _ => unreachable!("runtime implementation gate accepts desktop platforms only"),
        };
        let failures = match validate_linux_exit_demotion_residue(&*shell, daemon_path, &alias) {
            Ok(()) => Vec::new(),
            Err(e) => vec![format!("{alias}: {e}")],
        };
        let reported_skips = Vec::new();

        outcome_for(&failures, &reported_skips)
    }
}

fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    }
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "exit_demotion_residue_validation",
        "reported_skipped_exit_demotion_residue": skipped,
        "reason": "Exit-demotion-residue validation runs live on Linux through the \
                   Rust engine; non-Linux nodes are reported-skipped (named, never \
                   a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn stage_evidence_is_scoped_to_assigned_exit() {
        assert_eq!(
            ExitDemotionResidueValidationStage.applies_to_roles(),
            &[NodeRole::Exit]
        );
    }

    #[test]
    fn outcome_no_failures_no_skips_is_passed() {
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert_eq!(
            outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
            StageOutcome::Skipped
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: residual open relay".into()],
                &[("mac-1".into(), "Macos".into())]
            ),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("exit_demotion_residue_validation"));
    }

    #[test]
    fn no_exit_assignment_fails_closed() {
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
            orchestrator_dialect: None,
        };
        let outcome = ExitDemotionResidueValidationStage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Failed(message) if message.contains("no Exit")));
    }
}
