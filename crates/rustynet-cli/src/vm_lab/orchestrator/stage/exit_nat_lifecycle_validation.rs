#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::exit_nat_lifecycle::{
    exit_nat_lifecycle_runtime_implemented, validate_linux_exit_nat_lifecycle,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "exit_nat_lifecycle_validation.reported_skips.json";

/// Prove the exit node's NAT table is present during active exit service and
/// absent after daemon stop — a two-phase snapshot→stop→snapshot→merge→evaluate
/// lifecycle check folded into the standard Rust orchestrator.
///
/// Runs after `exit_dns_failclosed_validation` while the assigned exit is still
/// active. After proving stop-time teardown, it restarts/reactivates the exit so
/// the following demotion-residue proof starts from a non-vacuous active state.
pub struct ExitNatLifecycleValidationStage;

impl OrchestrationStage for ExitNatLifecycleValidationStage {
    fn id(&self) -> StageId {
        StageId::ExitNatLifecycleValidation
    }
    fn name(&self) -> &str {
        "exit_nat_lifecycle_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitDnsFailclosedValidation]
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
                    "exit-nat-lifecycle: no Exit node in assignments".to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter for exit-nat-lifecycle node"
                ));
            }
        };
        let platform = adapter.platform();
        if !exit_nat_lifecycle_runtime_implemented(platform) {
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
        if let Err(e) = validate_linux_exit_nat_lifecycle(&*shell, daemon_path, &alias) {
            return StageOutcome::Failed(format!("{alias}: {e}"));
        }

        // Lifecycle proof deliberately stops rustynetd. Restore the exact
        // active-exit precondition needed by exit-demotion-residue; failure to
        // restore is itself a hard lifecycle failure, never a silent skip.
        if let Err(e) = adapter.start_daemon() {
            return StageOutcome::Failed(format!(
                "{alias}: restart after NAT lifecycle proof failed: {e}"
            ));
        }
        if let Err(e) = adapter.activate_exit_serving() {
            return StageOutcome::Failed(format!(
                "{alias}: reactivate exit after NAT lifecycle proof failed: {e}"
            ));
        }
        if let Err(e) = adapter.assert_exit_actively_serving() {
            return StageOutcome::Failed(format!(
                "{alias}: reactivated exit failed active-serving assertion: {e}"
            ));
        }

        let failures = Vec::new();
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
        "stage": "exit_nat_lifecycle_validation",
        "reported_skipped_exit_nat_lifecycle": skipped,
        "reason": "Exit NAT lifecycle check runs live on Linux through the Rust engine; \
                   non-Linux nodes are reported-skipped (named, never a silent pass)",
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

    #[test]
    fn stage_evidence_is_scoped_to_assigned_exit() {
        assert_eq!(
            ExitNatLifecycleValidationStage.applies_to_roles(),
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
                &["deb-1: exit NAT lifecycle check failed".into()],
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
        assert!(s.contains("exit_nat_lifecycle_validation"));
    }
}
