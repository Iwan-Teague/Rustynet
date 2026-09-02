//! C7: validate the macOS reboot-with-protection survival as a first-class
//! `--node` engine stage (`MacosDnsBackupRebootSurvivalPlan_2026-09-02.md`).
//! The stage drives a real `sudo -n shutdown -r now` on the macOS node after
//! capturing pre-reboot evidence that the M1 networksetup-DNS fail-closed
//! protection is in place (durable backup present and mode 0600, every
//! enabled networksetup service pinned to loopback), then waits bounded for
//! SSH to return and proves the post-reboot state: the daemon is LIVE with a
//! parseable node identity, the networksetup protection was restored (the
//! startup-recovery log line, or the fail-closed check reporting clean), the
//! typed `macos-dns-failclosed-check` evaluator reports overall_ok, and the
//! QH-40 shutdown-residue marker is absent.
//!
//! FAIL-LOUD: the live result is the stage status. The stage Skips only when
//! the run did not elect macOS for reboot recovery (`--reboot-platform
//! macos`) or when its `validate_baseline_runtime` dependency did not pass;
//! it never reports a dry-run as a pass and never downgrades a failed
//! reboot-recovery proof.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

pub struct MacosRebootRecoveryValidationStage;

impl OrchestrationStage for MacosRebootRecoveryValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosRebootRecoveryValidation
    }

    fn name(&self) -> &'static str {
        self.id().as_str()
    }

    fn dependencies(&self) -> &[StageId] {
        // The reboot proof only means something on a node whose daemon was
        // validated live before the reboot, so the baseline runtime
        // validation is the gate: its "skipped: dependency did not pass"
        // record carries the same fail-closed semantics forward.
        &[StageId::ValidateBaselineRuntime]
    }

    fn applies_to_roles(&self) -> &[crate::vm_lab::orchestrator::role::NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Election first: a run that did not elect macOS for reboot recovery
        // (every other run included) records a reported skip, exactly as the
        // sibling C6 role-transition validator does. Only an ELECTED run then
        // fails closed when the topology cannot supply exactly one macOS
        // target.
        if !ctx.macos_reboot_recovery_elected {
            return StageOutcome::Skipped(
                "skipped: macOS is not elected for reboot recovery (reboot_platform != macos)"
                    .to_owned(),
            );
        }
        let alias = match macos_reboot_recovery_alias(ctx) {
            Ok(alias) => alias,
            Err(err) => return StageOutcome::Failed(err),
        };
        let inventory_path = match ctx.inventory_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no inventory path recorded for this run; the macOS live reboot-recovery validator cannot resolve SSH targets"
                ));
            }
        };
        let adapter = match ctx.adapters.get(&alias) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter registered for the macOS reboot-recovery target"
                ));
            }
        };
        let params = match adapter.ssh_connection_params() {
            Some(params) => params,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no SSH connection parameters resolved for the macOS reboot-recovery target"
                ));
            }
        };
        match crate::vm_lab::exercise_macos_reboot_recovery_live(
            &alias,
            Path::new(&inventory_path),
            &params.identity_file,
            Some(params.known_hosts.as_path()),
            Some(ctx.report_dir.as_path()),
        ) {
            // `Passed` carries no payload (the sibling C6 validator has the
            // same shape), so the human-readable proof line stays in the
            // helper's Ok value and is intentionally not duplicated here.
            Ok(_) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(format!("{alias}: {err}")),
        }
    }
}

/// Resolve the single macOS node the reboot-recovery validator drives. The
/// contract mirrors the sibling C6 validator — exactly one macOS node in the
/// topology, else fail closed.
fn macos_reboot_recovery_alias(ctx: &OrchestrationContext) -> Result<String, String> {
    let macos_aliases: Vec<String> = ctx
        .assignments
        .iter()
        .filter(|assignment| {
            ctx.adapters
                .get(&assignment.alias)
                .is_some_and(|adapter| adapter.platform() == VmGuestPlatform::Macos)
        })
        .map(|assignment| assignment.alias.clone())
        .collect();
    match macos_aliases.split_first() {
        None => Err(
            "no macOS node is present in this topology; the live reboot-recovery validator has no target"
                .to_owned(),
        ),
        Some((first, [])) => Ok(first.clone()),
        Some((_, rest)) => Err(format!(
            "expected exactly one macOS node for the live reboot-recovery validator, found {}",
            rest.len() + 1
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    fn empty_ctx() -> OrchestrationContext {
        OrchestrationContext::new(
            Vec::<NodeRoleAssignment>::new(),
            std::env::temp_dir().join("macos-reboot-recovery-stage-tests"),
            "net".to_owned(),
        )
    }

    #[test]
    fn skips_with_reason_when_macos_is_not_elected() {
        // Every run that did not elect macOS for reboot recovery — a
        // Linux-only run included — must record a reported skip, never a
        // failure: the stage is in the default plan.
        let mut ctx = empty_ctx();
        assert!(
            !ctx.macos_reboot_recovery_elected,
            "a fresh context must default to not-elected (fail closed)"
        );
        let outcome = MacosRebootRecoveryValidationStage.execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Skipped(reason) if reason.contains("not elected")),
            "a non-elected run must skip with a reason: {outcome:?}"
        );
    }

    #[test]
    fn fails_closed_when_elected_but_no_macos_node_exists() {
        let mut ctx = empty_ctx();
        ctx.macos_reboot_recovery_elected = true;
        let outcome = MacosRebootRecoveryValidationStage.execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Failed(message) if message.contains("no macOS node")),
            "an elected run without a macOS node fails closed rather than skipping silently: {outcome:?}"
        );
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        let stage = MacosRebootRecoveryValidationStage;
        assert_eq!(stage.id(), StageId::MacosRebootRecoveryValidation);
        assert_eq!(stage.name(), "validate_macos_reboot_recovery");
        assert_eq!(stage.fanout(), StageFanout::Once);
        assert_eq!(stage.dependencies(), &[StageId::ValidateBaselineRuntime]);
    }
}
