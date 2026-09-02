//! C6: validate the macOS live role-transition validator as a first-class
//! `--node` engine stage (`LiveLabStagePassLikelihood_Summary_2026-09-01.md`
//! C6). Previously the legacy `vm_lab` hub block `validate_macos_role_transition`,
//! which never dispatched under the Rust engine after the bash orchestrator
//! was retired (W5.7). The stage drives a real `TransitionKind::LocalOnly`
//! admin<->client flip on the macOS node through the actual
//! `rustynet role set <to>` CLI — never a second apply path — including the
//! macOS-only launchd bootout+bootstrap reload, an assertion that the daemon
//! reports the new role after restart (live identity/status, not a config
//! file), a `state refresh`, and a mesh-connectivity regression check.
//!
//! FAIL-LOUD: the live result is the stage status. The stage Skips only when
//! the run did not elect macOS for role transition
//! (`--role-switch-platform macos`) or when its `validate_baseline_runtime`
//! dependency did not pass; it never reports a dry-run as a pass and never
//! downgrades a failed flip.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

pub struct MacosRoleTransitionValidationStage;

impl OrchestrationStage for MacosRoleTransitionValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosRoleTransitionValidation
    }

    fn name(&self) -> &'static str {
        self.id().as_str()
    }

    fn dependencies(&self) -> &[StageId] {
        // The legacy hub gate was `validate_macos_mesh_join did not pass`;
        // the `--node` engine's equivalent proof that the node is mesh-joined
        // is the baseline runtime validation, so the dependency wiring (and
        // the runner's "skipped: dependency did not pass" record) carries the
        // same gate forward.
        &[StageId::ValidateBaselineRuntime]
    }

    fn applies_to_roles(&self) -> &[crate::vm_lab::orchestrator::role::NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Election first: a run that did not elect macOS for role transition
        // (every Linux-only run included) records a reported skip, exactly as
        // the legacy hub gate did. Only an ELECTED run then fails closed when
        // the topology cannot supply exactly one macOS target.
        if !ctx.macos_role_transition_elected {
            return StageOutcome::Skipped(
                "skipped: macOS is not elected for role transition (role_switch_platform != macos)"
                    .to_owned(),
            );
        }
        let alias = match macos_role_transition_alias(ctx) {
            Ok(alias) => alias,
            Err(err) => return StageOutcome::Failed(err),
        };
        let inventory_path = match ctx.inventory_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no inventory path recorded for this run; the macOS live role-transition validator cannot resolve SSH targets"
                ));
            }
        };
        let adapter = match ctx.adapters.get(&alias) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter registered for the macOS role-transition target"
                ));
            }
        };
        let params = match adapter.ssh_connection_params() {
            Some(params) => params,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no SSH connection parameters resolved for the macOS role-transition target"
                ));
            }
        };
        match crate::vm_lab::exercise_macos_role_transition_live(
            &alias,
            Path::new(&inventory_path),
            &params.identity_file,
            Some(params.known_hosts.as_path()),
        ) {
            // `Passed` carries no payload (the sibling MAC-D3 validator has
            // the same shape), so the human-readable proof line stays in the
            // helper's Ok value and is intentionally not duplicated here.
            Ok(_) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(format!("{alias}: {err}")),
        }
    }
}

/// Resolve the single macOS node the role-transition validator drives. The
/// legacy hub used the run's single elected macOS guest; the engine keeps the
/// same contract — exactly one macOS node in the topology, else fail closed.
fn macos_role_transition_alias(ctx: &OrchestrationContext) -> Result<String, String> {
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
            "no macOS node is present in this topology; the live role-transition validator has no target"
                .to_owned(),
        ),
        Some((first, [])) => Ok(first.clone()),
        Some((_, rest)) => Err(format!(
            "expected exactly one macOS node for the live role-transition validator, found {}",
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
            std::env::temp_dir().join("macos-role-transition-stage-tests"),
            "net".to_owned(),
        )
    }

    #[test]
    fn skips_with_reason_when_macos_is_not_elected() {
        // Every run that did not elect macOS for role transition — a
        // Linux-only run included — must record a reported skip, never a
        // failure: the stage is in the default plan.
        let mut ctx = empty_ctx();
        assert!(
            !ctx.macos_role_transition_elected,
            "a fresh context must default to not-elected (fail closed)"
        );
        let outcome = MacosRoleTransitionValidationStage.execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Skipped(reason) if reason.contains("not elected")),
            "a non-elected run must skip with a reason: {outcome:?}"
        );
    }

    #[test]
    fn fails_closed_when_elected_but_no_macos_node_exists() {
        let mut ctx = empty_ctx();
        ctx.macos_role_transition_elected = true;
        let outcome = MacosRoleTransitionValidationStage.execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Failed(message) if message.contains("no macOS node")),
            "an elected run without a macOS node fails closed rather than skipping silently: {outcome:?}"
        );
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        let stage = MacosRoleTransitionValidationStage;
        assert_eq!(stage.id(), StageId::MacosRoleTransitionValidation);
        assert_eq!(stage.name(), "validate_macos_role_transition");
        assert_eq!(stage.fanout(), StageFanout::Once);
        assert_eq!(stage.dependencies(), &[StageId::ValidateBaselineRuntime]);
    }
}
