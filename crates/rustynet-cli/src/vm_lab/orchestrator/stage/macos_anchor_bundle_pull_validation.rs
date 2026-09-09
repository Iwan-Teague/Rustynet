#![allow(dead_code)]
//! MAC-D3: validate the macOS anchor bundle pull (loopback serving, token
//! gate, LAN refusal, secrets hygiene) as a first-class `--node` stage.
//! Previously a bash-era registry entry that never dispatched under the Rust
//! engine; now wired into the engine of record so an elected macOS anchor
//! run produces real runtime evidence instead of a bookkeeping delegation.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

/// QH-83 F1: the macOS anchor bundle-pull stage's pass witness.
/// `exercise_macos_anchor_bundle_pull_live` reads and validates this report
/// (fatal on absence) before returning Ok, so a Passed verdict is only
/// proven when this artifact exists and is non-empty.
pub(crate) const BUNDLE_PULL_REPORT_RELATIVE: &str = "live_macos_anchor_bundle_pull_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(BUNDLE_PULL_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

pub struct MacosAnchorBundlePullValidationStage;

impl OrchestrationStage for MacosAnchorBundlePullValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosAnchorBundlePullValidation
    }

    fn name(&self) -> &str {
        "validate_macos_anchor_bundle_pull"
    }

    fn dependencies(&self) -> &[StageId] {
        &[StageId::MacosAnchorProfileDeploy]
    }

    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let macos_alias = match macos_anchor_alias(ctx) {
            Ok(alias) => alias,
            Err(skip) => return StageOutcome::Skipped(skip),
        };
        if !ctx.macos_anchor_validators_elected {
            return StageOutcome::Skipped(
                "macOS anchor validators were not elected for this run (--anchor-platform macos)"
                    .to_owned(),
            );
        }
        let inventory_path = match ctx.inventory_path.as_deref() {
            Some(path) => path.to_owned(),
            None => {
                // Fail closed: the validators were elected but the run-local
                // inventory path is missing (e.g. a resumed context). Never
                // silently skip a security posture validation.
                return StageOutcome::Failed(
                    "macOS anchor validators elected but orchestration context carries no inventory path"
                        .to_owned(),
                );
            }
        };
        let adapter = match ctx.adapters.get(macos_alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "no adapter registered for macOS anchor node {macos_alias}"
                ));
            }
        };
        let params = match adapter.ssh_connection_params() {
            Some(params) => params,
            None => {
                return StageOutcome::Failed(format!(
                    "{macos_alias}: no SSH connection params available for bundle-pull validation"
                ));
            }
        };
        let ssh_identity_file = params.identity_file.clone();
        let known_hosts_path = params.known_hosts.clone();
        match crate::vm_lab::exercise_macos_anchor_bundle_pull_live(
            &macos_alias,
            Path::new(&inventory_path),
            &ssh_identity_file,
            Some(known_hosts_path.as_path()),
            &ctx.report_dir,
        ) {
            Ok(_detail) => match verify_report_artifact(&ctx.report_dir) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(e),
            },
            Err(err) => StageOutcome::Failed(format!("{macos_alias}: {err}")),
        }
    }
}

/// Resolve the single macOS anchor node alias, or fail with a skip reason.
/// Skips (not failures) when no macOS node is assigned the anchor role: the
/// stage is a no-op on topologies without an elected macOS anchor.
fn macos_anchor_alias(ctx: &OrchestrationContext) -> Result<String, String> {
    let mut macos_anchor: Option<String> = None;
    for assignment in &ctx.assignments {
        if assignment.role != NodeRole::Anchor {
            continue;
        }
        let is_macos = ctx
            .adapters
            .get(assignment.alias.as_str())
            .map(|adapter| adapter.platform() == VmGuestPlatform::Macos)
            .unwrap_or(false);
        if is_macos {
            if macos_anchor.is_some() {
                return Err(
                    "multiple macOS nodes are assigned the anchor role in this topology".to_owned(),
                );
            }
            macos_anchor = Some(assignment.alias.clone());
        }
    }
    macos_anchor
        .ok_or_else(|| "no macOS node is assigned the anchor role in this topology".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    fn empty_ctx() -> OrchestrationContext {
        let report_dir = std::env::temp_dir().join("macos-anchor-bundle-pull-stage-test");
        OrchestrationContext::new(
            Vec::<NodeRoleAssignment>::new(),
            report_dir,
            "net".to_owned(),
        )
    }

    #[test]
    fn skips_when_no_node_is_assigned_the_anchor_role() {
        let mut ctx = empty_ctx();
        assert!(!ctx.macos_anchor_validators_elected);
        let outcome = MacosAnchorBundlePullValidationStage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Skipped(_)));
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        assert_eq!(
            MacosAnchorBundlePullValidationStage.id(),
            StageId::MacosAnchorBundlePullValidation
        );
        assert_eq!(
            MacosAnchorBundlePullValidationStage.name(),
            "validate_macos_anchor_bundle_pull"
        );
        assert_eq!(
            MacosAnchorBundlePullValidationStage.fanout(),
            StageFanout::Once
        );
    }

    #[test]
    fn macos_anchor_bundle_pull_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::MacosAnchorBundlePullValidation.evidence(),
            StageEvidence::File(BUNDLE_PULL_REPORT_RELATIVE),
            "the catalog must declare the bundle-pull report as the pass witness"
        );
    }

    #[test]
    fn macos_anchor_bundle_pull_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "bundle_pull_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let result = verify_report_artifact(&dir);
        assert!(result.is_err(), "an empty report dir must not pass");
        assert!(
            result.unwrap_err().contains(BUNDLE_PULL_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
