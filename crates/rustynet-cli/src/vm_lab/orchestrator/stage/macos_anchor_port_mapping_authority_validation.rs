#![allow(dead_code)]
//! MAC-D3: validate the macOS anchor port-mapping authority as a first-class
//! `--node` stage. Previously a bash-era registry entry that never dispatched
//! under the Rust engine; now wired into the engine of record so an elected
//! macOS anchor run proves port-mapping authority live.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

pub struct MacosAnchorPortMappingAuthorityValidationStage;

impl OrchestrationStage for MacosAnchorPortMappingAuthorityValidationStage {
    fn id(&self) -> StageId {
        StageId::MacosAnchorPortMappingAuthorityValidation
    }

    fn name(&self) -> &str {
        "validate_macos_anchor_port_mapping_authority"
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
                    "{macos_alias}: no SSH connection params available for port-mapping validation"
                ));
            }
        };
        let ssh_identity_file = params.identity_file.clone();
        let known_hosts_path = params.known_hosts.clone();
        match crate::vm_lab::exercise_macos_anchor_port_mapping_authority_live(
            &macos_alias,
            Path::new(&inventory_path),
            &ssh_identity_file,
            Some(known_hosts_path.as_path()),
        ) {
            Ok(_detail) => StageOutcome::Passed,
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
        let report_dir = std::env::temp_dir().join("macos-anchor-port-mapping-stage-test");
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
        let outcome = MacosAnchorPortMappingAuthorityValidationStage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Skipped(_)));
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.id(),
            StageId::MacosAnchorPortMappingAuthorityValidation
        );
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.name(),
            "validate_macos_anchor_port_mapping_authority"
        );
        assert_eq!(
            MacosAnchorPortMappingAuthorityValidationStage.fanout(),
            StageFanout::Once
        );
    }
}
