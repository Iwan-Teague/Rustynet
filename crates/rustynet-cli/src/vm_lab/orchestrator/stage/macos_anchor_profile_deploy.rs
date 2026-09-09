#![allow(dead_code)]
//! MAC-D3: deploy the macOS anchor launchd profile as a first-class `--node`
//! stage. This stage was previously a bash-era registry entry that never
//! dispatched under the Rust engine; it is now wired into the engine of
//! record so an elected macOS anchor run actually deploys the profile before
//! the bundle-pull and port-mapping-authority validators run.

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::Path;

pub struct MacosAnchorProfileDeployStage;

impl OrchestrationStage for MacosAnchorProfileDeployStage {
    fn id(&self) -> StageId {
        StageId::MacosAnchorProfileDeploy
    }

    fn name(&self) -> &str {
        "deploy_macos_anchor_profile"
    }

    fn dependencies(&self) -> &[StageId] {
        &[StageId::ValidateBaselineRuntime]
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
                    "{macos_alias}: no SSH connection params available for profile deploy"
                ));
            }
        };
        let ssh_identity_file = params.identity_file.clone();
        let known_hosts_path = params.known_hosts.clone();
        match crate::vm_lab::deploy_macos_anchor_profile(
            &macos_alias,
            Path::new(&inventory_path),
            &ssh_identity_file,
            Some(known_hosts_path.as_path()),
        ) {
            Ok(detail) => {
                // QH-83 evidence-on-pass: the deploy proof (alias + helper
                // detail) must land in the stage's rust-native evidence log;
                // a write failure fails the stage instead of passing
                // unwitnessed.
                match write_profile_deploy_witness(&ctx.report_dir, &macos_alias, &detail) {
                    Ok(()) => StageOutcome::Passed,
                    Err(e) => StageOutcome::Failed(format!(
                        "{macos_alias}: profile deploy witness write failed: {e}"
                    )),
                }
            }
            Err(err) => StageOutcome::Failed(format!("{macos_alias}: {err}")),
        }
    }
}

/// Append one single-line witness record (`<alias>: <detail>`) for a
/// successful profile deploy to the stage's rust-native evidence log. The
/// helper detail is single-line by contract, but any embedded newline is
/// flattened first so it cannot forge extra evidence lines.
fn write_profile_deploy_witness(
    report_dir: &Path,
    alias: &str,
    detail: &str,
) -> Result<(), String> {
    let detail = detail.replace(['\n', '\r'], " ");
    let line = format!("{alias}: {detail}");
    append_stage_evidence_line(
        report_dir,
        StageId::MacosAnchorProfileDeploy.as_str(),
        &line,
    )
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
    use crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;

    fn empty_ctx() -> OrchestrationContext {
        let report_dir = std::env::temp_dir().join("macos-anchor-deploy-stage-test");
        OrchestrationContext::new(
            Vec::<NodeRoleAssignment>::new(),
            report_dir,
            "net".to_owned(),
        )
    }

    #[test]
    fn profile_deploy_witness_line_carries_alias_and_detail() {
        // The witness record must carry the real deploy datum (alias +
        // helper detail) as one line, with any embedded newline flattened.
        let report_dir = std::env::temp_dir().join(format!(
            "profile_deploy_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&report_dir).expect("create temp report dir");
        write_profile_deploy_witness(&report_dir, "macos-anchor-1", "deployed\nlabel")
            .expect("witness write must succeed");
        let log = std::fs::read_to_string(rust_native_stage_log_path(
            &report_dir,
            StageId::MacosAnchorProfileDeploy.as_str(),
        ))
        .expect("evidence log must exist");
        assert!(
            log.contains("macos-anchor-1: deployed label"),
            "witness line must carry alias + flattened detail: {log:?}"
        );
        assert!(!log.contains("\nlabel"), "newline must be flattened");
        let _ = std::fs::remove_dir_all(&report_dir);
    }

    #[test]
    fn profile_deploy_witness_write_failure_is_propagated() {
        // A report_dir that cannot host the evidence log (a regular file
        // occupies the path) must surface as an error the stage turns into a
        // failure, not a silent pass.
        let blocker = std::env::temp_dir().join(format!(
            "profile_deploy_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::write(&blocker, b"not a directory").expect("create blocker file");
        let err = write_profile_deploy_witness(&blocker, "macos-anchor-1", "deployed")
            .expect_err("witness write into a file must fail");
        assert!(!err.is_empty(), "error must explain the failure: {err}");
        let _ = std::fs::remove_file(&blocker);
    }

    #[test]
    fn skips_when_no_node_is_assigned_the_anchor_role() {
        let mut ctx = empty_ctx();
        assert!(!ctx.macos_anchor_validators_elected);
        let outcome = MacosAnchorProfileDeployStage.execute(&mut ctx);
        assert!(matches!(outcome, StageOutcome::Skipped(_)));
    }

    #[test]
    fn stage_metadata_matches_the_catalog() {
        assert_eq!(
            MacosAnchorProfileDeployStage.id(),
            StageId::MacosAnchorProfileDeploy
        );
        assert_eq!(
            MacosAnchorProfileDeployStage.name(),
            "deploy_macos_anchor_profile"
        );
        assert_eq!(MacosAnchorProfileDeployStage.fanout(), StageFanout::Once);
    }
}
