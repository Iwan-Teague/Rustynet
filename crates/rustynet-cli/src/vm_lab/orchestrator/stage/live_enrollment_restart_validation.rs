#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

pub struct LiveEnrollmentRestartValidationStage;

impl OrchestrationStage for LiveEnrollmentRestartValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveEnrollmentRestartValidation
    }
    fn name(&self) -> &str {
        "live_enrollment_restart_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveKeyCustodyValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Enrollment-restart requires a dedicated `aux` enrollee node (the
        // admin enrolls it, restarts it, and proves the enrollment survives).
        // A minimal topology (e.g. exit + single client) has no aux node and
        // cannot exercise this — skip rather than fail-closed, matching the
        // two_hop incomplete-topology skip and the role-gated live-suite
        // stages. A missing `exit` (the enrolling admin) remains a hard fail.
        if !ctx.assignments.iter().any(|a| a.role.as_str() == "aux") {
            return StageOutcome::Skipped;
        }
        let admin_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let enrollee_params = match ssh_params_for_role(ctx, "aux") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let admin_node_id = node_id_for_alias(ctx, &admin_params.alias);
        let enrollee_node_id = node_id_for_alias(ctx, &enrollee_params.alias);
        let admin_target = format!("{}@{}", admin_params.user, admin_params.host);
        let enrollee_target = format!("{}@{}", enrollee_params.user, enrollee_params.host);
        let identity_file = admin_params.identity_file.to_string_lossy().into_owned();
        let report_path = ctx
            .report_dir
            .join("live_enrollment_restart_report.json")
            .to_string_lossy()
            .into_owned();
        let log_path = ctx
            .report_dir
            .join("live_enrollment_restart.log")
            .to_string_lossy()
            .into_owned();

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "live_linux_enrollment_restart_test",
            "--",
        ])
        .arg("--ssh-identity-file")
        .arg(identity_file.as_str())
        .arg("--admin-host")
        .arg(&admin_target)
        .arg("--enrollee-host")
        .arg(&enrollee_target)
        .arg("--admin-node-id")
        .arg(&admin_node_id)
        .arg("--enrollee-node-id")
        .arg(&enrollee_node_id)
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        match cmd.status() {
            Ok(status) if status.success() => StageOutcome::Passed,
            Ok(status) => {
                StageOutcome::Failed(format!("live_enrollment_restart_test exited with {status}"))
            }
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_enrollment_restart_test: {e}"))
            }
        }
    }
}

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: PathBuf,
}

fn alias_matching_label(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|a| a.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to label {label}"))?;
    let adapter = ctx
        .adapters
        .get(assignment.alias.as_str())
        .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("no SSH params for {}", assignment.alias))?;
    let user = match adapter.platform() {
        VmGuestPlatform::Windows => "admin",
        _ => "debian",
    };
    Ok(ResolvedParams {
        alias: assignment.alias.clone(),
        host: params.host.clone(),
        user: user.to_owned(),
        identity_file: params.identity_file.clone(),
    })
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    alias_matching_label(ctx, label)
}

fn node_id_for_alias(ctx: &OrchestrationContext, alias: &str) -> String {
    ctx.node_ids
        .get(alias)
        .cloned()
        .unwrap_or_else(|| alias.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_enrollment_restart() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.id(),
            StageId::LiveEnrollmentRestartValidation
        );
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.name(),
            "live_enrollment_restart_validation"
        );
    }

    #[test]
    fn depends_on_live_key_custody() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.dependencies(),
            &[StageId::LiveKeyCustodyValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.fanout(),
            StageFanout::Once
        );
    }
}
