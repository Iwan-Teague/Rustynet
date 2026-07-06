#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

pub struct LiveLanToggleValidationStage;

impl OrchestrationStage for LiveLanToggleValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveLanToggleValidation
    }
    fn name(&self) -> &str {
        "live_lan_toggle_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveEnrollmentRestartValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let exit_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let blind_exit_params = match find_blind_exit(ctx) {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let platform = platform_for_node(ctx, &exit_params.alias);
        let exit_node_id = node_id_for_alias(ctx, &exit_params.alias);
        let client_node_id = node_id_for_alias(ctx, &client_params.alias);
        let blind_exit_node_id = node_id_for_alias(ctx, &blind_exit_params.alias);
        let exit_target = format!("{}@{}", exit_params.user, exit_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);
        let blind_exit_target = format!("{}@{}", blind_exit_params.user, blind_exit_params.host);
        let identity_file = exit_params.identity_file.to_string_lossy().into_owned();
        let report_path = ctx
            .report_dir
            .join("live_lan_toggle_report.json")
            .to_string_lossy()
            .into_owned();
        let log_path = ctx
            .report_dir
            .join("live_lan_toggle.log")
            .to_string_lossy()
            .into_owned();

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "live_linux_lan_toggle_test",
            "--",
        ])
        .arg("--platform")
        .arg(platform)
        .arg("--ssh-identity-file")
        .arg(&identity_file)
        .arg("--exit-host")
        .arg(&exit_target)
        .arg("--client-host")
        .arg(&client_target)
        .arg("--blind-exit-host")
        .arg(&blind_exit_target)
        .arg("--exit-node-id")
        .arg(&exit_node_id)
        .arg("--client-node-id")
        .arg(&client_node_id)
        .arg("--blind-exit-node-id")
        .arg(&blind_exit_node_id)
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        match cmd.status() {
            Ok(status) if status.success() => StageOutcome::Passed,
            Ok(status) => {
                StageOutcome::Failed(format!("live_linux_lan_toggle_test exited with {}", status))
            }
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_linux_lan_toggle_test: {e}"))
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

fn find_blind_exit(ctx: &OrchestrationContext) -> Result<ResolvedParams, String> {
    for label in &["aux", "extra", "entry"] {
        let assignment = ctx.assignments.iter().find(|a| a.role.as_str() == *label);
        if let Some(assignment) = assignment {
            let adapter = ctx
                .adapters
                .get(assignment.alias.as_str())
                .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
            if adapter.platform() == VmGuestPlatform::Linux {
                let params = adapter
                    .ssh_connection_params()
                    .ok_or_else(|| format!("no SSH params for {}", assignment.alias))?;
                return Ok(ResolvedParams {
                    alias: assignment.alias.clone(),
                    host: params.host.clone(),
                    user: "debian".to_owned(),
                    identity_file: params.identity_file.clone(),
                });
            }
        }
    }
    Err("no Linux node found for blind_exit role among aux/extra/entry".to_owned())
}

fn platform_for_node(ctx: &OrchestrationContext, alias: &str) -> &'static str {
    let adapter = ctx.adapters.get(alias);
    match adapter.map(|a| a.platform()) {
        Some(VmGuestPlatform::Macos) => "macos",
        Some(VmGuestPlatform::Windows) => "windows",
        _ => "linux",
    }
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
    fn stage_id_is_live_lan_toggle() {
        assert_eq!(
            LiveLanToggleValidationStage.id(),
            StageId::LiveLanToggleValidation
        );
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        assert_eq!(
            LiveLanToggleValidationStage.name(),
            "live_lan_toggle_validation"
        );
    }

    #[test]
    fn depends_on_live_enrollment_restart() {
        assert_eq!(
            LiveLanToggleValidationStage.dependencies(),
            &[StageId::LiveEnrollmentRestartValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveLanToggleValidationStage.fanout(), StageFanout::Once);
    }
}
