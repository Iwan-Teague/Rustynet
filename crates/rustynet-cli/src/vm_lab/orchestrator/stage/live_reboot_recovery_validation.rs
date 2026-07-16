#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORT_FILENAME: &str = "live_reboot_recovery_report.json";

pub struct LiveRebootRecoveryValidationStage;

impl OrchestrationStage for LiveRebootRecoveryValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveRebootRecoveryValidation
    }
    fn name(&self) -> &str {
        "live_reboot_recovery_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveNetworkFlapValidation]
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

        let exit_node_id = match ctx.node_ids.get(&exit_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("exit node_id not found".into()),
        };
        let client_node_id = match ctx.node_ids.get(&client_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("client node_id not found".into()),
        };

        let report_path = ctx.report_dir.join(REPORT_FILENAME);
        let log_path = ctx.report_dir.join("live_reboot_recovery.log");

        let exit_target = format!("{}@{}", exit_params.user, exit_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path_str = report_path
            .to_str()
            .unwrap_or("live_reboot_recovery_report.json");
        let log_path_str = log_path.to_str().unwrap_or("live_reboot_recovery.log");
        let identity_file = exit_params.identity_file.to_str().unwrap_or("");

        let result = std::process::Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--bin",
                "live_linux_reboot_recovery_test",
                "--",
                "--ssh-identity-file",
                identity_file,
                "--exit-host",
                &exit_target,
                "--exit-node-id",
                &exit_node_id,
                "--client-host",
                &client_target,
                "--client-node-id",
                &client_node_id,
                "--report-path",
                report_path_str,
                "--log-path",
                log_path_str,
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    StageOutcome::Passed
                } else {
                    StageOutcome::Failed(
                        crate::vm_lab::orchestrator::stage::format_stage_binary_failure(
                            "live_reboot_recovery binary",
                            output.status,
                            &output.stdout,
                            &output.stderr,
                        ),
                    )
                }
            }
            Err(e) => StageOutcome::Failed(format!(
                "live_reboot_recovery binary invocation failed: {e}"
            )),
        }
    }
}

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: std::path::PathBuf,
    known_hosts: std::path::PathBuf,
}

fn alias_matching_label(ctx: &OrchestrationContext, label: &str) -> Option<String> {
    ctx.assignments
        .iter()
        .find(|a| a.role.as_str() == label)
        .map(|a| a.alias.clone())
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let alias = alias_matching_label(ctx, label)
        .ok_or_else(|| format!("no node with role label '{label}' in assignments"))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (label '{label}')"))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{alias} ({label}): no SSH connection params available"))?;
    let user = params.user.unwrap_or_else(|| {
        match adapter.platform() {
            VmGuestPlatform::Linux => "root",
            VmGuestPlatform::Macos => "admin",
            VmGuestPlatform::Windows => "administrator",
            _ => "root",
        }
        .to_owned()
    });
    Ok(ResolvedParams {
        alias,
        host: params.host,
        user,
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_reboot_recovery() {
        let stage = LiveRebootRecoveryValidationStage;
        assert_eq!(stage.id(), StageId::LiveRebootRecoveryValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveRebootRecoveryValidationStage;
        assert_eq!(stage.name(), "live_reboot_recovery_validation");
    }

    #[test]
    fn depends_on_live_network_flap() {
        assert_eq!(
            LiveRebootRecoveryValidationStage.dependencies(),
            &[StageId::LiveNetworkFlapValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(
            LiveRebootRecoveryValidationStage.fanout(),
            StageFanout::Once
        );
    }
}
