#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::{Command, Output};

pub struct LiveExtendedSoakValidationStage;

impl OrchestrationStage for LiveExtendedSoakValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveExtendedSoakValidation
    }

    fn name(&self) -> &str {
        "extended_soak"
    }

    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveMixedTopologyValidation]
    }

    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }

    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        match run_extended_soak(ctx) {
            Ok(()) => StageOutcome::Passed,
            Err(err) => StageOutcome::Failed(err),
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
}

fn run_extended_soak(ctx: &OrchestrationContext) -> Result<(), String> {
    let exit = ssh_params_for_role(ctx, "exit")?;
    let client = ssh_params_for_role(ctx, "client")?;
    let entry = ssh_params_for_role(ctx, "entry")?;
    let aux = ssh_params_for_role(ctx, "aux")?;
    let second_client = ssh_params_for_second_client(ctx)?;

    let identity_file = exit.identity_file.to_string_lossy().into_owned();
    let known_hosts = exit.known_hosts.to_string_lossy().into_owned();
    let ssh_allow_cidrs = if ctx.ssh_allow_cidrs.trim().is_empty() {
        "0.0.0.0/0".to_owned()
    } else {
        ctx.ssh_allow_cidrs.clone()
    };

    run_substep(
        "extended_soak pre-reboot two-hop",
        cargo_bin_command(
            "live_linux_two_hop_test",
            vec![
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--known-hosts".to_owned(),
                known_hosts.clone(),
                "--final-exit-host".to_owned(),
                target(&exit),
                "--final-exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--entry-host".to_owned(),
                target(&entry),
                "--entry-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--second-client-host".to_owned(),
                target(&second_client),
                "--second-client-node-id".to_owned(),
                node_id_for_alias(ctx, &second_client.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_two_hop_soak_pre_reboot_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_two_hop_soak_pre_reboot.log")
                    .to_string_lossy()
                    .into_owned(),
            ],
        ),
    )?;

    run_substep(
        "extended_soak exit handoff",
        cargo_bin_command(
            "live_linux_exit_handoff_test",
            vec![
                "--platform".to_owned(),
                platform_for_node(ctx, &exit.alias).to_owned(),
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--known-hosts".to_owned(),
                known_hosts.clone(),
                "--exit-a-host".to_owned(),
                target(&exit),
                "--exit-a-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--exit-b-host".to_owned(),
                target(&entry),
                "--exit-b-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--switch-iteration".to_owned(),
                "60".to_owned(),
                "--monitor-iterations".to_owned(),
                "180".to_owned(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_exit_handoff_soak_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_exit_handoff_soak.log")
                    .to_string_lossy()
                    .into_owned(),
                "--monitor-log".to_owned(),
                ctx.report_dir
                    .join("live_linux_exit_handoff_soak_monitor.log")
                    .to_string_lossy()
                    .into_owned(),
            ],
        ),
    )?;

    run_substep(
        "extended_soak lan toggle",
        cargo_bin_command(
            "live_linux_lan_toggle_test",
            vec![
                "--platform".to_owned(),
                platform_for_node(ctx, &exit.alias).to_owned(),
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--exit-host".to_owned(),
                target(&exit),
                "--exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--blind-exit-host".to_owned(),
                target(&aux),
                "--blind-exit-node-id".to_owned(),
                node_id_for_alias(ctx, &aux.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_lan_toggle_soak_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_lan_toggle_soak.log")
                    .to_string_lossy()
                    .into_owned(),
            ],
        ),
    )?;

    run_substep(
        "extended_soak reboot recovery",
        cargo_bin_command(
            "live_linux_reboot_recovery_test",
            vec![
                "--ssh-identity-file".to_owned(),
                identity_file,
                "--known-hosts".to_owned(),
                known_hosts,
                "--exit-host".to_owned(),
                target(&exit),
                "--exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--entry-host".to_owned(),
                target(&entry),
                "--entry-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--second-client-host".to_owned(),
                target(&second_client),
                "--second-client-node-id".to_owned(),
                node_id_for_alias(ctx, &second_client.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs,
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_reboot_recovery_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_reboot_recovery.log")
                    .to_string_lossy()
                    .into_owned(),
            ],
        ),
    )
}

fn cargo_bin_command(bin: &str, extra_args: Vec<String>) -> Command {
    let mut command = Command::new("cargo");
    command.args(["run", "--quiet", "-p", "rustynet-cli", "--bin", bin, "--"]);
    command.args(extra_args);
    command
}

fn run_substep(label: &str, mut command: Command) -> Result<(), String> {
    match command.output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format_substep_failure(label, &output)),
        Err(err) => Err(format!("{label}: invocation failed: {err}")),
    }
}

fn format_substep_failure(label: &str, output: &Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let stdout = String::from_utf8_lossy(&output.stdout);
    let detail = if stderr.trim().is_empty() {
        stdout.trim()
    } else {
        stderr.trim()
    };
    format!("{label}: command failed ({}): {detail}", output.status)
}

fn target(params: &ResolvedParams) -> String {
    format!("{}@{}", params.user, params.host)
}

fn node_id_for_alias(ctx: &OrchestrationContext, alias: &str) -> Result<String, String> {
    ctx.node_ids
        .get(alias)
        .cloned()
        .ok_or_else(|| format!("{alias}: node_id not found"))
}

fn platform_for_node(ctx: &OrchestrationContext, alias: &str) -> &'static str {
    match ctx.adapters.get(alias).map(|adapter| adapter.platform()) {
        Some(VmGuestPlatform::Macos) => "macos",
        Some(VmGuestPlatform::Windows) => "windows",
        _ => "linux",
    }
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let alias = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .map(|assignment| assignment.alias.clone())
        .ok_or_else(|| format!("extended_soak requires node role label '{label}'"))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (role '{label}')"))?;
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

fn ssh_params_for_second_client(ctx: &OrchestrationContext) -> Result<ResolvedParams, String> {
    for label in ["extra", "aux"] {
        if let Ok(params) = ssh_params_for_role(ctx, label) {
            return Ok(params);
        }
    }
    Err("extended_soak requires an aux or extra node for second-client checks".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_extended_soak() {
        assert_eq!(
            LiveExtendedSoakValidationStage.id(),
            StageId::LiveExtendedSoakValidation
        );
    }

    #[test]
    fn stage_name_matches_legacy_logical_stage() {
        assert_eq!(LiveExtendedSoakValidationStage.name(), "extended_soak");
    }

    #[test]
    fn depends_on_mixed_topology() {
        assert_eq!(
            LiveExtendedSoakValidationStage.dependencies(),
            &[StageId::LiveMixedTopologyValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveExtendedSoakValidationStage.fanout(), StageFanout::Once);
    }

    #[test]
    fn substep_failure_surfaces_stderr() {
        let output = Command::new("sh")
            .args(["-c", "printf problem >&2; exit 7"])
            .output()
            .expect("shell output");
        let msg = format_substep_failure("label", &output);
        assert!(msg.contains("label"));
        assert!(msg.contains("problem"));
        assert!(msg.contains("exit status: 7"));
    }
}
