#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

pub struct LiveAnchorStage;

impl OrchestrationStage for LiveAnchorStage {
    fn id(&self) -> StageId {
        StageId::LiveAnchor
    }

    fn name(&self) -> &str {
        "live_anchor"
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
        let anchor = match ssh_params_for_role(ctx, "exit") {
            Ok(params) => params,
            Err(err) => return StageOutcome::Failed(err),
        };
        let second_anchor = match ssh_params_for_role(ctx, "entry") {
            Ok(params) => params,
            Err(_) => return StageOutcome::Skipped,
        };
        let leaf_client = match ssh_params_for_role(ctx, "aux") {
            Ok(params) => params,
            Err(_) => return StageOutcome::Skipped,
        };
        let enrollee = match ssh_params_for_role(ctx, "extra") {
            Ok(params) => params,
            Err(_) => return StageOutcome::Skipped,
        };

        let anchor_node_id = match node_id_for_role(ctx, "exit") {
            Ok(node_id) => node_id,
            Err(err) => return StageOutcome::Failed(err),
        };
        let second_anchor_node_id = match node_id_for_role(ctx, "entry") {
            Ok(node_id) => node_id,
            Err(err) => return StageOutcome::Failed(err),
        };
        let leaf_client_node_id = match node_id_for_role(ctx, "aux") {
            Ok(node_id) => node_id,
            Err(err) => return StageOutcome::Failed(err),
        };
        let enrollee_node_id = match node_id_for_role(ctx, "extra") {
            Ok(node_id) => node_id,
            Err(err) => return StageOutcome::Failed(err),
        };

        let report_path = ctx.report_dir.join("live_linux_anchor_report.json");
        let log_path = ctx.report_dir.join("live_linux_anchor.log");
        let owner_approver_id = format!("{anchor_node_id}-owner");

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "live_linux_anchor_test",
            "--",
            "--platform",
            platform_arg(anchor.platform),
            "--ssh-identity-file",
        ])
        .arg(&anchor.identity_file)
        .arg("--known-hosts")
        .arg(&anchor.known_hosts)
        .arg("--anchor-host")
        .arg(&anchor.target)
        .arg("--anchor-node-id")
        .arg(&anchor_node_id)
        .arg("--second-anchor-host")
        .arg(&second_anchor.target)
        .arg("--second-anchor-node-id")
        .arg(&second_anchor_node_id)
        .arg("--leaf-client-host")
        .arg(&leaf_client.target)
        .arg("--leaf-client-node-id")
        .arg(&leaf_client_node_id)
        .arg("--leaf-client-platform")
        .arg(platform_arg(leaf_client.platform))
        .arg("--enrollee-host")
        .arg(&enrollee.target)
        .arg("--enrollee-node-id")
        .arg(&enrollee_node_id)
        .arg("--owner-approver-id")
        .arg(&owner_approver_id)
        .arg("--anchor-bundle-pull-addr")
        .arg("127.0.0.1:51822")
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        match cmd.output() {
            Ok(output) if output.status.success() => StageOutcome::Passed,
            Ok(output) => StageOutcome::Failed(format!(
                "live_linux_anchor_test exited with {}: {}",
                output.status,
                stderr_snippet(&output.stderr)
            )),
            Err(err) => {
                StageOutcome::Failed(format!("failed to run live_linux_anchor_test: {err}"))
            }
        }
    }
}

struct ResolvedParams {
    target: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
    platform: VmGuestPlatform,
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to role {label}"))?;
    let adapter = ctx
        .adapters
        .get(assignment.alias.as_str())
        .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
    let params = adapter
        .ssh_connection_params()
        .ok_or_else(|| format!("{} ({label}): no SSH params available", assignment.alias))?;
    let platform = adapter.platform();
    let user = params
        .user
        .unwrap_or_else(|| default_ssh_user(platform).to_owned());
    Ok(ResolvedParams {
        target: format!("{user}@{}", params.host),
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
        platform,
    })
}

fn node_id_for_role(ctx: &OrchestrationContext, label: &str) -> Result<String, String> {
    let assignment = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .ok_or_else(|| format!("no node assigned to role {label}"))?;
    ctx.node_ids
        .get(assignment.alias.as_str())
        .cloned()
        .ok_or_else(|| format!("no node_id for {}", assignment.alias))
}

fn default_ssh_user(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Windows => "administrator",
        VmGuestPlatform::Macos => "admin",
        _ => "debian",
    }
}

fn platform_arg(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Macos => "macos",
        VmGuestPlatform::Windows => "windows",
        _ => "linux",
    }
}

fn stderr_snippet(stderr: &[u8]) -> String {
    String::from_utf8_lossy(stderr)
        .chars()
        .take(500)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_anchor_stage_metadata_matches_registry_name() {
        let stage = LiveAnchorStage;
        assert_eq!(stage.id(), StageId::LiveAnchor);
        assert_eq!(stage.name(), "live_anchor");
        assert_eq!(
            stage.dependencies(),
            &[StageId::LiveMixedTopologyValidation]
        );
        assert_eq!(stage.fanout(), StageFanout::Once);
    }
}
