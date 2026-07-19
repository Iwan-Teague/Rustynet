#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

pub struct LiveMixedTopologyValidationStage;

impl OrchestrationStage for LiveMixedTopologyValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveMixedTopologyValidation
    }
    fn name(&self) -> &str {
        "live_mixed_topology_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveLanToggleValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Mixed-topology needs one node of EACH desktop platform (Linux +
        // macOS + Windows). A single-platform topology cannot exercise it —
        // skip rather than fail-closed, matching the two_hop /
        // enrollment-restart / extended-soak incomplete-topology skips. With
        // all three platforms assigned, any resolution error below remains a
        // hard fail.
        let all_platforms_assigned = [
            VmGuestPlatform::Linux,
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
        ]
        .iter()
        .all(|platform| {
            ctx.assignments.iter().any(|assignment| {
                ctx.adapters
                    .get(assignment.alias.as_str())
                    .is_some_and(|adapter| adapter.platform() == *platform)
            })
        });
        if !all_platforms_assigned {
            return StageOutcome::Skipped;
        }
        let linux = match find_platform_node(ctx, VmGuestPlatform::Linux) {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let macos = match find_platform_node(ctx, VmGuestPlatform::Macos) {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let windows = match find_platform_node(ctx, VmGuestPlatform::Windows) {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let identity_file = linux.identity_file.to_string_lossy().into_owned();
        let known_hosts = ctx
            .report_dir
            .join("known_hosts")
            .to_string_lossy()
            .into_owned();
        let report_path = ctx
            .report_dir
            .join("live_mixed_topology_report.json")
            .to_string_lossy()
            .into_owned();
        let log_path = ctx
            .report_dir
            .join("live_mixed_topology.log")
            .to_string_lossy()
            .into_owned();

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "live_linux_mixed_topology_test",
            "--",
        ])
        .arg("--ssh-identity-file")
        .arg(identity_file)
        .arg("--known-hosts")
        .arg(&known_hosts)
        .arg("--linux-host")
        .arg(&linux.target)
        .arg("--linux-node-id")
        .arg(&linux.node_id)
        .arg("--macos-host")
        .arg(&macos.target)
        .arg("--macos-node-id")
        .arg(&macos.node_id)
        .arg("--windows-host")
        .arg(&windows.target)
        .arg("--windows-node-id")
        .arg(&windows.node_id)
        .arg("--handshake-freshness-secs")
        .arg("300")
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        match cmd.status() {
            Ok(status) if status.success() => StageOutcome::Passed,
            Ok(status) => StageOutcome::Failed(format!(
                "live_linux_mixed_topology_test exited with {status}"
            )),
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_linux_mixed_topology_test: {e}"))
            }
        }
    }
}

struct PlatformNode {
    target: String,
    node_id: String,
    identity_file: PathBuf,
}

fn find_platform_node(
    ctx: &OrchestrationContext,
    platform: VmGuestPlatform,
) -> Result<PlatformNode, String> {
    for assignment in &ctx.assignments {
        let adapter = ctx
            .adapters
            .get(assignment.alias.as_str())
            .ok_or_else(|| format!("no adapter for {}", assignment.alias))?;
        if adapter.platform() == platform {
            let params = adapter
                .ssh_connection_params()
                .ok_or_else(|| format!("no SSH params for {}", assignment.alias))?;
            let user = match platform {
                VmGuestPlatform::Windows => "admin",
                _ => "debian",
            };
            let target = format!("{user}@{}", params.host);
            let node_id = ctx
                .node_ids
                .get(&assignment.alias)
                .cloned()
                .unwrap_or_else(|| assignment.alias.clone());
            return Ok(PlatformNode {
                target,
                node_id,
                identity_file: params.identity_file.clone(),
            });
        }
    }
    Err(format!("no {platform:?} node found in assignments",))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_mixed_topology() {
        assert_eq!(
            LiveMixedTopologyValidationStage.id(),
            StageId::LiveMixedTopologyValidation
        );
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        assert_eq!(
            LiveMixedTopologyValidationStage.name(),
            "live_mixed_topology_validation"
        );
    }

    #[test]
    fn depends_on_live_lan_toggle() {
        assert_eq!(
            LiveMixedTopologyValidationStage.dependencies(),
            &[StageId::LiveLanToggleValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveMixedTopologyValidationStage.fanout(), StageFanout::Once);
    }
}
