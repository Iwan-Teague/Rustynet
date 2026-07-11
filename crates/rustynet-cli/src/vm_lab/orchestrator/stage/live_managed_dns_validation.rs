#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORT_FILENAME: &str = "live_managed_dns_report.json";

pub struct LiveManagedDnsValidationStage;

impl OrchestrationStage for LiveManagedDnsValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveManagedDnsValidation
    }
    fn name(&self) -> &str {
        "live_managed_dns_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveTwoHopValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let signer_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };

        let signer_node_id = match ctx.node_ids.get(&signer_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("signer (exit) node_id not found".into()),
        };
        let client_node_id = match ctx.node_ids.get(&client_params.alias) {
            Some(id) => id.clone(),
            None => return StageOutcome::Failed("client node_id not found".into()),
        };

        let report_path = ctx.report_dir.join(REPORT_FILENAME);
        let log_path = ctx.report_dir.join("live_managed_dns.log");

        let ssh_allow_cidrs = "0.0.0.0/0";

        let signer_target = format!("{}@{}", signer_params.user, signer_params.host);
        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path_str = report_path
            .to_str()
            .unwrap_or("live_managed_dns_report.json");
        let log_path_str = log_path.to_str().unwrap_or("live_managed_dns.log");
        let identity_file = signer_params.identity_file.to_str().unwrap_or("");

        let managed_peers: Vec<String> = managed_peer_args(ctx);

        let mut args: Vec<&str> = vec![
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "live_linux_managed_dns_test",
            "--",
            "--ssh-identity-file",
            identity_file,
            "--signer-host",
            &signer_target,
            "--signer-node-id",
            &signer_node_id,
            "--client-host",
            &client_target,
            "--client-node-id",
            &client_node_id,
            "--ssh-allow-cidrs",
            ssh_allow_cidrs,
            "--report-path",
            report_path_str,
            "--log-path",
            log_path_str,
        ];
        for peer in &managed_peers {
            args.extend(["--managed-peer", peer.as_str()]);
        }

        let result = std::process::Command::new("cargo").args(&args).output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    StageOutcome::Passed
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    StageOutcome::Failed(format!(
                        "live_managed_dns binary failed (exit {}): {}",
                        output.status,
                        stderr.trim()
                    ))
                }
            }
            Err(e) => {
                StageOutcome::Failed(format!("live_managed_dns binary invocation failed: {e}"))
            }
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

fn platform_str(platform: VmGuestPlatform) -> &'static str {
    match platform {
        VmGuestPlatform::Linux => "linux",
        VmGuestPlatform::Macos => "macos",
        VmGuestPlatform::Windows => "windows",
        _ => "linux",
    }
}

fn managed_peer_args(ctx: &OrchestrationContext) -> Vec<String> {
    let mut peers: Vec<String> = Vec::new();
    for assignment in &ctx.assignments {
        if assignment.role.as_str() == "exit" || assignment.role.as_str() == "client" {
            continue;
        }
        let alias = &assignment.alias;
        let node_id = match ctx.node_ids.get(alias.as_str()) {
            Some(id) => id,
            None => continue,
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(a) => a,
            None => continue,
        };
        let Some(params) = adapter.ssh_connection_params() else {
            continue;
        };
        let user = params.user.unwrap_or_else(|| {
            match adapter.platform() {
                VmGuestPlatform::Linux => "root",
                VmGuestPlatform::Macos => "admin",
                VmGuestPlatform::Windows => "administrator",
                _ => "root",
            }
            .to_owned()
        });
        let host = format!("{user}@{}", params.host);
        let platform = platform_str(adapter.platform());
        peers.push(format!("{node_id}|{host}|{platform}"));
    }
    peers
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_managed_dns() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.id(), StageId::LiveManagedDnsValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.name(), "live_managed_dns_validation");
    }

    #[test]
    fn depends_on_live_two_hop() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.dependencies(), &[StageId::LiveTwoHopValidation]);
    }

    #[test]
    fn fanout_is_once() {
        let stage = LiveManagedDnsValidationStage;
        assert_eq!(stage.fanout(), StageFanout::Once);
    }
}
