#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{
    OrchestrationStage, StageFanout, StageId, resolve_ssh_user,
};
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
        // The LAN-toggle scenario drives THREE nodes: exit, client, and a
        // Linux aux/extra/entry node it promotes to the blind_exit posture
        // (the test binary requires --blind-exit-host). A 2-node topology
        // cannot exercise it — skip rather than fail-closed, matching the
        // two_hop / enrollment-restart / soak / mixed-topology
        // incomplete-topology skips.
        let blind_exit_params = match find_blind_exit(ctx) {
            Ok(p) => p,
            Err(_) => {
                return StageOutcome::Skipped(
                    "no blind_exit node is available in this topology".to_owned(),
                );
            }
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

        // QH-57: fail before touching any node if the run context cannot
        // supply a usable management CIDR - the two_hop stage's precedent.
        // The binary re-validates (it is the choke point for every spawner);
        // this stage-side check just turns the error into a clean stage
        // failure with no cargo spawn.
        let ssh_allow_cidrs = match stage_ssh_allow_cidrs(&ctx.ssh_allow_cidrs) {
            Ok(value) => value,
            Err(reason) => return StageOutcome::Failed(reason),
        };

        let mut cmd = Command::new("cargo");
        cmd.args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--features",
            "vm-lab",
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
        .arg("--ssh-allow-cidrs")
        .arg(&ssh_allow_cidrs)
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        // `.output()` not `.status()`: `.status()` discards the binary's
        // stdout/stderr, so a failure could only ever report an exit code. That
        // is what produced "exited with exit status: 1" beside a 0-byte log, with
        // the actual reason unrecoverable from the run's own evidence.
        match cmd.output() {
            Ok(output) if output.status.success() => StageOutcome::Passed,
            Ok(output) => StageOutcome::Failed(
                crate::vm_lab::orchestrator::stage::format_stage_binary_failure(
                    "live_linux_lan_toggle_test",
                    output.status,
                    &output.stdout,
                    &output.stderr,
                ),
            ),
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_linux_lan_toggle_test: {e}"))
            }
        }
    }
}

/// QH-57: the run's management CIDRs, validated for the two lethal shapes
/// before any node is touched. Empty means the orchestrator could not derive
/// them; a default-route entry cannot scope the full-tunnel management
/// bypass. Kept as its own function so the rejection is unit-testable.
fn stage_ssh_allow_cidrs(ctx_value: &str) -> Result<String, String> {
    let value = ctx_value.trim();
    if value.is_empty() {
        return Err(
            "lan-toggle requires the run's management CIDRs (ctx.ssh_allow_cidrs \
             is empty); refusing to fall back to a stale default (QH-57)"
                .to_owned(),
        );
    }
    for entry in value.split(',') {
        let entry = entry.trim();
        if entry == "0.0.0.0/0" || entry == "::/0" {
            return Err(format!(
                "lan-toggle refuses management CIDR entry {entry}: a default \
                 route cannot scope the full-tunnel management bypass (QH-57)"
            ));
        }
    }
    Ok(value.to_owned())
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
    let user = resolve_ssh_user(params.user.as_deref(), adapter.platform());
    Ok(ResolvedParams {
        alias: assignment.alias.clone(),
        host: params.host.clone(),
        user,
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
                    user: resolve_ssh_user(params.user.as_deref(), adapter.platform()),
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
    #[test]
    fn stage_ssh_allow_cidrs_fails_closed_on_empty_and_default_route() {
        assert!(super::stage_ssh_allow_cidrs("").is_err());
        assert!(super::stage_ssh_allow_cidrs("  ").is_err());
        assert!(super::stage_ssh_allow_cidrs("0.0.0.0/0").is_err());
        assert!(super::stage_ssh_allow_cidrs("192.168.64.0/24,::/0").is_err());
        assert_eq!(
            super::stage_ssh_allow_cidrs(" 192.168.64.0/24 ").as_deref(),
            Ok("192.168.64.0/24")
        );
    }

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

    /// The regression this stage actually died on: a Fedora guest reached over
    /// SSH as `debian`. The inventory carries the right username; the resolver
    /// must use it rather than a per-platform guess.
    #[test]
    fn inventory_username_wins_over_the_platform_default() {
        assert_eq!(
            resolve_ssh_user(Some("fedora"), VmGuestPlatform::Linux),
            "fedora"
        );
        assert_eq!(
            resolve_ssh_user(Some("rocky"), VmGuestPlatform::Linux),
            "rocky"
        );
        assert_eq!(
            resolve_ssh_user(Some("ubuntu"), VmGuestPlatform::Linux),
            "ubuntu"
        );
        // A Windows guest with an explicit username is not overridden either.
        assert_eq!(
            resolve_ssh_user(Some("labadmin"), VmGuestPlatform::Windows),
            "labadmin"
        );
    }

    /// Absent or blank inventory data falls back to the previous hardcoded
    /// values, so this fix cannot regress a topology that relied on them.
    #[test]
    fn missing_or_blank_username_falls_back_to_the_platform_default() {
        assert_eq!(resolve_ssh_user(None, VmGuestPlatform::Linux), "debian");
        assert_eq!(resolve_ssh_user(None, VmGuestPlatform::Windows), "admin");
        // Whitespace-only is treated as absent, not dialled as an empty user.
        assert_eq!(
            resolve_ssh_user(Some("   "), VmGuestPlatform::Linux),
            "debian"
        );
        assert_eq!(
            resolve_ssh_user(Some(""), VmGuestPlatform::Windows),
            "admin"
        );
    }

    /// Surrounding whitespace in an inventory value must not reach the SSH
    /// target string, where it would produce `" fedora"@host`.
    #[test]
    fn inventory_username_is_trimmed() {
        assert_eq!(
            resolve_ssh_user(Some("  fedora \n"), VmGuestPlatform::Linux),
            "fedora"
        );
    }
}
