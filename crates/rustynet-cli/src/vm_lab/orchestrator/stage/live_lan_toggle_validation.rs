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

struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: PathBuf,
}

/// Resolve the SSH username for a lab guest: the inventory's value when it has
/// one, and only otherwise a per-platform default.
///
/// Both helpers in this file used to IGNORE the inventory entirely and hardcode
/// `"debian"` for every non-Windows guest. That is correct only on an all-Debian
/// topology, so the bug was invisible until a run put a Fedora node in one of
/// these three roles: the stage then dialled `debian@<fedora's address>` and
/// died with `Permission denied (publickey,...)` — one node's username against
/// another node's host. Measured on run `qh46-series-20260813z`, where
/// `live_lan_toggle_validation` was the only failing stage and the inventory
/// recorded `fedora-utm-1 -> ssh_user=fedora` correctly all along.
///
/// The fallback deliberately preserves the previous hardcoded values rather than
/// adopting the `root`/`admin`/`administrator` triple its sibling
/// `ssh_params_for_role` uses elsewhere. Changing an untested fallback is a
/// separate behavioural change from fixing "the real username was available and
/// thrown away", and bundling the two would make a regression here impossible to
/// attribute.
fn resolve_ssh_user(inventory_user: Option<&str>, platform: VmGuestPlatform) -> String {
    if let Some(user) = inventory_user.map(str::trim).filter(|u| !u.is_empty()) {
        return user.to_owned();
    }
    match platform {
        VmGuestPlatform::Windows => "admin",
        _ => "debian",
    }
    .to_owned()
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
