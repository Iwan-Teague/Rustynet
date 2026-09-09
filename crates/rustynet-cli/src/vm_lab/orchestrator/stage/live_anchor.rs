#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

/// QH-83 pass witness for `LiveAnchor`: the `live_linux_anchor_test` binary
/// writes this JSON report on EVERY success path (both its dry-run and its
/// real run write the report immediately before returning `Ok`), and logger
/// failures propagate as a non-zero exit. The runner deletes a declared
/// File witness at stage start, so a `Passed` verdict is only honest when
/// this artifact exists and is non-empty from THIS execute — verify it
/// before declaring victory; absence is fatal, never best-effort.
pub(crate) const ANCHOR_REPORT_RELATIVE: &str = "live_linux_anchor_report.json";

/// Fail-closed artifact check for the declared pass witness. A stage pass
/// whose witness cannot be read back must fail the stage instead of
/// standing as an unwitnessed green.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(ANCHOR_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

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
            Err(_) => {
                return StageOutcome::Skipped(
                    "no second anchor/entry node is available in this topology".to_owned(),
                );
            }
        };
        let leaf_client = match ssh_params_for_role(ctx, "aux") {
            Ok(params) => params,
            Err(_) => {
                return StageOutcome::Skipped(
                    "no node in this topology is assigned the aux role the anchor leaf needs"
                        .to_owned(),
                );
            }
        };
        let enrollee = match ssh_params_for_role(ctx, "extra") {
            Ok(params) => params,
            Err(_) => {
                return StageOutcome::Skipped(
                    "no node in this topology is assigned the extra role the anchor enrollee needs"
                        .to_owned(),
                );
            }
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

        let report_path = ctx.report_dir.join(ANCHOR_REPORT_RELATIVE);
        let log_path = ctx.report_dir.join("live_linux_anchor.log");
        let owner_approver_id = format!("{anchor_node_id}-owner");

        // I3 follow-up (STAGES review): route the `--platform` labels through
        // the exhaustive desktop tag helper instead of a `_ => "linux"` arm.
        let anchor_platform_tag =
            match super::desktop_platform_tag(anchor.platform, "live_anchor anchor") {
                Ok(tag) => tag,
                Err(err) => return StageOutcome::Failed(err),
            };
        let leaf_platform_tag =
            match super::desktop_platform_tag(leaf_client.platform, "live_anchor leaf client") {
                Ok(tag) => tag,
                Err(err) => return StageOutcome::Failed(err),
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
            "live_linux_anchor_test",
            "--",
            "--platform",
            anchor_platform_tag,
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
        .arg(leaf_platform_tag)
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
            Ok(output) if output.status.success() => {
                match verify_report_artifact(&ctx.report_dir) {
                    Ok(()) => StageOutcome::Passed,
                    Err(e) => StageOutcome::Failed(e),
                }
            }
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
    use crate::vm_lab::orchestrator::stage::StageEvidence;

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

    #[test]
    fn live_anchor_declared_witness_matches_its_artifact_path() {
        assert_eq!(
            StageId::LiveAnchor.evidence(),
            StageEvidence::File(ANCHOR_REPORT_RELATIVE)
        );
    }

    #[test]
    fn live_anchor_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "live_anchor_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let err = verify_report_artifact(&dir).expect_err("missing artifact must fail");
        assert!(err.contains(ANCHOR_REPORT_RELATIVE));
        std::fs::remove_dir_all(&dir).ok();
    }
}
