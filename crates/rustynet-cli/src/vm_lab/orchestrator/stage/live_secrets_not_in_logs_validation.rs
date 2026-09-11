#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// QH-83 F1: the secrets-not-in-logs stage's pass witness. The
/// `live_secrets_not_in_logs` binary writes this report on every success
/// path, so a Passed verdict is only proven when this artifact exists and
/// is non-empty.
pub(crate) const SECRETS_REPORT_RELATIVE: &str = "live_secrets_not_in_logs_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(SECRETS_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

pub struct LiveSecretsNotInLogsValidationStage;

impl OrchestrationStage for LiveSecretsNotInLogsValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveSecretsNotInLogsValidation
    }
    fn name(&self) -> &str {
        "live_secrets_not_in_logs_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveRebootRecoveryValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if let Some(skip) = crate::vm_lab::orchestrator::stage::exit_only_topology_skip(
            ctx,
            "secrets-not-in-logs validation",
        ) {
            return skip;
        }
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };

        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path = ctx.report_dir.join(SECRETS_REPORT_RELATIVE);
        let log_path = ctx.report_dir.join("live_secrets_not_in_logs.log");
        let report_path_str = match crate::vm_lab::orchestrator::stage::require_utf8_path(
            &report_path,
            "report path",
        ) {
            Ok(value) => value,
            Err(err) => return StageOutcome::Failed(err),
        };
        let log_path_str =
            match crate::vm_lab::orchestrator::stage::require_utf8_path(&log_path, "log path") {
                Ok(value) => value,
                Err(err) => return StageOutcome::Failed(err),
            };
        let identity_file = match crate::vm_lab::orchestrator::stage::require_utf8_path(
            &client_params.identity_file,
            "identity file",
        ) {
            Ok(value) => value,
            Err(err) => return StageOutcome::Failed(err),
        };

        let result = std::process::Command::new("cargo")
            .args([
                "run",
                "--quiet",
                "-p",
                "rustynet-cli",
                "--features",
                "vm-lab",
                "--bin",
                "live_linux_secrets_not_in_logs_test",
                "--",
                "--ssh-identity-file",
                identity_file,
                "--target-host",
                &client_target,
                "--report-path",
                report_path_str,
                "--log-path",
                log_path_str,
            ])
            .output();

        match result {
            Ok(output) => {
                if output.status.success() {
                    match verify_report_artifact(&ctx.report_dir) {
                        Ok(()) => StageOutcome::Passed,
                        Err(e) => StageOutcome::Failed(e),
                    }
                } else {
                    StageOutcome::Failed(
                        // QH-09: name the binary's own complete log (--log-path
                        // above) so the clip disclosure cannot read as evidence
                        // loss when the unclipped output sits beside it.
                        crate::vm_lab::orchestrator::stage::format_stage_binary_failure_with_log(
                            "live_secrets_not_in_logs binary",
                            output.status,
                            &output.stdout,
                            &output.stderr,
                            Some(log_path_str),
                        ),
                    )
                }
            }
            Err(e) => StageOutcome::Failed(format!(
                "live_secrets_not_in_logs binary invocation failed: {e}"
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
    fn stage_id_is_live_secrets_not_in_logs() {
        let stage = LiveSecretsNotInLogsValidationStage;
        assert_eq!(stage.id(), StageId::LiveSecretsNotInLogsValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveSecretsNotInLogsValidationStage;
        assert_eq!(stage.name(), "live_secrets_not_in_logs_validation");
    }

    #[test]
    fn depends_on_live_reboot_recovery() {
        assert_eq!(
            LiveSecretsNotInLogsValidationStage.dependencies(),
            &[StageId::LiveRebootRecoveryValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(
            LiveSecretsNotInLogsValidationStage.fanout(),
            StageFanout::Once
        );
    }

    #[test]
    fn live_secrets_not_in_logs_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::LiveSecretsNotInLogsValidation.evidence(),
            StageEvidence::File(SECRETS_REPORT_RELATIVE),
            "the catalog must declare the secrets-not-in-logs report as the pass witness"
        );
    }

    #[test]
    fn live_secrets_not_in_logs_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "secrets_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap_or_default();
        let result = verify_report_artifact(&dir);
        assert!(result.is_err(), "an empty report dir must not pass");
        assert!(
            result.unwrap_err().contains(SECRETS_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
