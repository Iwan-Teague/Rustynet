#![allow(dead_code)]
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
use std::process::Command;

/// QH-83 F1: the enrollment-restart stage's pass witness. The
/// `live_enrollment_restart` binary writes this report on every success
/// path, so a Passed verdict is only proven when this artifact exists and
/// is non-empty.
pub(crate) const ENROLLMENT_RESTART_REPORT_RELATIVE: &str = "live_enrollment_restart_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(ENROLLMENT_RESTART_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

pub struct LiveEnrollmentRestartValidationStage;

impl OrchestrationStage for LiveEnrollmentRestartValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveEnrollmentRestartValidation
    }
    fn name(&self) -> &str {
        "live_enrollment_restart_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveKeyCustodyValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Enrollment-restart requires a dedicated `aux` enrollee node (the
        // admin enrolls it, restarts it, and proves the enrollment survives).
        // A minimal topology (e.g. exit + single client) has no aux node and
        // cannot exercise this — skip rather than fail-closed, matching the
        // two_hop incomplete-topology skip and the role-gated live-suite
        // stages. A missing `exit` (the enrolling admin) remains a hard fail.
        if !ctx.assignments.iter().any(|a| a.role.as_str() == "aux") {
            return StageOutcome::Skipped(
                "no node in this topology is assigned the aux role".to_owned(),
            );
        }
        let admin_params = match ssh_params_for_role(ctx, "exit") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let enrollee_params = match ssh_params_for_role(ctx, "aux") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let admin_node_id = node_id_for_alias(ctx, &admin_params.alias);
        let enrollee_node_id = node_id_for_alias(ctx, &enrollee_params.alias);
        let admin_target = format!("{}@{}", admin_params.user, admin_params.host);
        let enrollee_target = format!("{}@{}", enrollee_params.user, enrollee_params.host);
        let identity_file = admin_params.identity_file.to_string_lossy().into_owned();
        let report_path = ctx
            .report_dir
            .join(ENROLLMENT_RESTART_REPORT_RELATIVE)
            .to_string_lossy()
            .into_owned();
        let log_path = ctx
            .report_dir
            .join("live_enrollment_restart.log")
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
            "live_linux_enrollment_restart_test",
            "--",
        ])
        .arg("--ssh-identity-file")
        .arg(identity_file.as_str())
        .arg("--admin-host")
        .arg(&admin_target)
        .arg("--enrollee-host")
        .arg(&enrollee_target)
        .arg("--admin-node-id")
        .arg(&admin_node_id)
        .arg("--enrollee-node-id")
        .arg(&enrollee_node_id)
        .arg("--report-path")
        .arg(&report_path)
        .arg("--log-path")
        .arg(&log_path);

        // `.output()` not `.status()`: `.status()` discards the binary's
        // stdout/stderr, so a failure could only ever report an exit code. That
        // is what produced "exited with exit status: 1" beside a 0-byte log, with
        // the actual reason unrecoverable from the run's own evidence.
        match cmd.output() {
            Ok(output) if output.status.success() => {
                match verify_report_artifact(&ctx.report_dir) {
                    Ok(()) => StageOutcome::Passed,
                    Err(e) => StageOutcome::Failed(e),
                }
            }
            Ok(output) => StageOutcome::Failed(
                // QH-09: name the binary's own complete log (--log-path above)
                // so the clip disclosure cannot read as evidence loss when the
                // unclipped output sits beside it.
                crate::vm_lab::orchestrator::stage::format_stage_binary_failure_with_log(
                    "live_enrollment_restart_test",
                    output.status,
                    &output.stdout,
                    &output.stderr,
                    Some(&log_path),
                ),
            ),
            Err(e) => {
                StageOutcome::Failed(format!("failed to run live_enrollment_restart_test: {e}"))
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
    // QH-56: the inventory records each guest's real username - hardcoding
    // "debian" dialled rocky-utm-1 as debian@ and died with Permission denied.
    let user = super::resolve_ssh_user(params.user.as_deref(), adapter.platform());
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
    fn stage_id_is_live_enrollment_restart() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.id(),
            StageId::LiveEnrollmentRestartValidation
        );
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.name(),
            "live_enrollment_restart_validation"
        );
    }

    #[test]
    fn depends_on_live_key_custody() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.dependencies(),
            &[StageId::LiveKeyCustodyValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(
            LiveEnrollmentRestartValidationStage.fanout(),
            StageFanout::Once
        );
    }

    #[test]
    fn live_enrollment_restart_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::LiveEnrollmentRestartValidation.evidence(),
            StageEvidence::File(ENROLLMENT_RESTART_REPORT_RELATIVE),
            "the catalog must declare the enrollment-restart report as the pass witness"
        );
    }

    #[test]
    fn live_enrollment_restart_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "enrollment_restart_witness_{}_{}",
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
            result
                .unwrap_err()
                .contains(ENROLLMENT_RESTART_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
