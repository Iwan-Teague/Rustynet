#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

/// QH-83 F1: the key-custody stage's pass witness. The `live_key_custody`
/// binary writes this report on every success path, so a Passed verdict is
/// only proven when this artifact exists and is non-empty.
pub(crate) const KEY_CUSTODY_REPORT_RELATIVE: &str = "live_key_custody_report.json";

/// QH-83 F1: fail a success exit whose pass witness artifact is missing or
/// empty instead of declaring Passed without evidence on disk.
fn verify_report_artifact(report_dir: &std::path::Path) -> Result<(), String> {
    let path = report_dir.join(KEY_CUSTODY_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!("pass witness artifact {path:?} is empty")),
        Err(err) => Err(format!("pass witness artifact {path:?} missing: {err}")),
    }
}

/// Named reported-skip bookkeeping (active_exit precedent): a platform the
/// live custody probe honestly cannot run against is recorded here, never
/// absorbed into a silent pass.
const REPORTED_SKIP_FILENAME: &str = "live_key_custody.reported_skips.json";

/// Pure skip-note serializer (no I/O) so a unit test pins the content.
fn custody_skip_json_bytes(alias: &str, platform: VmGuestPlatform) -> Vec<u8> {
    let body = serde_json::json!({
        "stage": "live_key_custody_validation",
        "reported_skipped_key_custody": [{
            "alias": alias,
            "platform": format!("{platform:?}"),
        }],
        "reason": "the live custody probe asserts POSIX file-mode enforcement (0600 key \
                   file in a 0700 dir) plus a service-manager restart choreography; Windows \
                   key custody is in-memory/DPAPI with no POSIX key file, so there is no \
                   honest probe to run there — reported-skipped here, never a silent pass",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

/// Write the reported-skip note. Best-effort: a write failure does not change
/// the stage outcome (the Skipped reason still names the node).
fn write_reported_skip_note(ctx: &OrchestrationContext, alias: &str, platform: VmGuestPlatform) {
    let path = ctx.report_dir.join(REPORTED_SKIP_FILENAME);
    let _ = std::fs::write(&path, custody_skip_json_bytes(alias, platform));
}

/// Live key-custody enforcement proof — manipulates key file permissions on a
/// running daemon (client) and validates rejection + recovery through the
/// hardened `live_linux_key_custody_test` binary.
pub struct LiveKeyCustodyValidationStage;

impl OrchestrationStage for LiveKeyCustodyValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveKeyCustodyValidation
    }
    fn name(&self) -> &str {
        "live_key_custody_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::LiveSecretsNotInLogsValidation]
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
            "key custody validation",
        ) {
            return skip;
        }
        let client_params = match ssh_params_for_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        // Windows has no POSIX key file to probe (in-memory/DPAPI custody) and
        // no service-manager restart choreography the probe could drive: a
        // named reported skip, never a silent pass. Linux and macOS run the
        // probe against their own deployed custody layout.
        if client_params.platform == VmGuestPlatform::Windows {
            write_reported_skip_note(ctx, &client_params.alias, client_params.platform);
            return StageOutcome::Skipped(format!(
                "live key custody probe has no honest Windows equivalent (in-memory/DPAPI \
                 custody, no POSIX mode enforcement) — reported-skipped node {} \
                 (platform Windows), never a silent pass",
                client_params.alias
            ));
        }

        let client_target = format!("{}@{}", client_params.user, client_params.host);

        let report_path = ctx.report_dir.join(KEY_CUSTODY_REPORT_RELATIVE);
        let log_path = ctx.report_dir.join("live_key_custody.log");
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
        // The probe must drive the CLIENT node's own service manager and
        // custody layout: thread the node's platform tag (Linux systemd /
        // macOS launchd).
        let client_platform_tag = match crate::vm_lab::orchestrator::stage::desktop_platform_tag(
            client_params.platform,
            "key custody validator target",
        ) {
            Ok(tag) => tag,
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
                "live_linux_key_custody_test",
                "--",
                "--ssh-identity-file",
                identity_file,
                "--target-host",
                &client_target,
                "--platform",
                client_platform_tag,
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
                            "live_key_custody binary",
                            output.status,
                            &output.stdout,
                            &output.stderr,
                            Some(log_path_str),
                        ),
                    )
                }
            }
            Err(e) => {
                StageOutcome::Failed(format!("live_key_custody binary invocation failed: {e}"))
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
    platform: VmGuestPlatform,
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
        platform: adapter.platform(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_id_is_live_key_custody() {
        let stage = LiveKeyCustodyValidationStage;
        assert_eq!(stage.id(), StageId::LiveKeyCustodyValidation);
    }

    #[test]
    fn stage_name_is_lowercase_kebab() {
        let stage = LiveKeyCustodyValidationStage;
        assert_eq!(stage.name(), "live_key_custody_validation");
    }

    #[test]
    fn depends_on_live_secrets_not_in_logs() {
        assert_eq!(
            LiveKeyCustodyValidationStage.dependencies(),
            &[StageId::LiveSecretsNotInLogsValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveKeyCustodyValidationStage.fanout(), StageFanout::Once);
    }

    #[test]
    fn live_key_custody_declared_witness_matches_its_artifact_path() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;

        assert_eq!(
            StageId::LiveKeyCustodyValidation.evidence(),
            StageEvidence::File(KEY_CUSTODY_REPORT_RELATIVE),
            "the catalog must declare the key-custody report as the pass witness"
        );
    }

    #[test]
    fn live_key_custody_pass_without_report_artifact_is_fatal() {
        let dir = std::env::temp_dir().join(format!(
            "key_custody_witness_{}_{}",
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
            result.unwrap_err().contains(KEY_CUSTODY_REPORT_RELATIVE),
            "the failure must name the missing witness artifact"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn windows_skip_note_names_the_node_platform_and_the_honest_gap() {
        let bytes = custody_skip_json_bytes("win-1", VmGuestPlatform::Windows);
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("valid json");
        assert_eq!(parsed["stage"], "live_key_custody_validation");
        let entry = &parsed["reported_skipped_key_custody"][0];
        assert_eq!(entry["alias"], "win-1");
        assert_eq!(entry["platform"], "Windows");
        let reason = parsed["reason"].as_str().expect("reason string");
        assert!(reason.contains("in-memory/DPAPI"), "{reason}");
        assert!(reason.contains("never a silent pass"), "{reason}");
    }

    #[test]
    fn reported_skip_note_file_name_is_stable() {
        assert_eq!(
            REPORTED_SKIP_FILENAME,
            "live_key_custody.reported_skips.json"
        );
    }
}
