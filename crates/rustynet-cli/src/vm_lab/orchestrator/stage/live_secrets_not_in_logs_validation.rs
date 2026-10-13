#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
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

/// AQ-68 lab/production alignment: the enrollment secret is seeded for
/// admin-daemon nodes only (the production `ops install-systemd` branch), so
/// this stage runs its enrollment-activity leg against THAT node — the old
/// client-role target carried no secret and the stage passed vacuously — and
/// additionally witnesses that a client-daemon node carries NONE (the
/// fail-closed boundary this alignment exists to preserve).
///
/// Same literal as `ENROLLMENT_SECRET_PATH` in the production installer and
/// the negative-control enrollment replay.
///
/// Per-OS: the deployed daemon's seeded secret path differs by service
/// manager — launchd passes `${STATE_ROOT}/keys/enrollment.secret` with
/// `STATE_ROOT=/usr/local/var/rustynet`
/// (scripts/bootstrap/macos/Install-RustyNetMacosService.sh +
/// Bootstrap-RustyNetMacos.sh). The Linux literal is byte-identical to the
/// pre-port const. Everything else fails closed: probing a guessed path
/// would forge either custody witness.
fn enrollment_secret_path_for(platform: VmGuestPlatform) -> Result<&'static str, String> {
    match platform {
        VmGuestPlatform::Linux => Ok("/var/lib/rustynet/keys/enrollment.secret"),
        VmGuestPlatform::Macos => Ok("/usr/local/var/rustynet/keys/enrollment.secret"),
        other => Err(format!(
            "secrets-not-in-logs custody witness has no enrollment-secret state path for \
             platform {other:?} (fail closed)"
        )),
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
        // The enrollment-activity leg targets the node whose DAEMON runs the
        // admin role (Linux/Windows Exit|Admin|Anchor; macOS Admin|Anchor) —
        // the only node class the production installer seeds the secret on.
        // Fail closed, with a named reason, when no such node is assigned.
        let admin_params = match ssh_params_for_daemon_role(ctx, "admin") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };
        let client_params = match ssh_params_for_daemon_role(ctx, "client") {
            Ok(p) => p,
            Err(e) => return StageOutcome::Failed(e),
        };

        // Custody-posture witness (AQ-68 alignment): the admin target must
        // carry the secret (seeded by install-systemd for its role), and a
        // client-daemon node must NOT (the bootstrap no longer seeds it
        // unconditionally — a non-admin secret is a production-parity
        // violation, never absorbed). Each node is probed at the path its own
        // deployed daemon was seeded with (Linux /var/lib, macOS /usr/local/var).
        for (params, want_present) in [(&admin_params, true), (&client_params, false)] {
            let secret_path = match enrollment_secret_path_for(params.platform) {
                Ok(path) => path,
                Err(e) => return StageOutcome::Failed(e),
            };
            match remote_probe(
                ctx,
                &params.alias,
                if want_present { "test -s" } else { "test -e" },
                secret_path,
            ) {
                Ok(code) if (code == 0) == want_present => {}
                Ok(code) => {
                    return StageOutcome::Failed(enrollment_secret_witness_error(
                        &params.alias,
                        want_present,
                        code,
                        secret_path,
                    ));
                }
                Err(err) => return StageOutcome::Failed(err),
            }
        }

        let admin_target = format!("{}@{}", admin_params.user, admin_params.host);

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
            &admin_params.identity_file,
            "identity file",
        ) {
            Ok(value) => value,
            Err(err) => return StageOutcome::Failed(err),
        };
        // The binary must scan the ADMIN node's own log sources: thread the
        // node's platform tag so it collects launchd/unified-log evidence on a
        // macOS admin instead of a journald argv that cannot exist there.
        let admin_platform_tag = match crate::vm_lab::orchestrator::stage::desktop_platform_tag(
            admin_params.platform,
            "secrets-not-in-logs validator target",
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
                "live_linux_secrets_not_in_logs_test",
                "--",
                "--ssh-identity-file",
                identity_file,
                "--target-host",
                &admin_target,
                "--platform",
                admin_platform_tag,
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
    platform: VmGuestPlatform,
}

/// Pure daemon-role selection: the first assignment whose role maps to
/// `want` on that node's platform (role.rs
/// `daemon_node_role_for_platform` — Linux/Windows Exit|Admin|Anchor and
/// macOS Admin|Anchor are admin; BlindExit is blind_exit; the rest are
/// client). A macOS Exit is deliberately NOT an admin-daemon node (per-OS
/// blind_exit divergence). `None` ⇒ caller fails closed with the named gap.
fn select_daemon_role_alias(
    assignments: &[NodeRoleAssignment],
    want: &str,
    platform_of: &dyn Fn(&str) -> Option<VmGuestPlatform>,
) -> Option<String> {
    assignments
        .iter()
        .find(|a| {
            platform_of(&a.alias)
                .and_then(|platform| a.role.daemon_node_role_for_platform(&platform).ok())
                == Some(want)
        })
        .map(|a| a.alias.clone())
}

fn daemon_role_selection_error(want: &str) -> String {
    format!(
        "no node whose DAEMON role is '{want}' in the assignments; the secrets-not-in-logs \
         stage must exercise enrollment on an admin-daemon node (the only node class the \
         production installer seeds the enrollment secret on) and witness absence on a \
         client-daemon node — fail closed on the topology gap"
    )
}

fn ssh_params_for_daemon_role(
    ctx: &OrchestrationContext,
    want: &str,
) -> Result<ResolvedParams, String> {
    let platform_of = |alias: &str| ctx.adapters.get(alias).map(|a| a.platform());
    let alias = select_daemon_role_alias(&ctx.assignments, want, &platform_of)
        .ok_or_else(|| daemon_role_selection_error(want))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (daemon role '{want}')"))?;
    let params = adapter.ssh_connection_params().ok_or_else(|| {
        format!("{alias} (daemon role '{want}'): no SSH connection params available")
    })?;
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

/// One root remote probe through the node's adapter shell. Returns the exit
/// code; transport failures are named errors.
fn remote_probe(
    ctx: &OrchestrationContext,
    alias: &str,
    test_op: &str,
    path: &str,
) -> Result<i32, String> {
    let adapter = ctx
        .adapters
        .get(alias)
        .ok_or_else(|| format!("no adapter for {alias} (secrets-not-in-logs witness)"))?;
    let shell = adapter
        .shell_host()
        .map_err(|err| format!("{alias}: no remote shell host for the custody witness: {err}"))?;
    let mut argv: Vec<&str> = test_op.split(' ').collect();
    argv.push(path);
    let status = shell
        .run_argv(&argv, &[], &[])
        .map_err(|err| format!("{alias}: transport failure running {test_op} {path}: {err}"))?;
    Ok(status.code)
}

/// The named failure for a violated custody witness: `want_present` is the
/// ADMIN leg (secret must exist, seeded by install-systemd for the admin
/// role); `!want_present` is the CLIENT leg (secret must be absent so the
/// daemon's enrollment IPC stays fail-closed). `path` is the exact path the
/// probe ran against — the witness names what it actually checked, which
/// differs per node platform.
fn enrollment_secret_witness_error(
    alias: &str,
    want_present: bool,
    exit: i32,
    path: &str,
) -> String {
    if want_present {
        format!(
            "admin-daemon node {alias} has NO enrollment secret at {path} \
             (probe exit {exit}); `ops install-systemd` seeds admin-role nodes and the e2e \
             bootstrap no longer seeds unconditionally (AQ-68 lab/production alignment) — \
             the enrollment code path cannot be exercised here (fail closed)"
        )
    } else {
        format!(
            "non-admin node {alias} CARRIES an enrollment secret at {path}; \
             non-admin nodes must stay secretless so the daemon's enrollment IPC stays \
             fail-closed (production-parity custody witness, fail closed)"
        )
    }
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

    fn assignment(alias: &str, role: NodeRole) -> NodeRoleAssignment {
        NodeRoleAssignment {
            alias: alias.to_owned(),
            role,
        }
    }

    #[test]
    fn selection_targets_daemon_roles_not_role_labels() {
        let platform = |alias: &str| match alias {
            "mac-x" => Some(VmGuestPlatform::Macos),
            _ => Some(VmGuestPlatform::Linux),
        };
        let full = vec![
            assignment("client-1", NodeRole::Client),
            assignment("relay-1", NodeRole::Relay),
            assignment("exit-1", NodeRole::Exit),
        ];
        // The mint leg runs on the ADMIN-daemon node (Exit on Linux); a relay
        // or client role label must never win it.
        assert_eq!(
            select_daemon_role_alias(&full, "admin", &platform).as_deref(),
            Some("exit-1")
        );
        // The absence witness runs on a CLIENT-daemon node (relay maps to
        // client too — any client-daemon node qualifies).
        assert_eq!(
            select_daemon_role_alias(&full, "client", &platform).as_deref(),
            Some("client-1")
        );
    }

    #[test]
    fn macos_exit_is_a_blind_exit_daemon_never_an_admin_node() {
        // Per-OS divergence (role.rs): a macOS Exit runs the blind_exit
        // daemon posture, so it must NOT host the enrollment-mint leg; the
        // macOS Anchor (admin daemon role) must.
        let platform = |_alias: &str| Some(VmGuestPlatform::Macos);
        let roles = vec![
            assignment("mac-exit", NodeRole::Exit),
            assignment("mac-anchor", NodeRole::Anchor),
        ];
        assert_eq!(
            select_daemon_role_alias(&roles, "admin", &platform).as_deref(),
            Some("mac-anchor")
        );
        assert_eq!(
            select_daemon_role_alias(&roles, "blind_exit", &platform).as_deref(),
            Some("mac-exit")
        );
    }

    #[test]
    fn missing_daemon_roles_are_named_failures_not_absorbed() {
        let platform = |_: &str| Some(VmGuestPlatform::Linux);
        let clients_only = vec![
            assignment("client-1", NodeRole::Client),
            assignment("aux-1", NodeRole::Aux),
        ];
        assert_eq!(
            select_daemon_role_alias(&clients_only, "admin", &platform),
            None,
            "no admin-daemon node ⇒ the caller must fail closed"
        );
        let err = daemon_role_selection_error("admin");
        assert!(err.contains("DAEMON role is 'admin'"), "{err}");
        assert!(err.contains("fail closed"), "{err}");
    }

    #[test]
    fn custody_witness_errors_name_the_violated_boundary() {
        let linux_path = enrollment_secret_path_for(VmGuestPlatform::Linux).expect("linux");
        let admin_absent = enrollment_secret_witness_error("exit-1", true, 1, linux_path);
        assert!(
            admin_absent.contains("admin-daemon node exit-1 has NO enrollment secret"),
            "{admin_absent}"
        );
        assert!(admin_absent.contains("fail closed"), "{admin_absent}");
        assert!(admin_absent.contains(linux_path), "{admin_absent}");
        let client_present = enrollment_secret_witness_error("client-1", false, 0, linux_path);
        assert!(
            client_present.contains("non-admin node client-1 CARRIES an enrollment secret"),
            "{client_present}"
        );
        assert!(
            client_present.contains("production-parity custody witness"),
            "{client_present}"
        );
    }

    #[test]
    fn enrollment_secret_paths_match_each_deployed_daemon_seeded_location() {
        assert_eq!(
            enrollment_secret_path_for(VmGuestPlatform::Linux).expect("linux"),
            "/var/lib/rustynet/keys/enrollment.secret",
            "the Linux path is byte-identical to the pre-port const"
        );
        assert_eq!(
            enrollment_secret_path_for(VmGuestPlatform::Macos).expect("macos"),
            "/usr/local/var/rustynet/keys/enrollment.secret",
            "the launchd plist passes ${{STATE_ROOT}}/keys/enrollment.secret with \
             STATE_ROOT=/usr/local/var/rustynet"
        );
    }

    #[test]
    fn custody_witness_fails_closed_on_platforms_without_a_state_path() {
        for platform in [
            VmGuestPlatform::Windows,
            VmGuestPlatform::Ios,
            VmGuestPlatform::Android,
        ] {
            let err = enrollment_secret_path_for(platform).expect_err("fail closed");
            assert!(err.contains("fail closed"), "{err}");
            assert!(err.contains("enrollment-secret state path"), "{err}");
        }
    }
}
