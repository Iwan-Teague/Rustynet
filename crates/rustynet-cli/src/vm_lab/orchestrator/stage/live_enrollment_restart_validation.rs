#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::remote_shell::RemoteShellHost;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::blind_exit::{
    DAEMON_ROLE_POLL_MAX_ATTEMPTS, DAEMON_ROLE_POLL_RETRY_DELAY, parse_header_node_role,
    run_daemon_status_sudoed,
};
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
        // Precondition (katana-xnet-113): enrollment consume is admin-only on
        // the daemon (`NodeRole::allows_command` gates `EnrollmentConsume`),
        // so an earlier stage that demoted this node and never restored it
        // must surface here as a named refusal — BEFORE the test binary runs
        // and dies with an opaque "command denied: current node role does not
        // permit this operation".
        if let Err(e) = enrollment_admin_role_precondition(ctx, &admin_params) {
            return StageOutcome::Failed(e);
        }
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

/// Precondition glue: resolve the admin node's adapter + shell (the same
/// seam the stage unit tests drive with the [`MockShellHost`] double) and
/// assert its daemon reports `node_role=admin` before the test binary is
/// dispatched.
fn enrollment_admin_role_precondition(
    ctx: &OrchestrationContext,
    admin_params: &ResolvedParams,
) -> Result<(), String> {
    let adapter = ctx
        .adapters
        .get(admin_params.alias.as_str())
        .ok_or_else(|| {
            format!(
                "{}: no adapter for the enrollment admin role precondition",
                admin_params.alias
            )
        })?;
    let platform = adapter.platform();
    let shell = adapter.shell_host().map_err(|e| {
        format!(
            "{}: shell host unavailable for the enrollment admin role precondition: {e}",
            admin_params.alias
        )
    })?;
    assert_admin_daemon_role(&*shell, platform, &admin_params.alias)
}

/// The daemon role the enrollment admin must report for this precondition
/// to apply, by platform (D2a). Linux maps the lab `Exit` to the daemon's
/// `admin` role; macOS maps it to the `blind_exit` posture (the
/// `daemon_node_role_for_platform` DECREE in `role.rs`), where "expected
/// admin" would be factually wrong — and the poison this precondition
/// guards (the Linux-only `exit_demotion_residue` stage leaving the node
/// demoted) cannot occur there anyway. So the precondition applies on Linux
/// ONLY and is skipped, with a named log line, on every other platform.
fn expected_admin_daemon_role(platform: VmGuestPlatform) -> Option<&'static str> {
    match platform {
        VmGuestPlatform::Linux => Some("admin"),
        VmGuestPlatform::Macos
        | VmGuestPlatform::Windows
        | VmGuestPlatform::Ios
        | VmGuestPlatform::Android => None,
    }
}

/// Query the admin node's daemon status through the SAME sudo-wrapped seam
/// the exit-demotion restore uses (`sudo -n env RUSTYNET_DAEMON_SOCKET=…
/// rustynet status` — the daemon's socket is root-owned 0600 with a 0700
/// parent on Linux guests, so an unsudoed query hits EACCES on a healthy
/// node; D1) and fail closed unless it reports the expected primary role.
///
/// Transient failures — transport errors, non-zero exits, bodies without a
/// readable role — are retried within the same bounded window as the
/// restore poll (4 × 3 s; D2b), because the stages just before this one
/// restart daemons. A DEFINITIVE demoted role is never retried (it cannot
/// change under us) and fails immediately with the named refusal. The final
/// failure names the last error.
fn assert_admin_daemon_role(
    shell: &dyn RemoteShellHost,
    platform: VmGuestPlatform,
    alias: &str,
) -> Result<(), String> {
    let Some(expected_role) = expected_admin_daemon_role(platform) else {
        eprintln!(
            "live_enrollment_restart_validation: admin daemon role precondition \
             not applied on {platform:?}: the lab exit runs the blind_exit \
             daemon posture there and the demotion poison it guards is \
             Linux-only"
        );
        return Ok(());
    };
    let mut last_error = String::from("no status attempt was made");
    for attempt in 1..=DAEMON_ROLE_POLL_MAX_ATTEMPTS {
        match run_daemon_status_sudoed(shell, platform) {
            Ok(out) if out.code == 0 => {
                let status = String::from_utf8_lossy(&out.stdout);
                match parse_header_node_role(&status) {
                    Some(role) if role == expected_role => return Ok(()),
                    Some(role) => {
                        return Err(format!(
                            "admin node {alias} daemon role is {role}, expected \
                             {expected_role}: an earlier stage left it demoted"
                        ));
                    }
                    None => {
                        last_error = format!(
                            "admin node {alias} daemon status carried no node_role \
                             field: {}",
                            status.trim()
                        );
                    }
                }
            }
            Ok(out) => {
                last_error = format!(
                    "admin node {alias} daemon status query exited non-zero: {}",
                    String::from_utf8_lossy(&out.stdout).trim()
                );
            }
            Err(err) => {
                last_error = format!("admin node {alias} daemon status query failed: {err}");
            }
        }
        if attempt >= DAEMON_ROLE_POLL_MAX_ATTEMPTS {
            break;
        }
        std::thread::sleep(DAEMON_ROLE_POLL_RETRY_DELAY);
    }
    Err(format!(
        "{last_error} (after {DAEMON_ROLE_POLL_MAX_ATTEMPTS} attempts)"
    ))
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
    use crate::vm_lab::orchestrator::adapter::node_adapter::{NodeAdapter, SshConnectionParams};
    use crate::vm_lab::orchestrator::error::{
        AdapterError, BundleKind, GossipIdentity, InstallReport, MembershipOwnerKey,
        MembershipSnapshot, NodeId, NodeMembershipPeer, TrafficTestResult, TunnelsList,
        ValidatorReport,
    };
    use crate::vm_lab::orchestrator::remote_shell::{MockShellHost, RemoteExitStatus};
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::source_archive::SourceArchive;

    /// Adapter double whose shell is a shared [`MockShellHost`] with SSH
    /// params — the existing stage-test seam — so the admin role precondition
    /// is driven without any live host or test-binary dispatch.
    #[derive(Debug)]
    struct ShellNodeAdapter {
        alias: &'static str,
        platform: VmGuestPlatform,
        shell: std::sync::Arc<MockShellHost>,
    }

    impl NodeAdapter for ShellNodeAdapter {
        fn platform(&self) -> VmGuestPlatform {
            self.platform
        }
        fn alias(&self) -> &str {
            self.alias
        }
        fn shell_host(&self) -> Result<std::sync::Arc<dyn RemoteShellHost>, AdapterError> {
            Ok(self.shell.clone())
        }
        fn ssh_connection_params(&self) -> Option<SshConnectionParams> {
            Some(SshConnectionParams {
                host: "192.0.2.10".to_owned(),
                port: 22,
                user: Some("debian".to_owned()),
                identity_file: std::path::PathBuf::from("/tmp/enroll-test-id"),
                known_hosts: std::path::PathBuf::from("/tmp/enroll-test-known-hosts"),
            })
        }
        fn collect_mesh_ip(&self) -> Result<String, AdapterError> {
            unimplemented!()
        }
        fn collect_artifacts(&self, _dst: &std::path::Path) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn start_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn stop_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn restart_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn uninstall_daemon(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_membership_owner_key(&self) -> Result<MembershipOwnerKey, AdapterError> {
            unimplemented!()
        }
        fn collect_wireguard_public_key(
            &self,
        ) -> Result<crate::vm_lab::orchestrator::error::WireguardPublicKey, AdapterError> {
            unimplemented!()
        }
        fn collect_gossip_identity(&self) -> Result<GossipIdentity, AdapterError> {
            unimplemented!()
        }
        fn collect_node_id(&self) -> Result<NodeId, AdapterError> {
            unimplemented!()
        }
        fn run_validator(
            &self,
            _op: crate::vm_lab::DaemonProbeOp,
            _extra_args: &[String],
        ) -> Result<ValidatorReport, AdapterError> {
            unimplemented!()
        }
        fn ping_mesh_peer(&self, _peer_mesh_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn probe_denied_peer(&self, _denied_ip: &str) -> Result<TrafficTestResult, AdapterError> {
            unimplemented!()
        }
        fn collect_active_tunnels(&self) -> Result<TunnelsList, AdapterError> {
            unimplemented!()
        }
        fn cleanup_runtime_state(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn check_ssh_reachable(&self) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn endpoint(&self) -> String {
            unimplemented!()
        }
        fn install_daemon(
            &self,
            _source: &SourceArchive,
            _ctx: &OrchestrationContext,
        ) -> Result<InstallReport, AdapterError> {
            unimplemented!()
        }
        fn init_membership_snapshot(
            &self,
            _owner_key: &MembershipOwnerKey,
            _peers: &[NodeMembershipPeer],
        ) -> Result<MembershipSnapshot, AdapterError> {
            unimplemented!()
        }
        fn distribute_signed_bundle(
            &self,
            _kind: BundleKind,
            _bundle_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn distribute_verifier_key(
            &self,
            _kind: BundleKind,
            _pub_key_path: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
        fn issue_bundles_to_dir(
            &self,
            _kind: BundleKind,
            _env_content: &str,
            _local_out_dir: &std::path::Path,
        ) -> Result<(), AdapterError> {
            unimplemented!()
        }
    }

    /// The exact argv the precondition must issue: the sudo-wrapped daemon
    /// status seam (`sudo -n env RUSTYNET_DAEMON_SOCKET=… rustynet status`),
    /// the same shape the exit-demotion restore uses — the root-owned 0600
    /// socket is unreachable unsudoed on Linux guests (D1).
    fn sudoed_status_argv() -> [&'static str; 6] {
        [
            "sudo",
            "-n",
            "env",
            "RUSTYNET_DAEMON_SOCKET=/run/rustynet/rustynetd.sock",
            "/usr/local/bin/rustynet",
            "status",
        ]
    }

    fn program_status(shell: &MockShellHost, code: i32, stdout: &str) {
        shell.program_run_response(
            &sudoed_status_argv(),
            RemoteExitStatus {
                code,
                stdout: stdout.as_bytes().to_vec(),
                stderr: Vec::new(),
            },
        );
    }

    fn unique_test_dir(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "enroll_restart_{name}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    /// katana-xnet-113: the demoted admin (node_role=client) must refuse the
    /// stage with the named precondition failure — BEFORE the opaque test
    /// binary runs and dies with "command denied".
    #[test]
    fn enrollment_precondition_refuses_demoted_admin_before_the_test_binary() {
        let exit_shell = std::sync::Arc::new(MockShellHost::new());
        program_status(
            &exit_shell,
            0,
            "node_id=katana-exit-1-bootstrap node_role=client state=DataplaneApplied\n",
        );
        let mut ctx = OrchestrationContext::new(
            vec![
                NodeRoleAssignment {
                    alias: "katana-exit-1".to_owned(),
                    role: NodeRole::Exit,
                },
                NodeRoleAssignment {
                    alias: "katana-aux-1".to_owned(),
                    role: NodeRole::Aux,
                },
            ],
            unique_test_dir("refusal"),
            "net".to_owned(),
        );
        ctx.adapters.insert(
            "katana-exit-1".to_owned(),
            Box::new(ShellNodeAdapter {
                alias: "katana-exit-1",
                platform: VmGuestPlatform::Linux,
                shell: exit_shell.clone(),
            }),
        );
        ctx.adapters.insert(
            "katana-aux-1".to_owned(),
            Box::new(ShellNodeAdapter {
                alias: "katana-aux-1",
                platform: VmGuestPlatform::Linux,
                shell: std::sync::Arc::new(MockShellHost::new()),
            }),
        );

        let outcome = LiveEnrollmentRestartValidationStage.execute(&mut ctx);
        match outcome {
            StageOutcome::Failed(message) => assert!(
                message.contains(
                    "admin node katana-exit-1 daemon role is client, expected admin: an earlier stage left it demoted"
                ),
                "unexpected refusal: {message}"
            ),
            other => panic!(
                "a demoted admin must refuse the stage; got {other:?}"
            ),
        }
        // The refusal fired before any test-binary dispatch: exactly one
        // status query ran on the admin shell, nothing else — and through
        // the sudo-wrapped seam (D1).
        assert_eq!(exit_shell.run_log().len(), 1, "{:?}", exit_shell.run_log());
        assert_eq!(
            exit_shell.run_log()[0].argv,
            sudoed_status_argv(),
            "the precondition must query through the sudo-wrapped seam: \
             the root-owned 0600 socket is unreachable unsudoed on Linux guests"
        );
    }

    /// The pass path is asserted on the precondition fn directly: driving
    /// execute() to green here would dispatch the real cargo test binary.
    #[test]
    fn enrollment_precondition_passes_for_admin_role() {
        let shell = MockShellHost::new();
        program_status(
            &shell,
            0,
            "node_id=katana-exit-1-bootstrap node_role=admin state=DataplaneApplied\n",
        );
        assert_admin_daemon_role(&shell, VmGuestPlatform::Linux, "katana-exit-1")
            .expect("an admin-role daemon must pass the precondition");
        assert_eq!(shell.run_log().len(), 1);
    }

    /// D2b: transient transport failures are retried within the bounded
    /// window; the final error names the last error and the attempt count.
    #[test]
    fn enrollment_precondition_fails_closed_on_transport_error_after_retries() {
        let shell = MockShellHost::new();
        let err = assert_admin_daemon_role(&shell, VmGuestPlatform::Linux, "katana-exit-1")
            .expect_err("an unanswerable status query must fail closed");
        assert!(
            err.contains("admin node katana-exit-1 daemon status query failed"),
            "{err}"
        );
        assert!(
            err.contains(&format!("after {DAEMON_ROLE_POLL_MAX_ATTEMPTS} attempts")),
            "the final failure must name the attempt count: {err}"
        );
        assert_eq!(shell.run_log().len(), DAEMON_ROLE_POLL_MAX_ATTEMPTS);
    }

    /// D2b: persistent non-zero status exits are retried, then fail naming
    /// the last error.
    #[test]
    fn enrollment_precondition_retries_non_zero_then_fails_naming_last_error() {
        let shell = MockShellHost::new();
        for _ in 0..DAEMON_ROLE_POLL_MAX_ATTEMPTS {
            program_status(&shell, 1, "daemon unreachable");
        }
        let err = assert_admin_daemon_role(&shell, VmGuestPlatform::Linux, "katana-exit-1")
            .expect_err("a non-zero status exit must fail closed");
        assert!(
            err.contains("daemon status query exited non-zero")
                && err.contains("daemon unreachable"),
            "the final failure must name the last error: {err}"
        );
        assert_eq!(shell.run_log().len(), DAEMON_ROLE_POLL_MAX_ATTEMPTS);
    }

    /// D2b: a body without a readable node_role (mid-restart garbage) is
    /// transient — retried, then failed closed.
    #[test]
    fn enrollment_precondition_retries_fieldless_body_then_fails_closed() {
        let shell = MockShellHost::new();
        for _ in 0..DAEMON_ROLE_POLL_MAX_ATTEMPTS {
            program_status(&shell, 0, "node_id=katana-exit-1 state=Ready\n");
        }
        let err = assert_admin_daemon_role(&shell, VmGuestPlatform::Linux, "katana-exit-1")
            .expect_err("a status without node_role must fail closed");
        assert!(err.contains("no node_role field"), "{err}");
        assert_eq!(shell.run_log().len(), DAEMON_ROLE_POLL_MAX_ATTEMPTS);
    }

    /// D2b: a SINGLE transient failure (first attempt exits non-zero, the
    /// daemon is mid-restart) must be retried to success, not fatal.
    #[test]
    fn enrollment_precondition_retries_transient_failure_then_succeeds() {
        let shell = MockShellHost::new();
        program_status(&shell, 1, "daemon restarting");
        program_status(
            &shell,
            0,
            "node_id=katana-exit-1-bootstrap node_role=admin state=DataplaneApplied\n",
        );
        assert_admin_daemon_role(&shell, VmGuestPlatform::Linux, "katana-exit-1")
            .expect("a transient failure followed by the admin role must pass");
        assert_eq!(shell.run_log().len(), 2);
    }

    /// D2a: the precondition applies on Linux only — on macOS the lab exit
    /// runs the blind_exit daemon posture, so the precondition is skipped
    /// with a named log line and WITHOUT issuing any status query.
    #[test]
    fn enrollment_precondition_skipped_on_macos_without_status_query() {
        let shell = MockShellHost::new();
        assert_admin_daemon_role(&shell, VmGuestPlatform::Macos, "mac-exit-1")
            .expect("a non-Linux platform must skip the precondition, not fail");
        assert!(
            shell.run_log().is_empty(),
            "the skipped precondition must not query the daemon: {:?}",
            shell.run_log()
        );
    }

    /// D2a table: Linux expects the admin daemon role; every other platform
    /// skips (None). Mutation witness: flipping any arm fails this test.
    #[test]
    fn expected_admin_daemon_role_applies_only_on_linux() {
        assert_eq!(
            expected_admin_daemon_role(VmGuestPlatform::Linux),
            Some("admin")
        );
        for skipped in [
            VmGuestPlatform::Macos,
            VmGuestPlatform::Windows,
            VmGuestPlatform::Ios,
            VmGuestPlatform::Android,
        ] {
            assert_eq!(
                expected_admin_daemon_role(skipped),
                None,
                "platform {skipped:?} must skip the Linux-only precondition"
            );
        }
    }

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
