#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{
    OrchestrationStage, StageFanout, StageId, desktop_platform_tag,
};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

pub struct LiveExtendedSoakValidationStage;

impl OrchestrationStage for LiveExtendedSoakValidationStage {
    fn id(&self) -> StageId {
        StageId::LiveExtendedSoakValidation
    }

    fn name(&self) -> &str {
        "extended_soak"
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
        // The extended soak drives a five-node topology (exit + client +
        // entry + aux + a second client). A smaller topology cannot exercise
        // it — skip rather than fail-closed, matching the two_hop /
        // enrollment-restart incomplete-topology skips. With all roles
        // present, any error below remains a hard fail.
        let complete = ["exit", "client", "entry", "aux"]
            .iter()
            .all(|label| ssh_params_for_role(ctx, label).is_ok())
            && ssh_params_for_second_client(ctx).is_ok();
        if !complete {
            return StageOutcome::Skipped(
                "the topology lacks the second client this soak requires".to_owned(),
            );
        }
        // AQ-256 design D (typed, non-blocking): the soak's lan-toggle substep
        // promotes the aux node to the blind_exit daemon role, which rustynetd
        // refuses while the vxlan substrate's transit attestation is on that
        // node. Without this guard the soak would run its two-hop and
        // exit-handoff substeps (many minutes) and only then fail on the
        // doomed substep, leaving the exit and client fail-closed. The whole
        // stage skips, never just the substep: a soak that silently dropped
        // one of its substeps and still reported Passed would claim coverage
        // it did not run. Decided from the run's substrate record alone,
        // before any ssh/cargo.
        if let Ok(aux) = ssh_params_for_role(ctx, "aux")
            && let Some(skip) =
                crate::vm_lab::orchestrator::stage::substrate_blind_exit_conflict_skip(
                    ctx.substrate_record.as_ref(),
                    &aux.alias,
                    "the extended soak's lan-toggle substep",
                )
        {
            return skip;
        }
        match run_extended_soak(ctx) {
            Ok(()) => match verify_report_artifact(&ctx.report_dir) {
                Ok(()) => StageOutcome::Passed,
                Err(e) => StageOutcome::Failed(e),
            },
            Err(err) => StageOutcome::Failed(err),
        }
    }
}

/// QH-83: the soak's pass verdict rests on the final substep's report, the
/// reboot-recovery JSON. Substeps are sequential and exit-gated, so on every
/// `Passed` path that artifact exists; verify it is present and non-empty
/// before recording the pass, and fail the stage (never a best-effort note)
/// when it is not.
const REBOOT_RECOVERY_REPORT_RELATIVE: &str = "live_linux_reboot_recovery_report.json";

fn verify_report_artifact(report_dir: &Path) -> Result<(), String> {
    let path = report_dir.join(REBOOT_RECOVERY_REPORT_RELATIVE);
    match std::fs::metadata(&path) {
        Ok(meta) if meta.is_file() && meta.len() > 0 => Ok(()),
        Ok(_) => Err(format!(
            "extended soak witness artifact {REBOOT_RECOVERY_REPORT_RELATIVE} is not a non-empty regular file"
        )),
        Err(err) => Err(format!(
            "extended soak witness artifact {REBOOT_RECOVERY_REPORT_RELATIVE} missing or unreadable: {err}"
        )),
    }
}

#[derive(Debug, Clone)]
struct ResolvedParams {
    alias: String,
    host: String,
    user: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
}

fn run_extended_soak(ctx: &OrchestrationContext) -> Result<(), String> {
    let exit = ssh_params_for_role(ctx, "exit")?;
    let client = ssh_params_for_role(ctx, "client")?;
    let entry = ssh_params_for_role(ctx, "entry")?;
    let aux = ssh_params_for_role(ctx, "aux")?;
    let second_client = ssh_params_for_second_client(ctx)?;

    let identity_file = exit.identity_file.to_string_lossy().into_owned();
    let known_hosts = exit.known_hosts.to_string_lossy().into_owned();
    // QH-57: refuse the 0.0.0.0/0 substitute this fallback used to inject.
    // The soak spawns two_hop / exit-handoff / lan-toggle / reboot subchecks
    // that ENFORCE this value onto nodes, and a default-route management
    // CIDR is exactly the wedge class QH-57 documents. Fail closed instead.
    let ssh_allow_cidrs = soak_ssh_allow_cidrs(&ctx.ssh_allow_cidrs)?;

    // QH-09: each substep's binary writes its own complete log via --log-path;
    // thread that path into the failure formatter so a clipped summary names
    // the unclipped sidecar instead of reading as evidence loss.
    let two_hop_pre_log = ctx
        .report_dir
        .join("live_linux_two_hop_soak_pre_reboot.log")
        .to_string_lossy()
        .into_owned();
    let exit_handoff_log = ctx
        .report_dir
        .join("live_linux_exit_handoff_soak.log")
        .to_string_lossy()
        .into_owned();
    let lan_toggle_log = ctx
        .report_dir
        .join("live_linux_lan_toggle_soak.log")
        .to_string_lossy()
        .into_owned();
    let reboot_recovery_log = ctx
        .report_dir
        .join("live_linux_reboot_recovery.log")
        .to_string_lossy()
        .into_owned();

    run_substep(
        "extended_soak pre-reboot two-hop",
        cargo_bin_command(
            "live_linux_two_hop_test",
            vec![
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--known-hosts".to_owned(),
                known_hosts.clone(),
                "--final-exit-host".to_owned(),
                target(&exit),
                "--final-exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--entry-host".to_owned(),
                target(&entry),
                "--entry-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--second-client-host".to_owned(),
                target(&second_client),
                "--second-client-node-id".to_owned(),
                node_id_for_alias(ctx, &second_client.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_two_hop_soak_pre_reboot_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                two_hop_pre_log.clone(),
            ],
        ),
        &two_hop_pre_log,
    )?;

    run_substep(
        "extended_soak exit handoff",
        cargo_bin_command(
            "live_linux_exit_handoff_test",
            vec![
                "--platform".to_owned(),
                platform_for_node(ctx, &exit.alias)?.to_owned(),
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--known-hosts".to_owned(),
                known_hosts.clone(),
                "--exit-a-host".to_owned(),
                target(&exit),
                "--exit-a-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--exit-b-host".to_owned(),
                target(&entry),
                "--exit-b-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--switch-iteration".to_owned(),
                "60".to_owned(),
                "--monitor-iterations".to_owned(),
                "180".to_owned(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_exit_handoff_soak_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                exit_handoff_log.clone(),
                "--monitor-log".to_owned(),
                ctx.report_dir
                    .join("live_linux_exit_handoff_soak_monitor.log")
                    .to_string_lossy()
                    .into_owned(),
            ],
        ),
        &exit_handoff_log,
    )?;

    run_substep(
        "extended_soak lan toggle",
        cargo_bin_command(
            "live_linux_lan_toggle_test",
            vec![
                "--platform".to_owned(),
                platform_for_node(ctx, &exit.alias)?.to_owned(),
                "--ssh-identity-file".to_owned(),
                identity_file.clone(),
                "--exit-host".to_owned(),
                target(&exit),
                "--exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--blind-exit-host".to_owned(),
                target(&aux),
                "--blind-exit-node-id".to_owned(),
                node_id_for_alias(ctx, &aux.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs.clone(),
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_lan_toggle_soak_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                lan_toggle_log.clone(),
            ],
        ),
        &lan_toggle_log,
    )?;

    run_substep(
        "extended_soak reboot recovery",
        cargo_bin_command(
            "live_linux_reboot_recovery_test",
            vec![
                "--ssh-identity-file".to_owned(),
                identity_file,
                "--known-hosts".to_owned(),
                known_hosts,
                "--exit-host".to_owned(),
                target(&exit),
                "--exit-node-id".to_owned(),
                node_id_for_alias(ctx, &exit.alias)?,
                "--client-host".to_owned(),
                target(&client),
                "--client-node-id".to_owned(),
                node_id_for_alias(ctx, &client.alias)?,
                "--entry-host".to_owned(),
                target(&entry),
                "--entry-node-id".to_owned(),
                node_id_for_alias(ctx, &entry.alias)?,
                "--second-client-host".to_owned(),
                target(&second_client),
                "--second-client-node-id".to_owned(),
                node_id_for_alias(ctx, &second_client.alias)?,
                "--ssh-allow-cidrs".to_owned(),
                ssh_allow_cidrs,
                "--report-path".to_owned(),
                ctx.report_dir
                    .join("live_linux_reboot_recovery_report.json")
                    .to_string_lossy()
                    .into_owned(),
                "--log-path".to_owned(),
                reboot_recovery_log.clone(),
            ],
        ),
        &reboot_recovery_log,
    )
}

fn cargo_bin_command(bin: &str, extra_args: Vec<String>) -> Command {
    let mut command = Command::new("cargo");
    // `--features vm-lab` for the same two reasons as every sibling stage
    // launcher: a stage bin carrying `required-features = ["vm-lab"]` is
    // otherwise REFUSED outright (`error: target … requires the features`,
    // exit 101), and the orchestrator itself is a `vm-lab` build, so shelling
    // out with a different feature set makes cargo rebuild the crate in that
    // second configuration mid-run instead of reusing what is already built.
    command.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--features",
        "vm-lab",
        "--bin",
        bin,
        "--",
    ]);
    command.args(extra_args);
    command
}

fn run_substep(label: &str, mut command: Command, full_log: &str) -> Result<(), String> {
    match command.output() {
        Ok(output) if output.status.success() => Ok(()),
        Ok(output) => Err(format_substep_failure(label, &output, Some(full_log))),
        Err(err) => Err(format!("{label}: invocation failed: {err}")),
    }
}

fn format_substep_failure(label: &str, output: &Output, full_log: Option<&str>) -> String {
    // Was: stdout only when stderr is empty. That is not enough — the guest's
    // cause arrives on stdout while the wrapper's terse message goes to
    // stderr, so a non-empty stderr (the common case) hid the cause. Surface
    // both; see `format_stage_binary_failure`. QH-09: the substep binary's own
    // complete log (--log-path) is named when the summary is clipped, so the
    // disclosure never reads as evidence loss.
    crate::vm_lab::orchestrator::stage::format_stage_binary_failure_with_log(
        label,
        output.status,
        &output.stdout,
        &output.stderr,
        full_log,
    )
}

fn target(params: &ResolvedParams) -> String {
    format!("{}@{}", params.user, params.host)
}

fn node_id_for_alias(ctx: &OrchestrationContext, alias: &str) -> Result<String, String> {
    ctx.node_ids
        .get(alias)
        .cloned()
        .ok_or_else(|| format!("{alias}: node_id not found"))
}

/// The platform label fed to the soak substep binaries' `--platform` argv
/// (audit I3): desktop platforms tag through the shared exhaustive
/// [`desktop_platform_tag`]; a missing adapter or a never-hosted platform is
/// an `Err` propagated into the substep failure — never a silent `linux`
/// stamp.
fn platform_for_node(ctx: &OrchestrationContext, alias: &str) -> Result<&'static str, String> {
    let adapter = ctx
        .adapters
        .get(alias)
        .ok_or_else(|| format!("{alias}: no adapter for platform labelling"))?;
    desktop_platform_tag(adapter.platform(), "extended-soak validation")
}

fn ssh_params_for_role(ctx: &OrchestrationContext, label: &str) -> Result<ResolvedParams, String> {
    let alias = ctx
        .assignments
        .iter()
        .find(|assignment| assignment.role.as_str() == label)
        .map(|assignment| assignment.alias.clone())
        .ok_or_else(|| format!("extended_soak requires node role label '{label}'"))?;
    let adapter = ctx
        .adapters
        .get(alias.as_str())
        .ok_or_else(|| format!("no adapter for {alias} (role '{label}')"))?;
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

fn ssh_params_for_second_client(ctx: &OrchestrationContext) -> Result<ResolvedParams, String> {
    for label in ["extra", "aux"] {
        if let Ok(params) = ssh_params_for_role(ctx, label) {
            return Ok(params);
        }
    }
    Err("extended_soak requires an aux or extra node for second-client checks".to_owned())
}

/// QH-57: the soak's subchecks enforce this value onto live nodes, so an
/// empty run context must fail the stage rather than degrade to 0.0.0.0/0.
/// Unit-testable on purpose - deleting the rejection must fail a test.
fn soak_ssh_allow_cidrs(ctx_value: &str) -> Result<String, String> {
    let value = ctx_value.trim();
    if value.is_empty() {
        return Err("extended soak requires the run's management CIDRs \
             (ctx.ssh_allow_cidrs is empty); refusing the 0.0.0.0/0 \
             substitute that wedges full-tunnel nodes (QH-57)"
            .to_owned());
    }
    Ok(value.to_owned())
}

#[cfg(test)]
mod tests {
    #[test]
    fn soak_ssh_allow_cidrs_refuses_the_default_route_substitute() {
        // Deleting the rejection and restoring the old 0.0.0.0/0 fallback
        // must fail this test: the soak's subchecks enforce the value onto
        // live nodes (QH-57).
        let err = super::soak_ssh_allow_cidrs("").expect_err("empty ctx must fail closed");
        assert!(err.contains("0.0.0.0/0"));
        assert_eq!(
            super::soak_ssh_allow_cidrs("192.168.64.0/24").as_deref(),
            Ok("192.168.64.0/24")
        );
    }

    use super::*;

    #[test]
    fn stage_id_is_extended_soak() {
        assert_eq!(
            LiveExtendedSoakValidationStage.id(),
            StageId::LiveExtendedSoakValidation
        );
    }

    #[test]
    fn stage_name_matches_legacy_logical_stage() {
        assert_eq!(LiveExtendedSoakValidationStage.name(), "extended_soak");
    }

    #[test]
    fn depends_on_mixed_topology() {
        assert_eq!(
            LiveExtendedSoakValidationStage.dependencies(),
            &[StageId::LiveMixedTopologyValidation]
        );
    }

    #[test]
    fn fanout_is_once() {
        assert_eq!(LiveExtendedSoakValidationStage.fanout(), StageFanout::Once);
    }

    #[test]
    fn live_extended_soak_declared_witness_matches_its_artifact_path() {
        // QH-83: the catalog row must declare exactly the artifact the pass
        // verdict is verified against, so the runner's witness check and the
        // stage's own fatality cannot drift apart.
        use crate::vm_lab::orchestrator::stage::StageEvidence;
        assert_eq!(
            StageId::LiveExtendedSoakValidation.evidence(),
            StageEvidence::File(REBOOT_RECOVERY_REPORT_RELATIVE)
        );
    }

    #[test]
    fn live_extended_soak_pass_without_report_artifact_is_fatal() {
        // QH-83: a `Passed` verdict with no reboot-recovery report must be
        // impossible — the verifier fails closed and names the artifact.
        let dir = std::env::temp_dir().join(format!(
            "soak_witness_missing_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let err = super::verify_report_artifact(&dir).expect_err("missing artifact must fail");
        assert!(err.contains(REBOOT_RECOVERY_REPORT_RELATIVE), "{err}");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }

    #[test]
    fn substep_failure_surfaces_stderr() {
        let output = Command::new("sh")
            .args(["-c", "printf problem >&2; exit 7"])
            .output()
            .expect("shell output");
        let msg = format_substep_failure("label", &output, Some("soak.log"));
        assert!(msg.contains("label"));
        assert!(msg.contains("problem"));
        assert!(msg.contains("exit status: 7"));
    }

    #[test]
    fn a_clipped_substep_failure_names_the_sidecar_log() {
        // QH-09: when the summary is clipped, the disclosure must point at the
        // complete unclipped log instead of reading as evidence loss.
        let mut noisy = vec![b'y'; 6000];
        noisy.extend_from_slice(b"THE SOAK ERROR");
        let output = Command::new("sh")
            .args(["-c", "cat; exit 9"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write as _;
                child.stdin.as_mut().expect("stdin").write_all(&noisy)?;
                child.wait_with_output()
            })
            .expect("shell output");
        let msg = format_substep_failure("soak substep", &output, Some("live_two_hop_soak.log"));
        assert!(msg.contains("clipped"), "{msg}");
        assert!(
            msg.contains("complete unclipped output: live_two_hop_soak.log"),
            "the clipped summary must name the sidecar: {msg}"
        );
    }

    // ── AQ-256 design D: the lan-toggle substep must not promote an attested aux ──

    use crate::vm_lab::orchestrator::stage::SubstrateBlindExitConflict;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::SubstrateRecord;

    fn soak_substrate_record(provisioned: bool, participants: &[&str]) -> SubstrateRecord {
        SubstrateRecord {
            substrate_id: "vxlan".to_owned(),
            topology_digest: "digest".to_owned(),
            provisioned,
            participants: participants
                .iter()
                .map(|alias| (*alias).to_owned())
                .collect(),
        }
    }

    /// exit + client + entry + aux over offline SSH connections (nothing is
    /// dialled, no file is read), so the topology is `complete` for the soak.
    /// The run's management CIDRs are deliberately left EMPTY: a soak that
    /// gets past its guards then fails closed at the QH-57 check inside
    /// `run_extended_soak`, BEFORE any substep (cargo) is spawned, which is
    /// what lets these tests run `execute` for real.
    fn soak_ctx(substrate_record: Option<SubstrateRecord>) -> OrchestrationContext {
        use crate::vm_lab::orchestrator::adapter::linux::LinuxNodeAdapter;
        use crate::vm_lab::orchestrator::connection::NodeConnection;
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        let nodes = [
            ("exit-1", NodeRole::Exit, "192.0.2.10"),
            ("client-1", NodeRole::Client, "192.0.2.11"),
            ("entry-1", NodeRole::Entry, "192.0.2.12"),
            ("aux-1", NodeRole::Aux, "192.0.2.13"),
        ];
        let assignments = nodes
            .iter()
            .map(|(alias, role, _)| NodeRoleAssignment {
                alias: (*alias).to_owned(),
                role: role.clone(),
            })
            .collect();
        let mut ctx = OrchestrationContext::new(
            assignments,
            PathBuf::from("soak-substrate-guard-report"),
            "net".to_owned(),
        );
        for (alias, _, host) in nodes {
            ctx.adapters.insert(
                alias.to_owned(),
                Box::new(LinuxNodeAdapter::new(
                    alias,
                    NodeConnection::Ssh {
                        host: host.to_owned(),
                        port: 22,
                        user: Some("debian".to_owned()),
                        identity_file: PathBuf::from("/nonexistent/soak_guard_id"),
                        known_hosts: PathBuf::from("/nonexistent/soak_guard_known_hosts"),
                        ssh_password: None,
                    },
                )),
            );
        }
        ctx.substrate_record = substrate_record;
        ctx
    }

    /// The soak's lan-toggle substep promotes `aux` to blind_exit. On a vxlan
    /// run that attested aux the whole stage must skip up front (typed,
    /// non-blocking, never a pass) instead of running two-hop and exit-handoff
    /// for minutes and then failing on the doomed substep. With the guard
    /// removed `execute` runs on and returns `Failed` (QH-57 CIDR check here).
    #[test]
    fn soak_skips_when_the_lan_toggle_aux_is_a_substrate_participant() {
        let mut ctx = soak_ctx(Some(soak_substrate_record(
            true,
            &["exit-1", "client-1", "entry-1", "aux-1"],
        )));
        let outcome = LiveExtendedSoakValidationStage.execute(&mut ctx);
        match &outcome {
            StageOutcome::Skipped(reason) => {
                assert!(
                    SubstrateBlindExitConflict::is_skip_reason(reason)
                        && reason.contains("aux-1")
                        && reason.contains("blind_exit")
                        && reason.contains("lan-toggle substep"),
                    "the skip must be typed and name the aux node and the conflict: {reason}"
                );
            }
            other => panic!("a substrate-attested aux must skip the soak, not run it: {other:?}"),
        }
        assert!(!outcome.is_blocking(), "the typed skip must not block");
    }

    /// Negative twins: an unprovisioned substrate, a non-participant aux and no
    /// substrate at all all leave the soak running (it reaches its own QH-57
    /// check, which proves execution went past the substrate guard), and the
    /// failure there still fails and blocks.
    #[test]
    fn soak_runs_when_the_substrate_does_not_cover_aux() {
        for record in [
            Some(soak_substrate_record(false, &[])),
            Some(soak_substrate_record(
                true,
                &["exit-1", "client-1", "entry-1"],
            )),
            None,
        ] {
            let mut ctx = soak_ctx(record.clone());
            let outcome = LiveExtendedSoakValidationStage.execute(&mut ctx);
            match &outcome {
                StageOutcome::Failed(reason) => assert!(
                    reason.contains("management CIDRs"),
                    "the soak must run on to its own pre-check for {record:?}: {reason}"
                ),
                other => panic!("the soak must not skip for {record:?}: {other:?}"),
            }
            assert!(outcome.is_blocking(), "{record:?}: a failure must block");
        }
    }

    /// Pin: the guard sits after the topology-completeness skip and BEFORE
    /// `run_extended_soak` (which spawns every substep), and it returns the
    /// typed non-blocking skip for the whole stage.
    #[test]
    fn soak_substrate_guard_precedes_the_substeps() {
        let source = crate::vm_lab::implementation_source_slice(include_str!(
            "live_extended_soak_validation.rs"
        ))
        .expect("live_extended_soak_validation.rs implementation slice must parse");
        let execute_start = source
            .find("fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {")
            .expect("execute() must exist");
        let execute_body = &source[execute_start..];
        let complete = execute_body
            .find("if !complete {")
            .expect("the incomplete-topology skip must exist");
        let guard = execute_body
            .find("substrate_blind_exit_conflict_skip(")
            .expect("the substrate guard must exist");
        let run = execute_body
            .find("match run_extended_soak(ctx)")
            .expect("the soak run must exist");
        assert!(
            complete < guard && guard < run,
            "the substrate guard ({guard}) must follow the topology skip ({complete}) and \
             precede the soak run ({run})"
        );
        let skip_return = execute_body[guard..]
            .find("return skip;")
            .map(|offset| guard + offset)
            .expect("the guard must return the typed skip");
        assert!(
            skip_return < run,
            "the guard's skip return ({skip_return}) must precede the soak run ({run})"
        );
    }
}
