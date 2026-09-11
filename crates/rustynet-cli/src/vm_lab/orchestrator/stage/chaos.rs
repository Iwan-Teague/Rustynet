#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Clone, Copy)]
enum ChaosTargets {
    Offline,
    Exit,
    ExitAndClient,
}

struct ChaosBinSpec {
    id: StageId,
    name: &'static str,
    bin: &'static str,
    targets: ChaosTargets,
    extra_args: &'static [(&'static str, &'static str)],
}

macro_rules! chaos_stage {
    ($type_name:ident, $id:ident, $name:literal, $bin:literal, $targets:ident $(, $flag:literal => $value:literal)* $(,)?) => {
        pub struct $type_name;

        impl $type_name {
            const SPEC: ChaosBinSpec = ChaosBinSpec {
                id: StageId::$id,
                name: $name,
                bin: $bin,
                targets: ChaosTargets::$targets,
                extra_args: &[$(($flag, $value)),*],
            };
        }

        impl OrchestrationStage for $type_name {
            fn id(&self) -> StageId {
                Self::SPEC.id.clone()
            }

            fn name(&self) -> &str {
                Self::SPEC.name
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
                run_chaos_bin(ctx, &Self::SPEC)
            }
        }
    };
}

chaos_stage!(
    ChaosClockAttackStage,
    ChaosClockAttack,
    "chaos_clock_attack",
    "live_chaos_clock_attack_test",
    Exit,
);
chaos_stage!(
    ChaosCrashRecoveryStage,
    ChaosCrashRecovery,
    "chaos_crash_recovery",
    "live_chaos_crash_recovery_test",
    Exit,
);
chaos_stage!(
    ChaosDaemonFaultStage,
    ChaosDaemonFault,
    "chaos_daemon_fault",
    "live_chaos_daemon_fault_test",
    ExitAndClient,
);
chaos_stage!(
    ChaosDaemonSigstopSigcontStage,
    ChaosDaemonSigstopSigcont,
    "chaos_daemon_sigstop_sigcont",
    "live_chaos_daemon_fault_test",
    ExitAndClient,
    "--fault-mode" => "sigstop-cont",
);
chaos_stage!(
    ChaosMembershipAdversarialStage,
    ChaosMembershipAdversarial,
    "chaos_membership_adversarial",
    "live_chaos_membership_adversarial_test",
    Offline,
);
chaos_stage!(
    ChaosNetworkImpairmentStage,
    ChaosNetworkImpairment,
    "chaos_network_impairment",
    "live_chaos_network_impairment_test",
    ExitAndClient,
);
chaos_stage!(
    ChaosPrivilegedBoundaryStage,
    ChaosPrivilegedBoundary,
    "chaos_privileged_boundary",
    "live_chaos_privileged_boundary_test",
    Offline,
);
chaos_stage!(
    ChaosResourceExhaustionStage,
    ChaosResourceExhaustion,
    "chaos_resource_exhaustion",
    "live_chaos_resource_exhaustion_test",
    Exit,
);
chaos_stage!(
    ChaosSignedStateAdversarialStage,
    ChaosSignedStateAdversarial,
    "chaos_signed_state_adversarial",
    "live_chaos_signed_state_adversarial_test",
    Offline,
    "--scenario" => "all",
);

fn run_chaos_bin(ctx: &OrchestrationContext, spec: &ChaosBinSpec) -> StageOutcome {
    // Role cells run `exit + <role>` with no client: a client-dependent chaos
    // bin cannot run there, and the answer is the same declared skip the live
    // stages report (review B, 2026-09-11), never a stage failure.
    if matches!(spec.targets, ChaosTargets::ExitAndClient)
        && let Some(skip) =
            crate::vm_lab::orchestrator::stage::exit_only_topology_skip(ctx, spec.name)
    {
        return skip;
    }
    // The chaos bins drive systemd, nft, tc and libfaketime on the guest:
    // Linux-only by construction. A mac/win target is a platform gap to
    // report (review F, 2026-09-11), not a failure.
    if !matches!(spec.targets, ChaosTargets::Offline) {
        let non_linux: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| matches!(a.role, NodeRole::Exit | NodeRole::Client))
            .filter(|a| {
                ctx.adapters
                    .get(a.alias.as_str())
                    .is_some_and(|adapter| adapter.platform() != VmGuestPlatform::Linux)
            })
            .map(|a| a.alias.clone())
            .collect();
        if !non_linux.is_empty() {
            return StageOutcome::Skipped(format!(
                "{} targets a non-Linux guest ({}); the chaos bins are Linux-only",
                spec.name,
                non_linux.join(",")
            ));
        }
    }
    let report_path = ctx.report_dir.join(format!("{}_report.json", spec.name));
    let log_path = ctx.report_dir.join(format!("{}.log", spec.name));

    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--features",
        "vm-lab",
        "--bin",
        spec.bin,
        "--",
        "--report-path",
    ])
    .arg(&report_path)
    .arg("--log-path")
    .arg(&log_path);

    match spec.targets {
        ChaosTargets::Offline => {}
        ChaosTargets::Exit => {
            let exit = match ssh_params_for_role(ctx, "exit") {
                Ok(params) => params,
                Err(err) => return StageOutcome::Failed(err),
            };
            add_single_target_args(&mut cmd, &exit);
        }
        ChaosTargets::ExitAndClient => {
            let exit = match ssh_params_for_role(ctx, "exit") {
                Ok(params) => params,
                Err(err) => return StageOutcome::Failed(err),
            };
            let client = match ssh_params_for_role(ctx, "client") {
                Ok(params) => params,
                Err(err) => return StageOutcome::Failed(err),
            };
            add_single_target_args(&mut cmd, &exit);
            cmd.arg("--client-host").arg(&client.target);
        }
    }

    for (flag, value) in spec.extra_args {
        cmd.arg(flag).arg(value);
    }

    match cmd.output() {
        Ok(output) if output.status.success() => {
            match verify_chaos_report_artifact(&ctx.report_dir, spec.name) {
                Ok(()) => StageOutcome::Passed,
                Err(err) => StageOutcome::Failed(format!("{}: {err}", spec.bin)),
            }
        }
        Ok(output) => StageOutcome::Failed(format!(
            "{} exited with {}: {}",
            spec.bin,
            output.status,
            stderr_snippet(&output.stderr)
        )),
        Err(err) => StageOutcome::Failed(format!("failed to run {}: {err}", spec.bin)),
    }
}

/// QH-83: the on-disk witness behind a chaos PASS verdict. Every chaos bin
/// writes `<stage>_report.json` (a non-empty pretty JSON document) into the
/// run's report dir before it exits, so an exit-0 run with no artifact means
/// the bin never actually produced evidence — fail the stage instead of
/// passing on the runner's post-hoc demotion alone.
fn chaos_report_relative_path(stage_name: &str) -> String {
    format!("{stage_name}_report.json")
}

fn verify_chaos_report_artifact(report_dir: &Path, stage_name: &str) -> Result<(), String> {
    let path = report_dir.join(chaos_report_relative_path(stage_name));
    let metadata = std::fs::metadata(&path)
        .map_err(|err| format!("chaos report witness {}: {err}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!(
            "chaos report witness {} is not a regular file",
            path.display()
        ));
    }
    if metadata.len() == 0 {
        return Err(format!("chaos report witness {} is empty", path.display()));
    }
    // The witness must be the bin's scenario report, not merely bytes: a
    // JSON object carrying the verdict field (review NIT, 2026-09-10).
    let raw = std::fs::read_to_string(&path)
        .map_err(|err| format!("chaos report witness {}: {err}", path.display()))?;
    verify_chaos_report_shape(&raw)
        .map_err(|err| format!("chaos report witness {}: {err}", path.display()))
}

/// Pure shape check on a chaos report: JSON object with an `overall_status`
/// string. Anything else is not evidence.
fn verify_chaos_report_shape(raw: &str) -> Result<(), String> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| format!("not valid JSON: {err}"))?;
    match value.get("overall_status").and_then(|v| v.as_str()) {
        Some(status) if !status.is_empty() => Ok(()),
        _ => Err("JSON has no `overall_status` string; not a chaos scenario report".to_owned()),
    }
}

fn add_single_target_args(cmd: &mut Command, params: &ResolvedParams) {
    cmd.arg("--target-host")
        .arg(&params.target)
        .arg("--ssh-identity-file")
        .arg(&params.identity_file)
        .arg("--known-hosts-file")
        .arg(&params.known_hosts);
}

struct ResolvedParams {
    target: String,
    identity_file: PathBuf,
    known_hosts: PathBuf,
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
    let user = params
        .user
        .unwrap_or_else(|| default_ssh_user(adapter.platform()).to_owned());
    Ok(ResolvedParams {
        target: format!("{user}@{}", params.host),
        identity_file: params.identity_file,
        known_hosts: params.known_hosts,
    })
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

    // Review B (2026-09-11): the three client-dependent chaos bins must
    // report the topology gap on an exit-only cell, not fail.
    #[test]
    fn client_dependent_chaos_bin_skips_on_an_exit_only_topology() {
        use crate::vm_lab::orchestrator::role::NodeRole;
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use std::collections::HashMap;
        let mut ctx = OrchestrationContext {
            assignments: vec![NodeRoleAssignment {
                alias: "exit-1".to_owned(),
                role: NodeRole::Exit,
            }],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            collected_gossip_identities: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            reflexive_endpoints: HashMap::new(),
            lab_stun_servers: Vec::new(),
            linux_backend: None,
            orchestrator_dialect: None,
            substrate: None,
            substrate_record: None,
            inventory_path: None,
            macos_anchor_validators_elected: false,
            macos_role_transition_elected: false,
            macos_reboot_recovery_elected: false,
            relay_forwarding_validation_elected: false,
        };
        let outcome = ChaosDaemonFaultStage.execute(&mut ctx);
        assert!(
            matches!(&outcome, StageOutcome::Skipped(reason) if reason.contains("no client node")),
            "{outcome:?}"
        );
    }

    #[test]
    fn chaos_report_shape_requires_a_json_object_with_a_verdict() {
        assert!(verify_chaos_report_shape(r#"{"overall_status":"pass","stages":[]}"#).is_ok());
        assert!(verify_chaos_report_shape("not json").is_err());
        assert!(verify_chaos_report_shape(r#"{"stages":[]}"#).is_err());
        assert!(verify_chaos_report_shape(r#"{"overall_status":""}"#).is_err());
        assert!(verify_chaos_report_shape("[]").is_err());
    }

    #[test]
    fn chaos_sigstop_reuses_daemon_fault_binary_with_sigstop_mode() {
        assert_eq!(
            ChaosDaemonSigstopSigcontStage.id(),
            StageId::ChaosDaemonSigstopSigcont
        );
        assert_eq!(
            ChaosDaemonSigstopSigcontStage.name(),
            "chaos_daemon_sigstop_sigcont"
        );
        assert_eq!(
            ChaosDaemonSigstopSigcontStage.dependencies(),
            &[StageId::LiveMixedTopologyValidation]
        );
        assert_eq!(ChaosDaemonSigstopSigcontStage.fanout(), StageFanout::Once);
        assert_eq!(
            ChaosDaemonSigstopSigcontStage::SPEC.bin,
            "live_chaos_daemon_fault_test"
        );
        assert_eq!(
            ChaosDaemonSigstopSigcontStage::SPEC.extra_args,
            &[("--fault-mode", "sigstop-cont")]
        );
    }

    #[test]
    fn offline_chaos_stages_do_not_require_ssh_targets() {
        assert!(matches!(
            ChaosSignedStateAdversarialStage::SPEC.targets,
            ChaosTargets::Offline
        ));
        assert_eq!(
            ChaosSignedStateAdversarialStage::SPEC.extra_args,
            &[("--scenario", "all")]
        );
    }

    fn chaos_witness_temp_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "chaos_witness_{label}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    #[test]
    fn chaos_report_witness_missing_artifact_is_rejected() {
        let dir = chaos_witness_temp_dir("missing");
        std::fs::create_dir_all(&dir).unwrap();
        let err = verify_chaos_report_artifact(&dir, "chaos_clock_attack")
            .expect_err("a pass with no report artifact must be rejected");
        assert!(err.contains("chaos_clock_attack_report.json"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chaos_report_witness_empty_artifact_is_rejected() {
        let dir = chaos_witness_temp_dir("empty");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("chaos_clock_attack_report.json"), b"").unwrap();
        let err = verify_chaos_report_artifact(&dir, "chaos_clock_attack")
            .expect_err("an empty report artifact must be rejected");
        assert!(err.contains("is empty"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chaos_report_witness_present_artifact_passes() {
        let dir = chaos_witness_temp_dir("present");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("chaos_signed_state_adversarial_report.json"),
            b"{\"overall_status\":\"fail\"}\n",
        )
        .unwrap();
        verify_chaos_report_artifact(&dir, "chaos_signed_state_adversarial")
            .expect("a non-empty report artifact must verify");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn chaos_report_witness_declared_per_stage_and_unique() {
        use crate::vm_lab::orchestrator::stage::StageEvidence;
        use std::collections::HashSet;

        let stages: [&dyn OrchestrationStage; 9] = [
            &ChaosClockAttackStage,
            &ChaosCrashRecoveryStage,
            &ChaosDaemonFaultStage,
            &ChaosDaemonSigstopSigcontStage,
            &ChaosMembershipAdversarialStage,
            &ChaosNetworkImpairmentStage,
            &ChaosPrivilegedBoundaryStage,
            &ChaosResourceExhaustionStage,
            &ChaosSignedStateAdversarialStage,
        ];
        let mut declared: HashSet<String> = HashSet::new();
        for stage in stages {
            let id = stage.id();
            let name = id.as_str();
            match id.evidence() {
                StageEvidence::File(relative) => {
                    assert_eq!(relative, chaos_report_relative_path(name));
                    assert!(declared.insert(relative.to_owned()));
                }
                other => panic!("stage {name} must declare its report File witness, got {other:?}"),
            }
        }
        assert_eq!(
            declared.len(),
            9,
            "each chaos stage needs its own report file"
        );
    }
}
