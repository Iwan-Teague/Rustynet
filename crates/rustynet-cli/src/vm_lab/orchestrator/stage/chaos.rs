#![allow(dead_code)]
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use std::path::PathBuf;
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
    let report_path = ctx.report_dir.join(format!("{}_report.json", spec.name));
    let log_path = ctx.report_dir.join(format!("{}.log", spec.name));

    let mut cmd = Command::new("cargo");
    cmd.args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
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
        Ok(output) if output.status.success() => StageOutcome::Passed,
        Ok(output) => StageOutcome::Failed(format!(
            "{} exited with {}: {}",
            spec.bin,
            output.status,
            stderr_snippet(&output.stderr)
        )),
        Err(err) => StageOutcome::Failed(format!("failed to run {}: {err}", spec.bin)),
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
}
