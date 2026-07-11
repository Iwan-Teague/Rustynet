#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::exit_dns_failclosed::{
    exit_dns_failclosed_runtime_implemented, validate_linux_exit_dns_failclosed,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "exit_dns_failclosed_validation.reported_skips.json";

/// Prove the assigned Linux exit passes the exit-mode DNS fail-closed
/// leak proof — six-artifact directory-based contract (firewall rules, UDP/TCP
/// block pcaps, active off-tunnel probe, tunnel positive control, resolv.conf
/// snapshot) — folding the formerly bash-only check into the standard Rust
/// orchestrator so a `--node` run exercises it.
///
/// Runs immediately after `active_exit`, while exit NAT/killswitch/DNS state is
/// still active, and before destructive lifecycle/demotion proofs.
/// Accepted only on the evaluator's full contract (missing artifacts, non-empty
/// pcaps, vacuous probes, and DNS leaks all fail closed). A macOS / Windows
/// node is **reported-skipped** — named in
/// `exit_dns_failclosed_validation.reported_skips.json`, never a silent pass.
pub struct ExitDnsFailclosedValidationStage;

impl OrchestrationStage for ExitDnsFailclosedValidationStage {
    fn id(&self) -> StageId {
        StageId::ExitDnsFailclosedValidation
    }
    fn name(&self) -> &str {
        "exit_dns_failclosed_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ActiveExit]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::Exit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::Once
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let alias = match ctx.assignments.iter().find(|a| a.role == NodeRole::Exit) {
            Some(assignment) => assignment.alias.clone(),
            None => {
                return StageOutcome::Failed(
                    "exit-dns-failclosed: no Exit node in assignments".to_owned(),
                );
            }
        };
        let mesh_hostname = match ctx
            .node_ids
            .get(alias.as_str())
            .ok_or_else(|| "missing node identity".to_owned())
            .and_then(|node_id| mesh_hostname_for_node_id(node_id))
        {
            Ok(hostname) => hostname,
            Err(err) => {
                return StageOutcome::Failed(format!(
                    "{alias}: {err} for tunnel DNS positive control"
                ));
            }
        };
        let adapter = match ctx.adapters.get(alias.as_str()) {
            Some(adapter) => adapter,
            None => {
                return StageOutcome::Failed(format!(
                    "{alias}: no adapter for exit-dns-failclosed node"
                ));
            }
        };
        let platform = adapter.platform();
        if !exit_dns_failclosed_runtime_implemented(platform) {
            let reported_skips = vec![(alias, format!("{platform:?}"))];
            write_reported_skips_note(ctx, &reported_skips);
            return StageOutcome::Skipped;
        }
        let shell = match adapter.shell_host() {
            Ok(shell) => shell,
            Err(e) => {
                return StageOutcome::Failed(format!("{alias}: shell host unavailable: {e}"));
            }
        };
        let daemon_path = match platform {
            VmGuestPlatform::Linux => LINUX_RUSTYNETD_PATH,
            VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
            VmGuestPlatform::Windows => WINDOWS_RUSTYNETD_PATH,
            _ => unreachable!("runtime implementation gate accepts desktop platforms only"),
        };
        let failures = match validate_linux_exit_dns_failclosed(
            &*shell,
            daemon_path,
            &alias,
            &mesh_hostname,
        ) {
            Ok(()) => Vec::new(),
            Err(e) => vec![format!("{alias}: {e}")],
        };
        let reported_skips = Vec::new();
        outcome_for(&failures, &reported_skips)
    }
}

fn mesh_hostname_for_node_id(node_id: &str) -> Result<String, String> {
    let node_id = node_id.trim();
    if node_id.is_empty() {
        return Err("empty node identity".to_owned());
    }
    Ok(format!("{node_id}.rustynet"))
}

fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped
    } else {
        StageOutcome::Passed
    }
}

fn reported_skips_json_bytes(reported_skips: &[(String, String)]) -> Vec<u8> {
    let skipped: Vec<serde_json::Value> = reported_skips
        .iter()
        .map(|(alias, platform)| serde_json::json!({ "alias": alias, "platform": platform }))
        .collect();
    let body = serde_json::json!({
        "stage": "exit_dns_failclosed_validation",
        "reported_skipped_exit_dns_failclosed": skipped,
        "reason": "Exit DNS fail-closed leak proof runs live on Linux through the Rust engine; \
                   non-Linux nodes are reported-skipped (named, never a silent pass)",
    });
    serde_json::to_vec_pretty(&body).unwrap_or_default()
}

fn write_reported_skips_note(ctx: &OrchestrationContext, reported_skips: &[(String, String)]) {
    let path = ctx.report_dir.join(REPORTED_SKIPS_FILENAME);
    let _ = std::fs::write(&path, reported_skips_json_bytes(reported_skips));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stage_evidence_is_scoped_to_assigned_exit() {
        assert_eq!(
            ExitDnsFailclosedValidationStage.applies_to_roles(),
            &[NodeRole::Exit]
        );
    }

    #[test]
    fn positive_control_uses_actual_exit_node_identity() {
        assert_eq!(
            mesh_hostname_for_node_id("debian-headless-2-bootstrap").unwrap(),
            "debian-headless-2-bootstrap.rustynet"
        );
        assert!(mesh_hostname_for_node_id(" ").is_err());
    }

    #[test]
    fn outcome_no_failures_no_skips_is_passed() {
        assert_eq!(outcome_for(&[], &[]), StageOutcome::Passed);
    }

    #[test]
    fn outcome_reported_skip_only_is_skipped() {
        assert_eq!(
            outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
            StageOutcome::Skipped
        );
    }

    #[test]
    fn outcome_failure_is_failed_even_with_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: exit dns failed".into()],
                &[("mac-1".into(), "Macos".into())]
            ),
            StageOutcome::Failed(_)
        ));
    }

    #[test]
    fn reported_skip_note_names_every_skipped_node() {
        let bytes = reported_skips_json_bytes(&[
            ("mac-1".into(), "Macos".into()),
            ("win-1".into(), "Windows".into()),
        ]);
        let s = String::from_utf8_lossy(&bytes);
        assert!(s.contains("mac-1") && s.contains("win-1"));
        assert!(s.contains("exit_dns_failclosed_validation"));
    }
}
