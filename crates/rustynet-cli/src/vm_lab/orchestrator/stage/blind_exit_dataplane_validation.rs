#![allow(dead_code)]
use crate::vm_lab::LINUX_RUSTYNETD_PATH;
use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::adapter::macos_install::MACOS_RUSTYNETD_PATH;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::role_validation::blind_exit_dataplane::{
    blind_exit_dataplane_runtime_implemented, validate_linux_blind_exit_dataplane,
};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const WINDOWS_RUSTYNETD_PATH: &str = r"C:\Program Files\RustyNet\rustynetd.exe";

const REPORTED_SKIPS_FILENAME: &str = "blind_exit_dataplane_validation.reported_skips.json";

/// Prove every Linux node's daemon passes the blind-exit dataplane self-check —
/// live nft ruleset capture with five hardened subchecks (ruleset captured,
/// mesh-scoped forward, no NAT, no unrestricted forward, no own-egress) —
/// folding the formerly bash-only check into the standard Rust orchestrator
/// so a `--node` run exercises it.
///
/// Runs after `exit_nat_lifecycle_validation` and before the relay/traffic
/// stages. This is a per-node posture check, so it applies to every node
/// regardless of role. Accepted only on an explicit `overall_ok: true`
/// (fail-closed). A macOS / Windows node is **reported-skipped** — named in
/// `blind_exit_dataplane_validation.reported_skips.json`, never a silent pass —
/// on the [`blind_exit_dataplane_runtime_implemented`] posture gate.
pub struct BlindExitDataplaneValidationStage;

impl OrchestrationStage for BlindExitDataplaneValidationStage {
    fn id(&self) -> StageId {
        StageId::BlindExitDataplaneValidation
    }
    fn name(&self) -> &str {
        "blind_exit_dataplane_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::ExitDemotionResidueValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[NodeRole::BlindExit]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        // Only nodes ASSIGNED the blind_exit role carry the blind_exit forward
        // chain to validate. Mirror the `blind_exit` deploy stage's role filter
        // (`BlindExitStage`): validating every node would fail-loud on a regular
        // exit / client that legitimately has no mesh-scoped forward rule. When
        // no node holds the role the stage is a no-op — the same topology that
        // makes the deploy stage skip.
        let aliases: Vec<String> = ctx
            .assignments
            .iter()
            .filter(|a| a.role == NodeRole::BlindExit)
            .map(|a| a.alias.clone())
            .collect();
        if aliases.is_empty() {
            // No blind_exit node in this topology — nothing to validate. Skipped
            // (not Passed) so the evidence does not promise a dataplane check
            // that never ran; mirrors the `blind_exit` deploy stage.
            return StageOutcome::Skipped;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for blind-exit-dataplane node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !blind_exit_dataplane_runtime_implemented(platform) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let shell = match adapter.shell_host() {
                Ok(shell) => shell,
                Err(e) => {
                    failures.push(format!("{alias}: shell host unavailable: {e}"));
                    continue;
                }
            };
            let daemon_path = match platform {
                VmGuestPlatform::Linux => LINUX_RUSTYNETD_PATH,
                VmGuestPlatform::Macos => MACOS_RUSTYNETD_PATH,
                VmGuestPlatform::Windows => WINDOWS_RUSTYNETD_PATH,
                _ => {
                    reported_skips.push((alias.clone(), format!("{platform:?}")));
                    continue;
                }
            };
            if let Err(e) = validate_linux_blind_exit_dataplane(&*shell, daemon_path, alias) {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips)
    }
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
        "stage": "blind_exit_dataplane_validation",
        "reported_skipped_blind_exit_dataplane": skipped,
        "reason": "Blind-exit dataplane check runs live on Linux through the Rust engine; \
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
                &["deb-1: blind exit dataplane check failed".into()],
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
        assert!(s.contains("blind_exit_dataplane_validation"));
    }

    #[test]
    fn non_blind_exit_assignments_skip_without_validating() {
        use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
        use std::collections::HashMap;
        // A topology with only exit + client (no blind_exit role) must SKIP —
        // returning before any adapter is touched (empty map proves it never
        // reaches validation) — instead of fail-closing on nodes that
        // legitimately carry no blind_exit forward chain. Regression for the
        // live-lab false failure unmasked once exit_demotion started passing.
        let mut ctx = OrchestrationContext {
            assignments: vec![
                NodeRoleAssignment {
                    alias: "exit-1".to_owned(),
                    role: NodeRole::Exit,
                },
                NodeRoleAssignment {
                    alias: "client-1".to_owned(),
                    role: NodeRole::Client,
                },
            ],
            adapters: HashMap::new(),
            source_archive: None,
            report_dir: std::env::temp_dir(),
            stage_outcomes: HashMap::new(),
            collected_pubkeys: HashMap::new(),
            network_id: "net".to_owned(),
            node_ids: HashMap::new(),
            ssh_allow_cidrs: String::new(),
            membership_snapshot: None,
            mesh_ips: HashMap::new(),
            endpoints: HashMap::new(),
            orchestrator_dialect: None,
        };
        assert_eq!(
            BlindExitDataplaneValidationStage.execute(&mut ctx),
            StageOutcome::Skipped
        );
    }
}
