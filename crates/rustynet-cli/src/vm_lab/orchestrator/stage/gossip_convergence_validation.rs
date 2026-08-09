#![allow(dead_code)]
use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};

const REPORTED_SKIPS_FILENAME: &str = "gossip_convergence_validation.reported_skips.json";

/// Prove every Linux node's gossip actually converges: it is registered as a
/// peer, it has verified at least one signed bundle from a peer, its identity
/// does not mismatch, and it is rejecting nothing as an unknown source.
///
/// This is the regression guard for the producer-alignment work. Before it, a
/// node publishing its WireGuard public key instead of its derived gossip
/// verifying key produced a mesh where every peer rejected it forever —
/// `gossip_reject_unknown_source`, `peers=0` — while every other stage stayed
/// green, because nothing asserted gossip convergence at all.
///
/// Accepted only on the full four-criterion contract (fail-closed); a missing
/// status field fails rather than skips. A macOS / Windows node is
/// **reported-skipped** — named in the JSON note beside the report, never a
/// silent pass — because gossip is unix-only.
pub struct GossipConvergenceValidationStage;

impl OrchestrationStage for GossipConvergenceValidationStage {
    fn id(&self) -> StageId {
        StageId::GossipConvergenceValidation
    }
    fn name(&self) -> &str {
        "gossip_convergence_validation"
    }
    fn dependencies(&self) -> &[StageId] {
        &[StageId::MeshStatusValidation]
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        &[]
    }
    fn fanout(&self) -> StageFanout {
        StageFanout::PerNode
    }

    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        let aliases: Vec<String> = ctx.assignments.iter().map(|a| a.alias.clone()).collect();
        if aliases.is_empty() {
            return StageOutcome::Passed;
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        for alias in &aliases {
            let adapter = match ctx.adapters.get(alias.as_str()) {
                Some(adapter) => adapter,
                None => {
                    failures.push(format!("{alias}: no adapter for gossip-convergence node"));
                    continue;
                }
            };
            let platform = adapter.platform();
            if !adapter.supports_role_validator(RoleValidatorKind::GossipConvergence) {
                reported_skips.push((alias.clone(), format!("{platform:?}")));
                continue;
            }
            let expected_node_id = ctx.node_ids.get(alias.as_str()).map(String::as_str);
            if let Err(e) =
                adapter.run_role_validator(RoleValidatorKind::GossipConvergence, expected_node_id)
            {
                failures.push(format!("{alias}: {e}"));
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        outcome_for(&failures, &reported_skips)
    }
}

/// A failure always wins. A run where every node was skipped is Skipped, never
/// Passed — an all-non-Linux topology must not read as gossip having converged.
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
        "stage": "gossip_convergence_validation",
        "reported_skipped_gossip_convergence": skipped,
        "reason": "Gossip transport is unix-only and the lab macOS bootstrap never mints \
                   a signing secret, so convergence runs live on Linux only; non-Linux \
                   nodes are reported-skipped (named, never a silent pass)",
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
    fn outcome_all_skipped_is_skipped_never_passed() {
        // An all-macOS/Windows topology must not read as "gossip converged".
        assert_eq!(
            outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
            StageOutcome::Skipped
        );
    }

    #[test]
    fn outcome_failure_wins_over_skips() {
        assert!(matches!(
            outcome_for(
                &["deb-1: gossip convergence: gossip_peers_registered=0".into()],
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
        assert!(s.contains("gossip_convergence_validation"));
    }
}
