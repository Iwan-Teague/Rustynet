#![allow(dead_code)]
use crate::vm_lab::orchestrator::adapter::node_adapter::RoleValidatorKind;
use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::append_stage_evidence_line;
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
        // A topology with no nodes validated NOTHING: a pass here would record
        // a green ledger row for an unexercised control — the vacuous-pass
        // false green (skip-semantics review F1). Skip so the run stays
        // Partial and the gap stays visible; never `Passed`.
        if aliases.is_empty() {
            return StageOutcome::Skipped(
                "no node assignments in this topology; nothing was validated".to_owned(),
            );
        }

        let mut failures: Vec<String> = Vec::new();
        let mut reported_skips: Vec<(String, String)> = Vec::new();
        // Aliases whose gossip-convergence validator actually ran and passed
        // (all four criteria met) — the witness names them so a PASS is never
        // backed by nothing.
        let mut validated: Vec<String> = Vec::new();
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
            match adapter.run_role_validator(
                RoleValidatorKind::GossipConvergence,
                expected_node_id,
                None,
            ) {
                Ok(()) => validated.push(alias.clone()),
                Err(e) => failures.push(format!("{alias}: {e}")),
            }
        }

        if !reported_skips.is_empty() {
            write_reported_skips_note(ctx, &reported_skips);
        }
        // QH-83: the witness is written on the single pass path and a write
        // failure fails the stage — an unwitnessed gossip-convergence pass
        // must never be recorded (the runner would demote it).
        match outcome_for(&failures, &reported_skips) {
            StageOutcome::Passed => {
                match write_gossip_convergence_witness(&ctx.report_dir, &validated) {
                    Ok(()) => StageOutcome::Passed,
                    Err(e) => StageOutcome::Failed(format!(
                        "gossip convergence witness write failed: {e}"
                    )),
                }
            }
            other => other,
        }
    }
}

/// Writes the QH-83 witness line for a gossip-convergence PASS: the validated
/// node count plus each alias whose four-criterion contract was actually
/// proven, so a bare PASS can never be recorded without the on-disk evidence
/// behind it. An unwritable witness fails the stage — fail closed.
fn write_gossip_convergence_witness(
    report_dir: &std::path::Path,
    validated: &[String],
) -> Result<(), String> {
    append_stage_evidence_line(
        report_dir,
        StageId::GossipConvergenceValidation.as_str(),
        &format!(
            "gossip_convergence=yes validated_nodes={} ({})",
            validated.len(),
            validated.join(",")
        ),
    )
}

/// A failure always wins. A run where every node was skipped is Skipped, never
/// Passed — an all-non-Linux topology must not read as gossip having converged.
fn outcome_for(failures: &[String], reported_skips: &[(String, String)]) -> StageOutcome {
    if !failures.is_empty() {
        StageOutcome::Failed(failures.join("; "))
    } else if !reported_skips.is_empty() {
        StageOutcome::Skipped(format!(
            "no node executed this validation; {} node(s) reported a runtime skip",
            reported_skips.len()
        ))
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
        assert!(
            matches!(
                outcome_for(&[], &[("mac-1".into(), "Macos".into())]),
                StageOutcome::Skipped(_)
            ),
            "expected a skip; got {:?}",
            outcome_for(&[], &[("mac-1".into(), "Macos".into())])
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

    /// The empty-assignments guard must SKIP, never PASS: with zero nodes the
    /// stage validated nothing, and a pass would record a green ledger row for
    /// an unexercised control (skip-semantics review F1's vacuous pass).
    /// Mutation caught: reverting the guard arm to `return StageOutcome::Passed;`
    /// (the empty-assignments-vacuous-pass mutation).
    #[test]
    fn empty_assignments_is_skipped_never_passed() {
        let mut ctx = OrchestrationContext::new(Vec::new(), std::env::temp_dir(), "net".to_owned());
        assert!(
            matches!(
                GossipConvergenceValidationStage.execute(&mut ctx),
                StageOutcome::Skipped(_)
            ),
            "an empty topology must skip, never pass; got {:?}",
            GossipConvergenceValidationStage.execute(&mut ctx)
        );
    }

    // QH-83: the pass witness must name the validated node count and the
    // aliases — a bare "pass" line would be appeasement, not evidence.
    // Mutation caught: dropping the witness write or demoting it to
    // best-effort.
    #[test]
    fn gossip_convergence_witness_line_names_the_validated_node_count() {
        let dir = std::env::temp_dir().join(format!(
            "gossip_witness_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_gossip_convergence_witness(&dir, &["deb-1".to_owned(), "deb-2".to_owned()])
            .expect("witness write");
        let log = std::fs::read_to_string(
            crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                &dir,
                StageId::GossipConvergenceValidation.as_str(),
            ),
        )
        .expect("stage log");
        assert!(log.contains("gossip_convergence=yes"), "{log}");
        assert!(log.contains("validated_nodes=2"), "{log}");
        assert!(log.contains("deb-1") && log.contains("deb-2"), "{log}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fail-closed check: a witness write that cannot land must surface as an
    /// error the execute path turns into `Failed` — never a silent pass.
    #[test]
    fn gossip_convergence_witness_write_failure_is_propagated() {
        let dir = std::env::temp_dir().join(format!(
            "gossip_witness_blocker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .subsec_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("test dir");
        std::fs::write(dir.join("logs"), b"not a directory").expect("blocker file");
        let err = write_gossip_convergence_witness(&dir, &["deb-1".to_owned()])
            .expect_err("witness write must fail when the logs path is a regular file");
        assert!(!err.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
