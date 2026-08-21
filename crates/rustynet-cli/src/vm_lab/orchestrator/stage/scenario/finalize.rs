//! Finalizer-side scenario-evidence evaluation (L1b,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §3.1.2).
//!
//! This is the bridge the native finalizer calls to layer INDEPENDENT
//! per-scenario re-derivation on top of the L0 structural pass — and the first
//! non-test caller of [`pass_certificate::evaluate`]. For each wired T5 control
//! that emitted a `scenario.v1` this run, it resolves the scenario to its
//! independently-defined contract (never the scenario's own assertion list) and
//! recomputes every required assertion from the raw witnesses. The finalizer
//! folds the result into the run's verdict: a scenario that does not prove out
//! DEMOTES the run even when it was structurally green, and the durable verdict
//! binds to the real contract digest + artifact map.
//!
//! Today the two local, in-process controls are wired — signed-bundle forgery
//! rejection and wrong-node substitution — and both are evaluated when present.
//! New controls join by adding their `(stage_id, assertion_id, recomputer)` to
//! [`wired_scenarios`].

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use crate::vm_lab::orchestrator::stage::negative_control::signed_bundle;

use super::artifact::ValidatedArtifact;
use super::pass_certificate::{self, Assessment, Recomputer};
use super::registry::ScenarioContractRegistry;
use super::schema::{AssertionRecord, ScenarioV1, scenario_v1_path};

/// Per-artifact byte budget for scenario evidence. A transcript is tiny; this is
/// a containment cap (an over-budget artifact is refused, never slurped), not a
/// real size limit.
const MAX_ARTIFACT_BYTES: u64 = 1 << 20;

/// A recomputer for one required assertion id, as a plain fn pointer so the
/// finalizer can borrow it into the `&Recomputer` map [`pass_certificate::evaluate`]
/// expects.
type RecomputerFn = fn(&AssertionRecord, &[ValidatedArtifact]) -> Result<(), String>;

/// The wired T5 controls: `(stage_id, assertion_id, recomputer)`. New controls
/// register here when their `scenario.v1` emission + recomputer land.
fn wired_scenarios() -> Vec<(&'static str, &'static str, RecomputerFn)> {
    vec![
        (
            signed_bundle::SIGNED_BUNDLE_STAGE_ID,
            signed_bundle::SIGNED_BUNDLE_ASSERTION_ID,
            signed_bundle::recompute_signed_bundle_forgery_rejected,
        ),
        (
            signed_bundle::WRONG_NODE_STAGE_ID,
            signed_bundle::WRONG_NODE_ASSERTION_ID,
            signed_bundle::recompute_wrong_node_substitution_rejected,
        ),
    ]
}

/// The aggregate independent evaluation of EVERY wired scenario present this run.
pub struct WiredScenarioEval {
    /// True iff every present wired scenario proved out. A single non-pass
    /// demotes the run.
    pub all_passed: bool,
    /// Reason codes from the FIRST non-pass (a `ReasonCode` token, or `failed`),
    /// empty when all passed.
    pub reason_codes: Vec<String>,
    /// Human detail of the first non-pass, prefixed with its stage id (never a
    /// secret), empty when all passed.
    pub detail: String,
    /// A digest binding the SET of contracts evaluated (sha256 over the sorted
    /// per-scenario contract digests), for the durable verdict.
    pub contract_digest: String,
    /// Union of every evaluated scenario's `reference -> sha256`, for the
    /// monitor's staleness cross-check.
    pub artifact_digests: BTreeMap<String, String>,
}

/// The `(reason_codes, detail)` an assessment contributes to a demotion.
fn assessment_reason(assessment: &Assessment) -> (Vec<String>, String) {
    match assessment {
        Assessment::Passed(_) => (Vec::new(), String::new()),
        Assessment::NotProven(reason, detail) => (vec![reason.as_str().to_owned()], detail.clone()),
        Assessment::Failed(detail) => (vec!["failed".to_owned()], detail.clone()),
    }
}

/// Evaluate the wired scenario controls' emitted `scenario.v1` under
/// `report_dir`. Returns:
///   * `Ok(None)` — no wired scenario emitted this run (the control did not run,
///     e.g. the negative-control suite was not opted in);
///   * `Ok(Some(eval))` — a scenario resolved to its contract and was
///     independently assessed;
///   * `Err(_)` — a scenario document is present but could not be bound to its
///     contract (unknown stage / digest mismatch), or its evidence was
///     unreadable: an integrity fault the finalizer treats as an evidence error
///     (fail closed).
///
/// Evaluates ALL wired scenarios present this run — the negative-control suite
/// runs both local controls, so both emit and BOTH must be independently
/// verified (evaluating only the first would leave the second present-but-
/// unverified). The run passes only if every present scenario proves out.
pub fn evaluate_wired_scenarios(
    report_dir: &Path,
    run_instance_id: &str,
) -> Result<Option<WiredScenarioEval>, String> {
    let mut evaluated = 0usize;
    let mut all_passed = true;
    let mut reason_codes: Vec<String> = Vec::new();
    let mut detail = String::new();
    let mut contract_digests: Vec<String> = Vec::new();
    let mut artifact_digests: BTreeMap<String, String> = BTreeMap::new();

    for (stage_id, assertion_id, recompute) in wired_scenarios() {
        let path = scenario_v1_path(report_dir, stage_id);
        if !path.exists() {
            continue;
        }
        evaluated += 1;
        let body =
            std::fs::read_to_string(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
        let scenario =
            ScenarioV1::parse(&body).map_err(|e| format!("parse {}: {e}", path.display()))?;

        // Resolve against the INDEPENDENT registry: an unknown stage or a digest
        // mismatch is an integrity fault, surfaced as an error (fail closed).
        let registry = ScenarioContractRegistry::canonical();
        let registered = registry
            .resolve_for(&scenario)
            .map_err(|e| format!("resolve contract for {stage_id}: {e}"))?;

        // Borrow the fn pointer as a `&Recomputer` (a fn implements `Fn`).
        let recompute: RecomputerFn = recompute;
        let mut recomputers: HashMap<&str, &Recomputer<'_>> = HashMap::new();
        recomputers.insert(assertion_id, &recompute);

        let assessment = pass_certificate::evaluate(
            report_dir,
            &scenario,
            &registered.contract().evidence,
            registered.contract_digest(),
            run_instance_id,
            MAX_ARTIFACT_BYTES,
            &recomputers,
        );

        contract_digests.push(registered.contract_digest().to_owned());
        for a in &scenario.assertions {
            for aref in &a.evidence {
                artifact_digests.insert(aref.reference.clone(), aref.sha256.clone());
            }
        }
        if !assessment.is_pass() && all_passed {
            // Record the FIRST non-pass (subsequent ones do not change the
            // demotion, only the primary reason).
            all_passed = false;
            let (rc, d) = assessment_reason(&assessment);
            reason_codes = rc;
            detail = format!("{stage_id}: {d}");
        }
    }

    if evaluated == 0 {
        return Ok(None);
    }
    // Bind the verdict to the SET of contracts evaluated (order-independent).
    contract_digests.sort();
    let contract_digest = crate::vm_lab::sha256_hex_bytes(contract_digests.join("\n").as_bytes());

    Ok(Some(WiredScenarioEval {
        all_passed,
        reason_codes,
        detail,
        contract_digest,
        artifact_digests,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::error::StageOutcome;

    /// Emit exactly what the signed-bundle control's `execute()` would, under a
    /// fresh report root, bound to `run_id`.
    fn emit_signed_bundle(report_root: &Path, run_id: &str) {
        let control_dir = report_root
            .join("negative_control")
            .join(signed_bundle::SIGNED_BUNDLE_STAGE_ID);
        assert!(matches!(
            signed_bundle::run_signed_bundle_control(&control_dir),
            StageOutcome::Passed
        ));
        signed_bundle::emit_signed_bundle_scenario_v1(report_root, &control_dir, run_id, true)
            .expect("emit");
    }

    /// Emit exactly what the wrong-node control's `execute()` would.
    fn emit_wrong_node(report_root: &Path, run_id: &str) {
        let control_dir = report_root
            .join("negative_control")
            .join(signed_bundle::WRONG_NODE_STAGE_ID);
        assert!(matches!(
            signed_bundle::run_wrong_node_control(&control_dir),
            StageOutcome::Passed
        ));
        signed_bundle::emit_wrong_node_scenario_v1(report_root, &control_dir, run_id, true)
            .expect("emit");
    }

    #[test]
    fn absent_scenario_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(
            evaluate_wired_scenarios(tmp.path(), "run-1")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_wired_control_emission_resolves_and_recomputes_to_a_pass() {
        let report = tempfile::tempdir().unwrap();
        let run_id = "0123456789abcdef0123456789abcdef";
        emit_signed_bundle(report.path(), run_id);

        let eval = evaluate_wired_scenarios(report.path(), run_id)
            .unwrap()
            .expect("scenario present");
        assert!(
            eval.all_passed,
            "independent evaluate must pass: {}",
            eval.detail
        );
        assert_eq!(eval.contract_digest.len(), 64, "sha-256 hex");
        assert!(
            !eval.artifact_digests.is_empty(),
            "the transcript artifact must be bound"
        );
    }

    #[test]
    fn both_controls_present_are_both_evaluated_and_pass() {
        // The negative-control suite emits BOTH local controls; both must be
        // evaluated (not just the first), and the aggregate binds both artifacts.
        let report = tempfile::tempdir().unwrap();
        let run_id = "0123456789abcdef0123456789abcdef";
        emit_signed_bundle(report.path(), run_id);
        emit_wrong_node(report.path(), run_id);
        let eval = evaluate_wired_scenarios(report.path(), run_id)
            .unwrap()
            .expect("scenarios present");
        assert!(eval.all_passed, "both must prove out: {}", eval.detail);
        // Both transcripts bound.
        assert!(
            eval.artifact_digests
                .keys()
                .any(|k| k.ends_with(signed_bundle::SIGNED_BUNDLE_TRANSCRIPT_FILE)),
            "signed-bundle transcript bound"
        );
        assert!(
            eval.artifact_digests
                .keys()
                .any(|k| k.ends_with(signed_bundle::WRONG_NODE_TRANSCRIPT_FILE)),
            "wrong-node transcript bound"
        );
    }

    #[test]
    fn one_failing_control_demotes_the_aggregate() {
        // Two controls present; the wrong-node scenario is bound to the WRONG
        // generation → its recompute is stale → the aggregate does not pass even
        // though the signed-bundle scenario is clean.
        let report = tempfile::tempdir().unwrap();
        let run_id = "0123456789abcdef0123456789abcdef";
        emit_signed_bundle(report.path(), run_id);
        // Wrong-node emitted for a different generation.
        emit_wrong_node(report.path(), "ffffffffffffffffffffffffffffffff");
        let eval = evaluate_wired_scenarios(report.path(), run_id)
            .unwrap()
            .expect("scenarios present");
        assert!(!eval.all_passed);
        assert!(
            eval.detail.contains(signed_bundle::WRONG_NODE_STAGE_ID),
            "the demotion names the failing stage: {}",
            eval.detail
        );
    }

    #[test]
    fn a_wrong_generation_is_not_a_pass() {
        // The scenario was minted for one run; the finalizer expects a different
        // generation → stale evidence, never a pass.
        let report = tempfile::tempdir().unwrap();
        emit_signed_bundle(report.path(), "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        let eval = evaluate_wired_scenarios(report.path(), "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            .unwrap()
            .expect("scenario present");
        assert!(!eval.all_passed);
    }

    #[test]
    fn a_tampered_contract_digest_is_an_integrity_error() {
        // A scenario whose contract_digest does not match the registry cannot be
        // bound — the finalizer treats this as an error (fail closed), never a
        // silent pass.
        let report = tempfile::tempdir().unwrap();
        let run_id = "0123456789abcdef0123456789abcdef";
        emit_signed_bundle(report.path(), run_id);
        let path = scenario_v1_path(report.path(), signed_bundle::SIGNED_BUNDLE_STAGE_ID);
        let mut scenario = ScenarioV1::parse(&std::fs::read_to_string(&path).unwrap()).unwrap();
        scenario.contract_digest = "0".repeat(64);
        std::fs::write(&path, scenario.to_json_pretty().unwrap()).unwrap();
        assert!(evaluate_wired_scenarios(report.path(), run_id).is_err());
    }
}
