//! Cross-orchestrator parity diff (W5.5 evidence harness).
//!
//! Both the bash and the Rust orchestrators are expected to converge on the
//! same `LiveLabRunReport`-shaped JSON (`parity_input.json`) for the same
//! lab. This module produces a deterministic, machine-readable diff between
//! two such reports so the operator can prove parity without manual
//! eyeballing.
//!
//! The schema deliberately surfaces every dimension §W5.5 calls out:
//! - identical stage ID list (no missing/extra stages),
//! - identical pass/fail per stage,
//! - identical overall exit code,
//! - matching per-stage `outcome`,
//! - matching peer/validator counts.
//!
//! Live runs that produce the input reports are gated on a real lab; this
//! module is intentionally pure-data so it has full unit coverage.

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::report::{
    LiveLabRunReport, NodeStatus, RunStatus, StageOutcomeRecord, StageReport, ValidatorResult,
};
use crate::vm_lab::orchestrator::stage::StageId;

/// Build a `LiveLabRunReport` from the `(StageId, StageOutcome)` list
/// produced by `StateMachineRunner::run`, plus the `OrchestrationContext`
/// that holds the role assignments.
///
/// Validator results are not yet collected into the context (W3.2 wires
/// stage-level outcomes only); per-node `validator_results` therefore
/// ships empty until follow-up work threads `ValidatorReport` through
/// the context. The parity diff handles 0 vs 0 as a match, which is the
/// correct semantics until both orchestrators emit validator detail.
pub fn build_live_lab_run_report(
    run_id: String,
    timestamp_utc: String,
    ctx: &OrchestrationContext,
    results: &[(StageId, StageOutcome)],
) -> LiveLabRunReport {
    let stages: Vec<StageReport> = results
        .iter()
        .map(|(id, outcome)| {
            let (rec, error_detail) = match outcome {
                StageOutcome::Passed => (StageOutcomeRecord::Passed, None),
                StageOutcome::Skipped => (StageOutcomeRecord::Skipped, None),
                StageOutcome::Failed(msg) => (StageOutcomeRecord::Failed, Some(msg.clone())),
            };
            StageReport {
                stage_id: id.as_str().to_owned(),
                stage_name: id.as_str().to_owned(),
                outcome: rec,
                duration_ms: 0,
                error_detail,
            }
        })
        .collect();

    let any_failed = stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::Failed);
    let any_skipped = stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::Skipped);
    let overall_status = if any_failed {
        RunStatus::Failed
    } else if any_skipped {
        RunStatus::Partial
    } else {
        RunStatus::Passed
    };

    // Per-node validator detail is recorded by ValidateBaselineRuntime to
    // `{report_dir}/validator_results.json`. Read it back so node_statuses
    // carries the actual per-op pass/fail instead of an empty list (which made
    // parity's validator comparison a vacuous 0-vs-0 match). Absent/unparseable
    // file → empty, matching prior behaviour.
    let validator_results: HashMap<String, Vec<ValidatorResult>> = {
        let path = ctx.report_dir.join("validator_results.json");
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    };

    let mut node_statuses: HashMap<String, NodeStatus> = HashMap::new();
    for assignment in &ctx.assignments {
        let platform = ctx.adapters.get(&assignment.alias).map_or_else(
            || "unknown".to_owned(),
            |a| format!("{:?}", a.platform()).to_lowercase(),
        );
        node_statuses.insert(
            assignment.alias.clone(),
            NodeStatus {
                alias: assignment.alias.clone(),
                platform,
                role: assignment.role.as_str().to_owned(),
                validator_results: validator_results
                    .get(&assignment.alias)
                    .cloned()
                    .unwrap_or_default(),
            },
        );
    }

    LiveLabRunReport {
        run_id,
        timestamp_utc,
        overall_status,
        stages,
        node_statuses,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ParityDiff {
    /// `true` iff every dimension matches: stage list, per-stage outcome,
    /// overall status, node count, validator pass count.
    pub overall_parity_pass: bool,

    pub overall_status_match: bool,
    pub overall_status_left: RunStatus,
    pub overall_status_right: RunStatus,

    /// One entry per stage that appears in either report. Order is the
    /// union of left's order followed by any right-only stages, preserving
    /// determinism for repeated diffs.
    pub stages: Vec<StageParityEntry>,

    /// Stage IDs present on left but absent on right.
    pub stages_only_in_left: Vec<String>,
    /// Stage IDs present on right but absent on left.
    pub stages_only_in_right: Vec<String>,

    pub node_count_match: bool,
    pub node_count_left: usize,
    pub node_count_right: usize,

    pub validator_pass_count_match: bool,
    pub validator_pass_count_left: usize,
    pub validator_pass_count_right: usize,

    pub validator_total_count_match: bool,
    pub validator_total_count_left: usize,
    pub validator_total_count_right: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StageParityEntry {
    pub stage_id: String,
    pub left_outcome: Option<StageOutcomeRecord>,
    pub right_outcome: Option<StageOutcomeRecord>,
    pub matches: bool,
}

/// Count validator passes across all node statuses.
fn count_validator_results(report: &LiveLabRunReport) -> (usize, usize) {
    let mut total = 0usize;
    let mut passed = 0usize;
    for node in report.node_statuses.values() {
        for v in &node.validator_results {
            total += 1;
            if v.passed {
                passed += 1;
            }
        }
    }
    (passed, total)
}

/// Return the per-stage diff between two reports.
///
/// `left` is conventionally the legacy bash orchestrator's report and
/// `right` the Rust-native orchestrator's, but the function is symmetric
/// in semantics: an empty diff means full parity in either direction.
pub fn diff_live_lab_reports(left: &LiveLabRunReport, right: &LiveLabRunReport) -> ParityDiff {
    let left_by_id: BTreeMap<&str, &StageReport> = left
        .stages
        .iter()
        .map(|s| (s.stage_id.as_str(), s))
        .collect();
    let right_by_id: BTreeMap<&str, &StageReport> = right
        .stages
        .iter()
        .map(|s| (s.stage_id.as_str(), s))
        .collect();

    let mut stages: Vec<StageParityEntry> = Vec::new();
    // Walk left in order, then append right-only entries in right's order.
    for s in &left.stages {
        let left_outcome = Some(s.outcome.clone());
        let right_outcome = right_by_id
            .get(s.stage_id.as_str())
            .map(|r| r.outcome.clone());
        let matches = right_outcome.as_ref().is_some_and(|ro| ro == &s.outcome);
        stages.push(StageParityEntry {
            stage_id: s.stage_id.clone(),
            left_outcome,
            right_outcome,
            matches,
        });
    }
    for s in &right.stages {
        if !left_by_id.contains_key(s.stage_id.as_str()) {
            stages.push(StageParityEntry {
                stage_id: s.stage_id.clone(),
                left_outcome: None,
                right_outcome: Some(s.outcome.clone()),
                matches: false,
            });
        }
    }

    let stages_only_in_left: Vec<String> = left
        .stages
        .iter()
        .filter(|s| !right_by_id.contains_key(s.stage_id.as_str()))
        .map(|s| s.stage_id.clone())
        .collect();
    let stages_only_in_right: Vec<String> = right
        .stages
        .iter()
        .filter(|s| !left_by_id.contains_key(s.stage_id.as_str()))
        .map(|s| s.stage_id.clone())
        .collect();

    let overall_status_match = left.overall_status == right.overall_status;

    let node_count_left = left.node_statuses.len();
    let node_count_right = right.node_statuses.len();
    let node_count_match = node_count_left == node_count_right;

    let (vp_left, vt_left) = count_validator_results(left);
    let (vp_right, vt_right) = count_validator_results(right);
    let validator_pass_count_match = vp_left == vp_right;
    let validator_total_count_match = vt_left == vt_right;

    let stages_match_all = stages_only_in_left.is_empty()
        && stages_only_in_right.is_empty()
        && stages.iter().all(|e| e.matches);

    let overall_parity_pass = overall_status_match
        && stages_match_all
        && node_count_match
        && validator_pass_count_match
        && validator_total_count_match;

    ParityDiff {
        overall_parity_pass,
        overall_status_match,
        overall_status_left: left.overall_status.clone(),
        overall_status_right: right.overall_status.clone(),
        stages,
        stages_only_in_left,
        stages_only_in_right,
        node_count_match,
        node_count_left,
        node_count_right,
        validator_pass_count_match,
        validator_pass_count_left: vp_left,
        validator_pass_count_right: vp_right,
        validator_total_count_match,
        validator_total_count_left: vt_left,
        validator_total_count_right: vt_right,
    }
}

/// Canonicalize a stage ID so the bash and Rust dialects — which name the
/// same logical work differently by design — compare equal under functional
/// parity. Identity for any ID without a known alias (including all 8 stage
/// IDs the two dialects already share verbatim: `preflight`,
/// `prepare_source_archive`, `verify_ssh_reachability`, `cleanup_hosts`,
/// `bootstrap_hosts`, `collect_pubkeys`, `enforce_baseline_runtime`,
/// `validate_baseline_runtime`).
///
/// This table is the bridge that makes cross-dialect parity satisfiable at
/// all. [`diff_live_lab_reports`] (strict) requires byte-identical stage-ID
/// sets, which the two orchestrators cannot produce because they name their
/// stages differently; [`diff_live_lab_reports_functional`] maps both reports
/// through this table and compares the shared logical work.
pub fn canonical_stage_id(stage_id: &str) -> &str {
    match stage_id {
        // bash dialect -> canonical (Rust `StageId`) name.
        "membership_setup" => "membership_init",
        "distribute_membership_state" => "distribute_membership",
        "issue_and_distribute_assignments" => "distribute_assignments",
        "issue_and_distribute_traversal" => "distribute_traversal",
        "issue_and_distribute_dns_zone" => "distribute_dns_zone",
        // Everything else (the 8 shared IDs + any dialect-only stage) is its
        // own canonical form.
        other => other,
    }
}

/// Functional/outcome parity between two reports whose orchestrators use
/// DIFFERENT stage-ID vocabularies (bash vs Rust dialect).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FunctionalParityDiff {
    /// `true` iff functional/outcome parity holds: at least one shared
    /// (canonicalized) stage exists AND every shared stage has the same
    /// outcome on both sides AND the overall status matches AND the node
    /// count matches. Validator pass/total counts are reported below but are
    /// NOT part of this verdict — the two dialects legitimately run different
    /// validator *sets*, and whether baseline validation passed is already
    /// captured by the shared `validate_baseline_runtime` stage outcome.
    pub overall_functional_parity_pass: bool,

    pub overall_status_match: bool,
    pub overall_status_left: RunStatus,
    pub overall_status_right: RunStatus,

    /// One entry per canonical stage ID present on BOTH sides, with the
    /// outcome each dialect recorded for it.
    pub shared_stages: Vec<StageParityEntry>,
    /// Size of the shared (intersection) stage set. `0` forces
    /// `overall_functional_parity_pass = false` (fail-closed: a zero-overlap
    /// comparison proves nothing and must not read as a pass).
    pub shared_stage_count: usize,

    /// Canonical stage IDs present only on one side — reported for visibility
    /// but NOT a parity failure (the dialects legitimately run
    /// dialect-specific stages such as bash `prime_remote_access` or Rust
    /// `traffic_test_matrix`).
    pub stages_only_in_left: Vec<String>,
    pub stages_only_in_right: Vec<String>,

    pub node_count_match: bool,
    pub node_count_left: usize,
    pub node_count_right: usize,

    // Informational only (see `overall_functional_parity_pass` doc).
    pub validator_pass_count_match: bool,
    pub validator_pass_count_left: usize,
    pub validator_pass_count_right: usize,
    pub validator_total_count_match: bool,
    pub validator_total_count_left: usize,
    pub validator_total_count_right: usize,
}

/// Functional/outcome parity between two reports whose orchestrators use
/// DIFFERENT stage-ID vocabularies (bash vs Rust dialect).
///
/// Unlike [`diff_live_lab_reports`] (which requires byte-identical stage-ID
/// sets and is therefore unsatisfiable across dialects), this normalizes both
/// reports through [`canonical_stage_id`] and compares only the shared logical
/// work: overall status, per-shared-stage outcome, and node count. Stages that
/// exist on only one side are surfaced but do not fail parity.
///
/// Fail-closed: if the two reports share ZERO canonical stages, parity is
/// FALSE — a zero-overlap comparison proves nothing and must not read as a
/// pass.
pub fn diff_live_lab_reports_functional(
    left: &LiveLabRunReport,
    right: &LiveLabRunReport,
) -> FunctionalParityDiff {
    let left_by_id: BTreeMap<&str, &StageReport> = left
        .stages
        .iter()
        .map(|s| (canonical_stage_id(s.stage_id.as_str()), s))
        .collect();
    let right_by_id: BTreeMap<&str, &StageReport> = right
        .stages
        .iter()
        .map(|s| (canonical_stage_id(s.stage_id.as_str()), s))
        .collect();

    // Shared canonical stage IDs (intersection), walked in left's stage order
    // and de-duplicated so a canonical ID is compared once.
    let mut shared_stages: Vec<StageParityEntry> = Vec::new();
    let mut seen: std::collections::BTreeSet<&str> = std::collections::BTreeSet::new();
    for s in &left.stages {
        let cid = canonical_stage_id(s.stage_id.as_str());
        if !seen.insert(cid) {
            continue;
        }
        if let Some(r) = right_by_id.get(cid) {
            let matches = r.outcome == s.outcome;
            shared_stages.push(StageParityEntry {
                stage_id: cid.to_owned(),
                left_outcome: Some(s.outcome.clone()),
                right_outcome: Some(r.outcome.clone()),
                matches,
            });
        }
    }

    let stages_only_in_left: Vec<String> = left_by_id
        .keys()
        .filter(|k| !right_by_id.contains_key(*k))
        .map(|k| (*k).to_owned())
        .collect();
    let stages_only_in_right: Vec<String> = right_by_id
        .keys()
        .filter(|k| !left_by_id.contains_key(*k))
        .map(|k| (*k).to_owned())
        .collect();

    let overall_status_match = left.overall_status == right.overall_status;

    let node_count_left = left.node_statuses.len();
    let node_count_right = right.node_statuses.len();
    let node_count_match = node_count_left == node_count_right;

    let (vp_left, vt_left) = count_validator_results(left);
    let (vp_right, vt_right) = count_validator_results(right);
    let validator_pass_count_match = vp_left == vp_right;
    let validator_total_count_match = vt_left == vt_right;

    let shared_stage_count = shared_stages.len();
    let shared_stages_all_match = shared_stages.iter().all(|e| e.matches);

    let overall_functional_parity_pass = shared_stage_count > 0
        && shared_stages_all_match
        && overall_status_match
        && node_count_match;

    FunctionalParityDiff {
        overall_functional_parity_pass,
        overall_status_match,
        overall_status_left: left.overall_status.clone(),
        overall_status_right: right.overall_status.clone(),
        shared_stages,
        shared_stage_count,
        stages_only_in_left,
        stages_only_in_right,
        node_count_match,
        node_count_left,
        node_count_right,
        validator_pass_count_match,
        validator_pass_count_left: vp_left,
        validator_pass_count_right: vp_right,
        validator_total_count_match,
        validator_total_count_left: vt_left,
        validator_total_count_right: vt_right,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::report::{NodeStatus, ValidatorResult};
    use std::collections::HashMap;

    fn stage(id: &str, outcome: StageOutcomeRecord) -> StageReport {
        StageReport {
            stage_id: id.to_owned(),
            stage_name: id.to_owned(),
            outcome,
            duration_ms: 0,
            error_detail: None,
        }
    }

    fn node(alias: &str, validators: Vec<(&str, bool)>) -> (String, NodeStatus) {
        let validator_results = validators
            .into_iter()
            .map(|(op, passed)| ValidatorResult {
                op: op.to_owned(),
                passed,
                summary: String::new(),
            })
            .collect();
        (
            alias.to_owned(),
            NodeStatus {
                alias: alias.to_owned(),
                platform: "linux".to_owned(),
                role: "client".to_owned(),
                validator_results,
            },
        )
    }

    fn report(
        run_id: &str,
        overall: RunStatus,
        stages_in: Vec<StageReport>,
        nodes: Vec<(String, NodeStatus)>,
    ) -> LiveLabRunReport {
        LiveLabRunReport {
            run_id: run_id.to_owned(),
            timestamp_utc: "2026-04-29T00:00:00Z".to_owned(),
            overall_status: overall,
            stages: stages_in,
            node_statuses: nodes.into_iter().collect::<HashMap<_, _>>(),
        }
    }

    #[test]
    fn full_parity_two_identical_reports() {
        let stages_a = vec![
            stage("preflight", StageOutcomeRecord::Passed),
            stage("install", StageOutcomeRecord::Passed),
        ];
        let stages_b = stages_a.clone();
        let a = report(
            "a",
            RunStatus::Passed,
            stages_a,
            vec![node("n1", vec![("acl", true)])],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            stages_b,
            vec![node("n1", vec![("acl", true)])],
        );
        let diff = diff_live_lab_reports(&a, &b);
        assert!(diff.overall_parity_pass, "{diff:#?}");
        assert!(diff.stages.iter().all(|e| e.matches));
        assert!(diff.stages_only_in_left.is_empty());
        assert!(diff.stages_only_in_right.is_empty());
    }

    #[test]
    fn detects_overall_status_drift() {
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report("a", RunStatus::Passed, s.clone(), vec![]);
        let b = report("b", RunStatus::Failed, s, vec![]);
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        assert!(!diff.overall_status_match);
        assert_eq!(diff.overall_status_left, RunStatus::Passed);
        assert_eq!(diff.overall_status_right, RunStatus::Failed);
    }

    #[test]
    fn detects_per_stage_outcome_drift() {
        let a = report(
            "a",
            RunStatus::Passed,
            vec![
                stage("preflight", StageOutcomeRecord::Passed),
                stage("install", StageOutcomeRecord::Passed),
            ],
            vec![],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            vec![
                stage("preflight", StageOutcomeRecord::Passed),
                stage("install", StageOutcomeRecord::Failed),
            ],
            vec![],
        );
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        let install_entry = diff
            .stages
            .iter()
            .find(|e| e.stage_id == "install")
            .expect("install stage entry must exist");
        assert!(!install_entry.matches);
        assert_eq!(install_entry.left_outcome, Some(StageOutcomeRecord::Passed));
        assert_eq!(
            install_entry.right_outcome,
            Some(StageOutcomeRecord::Failed)
        );
    }

    #[test]
    fn detects_stage_only_on_one_side() {
        let a = report(
            "a",
            RunStatus::Passed,
            vec![stage("preflight", StageOutcomeRecord::Passed)],
            vec![],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            vec![
                stage("preflight", StageOutcomeRecord::Passed),
                stage("extra", StageOutcomeRecord::Passed),
            ],
            vec![],
        );
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        assert_eq!(diff.stages_only_in_right, vec!["extra".to_owned()]);
        assert!(diff.stages_only_in_left.is_empty());
        let extra_entry = diff
            .stages
            .iter()
            .find(|e| e.stage_id == "extra")
            .expect("extra stage entry must exist");
        assert!(!extra_entry.matches);
        assert!(extra_entry.left_outcome.is_none());
    }

    #[test]
    fn detects_node_count_drift() {
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report(
            "a",
            RunStatus::Passed,
            s.clone(),
            vec![node("n1", vec![]), node("n2", vec![])],
        );
        let b = report("b", RunStatus::Passed, s, vec![node("n1", vec![])]);
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        assert!(!diff.node_count_match);
        assert_eq!(diff.node_count_left, 2);
        assert_eq!(diff.node_count_right, 1);
    }

    #[test]
    fn detects_validator_pass_count_drift() {
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report(
            "a",
            RunStatus::Passed,
            s.clone(),
            vec![node("n1", vec![("acl", true), ("dns", true)])],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            s,
            vec![node("n1", vec![("acl", true), ("dns", false)])],
        );
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        assert!(!diff.validator_pass_count_match);
        assert_eq!(diff.validator_pass_count_left, 2);
        assert_eq!(diff.validator_pass_count_right, 1);
        // Total is identical (both ran 2 validators), so total-count match is true.
        assert!(diff.validator_total_count_match);
    }

    #[test]
    fn detects_validator_total_count_drift() {
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report(
            "a",
            RunStatus::Passed,
            s.clone(),
            vec![node("n1", vec![("acl", true)])],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            s,
            vec![node("n1", vec![("acl", true), ("dns", true)])],
        );
        let diff = diff_live_lab_reports(&a, &b);
        assert!(!diff.overall_parity_pass);
        assert!(!diff.validator_total_count_match);
        assert_eq!(diff.validator_total_count_left, 1);
        assert_eq!(diff.validator_total_count_right, 2);
    }

    #[test]
    fn parity_diff_is_serializable_json() {
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report("a", RunStatus::Passed, s.clone(), vec![]);
        let b = report("b", RunStatus::Passed, s, vec![]);
        let diff = diff_live_lab_reports(&a, &b);
        let json = serde_json::to_string(&diff).expect("ParityDiff must serialize");
        assert!(json.contains("\"overall_parity_pass\":true"));
        let round: ParityDiff = serde_json::from_str(&json).expect("ParityDiff must round-trip");
        assert_eq!(round, diff);
    }

    #[test]
    fn overall_parity_pass_requires_all_dimensions() {
        // Same stages but different node counts → parity must fail.
        let s = vec![stage("preflight", StageOutcomeRecord::Passed)];
        let a = report("a", RunStatus::Passed, s.clone(), vec![]);
        let b = report("b", RunStatus::Passed, s, vec![node("n1", vec![])]);
        let diff = diff_live_lab_reports(&a, &b);
        assert!(diff.overall_status_match);
        assert!(diff.stages.iter().all(|e| e.matches));
        assert!(!diff.node_count_match);
        assert!(!diff.overall_parity_pass);
    }

    // ---- functional/outcome parity (cross-dialect) ----

    #[test]
    fn canonical_stage_id_maps_bash_aliases_and_is_identity_otherwise() {
        // The 5 known bash-dialect aliases canonicalize to the Rust names.
        assert_eq!(canonical_stage_id("membership_setup"), "membership_init");
        assert_eq!(
            canonical_stage_id("distribute_membership_state"),
            "distribute_membership"
        );
        assert_eq!(
            canonical_stage_id("issue_and_distribute_assignments"),
            "distribute_assignments"
        );
        assert_eq!(
            canonical_stage_id("issue_and_distribute_traversal"),
            "distribute_traversal"
        );
        assert_eq!(
            canonical_stage_id("issue_and_distribute_dns_zone"),
            "distribute_dns_zone"
        );
        // Shared IDs + dialect-only stages are their own canonical form.
        assert_eq!(canonical_stage_id("bootstrap_hosts"), "bootstrap_hosts");
        assert_eq!(
            canonical_stage_id("traffic_test_matrix"),
            "traffic_test_matrix"
        );
        assert_eq!(
            canonical_stage_id("prime_remote_access"),
            "prime_remote_access"
        );
    }

    #[test]
    fn functional_parity_passes_across_dialects_with_matching_outcomes() {
        // bash dialect (left) vs Rust dialect (right): different stage-ID
        // vocabularies but the same logical work with identical outcomes.
        // The strict diff would FAIL this (divergent stage-ID sets); the
        // functional diff must PASS on the shared logical stages.
        let bash = report(
            "bash",
            RunStatus::Passed,
            vec![
                stage("bootstrap_hosts", StageOutcomeRecord::Passed),
                stage("membership_setup", StageOutcomeRecord::Passed),
                stage("distribute_membership_state", StageOutcomeRecord::Passed),
                stage(
                    "issue_and_distribute_assignments",
                    StageOutcomeRecord::Passed,
                ),
                // bash-only setup helper — legitimately not in the Rust plan.
                stage("prime_remote_access", StageOutcomeRecord::Passed),
            ],
            vec![node("n1", vec![("acl", true)])],
        );
        let rust = report(
            "rust",
            RunStatus::Passed,
            vec![
                stage("bootstrap_hosts", StageOutcomeRecord::Passed),
                stage("membership_init", StageOutcomeRecord::Passed),
                stage("distribute_membership", StageOutcomeRecord::Passed),
                stage("distribute_assignments", StageOutcomeRecord::Passed),
                // Rust-only stage — legitimately not in the bash setup run.
                stage("traffic_test_matrix", StageOutcomeRecord::Passed),
            ],
            vec![node("n1", vec![("acl", true)])],
        );

        // Strict diff cannot pass across dialects (sanity anchor).
        assert!(!diff_live_lab_reports(&bash, &rust).overall_parity_pass);

        let f = diff_live_lab_reports_functional(&bash, &rust);
        assert!(f.overall_functional_parity_pass, "{f:#?}");
        // 4 shared canonical stages: bootstrap_hosts + the 3 aliased ones.
        assert_eq!(f.shared_stage_count, 4);
        assert!(f.shared_stages.iter().all(|e| e.matches));
        // Dialect-only stages are surfaced but do not fail parity.
        assert_eq!(
            f.stages_only_in_left,
            vec!["prime_remote_access".to_owned()]
        );
        assert_eq!(
            f.stages_only_in_right,
            vec!["traffic_test_matrix".to_owned()]
        );
    }

    #[test]
    fn functional_parity_fails_closed_on_zero_overlap() {
        // No shared canonical stage → a vacuous comparison → must NOT pass.
        let a = report(
            "a",
            RunStatus::Passed,
            vec![stage("prime_remote_access", StageOutcomeRecord::Passed)],
            vec![node("n1", vec![])],
        );
        let b = report(
            "b",
            RunStatus::Passed,
            vec![stage("traffic_test_matrix", StageOutcomeRecord::Passed)],
            vec![node("n1", vec![])],
        );
        let f = diff_live_lab_reports_functional(&a, &b);
        assert_eq!(f.shared_stage_count, 0);
        assert!(
            !f.overall_functional_parity_pass,
            "zero-overlap must fail closed: {f:#?}"
        );
    }

    #[test]
    fn functional_parity_fails_on_shared_stage_outcome_divergence() {
        let bash = report(
            "bash",
            RunStatus::Failed,
            vec![
                stage("bootstrap_hosts", StageOutcomeRecord::Passed),
                stage("membership_setup", StageOutcomeRecord::Failed),
            ],
            vec![node("n1", vec![])],
        );
        let rust = report(
            "rust",
            RunStatus::Passed,
            vec![
                stage("bootstrap_hosts", StageOutcomeRecord::Passed),
                stage("membership_init", StageOutcomeRecord::Passed),
            ],
            vec![node("n1", vec![])],
        );
        let f = diff_live_lab_reports_functional(&bash, &rust);
        // membership canonical stage diverges (Failed vs Passed) AND overall
        // status diverges → functional parity fails.
        assert!(!f.overall_functional_parity_pass);
        assert!(!f.overall_status_match);
        assert!(f.shared_stages.iter().any(|e| !e.matches));
    }

    #[test]
    fn functional_parity_fails_on_node_count_divergence() {
        let s_bash = vec![stage("bootstrap_hosts", StageOutcomeRecord::Passed)];
        let s_rust = vec![stage("bootstrap_hosts", StageOutcomeRecord::Passed)];
        let bash = report("bash", RunStatus::Passed, s_bash, vec![node("n1", vec![])]);
        let rust = report(
            "rust",
            RunStatus::Passed,
            s_rust,
            vec![node("n1", vec![]), node("n2", vec![])],
        );
        let f = diff_live_lab_reports_functional(&bash, &rust);
        assert!(f.shared_stages.iter().all(|e| e.matches));
        assert!(!f.node_count_match);
        assert!(!f.overall_functional_parity_pass);
    }

    #[test]
    fn functional_parity_validator_counts_are_informational_not_gating() {
        // Different validator counts (bash ran extra security validators) but
        // matching shared-stage outcomes + overall + node count → functional
        // parity still PASSES; validator mismatch is reported, not gating.
        let bash = report(
            "bash",
            RunStatus::Passed,
            vec![stage(
                "validate_baseline_runtime",
                StageOutcomeRecord::Passed,
            )],
            vec![node(
                "n1",
                vec![("acl", true), ("dns", true), ("mesh", true)],
            )],
        );
        let rust = report(
            "rust",
            RunStatus::Passed,
            vec![stage(
                "validate_baseline_runtime",
                StageOutcomeRecord::Passed,
            )],
            vec![node("n1", vec![("acl", true)])],
        );
        let f = diff_live_lab_reports_functional(&bash, &rust);
        assert!(
            !f.validator_total_count_match,
            "counts should differ (3 vs 1)"
        );
        assert!(
            f.overall_functional_parity_pass,
            "validator-count divergence must NOT gate functional parity: {f:#?}"
        );
    }
}
