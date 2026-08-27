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
use std::path::Path;

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
    let stage_durations: HashMap<String, u64> = {
        let path = ctx.report_dir.join("state/stages.tsv");
        std::fs::read_to_string(&path)
            .ok()
            .map(|body| {
                body.lines()
                    .filter_map(|line| {
                        let line = line.trim_end_matches('\r');
                        if line.is_empty() || line.starts_with('#') {
                            return None;
                        }
                        let cols: Vec<&str> = line.split('\t').collect();
                        if cols.len() < 8 {
                            return None;
                        }
                        let stage_id = cols[0].trim().to_owned();
                        parse_stage_duration_ms(&cols).map(|d| (stage_id, d))
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let stages: Vec<StageReport> = results
        .iter()
        .map(|(id, outcome)| {
            let (rec, error_detail) = match outcome {
                StageOutcome::Passed => (StageOutcomeRecord::Passed, None),
                StageOutcome::Skipped(..) | StageOutcome::NotRun => {
                    (StageOutcomeRecord::Skipped, None)
                }
                StageOutcome::Reused { evidence_sha256 } => (
                    StageOutcomeRecord::Skipped,
                    Some(format!("reused prior evidence sha256={evidence_sha256}")),
                ),
                StageOutcome::Failed(msg) => (StageOutcomeRecord::Failed, Some(msg.clone())),
                // A blocking non-pass kept distinct from `Skipped` — an evidence
                // gap must never aggregate as a legitimate profile omission.
                StageOutcome::NotProven { reason, detail } => (
                    StageOutcomeRecord::NotProven,
                    Some(if detail.is_empty() {
                        format!("not_proven: {}", reason.as_str())
                    } else {
                        format!("not_proven: {} ({detail})", reason.as_str())
                    }),
                ),
            };
            StageReport {
                stage_id: id.as_str().to_owned(),
                stage_name: id.as_str().to_owned(),
                outcome: rec,
                duration_ms: stage_durations.get(id.as_str()).copied().unwrap_or(0),
                error_detail,
            }
        })
        .collect();

    let any_failed = stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::Failed);
    // A `NotProven` stage is a blocking non-pass: the run did not prove its
    // claim, so it dominates to `Failed` — never softened to `Partial`.
    let any_not_proven = stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::NotProven);
    let any_skipped = stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::Skipped);
    let overall_status = if any_failed || any_not_proven {
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
    let recorded_nodes = node_statuses_from_nodes_tsv(&ctx.report_dir);
    for assignment in &ctx.assignments {
        let platform = ctx.adapters.get(&assignment.alias).map_or_else(
            || "unknown".to_owned(),
            |a| format!("{:?}", a.platform()).to_lowercase(),
        );
        node_statuses.insert(
            assignment.alias.clone(),
            NodeStatus {
                alias: assignment.alias.clone(),
                target: recorded_nodes
                    .get(&assignment.alias)
                    .map(|node| node.target.clone())
                    .unwrap_or_default(),
                node_id: recorded_nodes
                    .get(&assignment.alias)
                    .map(|node| node.node_id.clone())
                    .or_else(|| ctx.node_ids.get(&assignment.alias).cloned())
                    .unwrap_or_default(),
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

/// Best-effort `(run_id, timestamp_utc)` from `<report_dir>/run_summary.json`.
/// Neither field participates in the functional-parity verdict, so absence /
/// unparseable JSON is not an error — the caller falls back to the directory
/// name and an empty timestamp.
fn run_summary_identity(report_dir: &Path) -> Option<(String, String)> {
    let body = std::fs::read_to_string(report_dir.join("run_summary.json")).ok()?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;
    let run_id = value.get("run_id")?.as_str()?.to_owned();
    let timestamp = value
        .get("started_at_utc")
        .or_else(|| value.get("timestamp_utc"))
        .or_else(|| value.get("finished_at_utc"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("")
        .to_owned();
    Some((run_id, timestamp))
}

/// Map an orchestrator `overall_status` / stage-status string to [`RunStatus`].
fn run_status_from_str(raw: &str) -> Option<RunStatus> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "pass" | "passed" | "success" | "succeeded" | "ok" => Some(RunStatus::Passed),
        "fail" | "failed" | "error" | "aborted" | "abort" | "timed_out" | "timeout" => {
            Some(RunStatus::Failed)
        }
        "partial" => Some(RunStatus::Partial),
        _ => None,
    }
}

/// `overall_status` derived from a stage list, matching [`build_live_lab_run_report`]:
/// any `Failed` or `NotProven` (both blocking non-pass) → `Failed`, else any
/// `Skipped` → `Partial`, else `Passed`.
fn derive_overall_status(stages: &[StageReport]) -> RunStatus {
    if stages.iter().any(|s| {
        s.outcome == StageOutcomeRecord::Failed || s.outcome == StageOutcomeRecord::NotProven
    }) {
        RunStatus::Failed
    } else if stages
        .iter()
        .any(|s| s.outcome == StageOutcomeRecord::Skipped)
    {
        RunStatus::Partial
    } else {
        RunStatus::Passed
    }
}

/// `node_statuses` from `<report_dir>/state/nodes.tsv` (best-effort): one entry
/// per `alias \t target \t node_id \t role` row. `platform` is `unknown` (the
/// artifact carries none) and `validator_results` is empty — the functional
/// diff uses only the node COUNT, so this is sufficient and honest.
fn node_statuses_from_nodes_tsv(report_dir: &Path) -> HashMap<String, NodeStatus> {
    let mut node_statuses: HashMap<String, NodeStatus> = HashMap::new();
    if let Ok(nodes_body) = std::fs::read_to_string(report_dir.join("state/nodes.tsv")) {
        for raw_line in nodes_body.lines() {
            let line = raw_line.trim_end_matches('\r');
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let cols: Vec<&str> = line.split('\t').collect();
            let alias = cols.first().map(|s| s.trim()).unwrap_or("");
            if alias.is_empty() {
                continue;
            }
            let role = cols.get(3).map(|s| s.trim()).unwrap_or("").to_owned();
            node_statuses.insert(
                alias.to_owned(),
                NodeStatus {
                    alias: alias.to_owned(),
                    target: cols
                        .get(1)
                        .map(|value| value.trim())
                        .unwrap_or("")
                        .to_owned(),
                    node_id: cols
                        .get(2)
                        .map(|value| value.trim())
                        .unwrap_or("")
                        .to_owned(),
                    platform: cols
                        .get(4)
                        .map(|value| value.trim())
                        .unwrap_or("unknown")
                        .to_owned(),
                    role,
                    validator_results: Vec::new(),
                },
            );
        }
    }
    node_statuses
}

/// Primary source: `<report_dir>/orchestration/orchestrate_result.json` — the
/// authoritative full-run record BOTH engines write. Returns `None` when the
/// file is absent or unparseable (the caller falls back to `stages.tsv`).
///
/// This is the fix for the bash under-reporting: the bash orchestrate path
/// records ONLY the setup stages in `state/stages.tsv` (and `run_summary.json`),
/// collapsing the entire live suite into a single `orchestrate_result` outcome
/// — so a bash run that PASSED setup but FAILED its live suite reads as `pass`
/// from `stages.tsv`/`run_summary.json` yet `fail` here. `overall_status` is
/// taken from the record's own field (falling back to a derivation over the
/// outcomes if absent), so the live-suite verdict is captured for both engines.
fn report_from_orchestrate_result(report_dir: &Path) -> Option<(RunStatus, Vec<StageReport>)> {
    use crate::live_lab_stage_registry::{StageStatus, parse_stage_status};

    let path = report_dir.join("orchestration/orchestrate_result.json");
    let body = std::fs::read_to_string(&path).ok()?;
    let value: serde_json::Value = serde_json::from_str(&body).ok()?;

    let mut stages: Vec<StageReport> = Vec::new();
    if let Some(outcomes) = value.get("outcomes").and_then(|v| v.as_array()) {
        for outcome in outcomes {
            let stage_id = outcome
                .get("stage")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("")
                .trim();
            if stage_id.is_empty() {
                continue;
            }
            let summary = outcome
                .get("summary")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            // Completeness placeholders the bash arm emits for stages that were
            // never part of this run's plan — not executed work, drop them so
            // they neither pollute the stage list nor push overall to Partial.
            if summary.contains("not dispatched this run") {
                continue;
            }
            let status = outcome
                .get("status")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let rec = match parse_stage_status(status) {
                Some(StageStatus::Pass) => StageOutcomeRecord::Passed,
                Some(StageStatus::Fail | StageStatus::Aborted | StageStatus::TimedOut) => {
                    StageOutcomeRecord::Failed
                }
                Some(StageStatus::NotProven) => StageOutcomeRecord::NotProven,
                Some(StageStatus::Skipped | StageStatus::NotRun | StageStatus::Reused) => {
                    StageOutcomeRecord::Skipped
                }
                Some(StageStatus::Pending | StageStatus::Running | StageStatus::NotApplicable)
                | None => continue,
            };
            let error_detail = if rec == StageOutcomeRecord::Failed && !summary.is_empty() {
                Some(summary.to_owned())
            } else {
                None
            };
            stages.push(StageReport {
                stage_id: stage_id.to_owned(),
                stage_name: stage_id.to_owned(),
                outcome: rec,
                duration_ms: 0,
                error_detail,
            });
        }
    }

    let overall_status = value
        .get("overall_status")
        .and_then(serde_json::Value::as_str)
        .and_then(run_status_from_str)
        .unwrap_or_else(|| derive_overall_status(&stages));

    Some((overall_status, stages))
}

/// Parse a stage timestamp in the format written by the realtime recorder:
/// `YYYY-MM-DDTHH:MM:SSZ`. Returns Unix milliseconds from the epoch, or None.
fn parse_stage_iso8601_ms(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.len() < 20 {
        return None;
    }
    let (date_part, time_part) = s.split_at(10);
    let time_part = time_part.strip_prefix('T')?;
    let time_part = time_part.strip_suffix('Z').unwrap_or(time_part);
    let y: i64 = date_part.get(0..4)?.parse().ok()?;
    let mon: u32 = date_part.get(5..7)?.parse().ok()?;
    let d: u32 = date_part.get(8..10)?.parse().ok()?;
    let h: u32 = time_part.get(0..2)?.parse().ok()?;
    let min: u32 = time_part.get(3..5)?.parse().ok()?;
    let sec: u32 = time_part.get(6..8)?.parse().ok()?;
    if !(1..=12).contains(&mon)
        || !(1..=31).contains(&d)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&min)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    let days_before_month: [i64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let epoch_days = (y - 1970) * 365 + ((y - 1969) / 4) - ((y - 1901) / 100)
        + ((y - 1601) / 400)
        + days_before_month[(mon - 1) as usize]
        + if mon > 2 && leap { 1 } else { 0 }
        + (d as i64)
        - 1;
    let total_secs = epoch_days * 86400 + h as i64 * 3600 + min as i64 * 60 + sec as i64;
    if total_secs < 0 {
        return None;
    }
    Some((total_secs as u64) * 1000)
}

fn parse_stage_duration_ms(cols: &[&str]) -> Option<u64> {
    let started = parse_stage_iso8601_ms(cols.get(6)?.trim())?;
    let finished = parse_stage_iso8601_ms(cols.get(7)?.trim())?;
    if finished >= started {
        Some(finished - started)
    } else {
        None
    }
}

/// Fallback source: `<report_dir>/state/stages.tsv` (the realtime recorder
/// TSV). Complete for a Rust `--node` run; for a bash run it holds only the
/// setup stages, which is why `orchestrate_result.json` is preferred. Fails
/// closed on an unreadable file or one with zero terminal stage rows.
fn report_from_stages_tsv(report_dir: &Path) -> Result<(RunStatus, Vec<StageReport>), String> {
    use crate::live_lab_stage_registry::{StageStatus, parse_stage_status};

    let stages_path = report_dir.join("state/stages.tsv");
    let stages_body = std::fs::read_to_string(&stages_path)
        .map_err(|err| format!("read stages.tsv '{}': {err}", stages_path.display()))?;

    let mut stages: Vec<StageReport> = Vec::new();
    for raw_line in stages_body.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        // 8-column v1 layout: stage, severity, status, rc, log, summary,
        // started, finished. Fewer than 3 columns cannot carry a status.
        if cols.len() < 3 {
            continue;
        }
        let stage_id = cols[0].trim();
        if stage_id.is_empty() {
            continue;
        }
        let outcome = match parse_stage_status(cols[2].trim()) {
            Some(StageStatus::Pass) => StageOutcomeRecord::Passed,
            Some(StageStatus::Fail | StageStatus::Aborted | StageStatus::TimedOut) => {
                StageOutcomeRecord::Failed
            }
            Some(StageStatus::NotProven) => StageOutcomeRecord::NotProven,
            Some(StageStatus::Skipped | StageStatus::NotRun | StageStatus::Reused) => {
                StageOutcomeRecord::Skipped
            }
            Some(StageStatus::Pending | StageStatus::Running | StageStatus::NotApplicable)
            | None => continue,
        };
        let error_detail = if outcome == StageOutcomeRecord::Failed {
            cols.get(5)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
        } else {
            None
        };
        stages.push(StageReport {
            stage_id: stage_id.to_owned(),
            stage_name: stage_id.to_owned(),
            outcome,
            duration_ms: parse_stage_duration_ms(&cols).unwrap_or(0),
            error_detail,
        });
    }

    if stages.is_empty() {
        return Err(format!(
            "no terminal stage rows in '{}': cannot build a parity report",
            stages_path.display()
        ));
    }

    Ok((derive_overall_status(&stages), stages))
}

/// Engine-agnostic reconstruction of a [`LiveLabRunReport`] from a completed
/// run's on-disk evidence, independent of which orchestrator produced it.
///
/// This removes the Bucket-7 blocker: the Rust `--node` path already emits
/// `parity_input.json` directly (via [`build_live_lab_run_report`]), but the
/// bash orchestrator never did. Reconstructing ANY report directory — bash or
/// Rust — into a `LiveLabRunReport` through this one function lets the
/// functional-parity gate (the redefined W5.6 flip gate) run bash-vs-Rust, and
/// deriving BOTH sides identically guarantees a diff reflects a real difference
/// in the runs rather than in how the report was built.
///
/// Source precedence (see the helpers):
/// - PRIMARY `<report_dir>/orchestration/orchestrate_result.json` — the
///   authoritative full-run record both engines write. Required because the
///   bash arm records only the SETUP stages in `state/stages.tsv` /
///   `run_summary.json` and collapses the live suite into one
///   `orchestrate_result` outcome; reading `stages.tsv` alone would misreport a
///   bash run that failed its live suite as `pass`.
/// - FALLBACK `<report_dir>/state/stages.tsv` — used only when
///   `orchestrate_result.json` is absent/unparseable (e.g. a crashed run).
///
/// Stage statuses are normalized through the canonical
/// [`parse_stage_status`](crate::live_lab_stage_registry::parse_stage_status)
/// taxonomy (`pass` → `Passed`, `fail`/`aborted`/`timed_out` → `Failed`,
/// `skip` → `Skipped`; non-terminal / never-dispatched rows excluded).
/// `node_statuses` comes from `state/nodes.tsv`; `run_id`/`timestamp_utc` are
/// best-effort from `run_summary.json`.
///
/// Fail-closed: if neither source yields any stage rows, this is an error — a
/// report with no executed work cannot prove parity and must never read as a
/// pass.
pub fn live_lab_run_report_from_report_dir(report_dir: &Path) -> Result<LiveLabRunReport, String> {
    let node_statuses = node_statuses_from_nodes_tsv(report_dir);
    let (run_id, timestamp_utc) = run_summary_identity(report_dir).unwrap_or_else(|| {
        let fallback = report_dir
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("converted")
            .to_owned();
        (fallback, String::new())
    });

    let (overall_status, stages) = match report_from_orchestrate_result(report_dir) {
        Some(result) => result,
        None => report_from_stages_tsv(report_dir)?,
    };

    Ok(LiveLabRunReport {
        run_id,
        timestamp_utc,
        overall_status,
        stages,
        node_statuses,
    })
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
                target: String::new(),
                node_id: alias.to_owned(),
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
    fn not_proven_stage_forces_overall_failed_never_partial() {
        // A run whose only non-pass is a NotProven stage did not prove its
        // claim: it must read Failed, never Partial (which reads "some skips,
        // basically fine") and never Passed. This is the release-truth
        // invariant — an evidence gap can never present as green-ish.
        let stages = vec![
            stage("preflight", StageOutcomeRecord::Passed),
            stage("mesh_status_validation", StageOutcomeRecord::NotProven),
        ];
        assert_eq!(derive_overall_status(&stages), RunStatus::Failed);

        // NotProven must dominate a Skipped that would otherwise soften to
        // Partial — order-independent.
        let mixed = vec![
            stage("a", StageOutcomeRecord::Skipped),
            stage("b", StageOutcomeRecord::NotProven),
        ];
        assert_eq!(derive_overall_status(&mixed), RunStatus::Failed);

        // Sanity: a run with only Skipped is Partial (NotProven is doing real
        // work in the assertions above, not just always-Failed).
        let only_skips = vec![stage("a", StageOutcomeRecord::Skipped)];
        assert_eq!(derive_overall_status(&only_skips), RunStatus::Partial);
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

    // ── report_dir → LiveLabRunReport converter (Bucket 7 blocker removal) ──

    fn write_report_dir(
        name: &str,
        stages_tsv: &str,
        nodes_tsv: Option<&str>,
    ) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rustynet-parity-conv-{name}-{stamp}"));
        let state = dir.join("state");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(state.join("stages.tsv"), stages_tsv).expect("stages.tsv");
        if let Some(nodes) = nodes_tsv {
            std::fs::write(state.join("nodes.tsv"), nodes).expect("nodes.tsv");
        }
        dir
    }

    #[test]
    fn converter_reads_stages_and_nodes_and_derives_passed() {
        // bash dialect stage IDs, all pass; `na`/`running` rows are ignored.
        let stages = "membership_setup\thard\tpass\t0\t/tmp/m.log\tok\t2026-07-05T00:00:00Z\t2026-07-05T00:01:00Z\n\
             validate_baseline_runtime\thard\tpass\t0\t/tmp/b.log\tok\t2026-07-05T00:02:00Z\t2026-07-05T00:03:00Z\n\
             activate_macos_exit_role\tsoft\tna\t\t\t\t\t\n";
        let nodes = "debian-headless-1\tdebian@192.168.0.200\texit-1\texit\n\
             debian-headless-2\tdebian@192.168.0.201\tclient-1\tclient\n";
        let dir = write_report_dir("passed", stages, Some(nodes));
        let report = live_lab_run_report_from_report_dir(&dir).expect("converts");
        assert_eq!(report.overall_status, RunStatus::Passed);
        // The `na` row is excluded; only the two terminal rows survive.
        assert_eq!(report.stages.len(), 2, "{:#?}", report.stages);
        assert_eq!(report.node_statuses.len(), 2);
        assert_eq!(
            report.node_statuses["debian-headless-1"].role,
            "exit".to_owned()
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn converter_maps_fail_and_skip_and_prefers_failed_overall() {
        let stages = "bootstrap_hosts\thard\tpass\t0\t/tmp/a.log\tok\t\t\n\
             traffic_test_matrix\thard\tfail\t1\t/tmp/t.log\tclient pair unreachable\t\t\n\
             role_switch_matrix\thard\tskip\t\t\t\t\t\n";
        let dir = write_report_dir("failed", stages, None);
        let report = live_lab_run_report_from_report_dir(&dir).expect("converts");
        assert_eq!(report.overall_status, RunStatus::Failed);
        let traffic = report
            .stages
            .iter()
            .find(|s| s.stage_id == "traffic_test_matrix")
            .expect("traffic stage present");
        assert_eq!(traffic.outcome, StageOutcomeRecord::Failed);
        assert_eq!(
            traffic.error_detail.as_deref(),
            Some("client pair unreachable")
        );
        // No nodes.tsv → empty node set, but the stage list still stands.
        assert_eq!(report.node_statuses.len(), 0);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn converter_errors_on_empty_stages() {
        // Only a non-terminal row → zero executed stages → fail-closed error.
        let stages = "preflight\thard\trunning\t\t\t\t\t\n";
        let dir = write_report_dir("empty", stages, None);
        let err = live_lab_run_report_from_report_dir(&dir).expect_err("must fail closed");
        assert!(err.contains("no terminal stage rows"), "{err}");
        std::fs::remove_dir_all(&dir).ok();
    }

    fn write_report_dir_with_result(
        name: &str,
        stages_tsv: Option<&str>,
        orchestrate_result_json: &str,
    ) -> std::path::PathBuf {
        use std::time::{SystemTime, UNIX_EPOCH};
        let stamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!("rustynet-parity-orch-{name}-{stamp}"));
        std::fs::create_dir_all(dir.join("state")).expect("state dir");
        std::fs::create_dir_all(dir.join("orchestration")).expect("orchestration dir");
        if let Some(tsv) = stages_tsv {
            std::fs::write(dir.join("state/stages.tsv"), tsv).expect("stages.tsv");
        }
        std::fs::write(
            dir.join("orchestration/orchestrate_result.json"),
            orchestrate_result_json,
        )
        .expect("orchestrate_result.json");
        dir
    }

    #[test]
    fn converter_prefers_orchestrate_result_over_setup_only_stages_tsv() {
        // The bash-run bug: stages.tsv holds only the SETUP stages (all pass),
        // but the live suite failed — recorded only in orchestrate_result.json.
        // The converter must report Failed (from the authoritative record), not
        // Passed (from the setup-only TSV).
        let setup_only_tsv = "membership_setup\thard\tpass\t0\t\t\t\t\n\
             validate_baseline_runtime\thard\tpass\t0\t\t\t\t\n";
        let result = serde_json::json!({
            "overall_status": "fail",
            "outcomes": [
                {"stage": "validate_baseline_runtime", "status": "pass", "summary": "ok"},
                {"stage": "vm_lab_run_live_lab", "status": "fail", "summary": "traffic pair unreachable"}
            ]
        })
        .to_string();
        let dir = write_report_dir_with_result("prefers", Some(setup_only_tsv), &result);
        let report = live_lab_run_report_from_report_dir(&dir).expect("converts");
        assert_eq!(
            report.overall_status,
            RunStatus::Failed,
            "must take the live-suite failure from orchestrate_result.json, not the setup-only TSV"
        );
        assert!(
            report
                .stages
                .iter()
                .any(|s| s.stage_id == "vm_lab_run_live_lab"
                    && s.outcome == StageOutcomeRecord::Failed),
            "{:#?}",
            report.stages
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn converter_drops_not_dispatched_placeholders() {
        // The bash arm records "not dispatched this run" completeness
        // placeholders; they are not executed work and must not appear as
        // Skipped stages (which would otherwise push a clean run to Partial).
        let result = serde_json::json!({
            "overall_status": "pass",
            "outcomes": [
                {"stage": "bootstrap_hosts", "status": "pass", "summary": "ok"},
                {"stage": "validate_linux_relay_service_lifecycle", "status": "skipped",
                 "summary": "not dispatched this run (conditional/job-level; recorded for completeness)"}
            ]
        })
        .to_string();
        let dir = write_report_dir_with_result("placeholders", None, &result);
        let report = live_lab_run_report_from_report_dir(&dir).expect("converts");
        assert_eq!(report.overall_status, RunStatus::Passed);
        assert_eq!(report.stages.len(), 1, "{:#?}", report.stages);
        assert_eq!(report.stages[0].stage_id, "bootstrap_hosts");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn converter_falls_back_to_stages_tsv_when_no_orchestrate_result() {
        // A report dir with only the recorder TSV (e.g. a crashed run) still
        // converts via the fallback path.
        let dir = write_report_dir(
            "fallback",
            "preflight\thard\tpass\t0\t\t\t\t\nbootstrap_hosts\thard\tpass\t0\t\t\t\t\n",
            None,
        );
        let report = live_lab_run_report_from_report_dir(&dir).expect("fallback converts");
        assert_eq!(report.overall_status, RunStatus::Passed);
        assert_eq!(report.stages.len(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }
}
