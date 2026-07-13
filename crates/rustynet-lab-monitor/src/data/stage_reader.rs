use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

#[derive(Debug, Clone, Deserialize)]
pub struct OrchestrateResult {
    #[serde(default)]
    #[allow(dead_code)]
    pub overall_status: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub report_dir: String,
    #[serde(default)]
    pub outcomes: Vec<StageOutcome>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct StageOutcome {
    pub stage: String,
    pub status: String,
    #[serde(default)]
    pub summary: String,
    #[serde(default)]
    pub artifacts: Vec<String>,
}

/// Monitor-side view of the orchestrator's closed status taxonomy. Kept in
/// one place so active-stage inference, counters, timers, and rendering do
/// not each maintain a subtly different string match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageStatus {
    Pending,
    Running,
    Pass,
    Fail,
    Skipped,
    NotRun,
    Reused,
    NotApplicable,
    TimedOut,
    Aborted,
    Unknown,
}

impl StageStatus {
    pub fn parse(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "pending" | "" => Self::Pending,
            "running" => Self::Running,
            "pass" | "passed" | "success" | "succeeded" | "ok" => Self::Pass,
            "fail" | "failed" | "error" => Self::Fail,
            "skip" | "skipped" => Self::Skipped,
            "not_run" | "not-run" | "not run" => Self::NotRun,
            "reused" | "reuse" => Self::Reused,
            "na" | "n/a" | "not_applicable" | "not-applicable" => Self::NotApplicable,
            "timed_out" | "timedout" | "timeout" => Self::TimedOut,
            "aborted" | "abort" => Self::Aborted,
            _ => Self::Unknown,
        }
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Pending | Self::Running | Self::Unknown)
    }

    pub fn is_failure(self) -> bool {
        matches!(self, Self::Fail | Self::TimedOut | Self::Aborted)
    }

    pub fn is_satisfied(self) -> bool {
        matches!(self, Self::Pass | Self::Reused)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutcomeSource {
    LiveStagesTsv,
    FinalResultJson,
    None,
}

#[derive(Debug, Clone)]
pub struct StageRead {
    pub result: OrchestrateResult,
    pub source: OutcomeSource,
    pub modified: Option<SystemTime>,
}

pub fn read_orchestrate_result(report_dir: &Path) -> Result<OrchestrateResult> {
    let path = orchestrate_result_path(report_dir);
    if !path.exists() {
        return Ok(OrchestrateResult {
            overall_status: String::new(),
            report_dir: report_dir.display().to_string(),
            outcomes: read_live_stages_tsv(report_dir)?,
        });
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&raw).with_context(|| format!("parsing {}", path.display()))
}

/// Read outcomes for an ACTIVE invocation. `stages.tsv` is the live recorder
/// and therefore wins whenever present. A final JSON in a reused report dir
/// may belong to the previous invocation and must never mask current rows.
/// JSON remains a compatibility fallback for legacy runs without a recorder.
pub fn read_active_stage_state(report_dir: &Path) -> Result<StageRead> {
    let tsv = report_dir.join("state/stages.tsv");
    if tsv.exists() {
        return Ok(StageRead {
            result: OrchestrateResult {
                overall_status: String::new(),
                report_dir: report_dir.display().to_string(),
                outcomes: read_live_stages_tsv(report_dir)?,
            },
            source: OutcomeSource::LiveStagesTsv,
            modified: modified_time(&tsv),
        });
    }

    let json = orchestrate_result_path(report_dir);
    if json.exists() {
        return Ok(StageRead {
            result: read_orchestrate_result(report_dir)?,
            source: OutcomeSource::FinalResultJson,
            modified: modified_time(&json),
        });
    }

    Ok(StageRead {
        result: OrchestrateResult {
            overall_status: String::new(),
            report_dir: report_dir.display().to_string(),
            outcomes: Vec::new(),
        },
        source: OutcomeSource::None,
        modified: None,
    })
}

/// Read a completed/held run. Final JSON owns the verdict; TSV is the crash
/// recovery fallback when finalization never happened.
pub fn read_completed_stage_state(report_dir: &Path) -> Result<StageRead> {
    let json = orchestrate_result_path(report_dir);
    if json.exists() {
        return Ok(StageRead {
            result: read_orchestrate_result(report_dir)?,
            source: OutcomeSource::FinalResultJson,
            modified: modified_time(&json),
        });
    }
    let tsv = report_dir.join("state/stages.tsv");
    if tsv.exists() {
        return Ok(StageRead {
            result: OrchestrateResult {
                overall_status: String::new(),
                report_dir: report_dir.display().to_string(),
                outcomes: read_live_stages_tsv(report_dir)?,
            },
            source: OutcomeSource::LiveStagesTsv,
            modified: modified_time(&tsv),
        });
    }
    Ok(StageRead {
        result: OrchestrateResult {
            overall_status: String::new(),
            report_dir: report_dir.display().to_string(),
            outcomes: Vec::new(),
        },
        source: OutcomeSource::None,
        modified: None,
    })
}

fn modified_time(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).ok()?.modified().ok()
}

/// Infer the active stage from the orchestrate.log file.
/// Returns the stage name if a `STAGE:` marker line is found.
///
/// `ordered_enabled_stages` and `outcomes` back a THIRD fallback (see
/// `infer_active_stage_from_pipeline_position`) for stages whose dispatcher
/// writes its `.log` file only once, wholesale, after the remote command
/// returns (e.g. `bootstrap_macos_host`, `bootstrap_windows_host`, and other
/// one-shot SSH-dispatch stages) -- those never emit a `[stage:xxx] START`
/// line while genuinely running, so the two log-based methods above can
/// never detect them as active no matter how long they take. Pass an empty
/// slice for either to skip this fallback (e.g. from a caller without a
/// config-driven stage list).
pub fn infer_active_stage(
    report_dir: &Path,
    ordered_enabled_stages: &[String],
    outcomes: &[StageOutcome],
) -> Result<Option<String>> {
    // Recorder-first realtime contract (Fable5 Finding 4): the orchestrator's
    // shared recorder writes a `running` row into stages.tsv when a stage
    // starts and replaces it with the terminal outcome when it finishes. When
    // present, that row is the AUTHORITATIVE active stage -- read it directly,
    // no inference. Everything below is the legacy fallback for pre-recorder
    // report dirs (no running row) whose active stage must still be guessed
    // from logs / pipeline position.
    if let Some(running) = outcomes
        .iter()
        .find(|outcome| StageStatus::parse(&outcome.status) == StageStatus::Running)
    {
        return Ok(Some(running.stage.clone()));
    }
    // Log-based candidate (orchestrate.log STAGE: marker, then the newest
    // per-stage `[stage:xxx] START` log). Only accepted if it does not
    // REGRESS behind work the pipeline has provably already finished --
    // otherwise a stale marker, or a late-running infra stage that recurs
    // (rediscover_local_utm re-runs after bootstrap), snaps the active
    // pointer backward into an earlier phase. When it would regress, or
    // there's no log signal at all, fall through to the monotonic
    // pipeline-position fallback below.
    //
    // Reading either log is best-effort: a concurrently-written log can be
    // caught mid-write (e.g. a torn multi-byte UTF-8 sequence at the buffer
    // boundary makes the whole file briefly invalid UTF-8), and a crashed or
    // rotated log can vanish between being listed and being read. None of
    // that should disable active-stage tracking for the whole run -- an
    // unreadable log is simply "no signal from this source", falling
    // through to the pipeline-position fallback below, not a hard error.
    let mut candidate = None;
    let log_path = report_dir.join("orchestration").join("orchestrate.log");
    if log_path.exists()
        && let Ok(raw) = std::fs::read_to_string(&log_path)
    {
        // Find the most recent line containing STAGE:
        for line in raw.lines().rev() {
            if let Some(idx) = line.find("STAGE:") {
                let rest = &line[idx + 6..];
                let stage = rest.trim().trim_matches('"').trim_matches('\'');
                if !stage.is_empty() {
                    candidate = Some(stage.to_string());
                    break;
                }
            }
        }
    }
    if candidate.is_none() {
        candidate = infer_active_stage_from_logs(report_dir);
    }

    if let Some(stage) = candidate
        && !would_regress(&stage, ordered_enabled_stages, outcomes)
    {
        return Ok(Some(stage));
    }

    Ok(infer_active_stage_from_pipeline_position(
        ordered_enabled_stages,
        outcomes,
    ))
}

/// True when `candidate` sits strictly BEFORE the furthest stage that has
/// already reached a terminal outcome, in the known pipeline order -- i.e.
/// accepting it would move the active indicator backward past completed
/// work. A candidate not present in `ordered_enabled_stages` (unknown
/// position) never counts as a regression, so a legitimately novel stage
/// name is still honored. An empty order (callers with no config-driven
/// list) also never regresses.
fn would_regress(
    candidate: &str,
    ordered_enabled_stages: &[String],
    outcomes: &[StageOutcome],
) -> bool {
    let Some(candidate_idx) = ordered_enabled_stages.iter().position(|s| s == candidate) else {
        return false;
    };
    let finished = finished_stage_set(outcomes);
    let furthest_done = ordered_enabled_stages
        .iter()
        .rposition(|s| finished.contains(s.as_str()));
    matches!(furthest_done, Some(done_idx) if candidate_idx < done_idx)
}

/// Stages with a recorded terminal (non-pending) status, as a lookup set.
fn finished_stage_set(outcomes: &[StageOutcome]) -> std::collections::HashSet<&str> {
    outcomes
        .iter()
        .filter(|o| StageStatus::parse(&o.status).is_terminal())
        .map(|o| o.stage.as_str())
        .collect()
}

/// The first stage (in pipeline order) that hasn't reached a final status
/// yet. Doesn't depend on any log file existing or following a particular
/// format at all -- just the fixed, always-known pipeline order and
/// whatever outcomes have actually been recorded so far -- so it still
/// finds the right answer for a stage whose log only appears after it
/// finishes. This is a positional approximation: it assumes
/// `ordered_enabled_stages` reflects real execution order (true for the
/// pipeline as currently defined), so it can occasionally point at the
/// wrong one of two genuinely-parallel stages -- but it's never worse than
/// the "nothing detected" status quo for stages the log-based methods are
/// structurally blind to.
fn infer_active_stage_from_pipeline_position(
    ordered_enabled_stages: &[String],
    outcomes: &[StageOutcome],
) -> Option<String> {
    let finished = finished_stage_set(outcomes);
    // Monotonic: start the search AFTER the furthest stage that has already
    // finished, never at the very first unfinished one. Some enabled stages
    // are conditional infra (restart_unready_vms, rediscover_local_utm,
    // cross_network_preflight) that record NO terminal outcome when their
    // precondition already holds -- the naive "first unfinished" anchors to
    // the earliest such phantom-pending stage forever, dragging the active
    // pointer back into PRE even after BOOTSTRAP/LIVE stages have completed
    // (the reported PRE<->BOOTSTRAP bounce / stuck-on-restart_unready_vms).
    let start = ordered_enabled_stages
        .iter()
        .rposition(|stage| finished.contains(stage.as_str()))
        .map(|idx| idx + 1)
        .unwrap_or(0);
    ordered_enabled_stages
        .get(start..)
        .unwrap_or(&[])
        .iter()
        .find(|stage| !finished.contains(stage.as_str()))
        .cloned()
}

fn orchestrate_result_path(report_dir: &Path) -> PathBuf {
    report_dir
        .join("orchestration")
        .join("orchestrate_result.json")
}

fn read_live_stages_tsv(report_dir: &Path) -> Result<Vec<StageOutcome>> {
    let path = report_dir.join("state").join("stages.tsv");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw =
        std::fs::read_to_string(&path).with_context(|| format!("reading {}", path.display()))?;
    let mut outcomes = Vec::new();
    for line in raw.lines() {
        let cols = line.split('\t').collect::<Vec<_>>();
        if cols.len() < 3 {
            continue;
        }
        outcomes.push(StageOutcome {
            stage: cols[0].to_owned(),
            status: cols[2].to_owned(),
            summary: cols.get(5).copied().unwrap_or_default().to_owned(),
            artifacts: cols
                .get(4)
                .map(|p| vec![(*p).to_owned()])
                .unwrap_or_default(),
        });
    }
    Ok(outcomes)
}

/// Best-effort: a directory listing can race a concurrent writer (a log
/// rotated or removed between being listed and being read, a `.log` name
/// that is transiently a half-created directory, a metadata call on an
/// entry that vanished a moment ago), and a log file can be caught mid-write
/// with invalid-UTF-8 bytes at the tail. None of that is fatal to active-stage
/// inference -- it just means this one candidate source has nothing to offer,
/// so every fallible step here degrades to "skip this entry" / `None` instead
/// of failing the whole scan.
fn infer_active_stage_from_logs(report_dir: &Path) -> Option<String> {
    let logs_dir = report_dir.join("logs");
    if !logs_dir.exists() {
        return None;
    }
    let mut logs = Vec::new();
    let Ok(read_dir) = std::fs::read_dir(&logs_dir) else {
        return None;
    };
    for entry in read_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
            continue;
        }
        let modified = entry.metadata().ok().and_then(|meta| meta.modified().ok());
        logs.push((modified, path));
    }
    logs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));

    for (_, path) in logs {
        let Ok(raw) = std::fs::read_to_string(&path) else {
            continue;
        };
        if let Some(stage) = active_stage_from_log_text(&raw) {
            return Some(stage);
        }
    }
    None
}

fn active_stage_from_log_text(raw: &str) -> Option<String> {
    for line in raw.lines().rev() {
        let Some(stage) = bracket_stage(line) else {
            continue;
        };
        if line.contains(" PASS ")
            || line.contains(" FAIL ")
            || line.contains(" SKIP ")
            || line.contains(" TIMEOUT ")
        {
            return None;
        }
        if line.contains(" START ") {
            return Some(stage);
        }
    }
    None
}

fn bracket_stage(line: &str) -> Option<String> {
    let rest = line.strip_prefix("[stage:")?;
    let (stage, _) = rest.split_once(']')?;
    if stage.is_empty() {
        None
    } else {
        Some(stage.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn active_stage_comes_from_latest_unfinished_stage_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(
            logs.join("bootstrap_hosts.log"),
            "[stage:bootstrap_hosts] START fresh install\n",
        )
        .expect("log");

        let stage = infer_active_stage(dir.path(), &[], &[]).expect("stage");

        assert_eq!(stage.as_deref(), Some("bootstrap_hosts"));
    }

    #[test]
    fn active_stage_falls_back_to_pipeline_position_when_no_log_signal_exists() {
        // bootstrap_macos_host (and other one-shot SSH-dispatch stages)
        // write their .log file only once, after the remote command
        // returns -- there's no "logs" dir at all yet while genuinely
        // running, so infer_active_stage_from_logs finds nothing. The
        // pipeline-position fallback must still say it's active.
        let dir = tempfile::tempdir().expect("tempdir");
        let ordered = vec!["preflight".to_owned(), "bootstrap_macos_host".to_owned()];
        let outcomes = vec![StageOutcome {
            stage: "preflight".to_owned(),
            status: "pass".to_owned(),
            summary: String::new(),
            artifacts: Vec::new(),
        }];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");

        assert_eq!(stage.as_deref(), Some("bootstrap_macos_host"));
    }

    #[test]
    fn pipeline_fallback_never_regresses_to_a_phantom_pending_early_stage() {
        // Regression for the reported PRE<->BOOTSTRAP bounce: restart_unready_vms
        // is an enabled PRE stage that records NO outcome when the VMs were
        // already ready. The naive "first unfinished" returned it forever,
        // even after BOOTSTRAP stages had passed. The monotonic fallback must
        // skip it and point at the genuinely-current stage.
        let dir = tempfile::tempdir().expect("tempdir");
        let ordered = vec![
            "preflight".to_owned(),
            "restart_unready_vms".to_owned(), // enabled, never records
            "bootstrap_hosts".to_owned(),
            "membership_setup".to_owned(),
            "validate_baseline_runtime".to_owned(),
        ];
        let outcomes = vec![
            outcome("preflight", "pass"),
            outcome("bootstrap_hosts", "pass"),
            outcome("membership_setup", "pass"),
            // restart_unready_vms + validate_baseline_runtime unrecorded
        ];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");

        assert_eq!(
            stage.as_deref(),
            Some("validate_baseline_runtime"),
            "must advance past the phantom-pending PRE stage, not snap back to it"
        );
    }

    #[test]
    fn log_marker_that_would_regress_behind_completed_work_is_ignored() {
        // A stale/recurring log marker (e.g. rediscover_local_utm re-running
        // late in the pipeline) must not drag the active pointer backward
        // once later stages have finished.
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(
            logs.join("restart_unready_vms.log"),
            "[stage:restart_unready_vms] START retrying stuck guests\n",
        )
        .expect("log");
        let ordered = vec![
            "restart_unready_vms".to_owned(),
            "bootstrap_hosts".to_owned(),
            "validate_baseline_runtime".to_owned(),
        ];
        let outcomes = vec![
            outcome("restart_unready_vms", "pass"),
            outcome("bootstrap_hosts", "pass"),
        ];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");

        assert_eq!(
            stage.as_deref(),
            Some("validate_baseline_runtime"),
            "the backward log marker must be rejected in favor of forward progress"
        );
    }

    fn outcome(stage: &str, status: &str) -> StageOutcome {
        StageOutcome {
            stage: stage.to_owned(),
            status: status.to_owned(),
            summary: String::new(),
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn a_running_outcome_is_the_authoritative_active_stage_over_inference() {
        // Recorder-first: when the orchestrator's recorder has written a
        // `running` row (surfaced as a status="running" outcome), that stage
        // is the active one directly -- no log/pipeline-position guessing, and
        // it wins even over a stale log marker that would point elsewhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(
            logs.join("preflight.log"),
            "[stage:preflight] START stale marker\n",
        )
        .expect("log");
        let ordered = vec!["preflight".to_owned(), "bootstrap_hosts".to_owned()];
        let outcomes = vec![
            outcome("preflight", "pass"),
            outcome("bootstrap_hosts", "running"),
        ];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");

        assert_eq!(
            stage.as_deref(),
            Some("bootstrap_hosts"),
            "the running row wins over the stale log marker + pipeline inference"
        );
    }

    #[test]
    fn active_stage_falls_back_to_inference_without_a_running_row() {
        // No running row (legacy pre-recorder run) -> the existing
        // log/pipeline inference still drives the active stage.
        let dir = tempfile::tempdir().expect("tempdir");
        let ordered = vec!["preflight".to_owned(), "bootstrap_hosts".to_owned()];
        let outcomes = vec![outcome("preflight", "pass")];
        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");
        assert_eq!(stage.as_deref(), Some("bootstrap_hosts"));
    }

    #[test]
    fn active_stage_pipeline_fallback_is_none_when_everything_enabled_is_finished() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ordered = vec!["preflight".to_owned()];
        let outcomes = vec![StageOutcome {
            stage: "preflight".to_owned(),
            status: "pass".to_owned(),
            summary: String::new(),
            artifacts: Vec::new(),
        }];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");

        assert_eq!(stage, None);
    }

    #[test]
    fn every_closed_terminal_status_advances_pipeline_position() {
        let dir = tempfile::tempdir().expect("tempdir");
        let ordered = vec!["first".to_owned(), "second".to_owned()];
        for status in [
            "pass",
            "fail",
            "skipped",
            "not_run",
            "reused",
            "not_applicable",
            "timed_out",
            "aborted",
        ] {
            let outcomes = vec![outcome("first", status)];
            let stage = infer_active_stage(dir.path(), &ordered, &outcomes).expect("stage");
            assert_eq!(stage.as_deref(), Some("second"), "status={status}");
        }
    }

    #[test]
    fn log_based_detection_still_wins_over_the_pipeline_position_fallback() {
        // When a real "[stage:xxx] START" marker exists, it's more precise
        // (immediate, not just positional) than the fallback -- it must
        // still take priority even if the fallback would point elsewhere.
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(
            logs.join("bootstrap_hosts.log"),
            "[stage:bootstrap_hosts] START fresh install\n",
        )
        .expect("log");
        let ordered = vec!["some_other_stage".to_owned()];

        let stage = infer_active_stage(dir.path(), &ordered, &[]).expect("stage");

        assert_eq!(stage.as_deref(), Some("bootstrap_hosts"));
    }

    #[test]
    fn live_stage_tsv_populates_outcomes_before_final_json_exists() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(
            state.join("stages.tsv"),
            "preflight\thard\tpass\t0\t/tmp/preflight.log\tverify\n",
        )
        .expect("stages");

        let result = read_orchestrate_result(dir.path()).expect("result");

        assert_eq!(result.outcomes.len(), 1);
        assert_eq!(result.outcomes[0].stage, "preflight");
        assert_eq!(result.outcomes[0].status, "pass");
    }

    #[test]
    fn active_reader_prefers_live_tsv_over_stale_final_json() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::create_dir_all(&orchestration).expect("orchestration dir");
        std::fs::write(
            orchestration.join("orchestrate_result.json"),
            r#"{"overall_status":"pass","outcomes":[{"stage":"old","status":"pass"}]}"#,
        )
        .expect("old result");
        std::fs::write(
            state.join("stages.tsv"),
            "new\thard\trunning\t0\t/tmp/new.log\tactive\n",
        )
        .expect("live stages");

        let read = read_active_stage_state(dir.path()).expect("active read");

        assert_eq!(read.source, OutcomeSource::LiveStagesTsv);
        assert_eq!(read.result.outcomes.len(), 1);
        assert_eq!(read.result.outcomes[0].stage, "new");
        assert_eq!(read.result.outcomes[0].status, "running");
    }

    #[test]
    fn empty_stages_tsv_file_yields_no_outcomes_not_a_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(state.join("stages.tsv"), "").expect("empty stages.tsv");

        let result = read_orchestrate_result(dir.path()).expect("result");

        assert!(result.outcomes.is_empty());
    }

    #[test]
    fn stages_tsv_mixed_wellformed_and_malformed_rows_keeps_only_wellformed() {
        // A concurrently-appended stages.tsv can contain blank lines, short
        // rows (an interrupted write with fewer tab-separated fields than
        // the recorder's own 3-column minimum), and a genuinely torn last
        // row with no trailing newline -- mixed in with real, complete rows.
        let dir = tempfile::tempdir().expect("tempdir");
        let state = dir.path().join("state");
        std::fs::create_dir_all(&state).expect("state dir");
        std::fs::write(
            state.join("stages.tsv"),
            "preflight\thard\tpass\t0\t/tmp/preflight.log\tverify\n\
             \n\
             short\trow\n\
             bootstrap_hosts\thard\trunning\t0\t/tmp/b.log\tin progress",
        )
        .expect("mixed stages.tsv");

        let result = read_orchestrate_result(dir.path()).expect("result");

        assert_eq!(result.outcomes.len(), 2, "{:?}", result.outcomes);
        assert_eq!(result.outcomes[0].stage, "preflight");
        assert_eq!(result.outcomes[0].status, "pass");
        assert_eq!(result.outcomes[1].stage, "bootstrap_hosts");
        assert_eq!(result.outcomes[1].status, "running");
    }

    #[test]
    fn a_truncated_status_word_parses_as_unknown_never_a_false_pass_or_fail() {
        // A torn write can leave a genuine prefix of a status word (e.g. the
        // recorder was writing "pass" and got cut off after 3 bytes). That
        // must never coincidentally read as terminal/satisfied -- it must
        // render as the explicit Unknown state, not a false green (or red).
        for truncated in ["pas", "fai", "runnin", "p", ""] {
            if truncated.is_empty() {
                // Empty parses as Pending by design (see StageStatus::parse);
                // covered by its own dedicated arm, not Unknown.
                assert_eq!(StageStatus::parse(truncated), StageStatus::Pending);
                continue;
            }
            let status = StageStatus::parse(truncated);
            assert_eq!(
                status,
                StageStatus::Unknown,
                "truncated status {truncated:?} must not parse as anything decisive"
            );
            assert!(!status.is_terminal());
            assert!(!status.is_satisfied());
            assert!(!status.is_failure());
        }
    }

    #[test]
    fn corrupt_orchestrate_result_json_returns_err_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).expect("orchestration dir");
        std::fs::write(
            orchestration.join("orchestrate_result.json"),
            [0x7b, 0xff, 0xfe, 0x22],
        )
        .expect("corrupt result");

        assert!(read_orchestrate_result(dir.path()).is_err());
        assert!(read_completed_stage_state(dir.path()).is_err());
    }

    #[test]
    fn empty_orchestrate_result_json_file_returns_err_not_panic() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).expect("orchestration dir");
        std::fs::write(orchestration.join("orchestrate_result.json"), "").expect("empty result");

        assert!(read_orchestrate_result(dir.path()).is_err());
    }

    #[test]
    fn read_active_stage_state_degrades_to_err_on_corrupt_json_when_no_tsv_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).expect("orchestration dir");
        std::fs::write(orchestration.join("orchestrate_result.json"), "not json")
            .expect("corrupt result");

        // No panic; an explicit Err the caller (App::refresh_state) turns
        // into a visible `data_errors` entry instead of a false-green
        // "nothing running" or stale display.
        assert!(read_active_stage_state(dir.path()).is_err());
    }

    #[test]
    fn infer_active_stage_survives_non_utf8_orchestrate_log() {
        // A concurrent writer can be caught mid-write on a multi-byte UTF-8
        // boundary, making the whole file transiently invalid UTF-8. That
        // must degrade to "no signal from this source" (falling through to
        // the pipeline-position fallback), never a hard failure that freezes
        // active-stage tracking.
        let dir = tempfile::tempdir().expect("tempdir");
        let orchestration = dir.path().join("orchestration");
        std::fs::create_dir_all(&orchestration).expect("orchestration dir");
        std::fs::write(
            orchestration.join("orchestrate.log"),
            [b'S', b'T', b'A', b'G', b'E', b':', 0xff, 0xfe],
        )
        .expect("non-utf8 log");
        let ordered = vec!["preflight".to_owned(), "bootstrap_hosts".to_owned()];
        let outcomes = vec![outcome("preflight", "pass")];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes)
            .expect("must not error on unreadable log content");

        assert_eq!(
            stage.as_deref(),
            Some("bootstrap_hosts"),
            "falls through to the pipeline-position fallback"
        );
    }

    #[test]
    fn infer_active_stage_survives_non_utf8_per_stage_log() {
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(&logs).expect("logs dir");
        std::fs::write(logs.join("bootstrap_hosts.log"), [0xff, 0xfe, 0x00, 0x01])
            .expect("non-utf8 stage log");
        let ordered = vec!["preflight".to_owned(), "bootstrap_hosts".to_owned()];
        let outcomes = vec![outcome("preflight", "pass")];

        let stage = infer_active_stage(dir.path(), &ordered, &outcomes)
            .expect("must not error on an unreadable per-stage log");

        assert_eq!(stage.as_deref(), Some("bootstrap_hosts"));
    }

    #[test]
    fn infer_active_stage_skips_a_directory_shaped_log_entry() {
        // A `.log`-suffixed path can transiently be a directory rather than
        // a file (a half-created artifact). Listing it is fine; reading it
        // errors (Is a directory) and must be skipped, not propagated.
        let dir = tempfile::tempdir().expect("tempdir");
        let logs = dir.path().join("logs");
        std::fs::create_dir_all(logs.join("weird.log")).expect("dir shaped like a .log");
        std::fs::write(
            logs.join("bootstrap_hosts.log"),
            "[stage:bootstrap_hosts] START fresh install\n",
        )
        .expect("real log");

        let stage = infer_active_stage(dir.path(), &[], &[])
            .expect("must not error on a directory-shaped .log entry");

        assert_eq!(stage.as_deref(), Some("bootstrap_hosts"));
    }
}
