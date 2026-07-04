use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

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
    if let Some(running) = outcomes.iter().find(|outcome| outcome.status == "running") {
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
    let mut candidate = None;
    let log_path = report_dir.join("orchestration").join("orchestrate.log");
    if log_path.exists() {
        let raw = std::fs::read_to_string(&log_path)
            .with_context(|| format!("reading {}", log_path.display()))?;

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
        candidate = infer_active_stage_from_logs(report_dir)?;
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
        .filter(|o| matches!(o.status.as_str(), "pass" | "fail" | "skip" | "skipped"))
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

fn infer_active_stage_from_logs(report_dir: &Path) -> Result<Option<String>> {
    let logs_dir = report_dir.join("logs");
    if !logs_dir.exists() {
        return Ok(None);
    }
    let mut logs = Vec::new();
    for entry in
        std::fs::read_dir(&logs_dir).with_context(|| format!("reading {}", logs_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("log") {
            continue;
        }
        let modified = entry.metadata()?.modified().ok();
        logs.push((modified, path));
    }
    logs.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));

    for (_, path) in logs {
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        if let Some(stage) = active_stage_from_log_text(&raw) {
            return Ok(Some(stage));
        }
    }
    Ok(None)
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
}
