use anyhow::{Context, Result};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    Client,
    Admin,
    Exit,
    BlindExit,
    Relay,
    Anchor,
    Nas,
    Llm,
}

impl Role {
    pub fn label(&self) -> &'static str {
        match self {
            Role::Client => "client",
            Role::Admin => "admin",
            Role::Exit => "exit",
            Role::BlindExit => "blind_exit",
            Role::Relay => "relay",
            Role::Anchor => "anchor",
            Role::Nas => "nas",
            Role::Llm => "llm",
        }
    }

    pub fn all() -> [Role; 8] {
        [
            Role::Client,
            Role::Admin,
            Role::Exit,
            Role::BlindExit,
            Role::Relay,
            Role::Anchor,
            Role::Nas,
            Role::Llm,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Linux,
    Macos,
    Windows,
}

impl Os {
    pub fn label(&self) -> &'static str {
        match self {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Windows => "windows",
        }
    }

    pub fn csv_prefix(&self) -> &'static str {
        self.label()
    }

    pub fn all() -> [Os; 3] {
        [Os::Linux, Os::Macos, Os::Windows]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParityState {
    Proven,
    Failed,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CellOutcome {
    Pass,
    Fail,
    NotRun,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StageProgress {
    pub passed: usize,
    pub total: usize,
}

pub fn load_parity_matrix(repo_root: &Path) -> Result<HashMap<(Role, Os), ParityState>> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&path)
        .with_context(|| format!("opening {}", path.display()))?;

    let headers = reader.headers().ok().cloned();

    let mut rows: Vec<csv::StringRecord> = Vec::new();
    for result in reader.records() {
        match result {
            Ok(r) => rows.push(r),
            Err(_) => continue,
        }
    }
    rows.reverse();

    let mut matrix: HashMap<(Role, Os), ParityState> = HashMap::new();

    let header_index = |name: &str| {
        headers
            .as_ref()
            .and_then(|h| h.iter().position(|header| header == name))
    };

    for role in Role::all() {
        for os in Os::all() {
            let col_names = role_stage_columns(role, os);
            let key = (role, os);
            let mut state = ParityState::Unproven;

            for row in &rows {
                let val = col_names
                    .iter()
                    .filter_map(|col| header_index(col))
                    .filter_map(|idx| row.get(idx))
                    .find(|value| matches!(*value, "pass" | "fail"))
                    .unwrap_or("");
                match val {
                    "pass" => {
                        state = ParityState::Proven;
                        break;
                    }
                    "fail" => {
                        state = ParityState::Failed;
                        break;
                    }
                    _ => {}
                }
            }

            matrix.insert(key, state);
        }
    }

    Ok(matrix)
}

pub fn load_stage_progress(repo_root: &Path) -> Result<StageProgress> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(StageProgress::default());
    }

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&path)
        .with_context(|| format!("opening {}", path.display()))?;
    let headers = reader
        .headers()
        .with_context(|| format!("reading headers from {}", path.display()))?
        .clone();
    let mut rows: Vec<csv::StringRecord> = Vec::new();
    for result in reader.records() {
        match result {
            Ok(r) => rows.push(r),
            Err(_) => continue,
        }
    }

    let mut total = 0usize;
    let mut passed = 0usize;
    for (idx, header) in headers.iter().enumerate() {
        if !stage_progress_column(header, &rows, idx) {
            continue;
        }
        total += 1;
        if latest_decisive_value(&rows, idx) == Some("pass") {
            passed += 1;
        }
    }
    Ok(StageProgress { passed, total })
}

/// Summary of a single completed lab run, for the Previous Runs panel.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub run_id: String,
    /// Short (7-char) git commit SHA.
    pub git_commit: String,
    pub overall_result: String,
    /// Name of the first stage that failed, if any.
    pub first_failed_stage: String,
    /// Number of stages with a "pass" outcome.
    pub passed_stages: usize,
    /// Total stages with any decisive outcome in the run.
    pub total_stages: usize,
}

fn is_meta_column(header: &str) -> bool {
    matches!(
        header,
        "run_id"
            | "run_started_utc"
            | "run_finished_utc"
            | "git_commit"
            | "git_branch"
            | "git_dirty_state"
            | "operator"
            | "profile_path"
            | "inventory_path"
            | "report_dir"
            | "run_command"
            | "topology_summary"
            | "overall_result"
            | "first_failed_stage"
            | "failure_digest_path"
            | "evidence_bundle_path"
            | "notes"
            | "linux_present"
            | "macos_present"
            | "windows_present"
    )
}

fn is_stage_value(v: &str) -> bool {
    matches!(
        v.trim(),
        "pass" | "fail" | "not_run" | "na" | "skip" | "skipped"
    )
}

pub fn load_recent_runs(repo_root: &Path, n: usize) -> Result<Vec<RunSummary>> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(Vec::new());
    }

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&path)
        .with_context(|| format!("opening {}", path.display()))?;

    let headers = reader
        .headers()
        .with_context(|| format!("reading headers from {}", path.display()))?
        .clone();

    let col_idx = |name: &str| headers.iter().position(|h| h == name);
    let git_commit_idx = col_idx("git_commit");
    let overall_idx = col_idx("overall_result");
    let first_failed_idx = col_idx("first_failed_stage");
    let run_id_idx = col_idx("run_id");

    let stage_col_indices: Vec<usize> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| !is_meta_column(h))
        .map(|(i, _)| i)
        .collect();

    let mut rows: Vec<csv::StringRecord> = Vec::new();
    for result in reader.records() {
        match result {
            Ok(r) => rows.push(r),
            Err(_) => continue,
        }
    }

    let start = rows.len().saturating_sub(n);
    let summaries: Vec<RunSummary> = rows[start..]
        .iter()
        .rev()
        .map(|row| {
            let git_commit: String = git_commit_idx
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .chars()
                .take(7)
                .collect();

            let overall_result = overall_idx
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .to_owned();

            let first_failed_stage = first_failed_idx
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .to_owned();

            let run_id = run_id_idx
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .to_owned();

            let mut passed = 0usize;
            let mut total = 0usize;
            for &idx in &stage_col_indices {
                if let Some(val) = row.get(idx) {
                    if is_stage_value(val) {
                        total += 1;
                        if val.trim() == "pass" {
                            passed += 1;
                        }
                    }
                }
            }

            RunSummary {
                run_id,
                git_commit,
                overall_result,
                first_failed_stage,
                passed_stages: passed,
                total_stages: total,
            }
        })
        .collect();

    Ok(summaries)
}

pub fn load_sparklines(
    repo_root: &Path,
    n: usize,
) -> Result<HashMap<(Role, Os), Vec<CellOutcome>>> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(HashMap::new());
    }

    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_path(&path)
        .with_context(|| format!("opening {}", path.display()))?;

    let headers = reader.headers().ok().cloned();

    let mut rows: Vec<csv::StringRecord> = Vec::new();
    for result in reader.records() {
        match result {
            Ok(r) => rows.push(r),
            Err(_) => continue,
        }
    }

    let start = rows.len().saturating_sub(n);
    let rows_slice = &rows[start..];

    let header_index = |name: &str| {
        headers
            .as_ref()
            .and_then(|h| h.iter().position(|header| header == name))
    };

    let mut sparklines: HashMap<(Role, Os), Vec<CellOutcome>> = HashMap::new();

    for role in Role::all() {
        for os in Os::all() {
            let col_names = role_stage_columns(role, os);
            let history: Vec<CellOutcome> = rows_slice
                .iter()
                .map(|row| {
                    let val = col_names
                        .iter()
                        .filter_map(|col| header_index(col))
                        .filter_map(|idx| row.get(idx))
                        .find(|v| matches!(*v, "pass" | "fail"))
                        .unwrap_or("");
                    match val {
                        "pass" => CellOutcome::Pass,
                        "fail" => CellOutcome::Fail,
                        _ => CellOutcome::NotRun,
                    }
                })
                .collect();
            sparklines.insert((role, os), history);
        }
    }

    Ok(sparklines)
}

fn role_stage_columns(role: Role, os: Os) -> Vec<String> {
    let prefix = os.csv_prefix();
    match role {
        Role::Client => ["bootstrap", "membership", "assignments", "baseline_runtime"]
            .into_iter()
            .map(|suffix| format!("{prefix}_stage_{suffix}"))
            .collect(),
        Role::Admin => vec![format!("{prefix}_stage_role_switch_matrix")],
        Role::Exit => vec![format!("{prefix}_stage_exit_handoff")],
        Role::BlindExit => vec![format!("{prefix}_blind_exit")],
        Role::Relay => vec![format!("{prefix}_stage_relay_service_lifecycle")],
        Role::Anchor => vec![format!("{prefix}_stage_anchor")],
        Role::Nas => vec![format!("{prefix}_stage_nas")],
        Role::Llm => vec![format!("{prefix}_stage_llm")],
    }
}

fn stage_progress_column(header: &str, rows: &[csv::StringRecord], idx: usize) -> bool {
    if matches!(
        header,
        "overall_result" | "linux_present" | "macos_present" | "windows_present"
    ) {
        return false;
    }
    rows.iter().any(|row| {
        row.get(idx).is_some_and(|value| {
            matches!(
                value.trim(),
                "pass" | "fail" | "not_run" | "skip" | "skipped"
            )
        })
    })
}

fn latest_decisive_value(rows: &[csv::StringRecord], idx: usize) -> Option<&str> {
    rows.iter()
        .rev()
        .find_map(|row| match row.get(idx)?.trim() {
            "pass" => Some("pass"),
            "fail" => Some("fail"),
            _ => None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_matrix_csv(dir: &std::path::Path, content: &str) {
        let docs = dir.join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("live_lab_run_matrix.csv"), content).unwrap();
    }

    #[test]
    fn sparkline_captures_last_n_outcomes_in_order() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,macos_stage_anchor\npass,pass\npass,fail\npass,pass\n",
        );
        let sparklines = load_sparklines(dir.path(), 8).unwrap();
        let history = sparklines.get(&(Role::Anchor, Os::Macos)).unwrap();
        assert_eq!(
            history,
            &[CellOutcome::Pass, CellOutcome::Fail, CellOutcome::Pass]
        );
    }

    #[test]
    fn sparkline_truncates_to_n_most_recent() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,macos_stage_anchor\n\
             pass,pass\npass,pass\npass,pass\npass,fail\npass,pass\n",
        );
        let sparklines = load_sparklines(dir.path(), 3).unwrap();
        let history = sparklines.get(&(Role::Anchor, Os::Macos)).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(
            history,
            &[CellOutcome::Pass, CellOutcome::Fail, CellOutcome::Pass]
        );
    }

    #[test]
    fn sparkline_missing_column_yields_not_run() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(dir.path(), "overall_result,macos_stage_anchor\npass,pass\n");
        let sparklines = load_sparklines(dir.path(), 4).unwrap();
        let windows_relay = sparklines.get(&(Role::Relay, Os::Windows)).unwrap();
        assert!(windows_relay.iter().all(|o| *o == CellOutcome::NotRun));
    }

    #[test]
    fn recent_runs_most_recent_first_with_stage_counts() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,git_commit,overall_result,first_failed_stage,macos_stage_anchor,linux_stage_bootstrap,linux_stage_exit_handoff\n\
             run-old,aaa1111,pass,,pass,pass,pass\n\
             run-new,bbb2222,fail,linux_stage_exit_handoff,not_run,pass,fail\n",
        );
        let runs = load_recent_runs(dir.path(), 3).unwrap();
        assert_eq!(runs.len(), 2);
        // Most recent first
        assert_eq!(runs[0].run_id, "run-new");
        assert_eq!(runs[0].git_commit, "bbb2222");
        assert_eq!(runs[0].overall_result, "fail");
        assert_eq!(runs[0].first_failed_stage, "linux_stage_exit_handoff");
        // not_run + pass + fail = 3 total, 1 passed
        assert_eq!(runs[0].total_stages, 3);
        assert_eq!(runs[0].passed_stages, 1);
        // Second is older
        assert_eq!(runs[1].run_id, "run-old");
        assert_eq!(runs[1].overall_result, "pass");
        assert_eq!(runs[1].passed_stages, 3);
        assert_eq!(runs[1].total_stages, 3);
    }

    #[test]
    fn parity_empty_csv_returns_unproven() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(dir.path(), "overall_result,macos_stage_anchor\n");
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::Anchor, Os::Macos)),
            Some(&ParityState::Unproven)
        );
    }

    #[test]
    fn parity_proven_when_pass_row_exists() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,macos_stage_anchor,windows_stage_relay\npass,pass,not_run\n",
        );
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::Anchor, Os::Macos)),
            Some(&ParityState::Proven)
        );
    }

    #[test]
    fn parity_failed_overrides_unproven() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(dir.path(), "overall_result,macos_stage_anchor\npass,fail\n");
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::Anchor, Os::Macos)),
            Some(&ParityState::Failed)
        );
    }

    #[test]
    fn parity_uses_headers_when_overall_result_is_not_first_column() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,started_at_utc,overall_result,macos_stage_exit_handoff\nrun-1,now,pass,pass\n",
        );
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::Exit, Os::Macos)),
            Some(&ParityState::Proven)
        );
    }

    #[test]
    fn parity_latest_stage_failure_is_red() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,windows_stage_relay_service_lifecycle\nold,pass,pass\nnew,fail,fail\n",
        );
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::Relay, Os::Windows)),
            Some(&ParityState::Failed)
        );
    }

    #[test]
    fn stage_progress_counts_latest_green_outcome_columns() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,linux_present,linux_client,macos_stage_anchor,cross_os_dns,windows_stage_exit_handoff,linux_client_alias\n\
             old,pass,pass,pass,fail,pass,pass,debian-headless-1\n\
             new,fail,pass,pass,pass,fail,not_run,debian-headless-1\n",
        );

        let progress = load_stage_progress(dir.path()).unwrap();

        assert_eq!(progress.total, 4);
        assert_eq!(progress.passed, 3);
    }
}
