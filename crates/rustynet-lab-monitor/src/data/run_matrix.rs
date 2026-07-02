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
    /// Not currently rendered by any panel; kept for tests/future display.
    #[allow(dead_code)]
    pub run_id: String,
    /// Short (7-char) git commit SHA.
    pub git_commit: String,
    pub overall_result: String,
    /// Name of the first stage that failed (from the `first_failed_stage` CSV column).
    pub first_failed_stage: String,
    /// Number of `_stage_` / `cross_os_*` columns with outcome "pass".
    pub passed_stages: usize,
    /// Count of stage columns with a decisive outcome (pass/fail/skip) — NOT counting not_run.
    pub total_stages: usize,
    /// Column name of the last stage that ran (any non-not_run value), for PASS run display.
    pub last_ran_stage: String,
}

/// True for columns that represent actual orchestrator stages (not role-presence summaries).
/// Only `*_stage_*` and `cross_os_*` columns count as lab stages.
fn is_lab_stage_column(header: &str) -> bool {
    header.contains("_stage_") || header.starts_with("cross_os_")
}

/// The full, authoritative "does this column represent a real pass/fail
/// check" definition shared by [`load_stage_progress`] (the header bar
/// counter) and [`load_full_stage_matrix`] (the FULL STAGE MATRIX tab), so
/// the two always agree. Deliberately excludes role-presence columns
/// (`linux_client`, `macos_admin`, ...) and per-role alias/node_id/target
/// metadata columns — those record "was this role elected" / "which node
/// served it", not a pass/fail outcome, even though they use the same
/// `{os}_` prefix as real checks. Purely header-driven (no hardcoded column
/// list), so a newly added `{os}_stage_*` or `{os}_<check-name>` column is
/// picked up automatically without a code change.
fn is_full_stage_matrix_column(header: &str) -> bool {
    is_lab_stage_column(header) || is_oneoff_check_column(header)
}

/// Split an `{os}_...` column into its OS prefix and the rest, trying each
/// known OS prefix in turn. `None` if the header doesn't start with one of
/// the three OS prefixes at all (e.g. `run_id`, `regression_notes`).
fn os_prefix_and_rest(header: &str) -> Option<(Os, &str)> {
    Os::all().into_iter().find_map(|os| {
        header
            .strip_prefix(os.csv_prefix())
            .and_then(|rest| rest.strip_prefix('_'))
            .map(|rest| (os, rest))
    })
}

/// True for the `{os}_present` / `{os}_{role}` role-presence flags and the
/// per-role `{os}_{role}_alias` / `_node_id` / `_target` metadata columns —
/// everything under an OS prefix that ISN'T a pass/fail check, enumerated
/// from the existing [`Role`] catalog rather than a separate hardcoded list.
fn is_role_presence_or_metadata_suffix(rest: &str) -> bool {
    if rest == "present" {
        return true;
    }
    Role::all().iter().any(|role| {
        rest == role.label()
            || ["alias", "node_id", "target"]
                .iter()
                .any(|meta| rest == format!("{}_{meta}", role.label()))
    })
}

/// True for a genuine one-off check column outside the `_stage_` naming
/// convention (e.g. `linux_membership_revoke_applies`,
/// `windows_named_pipe_acl`) — any `{os}_`-prefixed column that isn't a
/// `_stage_` column and isn't role-presence/metadata. Discovered purely
/// from the header, so newly added checks need no code change.
fn is_oneoff_check_column(header: &str) -> bool {
    if header.contains("_stage_") {
        return false;
    }
    match os_prefix_and_rest(header) {
        Some((_, rest)) => !is_role_presence_or_metadata_suffix(rest),
        None => false,
    }
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

    // Ordered list of (column_index, header_name) for lab stage columns only.
    let stage_cols: Vec<(usize, String)> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| is_lab_stage_column(h))
        .map(|(i, h)| (i, h.to_owned()))
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

            let run_id = run_id_idx.and_then(|i| row.get(i)).unwrap_or("").to_owned();

            let mut passed = 0usize;
            let mut total = 0usize;
            let mut last_ran_stage = String::new();

            for (idx, col_name) in &stage_cols {
                let v = row.get(*idx).unwrap_or("").trim();
                match v {
                    "pass" => {
                        passed += 1;
                        total += 1;
                        last_ran_stage = col_name.clone();
                    }
                    "fail" | "skip" | "skipped" => {
                        total += 1;
                        last_ran_stage = col_name.clone();
                    }
                    // "not_run" / "na" / "" → don't count, don't update last_ran
                    _ => {}
                }
            }

            RunSummary {
                run_id,
                git_commit,
                overall_result,
                first_failed_stage,
                passed_stages: passed,
                total_stages: total,
                last_ran_stage,
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

/// One row in the full stage matrix: a stage's display name plus its
/// current pass/fail/untested state (same [`ParityState`] semantics used
/// elsewhere — latest decisive `pass`/`fail` in run history wins; `skip`
/// and `not_run` both read as `Unproven`, matching [`latest_decisive_value`]).
#[derive(Debug, Clone)]
pub struct StageMatrixEntry {
    pub name: String,
    pub state: ParityState,
}

/// The complete "what needs to pass" grid: every real live-lab stage
/// check, bucketed by the OS it validates. `cross_os` holds the shared
/// interop checks that don't belong to a single OS.
#[derive(Debug, Clone, Default)]
pub struct FullStageMatrix {
    pub linux: Vec<StageMatrixEntry>,
    pub macos: Vec<StageMatrixEntry>,
    pub windows: Vec<StageMatrixEntry>,
    pub cross_os: Vec<StageMatrixEntry>,
}

/// Discover every distinct `_stage_` suffix across all three OS-prefixed
/// columns, in first-appearance order in the header — so row N means the
/// same stage in every OS column (required for the "Windows is ahead,
/// macOS still has gaps" at-a-glance comparison) without needing a
/// hardcoded canonical list: a newly appended `{os}_stage_<name>` column is
/// discovered automatically and takes the next row.
fn discover_stage_suffixes(headers: &csv::StringRecord) -> Vec<String> {
    let mut order = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for header in headers.iter() {
        for os in Os::all() {
            if let Some(suffix) = header.strip_prefix(&format!("{}_stage_", os.csv_prefix()))
                && seen.insert(suffix.to_owned())
            {
                order.push(suffix.to_owned());
            }
        }
    }
    order
}

/// Discover every one-off check column (see [`is_oneoff_check_column`])
/// belonging to one OS, in header order, as `(csv_column, display_name)`.
fn discover_oneoff_columns(headers: &csv::StringRecord, os: Os) -> Vec<(String, String)> {
    let prefix = format!("{}_", os.csv_prefix());
    headers
        .iter()
        .filter(|header| header.starts_with(&prefix) && is_oneoff_check_column(header))
        .map(|header| (header.to_owned(), header[prefix.len()..].to_owned()))
        .collect()
}

/// Load the full per-OS stage matrix (every `{os}_stage_*` column plus each
/// OS's one-off security columns, plus `cross_os_*` as a shared bucket) —
/// entirely discovered from the live CSV header via
/// [`discover_stage_suffixes`] / [`discover_oneoff_columns`], so adding a
/// new stage or check column to the CSV schema shows up here with no code
/// change. Deliberately independent of [`role_stage_columns`] — that
/// function maps a coarse role to a representative stage for the 8x3
/// parity view; this loads every individual stage check for the full
/// matrix view.
pub fn load_full_stage_matrix(repo_root: &Path) -> Result<FullStageMatrix> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(FullStageMatrix::default());
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
    for r in reader.records().flatten() {
        rows.push(r);
    }

    let state_for = |column: &str| -> ParityState {
        let Some(idx) = headers.iter().position(|h| h == column) else {
            return ParityState::Unproven;
        };
        match latest_decisive_value(&rows, idx) {
            Some("pass") => ParityState::Proven,
            Some("fail") => ParityState::Failed,
            _ => ParityState::Unproven,
        }
    };

    let mut matrix = FullStageMatrix::default();
    for suffix in discover_stage_suffixes(&headers) {
        matrix.linux.push(StageMatrixEntry {
            name: suffix.clone(),
            state: state_for(&format!("linux_stage_{suffix}")),
        });
        matrix.macos.push(StageMatrixEntry {
            name: suffix.clone(),
            state: state_for(&format!("macos_stage_{suffix}")),
        });
        matrix.windows.push(StageMatrixEntry {
            name: suffix.clone(),
            state: state_for(&format!("windows_stage_{suffix}")),
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Linux) {
        matrix.linux.push(StageMatrixEntry {
            name,
            state: state_for(&column),
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Macos) {
        matrix.macos.push(StageMatrixEntry {
            name,
            state: state_for(&column),
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Windows) {
        matrix.windows.push(StageMatrixEntry {
            name,
            state: state_for(&column),
        });
    }
    for header in headers.iter() {
        if let Some(name) = header.strip_prefix("cross_os_") {
            matrix.cross_os.push(StageMatrixEntry {
                name: name.to_owned(),
                state: state_for(header),
            });
        }
    }

    Ok(matrix)
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
    if !is_full_stage_matrix_column(header) {
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
            "run_id,git_commit,overall_result,first_failed_stage,\
             macos_stage_anchor,linux_stage_bootstrap,linux_stage_exit_handoff\n\
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
        // not_run is excluded from total; pass=1 fail=1 → total=2
        assert_eq!(runs[0].passed_stages, 1);
        assert_eq!(runs[0].total_stages, 2);
        assert_eq!(runs[0].last_ran_stage, "linux_stage_exit_handoff");
        // Older pass run: 3 stage columns all pass
        assert_eq!(runs[1].run_id, "run-old");
        assert_eq!(runs[1].overall_result, "pass");
        assert_eq!(runs[1].passed_stages, 3);
        assert_eq!(runs[1].total_stages, 3);
        assert_eq!(runs[1].last_ran_stage, "linux_stage_exit_handoff");
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

        // Only macos_stage_anchor, cross_os_dns, windows_stage_exit_handoff are
        // real stage columns; linux_present/linux_client are role-presence
        // flags and must not count (see next test).
        assert_eq!(progress.total, 3);
        // macos_stage_anchor latest=pass, cross_os_dns latest=fail,
        // windows_stage_exit_handoff latest row is not_run so falls back to
        // the earlier decisive "pass".
        assert_eq!(progress.passed, 2);
    }

    #[test]
    fn stage_progress_excludes_role_presence_columns() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_present,linux_client,linux_admin,macos_present,macos_exit,windows_present,windows_relay\n\
             pass,pass,pass,pass,pass,pass,pass,pass\n",
        );

        let progress = load_stage_progress(dir.path()).unwrap();

        // Every column here is a role-presence/summary flag; none are real
        // stage checks, so the header bar's counter must read 0/0, not 8/8.
        assert_eq!(progress.total, 0);
        assert_eq!(progress.passed, 0);
    }

    #[test]
    fn stage_progress_agrees_with_full_stage_matrix_total_on_a_complete_csv() {
        // Build a CSV containing a handful of stage columns (all 3 OS x 2
        // suffixes), a couple of one-offs per OS, a couple of cross_os_*
        // columns, and a role-presence column that must NOT be counted.
        // load_stage_progress's total and load_full_stage_matrix's total
        // are driven by the exact same header-discovery logic, so they must
        // always agree on any CSV, not just a specific hand-maintained one.
        let mut headers = vec!["overall_result".to_owned(), "linux_present".to_owned()];
        for suffix in ["bootstrap", "membership"] {
            headers.push(format!("linux_stage_{suffix}"));
            headers.push(format!("macos_stage_{suffix}"));
            headers.push(format!("windows_stage_{suffix}"));
        }
        headers.push("linux_membership_revoke_applies".to_owned());
        headers.push("macos_pf_killswitch".to_owned());
        headers.push("windows_named_pipe_acl".to_owned());
        headers.push("cross_os_bootstrap".to_owned());
        headers.push("cross_os_dns".to_owned());

        let values: Vec<&str> = headers.iter().map(|_| "pass").collect();
        let csv = format!("{}\n{}\n", headers.join(","), values.join(","));

        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(dir.path(), &csv);

        let progress = load_stage_progress(dir.path()).unwrap();
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        let matrix_total =
            matrix.linux.len() + matrix.macos.len() + matrix.windows.len() + matrix.cross_os.len();

        assert_eq!(progress.total, matrix_total);
        // 2 suffixes x 3 OS + 3 one-offs + 2 cross_os = 11; linux_present excluded.
        assert_eq!(matrix_total, 11);
    }

    #[test]
    fn full_stage_matrix_discovers_stage_suffixes_in_header_order() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_stage_bootstrap,linux_stage_membership,macos_stage_bootstrap\n\
             pass,pass,pass,pass\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        // Only the suffixes actually present anywhere in the header are
        // discovered ("bootstrap", "membership" — in that order), and each
        // discovered suffix gets a row in every OS column even if that
        // specific OS doesn't have the column yet (macOS has no
        // macos_stage_membership here, so it reads Unproven, not missing).
        assert_eq!(matrix.linux.len(), 2);
        assert_eq!(matrix.macos.len(), 2);
        assert_eq!(matrix.windows.len(), 2);
        assert_eq!(matrix.linux[0].name, "bootstrap");
        assert_eq!(matrix.linux[1].name, "membership");
        assert_eq!(matrix.macos[0].state, ParityState::Proven);
        assert_eq!(matrix.macos[1].state, ParityState::Unproven);
    }

    #[test]
    fn full_stage_matrix_picks_up_a_newly_added_stage_column_automatically() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_stage_brand_new_check\npass,pass\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        let progress = load_stage_progress(dir.path()).unwrap();
        assert!(
            matrix
                .linux
                .iter()
                .any(|e| e.name == "brand_new_check" && e.state == ParityState::Proven),
            "a never-before-seen _stage_ suffix must appear with no code change: {:?}",
            matrix.linux
        );
        assert_eq!(progress.total, 1);
        assert_eq!(progress.passed, 1);
    }

    #[test]
    fn full_stage_matrix_picks_up_a_newly_added_oneoff_column_automatically() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,macos_brand_new_security_check\npass,fail\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        let progress = load_stage_progress(dir.path()).unwrap();
        assert!(
            matrix
                .macos
                .iter()
                .any(|e| e.name == "brand_new_security_check" && e.state == ParityState::Failed),
            "a never-before-seen one-off check column must appear with no code change: {:?}",
            matrix.macos
        );
        assert_eq!(progress.total, 1);
        assert_eq!(progress.passed, 0);
    }

    #[test]
    fn full_stage_matrix_still_excludes_role_presence_and_metadata_columns() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_present,linux_client,linux_client_alias,linux_client_node_id,linux_client_target\n\
             pass,pass,pass,debian-1,client-1,debian@192.168.0.1\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        let progress = load_stage_progress(dir.path()).unwrap();
        assert!(matrix.linux.is_empty(), "{:?}", matrix.linux);
        assert_eq!(progress.total, 0);
    }

    #[test]
    fn full_stage_matrix_distinguishes_role_presence_from_a_same_prefixed_check() {
        // "linux_blind_exit" is the blind_exit role-presence flag; a check
        // column that happens to start with the same role name (like the
        // real linux_blind_exit_reversal_denied) must still be counted.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_blind_exit,linux_blind_exit_reversal_denied\npass,pass,fail\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        assert_eq!(matrix.linux.len(), 1);
        assert_eq!(matrix.linux[0].name, "blind_exit_reversal_denied");
        assert_eq!(matrix.linux[0].state, ParityState::Failed);
    }

    #[test]
    fn full_stage_matrix_computes_latest_decisive_state_per_column() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,macos_stage_anchor,windows_stage_bootstrap\n\
             pass,pass,fail\n\
             pass,fail,not_run\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        let macos_anchor = matrix.macos.iter().find(|e| e.name == "anchor").unwrap();
        assert_eq!(macos_anchor.state, ParityState::Failed);
        let windows_bootstrap = matrix
            .windows
            .iter()
            .find(|e| e.name == "bootstrap")
            .unwrap();
        // Latest row is not_run; falls back to the earlier decisive "fail".
        assert_eq!(windows_bootstrap.state, ParityState::Failed);
    }

    #[test]
    fn full_stage_matrix_missing_column_is_unproven() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(dir.path(), "overall_result\npass\n");
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        assert!(
            matrix
                .linux
                .iter()
                .all(|e| e.state == ParityState::Unproven)
        );
    }

    #[test]
    fn full_stage_matrix_places_oneoff_columns_in_the_right_os_and_cross_os_bucket() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,windows_named_pipe_acl,windows_dpapi_key_custody,\
             macos_keychain_key_custody,macos_pf_killswitch,\
             linux_membership_revoke_applies,linux_revoked_peer_denied_e2e,cross_os_dns\n\
             pass,pass,fail,pass,fail,pass,fail,pass\n",
        );
        let matrix = load_full_stage_matrix(dir.path()).unwrap();
        // No _stage_ columns in this CSV, so each OS bucket holds exactly
        // its one-off checks -- nothing hardcoded/expected beyond the header.
        assert_eq!(matrix.windows.len(), 2);
        assert_eq!(matrix.macos.len(), 2);
        assert_eq!(matrix.linux.len(), 2);
        assert!(
            matrix
                .windows
                .iter()
                .any(|e| e.name == "named_pipe_acl" && e.state == ParityState::Proven)
        );
        assert!(
            matrix
                .macos
                .iter()
                .any(|e| e.name == "pf_killswitch" && e.state == ParityState::Failed)
        );
        assert!(
            matrix
                .linux
                .iter()
                .any(|e| e.name == "membership_revoke_applies" && e.state == ParityState::Proven)
        );
        assert!(
            matrix
                .linux
                .iter()
                .any(|e| e.name == "revoked_peer_denied_e2e" && e.state == ParityState::Failed)
        );
        assert_eq!(matrix.cross_os.len(), 1);
        assert_eq!(matrix.cross_os[0].name, "dns");
        assert_eq!(matrix.cross_os[0].state, ParityState::Proven);
    }
}
