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
    /// The latest decisive result may say pass or fail, but recent history
    /// (see [`classify_recent_history`]) shows an elevated failure rate
    /// without being consistently broken -- don't fully trust either color.
    Flaky,
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

    let mut matrix: HashMap<(Role, Os), ParityState> = HashMap::new();

    let header_index = |name: &str| {
        headers
            .as_ref()
            .and_then(|h| h.iter().position(|header| header == name))
    };

    for role in Role::all() {
        for os in Os::all() {
            let col_indices: Vec<usize> = role_stage_columns(role, os)
                .iter()
                .filter_map(|col| header_index(col))
                .collect();
            // Per row (oldest first, matching decisive_history's
            // convention), the same "first decisive of this role's
            // representative columns wins" rule as before -- just now
            // building the full history instead of stopping at the latest.
            let history: Vec<bool> = rows
                .iter()
                .filter_map(|row| {
                    col_indices
                        .iter()
                        .filter_map(|&idx| row.get(idx))
                        .find(|value| matches!(*value, "pass" | "fail"))
                })
                .map(|value| value == "fail")
                .collect();
            matrix.insert((role, os), classify_recent_history(&history));
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
        // classify_recent_history, not just "did the latest run pass" --
        // matching load_full_stage_matrix's classifier so the header bar
        // and the Full Stage Matrix panel always agree on a passed count.
        // A column whose latest run passed but whose recent history is
        // unstable (Flaky) must not inflate the header count while the
        // matrix panel correctly declines to count it.
        if classify_recent_history(&decisive_history(&rows, idx)) == ParityState::Proven {
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
    /// Number of `_stage_` / `cross_os_*` columns with outcome "pass", PLUS
    /// PRE's always-complete 5 (see `section_stages`) -- kept in step with
    /// what the Previous Runs bar actually renders (all 3 sections,
    /// including PRE), so the displayed "x/y" text next to the bar can't
    /// look inconsistent with the bar's own fill (previously PRE rendered
    /// as a solid green section while being entirely excluded from this
    /// count, reading as more evidence than the number backed up). Not used
    /// by the CHECKS header or Full Stage Matrix, which intentionally stay
    /// scoped to CSV check columns only -- this field is Previous-Runs-only.
    pub passed_stages: usize,
    /// Count of stage columns that were possible for this run: `pass`,
    /// `fail`, and `not_run` all count (not_run means "never reached" --
    /// e.g. the pipeline stopped early after an earlier failure -- which
    /// is still a stage that COULD have run, just didn't get there). Only
    /// `skip`/`skipped` (the orchestrator itself deciding this stage
    /// doesn't apply to this run's topology/flags) is excluded, so a run
    /// that deliberately skips half the catalog doesn't shrink the
    /// denominator, but a run that fails early and never reaches the rest
    /// still reports against the full possible count. PLUS PRE's
    /// always-complete 5 -- see `passed_stages`.
    pub total_stages: usize,
    /// Column name of the last stage with outcome "pass", for PASS run
    /// display — not just "the last non-not_run column", since that could
    /// be a skip and would misleadingly render with the pass-green check.
    pub last_passed_stage: String,
    /// (passed, total) for the Previous Runs panel's 3-section bar, one pair
    /// per Stage Grid group (PRE/BOOTSTRAP/LIVE LAB). PRE has no CSV
    /// representation at all (its steps -- preflight, SSH reachability,
    /// etc. -- never get a pass/fail column) and a run that failed during
    /// PRE itself never gets far enough to produce a CSV row at all, so any
    /// row that exists here by definition got past PRE -- always (5, 5),
    /// unconditionally. BOOTSTRAP is the `{os}_stage_{bootstrap,
    /// membership,assignments,baseline_runtime}` columns across all 3 OSes
    /// (12 columns) -- a genuine semantic match to Stage Grid's BOOTSTRAP
    /// phase, unlike a positional slice of the header (which mixed early and
    /// late stages together, since the CSV is ordered OS-then-checktype, not
    /// by pipeline phase, and produced a misleadingly near-empty BOOTSTRAP
    /// section even when most of that phase actually passed). LIVE LAB is
    /// every other real check column.
    pub section_stages: [(usize, usize); 3],
}

/// True for columns that represent actual orchestrator stages (not role-presence summaries).
/// Only `*_stage_*` and `cross_os_*` columns count as lab stages.
fn is_lab_stage_column(header: &str) -> bool {
    header.contains("_stage_") || header.starts_with("cross_os_")
}

/// The 4 `_stage_` suffixes that correspond to Stage Grid's BOOTSTRAP phase
/// (bootstrap_hosts/membership_setup+distribute_membership_state/
/// issue_and_distribute_*/enforce+validate_baseline_runtime) -- see
/// `RunSummary::section_stages`.
const BOOTSTRAP_PHASE_STAGE_SUFFIXES: [&str; 4] =
    ["bootstrap", "membership", "assignments", "baseline_runtime"];

fn is_bootstrap_phase_stage_column(header: &str) -> bool {
    Os::all().into_iter().any(|os| {
        BOOTSTRAP_PHASE_STAGE_SUFFIXES
            .iter()
            .any(|suffix| header == format!("{}_stage_{suffix}", os.csv_prefix()))
    })
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

    // Ordered list of (column_index, header_name) for every real check column
    // -- is_full_stage_matrix_column, the same "what counts as a check"
    // definition the header bar (load_stage_progress) and Full Stage Matrix
    // use, so a run's x/y here means the same thing as the header's X/Y.
    // Previously this only counted is_lab_stage_column (the 74 generic
    // `_stage_`/`cross_os_` columns), silently excluding the ~40 one-off
    // security-audit columns that the header bar and Full Stage Matrix DO
    // count -- so a run's total here could read e.g. 74 while the header
    // read 116 for the exact same CSV.
    let stage_cols: Vec<(usize, String)> = headers
        .iter()
        .enumerate()
        .filter(|(_, h)| is_full_stage_matrix_column(h))
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
            let mut last_passed_stage = String::new();
            let (mut boot_passed, mut boot_total) = (0usize, 0usize);
            let (mut lab_passed, mut lab_total) = (0usize, 0usize);

            for (idx, col_name) in &stage_cols {
                let v = row.get(*idx).unwrap_or("").trim();
                let is_pass = v == "pass";
                let is_decisive = matches!(v, "pass" | "fail" | "not_run" | "na" | "");
                // Only "skip"/"skipped" -- the orchestrator itself deciding
                // this doesn't apply to this run's topology/flags -- is
                // excluded entirely; everything else counts toward total.
                if !is_decisive {
                    continue;
                }
                total += 1;
                if is_pass {
                    passed += 1;
                    last_passed_stage = col_name.clone();
                }
                let (section_passed, section_total) = if is_bootstrap_phase_stage_column(col_name) {
                    (&mut boot_passed, &mut boot_total)
                } else {
                    (&mut lab_passed, &mut lab_total)
                };
                *section_total += 1;
                if is_pass {
                    *section_passed += 1;
                }
            }

            // PRE has no CSV representation of its own (preflight, SSH
            // reachability, etc. never get a pass/fail column) and a run
            // that failed during PRE itself never gets far enough to
            // produce a CSV row at all -- so any row that exists here by
            // definition got past PRE. Always show it complete rather than
            // conditionally inferring it, and fold its 5/5 into the
            // displayed passed/total so the count text agrees with what the
            // bar actually shows (previously "4/116" excluded PRE entirely
            // while the bar still rendered it as a solid green section,
            // reading as more evidence than the number backed up).
            const PRE_STAGE_COUNT: usize = 5;
            let pre = (PRE_STAGE_COUNT, PRE_STAGE_COUNT);

            RunSummary {
                run_id,
                git_commit,
                overall_result,
                first_failed_stage,
                passed_stages: passed + PRE_STAGE_COUNT,
                total_stages: total + PRE_STAGE_COUNT,
                last_passed_stage,
                section_stages: [pre, (boot_passed, boot_total), (lab_passed, lab_total)],
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
/// current state, classified from recent history (see
/// [`classify_recent_history`]) rather than just the latest value — a
/// stage with an elevated-but-not-total recent failure rate reads as
/// `Flaky` rather than whatever its single most recent result happened to
/// be. `skip`/`not_run` rows aren't part of the series at all (see
/// [`decisive_history`]); with zero decisive samples ever, reads
/// `Unproven`.
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
        classify_recent_history(&decisive_history(&rows, idx))
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
        // NOT `{prefix}_blind_exit` -- that's the role-PRESENCE flag
        // (`{os}_{role}`, see `is_role_presence_or_metadata_suffix`), which
        // records "was a node assigned this role", not a pass/fail outcome.
        // It only ever holds not_run/na/empty, so the parity cell for
        // BlindExit was permanently stuck at Unproven no matter how many
        // times blind_exit actually passed. `_reversal_denied` is a real
        // check column (proves a revoked/blind_exit peer is correctly
        // denied) and exists for all 3 OSes.
        Role::BlindExit => vec![format!("{prefix}_blind_exit_reversal_denied")],
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

/// Every decisive (pass/fail) value for a column, in the CSV's append
/// order (oldest first). `true` = fail. Rows where the column is
/// not_run/skip/absent are simply not part of the series -- a stage that
/// only ran on 12 of 400 runs (because most runs were a different
/// topology) gets a 12-long series, not a 400-long one padded with noise.
fn decisive_history(rows: &[csv::StringRecord], idx: usize) -> Vec<bool> {
    rows.iter()
        .filter_map(|row| match row.get(idx)?.trim() {
            "pass" => Some(false),
            "fail" => Some(true),
            _ => None,
        })
        .collect()
}

/// Page's CUSUM (Biometrika 1954): two one-sided cumulative sums with
/// slack `k` = half the shift to detect and decision interval `h`. Ported
/// from `rustynet-cli`'s `vm_lab::run_history` (FIS-0006) rather than
/// shared as a dependency -- this crate is deliberately excluded from the
/// main workspace to stay lightweight, and rustynet-cli is far too large
/// to pull in just for this ~20-line struct.
struct CusumDetector {
    sum_pos: f64,
    sum_neg: f64,
    k: f64,
    h: f64,
    baseline_p0: f64,
}

impl CusumDetector {
    fn new(baseline_p0: f64, shift_to_detect_p1: f64, decision_interval_h: f64) -> Self {
        Self {
            sum_pos: 0.0,
            sum_neg: 0.0,
            k: (shift_to_detect_p1 - baseline_p0).abs() / 2.0,
            h: decision_interval_h,
            baseline_p0,
        }
    }

    /// Returns `true` the first time the cumulative sum latches a shift
    /// above baseline (an elevated failure rate).
    fn update_shifted_up(&mut self, is_failure: bool) -> bool {
        let x = if is_failure { 1.0 } else { 0.0 } - self.baseline_p0;
        self.sum_pos = (self.sum_pos + x - self.k).max(0.0);
        self.sum_neg = (self.sum_neg - x - self.k).max(0.0);
        self.sum_pos > self.h
    }
}

/// How many trailing decisive results to classify against. Recent behavior
/// matters more than a check's entire history -- a stage that regressed
/// weeks ago and has been failing consistently ever since should read as
/// FAILED, not flaky, even though its full history is "mixed" (old passes
/// alongside new fails). Bounding to a trailing window keeps the verdict
/// current instead of dragged down by archaeology.
const FLAKE_WINDOW: usize = 10;

/// Below this many decisive samples in the window, a flakiness verdict
/// isn't meaningful -- fall back to the plain latest-value read.
const FLAKE_MIN_SAMPLES: usize = 4;

/// Assumed "healthy" baseline failure rate for anything in this window --
/// occasional single-digit-percent noise (an SSH hiccup, a slow VM) is
/// normal and shouldn't read as flaky. `FLAKE_SHIFT_P1` is the elevated
/// rate CUSUM is tuned to detect a shift toward.
const FLAKE_BASELINE_P0: f64 = 0.05;
const FLAKE_SHIFT_P1: f64 = 0.4;
/// Decision interval `h`: lower = more sensitive (latches sooner) at the
/// cost of more false positives. FIS-0006 uses 3.0, but that's tuned for
/// series that can run to hundreds of samples; against a bounded
/// [`FLAKE_WINDOW`] of 10, 3.0 doesn't reliably latch even a clean 50/50
/// alternating pattern before the window runs out. 2.0 still comfortably
/// ignores a single stray failure among many passes (peak ~0.775, see
/// tests) while latching a sustained or alternating elevated rate within
/// the window.
const FLAKE_DECISION_INTERVAL_H: f64 = 2.0;

/// Classify a column's recent decisive history into a display state.
/// Below [`FLAKE_MIN_SAMPLES`], just reads the latest value (today's
/// pass/fail/not-run behavior, unchanged). Above it, runs CUSUM over the
/// trailing [`FLAKE_WINDOW`]: no shift detected -> Proven (occasional
/// noise is normal); shift detected but at least one recent pass ->
/// Flaky (elevated failure rate, not consistently broken); shift detected
/// with zero recent passes -> Failed (a real, stuck regression).
fn classify_recent_history(history: &[bool]) -> ParityState {
    if history.len() < FLAKE_MIN_SAMPLES {
        return match history.last() {
            Some(true) => ParityState::Failed,
            Some(false) => ParityState::Proven,
            None => ParityState::Unproven,
        };
    }
    let window = &history[history.len().saturating_sub(FLAKE_WINDOW)..];
    let mut cusum =
        CusumDetector::new(FLAKE_BASELINE_P0, FLAKE_SHIFT_P1, FLAKE_DECISION_INTERVAL_H);
    let mut shifted_up = false;
    for &is_failure in window {
        shifted_up |= cusum.update_shifted_up(is_failure);
    }
    if !shifted_up {
        return ParityState::Proven;
    }
    if window.iter().any(|&is_failure| !is_failure) {
        ParityState::Flaky
    } else {
        ParityState::Failed
    }
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
    fn classify_recent_history_below_min_samples_falls_back_to_latest_value() {
        assert_eq!(classify_recent_history(&[]), ParityState::Unproven);
        assert_eq!(classify_recent_history(&[false]), ParityState::Proven);
        assert_eq!(classify_recent_history(&[true]), ParityState::Failed);
        // 3 samples: still below FLAKE_MIN_SAMPLES (4), even though mixed.
        assert_eq!(
            classify_recent_history(&[false, true, false]),
            ParityState::Proven
        );
    }

    #[test]
    fn classify_recent_history_all_pass_is_proven() {
        assert_eq!(
            classify_recent_history(&[false, false, false, false, false, false]),
            ParityState::Proven
        );
    }

    #[test]
    fn classify_recent_history_one_stray_failure_in_a_healthy_run_is_still_proven() {
        // A single blip among many passes is normal background noise, not
        // flakiness -- must not latch a shift.
        let mut history = vec![false; 12];
        history[5] = true;
        assert_eq!(classify_recent_history(&history), ParityState::Proven);
    }

    #[test]
    fn classify_recent_history_all_fail_is_failed_not_flaky() {
        assert_eq!(
            classify_recent_history(&[true, true, true, true, true, true]),
            ParityState::Failed
        );
    }

    #[test]
    fn classify_recent_history_mostly_fail_with_one_recent_pass_is_flaky() {
        // The exact shape found in production for windows_stage_anchor:
        // sustained failures with a single recent pass mixed in.
        let mut history = vec![true; 9];
        history.push(false);
        assert_eq!(classify_recent_history(&history), ParityState::Flaky);
    }

    #[test]
    fn classify_recent_history_alternating_is_flaky() {
        let history = vec![true, false, true, false, true, false, true, false];
        assert_eq!(classify_recent_history(&history), ParityState::Flaky);
    }

    #[test]
    fn classify_recent_history_old_failures_outside_the_window_do_not_count() {
        // 20 old fails, then 10 clean recent passes: the window is
        // entirely inside the passing tail, so this must read Proven, not
        // dragged down by ancient (now-irrelevant) history.
        let mut history = vec![true; 20];
        history.extend(vec![false; 10]);
        assert_eq!(classify_recent_history(&history), ParityState::Proven);
    }

    #[test]
    fn full_stage_matrix_flags_a_flaky_column() {
        let dir = tempfile::tempdir().unwrap();
        let header = "overall_result,linux_stage_bootstrap";
        let mut lines = vec![header.to_owned()];
        for outcome in [
            "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "pass",
        ] {
            lines.push(format!("pass,{outcome}"));
        }
        write_matrix_csv(dir.path(), &format!("{}\n", lines.join("\n")));

        let matrix = load_full_stage_matrix(dir.path()).unwrap();

        assert_eq!(matrix.linux[0].state, ParityState::Flaky);
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
        // not_run still counts toward total (it was possible, just never
        // reached after the earlier failure) -- pass=1 fail=1 not_run=1 →
        // total=3, plus PRE's always-complete 5/5 folded in (a row exists
        // at all only if the run got past PRE) -> 6/8.
        assert_eq!(runs[0].passed_stages, 6);
        assert_eq!(runs[0].total_stages, 8);
        // The last column with outcome "fail" doesn't count as a passed
        // stage -- last_passed_stage must be the actual last PASS, not
        // just the last column that ran at all.
        assert_eq!(runs[0].last_passed_stage, "linux_stage_bootstrap");
        // Older pass run: 3 stage columns all pass, plus PRE's 5/5 -> 8/8.
        assert_eq!(runs[1].run_id, "run-old");
        assert_eq!(runs[1].overall_result, "pass");
        assert_eq!(runs[1].passed_stages, 8);
        assert_eq!(runs[1].total_stages, 8);
        assert_eq!(runs[1].last_passed_stage, "linux_stage_exit_handoff");
    }

    #[test]
    fn recent_runs_excludes_skipped_stages_from_the_count_and_last_passed() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,macos_stage_anchor,macos_stage_exit_handoff,cross_os_dns\n\
             run-1,pass,pass,skip,skip\n",
        );
        let runs = load_recent_runs(dir.path(), 1).unwrap();

        // Only macos_stage_anchor is a real pass/fail outcome; the two
        // skips are deliberately-not-applicable, not "attempted and
        // stopped partway" -- must not inflate the denominator or look
        // like the run only got 1/3 of the way through. Plus PRE's
        // always-complete 5/5 folded in -> 6/6.
        assert_eq!(runs[0].passed_stages, 6);
        assert_eq!(runs[0].total_stages, 6);
        assert_eq!(runs[0].last_passed_stage, "macos_stage_anchor");
    }

    #[test]
    fn recent_runs_counts_not_run_toward_total_but_not_skip() {
        // A run that fails partway through: 3 stages passed, 1 failed, 2
        // were skipped (not applicable to this run's topology), and the 2
        // after the failure never ran. total_stages must be 6 (everything
        // possible except the 2 skips), not 4 (only decisive pass/fail).
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,\
             linux_stage_bootstrap,linux_stage_membership,linux_stage_assignments,\
             macos_stage_anchor,macos_stage_exit_handoff,\
             windows_stage_bootstrap,windows_stage_membership,windows_stage_assignments\n\
             run-1,fail,pass,pass,pass,fail,skip,not_run,not_run,skip\n",
        );
        let runs = load_recent_runs(dir.path(), 1).unwrap();

        // 3 passed, 6 total from the CSV columns, plus PRE's always-complete
        // 5/5 folded in -> 8/11.
        assert_eq!(runs[0].passed_stages, 8);
        assert_eq!(runs[0].total_stages, 11);
    }

    #[test]
    fn section_stages_classifies_columns_by_name_not_header_position() {
        // Regression: section_stages must route each column into BOOTSTRAP
        // or LIVE LAB by what it actually IS (its `_stage_{suffix}` name),
        // not by where it happens to sit in the CSV header -- the CSV is
        // ordered OS-then-checktype, not by pipeline phase, so a positional
        // slice previously mixed early and late stages together and could
        // show BOOTSTRAP as nearly empty even when most of it had passed.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,\
             linux_stage_bootstrap,linux_stage_membership,linux_stage_assignments,\
             macos_stage_anchor,macos_stage_exit_handoff,\
             windows_stage_bootstrap,windows_stage_membership,windows_stage_assignments\n\
             run-1,fail,pass,pass,pass,fail,skip,not_run,not_run,skip\n",
        );
        let runs = load_recent_runs(dir.path(), 1).unwrap();

        // 3 passed, 6 total from the CSV columns, plus PRE's always-complete
        // 5/5 folded in -> 8/11.
        assert_eq!(runs[0].passed_stages, 8);
        assert_eq!(runs[0].total_stages, 11);
        let [pre, bootstrap, live_lab] = runs[0].section_stages;
        assert_eq!(pre, (5, 5));
        // bootstrap/membership (linux, pass) + bootstrap/membership
        // (windows, not_run) are all `_stage_{bootstrap,membership,
        // assignments,baseline_runtime}` -- BOOTSTRAP-phase columns --
        // regardless of OS or header position: linux_stage_bootstrap (pass),
        // linux_stage_membership (pass), linux_stage_assignments (pass),
        // windows_stage_bootstrap (not_run), windows_stage_membership
        // (not_run) = 3 passed of 5 (windows_stage_assignments is skip,
        // excluded).
        assert_eq!(bootstrap, (3, 5));
        // macos_stage_anchor (fail) is the only non-bootstrap-suffix column
        // here -> LIVE LAB, 0 passed of 1.
        assert_eq!(live_lab, (0, 1));
    }

    #[test]
    fn pre_section_is_always_complete_even_with_no_other_decisive_data() {
        // A run that failed during PRE itself never gets far enough to
        // produce a CSV row at all -- so any row that exists here, no
        // matter how sparse, implies PRE was already past. No more "0/5"
        // fallback: PRE is unconditionally (5, 5).
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,linux_stage_bootstrap\nrun-1,,skip\n",
        );
        let runs = load_recent_runs(dir.path(), 1).unwrap();
        assert_eq!(runs[0].section_stages[0], (5, 5));
        assert_eq!(runs[0].passed_stages, 5);
        assert_eq!(runs[0].total_stages, 5);
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
    fn blind_exit_parity_reads_from_the_real_check_column_not_the_role_presence_flag() {
        // Regression: role_stage_columns(Role::BlindExit, ..) used to point
        // at "{os}_blind_exit" -- a role-presence flag ("was a node
        // assigned blind_exit"), which only ever holds not_run/na/empty and
        // can never carry a pass/fail outcome. That column and the real
        // check column can disagree, so a real pass here must be reflected.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_blind_exit,linux_blind_exit_reversal_denied\n\
             pass,not_run,pass\n",
        );
        let matrix = load_parity_matrix(dir.path()).unwrap();
        assert_eq!(
            matrix.get(&(Role::BlindExit, Os::Linux)),
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
    fn parity_matrix_flags_a_flaky_role_os_cell() {
        let dir = tempfile::tempdir().unwrap();
        let mut lines = vec!["run_id,overall_result,windows_stage_anchor".to_owned()];
        for (i, outcome) in [
            "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "fail", "pass",
        ]
        .iter()
        .enumerate()
        {
            lines.push(format!("run-{i},pass,{outcome}"));
        }
        write_matrix_csv(dir.path(), &format!("{}\n", lines.join("\n")));

        let matrix = load_parity_matrix(dir.path()).unwrap();

        assert_eq!(
            matrix.get(&(Role::Anchor, Os::Windows)),
            Some(&ParityState::Flaky)
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
    fn stage_progress_passed_count_agrees_with_full_stage_matrix_on_a_flaky_column() {
        // Regression for the header bar (CHECKS) reporting a higher passed
        // count than the Full Stage Matrix panel (39 vs 33 in the field):
        // load_stage_progress used to count a column as passed whenever its
        // single latest row said "pass", while load_full_stage_matrix ran
        // the CUSUM classifier over its recent history and correctly
        // demoted an unstable column to Flaky. A column with this alternating
        // pass/fail history ends on "pass" but is Flaky, so BOTH functions
        // must agree it does not count toward "passed".
        let dir = tempfile::tempdir().unwrap();
        let header = "overall_result,linux_stage_bootstrap";
        let mut lines = vec![header.to_owned()];
        for outcome in [
            "fail", "pass", "fail", "pass", "fail", "pass", "fail", "pass",
        ] {
            lines.push(format!("pass,{outcome}"));
        }
        write_matrix_csv(dir.path(), &format!("{}\n", lines.join("\n")));

        let progress = load_stage_progress(dir.path()).unwrap();
        let matrix = load_full_stage_matrix(dir.path()).unwrap();

        assert_eq!(matrix.linux[0].state, ParityState::Flaky);
        assert_eq!(progress.total, 1);
        assert_eq!(
            progress.passed, 0,
            "a Flaky column's latest-pass must not inflate the header bar's passed count"
        );
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
