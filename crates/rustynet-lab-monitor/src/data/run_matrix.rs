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

    /// Inverse of `label` -- `None` for anything that isn't a known role
    /// label (e.g. VM Status's "-" placeholder for "no role assigned").
    pub fn from_label(label: &str) -> Option<Role> {
        Role::all().into_iter().find(|role| role.label() == label)
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

    /// Inverse of `label` -- `None` for anything that isn't one of the 3
    /// known platform strings (e.g. VM Status's `VmStatus::platform`, which
    /// is always one of "linux"/"macos"/"windows" per
    /// `vm_prober::infer_platform`, but defensively `None` rather than
    /// panicking if that ever changes).
    pub fn from_label(label: &str) -> Option<Os> {
        Os::all().into_iter().find(|os| os.label() == label)
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
    /// Checks whose LATEST decisive outcome is pass — completion, the
    /// number an operator expects to move the moment a check goes green.
    pub passed: usize,
    pub total: usize,
    /// Of `passed`, how many the flake classifier does NOT yet consider
    /// stably Proven (green now, unstable recent history). Displayed as a
    /// separate warning — never subtracted from `passed`: gating the
    /// numerator on stability made the header sit at a stale-looking
    /// count right after a debugging loop turned checks green (observed
    /// live 2026-07-03: 9 freshly-passing checks invisible for hours).
    pub flaky: usize,
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
    let mut flaky = 0usize;
    for (idx, header) in headers.iter().enumerate() {
        if !stage_progress_column(header, &rows, idx) {
            continue;
        }
        total += 1;
        // `passed` = latest decisive outcome is pass (completion). The
        // Full Stage Matrix panel's stability classifier still runs, but
        // as a SEPARATE `flaky` count: a check that just went green after
        // a red debugging loop counts as passed immediately and carries a
        // flaky warning until its window stabilizes — the two panels tell
        // one story ("green now, N of them unstable") instead of the
        // header silently deflating progress.
        let history = decisive_history(&rows, idx);
        if history.last() == Some(&false) {
            passed += 1;
            if classify_recent_history(&history) != ParityState::Proven {
                flaky += 1;
            }
        }
    }
    // Header CHECKS counts real pass/fail CHECK columns only -- the exact
    // same definition (and therefore the same total) as the FULL STAGE
    // MATRIX tab, so the two headline numbers never disagree. PRE steps have
    // no CSV column and aren't parity checks, so they are deliberately NOT
    // folded in here (an earlier `+ PRE_STAGE_COUNT` made the header read 5
    // higher than the matrix and, with PRE now 9-10 stages, stale).
    Ok(StageProgress {
        passed,
        total,
        flaky,
    })
}

/// Summary of a single completed lab run, for the Previous Runs panel.
#[derive(Debug, Clone, PartialEq)]
pub struct RunSummary {
    /// Not currently rendered by any panel; kept for tests/future display.
    #[allow(dead_code)]
    pub run_id: String,
    /// Short (7-char) git commit SHA.
    pub git_commit: String,
    /// The run's report directory (verbatim from the CSV `report_dir`
    /// column, usually an absolute path). Lets the app read this run's OWN
    /// `stage_manifest.json` + `orchestrate_result.json` for authoritative,
    /// per-run-accurate, catalog-size-adaptive counts (see
    /// `App::run_plan_summary`), instead of the CSV-column approximation.
    /// Empty when the CSV has no `report_dir` column (older schema).
    pub report_dir: String,
    pub overall_result: String,
    /// Name of the first stage that failed (from the `first_failed_stage` CSV column).
    pub first_failed_stage: String,
    /// Number of fetched check columns with outcome `pass`. Not currently
    /// rendered directly -- the Previous Runs bar shows only the bare
    /// `total_stages` after the divider, with no matching numerator (see
    /// `subset_passed_stages` for the main fraction against this run's
    /// actual scope) -- kept for tests/future display, same as `run_id`.
    #[allow(dead_code)]
    pub passed_stages: usize,
    /// Count of stage columns that were possible for this run: `pass`,
    /// `fail`, and `not_run` all count (not_run means "never reached" --
    /// e.g. the pipeline stopped early after an earlier failure -- which
    /// is still a stage that COULD have run, just didn't get there). Only
    /// `skip`/`skipped` (the orchestrator itself deciding this stage
    /// doesn't apply to this run's topology/flags) is excluded, so a run
    /// that deliberately skips half the catalog doesn't shrink the
    /// denominator, but a run that fails early and never reaches the rest
    /// still reports against the full possible count.
    pub total_stages: usize,
    /// Column name of the last stage with outcome "pass", for PASS run
    /// display — not just "the last non-not_run column", since that could
    /// be a skip and would misleadingly render with the pass-green check.
    pub last_passed_stage: String,
    /// (passed, total) for the Previous Runs panel's 3-section bar. Exact
    /// PRE/BOOTSTRAP/LIVE LAB values are installed from the run's manifest.
    /// CSV-only fallback cannot reconstruct pipeline phases, so it leaves
    /// PRE/BOOTSTRAP empty and places fetched checks in LIVE LAB.
    pub section_stages: [(usize, usize); 3],
    /// Same as `passed_stages`, but restricted to the OSes/cross-OS group
    /// that were actually part of this run's topology -- an OS with NO
    /// decisive (pass/fail) value anywhere in the row was never targeted at
    /// all (e.g. macOS columns on a Linux-only run) and is excluded
    /// entirely, rather than counting its wall of `not_run` against the
    /// denominator as if those checks were ever going to run.
    pub subset_passed_stages: usize,
    /// Same as `total_stages`, but restricted the same way as
    /// `subset_passed_stages`.
    pub subset_total_stages: usize,
    /// Which of the 3 `section_stages` groups (0=PRE, 1=BOOTSTRAP,
    /// 2=LIVE LAB) contains this run's own named failure, if any --
    /// `None` for a passing run or when `first_failed_stage` is empty.
    /// PRE can never be the failing section (see `section_stages`).
    pub failing_section: Option<usize>,
    /// True only when this run's own manifest/result artifacts were read.
    /// False means counts are CSV checks only; UI labels them as such and
    /// never invents missing PRE/pipeline stages.
    pub counts_exact: bool,
}

/// True for columns that represent actual orchestrator stages (not role-presence summaries).
/// Only `*_stage_*` and `cross_os_*` columns count as lab stages.
fn is_lab_stage_column(header: &str) -> bool {
    header.contains("_stage_") || header.starts_with("cross_os_")
}

/// Which of the 4 CSV column families a `is_full_stage_matrix_column` header
/// belongs to -- used to decide whether an OS (or cross-OS) was even part of
/// a given run's topology at all (see `RunSummary::subset_total_stages`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum ScopeGroup {
    Linux,
    Macos,
    Windows,
    CrossOs,
}

fn scope_group_of(header: &str) -> ScopeGroup {
    if header.starts_with("cross_os_") {
        ScopeGroup::CrossOs
    } else if header.starts_with("linux_") {
        ScopeGroup::Linux
    } else if header.starts_with("macos_") {
        ScopeGroup::Macos
    } else {
        ScopeGroup::Windows
    }
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

/// Collapses rows that describe the SAME physical orchestrator invocation
/// written twice, keeping only the later (more complete) one.
///
/// The orchestrator has two CSV-writing code paths that both fire for a
/// single run: a narrower `live-linux-lab-orchestrator` writer appends a
/// Linux-only summary first, then the comprehensive
/// `vm-lab-orchestrate-live-lab` writer appends the full cross-OS result
/// right after -- same `report_dir`, same `run_started_utc`/
/// `run_finished_utc` (an actual re-invocation would have different
/// start/finish times even against the same report_dir; several report_dir
/// values are legitimately reused across many distinct retries over time,
/// each with its own timestamps, so report_dir alone is NOT a safe key).
/// When the two disagree, the narrow writer's row always reads "pass"
/// (it never saw the Windows/cross-OS stages that later failed), which
/// otherwise shows up in the Previous Runs panel as a phantom extra "run"
/// sitting right next to the real, complete result for the exact same
/// invocation. Verified against the full run-matrix history: of 243
/// (report_dir, started, finished) groups, 119 have exactly 2 rows, always
/// in (live-linux-lab-orchestrator, vm-lab-orchestrate-live-lab) order,
/// and the later row always has >= as many decisive pass/fail columns as
/// the earlier one -- so "keep the last-seen row per key" is safe. Rows
/// missing any of the three key fields (older CSV schema) are left
/// untouched, each counted as its own unique row.
fn dedupe_same_invocation_rows(
    rows: Vec<csv::StringRecord>,
    headers: &csv::StringRecord,
) -> Vec<csv::StringRecord> {
    let report_dir_idx = headers.iter().position(|h| h == "report_dir");
    let started_idx = headers.iter().position(|h| h == "run_started_utc");
    let finished_idx = headers.iter().position(|h| h == "run_finished_utc");

    let mut deduped: Vec<csv::StringRecord> = Vec::with_capacity(rows.len());
    let mut key_to_idx: HashMap<(String, String, String), usize> = HashMap::new();

    for row in rows {
        let key = (|| {
            let rd = row.get(report_dir_idx?)?.trim();
            let started = row.get(started_idx?)?.trim();
            let finished = row.get(finished_idx?)?.trim();
            if rd.is_empty() || started.is_empty() || finished.is_empty() {
                return None;
            }
            Some((rd.to_owned(), started.to_owned(), finished.to_owned()))
        })();

        let existing_idx = key.as_ref().and_then(|k| key_to_idx.get(k).copied());
        match existing_idx {
            Some(idx) => deduped[idx] = row,
            None => {
                if let Some(k) = key {
                    key_to_idx.insert(k, deduped.len());
                }
                deduped.push(row);
            }
        }
    }

    deduped
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
    let report_dir_idx = col_idx("report_dir");

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

    let rows = dedupe_same_invocation_rows(rows, &headers);

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

            let report_dir = report_dir_idx
                .and_then(|i| row.get(i))
                .unwrap_or("")
                .trim()
                .to_owned();

            // Which scope groups (linux / macos / windows / cross_os) have
            // ANY decisive (pass/fail) value anywhere in this row -- a group
            // with nothing decisive at all was never part of this run's
            // topology to begin with (e.g. macOS columns on a Linux-only
            // run), as opposed to a group that DID run but has some not_run
            // columns because the pipeline stopped early after a failure.
            // Used below to build "the subset that was actually in scope for
            // this run", not the full historical catalog.
            let mut scopes_in_play: std::collections::HashSet<ScopeGroup> =
                std::collections::HashSet::new();
            for (idx, col_name) in &stage_cols {
                if matches!(row.get(*idx).unwrap_or("").trim(), "pass" | "fail") {
                    scopes_in_play.insert(scope_group_of(col_name));
                }
            }

            let mut passed = 0usize;
            let mut total = 0usize;
            let mut subset_passed = 0usize;
            let mut subset_total = 0usize;
            let mut last_passed_stage = String::new();

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
                if scopes_in_play.contains(&scope_group_of(col_name)) {
                    subset_total += 1;
                    if is_pass {
                        subset_passed += 1;
                    }
                }
            }

            // CSV has check outcomes, but no exact PRE/BOOTSTRAP execution
            // plan. Keep every observed check in one explicit CSV section;
            // never manufacture pipeline counts from a stale local constant.
            let failing_section =
                if overall_result.eq_ignore_ascii_case("fail") && !first_failed_stage.is_empty() {
                    Some(2)
                } else {
                    None
                };

            RunSummary {
                run_id,
                git_commit,
                report_dir,
                overall_result,
                first_failed_stage,
                passed_stages: passed,
                total_stages: total,
                subset_passed_stages: subset_passed,
                subset_total_stages: subset_total,
                last_passed_stage,
                section_stages: [(0, 0), (0, 0), (subset_passed, subset_total)],
                failing_section,
                counts_exact: false,
            }
        })
        .collect();

    Ok(summaries)
}

/// Alias -> role label from the MOST RECENT run's `{os}_{role}_alias`
/// columns -- the authoritative record of which node actually served which
/// role in the latest live lab. VM STATUS uses it to light up nodes with the
/// role a real run gave them (and their parity glyph), even nodes outside the
/// monitor's own config slots (e.g. a `debian-headless-5` elected client, a
/// `debian-headless-3` elected relay, which the config heuristic alone can't
/// name). When one node served several roles in that run, the most
/// significant wins (exit > blind_exit > anchor > relay > admin > client).
/// Reads the newest row that has ANY alias column populated (older schema
/// rows, and the narrow Linux-only writer's role-less row, are skipped).
pub fn load_latest_run_roles(repo_root: &Path) -> Result<HashMap<String, String>> {
    let path = repo_root.join("documents/operations/live_lab_run_matrix.csv");
    if !path.exists() {
        return Ok(HashMap::new());
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

    // Least-significant role first, so a more significant role overwrites it
    // for a node that served several roles in the same run.
    let precedence = [
        Role::Client,
        Role::Admin,
        Role::Nas,
        Role::Llm,
        Role::Relay,
        Role::Anchor,
        Role::BlindExit,
        Role::Exit,
    ];
    let col_idx = |name: &str| headers.iter().position(|h| h == name);

    for row in rows.iter().rev() {
        let mut roles: HashMap<String, String> = HashMap::new();
        for role in precedence {
            for os in Os::all() {
                let column = format!("{}_{}_alias", os.csv_prefix(), role.label());
                if let Some(alias) = col_idx(&column)
                    .and_then(|idx| row.get(idx))
                    .map(str::trim)
                    .filter(|alias| !alias.is_empty())
                {
                    roles.insert(alias.to_owned(), role.label().to_owned());
                }
            }
        }
        if !roles.is_empty() {
            return Ok(roles);
        }
    }

    Ok(HashMap::new())
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
    /// Latest decisive outcome is pass — the completion signal the panel
    /// title counts, matching the header CHECKS definition. `state` stays
    /// the stability classification that colors the cell.
    pub latest_pass: bool,
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

    let state_for = |column: &str| -> (ParityState, bool) {
        let Some(idx) = headers.iter().position(|h| h == column) else {
            return (ParityState::Unproven, false);
        };
        let history = decisive_history(&rows, idx);
        (
            classify_recent_history(&history),
            history.last() == Some(&false),
        )
    };

    let mut matrix = FullStageMatrix::default();
    for suffix in discover_stage_suffixes(&headers) {
        matrix.linux.push({
            let (state, latest_pass) = state_for(&format!("linux_stage_{suffix}"));
            StageMatrixEntry {
                name: suffix.clone(),
                state,
                latest_pass,
            }
        });
        matrix.macos.push({
            let (state, latest_pass) = state_for(&format!("macos_stage_{suffix}"));
            StageMatrixEntry {
                name: suffix.clone(),
                state,
                latest_pass,
            }
        });
        matrix.windows.push({
            let (state, latest_pass) = state_for(&format!("windows_stage_{suffix}"));
            StageMatrixEntry {
                name: suffix.clone(),
                state,
                latest_pass,
            }
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Linux) {
        matrix.linux.push({
            let (state, latest_pass) = state_for(&column);
            StageMatrixEntry {
                name,
                state,
                latest_pass,
            }
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Macos) {
        matrix.macos.push({
            let (state, latest_pass) = state_for(&column);
            StageMatrixEntry {
                name,
                state,
                latest_pass,
            }
        });
    }
    for (column, name) in discover_oneoff_columns(&headers, Os::Windows) {
        matrix.windows.push({
            let (state, latest_pass) = state_for(&column);
            StageMatrixEntry {
                name,
                state,
                latest_pass,
            }
        });
    }
    for header in headers.iter() {
        if let Some(name) = header.strip_prefix("cross_os_") {
            matrix.cross_os.push({
                let (state, latest_pass) = state_for(header);
                StageMatrixEntry {
                    name: name.to_owned(),
                    state,
                    latest_pass,
                }
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
        // total=3. No PRE count is invented without a manifest.
        assert_eq!(runs[0].passed_stages, 1);
        assert_eq!(runs[0].total_stages, 3);
        assert!(!runs[0].counts_exact);
        // The last column with outcome "fail" doesn't count as a passed
        // stage -- last_passed_stage must be the actual last PASS, not
        // just the last column that ran at all.
        assert_eq!(runs[0].last_passed_stage, "linux_stage_bootstrap");
        // Older pass run: 3 CSV check columns all pass.
        assert_eq!(runs[1].run_id, "run-old");
        assert_eq!(runs[1].overall_result, "pass");
        assert_eq!(runs[1].passed_stages, 3);
        assert_eq!(runs[1].total_stages, 3);
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
        // like the run only got 1/3 of the way through.
        assert_eq!(runs[0].passed_stages, 1);
        assert_eq!(runs[0].total_stages, 1);
        assert_eq!(runs[0].last_passed_stage, "macos_stage_anchor");
    }

    #[test]
    fn recent_runs_collapses_the_same_invocation_written_by_two_orchestrator_paths() {
        // Real-world regression: the orchestrator has two CSV-writing code
        // paths that both fire for a single physical run -- a narrower
        // `live-linux-lab-orchestrator` writer appends a Linux-only "pass"
        // summary first, then the comprehensive `vm-lab-orchestrate-live-lab`
        // writer appends the true, full cross-OS result right after. Same
        // report_dir, same run_started_utc/run_finished_utc -- a real
        // re-invocation would have different start/finish times even
        // against a reused report_dir. Without deduping, Previous Runs
        // showed the phantom "pass" row as if it were a distinct earlier
        // run, sitting right next to the real failing result for the exact
        // same invocation.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,report_dir,run_started_utc,run_finished_utc,git_commit,overall_result,first_failed_stage,windows_stage_bootstrap,windows_hello_limiter_flood\n\
             run-old,other-dir,2026-01-01T00:00:00Z,2026-01-01T01:00:00Z,ccc3333,pass,,pass,pass\n\
             run-narrow,shared-dir,2026-07-03T10:16:28Z,2026-07-03T10:43:15Z,aaa1111,pass,,,\n\
             run-full,shared-dir,2026-07-03T10:16:28Z,2026-07-03T10:43:15Z,aaa1111,fail,windows_hello_limiter_flood,pass,fail\n",
        );

        let runs = load_recent_runs(dir.path(), 3).unwrap();

        // 2 distinct invocations, not 3 rows -- run-narrow and run-full
        // collapse into one, keeping run-full's real outcome.
        assert_eq!(runs.len(), 2);
        assert_eq!(runs[0].run_id, "run-full");
        assert_eq!(runs[0].overall_result, "fail");
        assert_eq!(runs[0].first_failed_stage, "windows_hello_limiter_flood");
        assert_eq!(runs[1].run_id, "run-old");
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

        assert_eq!(runs[0].passed_stages, 3);
        assert_eq!(runs[0].total_stages, 6);
    }

    #[test]
    fn csv_fallback_does_not_invent_pipeline_sections() {
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

        assert_eq!(runs[0].passed_stages, 3);
        assert_eq!(runs[0].total_stages, 6);
        let [pre, bootstrap, live_lab] = runs[0].section_stages;
        assert_eq!(pre, (0, 0));
        assert_eq!(bootstrap, (0, 0));
        assert_eq!(live_lab, (3, 4));
        assert!(!runs[0].counts_exact);
    }

    #[test]
    fn sparse_csv_does_not_claim_unrecorded_pre_work() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "run_id,overall_result,linux_stage_bootstrap\nrun-1,,skip\n",
        );
        let runs = load_recent_runs(dir.path(), 1).unwrap();
        assert_eq!(runs[0].section_stages[0], (0, 0));
        assert_eq!(runs[0].passed_stages, 0);
        assert_eq!(runs[0].total_stages, 0);
        assert!(!runs[0].counts_exact);
    }

    #[test]
    fn latest_run_roles_maps_each_node_to_the_role_it_served() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "git_commit,linux_client_alias,linux_exit_alias,linux_relay_alias,linux_anchor_alias\n\
             old1111,old-client,old-exit,,\n\
             new2222,debian-headless-5,debian-headless-1,debian-headless-3,debian-headless-1\n",
        );
        let roles = load_latest_run_roles(dir.path()).unwrap();
        // Newest row wins; each node maps to its role.
        assert_eq!(
            roles.get("debian-headless-5").map(String::as_str),
            Some("client")
        );
        assert_eq!(
            roles.get("debian-headless-3").map(String::as_str),
            Some("relay")
        );
        // debian-headless-1 served BOTH exit and anchor -- exit is more
        // significant, so it wins.
        assert_eq!(
            roles.get("debian-headless-1").map(String::as_str),
            Some("exit")
        );
        // Stale older-row aliases must not leak through.
        assert!(!roles.contains_key("old-client"));
    }

    #[test]
    fn latest_run_roles_skips_rows_with_no_alias_data() {
        let dir = tempfile::tempdir().unwrap();
        // Newest row is a role-less writer row; the loader must fall back to
        // the most recent row that actually carries alias columns.
        write_matrix_csv(
            dir.path(),
            "git_commit,linux_client_alias,linux_exit_alias\n\
             real1111,debian-headless-5,debian-headless-1\n\
             narrow22,,\n",
        );
        let roles = load_latest_run_roles(dir.path()).unwrap();
        assert_eq!(
            roles.get("debian-headless-5").map(String::as_str),
            Some("client")
        );
        assert_eq!(
            roles.get("debian-headless-1").map(String::as_str),
            Some("exit")
        );
    }

    #[test]
    fn latest_run_roles_empty_when_no_csv() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load_latest_run_roles(dir.path()).unwrap().is_empty());
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
        // flags and must not count (see next test). PRE steps have no CSV
        // column and are not parity checks, so they are NOT folded in --
        // header CHECKS counts real check columns only, matching the matrix.
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

        // Header CHECKS and the FULL STAGE MATRIX count the exact same
        // check columns, so progress.total must equal matrix_total EXACTLY --
        // no PRE fold on either side, so the two headline numbers agree.
        assert_eq!(progress.total, matrix_total);
        // 2 suffixes x 3 OS + 3 one-offs + 2 cross_os = 11; linux_present excluded.
        assert_eq!(matrix_total, 11);
    }

    #[test]
    fn stage_progress_counts_a_flaky_latest_pass_and_flags_it() {
        // The header CHECKS numerator is COMPLETION (latest decisive
        // outcome), with stability carried as a separate `flaky` sidecar.
        // History: gating `passed` on the CUSUM classifier made the header
        // sit at a stale-looking count for hours after a debugging loop
        // turned checks green (field case 2026-07-03: 9 freshly-passing
        // checks — same-day windows anchor + macos exit wins — invisible
        // at "76/121"). A flaky column that currently passes counts as
        // passed AND as flaky; the Full Stage Matrix panel still colors it
        // Flaky — one story: "green now, unstable".
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
        assert!(
            matrix.linux[0].latest_pass,
            "the panel entry carries the completion bit so its title \
             (count_passed = latest_pass) agrees with the header CHECKS"
        );
        assert_eq!(progress.total, 1);
        assert_eq!(
            progress.passed, 1,
            "a currently-passing check counts as passed the moment it goes green"
        );
        assert_eq!(
            progress.flaky, 1,
            "...while carrying the instability warning"
        );

        // A column whose latest outcome is FAIL counts in neither.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv(
            dir.path(),
            "overall_result,linux_stage_bootstrap\npass,pass\npass,fail\n",
        );
        let progress = load_stage_progress(dir.path()).unwrap();
        assert_eq!(progress.passed, 0);
        assert_eq!(progress.flaky, 0);
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

    fn write_matrix_csv_bytes(dir: &std::path::Path, content: &[u8]) {
        let docs = dir.join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(docs.join("live_lab_run_matrix.csv"), content).unwrap();
    }

    /// A genuinely empty (0-byte) file is distinct from a MISSING file (the
    /// `!path.exists()` early-return) -- it exists, but the `csv` crate has
    /// no header row to read at all. Every loader must degrade to its empty
    /// default, never panic.
    #[test]
    fn genuinely_empty_csv_file_does_not_panic_across_every_loader() {
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv_bytes(dir.path(), b"");

        let matrix = load_parity_matrix(dir.path()).expect("parity matrix");
        assert!(matrix.values().all(|state| *state == ParityState::Unproven));

        let progress = load_stage_progress(dir.path()).expect("stage progress");
        assert_eq!(progress.total, 0);
        assert_eq!(progress.passed, 0);

        let runs = load_recent_runs(dir.path(), 3).expect("recent runs");
        assert!(runs.is_empty());

        let full = load_full_stage_matrix(dir.path()).expect("full stage matrix");
        assert!(full.linux.is_empty());
        assert!(full.macos.is_empty());
        assert!(full.windows.is_empty());
        assert!(full.cross_os.is_empty());

        let sparklines = load_sparklines(dir.path(), 8).expect("sparklines");
        assert!(
            sparklines
                .values()
                .all(|history| history.iter().all(|o| *o == CellOutcome::NotRun))
        );

        let roles = load_latest_run_roles(dir.path()).expect("latest run roles");
        assert!(roles.is_empty());
    }

    #[test]
    fn a_csv_path_that_is_actually_a_directory_returns_err_not_panic() {
        // A rare but possible shape: the expected CSV path is a directory
        // (e.g. a botched `mkdir -p` upstream). Opening it must fail
        // cleanly, exactly like any other unreadable file, not panic --
        // never a false "all proven" / "0 runs" read presented as real data.
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("documents").join("operations");
        std::fs::create_dir_all(docs.join("live_lab_run_matrix.csv")).unwrap();

        // `load_parity_matrix` treats a header-read failure the same as "no
        // matrix data at all" (`.headers().ok()`, not `?`) rather than a
        // hard error -- still fail-safe (every cell reads Unproven, never a
        // false Proven/Failed), just via a different, deliberately lenient
        // path than the other loaders below.
        let matrix = load_parity_matrix(dir.path()).expect("does not hard-error");
        assert!(matrix.values().all(|state| *state == ParityState::Unproven));
        assert!(load_stage_progress(dir.path()).is_err());
        assert!(load_recent_runs(dir.path(), 3).is_err());
        assert!(load_full_stage_matrix(dir.path()).is_err());
    }

    #[test]
    fn invalid_utf8_bytes_in_a_data_row_are_skipped_not_erred() {
        // A concurrently-appended CSV row caught mid-write can briefly
        // contain a torn multi-byte UTF-8 sequence. The `csv` crate errors
        // on that ONE record when materializing it as a `StringRecord`;
        // every loader here must skip just that record; a header
        // discovery / dedupe pass over the pass/fail history from remaining
        // valid rows.
        let dir = tempfile::tempdir().unwrap();
        let mut content = b"overall_result,macos_stage_anchor\npass,pass\n".to_vec();
        content.extend_from_slice(b"pass,\xff\xfe\n");
        content.extend_from_slice(b"pass,fail\n");
        write_matrix_csv_bytes(dir.path(), &content);

        let matrix = load_parity_matrix(dir.path()).expect("parity matrix");
        // Latest DECISIVE value among the valid rows is "fail" (the invalid
        // row in between contributed nothing).
        assert_eq!(
            matrix.get(&(Role::Anchor, Os::Macos)),
            Some(&ParityState::Failed)
        );

        let runs = load_recent_runs(dir.path(), 5).expect("recent runs");
        assert_eq!(
            runs.len(),
            2,
            "the one invalid-UTF8 row must be dropped, not crash the read"
        );
    }

    #[test]
    fn ragged_rows_with_fewer_or_more_columns_than_header_do_not_panic() {
        // `flexible(true)` accepts rows that don't match the header's column
        // count at all (a real-world source of ragged rows: a schema
        // version bump that adds/removes a trailing column, or -- for the
        // very last row -- a concurrent writer's row caught mid-append).
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv_bytes(
            dir.path(),
            b"overall_result,macos_stage_anchor,windows_stage_relay\n\
              pass,pass\n\
              pass,fail,not_run,extra_unexpected_column\n\
              pass,pass,pass\n",
        );

        // Must not panic; every loader still produces a well-formed result.
        let matrix = load_parity_matrix(dir.path()).expect("parity matrix");
        assert!(matrix.contains_key(&(Role::Anchor, Os::Macos)));
        let progress = load_stage_progress(dir.path()).expect("stage progress");
        assert_eq!(progress.total, 2);
        let runs = load_recent_runs(dir.path(), 5).expect("recent runs");
        assert_eq!(runs.len(), 3);
    }

    #[test]
    fn a_truncated_last_row_without_a_trailing_newline_does_not_corrupt_earlier_rows() {
        // Simulates the exact "concurrently updated" moment: the CSV
        // appender has flushed 2 complete rows and is partway through
        // writing a 3rd when this read happens -- no trailing newline yet,
        // and the row itself has fewer fields than the header.
        let dir = tempfile::tempdir().unwrap();
        write_matrix_csv_bytes(
            dir.path(),
            b"overall_result,macos_stage_anchor\n\
              pass,pass\n\
              fail,fail\n\
              pass,pa",
        );

        let runs = load_recent_runs(dir.path(), 5).expect("recent runs");
        assert_eq!(runs.len(), 3, "{runs:?}");
        // The earlier, complete rows must read exactly as written --
        // untouched by the torn trailing row.
        assert_eq!(runs[2].overall_result, "pass");
        assert_eq!(runs[1].overall_result, "fail");
    }
}
