use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Layout, Rect},
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::config::MonitorConfig;
use crate::data::job_watcher::JobState;
use crate::data::run_matrix::{
    CellOutcome, FullStageMatrix, Os, ParityState, Role, RunSummary, StageProgress,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    StageGrid,
    VmStatus,
    Parity,
    Log,
    Jobs,
    StageMatrix,
    Agents,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentsCol {
    Patch,
    Review,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentsRow {
    Model,
    Iterations,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Run,
    Matrix,
}

#[derive(Debug, Clone)]
pub struct StageGroup {
    pub name: &'static str,
    pub stages: Vec<String>,
}

fn empty_stage_groups() -> Vec<StageGroup> {
    ["PRE", "BOOTSTRAP", "LIVE LAB"]
        .into_iter()
        .map(|name| StageGroup {
            name,
            stages: Vec::new(),
        })
        .collect()
}

/// For a FAILED run, locates `first_failed_stage` (alias-prefix stripped)
/// directly in the canonical PRE/BOOTSTRAP/LIVE LAB pipeline order (`groups`,
/// i.e. `App::planned_stage_groups`) and derives (passed, total) per group
/// from ITS POSITION: the pipeline is serial, so every step strictly before
/// the failure is known to have passed, the failing step and everything
/// after it did not. Returns `None` if the bare stage name isn't found in
/// any group at all (e.g. an unrecognized name), in which case the caller
/// should keep whatever CSV-column-based approximation it already had.
#[cfg(test)]
fn position_based_failure_breakdown(
    groups: &[StageGroup],
    first_failed_stage: &str,
) -> Option<([(usize, usize); 3], usize)> {
    let bare = first_failed_stage.rsplit("::").next().unwrap_or("");
    if bare.is_empty() {
        return None;
    }
    let failing_group_idx = groups
        .iter()
        .position(|g| g.stages.iter().any(|s| s == bare))?;
    let failing_local_idx = groups[failing_group_idx]
        .stages
        .iter()
        .position(|s| s == bare)?;

    let mut section_stages = [(0usize, 0usize); 3];
    for (i, group) in groups.iter().enumerate().take(3) {
        let total = group.stages.len();
        let passed = match i.cmp(&failing_group_idx) {
            std::cmp::Ordering::Less => total,
            std::cmp::Ordering::Equal => failing_local_idx,
            std::cmp::Ordering::Greater => 0,
        };
        section_stages[i] = (passed, total);
    }
    Some((section_stages, failing_group_idx))
}

/// Per-run counts derived from the run's OWN `stage_manifest.json` +
/// `orchestrate_result.json` (see [`run_plan_summary`]) -- the authoritative,
/// per-run-accurate, catalog-size-adaptive source, used in preference to the
/// CSV-column approximation whenever the run's report dir is still on disk.
struct PlanCounts {
    /// `(passed, in_scope_total)` per PRE / BOOTSTRAP / LIVE LAB group.
    section_stages: [(usize, usize); 3],
    subset_passed: usize,
    subset_total: usize,
    grand_total: usize,
    failing_section: Option<usize>,
}

/// Read a completed run's real per-stage plan + outcomes and fold them into
/// one coherent count triple. Every tally is in the SAME universe (the run's
/// manifest stage list), so `passed <= in_scope <= catalog` holds by
/// construction -- the fix for the "28/165 | 100" contradiction, where the
/// left fraction came from the manifest plan (165) and the right number from
/// CSV columns (100), two incommensurable universes. Fully adaptive: the
/// numbers move automatically as the manifest gains or loses stages, with no
/// hardcoded PRE count anywhere. Returns `None` (caller falls back to the
/// CSV-column approximation) when the run has no report dir recorded or its
/// report dir / manifest is no longer on disk.
fn run_plan_summary(repo_root: &Path, run: &RunSummary) -> Option<PlanCounts> {
    if run.report_dir.trim().is_empty() {
        return None;
    }
    let report_dir = resolve_report_dir(repo_root, run.report_dir.trim());
    let manifest = crate::data::stage_manifest::read_stage_manifest(&report_dir)
        .ok()
        .flatten()?;
    let outcomes = crate::data::stage_reader::read_orchestrate_result(&report_dir)
        .map(|result| result.outcomes)
        .unwrap_or_default();
    let status_of: HashMap<&str, &str> = outcomes
        .iter()
        .map(|o| (o.stage.as_str(), o.status.as_str()))
        .collect();

    let group_index = |group: &str| match group {
        "pre" => 0,
        "bootstrap" => 1,
        _ => 2,
    };
    // Synthetic aggregates (e.g. linux_live_suite) stand in for a whole
    // sub-suite whose members are also listed; counting them would
    // double-count, so they sit outside every tally.
    let planned: Vec<&crate::data::stage_manifest::ManifestStage> = manifest
        .stages
        .iter()
        .filter(|stage| !stage.synthetic)
        .collect();
    let grand_total = planned.len();
    // Position, among the enabled stages, of the furthest one that reached a
    // DECISIVE (pass/fail) outcome -- the "how far did the pipeline provably
    // get" frontier. Deliberately NOT counting `skip` here: the orchestrator
    // marks every downstream stage `skip` when it aborts on a failure, which
    // would otherwise push the frontier to the end of the list and wrongly
    // reclassify genuinely never-reached stages as passed-over infra.
    let enabled_names: Vec<&str> = planned
        .iter()
        .filter(|stage| stage.enabled)
        .map(|stage| stage.name.as_str())
        .collect();
    let frontier = enabled_names.iter().rposition(|name| {
        status_of.get(name).is_some_and(|status| {
            let parsed = crate::data::stage_reader::StageStatus::parse(status);
            parsed.is_satisfied() || parsed.is_failure()
        })
    });

    let mut section = [(0usize, 0usize); 3];
    let mut enabled_idx = 0usize;
    for stage in &planned {
        if !stage.enabled {
            continue;
        }
        let idx = enabled_idx;
        enabled_idx += 1;
        let status = status_of.get(stage.name.as_str()).copied().unwrap_or("");
        // Out of the in-scope denominator: (a) stages the orchestrator
        // skipped as not-applicable to this run's topology, and (b)
        // conditional infra the pipeline provably passed WITHOUT recording an
        // outcome (no status, sitting before the frontier) -- same rule that
        // clears those cells in the Stage Grid. A no-outcome stage AFTER the
        // frontier is genuinely never-reached (e.g. everything past an early
        // failure) and DOES stay in the denominator, so an early failure
        // still reads "died at N of many", not a misleadingly near-complete
        // fraction.
        if matches!(
            crate::data::stage_reader::StageStatus::parse(status),
            crate::data::stage_reader::StageStatus::Skipped
                | crate::data::stage_reader::StageStatus::NotApplicable
        ) {
            continue;
        }
        // A no-outcome stage is passed-over plumbing rather than a
        // never-reached check when EITHER it sits before the decisive
        // frontier, OR it's a PRE step: PRE is pure setup (never a parity
        // check), and its conditional infra (restart_unready_vms,
        // rediscover_local_utm) both records nothing when it no-ops AND is
        // appended at the very end of the manifest's stage list, so a
        // frontier check alone would miscount the trailing one as
        // never-reached.
        if status.is_empty() && (stage.group == "pre" || matches!(frontier, Some(f) if idx < f)) {
            continue;
        }
        let gi = group_index(&stage.group);
        section[gi].1 += 1;
        if crate::data::stage_reader::StageStatus::parse(status).is_satisfied() {
            section[gi].0 += 1;
        }
    }
    let subset_passed = section.iter().map(|(p, _)| *p).sum();
    let subset_total = section.iter().map(|(_, t)| *t).sum();
    let failing_section = if run.overall_result.eq_ignore_ascii_case("fail") {
        let bare = run.first_failed_stage.rsplit("::").next().unwrap_or("");
        manifest
            .stages
            .iter()
            .find(|stage| stage.name == bare)
            .map(|stage| group_index(&stage.group))
    } else {
        None
    };
    Some(PlanCounts {
        section_stages: section,
        subset_passed,
        subset_total,
        grand_total,
        failing_section,
    })
}

fn resolve_report_dir(repo_root: &Path, report_dir: &str) -> PathBuf {
    let path = Path::new(report_dir);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        repo_root.join(report_dir)
    }
}

fn apply_plan_counts(run: &mut RunSummary, counts: PlanCounts) {
    run.section_stages = counts.section_stages;
    run.subset_passed_stages = counts.subset_passed;
    run.subset_total_stages = counts.subset_total;
    // `.max` is belt-and-suspenders: subset_total is already a subset of
    // grand_total by construction, but this guarantees the displayed
    // "passed / in-scope | catalog" can never read the catalog smaller than
    // the in-scope count.
    run.total_stages = counts.grand_total.max(counts.subset_total);
    run.failing_section = counts.failing_section;
    run.counts_exact = true;
}

/// Applies `position_based_failure_breakdown` to a single `RunSummary` in
/// place, for a FAILED run whose `first_failed_stage` resolves to a known
/// pipeline position. FALLBACK used only when [`run_plan_summary`] can't read
/// the run's own manifest (report dir pruned). Overrides
/// `section_stages`/`failing_section` and the LEFT-hand
/// `subset_passed_stages`/`subset_total_stages` fraction, and sets
/// `total_stages` to the same pipeline-plan catalog so the card stays
/// coherent (`passed <= in-scope <= catalog`) -- it must NOT be left at the
/// CSV-column value, which lives in a different universe and produced the
/// "28/165 | 100" contradiction. A no-op for a passing run or an
/// unrecognized stage name.
#[cfg(test)]
fn apply_position_based_failure_override(groups: &[StageGroup], run: &mut RunSummary) {
    if !run.overall_result.eq_ignore_ascii_case("fail") {
        return;
    }
    let Some((section_stages, failing_section)) =
        position_based_failure_breakdown(groups, &run.first_failed_stage)
    else {
        return;
    };
    run.section_stages = section_stages;
    run.failing_section = Some(failing_section);
    let (passed, total) = section_stages
        .iter()
        .fold((0, 0), |(p, t), &(sp, st)| (p + sp, t + st));
    run.subset_passed_stages = passed;
    run.subset_total_stages = total;
    run.total_stages = total;
}

pub struct App {
    pub repo_root: PathBuf,
    pub config: MonitorConfig,

    pub active_job: Option<JobState>,
    pub stage_outcomes: Vec<crate::data::stage_reader::StageOutcome>,
    pub active_stage: Option<String>,
    pub stage_data_source: crate::data::stage_reader::OutcomeSource,
    pub stage_data_modified: Option<std::time::SystemTime>,
    /// Current refresh defects. Empty means every displayed source loaded;
    /// non-empty is rendered in the header so cached data never looks fresh.
    pub data_errors: Vec<String>,
    pub log_lines: Vec<String>,
    /// Lines above the bottom (0 = follow tail). Positive = user scrolled up / pinned.
    pub log_scroll: usize,
    /// Total line count when the user first scrolled away from the tail.
    pub log_scroll_anchor: usize,
    pub recent_runs: Vec<RunSummary>,

    pub vm_statuses: Vec<crate::data::vm_prober::VmStatus>,
    pub selected_vm: usize,
    pub vm_role_overrides: HashMap<String, String>,
    /// Alias -> role label from the most recent run's authoritative
    /// `{os}_{role}_alias` record (see `run_matrix::load_latest_run_roles`),
    /// used to name (and light up the parity glyph for) VMs the config's own
    /// role slots don't recognize but a real run actually elected.
    pub latest_run_roles: HashMap<String, String>,

    pub parity_matrix: HashMap<(Role, Os), ParityState>,
    pub parity_sparklines: HashMap<(Role, Os), Vec<CellOutcome>>,
    pub stage_progress: StageProgress,
    pub stage_timings: HashMap<String, u64>,
    pub full_stage_matrix: FullStageMatrix,
    pub stage_matrix_scroll: [usize; 3],
    pub stage_matrix_os_col: usize,
    /// Rows actually visible inside an OS column last time it was drawn
    /// (written by `stage_matrix_panel::render`, which only takes `&App` --
    /// `Cell` gives it write access without threading `&mut App` through
    /// the whole render tree), so the up/down handlers can clamp
    /// `stage_matrix_scroll` to the real max immediately instead of only
    /// at render time -- otherwise scrolling past the bottom lets the
    /// value run away unbounded, and un-scrolling has to walk all the way
    /// back before the view visibly moves again.
    pub stage_matrix_visible_rows: Cell<usize>,

    pub focused_panel: Panel,
    pub page: Page,
    /// Which of the 3 stage-grid groups (0=PRE, 1=BOOTSTRAP, 2=LIVE LAB) is
    /// focused. Left/Right selects the group; Up/Down moves the cursor
    /// within it -- each group keeps its own cursor (`stage_grid_row`)
    /// rather than one flat index spanning all 3, so moving down the PRE
    /// column doesn't spill over into BOOTSTRAP once it runs out.
    pub stage_grid_col: usize,
    pub stage_grid_row: [usize; 3],
    pub show_help: bool,
    pub show_stage_detail: bool,
    pub stage_detail_scroll: usize,
    pub should_quit: bool,

    pub orchestrator_pgid: Option<u32>,
    pub stop_after_current: bool,

    pub available_models: Vec<String>,
    pub available_variants: Vec<String>,
    pub patch_model_idx: usize,
    pub patch_variant_idx: usize,
    pub review_model_idx: usize,
    pub agents_sel_col: Option<AgentsCol>,
    pub agents_sel_row: Option<AgentsRow>,
    pub agents_active: bool,
    pub patch_iterations: u8,
    pub review_iterations: u8,
    /// Cached agent/cost-ledger stats for the Agents panel. Loaded (and the
    /// underlying cost ledger reconciled + persisted) only in
    /// `refresh_state`'s 2s cadence -- rendering happens roughly every 100ms
    /// (see `run_event_loop`'s poll timeout), and re-doing the ledger's file
    /// I/O and disk write on every draw would be both wasteful and a needless
    /// widening of the window for a torn/lost write to the shared ledger file.
    pub agents_view: crate::ui::agents_panel::AgentsView,

    active_stage_start: Option<std::time::Instant>,
    last_vm_probe: Option<std::time::Instant>,
    last_vm_readiness_probe: Option<std::time::Instant>,
    vm_readiness_task:
        Option<tokio::task::JoinHandle<HashMap<String, crate::data::vm_prober::LabReadiness>>>,
    /// The active (or most recently seen) run's own resolved plan, read
    /// from `<report_dir>/orchestration/stage_manifest.json`. When present
    /// the stage grid renders THIS instead of the hardcoded fallback
    /// catalog — the run's plan, pinned to the config that launched it
    /// (finding 1/7 of the 2026-07-03 live-lab findings). Kept after the
    /// run goes idle so a held run's display cannot drift under config
    /// edits; replaced when a run with a different report dir starts.
    run_manifest: Option<crate::data::stage_manifest::RunStageManifest>,
    run_manifest_dir: Option<PathBuf>,
    /// The previous run ended without a recorded ending: its job JSON
    /// still claims `running` but the PID is dead. Rendered as CRASHED in
    /// the header while idle (finding 3's monitor half) — previously
    /// indistinguishable from a clean IDLE.
    pub last_run_crashed: bool,
}

/// Which stage's log is most useful to show once a run goes idle: the
/// first "fail" entry if the run failed (immediately shows what broke),
/// else the last entry (whatever ran most recently) -- mirrors
/// `copy_stage_logs`'s fail-first heuristic, but prefers the LAST entry
/// over the FIRST as the non-failing fallback, since "the most recently
/// completed stage" is a more informative final snapshot than an
/// arbitrary early one. `None` only when there's nothing recorded at all.
fn final_stage_for_idle_log(
    stage_outcomes: &[crate::data::stage_reader::StageOutcome],
) -> Option<String> {
    stage_outcomes
        .iter()
        .find(|o| crate::data::stage_reader::StageStatus::parse(&o.status).is_failure())
        .or_else(|| stage_outcomes.last())
        .map(|o| o.stage.clone())
}

impl App {
    pub fn new(repo_root: PathBuf) -> Result<Self> {
        let mut config = MonitorConfig::load(&repo_root).unwrap_or_default();
        config.apply_fast_stage_defaults();
        let parity_matrix =
            crate::data::run_matrix::load_parity_matrix(&repo_root).unwrap_or_default();
        let parity_sparklines =
            crate::data::run_matrix::load_sparklines(&repo_root, 8).unwrap_or_default();
        let stage_progress =
            crate::data::run_matrix::load_stage_progress(&repo_root).unwrap_or_default();
        let stage_timings =
            crate::data::timings::load_stage_timings(&repo_root).unwrap_or_default();
        let full_stage_matrix =
            crate::data::run_matrix::load_full_stage_matrix(&repo_root).unwrap_or_default();

        let vm_role_overrides = default_vm_role_overrides(&config);
        let latest_run_roles =
            crate::data::run_matrix::load_latest_run_roles(&repo_root).unwrap_or_default();
        let recent_runs =
            crate::data::run_matrix::load_recent_runs(&repo_root, 3).unwrap_or_default();

        let available_models = load_available_models(&repo_root);
        let patch_model_idx = config
            .patch_model_idx
            .min(available_models.len().saturating_sub(1));
        let review_model_idx = config
            .review_model_idx
            .min(available_models.len().saturating_sub(1));
        let available_variants = vec!["max".to_owned(), "on".to_owned()];
        let patch_variant_idx = config
            .patch_variant_idx
            .min(available_variants.len().saturating_sub(1));

        let patch_iterations = config.patch_iterations.max(1);
        let review_iterations = config.review_iterations.max(1);
        let agents_view = crate::ui::agents_panel::AgentsView::load(&repo_root);

        let mut app = Self {
            repo_root,
            config,
            active_job: None,
            stage_outcomes: Vec::new(),
            active_stage: None,
            stage_data_source: crate::data::stage_reader::OutcomeSource::None,
            stage_data_modified: None,
            data_errors: Vec::new(),
            log_lines: Vec::new(),
            log_scroll: 0,
            log_scroll_anchor: 0,
            recent_runs,
            vm_statuses: Vec::new(),
            selected_vm: 0,
            vm_role_overrides,
            latest_run_roles,
            parity_matrix,
            parity_sparklines,
            stage_progress,
            stage_timings,
            full_stage_matrix,
            stage_matrix_scroll: [0, 0, 0],
            stage_matrix_os_col: 0,
            stage_matrix_visible_rows: Cell::new(0),
            focused_panel: Panel::VmStatus,
            page: Page::Overview,
            stage_grid_col: 0,
            stage_grid_row: [0, 0, 0],
            show_help: false,
            show_stage_detail: false,
            stage_detail_scroll: 0,
            should_quit: false,
            orchestrator_pgid: None,
            stop_after_current: false,
            available_models,
            available_variants,
            patch_model_idx,
            patch_variant_idx,
            review_model_idx,
            agents_sel_col: None,
            agents_sel_row: None,
            agents_active: false,
            patch_iterations,
            review_iterations,
            agents_view,
            active_stage_start: None,
            last_vm_probe: None,
            last_vm_readiness_probe: None,
            vm_readiness_task: None,
            run_manifest: None,
            run_manifest_dir: None,
            last_run_crashed: false,
        };
        app.prune_unknown_disabled_stages();
        Ok(app)
    }

    pub fn stage_timer_labels(&self) -> Vec<(&'static str, String)> {
        if self.pipeline_phase_index() >= 4 {
            return ["PRE", "BOOTSTRAP", "LIVE LAB"]
                .into_iter()
                .map(|name| (timer_short_name(name), "0s".to_owned()))
                .collect();
        }
        ["PRE", "BOOTSTRAP", "LIVE LAB"]
            .into_iter()
            .map(|name| {
                (
                    timer_short_name(name),
                    format_duration(self.estimated_group_remaining_secs(name)),
                )
            })
            .collect()
    }

    /// Terminal pipeline stages over this run's manifest-enabled plan.
    pub fn current_run_stage_progress(&self) -> (usize, usize) {
        let enabled: HashSet<String> = self
            .planned_stage_groups()
            .into_iter()
            .flat_map(|group| group.stages)
            .filter(|stage| self.stage_enabled(stage))
            .collect();
        let completed = self
            .stage_outcomes
            .iter()
            .filter(|outcome| {
                enabled.contains(&outcome.stage)
                    && crate::data::stage_reader::StageStatus::parse(&outcome.status).is_terminal()
            })
            .map(|outcome| outcome.stage.as_str())
            .collect::<HashSet<_>>()
            .len();
        (completed, enabled.len())
    }

    /// Selected validation/check executions. `None` for schema-v1 manifests:
    /// old evidence did not carry this fact, so guessing would violate the
    /// monitor's emit-don't-infer contract.
    pub fn current_run_check_progress(&self) -> Option<(usize, usize)> {
        let manifest = self.run_manifest.as_ref()?;
        let selected: Vec<&str> = manifest
            .stages
            .iter()
            .filter(|stage| {
                stage.enabled && !stage.synthetic && stage.counts_as_check == Some(true)
            })
            .map(|stage| stage.name.as_str())
            .collect();
        if manifest
            .stages
            .iter()
            .any(|stage| stage.enabled && !stage.synthetic && stage.counts_as_check.is_none())
        {
            return None;
        }
        let completed = selected
            .iter()
            .filter(|name| {
                self.stage_outcomes.iter().any(|outcome| {
                    outcome.stage == **name
                        && crate::data::stage_reader::StageStatus::parse(&outcome.status)
                            .is_terminal()
                })
            })
            .count();
        Some((completed, selected.len()))
    }

    pub fn stage_source_title(&self) -> &'static str {
        if !self.data_errors.is_empty() {
            return "DATA ERROR";
        }
        if self.active_job.is_some() {
            "LIVE RUN"
        } else if self.stage_data_source != crate::data::stage_reader::OutcomeSource::None {
            "PREVIOUS RUN"
        } else {
            "RUN DATA"
        }
    }

    pub fn stage_source_value(&self) -> String {
        if !self.data_errors.is_empty() {
            return format!("{} source error(s)", self.data_errors.len());
        }
        let detail = match (self.active_job.is_some(), self.stage_data_source) {
            (true, crate::data::stage_reader::OutcomeSource::LiveStagesTsv) => Some("TSV"),
            (true, crate::data::stage_reader::OutcomeSource::FinalResultJson) => {
                Some("legacy JSON")
            }
            (false, crate::data::stage_reader::OutcomeSource::LiveStagesTsv) => Some("TSV"),
            (false, crate::data::stage_reader::OutcomeSource::FinalResultJson) => None,
            (_, crate::data::stage_reader::OutcomeSource::None) => return "waiting".to_owned(),
        };
        let age = self
            .stage_data_modified
            .and_then(|time| time.elapsed().ok())
            .map(|elapsed| {
                let age = human_age(elapsed.as_secs());
                if age == "now" {
                    age
                } else {
                    format!("{age} ago")
                }
            })
            .unwrap_or_else(|| "age unknown".to_owned());
        match detail {
            Some(detail) => format!("{detail} · {age}"),
            None => age,
        }
    }

    pub fn stage_source_label(&self) -> String {
        format!(
            "{}: {}",
            self.stage_source_title(),
            self.stage_source_value()
        )
    }

    pub fn plan_source_label(&self) -> &'static str {
        if self.run_manifest.is_some() {
            "RUN MANIFEST"
        } else if self.run_manifest_dir.is_some() {
            "WAITING FOR MANIFEST"
        } else {
            "LEGACY PREVIEW"
        }
    }

    fn estimated_group_remaining_secs(&self, group_name: &str) -> u64 {
        let completed = self
            .stage_outcomes
            .iter()
            .filter(|o| crate::data::stage_reader::StageStatus::parse(&o.status).is_terminal())
            .map(|o| o.stage.as_str())
            .collect::<std::collections::HashSet<_>>();
        let active = self.active_stage.as_deref();
        let active_elapsed = self
            .active_stage_start
            .map(|started| started.elapsed().as_secs())
            .unwrap_or(0);

        self.planned_stage_groups()
            .into_iter()
            .find(|group| group.name == group_name)
            .into_iter()
            .flat_map(|group| group.stages)
            .filter(|stage| self.stage_enabled(stage))
            .filter(|stage| !completed.contains(stage.as_str()))
            .map(|stage| {
                let estimate = self.estimate_stage_secs(&stage);
                if active == Some(stage.as_str()) {
                    estimate.saturating_sub(active_elapsed).max(60)
                } else {
                    estimate
                }
            })
            .sum()
    }

    /// Stage time budget: max(floor, P90-of-terminal-history x 1.2 slack).
    /// The floor is the run manifest's cold-start budget when present
    /// (shared with the orchestrator side), else the hand-tuned defaults.
    /// P90 over ALL terminal outcomes replaces the old pass-only P50: the
    /// stages with no passing history are exactly the new cells an
    /// operator iterates on, and half of HEALTHY runs exceed a P50 by
    /// definition — the wrong statistic for an "overdue" signal
    /// (finding 6).
    fn estimate_stage_secs(&self, stage: &str) -> u64 {
        let floor = self
            .run_manifest
            .as_ref()
            .and_then(|manifest| {
                manifest
                    .stages
                    .iter()
                    .find(|entry| entry.name == stage)
                    .map(|entry| entry.budget_secs)
            })
            .filter(|secs| *secs > 0)
            .unwrap_or_else(|| default_stage_secs(stage));
        let history = self
            .stage_timings
            .get(stage)
            .copied()
            .filter(|secs| *secs > 0)
            .map(|p90| p90.saturating_mul(6) / 5)
            .unwrap_or(0);
        floor.max(history)
    }

    fn ensure_active_stage_visible(&mut self) {
        let Some(active) = self.active_stage.as_deref() else {
            return;
        };
        if self
            .stage_outcomes
            .iter()
            .any(|outcome| outcome.stage == active)
        {
            return;
        }
        self.stage_outcomes
            .push(crate::data::stage_reader::StageOutcome {
                stage: active.to_owned(),
                status: "running".to_owned(),
                summary: "active stage".to_owned(),
                artifacts: Vec::new(),
            });
    }

    /// Clears everything that must not survive into idle once a job
    /// disappears: `active_stage`/`active_stage_start`/`orchestrator_pgid`,
    /// and any synthetic "running"-status placeholder(s)
    /// `ensure_active_stage_visible` pushed into `stage_outcomes` for
    /// whatever stage was active. Real recorded outcomes (from
    /// orchestrate_result.json / stages.tsv) are always pass/fail/skipped --
    /// "running" is exclusively that placeholder's marker -- so stripping it
    /// unconditionally here (not just when a fresh, non-empty result read
    /// happened to replace the whole list) is always safe. Without this, a
    /// run stopped before any real result ever existed left the placeholder
    /// in place forever, still rendering a spinner in Stage Grid / Stage
    /// Detail long after the lab had gone idle. Deliberately leaves
    /// `stage_outcomes` and `log_lines` otherwise untouched -- the last
    /// run's real outcomes stay on display until the next run starts.
    fn clear_stale_active_run_state(&mut self) {
        self.stage_outcomes.retain(|o| o.status != "running");
        self.active_stage = None;
        self.active_stage_start = None;
        self.orchestrator_pgid = None;
    }

    /// The stage name under the stage-grid cursor, per `stage_grid_col` /
    /// `stage_grid_row`.
    pub fn selected_stage_name(&self) -> Option<String> {
        let groups = self.planned_stage_groups();
        let group = groups.get(self.stage_grid_col)?;
        let row = self.stage_grid_row[self.stage_grid_col];
        group.stages.get(row).cloned()
    }

    pub fn selected_stage_outcome(&self) -> Option<&crate::data::stage_reader::StageOutcome> {
        let stage = self.selected_stage_name()?;
        self.stage_outcomes.iter().find(|o| o.stage == stage)
    }

    fn selected_stage_has_outcome(&self) -> bool {
        self.selected_stage_outcome().is_some()
    }

    pub fn pipeline_steps(&self) -> Vec<(&'static str, bool, bool)> {
        let active_idx = self.pipeline_phase_index();
        [
            "prepare VMs",
            "build binaries",
            "bootstrap rustynet",
            "run live lab",
            "generate report",
            "act on report",
        ]
        .into_iter()
        .enumerate()
        .map(|(idx, label)| (label, idx == active_idx, idx < active_idx))
        .collect()
    }

    fn pipeline_phase_index(&self) -> usize {
        if self
            .log_lines
            .iter()
            .any(|line| line.contains("OpenCode main agent") || line.contains("patch"))
        {
            return 5;
        }
        if self.log_lines.iter().any(|line| {
            line.contains("generating report")
                || line.contains("failure_digest")
                || line.contains("report-review")
        }) {
            return 4;
        }
        if let Some(stage) = self.active_stage.as_deref() {
            return pipeline_phase_for_stage(stage);
        }
        if self
            .active_job
            .as_ref()
            .map(|job| matches!(job.state.as_str(), "done" | "crashed"))
            .unwrap_or(false)
        {
            return 4;
        }
        0
    }

    /// Flattened view of `planned_stage_groups()`. Not used by the app
    /// itself anymore (the stage grid now navigates per-column), kept as
    /// a convenience for tests that don't care about grouping.
    #[allow(dead_code)]
    pub fn planned_stages(&self) -> Vec<String> {
        self.planned_stage_groups()
            .into_iter()
            .flat_map(|group| group.stages)
            .collect()
    }

    /// Plain-text rendering of the current model — the stage grid (grouped,
    /// with per-stage status + per-group passed/total), the active stage, and
    /// VM roles — for the headless `--snapshot` mode. Lets a script or CI
    /// verify what the TUI would show for the latest/active run without a real
    /// terminal (Bucket 3, Full-Replacement DoD). Dialect-agnostic: it renders
    /// whatever `planned_stage_groups()` (manifest-driven) + `stage_outcomes`
    /// (orchestrate_result/stages.tsv) contain, so it works for a bash or a
    /// Rust `--node` run identically.
    pub fn snapshot_text(&self) -> String {
        use std::fmt::Write as _;
        let status_by_stage: std::collections::HashMap<&str, &str> = self
            .stage_outcomes
            .iter()
            .map(|o| (o.stage.as_str(), o.status.as_str()))
            .collect();
        let mut out = String::new();
        let _ = writeln!(out, "=== rustynet-lab-monitor snapshot ===");
        let (run_done, run_total) = self.current_run_stage_progress();
        let run_checks = self
            .current_run_check_progress()
            .map(|(done, total)| format!("{done}/{total}"))
            .unwrap_or_else(|| "n/a (manifest schema lacks counts_as_check)".to_owned());
        let _ = writeln!(
            out,
            "plan_source: {}\ndata_source: {}\nrun_stages_settled: {run_done}/{run_total}\nrun_tests_settled: {run_checks}\ncoverage: {}/{}",
            self.plan_source_label(),
            self.stage_source_label(),
            self.stage_progress.passed,
            self.stage_progress.total
        );
        for error in &self.data_errors {
            let _ = writeln!(out, "data_error: {error}");
        }
        let _ = writeln!(
            out,
            "active_stage: {}",
            self.active_stage.as_deref().unwrap_or("-")
        );
        // Show the run's ENABLED plan (the manifest's in-scope stages), not the
        // full ~166-stage catalog — so the grid + counts reflect what this run
        // actually planned/ran (e.g. a full Rust plan of up to 67 stages) rather than being
        // diluted by the disabled catalog. Groups with nothing enabled are hidden.
        let _ = writeln!(out, "\nSTAGE GRID:");
        for group in self.planned_stage_groups() {
            let enabled: Vec<&String> = group
                .stages
                .iter()
                .filter(|s| self.stage_enabled(s))
                .collect();
            if enabled.is_empty() {
                continue;
            }
            let completed = enabled
                .iter()
                .filter(|s| {
                    status_by_stage.get(s.as_str()).is_some_and(|status| {
                        crate::data::stage_reader::StageStatus::parse(status).is_terminal()
                    })
                })
                .count();
            let _ = writeln!(out, "  [{}] ({completed}/{})", group.name, enabled.len());
            for stage in enabled {
                let status = status_by_stage.get(stage.as_str()).copied().unwrap_or("-");
                let _ = writeln!(out, "    {stage:<34} {status}");
            }
        }
        let _ = writeln!(out, "\nVM STATUS:");
        for vm in &self.vm_statuses {
            let _ = writeln!(
                out,
                "  {:<20} {:<9} power={:<8} online={} ready={:?} run={:<8} role={}",
                vm.alias,
                vm.platform,
                vm.power_state,
                if vm.ssh_ok { "up" } else { "down" },
                vm.lab_readiness.state,
                self.run_use_for_vm(&vm.alias),
                self.actual_role_for_vm(&vm.alias)
            );
        }
        out
    }

    /// Enabled stages the serial pipeline has provably advanced PAST but
    /// which never recorded a terminal outcome of their own -- conditional
    /// infra like `restart_unready_vms` / `rediscover_local_utm` /
    /// `cross_network_preflight` that no-op (record nothing) when their
    /// precondition already holds. Any enabled stage that sits before the
    /// furthest recorded terminal outcome in pipeline order, yet has no
    /// outcome, is treated as satisfied so its column can CLEAR instead of
    /// showing a forever-pending cell that stops PRE (or any earlier phase)
    /// from ever reading complete. Uses the same flattened planned order and
    /// terminal-status definition as the active-stage inference, so the two
    /// never disagree about "how far has the pipeline gotten".
    pub fn implicitly_completed_stages(&self) -> HashSet<String> {
        let ordered: Vec<String> = self
            .planned_stage_groups()
            .into_iter()
            .flat_map(|group| group.stages)
            .filter(|stage| self.stage_enabled(stage))
            .collect();
        let finished: HashSet<&str> = self
            .stage_outcomes
            .iter()
            .filter(|o| crate::data::stage_reader::StageStatus::parse(&o.status).is_terminal())
            .map(|o| o.stage.as_str())
            .collect();
        let Some(furthest_done) = ordered
            .iter()
            .rposition(|stage| finished.contains(stage.as_str()))
        else {
            return HashSet::new();
        };
        ordered
            .iter()
            .take(furthest_done)
            .filter(|stage| !finished.contains(stage.as_str()))
            .cloned()
            .collect()
    }

    /// `disabled_stages` (config.rs) is persisted as a bare `Vec<String>`
    /// with no validation against what this monitor actually knows how to
    /// run -- a stage renamed/removed in a later version, or a hand-typo'd
    /// entry from manual TOML editing, would otherwise sit in the list
    /// forever with zero effect and zero visibility. Called after every
    /// config load (fresh startup and the idle-poll hot-reload in
    /// `refresh_state`).
    fn prune_unknown_disabled_stages(&mut self) {
        let known: HashSet<String> = self.planned_stages().into_iter().collect();
        let before = self.config.disabled_stages.len();
        self.config
            .disabled_stages
            .retain(|stage| known.contains(stage));
        let pruned = before - self.config.disabled_stages.len();
        if pruned > 0 {
            tracing::warn!(pruned, "removed unknown stage name(s) from disabled_stages");
            self.save_config_best_effort();
        }
    }

    pub fn stage_enabled(&self, stage: &str) -> bool {
        !self
            .config
            .disabled_stages
            .iter()
            .any(|disabled| disabled == stage)
            && self.stage_selected_for_current_target(stage)
    }

    /// Whether `stage` is even *possible* for the current target config
    /// (right platform/role elected) -- independent of whether the user has
    /// manually toggled it off via `toggle_selected_stage`. Grid rendering
    /// needs this split from `stage_enabled`: a stage the user disabled but
    /// that is still possible must render as "possible, not currently
    /// planned" (white, empty box), never as "impossible" (grayed out) --
    /// greying out is reserved for genuinely impossible stages, e.g. a
    /// Windows-only check on a Linux-only run.
    pub fn stage_selected_for_current_target(&self, stage: &str) -> bool {
        // The run's own manifest is authoritative when present: it was
        // resolved from the selectors that actually launched the run, so
        // it cannot disagree with what the orchestrator is doing.
        if let Some(manifest) = &self.run_manifest
            && let Some(entry) = manifest.stages.iter().find(|entry| entry.name == stage)
        {
            return entry.enabled;
        }
        if matches!(
            stage,
            "preflight"
                | "prepare_source_archive"
                | "verify_ssh_reachability"
                | "prime_remote_access"
                | "cleanup_hosts"
                | "bootstrap_hosts"
                | "collect_pubkeys"
                | "membership_setup"
                | "distribute_membership_state"
                | "issue_and_distribute_assignments"
                | "issue_and_distribute_traversal"
                | "issue_and_distribute_dns_zone"
                | "enforce_baseline_runtime"
                | "validate_baseline_runtime"
        ) {
            return true;
        }
        if matches!(
            stage,
            "bootstrap_macos_host"
                | "collect_macos_pubkey"
                | "amend_membership_for_macos"
                | "distribute_macos_bundles"
                | "validate_macos_mesh_join"
        ) {
            return self.config.wants_macos();
        }
        if matches!(
            stage,
            "bootstrap_windows_host"
                | "amend_membership_for_windows"
                | "stage_windows_bundles_for_distribution"
                | "distribute_windows_membership"
                | "issue_windows_assignment"
                | "distribute_windows_assignment"
                | "validate_windows_mesh_join"
        ) {
            return self.config.wants_windows();
        }
        if matches!(
            stage,
            "activate_macos_exit_role"
                | "capture_macos_exit_evidence_artifacts"
                | "validate_macos_exit_nat_lifecycle"
                | "validate_macos_ipv6_leak"
                | "validate_macos_exit_dns_failclosed"
                | "validate_macos_exit_killswitch_precedence"
        ) {
            return self.config.macos_promote_exit || self.config.exit_platform == "macos";
        }
        if stage == "validate_macos_relay_service_lifecycle" {
            return self.config.relay_platform == "macos";
        }
        if matches!(
            stage,
            "deploy_macos_anchor_profile" | "validate_macos_anchor_bundle_pull"
        ) {
            return self.config.anchor_platform == "macos";
        }
        if stage == "validate_macos_admin_issue" {
            return self.config.admin_platform == "macos";
        }
        if stage == "validate_macos_blind_exit" {
            return self.config.blind_exit_platform == "macos";
        }
        if stage == "validate_macos_key_custody" {
            return self.config.wants_macos();
        }
        if matches!(
            stage,
            "validate_windows_client_install"
                | "validate_windows_runtime_acls"
                | "validate_windows_named_pipe_acls"
                | "validate_windows_service_hardening"
                | "validate_windows_key_custody"
                | "validate_windows_dns_failclosed"
        ) {
            return self.config.wants_windows();
        }
        if matches!(
            stage,
            "promote_windows_exit_active"
                | "validate_windows_exit_nat_lifecycle"
                | "validate_windows_exit_dns_failclosed"
                | "validate_windows_exit_killswitch_precedence"
        ) {
            return self.config.exit_platform == "windows";
        }
        if stage == "validate_windows_relay_service_lifecycle" {
            return self.config.relay_platform == "windows";
        }
        if stage == "validate_windows_anchor_bundle_pull" {
            return self.config.anchor_platform == "windows";
        }
        if stage == "validate_windows_admin_issue" {
            return self.config.admin_platform == "windows";
        }
        // Per-OS audit families run whenever that guest participates.
        if matches!(
            stage,
            "validate_macos_membership_revoke_applies"
                | "validate_macos_membership_signature_forgery"
                | "validate_macos_gossip_revoked_readmit"
                | "validate_macos_enrollment_replay"
                | "validate_macos_hello_limiter_flood"
                | "validate_macos_runtime_acls"
                | "validate_macos_service_hardening"
                | "validate_macos_mesh_status"
                | "validate_macos_authenticode"
                | "validate_macos_privileged_helper_allowlist"
                | "validate_macos_policy_default_deny"
                | "validate_macos_revoked_peer_denied_e2e"
                | "validate_macos_blind_exit_reversal_denied"
        ) {
            return self.config.wants_macos();
        }
        if matches!(
            stage,
            "validate_windows_membership_revoke_applies"
                | "validate_windows_membership_signature_forgery"
                | "validate_windows_gossip_revoked_readmit"
                | "validate_windows_enrollment_replay"
                | "validate_windows_hello_limiter_flood"
                | "validate_windows_mesh_status"
                | "validate_windows_privileged_helper_allowlist"
                | "validate_windows_policy_default_deny"
                | "validate_windows_revoked_peer_denied_e2e"
                | "validate_windows_blind_exit_reversal_denied"
        ) {
            return self.config.wants_windows();
        }
        if stage == "linux_live_suite" {
            return !self.config.skip_linux_live_suite;
        }
        linux_live_lab_catalog().contains(&stage) && !self.config.skip_linux_live_suite
    }

    /// The full stage catalog, every group unconditional -- whether a
    /// given stage actually runs for the *next* launch depends on the
    /// current config (mac/windows VM selection, --skip-* flags, which
    /// platform is elected exit/relay/anchor/admin/blind_exit), which
    /// `stage_enabled` reports for styling (grayed out vs white), but the
    /// stage itself is always listed. Previously mac/windows-only stages
    /// were omitted from the returned groups entirely whenever
    /// `wants_macos()`/`wants_windows()` was false, so e.g. running a
    /// Linux-only lab made every macOS/Windows stage vanish from the grid
    /// instead of just showing as not-currently-planned -- and disagreed
    /// with the Full Stage Matrix / Previous Runs panels, which show the
    /// whole history-wide catalog regardless of the *next* run's config.
    pub fn planned_stage_groups(&self) -> Vec<StageGroup> {
        if let Some(groups) = self.manifest_stage_groups() {
            return groups;
        }
        // A run/report has been selected but its manifest is missing or
        // invalid. Never replace run truth with a local catalog: render an
        // explicit waiting/error state until the producer contract appears.
        if self.run_manifest_dir.is_some() {
            return empty_stage_groups();
        }
        let pre = [
            "preflight",
            "prepare_source_archive",
            "verify_ssh_reachability",
            "prime_remote_access",
            "cleanup_hosts",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();
        let mut bootstrap = [
            "bootstrap_hosts",
            "collect_pubkeys",
            "membership_setup",
            "distribute_membership_state",
            "issue_and_distribute_assignments",
            "issue_and_distribute_traversal",
            "issue_and_distribute_dns_zone",
            "enforce_baseline_runtime",
            "validate_baseline_runtime",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<Vec<_>>();

        bootstrap.extend(
            [
                "bootstrap_macos_host",
                "collect_macos_pubkey",
                "amend_membership_for_macos",
                "distribute_macos_bundles",
                "validate_macos_mesh_join",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        bootstrap.extend(
            [
                // The real Windows sidecar pipeline, in dispatch order.
                // `collect_windows_pubkey` and `distribute_windows_bundles`
                // were phantoms: they never existed in executing code
                // (2026-07-03 findings, finding 1) — the real stages are
                // the bundle staging + membership/assignment distribution
                // quartet below.
                "bootstrap_windows_host",
                "amend_membership_for_windows",
                "stage_windows_bundles_for_distribution",
                "distribute_windows_membership",
                "issue_windows_assignment",
                "distribute_windows_assignment",
                "validate_windows_mesh_join",
            ]
            .into_iter()
            .map(str::to_owned),
        );

        let mut live_lab: Vec<String> = macos_live_lab_catalog()
            .iter()
            .map(|stage| (*stage).to_owned())
            .collect();
        live_lab.extend(
            windows_live_lab_catalog()
                .iter()
                .map(|stage| (*stage).to_owned()),
        );
        live_lab.push("linux_live_suite".to_owned());
        live_lab.extend(
            linux_live_lab_catalog()
                .iter()
                .map(|stage| (*stage).to_owned()),
        );

        vec![
            StageGroup {
                name: "PRE",
                stages: pre,
            },
            StageGroup {
                name: "BOOTSTRAP",
                stages: bootstrap,
            },
            StageGroup {
                name: "LIVE LAB",
                stages: live_lab,
            },
        ]
    }

    /// The stage grid derived from the active/held run's own manifest:
    /// pre → PRE, bootstrap → BOOTSTRAP, everything else (live, chaos,
    /// job) → LIVE LAB, in the manifest's own pipeline order. `None` when
    /// no manifest has been seen (pre-manifest report dirs, fresh monitor)
    /// — callers fall back to the hardcoded catalog.
    fn manifest_stage_groups(&self) -> Option<Vec<StageGroup>> {
        let manifest = self.run_manifest.as_ref()?;
        let mut pre = Vec::new();
        let mut bootstrap = Vec::new();
        let mut live = Vec::new();
        for stage in manifest.stages.iter().filter(|stage| !stage.synthetic) {
            match stage.group.as_str() {
                "pre" => pre.push(stage.name.clone()),
                "bootstrap" => bootstrap.push(stage.name.clone()),
                _ => live.push(stage.name.clone()),
            }
        }
        Some(vec![
            StageGroup {
                name: "PRE",
                stages: pre,
            },
            StageGroup {
                name: "BOOTSTRAP",
                stages: bootstrap,
            },
            StageGroup {
                name: "LIVE LAB",
                stages: live,
            },
        ])
    }

    pub async fn refresh_state(&mut self) {
        self.data_errors.clear();
        if self.active_job.is_none()
            && let Ok(mut config) = MonitorConfig::load(&self.repo_root)
        {
            config.apply_fast_stage_defaults();
            self.config = config;
            self.prune_unknown_disabled_stages();
        }
        self.stop_after_current =
            crate::control::stopper::stop_after_current_requested(&self.repo_root);

        // Poll for active job (sync, fast)
        match crate::data::job_watcher::find_active_job(&self.repo_root) {
            Ok(Some(job)) => {
                let is_new_job = self.active_job.as_ref().map(|j| j.report_dir.as_str())
                    != Some(job.report_dir.as_str());
                if let Some(args) = &job.request_args {
                    let mut config = self.config.clone();
                    config.apply_request_args(args);
                    self.config = config;
                } else if is_new_job {
                    // Jobs launched outside this monitor (raw CLI, another
                    // user's session) never carry request_args (see
                    // JobState::request_args) -- without this, the stage
                    // grid keeps showing whatever target THIS monitor last
                    // had configured locally, completely unrelated to the
                    // job whose live progress it's actually displaying
                    // (e.g. showing only macOS stages enabled while the
                    // active job is a Linux blind_exit run). Recover the
                    // real role/platform from the report dir's own naming
                    // convention and reconfigure to match -- only when the
                    // job actually changed, so an already-adopted target
                    // isn't reset every 2s poll of the same ongoing job.
                    if let Some((role, platform)) =
                        crate::data::job_watcher::infer_role_and_platform_from_report_dir(
                            Path::new(&job.report_dir),
                        )
                    {
                        self.configure_target(&role, &platform, None);
                    }
                }
                self.last_run_crashed = false;
                let report_dir = self.repo_root.join(&job.report_dir);
                // Mark active before plan/outcome calculations: if manifest
                // has not arrived, callers must see WAITING, never preview.
                self.active_job = Some(job.clone());
                // Adopt the run's own stage manifest as it appears. A new
                // report dir resets the held manifest; while the dir is
                // unchanged and no manifest has been seen yet, keep
                // retrying each poll — the orchestrator emits it at run
                // start, which can land moments after the job JSON.
                if self.run_manifest_dir.as_deref() != Some(report_dir.as_path()) {
                    self.run_manifest = None;
                    self.run_manifest_dir = Some(report_dir.clone());
                }
                // Re-read every poll. Resume/rerun may legitimately replace
                // the manifest in the SAME report dir for a new invocation.
                match crate::data::stage_manifest::read_stage_manifest(&report_dir) {
                    Ok(manifest) => self.run_manifest = manifest,
                    Err(err) => {
                        self.run_manifest = None;
                        self.data_errors.push(format!("manifest: {err}"));
                    }
                }
                match crate::data::stage_reader::read_active_stage_state(&report_dir) {
                    Ok(read) => {
                        self.stage_outcomes = read.result.outcomes;
                        self.stage_data_source = read.source;
                        self.stage_data_modified = read.modified;
                    }
                    Err(err) => {
                        self.stage_outcomes.clear();
                        self.active_stage = None;
                        self.stage_data_source = crate::data::stage_reader::OutcomeSource::None;
                        self.stage_data_modified = None;
                        self.data_errors.push(format!("stages: {err}"));
                    }
                }
                let ordered_enabled_stages: Vec<String> = self
                    .planned_stage_groups()
                    .into_iter()
                    .flat_map(|group| group.stages)
                    .filter(|stage| self.stage_enabled(stage))
                    .collect();
                if let Ok(active) = crate::data::stage_reader::infer_active_stage(
                    &report_dir,
                    &ordered_enabled_stages,
                    &self.stage_outcomes,
                ) {
                    if self.active_stage.as_deref() != active.as_deref() {
                        self.active_stage_start = Some(std::time::Instant::now());
                    }
                    self.active_stage = active;
                    self.ensure_active_stage_visible();
                }
            }
            Ok(None) => {
                if let Some(prev_job) = self.active_job.take() {
                    // The job left the active scan. If its JSON still says
                    // `running`, the PID died without the worker recording
                    // an ending — crashed/abandoned, not done.
                    self.last_run_crashed = crate::data::job_watcher::job_state_by_id(
                        &self.repo_root,
                        &prev_job.job_id,
                    )
                    .is_some_and(|job| job.state == "running");
                    // Do one final read to replace any synthetic "running" entries
                    // with the definitive pass/fail outcomes before going idle.
                    let report_dir = self.repo_root.join(&prev_job.report_dir);
                    match crate::data::stage_reader::read_completed_stage_state(&report_dir) {
                        Ok(read) if !read.result.outcomes.is_empty() => {
                            self.stage_outcomes = read.result.outcomes;
                            self.stage_data_source = read.source;
                            self.stage_data_modified = read.modified;
                        }
                        Ok(_) => {}
                        Err(err) => self.data_errors.push(format!("final stages: {err}")),
                    }
                    // The "reload log for active stage" block below only runs
                    // while active_job is Some -- without a final catch-up
                    // here, log_lines freezes at whatever the last live poll
                    // saw, which can be well behind the truth if the real run
                    // raced ahead (or fully finished) between that poll and
                    // this one going idle. Verified in the field: a run whose
                    // last live poll caught "bootstrap_macos_host, no log yet"
                    // kept showing that exact placeholder for 5+ minutes after
                    // the run had actually gone on to complete 25 more stages
                    // and finish, because nothing ever told log_lines to look
                    // again.
                    if let Some(stage) = final_stage_for_idle_log(&self.stage_outcomes)
                        && let Ok(lines) = crate::data::log_tailer::summarize_stage_lines(
                            &self.repo_root,
                            &report_dir,
                            &stage,
                        )
                        && !lines.is_empty()
                    {
                        self.log_lines = lines;
                    }
                    self.clear_stale_active_run_state();
                    // Keep stage_outcomes and log_lines — display last run until next one starts.
                }
            }
            Err(err) => self.data_errors.push(format!("job state: {err}")),
        }

        // Reload log for active stage, falling back to monitor stdout/stderr during launch.
        if let Some(ref job) = self.active_job {
            let report_dir = self.repo_root.join(&job.report_dir);
            let mut loaded = false;
            if let Some(ref stage) = self.active_stage
                && let Ok(lines) = crate::data::log_tailer::summarize_stage_lines(
                    &self.repo_root,
                    &report_dir,
                    stage,
                )
                && !lines.is_empty()
            {
                self.log_lines = lines;
                loaded = true;
            }
            if !loaded {
                for name in ["monitor_stderr.log", "monitor_stdout.log"] {
                    let log_path = report_dir.join(name);
                    if let Ok(lines) = crate::data::log_tailer::tail_lines(&log_path, 200)
                        && !lines.is_empty()
                    {
                        self.log_lines = lines;
                        break;
                    }
                }
            }
        }

        // Active lab: 5s reachability freshness. Idle: 30s to avoid needless
        // LAN traffic. Stage state remains on the independent 2s cadence.
        let now = std::time::Instant::now();
        let vm_probe_interval_secs = if self.active_job.is_some() { 5 } else { 30 };
        let should_probe = self
            .last_vm_probe
            .map(|t| now.duration_since(t).as_secs() >= vm_probe_interval_secs)
            .unwrap_or(true);

        if should_probe {
            self.last_vm_probe = Some(now);
            let cached_readiness = self
                .vm_statuses
                .iter()
                .map(|vm| (vm.alias.clone(), vm.lab_readiness.clone()))
                .collect();
            match probe_vms_sync(&self.repo_root, &cached_readiness).await {
                Ok(statuses) => self.vm_statuses = statuses,
                Err(err) => self.data_errors.push(format!("VM discovery: {err}")),
            }
            if self.selected_vm >= self.vm_statuses.len() {
                self.selected_vm = self.vm_statuses.len().saturating_sub(1);
            }
        }

        // Tool readiness is slower than power/TCP discovery. Run canonical
        // guest preflight off-loop, retain last result, refresh every minute.
        if self
            .vm_readiness_task
            .as_ref()
            .is_some_and(tokio::task::JoinHandle::is_finished)
            && let Some(task) = self.vm_readiness_task.take()
        {
            match task.await {
                Ok(results) => {
                    for vm in &mut self.vm_statuses {
                        if let Some(readiness) = results.get(&vm.alias) {
                            vm.lab_readiness = readiness.clone();
                        }
                    }
                }
                Err(err) => self
                    .data_errors
                    .push(format!("VM lab readiness task: {err}")),
            }
        }
        let readiness_due = self
            .last_vm_readiness_probe
            .map(|t| now.duration_since(t).as_secs() >= 60)
            .unwrap_or(true);
        if readiness_due && self.vm_readiness_task.is_none() {
            let aliases = self
                .vm_statuses
                .iter_mut()
                .filter(|vm| vm.inventory_registered && vm.ssh_ok)
                .map(|vm| {
                    vm.lab_readiness = crate::data::vm_prober::LabReadiness::checking();
                    vm.alias.clone()
                })
                .collect::<Vec<_>>();
            if !aliases.is_empty() {
                self.last_vm_readiness_probe = Some(now);
                let repo_root = self.repo_root.clone();
                self.vm_readiness_task = Some(tokio::spawn(async move {
                    crate::data::vm_prober::probe_lab_readiness(&repo_root, &aliases).await
                }));
            }
        }

        match crate::data::run_matrix::load_parity_matrix(&self.repo_root) {
            Ok(matrix) => self.parity_matrix = matrix,
            Err(err) => self.data_errors.push(format!("parity matrix: {err}")),
        }
        match crate::data::run_matrix::load_latest_run_roles(&self.repo_root) {
            Ok(roles) => self.latest_run_roles = roles,
            Err(err) => self.data_errors.push(format!("run roles: {err}")),
        }
        match crate::data::run_matrix::load_sparklines(&self.repo_root, 8) {
            Ok(sparklines) => self.parity_sparklines = sparklines,
            Err(err) => self.data_errors.push(format!("sparklines: {err}")),
        }
        match crate::data::run_matrix::load_stage_progress(&self.repo_root) {
            Ok(progress) => self.stage_progress = progress,
            Err(err) => self.data_errors.push(format!("coverage: {err}")),
        }
        match crate::data::timings::load_stage_timings(&self.repo_root) {
            Ok(stage_timings) => self.stage_timings = stage_timings,
            Err(err) => self.data_errors.push(format!("timings: {err}")),
        }
        match crate::data::run_matrix::load_full_stage_matrix(&self.repo_root) {
            Ok(full_stage_matrix) => self.full_stage_matrix = full_stage_matrix,
            Err(err) => self.data_errors.push(format!("stage matrix: {err}")),
        }
        match crate::data::run_matrix::load_recent_runs(&self.repo_root, 3) {
            Ok(runs) => {
                self.recent_runs = runs;
                // load_recent_runs computes section_stages/failing_section from
                // CSV CHECK COLUMNS, a coarser, differently-shaped vocabulary
                // than the pipeline STEP names Stage Grid uses (e.g. BOOTSTRAP
                // is 12 CSV columns -- 4 suffixes x 3 OS -- vs 19 named pipeline
                // steps) -- and `first_failed_stage` is always a pipeline step
                // name (e.g. "bootstrap_windows_host"), which never matches a
                // CSV column pattern, so the failing section silently defaulted
                // to LIVE LAB every time regardless of where the failure
                // actually was. Prefer the pipeline-position breakdown instead,
                // wherever it resolves.
                let repo_root = self.repo_root.clone();
                for run in &mut self.recent_runs {
                    // Only a run's OWN manifest can produce exact pipeline
                    // counts. With pruned evidence, keep the CSV-only summary
                    // explicitly inexact; never substitute today's catalog.
                    if let Some(counts) = run_plan_summary(&repo_root, run) {
                        apply_plan_counts(run, counts);
                    }
                }
            }
            Err(err) => self.data_errors.push(format!("recent runs: {err}")),
        }
        // Idle (no active job): render the NEWEST run's OWN manifest + outcomes so
        // the stage grid + counts reflect a finished / jobless run (e.g. a
        // direct-CLI --node run with no MCP job record, or any completed run)
        // instead of the generic catalog fallback. The active-job arm above only
        // loads the run manifest for a *running* job; without this, run_manifest
        // stays None for a completed run and planned_stage_groups() falls back to
        // the hardcoded ~90-stage catalog with every stage status blank — which is
        // exactly what a headless --snapshot on a finished run would show.
        if self.active_job.is_none() {
            let newest_report = self
                .recent_runs
                .first()
                .map(|r| r.report_dir.trim().to_owned())
                .filter(|s| !s.is_empty());
            if let Some(report_str) = newest_report {
                let report_dir = resolve_report_dir(&self.repo_root, &report_str);
                if self.run_manifest_dir.as_deref() != Some(report_dir.as_path()) {
                    self.run_manifest_dir = Some(report_dir.clone());
                }
                match crate::data::stage_manifest::read_stage_manifest(&report_dir) {
                    Ok(manifest) => self.run_manifest = manifest,
                    Err(err) => {
                        self.run_manifest = None;
                        self.data_errors.push(format!("manifest: {err}"));
                    }
                }
                match crate::data::stage_reader::read_completed_stage_state(&report_dir) {
                    Ok(read) => {
                        self.stage_outcomes = read.result.outcomes;
                        self.stage_data_source = read.source;
                        self.stage_data_modified = read.modified;
                    }
                    Err(err) => self.data_errors.push(format!("held stages: {err}")),
                }
            }
        }
        self.agents_view = crate::ui::agents_panel::AgentsView::load(&self.repo_root);
        if self.active_job.is_none() {
            self.advance_if_current_target_proven();
        }
    }

    pub async fn run_event_loop(
        &mut self,
        terminal: &mut Terminal<ratatui::backend::CrosstermBackend<io::Stdout>>,
    ) -> Result<()> {
        let tick_interval = tokio::time::Duration::from_secs(2);
        let mut last_refresh = tokio::time::Instant::now();

        loop {
            terminal
                .draw(|f| render_ui(f, self))
                .context("terminal draw")?;

            if self.should_quit {
                break;
            }

            // Poll for input with 100ms timeout
            if crossterm::event::poll(std::time::Duration::from_millis(100))
                .context("polling for events")?
                && let Event::Key(key) = crossterm::event::read().context("reading event")?
            {
                self.handle_key(key.code, key.modifiers);
            }

            // Refresh state every 2s
            if last_refresh.elapsed() >= tick_interval {
                self.refresh_state().await;
                last_refresh = tokio::time::Instant::now();
            }
        }

        Ok(())
    }

    fn handle_key(&mut self, code: KeyCode, _modifiers: KeyModifiers) {
        if self.show_help {
            if code == KeyCode::Esc || code == KeyCode::Char('?') {
                self.show_help = false;
            }
            return;
        }

        if self.show_stage_detail {
            match code {
                KeyCode::Esc | KeyCode::Enter => {
                    self.show_stage_detail = false;
                    self.stage_detail_scroll = 0;
                }
                KeyCode::Up => {
                    self.stage_detail_scroll = self.stage_detail_scroll.saturating_sub(1);
                }
                KeyCode::Down => {
                    self.stage_detail_scroll += 1;
                }
                _ => {}
            }
            return;
        }

        if code == KeyCode::Char('?') {
            self.show_help = true;
            self.show_stage_detail = false;
            return;
        }

        let plain_char = match code {
            KeyCode::Char(c) => Some(c.to_ascii_lowercase()),
            _ => None,
        };

        match code {
            KeyCode::Char(_) if plain_char == Some('q') => {
                self.should_quit = true;
            }
            KeyCode::Tab => {
                self.toggle_page();
            }
            // Window-focus hotkeys are numbers only, grouped by owning page
            // (1-3 Overview, 4-6 Run, 7 Matrix) so the order matches how the
            // panels actually sit on screen within each page -- previously
            // Agents was bound to '7', stranded after the unrelated Matrix
            // page's '6' instead of sitting with its own Overview siblings.
            KeyCode::Char('1') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
            }
            KeyCode::Char('2') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::Parity;
            }
            KeyCode::Char('3') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::Agents;
                self.agents_sel_col = Some(AgentsCol::Patch);
                self.agents_sel_row = Some(AgentsRow::Model);
                self.agents_active = false;
            }
            KeyCode::Char('4') => {
                self.page = Page::Run;
                self.focused_panel = Panel::StageGrid;
            }
            KeyCode::Char('5') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Log;
            }
            KeyCode::Char('6') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Jobs;
            }
            KeyCode::Char('7') => {
                self.page = Page::Matrix;
                self.focused_panel = Panel::StageMatrix;
            }
            KeyCode::Char(_) if plain_char == Some('a') => {
                if self.roles_locked_by_active_lab() {
                    self.log_lines =
                        vec!["VM roles locked to active live lab; cannot auto-reassign".into()];
                    return;
                }
                self.auto_select_next_target();
            }
            KeyCode::Char(_) if plain_char == Some('r') => {
                self.last_vm_probe = None;
            }
            KeyCode::Char(_) if plain_char == Some('y') => {
                self.copy_stage_logs();
            }

            // Ctrl+S is often swallowed by terminal flow control, so plain `s`
            // is the primary start key. Stop is deliberately separate.
            KeyCode::Char(_) if plain_char == Some('s') => {
                self.handle_start();
            }
            KeyCode::Char('\x13') => {
                self.handle_start();
            }
            KeyCode::Char(_) if plain_char == Some('x') => {
                self.handle_stop();
            }
            KeyCode::Char(_) if plain_char == Some('d') => {
                self.handle_stop_after_current();
            }

            KeyCode::Up => match self.focused_panel {
                Panel::StageGrid => {
                    let col = self.stage_grid_col;
                    self.move_stage_grid_cursor(col, -1);
                }
                Panel::Log => {
                    if self.log_scroll == 0 {
                        self.log_scroll_anchor = self.log_lines.len();
                    }
                    self.log_scroll += 1;
                }
                Panel::VmStatus if self.selected_vm > 0 => {
                    self.selected_vm -= 1;
                }
                Panel::StageMatrix => {
                    let col = self.stage_matrix_os_col;
                    self.stage_matrix_scroll[col] = self.stage_matrix_scroll[col].saturating_sub(1);
                    self.clamp_stage_matrix_scroll(col);
                }
                Panel::Agents if self.agents_sel_col.is_some() => {
                    self.agents_active = false;
                    self.agents_sel_row = match self.agents_sel_row {
                        Some(AgentsRow::Model) => Some(AgentsRow::Iterations),
                        Some(AgentsRow::Iterations) => Some(AgentsRow::Model),
                        None => Some(AgentsRow::Model),
                    };
                }
                Panel::Agents => {
                    self.agents_sel_col = Some(AgentsCol::Patch);
                    self.agents_sel_row = Some(AgentsRow::Model);
                    self.agents_active = false;
                }
                _ => {}
            },
            KeyCode::Down => match self.focused_panel {
                Panel::StageGrid => {
                    let col = self.stage_grid_col;
                    self.move_stage_grid_cursor(col, 1);
                }
                Panel::Log => {
                    self.log_scroll = self.log_scroll.saturating_sub(1);
                    if self.log_scroll == 0 {
                        self.log_scroll_anchor = 0;
                    }
                }
                Panel::VmStatus if self.selected_vm + 1 < self.vm_statuses.len() => {
                    self.selected_vm += 1;
                }
                Panel::StageMatrix => {
                    let col = self.stage_matrix_os_col;
                    self.stage_matrix_scroll[col] += 1;
                    self.clamp_stage_matrix_scroll(col);
                }
                Panel::Agents if self.agents_sel_col.is_some() => {
                    self.agents_active = false;
                    self.agents_sel_row = match self.agents_sel_row {
                        Some(AgentsRow::Model) => Some(AgentsRow::Iterations),
                        Some(AgentsRow::Iterations) => Some(AgentsRow::Model),
                        None => Some(AgentsRow::Iterations),
                    };
                }
                Panel::Agents => {
                    self.agents_sel_col = Some(AgentsCol::Patch);
                    self.agents_sel_row = Some(AgentsRow::Iterations);
                    self.agents_active = false;
                }
                _ => {}
            },
            KeyCode::End if self.focused_panel == Panel::Log => {
                self.log_scroll = 0;
                self.log_scroll_anchor = 0;
            }
            KeyCode::Char(_) if plain_char == Some('g') && self.focused_panel == Panel::Log => {
                self.log_scroll = 0;
                self.log_scroll_anchor = 0;
            }
            KeyCode::Left if self.focused_panel == Panel::VmStatus => {
                self.cycle_selected_vm_role(-1);
            }
            KeyCode::Right if self.focused_panel == Panel::VmStatus => {
                self.cycle_selected_vm_role(1);
            }
            KeyCode::Left if self.focused_panel == Panel::StageMatrix => {
                self.stage_matrix_os_col = self.stage_matrix_os_col.saturating_sub(1);
                self.clamp_stage_matrix_scroll(self.stage_matrix_os_col);
            }
            KeyCode::Right if self.focused_panel == Panel::StageMatrix => {
                self.stage_matrix_os_col = (self.stage_matrix_os_col + 1).min(2);
                self.clamp_stage_matrix_scroll(self.stage_matrix_os_col);
            }
            KeyCode::Left if self.focused_panel == Panel::StageGrid => {
                self.stage_grid_col = self.stage_grid_col.saturating_sub(1);
                self.clamp_stage_grid_row(self.stage_grid_col);
            }
            KeyCode::Right if self.focused_panel == Panel::StageGrid => {
                self.stage_grid_col = (self.stage_grid_col + 1).min(2);
                self.clamp_stage_grid_row(self.stage_grid_col);
            }
            KeyCode::Left if self.focused_panel == Panel::Agents => {
                if self.agents_active {
                    // Cycle active field left
                    match (self.agents_sel_col, self.agents_sel_row) {
                        (Some(col), Some(AgentsRow::Model)) => {
                            let n = self.available_models.len();
                            if n > 0 {
                                match col {
                                    AgentsCol::Patch => {
                                        self.patch_model_idx = (self.patch_model_idx + n - 1) % n;
                                        self.save_config();
                                    }
                                    AgentsCol::Review => {
                                        self.review_model_idx = (self.review_model_idx + n - 1) % n;
                                        self.save_config();
                                    }
                                }
                            }
                        }
                        (Some(col), Some(AgentsRow::Iterations)) => match col {
                            AgentsCol::Patch => {
                                self.patch_iterations = ((self.patch_iterations + 2) % 4) + 1;
                                self.save_config();
                            }
                            AgentsCol::Review => {
                                self.review_iterations = ((self.review_iterations + 2) % 4) + 1;
                                self.save_config();
                            }
                        },
                        _ => {}
                    }
                } else {
                    // Switch to Patch column, preserve row
                    let row = self.agents_sel_row.unwrap_or(AgentsRow::Model);
                    self.agents_sel_col = Some(AgentsCol::Patch);
                    self.agents_sel_row = Some(row);
                }
            }
            KeyCode::Right if self.focused_panel == Panel::Agents => {
                if self.agents_active {
                    // Cycle active field right
                    match (self.agents_sel_col, self.agents_sel_row) {
                        (Some(col), Some(AgentsRow::Model)) => {
                            let n = self.available_models.len();
                            if n > 0 {
                                match col {
                                    AgentsCol::Patch => {
                                        self.patch_model_idx = (self.patch_model_idx + 1) % n;
                                        self.save_config();
                                    }
                                    AgentsCol::Review => {
                                        self.review_model_idx = (self.review_model_idx + 1) % n;
                                        self.save_config();
                                    }
                                }
                            }
                        }
                        (Some(col), Some(AgentsRow::Iterations)) => match col {
                            AgentsCol::Patch => {
                                self.patch_iterations = (self.patch_iterations % 4) + 1;
                                self.save_config();
                            }
                            AgentsCol::Review => {
                                self.review_iterations = (self.review_iterations % 4) + 1;
                                self.save_config();
                            }
                        },
                        _ => {}
                    }
                } else {
                    // Switch to Review column, preserve row
                    let row = self.agents_sel_row.unwrap_or(AgentsRow::Model);
                    self.agents_sel_col = Some(AgentsCol::Review);
                    self.agents_sel_row = Some(row);
                }
            }
            KeyCode::Enter
                if self.focused_panel == Panel::Agents && self.agents_sel_row.is_some() =>
            {
                self.agents_active = !self.agents_active;
            }
            KeyCode::Esc if self.focused_panel == Panel::Agents => {
                if self.agents_active {
                    self.agents_active = false;
                } else {
                    self.agents_sel_col = None;
                    self.agents_sel_row = None;
                    self.agents_active = false;
                }
            }
            KeyCode::Char(' ') if self.page == Page::Run => {
                self.focused_panel = Panel::StageGrid;
                self.toggle_selected_stage();
            }
            KeyCode::Enter if self.focused_panel == Panel::StageGrid => {
                if self.selected_stage_has_outcome() {
                    self.show_stage_detail = true;
                    self.stage_detail_scroll = 0;
                } else {
                    self.toggle_selected_stage();
                }
            }
            _ => {}
        }
    }

    fn toggle_page(&mut self) {
        match self.page {
            Page::Overview => {
                self.page = Page::Run;
                self.focused_panel = Panel::StageGrid;
            }
            Page::Run => {
                self.page = Page::Matrix;
                self.focused_panel = Panel::StageMatrix;
            }
            Page::Matrix => {
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
            }
        }
    }

    fn toggle_selected_stage(&mut self) {
        if self.active_job.is_some() {
            return;
        }
        let Some(stage) = self.selected_stage_name() else {
            return;
        };
        // A stage that isn't possible for the current config (wrong
        // platform, wrong role target, etc.) can't be toggled on/off --
        // that's a config-driven fact, not a user choice. Only stages that
        // ARE possible but the user wants to skip anyway go through
        // disabled_stages.
        if !self.stage_selected_for_current_target(&stage) {
            return;
        }
        if let Some(idx) = self
            .config
            .disabled_stages
            .iter()
            .position(|disabled| disabled == &stage)
        {
            self.config.disabled_stages.remove(idx);
        } else {
            self.config.disabled_stages.push(stage);
            self.config.disabled_stages.sort();
            self.config.disabled_stages.dedup();
        }
        self.save_config_best_effort();
    }

    fn handle_start(&mut self) {
        if self.orchestrator_pgid.is_some() || self.active_job.is_some() {
            let job = self
                .active_job
                .as_ref()
                .map(|job| job.job_id.as_str())
                .unwrap_or("unknown");
            self.log_lines = vec![format!("loop already running: {job}; press x to stop")];
            return;
        }

        let repo_root = self.repo_root.clone();
        let mut config = self.config.clone();
        let linux_aliases = self
            .vm_statuses
            .iter()
            .filter(|vm| vm.platform == "linux")
            .map(|vm| vm.alias.clone())
            .collect::<Vec<_>>();
        if let Err(e) = crate::config::normalize_linux_lab_vms(&mut config, &linux_aliases) {
            self.log_lines = vec![format!("failed to normalize lab VM roles: {e}")];
            return;
        }
        config.apply_fast_stage_defaults();
        self.config = config.clone();
        self.save_config_best_effort();
        let patch_model = self
            .available_models
            .get(self.patch_model_idx)
            .cloned()
            .unwrap_or_default();
        let patch_variant = self
            .available_variants
            .get(self.patch_variant_idx)
            .cloned()
            .unwrap_or_default();
        let review_model = self
            .available_models
            .get(self.review_model_idx)
            .cloned()
            .unwrap_or_default();
        match crate::control::launcher::spawn_orchestrator(
            &repo_root,
            &config,
            &patch_model,
            &patch_variant,
            &review_model,
            self.patch_iterations,
            self.review_iterations,
        ) {
            Ok(spawned) => {
                let child_id = spawned.child.id();
                let job_id = spawned.job_id.clone();
                let report_dir = spawned.report_dir.clone();
                let job_state_path = spawned.job_state_path.clone();
                let area = config.area.clone();
                if let Some(id) = child_id {
                    self.orchestrator_pgid = Some(id);
                    tracing::info!(pgid = id, "orchestrator started");
                }
                self.active_job = Some(JobState {
                    job_id: job_id.clone(),
                    state: "running".to_owned(),
                    pid: child_id,
                    started_unix: Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs(),
                    ),
                    area: area.clone(),
                    report_dir: report_dir.display().to_string(),
                    request_args: None,
                });
                self.active_stage = None;
                self.log_scroll = 0;
                self.log_scroll_anchor = 0;
                let unsupported_disabled = config
                    .disabled_stages
                    .iter()
                    .filter(|stage| stage.as_str() != "linux_live_suite")
                    .cloned()
                    .collect::<Vec<_>>();
                self.log_lines = vec![
                    format!("launched {job_id}"),
                    format!("area: {area}"),
                    format!("report: {}", report_dir.display()),
                    format!(
                        "stage toggles enforced by CLI today: linux_live_suite only; unsupported disabled count: {}",
                        unsupported_disabled.len()
                    ),
                    "waiting for orchestrator logs...".to_owned(),
                ];
                let mut child = spawned.child;
                tokio::spawn(async move {
                    let state = match child.wait().await {
                        Ok(status) if status.success() => "done",
                        Ok(_) | Err(_) => "crashed",
                    };
                    let _ = crate::control::launcher::write_job_state(
                        &job_state_path,
                        &job_id,
                        state,
                        child_id,
                        &area,
                        &report_dir,
                    );
                });
            }
            Err(e) => {
                tracing::error!(%e, "failed to start orchestrator");
                self.log_lines = vec![format!("failed to start orchestrator: {e}")];
            }
        }
    }

    fn handle_stop(&mut self) {
        let mut targets: Vec<(String, u32)> = Vec::new();
        if let Some(pgid) = self.orchestrator_pgid.take() {
            targets.push(("current monitor loop".to_owned(), pgid));
        }
        if let Ok(mut jobs) = crate::data::job_watcher::find_running_jobs(&self.repo_root) {
            jobs.sort_by_key(|job| {
                (
                    !job.job_id.starts_with("monitor-"),
                    std::cmp::Reverse(job.started_unix.unwrap_or(0)),
                )
            });
            for job in jobs {
                if let Some(pid) = job.pid {
                    targets.push((job.job_id, pid));
                }
            }
        }

        let mut seen = HashSet::new();
        targets.retain(|(_, pid)| seen.insert(*pid));
        if targets.is_empty() {
            self.log_lines = if self.active_job.is_some() {
                vec![
                    "active loop detected but no pid/orchestrator_pid is available; cannot stop"
                        .to_owned(),
                ]
            } else {
                vec!["no active loop to stop".to_owned()]
            };
            return;
        }

        let mut lines = Vec::new();
        for (label, pid) in targets {
            if let Err(e) = crate::control::stopper::stop_orchestrator(pid) {
                tracing::error!(%e, pid, label, "failed to stop loop process group");
                lines.push(format!("failed to stop {label} pid {pid}: {e}"));
            } else {
                lines.push(format!("sent stop to {label} pid {pid}"));
            }
        }
        self.log_lines = lines;
    }

    fn handle_stop_after_current(&mut self) {
        if self.active_job.is_none() && self.orchestrator_pgid.is_none() {
            self.log_lines = vec!["no active loop to drain".to_owned()];
            return;
        }
        match crate::control::stopper::request_stop_after_current(&self.repo_root) {
            Ok(()) => {
                self.stop_after_current = true;
                self.log_lines = vec![
                    "stop-after-current requested".to_owned(),
                    "current live lab will finish; loop exits before next patch/relaunch"
                        .to_owned(),
                ];
            }
            Err(e) => {
                self.log_lines = vec![format!("failed to request stop-after-current: {e}")];
            }
        }
    }

    /// The role this alias plays in the current/newest run, taken from the
    /// run's OWN emitted manifest topology (Rust `--node` path). This is the
    /// emit-don't-infer source: strictly more authoritative than any inference
    /// below (config slots, previous-run CSV roles). `None` for bash/wrapper
    /// runs (which emit no `node_assignments`) and for aliases not in the run.
    fn role_from_run_manifest(&self, alias: &str) -> Option<String> {
        let manifest = self.run_manifest.as_ref()?;
        manifest
            .node_assignments
            .iter()
            .find(|a| a.alias == alias)
            .map(|a| a.role.clone())
            .filter(|role| !role.is_empty())
    }

    pub fn role_for_vm(&self, alias: &str) -> String {
        // Highest priority: the current run's OWN emitted node→role topology.
        // Beats every inference below because it is what actually dispatched.
        if let Some(role) = self.role_from_run_manifest(alias) {
            return role;
        }
        let config = self.config_for_role_display();
        if self.roles_locked_by_active_lab() {
            // A lab is running: its own config (request_args / report-dir
            // inference) is the source of truth for who's playing what.
            return role_for_vm_from_config(alias, &config);
        }
        if let Some(role) = self.vm_role_overrides.get(alias) {
            return role.clone();
        }
        let label = role_for_vm_from_config(alias, &config);
        // When the config's own slots can't name a real role for this node
        // (placeholder like "—" / "linux-target"), fall back to the role it
        // actually served in the most recent run -- so a node the last run
        // elected (e.g. a relay outside the monitor's default slots) still
        // shows its real role and lights up the parity glyph, updating as new
        // runs land, instead of sitting blank run after run.
        if Role::from_label(&label).is_none()
            && let Some(actual) = self.latest_run_roles.get(alias)
        {
            return actual.clone();
        }
        label
    }

    /// Role proven by actual current/previous run evidence. Planned config
    /// and manual role edits never appear as VM STATUS facts.
    pub fn actual_role_for_vm(&self, alias: &str) -> String {
        self.actual_run_assignment(alias)
            .map(|(role, _)| role)
            .unwrap_or_else(|| "—".to_owned())
    }

    pub fn run_use_for_vm(&self, alias: &str) -> &'static str {
        self.actual_run_assignment(alias)
            .map(|(_, run_use)| run_use)
            .unwrap_or("—")
    }

    fn actual_run_assignment(&self, alias: &str) -> Option<(String, &'static str)> {
        let current = self.lab_is_actively_running() || self.orchestrator_pgid.is_some();
        if current {
            // Rust-native runs emit exact assignments. Once present, absence
            // means this VM is not in the run; never fall back to config.
            if self
                .run_manifest
                .as_ref()
                .is_some_and(|manifest| !manifest.node_assignments.is_empty())
            {
                return self
                    .role_from_run_manifest(alias)
                    .map(|role| (role, "CURRENT"));
            }
            // Legacy runs have no assignment manifest. Their structured
            // launch selectors are best available actual membership source.
            return active_role_from_config(alias, &self.config_for_role_display())
                .map(|role| (role, "CURRENT"));
        }
        self.latest_run_roles
            .get(alias)
            .filter(|role| !role.trim().is_empty())
            .cloned()
            .map(|role| (role, "PREVIOUS"))
    }

    pub fn roles_locked_by_active_lab(&self) -> bool {
        self.active_job.is_some() || self.orchestrator_pgid.is_some()
    }

    /// True only while a lab is genuinely running right now -- the same
    /// condition the header uses to show "RUNNING" (see header.rs's
    /// job.state match). Stage Grid gates its spinner on this, not merely
    /// on `active_stage` being populated: `active_stage` is refreshed from
    /// log/pipeline-position inference and can otherwise go stale (e.g. a
    /// run stopped so early that `active_job` never observed a job-state
    /// transition to react to), leaving a spinner animating on a stage
    /// forever after the header has already gone IDLE/DONE/CRASHED.
    pub fn lab_is_actively_running(&self) -> bool {
        self.active_job
            .as_ref()
            .is_some_and(|job| job.state == "running")
    }

    fn config_for_role_display(&self) -> MonitorConfig {
        let mut config = self.config.clone();
        if let Some(job) = &self.active_job
            && let Some(args) = &job.request_args
        {
            config.apply_request_args(args);
        }
        config
    }

    /// Number of stages in the given stage-matrix OS column (0=Linux,
    /// 1=macOS, 2=Windows).
    fn stage_matrix_column_len(&self, col: usize) -> usize {
        match col {
            0 => self.full_stage_matrix.linux.len(),
            1 => self.full_stage_matrix.macos.len(),
            _ => self.full_stage_matrix.windows.len(),
        }
    }

    /// Keep `stage_matrix_scroll[col]` within `[0, max_scroll]` using the
    /// real last-rendered viewport height, so it can never run away past
    /// the point where the last stage is already the bottom visible row --
    /// otherwise scrolling down past the end silently keeps incrementing,
    /// and un-scrolling has to walk all the way back before the view
    /// visibly moves.
    fn clamp_stage_matrix_scroll(&mut self, col: usize) {
        let len = self.stage_matrix_column_len(col);
        let visible = self.stage_matrix_visible_rows.get().max(1);
        let max_scroll = len.saturating_sub(visible);
        self.stage_matrix_scroll[col] = self.stage_matrix_scroll[col].min(max_scroll);
    }

    /// Keep `stage_grid_row[col]` within the given group's actual stage
    /// count -- needed on a Left/Right column switch, since each group can
    /// have a different length and a stale row index from a longer group
    /// would otherwise point past the end of a shorter one. The cursor is
    /// free to rest on a disabled/not-possible stage -- only *acting* on
    /// one (Space to toggle) is blocked, not navigating to it -- so this
    /// only clamps bounds, it doesn't hunt for an enabled stage.
    fn clamp_stage_grid_row(&mut self, col: usize) {
        let groups = self.planned_stage_groups();
        let Some(group) = groups.get(col) else {
            return;
        };
        let max = group.stages.len().saturating_sub(1);
        self.stage_grid_row[col] = self.stage_grid_row[col].min(max);
    }

    /// Move `stage_grid_row[col]` by one step (+1 = Down, -1 = Up), clamped
    /// to the column's bounds. Deliberately does NOT skip disabled stages
    /// -- the user should be able to navigate to and see every stage,
    /// possible or not; only toggling one (see `toggle_selected_stage`) is
    /// restricted to stages that are actually possible for this config.
    fn move_stage_grid_cursor(&mut self, col: usize, direction: isize) {
        let groups = self.planned_stage_groups();
        let Some(group) = groups.get(col) else {
            return;
        };
        let len = group.stages.len();
        if len == 0 {
            return;
        }
        let idx = self.stage_grid_row[col].min(len - 1) as isize + direction;
        self.stage_grid_row[col] = idx.clamp(0, len as isize - 1) as usize;
    }

    fn cycle_selected_vm_role(&mut self, direction: isize) {
        if self.roles_locked_by_active_lab() {
            self.log_lines =
                vec!["VM roles locked to active live lab; wait for lab to finish".into()];
            return;
        }
        let Some(vm) = self.vm_statuses.get(self.selected_vm).cloned() else {
            return;
        };
        let roles = ["client", "admin", "exit", "relay", "anchor", "blind_exit"];
        let current = self.role_for_vm(&vm.alias);
        let current_idx = roles.iter().position(|r| *r == current).unwrap_or(0) as isize;
        let next_idx = (current_idx + direction).rem_euclid(roles.len() as isize) as usize;
        self.assign_vm_role(&vm, roles[next_idx]);
        self.save_config_best_effort();
    }

    fn assign_vm_role(&mut self, vm: &crate::data::vm_prober::VmStatus, role: &str) {
        let platform = vm.platform.as_str();
        self.configure_target(role, platform, Some(vm.alias.clone()));
    }

    fn configure_target(&mut self, role: &str, platform: &str, alias: Option<String>) {
        if let Some(alias) = alias.as_deref() {
            self.vm_role_overrides
                .insert(alias.to_owned(), role.to_owned());
        }
        self.config.exit_platform.clear();
        self.config.relay_platform.clear();
        self.config.anchor_platform.clear();
        self.config.admin_platform.clear();
        self.config.blind_exit_platform.clear();
        self.config.client_platform.clear();
        self.config.macos_promote_exit = false;

        match platform {
            "macos" => {
                if let Some(alias) = alias.clone() {
                    self.config.macos_vm = alias;
                }
                if role == "exit" {
                    self.config.macos_promote_exit = true;
                } else if role == "client" {
                    self.config.client_platform = "macos".to_owned();
                } else {
                    set_role_platform(&mut self.config, role, platform);
                }
                self.config.area = format!("macOS {role}");
                self.config.skip_linux_live_suite = true;
            }
            "windows" => {
                if let Some(alias) = alias.clone() {
                    self.config.windows_vm = alias;
                }
                if role == "client" {
                    self.config.client_platform = "windows".to_owned();
                } else {
                    set_role_platform(&mut self.config, role, platform);
                }
                self.config.area = format!("Windows {role}");
                self.config.skip_linux_live_suite = true;
            }
            _ => {
                if role == "client" {
                    if let Some(alias) = alias.clone() {
                        self.config.client_vm = alias;
                    }
                    self.config.client_platform = "linux".to_owned();
                    self.config.area = "Linux client".into();
                } else {
                    if let Some(alias) = alias.clone() {
                        self.config.exit_vm = alias;
                    }
                    set_role_platform(&mut self.config, role, "linux");
                    self.config.area = format!("Linux {role}");
                }
            }
        }
        if let Some(alias) = alias {
            self.config.rebuild_nodes = alias;
        }
        self.sync_stage_selection_for_target(platform);
    }

    fn sync_stage_selection_for_target(&mut self, platform: &str) {
        self.config.disabled_stages.clear();
        if matches!(platform, "macos" | "windows") {
            self.config.skip_linux_live_suite = true;
            self.config
                .disabled_stages
                .push("linux_live_suite".to_owned());
        } else {
            self.config.skip_linux_live_suite = false;
        }
        self.config.apply_fast_stage_defaults();
    }

    fn auto_select_next_target(&mut self) {
        if self.roles_locked_by_active_lab() {
            self.log_lines =
                vec!["VM roles locked to active live lab; cannot auto-reassign".into()];
            return;
        }
        if let Ok(matrix) = crate::data::run_matrix::load_parity_matrix(&self.repo_root) {
            self.parity_matrix = matrix;
        }
        let roles = [
            Role::Exit,
            Role::Relay,
            Role::Anchor,
            Role::Admin,
            Role::BlindExit,
            Role::Client,
        ];
        let passes = [
            (ParityState::Failed, Os::Macos),
            (ParityState::Failed, Os::Windows),
            (ParityState::Unproven, Os::Macos),
            (ParityState::Unproven, Os::Windows),
            (ParityState::Failed, Os::Linux),
            (ParityState::Unproven, Os::Linux),
        ];

        for (wanted_state, os) in passes {
            for role in roles {
                if self.parity_matrix.get(&(role, os)) == Some(&wanted_state) {
                    let alias = self.default_alias_for_os(os);
                    self.configure_target(role.label(), os.label(), alias);
                    self.save_config_best_effort();
                    // Deliberately does NOT touch focused_panel -- this runs
                    // both from the 'a' keypress and from the automatic
                    // advance-when-proven tick in refresh_state, so forcing
                    // focus to VmStatus would yank the cursor away from
                    // whatever panel (e.g. StageGrid) the user is actively
                    // working in, on every 2s refresh tick.
                    return;
                }
            }
        }
    }

    fn advance_if_current_target_proven(&mut self) {
        let Some((role, os)) = self.current_target_cell() else {
            return;
        };
        if self.parity_matrix.get(&(role, os)) == Some(&ParityState::Proven) {
            self.auto_select_next_target();
        }
    }

    /// Reads only structured selector fields -- no free-text `area`
    /// parsing. Previously fell back to substring-matching `area` (e.g.
    /// `contains("blind")`/`contains("relay")`/`contains("exit")`) to
    /// derive BOTH the role and the OS whenever none of the 5
    /// role-platform selectors were set; that fallback existed solely to
    /// cover the "client" role, which had no selector field of its own
    /// (see `client_platform`). With one now, every role has a structured
    /// signal and a free-text label like "windows-adjacent linux relay
    /// check" can no longer silently change what gets targeted.
    fn current_target_cell(&self) -> Option<(Role, Os)> {
        if self.config.macos_promote_exit || self.config.exit_platform == "macos" {
            return Some((Role::Exit, Os::Macos));
        }
        for (role, platform) in [
            (Role::Exit, self.config.exit_platform.as_str()),
            (Role::Relay, self.config.relay_platform.as_str()),
            (Role::Anchor, self.config.anchor_platform.as_str()),
            (Role::Admin, self.config.admin_platform.as_str()),
            (Role::BlindExit, self.config.blind_exit_platform.as_str()),
            (Role::Client, self.config.client_platform.as_str()),
        ] {
            let os = match platform {
                "linux" => Os::Linux,
                "macos" => Os::Macos,
                "windows" => Os::Windows,
                _ => continue,
            };
            return Some((role, os));
        }
        None
    }

    fn default_alias_for_os(&self, os: Os) -> Option<String> {
        let wanted = match os {
            Os::Linux => "linux",
            Os::Macos => "macos",
            Os::Windows => "windows",
        };
        self.vm_statuses
            .iter()
            .find(|vm| vm.platform == wanted)
            .map(|vm| vm.alias.clone())
            .or_else(|| match os {
                Os::Linux => Some(self.config.exit_vm.clone()),
                Os::Macos => Some(self.config.macos_vm.clone()),
                Os::Windows => Some(self.config.windows_vm.clone()),
            })
            .filter(|alias| !alias.is_empty())
    }

    fn save_config(&self) {
        let mut config = self.config.clone();
        config.patch_model_idx = self.patch_model_idx;
        config.patch_variant_idx = self.patch_variant_idx;
        config.review_model_idx = self.review_model_idx;
        config.patch_iterations = self.patch_iterations;
        config.review_iterations = self.review_iterations;
        if let Err(e) = config.save(&self.repo_root) {
            tracing::error!(%e, "failed to save monitor config");
        }
    }

    fn save_config_best_effort(&self) {
        if let Err(e) = self.config.save(&self.repo_root) {
            tracing::error!(%e, "failed to save monitor config");
        }
    }

    fn copy_stage_logs(&mut self) {
        let Some(job) = self.active_job.as_ref() else {
            self.log_lines = vec!["no active or recent run to copy logs from".into()];
            return;
        };
        let report_dir = self.repo_root.join(&job.report_dir);

        let stage = self.active_stage.clone().or_else(|| {
            self.stage_outcomes
                .iter()
                .find(|o| o.status == "fail")
                .or_else(|| self.stage_outcomes.first())
                .map(|o| o.stage.clone())
        });

        let Some(stage) = stage else {
            self.log_lines = vec!["no stage logs available to copy".into()];
            return;
        };

        let log_path = report_dir.join("logs").join(format!("{stage}.log"));
        let content = match std::fs::read_to_string(&log_path) {
            Ok(c) => c,
            Err(e) => {
                self.log_lines = vec![format!("failed to read log for {stage}: {e}")];
                return;
            }
        };

        let line_count = content.lines().count();
        match copy_to_clipboard(&content) {
            Ok(()) => {
                self.log_lines = vec![format!(
                    "copied {stage} log to clipboard ({line_count} lines)"
                )];
            }
            Err(e) => {
                self.log_lines = vec![format!("failed to copy to clipboard: {e}")];
            }
        }
    }
}

/// Pipe text to the system clipboard via the platform's native CLI tool.
/// macOS: pbcopy, Linux: xclip, Windows: clip
fn copy_to_clipboard(text: &str) -> Result<()> {
    let cmd = clipboard_command();
    let mut child = std::process::Command::new(cmd[0])
        .args(&cmd[1..])
        .stdin(std::process::Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("{} exited with {}", cmd[0], status);
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn clipboard_command() -> Vec<&'static str> {
    vec!["pbcopy"]
}

#[cfg(target_os = "linux")]
fn clipboard_command() -> Vec<&'static str> {
    vec!["xclip", "-selection", "clipboard"]
}

#[cfg(target_os = "windows")]
fn clipboard_command() -> Vec<&'static str> {
    vec!["clip"]
}

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
fn clipboard_command() -> Vec<&'static str> {
    // Will fail at spawn-time on unsupported platforms with a clear error.
    vec!["__no_clipboard_tool_on_this_platform__"]
}

fn role_for_vm_from_config(alias: &str, config: &MonitorConfig) -> String {
    if alias == config.macos_vm {
        if config.macos_promote_exit || config.exit_platform == "macos" {
            return "exit".into();
        }
        if config.relay_platform == "macos" {
            return "relay".into();
        }
        if config.anchor_platform == "macos" {
            return "anchor".into();
        }
        if config.admin_platform == "macos" {
            return "admin".into();
        }
        if config.blind_exit_platform == "macos" {
            return "blind_exit".into();
        }
        return "macos-target".into();
    }
    if alias == config.windows_vm {
        if config.exit_platform == "windows" {
            return "exit".into();
        }
        if config.relay_platform == "windows" {
            return "relay".into();
        }
        if config.anchor_platform == "windows" {
            return "anchor".into();
        }
        if config.admin_platform == "windows" {
            return "admin".into();
        }
        if config.blind_exit_platform == "windows" {
            return "blind_exit".into();
        }
        return "windows-target".into();
    }
    if alias == config.exit_vm {
        if config.relay_platform == "linux" {
            return "relay".into();
        }
        if config.anchor_platform == "linux" {
            return "anchor".into();
        }
        if config.admin_platform == "linux" {
            return "admin".into();
        }
        if config.blind_exit_platform == "linux" {
            return "blind_exit".into();
        }
        if config.exit_platform == "linux" || config.exit_platform.is_empty() {
            return "exit".into();
        }
        return "linux-target".into();
    }
    if alias == config.client_vm {
        return "client".into();
    }
    "—".into()
}

/// Mirrors launcher's structured `--node alias:role` synthesis for legacy
/// runs that cannot emit `node_assignments` themselves.
fn active_role_from_config(alias: &str, config: &MonitorConfig) -> Option<String> {
    let role_for_platform = |platform: &str| {
        if (platform == "macos" && config.macos_promote_exit) || config.exit_platform == platform {
            "exit"
        } else if config.relay_platform == platform {
            "relay"
        } else if config.anchor_platform == platform || config.admin_platform == platform {
            "anchor"
        } else if config.blind_exit_platform == platform {
            "exit"
        } else {
            "client"
        }
    };
    let non_linux_exit =
        config.macos_promote_exit || matches!(config.exit_platform.as_str(), "macos" | "windows");
    if alias == config.exit_vm && !non_linux_exit {
        return Some("exit".to_owned());
    }
    if alias == config.client_vm {
        return Some("client".to_owned());
    }
    if alias == config.entry_vm {
        return Some("entry".to_owned());
    }
    if alias == config.macos_vm && config.wants_macos() {
        return Some(role_for_platform("macos").to_owned());
    }
    if alias == config.windows_vm && config.wants_windows() {
        return Some(role_for_platform("windows").to_owned());
    }
    None
}

fn set_role_platform(config: &mut MonitorConfig, role: &str, platform: &str) {
    match role {
        "exit" => config.exit_platform = platform.into(),
        "relay" => config.relay_platform = platform.into(),
        "anchor" => config.anchor_platform = platform.into(),
        "admin" => config.admin_platform = platform.into(),
        "blind_exit" => config.blind_exit_platform = platform.into(),
        _ => {}
    }
}

fn macos_live_lab_catalog() -> &'static [&'static str] {
    &[
        "activate_macos_exit_role",
        "capture_macos_exit_evidence_artifacts",
        "validate_macos_exit_nat_lifecycle",
        "validate_macos_ipv6_leak",
        "validate_macos_exit_dns_failclosed",
        "validate_macos_exit_killswitch_precedence",
        "validate_macos_relay_service_lifecycle",
        "deploy_macos_anchor_profile",
        "validate_macos_anchor_bundle_pull",
        "validate_macos_admin_issue",
        "validate_macos_blind_exit",
        "validate_macos_key_custody",
        // macOS one-off security/protocol audit stages (same shape as the
        // linux catalog below). These really run and really fail runs —
        // several appear as first_failed_stage values in the run matrix;
        // before 2026-07-03 they had no cell anywhere in this UI.
        "validate_macos_membership_revoke_applies",
        "validate_macos_membership_signature_forgery",
        "validate_macos_gossip_revoked_readmit",
        "validate_macos_enrollment_replay",
        "validate_macos_hello_limiter_flood",
        "validate_macos_runtime_acls",
        "validate_macos_service_hardening",
        "validate_macos_mesh_status",
        "validate_macos_authenticode",
        "validate_macos_privileged_helper_allowlist",
        "validate_macos_policy_default_deny",
        "validate_macos_revoked_peer_denied_e2e",
        "validate_macos_blind_exit_reversal_denied",
    ]
}

fn windows_live_lab_catalog() -> &'static [&'static str] {
    &[
        "validate_windows_client_install",
        "validate_windows_runtime_acls",
        "validate_windows_named_pipe_acls",
        "validate_windows_service_hardening",
        "validate_windows_key_custody",
        "validate_windows_dns_failclosed",
        "validate_windows_exit_nat_lifecycle",
        "validate_windows_exit_dns_failclosed",
        "validate_windows_exit_killswitch_precedence",
        "validate_windows_relay_service_lifecycle",
        "validate_windows_anchor_bundle_pull",
        "validate_windows_admin_issue",
        // Windows audit family — see the macOS catalog note above.
        "promote_windows_exit_active",
        "validate_windows_membership_revoke_applies",
        "validate_windows_membership_signature_forgery",
        "validate_windows_gossip_revoked_readmit",
        "validate_windows_enrollment_replay",
        "validate_windows_hello_limiter_flood",
        "validate_windows_mesh_status",
        "validate_windows_privileged_helper_allowlist",
        "validate_windows_policy_default_deny",
        "validate_windows_revoked_peer_denied_e2e",
        "validate_windows_blind_exit_reversal_denied",
    ]
}

/// Linux one-off security/protocol audit stages -- distinct from
/// `linux_live_suite` (the coarse "did the whole Linux live-lab pipeline
/// pass" flag). Each maps to its own CSV column via
/// rustynet-cli's `set_special_stage_values` (see live_lab_run_matrix.rs)
/// and is gated on the same `!skip_linux_live_suite` condition, since they
/// only ever run as part of that suite.
fn linux_live_lab_catalog() -> &'static [&'static str] {
    &[
        "validate_linux_membership_revoke_applies",
        "validate_linux_revoked_peer_denied_e2e",
        "validate_linux_membership_signature_forgery",
        "validate_linux_privileged_helper_allowlist",
        "validate_linux_policy_default_deny",
        "validate_linux_runtime_acls",
        "validate_linux_service_hardening",
        "validate_linux_authenticode",
        "validate_linux_key_custody",
        "validate_linux_membership_genesis",
        "validate_linux_mesh_status",
        "validate_linux_blind_exit_reversal_denied",
        "validate_linux_gossip_revoked_readmit",
        "validate_linux_enrollment_replay",
        "validate_linux_hello_limiter_flood",
    ]
}

fn format_duration(secs: u64) -> String {
    let mins = secs / 60;
    if mins >= 60 {
        format!("{}h{}m", mins / 60, mins % 60)
    } else if mins > 0 {
        format!("{mins}m")
    } else {
        format!("{secs}s")
    }
}

fn human_age(secs: u64) -> String {
    match secs {
        0..=4 => "now".to_owned(),
        5..=59 => format!("{secs}s"),
        60..=3_599 => format!("{}m", secs / 60),
        3_600..=86_399 => format!("{}h", secs / 3_600),
        _ => format!("{}d", secs / 86_400),
    }
}

fn group_name_for_stage(stage: &str) -> &'static str {
    if stage.is_empty()
        || matches!(
            stage,
            "discover_local_utm"
                | "restart_unready_vms"
                | "rediscover_local_utm"
                | "preflight"
                | "prepare_source_archive"
                | "verify_ssh_reachability"
                | "prime_remote_access"
                | "cleanup_hosts"
                | "macos_preflight_check"
        )
    {
        "PRE"
    } else if stage.ends_with("_mesh_join") {
        // validate_{windows,macos}_mesh_join close the per-OS bootstrap
        // stream (matches planned_stage_groups).
        "BOOTSTRAP"
    } else if stage.starts_with("validate_") && stage != "validate_baseline_runtime" {
        // Audit/validator stages are LIVE LAB even when their names
        // contain bootstrap-flavored words (validate_*_membership_* would
        // otherwise be swallowed by the contains("membership") arm below).
        "LIVE LAB"
    } else if stage.contains("bootstrap")
        || stage.contains("membership")
        || stage.contains("distribute")
        || stage.contains("assignment")
        || stage.contains("traversal")
        || stage.contains("dns_zone")
        || stage.contains("baseline")
        || stage.contains("pubkey")
        || stage.contains("bundles")
        || stage == "enforce_baseline_runtime"
    {
        "BOOTSTRAP"
    } else {
        "LIVE LAB"
    }
}

fn pipeline_phase_for_stage(stage: &str) -> usize {
    if stage.contains("report") || stage.contains("digest") || stage.contains("triage") {
        return 4;
    }
    if stage == "prepare_source_archive"
        || stage == "bootstrap_hosts"
        || stage == "bootstrap_macos_host"
        || stage == "bootstrap_windows_host"
        || stage.contains("build")
    {
        return 1;
    }
    match group_name_for_stage(stage) {
        "PRE" => 0,
        "BOOTSTRAP" => 2,
        _ => 3,
    }
}

fn default_stage_secs(stage: &str) -> u64 {
    match stage {
        "preflight" | "macos_preflight_check" | "verify_ssh_reachability" => 60,
        "prepare_source_archive" => 30,
        "prime_remote_access" | "cleanup_hosts" => 60,
        "bootstrap_hosts" => 900,
        "bootstrap_macos_host" | "bootstrap_windows_host" => 600,
        "linux_live_suite" => 3_600,
        _ if stage.starts_with("validate_macos_")
            || stage.starts_with("validate_windows_")
            || stage.starts_with("activate_macos_")
            || stage.starts_with("capture_macos_")
            || stage.starts_with("deploy_macos_") =>
        {
            180
        }
        _ if stage.contains("collect") || stage.contains("distribute") => 60,
        _ if stage.contains("membership") || stage.contains("assignment") => 120,
        _ if stage.contains("baseline") => 300,
        _ if stage.contains("validate")
            || stage.contains("capture")
            || stage.contains("activate") =>
        {
            300
        }
        _ => 300,
    }
}

fn timer_short_name(group_name: &str) -> &'static str {
    match group_name {
        "PRE" => "PRE",
        "BOOTSTRAP" => "BOOT",
        "LIVE LAB" => "LAB",
        _ => "ETA",
    }
}

fn default_vm_role_overrides(config: &MonitorConfig) -> HashMap<String, String> {
    let mut roles = HashMap::new();
    if !config.exit_vm.is_empty() {
        roles.insert(config.exit_vm.clone(), "exit".to_owned());
    }
    if !config.client_vm.is_empty() {
        roles
            .entry(config.client_vm.clone())
            .or_insert("client".to_owned());
    }
    roles
}

#[derive(Debug, Clone)]
struct InventoryVm {
    alias: String,
    utm_name: String,
    ip: String,
    platform: String,
}

async fn probe_vms_sync(
    repo_root: &std::path::Path,
    cached_readiness: &HashMap<String, crate::data::vm_prober::LabReadiness>,
) -> Result<Vec<crate::data::vm_prober::VmStatus>> {
    let inventory_path = repo_root
        .join("documents")
        .join("operations")
        .join("active")
        .join("vm_lab_inventory.json");

    let inventory = load_inventory_vms(&inventory_path)?;
    let host_vms = crate::data::vm_prober::list_utm_vms().await?;
    let mut matched_inventory = HashSet::new();
    let mut tasks = Vec::new();
    for host_vm in host_vms {
        let matched = inventory
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.utm_name == host_vm.name || entry.alias == host_vm.name);
        let (alias, ip, platform, registered) = if let Some((idx, entry)) = matched {
            matched_inventory.insert(idx);
            (
                entry.alias.clone(),
                entry.ip.clone(),
                entry.platform.clone(),
                true,
            )
        } else {
            (
                host_vm.name.clone(),
                "-".to_owned(),
                "unknown".to_owned(),
                false,
            )
        };
        let readiness = cached_readiness.get(&alias).cloned();
        tasks.push(tokio::spawn(async move {
            crate::data::vm_prober::probe_vm(
                &alias,
                &ip,
                &platform,
                &host_vm.power_state,
                registered,
                readiness,
            )
            .await
        }));
    }

    // Inventory may retain a VM bundle that UTM no longer lists. Keep it
    // visible as `missing` rather than silently dropping configured lab data.
    for (idx, entry) in inventory.into_iter().enumerate() {
        if matched_inventory.contains(&idx) {
            continue;
        }
        let readiness = cached_readiness.get(&entry.alias).cloned();
        tasks.push(tokio::spawn(async move {
            crate::data::vm_prober::probe_vm(
                &entry.alias,
                &entry.ip,
                &entry.platform,
                "missing",
                true,
                readiness,
            )
            .await
        }));
    }

    let mut statuses = Vec::new();
    for task in tasks {
        statuses.push(task.await.context("joining VM probe task")?);
    }
    Ok(statuses)
}

fn load_inventory_vms(path: &Path) -> Result<Vec<InventoryVm>> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading VM inventory {}", path.display()))?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing VM inventory {}", path.display()))?;
    let entries = value
        .get("entries")
        .and_then(|entries| entries.as_array())
        .context("VM inventory has no entries array")?;
    Ok(entries
        .iter()
        .filter(|entry| {
            entry.pointer("/controller/type").and_then(|v| v.as_str()) == Some("local_utm")
        })
        .filter_map(|entry| {
            let alias = entry.get("alias")?.as_str()?.to_owned();
            let utm_name = entry
                .pointer("/controller/utm_name")
                .and_then(|value| value.as_str())
                .unwrap_or(&alias)
                .to_owned();
            let ip = entry
                .get("ssh_target")
                .and_then(|value| value.as_str())
                .unwrap_or("-")
                .to_owned();
            let platform = inventory_platform(entry).unwrap_or_else(|| "unknown".to_owned());
            Some(InventoryVm {
                alias,
                utm_name,
                ip,
                platform,
            })
        })
        .collect())
}

fn inventory_platform(entry: &serde_json::Value) -> Option<String> {
    entry
        .get("platform")
        .and_then(|value| value.as_str())
        .map(str::to_ascii_lowercase)
        .or_else(|| {
            let os = entry.get("os")?.as_str()?.to_ascii_lowercase();
            if os.contains("windows") {
                Some("windows".to_owned())
            } else if os.contains("macos") || os.contains("mac os") {
                Some("macos".to_owned())
            } else if os.contains("linux") {
                Some("linux".to_owned())
            } else {
                None
            }
        })
}

pub fn render_ui(f: &mut Frame, app: &App) {
    let area = f.area();
    let header_height = area.height.min(4);
    let footer_height = if area.height > header_height { 1 } else { 0 };
    let body_y = area.y.saturating_add(header_height);
    let body_height = area.height.saturating_sub(header_height + footer_height);
    let header_area = Rect {
        x: area.x,
        y: area.y,
        width: area.width,
        height: header_height,
    };
    let body_area = Rect {
        x: area.x,
        y: body_y,
        width: area.width,
        height: body_height,
    };
    let status_area = Rect {
        x: area.x,
        y: area.y + area.height.saturating_sub(footer_height),
        width: area.width,
        height: footer_height,
    };

    match app.page {
        Page::Overview => {
            let rows = Layout::vertical([
                Constraint::Length(3),
                Constraint::Percentage(48),
                Constraint::Percentage(52),
            ])
            .split(body_area);
            let lower =
                Layout::horizontal([Constraint::Percentage(34), Constraint::Percentage(66)])
                    .split(rows[2]);
            crate::ui::pipeline_panel::render(f, rows[0], app);
            crate::ui::vm_panel::render(f, rows[1], app);
            crate::ui::parity_panel::render(f, lower[0], app);
            crate::ui::agents_panel::render(f, lower[1], app);
        }
        Page::Run => {
            let rows = Layout::vertical([
                Constraint::Percentage(48),
                Constraint::Percentage(30),
                Constraint::Percentage(22),
            ])
            .split(body_area);
            let lower =
                Layout::horizontal([Constraint::Percentage(72), Constraint::Percentage(28)])
                    .split(rows[1]);
            crate::ui::stage_grid::render(f, rows[0], app);
            crate::ui::log_panel::render(f, lower[0], app);
            crate::ui::jobs_panel::render(f, lower[1], app);
            crate::ui::prev_runs_panel::render(f, rows[2], app);
        }
        Page::Matrix => {
            crate::ui::stage_matrix_panel::render(f, body_area, app);
        }
    }

    crate::ui::header::render(f, header_area, app);
    if footer_height > 0 {
        crate::ui::status_bar::render(f, status_area, app);
    }

    if app.show_help {
        crate::ui::help_overlay::render(f, area);
    }
    if app.show_stage_detail {
        crate::ui::stage_detail_overlay::render(f, area, app);
    }
}

/// deepseek-direct/* is a fixed provider defined in the user's global
/// `~/.config/opencode/opencode.jsonc` with its own hardcoded API key --
/// always safe to offer, unlike the project-local `deepseek/*` provider
/// below (needs a `.opencode/opencode.json` models block AND a resolvable
/// `DEEPSEEK_API_KEY`, neither of which exist in this repo/environment) and
/// unlike `opencode/deepseek-v4-flash-free` (OpenCode's hosted free-tier
/// proxy) which is confirmed to hang indefinitely with zero output when
/// invoked headlessly -- it must never be offered as a selectable model,
/// since `available_models` is indexed positionally (see
/// `patch_model_idx`/`review_model_idx`) and a persisted index landing on
/// it would silently break the whole "s" (start) loop, patch and review
/// agents alike.
const KNOWN_WORKING_DEEPSEEK_DIRECT_MODELS: [&str; 4] = [
    "deepseek-chat",
    "deepseek-v4-flash",
    "deepseek-v4-pro",
    "deepseek-reasoner",
];

fn load_available_models(repo_root: &Path) -> Vec<String> {
    let config_path = repo_root.join(".opencode/opencode.json");
    let mut models: Vec<String> = Vec::new();
    if let Ok(raw) = std::fs::read_to_string(&config_path)
        && let Ok(json) = serde_json::from_str::<serde_json::Value>(&raw)
        && let Some(provider_models) = json
            .get("provider")
            .and_then(|p| p.get("deepseek"))
            .and_then(|d| d.get("models"))
            .and_then(|m| m.as_object())
    {
        for key in provider_models.keys() {
            models.push(format!("deepseek/{key}"));
        }
    }
    for key in KNOWN_WORKING_DEEPSEEK_DIRECT_MODELS {
        models.push(format!("deepseek-direct/{key}"));
    }
    models.sort();
    models.dedup();
    models
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn position_based_failure_breakdown_places_a_bootstrap_windows_failure_correctly() {
        // Real-world regression: first_failed_stage = "bootstrap_windows_host"
        // is a pipeline STEP name, not a CSV column pattern -- it must be
        // attributed to BOOTSTRAP (where Stage Grid lists it, at local index
        // 14 of 19: 9 base + 5 macos before it), not silently default to
        // LIVE LAB.
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let (sections, failing) =
            position_based_failure_breakdown(&groups, "bootstrap_windows_host")
                .expect("bootstrap_windows_host must resolve to a known position");
        assert_eq!(failing, 1, "must be attributed to BOOTSTRAP, not LIVE LAB");
        assert_eq!(sections[0], (5, 5), "PRE fully passed before BOOTSTRAP");
        assert_eq!(
            sections[1],
            (14, 21),
            "14 BOOTSTRAP steps (9 base + 5 macos) precede bootstrap_windows_host"
        );
        assert_eq!(sections[2], (0, 64), "LIVE LAB never reached");
    }

    #[test]
    fn position_based_failure_breakdown_places_a_bootstrap_macos_failure_correctly() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let (sections, failing) = position_based_failure_breakdown(&groups, "bootstrap_macos_host")
            .expect("bootstrap_macos_host must resolve to a known position");
        assert_eq!(failing, 1);
        assert_eq!(sections[0], (5, 5));
        assert_eq!(
            sections[1],
            (9, 21),
            "the 9 base BOOTSTRAP steps precede bootstrap_macos_host"
        );
        assert_eq!(sections[2], (0, 64));
    }

    #[test]
    fn position_based_failure_breakdown_places_a_pre_phase_failure_correctly() {
        // Real-world regression: PRE was previously ALWAYS shown as (5, 5)
        // regardless of where the failure actually happened -- even when
        // the failure was itself inside PRE (verify_ssh_reachability, local
        // index 2 of 5), which produced a nonsensical "5 passed" count for
        // a run that broke on PRE's 3rd step. It must now show only the
        // steps strictly before the failure as passed.
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let (sections, failing) =
            position_based_failure_breakdown(&groups, "verify_ssh_reachability")
                .expect("verify_ssh_reachability must resolve to a known position");
        assert_eq!(failing, 0, "must be attributed to PRE");
        assert_eq!(
            sections[0],
            (2, 5),
            "only preflight + prepare_source_archive precede it"
        );
        assert_eq!(sections[1], (0, 21), "BOOTSTRAP never reached");
        assert_eq!(sections[2], (0, 64), "LIVE LAB never reached");
    }

    #[test]
    fn position_based_failure_breakdown_strips_a_node_alias_prefix() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let (_, failing) = position_based_failure_breakdown(
            &groups,
            "debian-headless-1::validate_linux_hello_limiter_flood",
        )
        .expect("alias-prefixed name must still resolve");
        assert_eq!(
            failing, 2,
            "validate_linux_hello_limiter_flood is a LIVE LAB stage"
        );
    }

    #[test]
    fn position_based_failure_breakdown_returns_none_for_an_unrecognized_name() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        assert!(position_based_failure_breakdown(&groups, "totally_unknown_stage").is_none());
        assert!(position_based_failure_breakdown(&groups, "").is_none());
    }

    fn sample_run_summary() -> crate::data::run_matrix::RunSummary {
        crate::data::run_matrix::RunSummary {
            run_id: "test-run".to_owned(),
            git_commit: "abc1234".to_owned(),
            // Empty so run_plan_summary returns None and these tests exercise
            // the CSV/pipeline-position fallback path they were written for.
            report_dir: String::new(),
            overall_result: "fail".to_owned(),
            first_failed_stage: "bootstrap_windows_host".to_owned(),
            passed_stages: 5,
            total_stages: 97,
            last_passed_stage: "validate_baseline_runtime".to_owned(),
            section_stages: [(0, 5), (0, 12), (0, 40)],
            subset_passed_stages: 5,
            subset_total_stages: 57,
            failing_section: Some(2),
            counts_exact: false,
        }
    }

    #[test]
    fn apply_position_based_failure_override_is_a_noop_for_a_passing_run() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let mut run = sample_run_summary();
        run.overall_result = "pass".to_owned();
        let before = run.clone();
        apply_position_based_failure_override(&groups, &mut run);
        assert_eq!(run, before, "a passing run must be left untouched");
    }

    #[test]
    fn apply_position_based_failure_override_corrects_a_failing_run_with_a_resolvable_stage() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let mut run = sample_run_summary();
        apply_position_based_failure_override(&groups, &mut run);

        assert_eq!(
            run.failing_section,
            Some(1),
            "bootstrap_windows_host must be attributed to BOOTSTRAP"
        );
        assert_eq!(run.section_stages, [(5, 5), (14, 21), (0, 64)]);
        assert_eq!(run.subset_passed_stages, 19);
        // 5 PRE + 21 BOOTSTRAP + 64 LIVE LAB after the catalog heal.
        assert_eq!(run.subset_total_stages, 90);
        // total_stages is pinned to the same pipeline-plan catalog as the
        // in-scope count, so the card stays coherent (passed <= in-scope <=
        // catalog): 19 <= 90 <= 90, never the old cross-universe "19/90 | 97".
        assert_eq!(run.total_stages, 90);
    }

    fn write_run_report(report_dir: &std::path::Path, manifest_json: &str, result_json: &str) {
        let orchestration = report_dir.join("orchestration");
        std::fs::create_dir_all(&orchestration).unwrap();
        std::fs::write(orchestration.join("stage_manifest.json"), manifest_json).unwrap();
        std::fs::write(orchestration.join("orchestrate_result.json"), result_json).unwrap();
    }

    const SAMPLE_MANIFEST_JSON: &str = r#"{
        "schema_version": 1, "run_command": "vm-lab-orchestrate-live-lab", "run_mode": "full",
        "stages": [
            {"name": "preflight", "group": "pre", "enabled": true},
            {"name": "restart_unready_vms", "group": "pre", "enabled": true},
            {"name": "bootstrap_hosts", "group": "bootstrap", "enabled": true},
            {"name": "validate_windows_client_install", "group": "bootstrap", "enabled": false},
            {"name": "check_a", "group": "live", "enabled": true},
            {"name": "check_b", "group": "live", "enabled": true},
            {"name": "linux_live_suite", "group": "live", "enabled": true, "synthetic": true}
        ]
    }"#;

    #[test]
    fn run_plan_summary_counts_are_coherent_and_drop_passed_over_infra_on_a_failed_run() {
        // The direct fix for the "28/165 | 100" contradiction: every number
        // comes from the run's own manifest, so passed <= in-scope <=
        // catalog holds. restart_unready_vms (enabled PRE infra, no recorded
        // outcome, before the failure frontier) is dropped from the
        // denominator; check_b (the failing stage) stays counted.
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report");
        write_run_report(
            &report,
            SAMPLE_MANIFEST_JSON,
            r#"{"overall_status":"fail","outcomes":[
                {"stage":"preflight","status":"pass"},
                {"stage":"bootstrap_hosts","status":"pass"},
                {"stage":"check_a","status":"pass"},
                {"stage":"check_b","status":"fail"}
            ]}"#,
        );
        let mut run = sample_run_summary();
        run.report_dir = report.display().to_string();
        run.first_failed_stage = "check_b".to_owned();

        let counts = run_plan_summary(&PathBuf::from("/tmp"), &run).expect("manifest present");

        assert_eq!(counts.section_stages, [(1, 1), (1, 1), (1, 2)]);
        assert_eq!(counts.subset_passed, 3);
        assert_eq!(counts.subset_total, 4);
        // grand_total = 6 non-synthetic stages (linux_live_suite excluded).
        assert_eq!(counts.grand_total, 6);
        assert_eq!(
            counts.failing_section,
            Some(2),
            "check_b is a LIVE LAB stage"
        );
        assert!(
            counts.subset_passed <= counts.subset_total
                && counts.subset_total <= counts.grand_total,
            "passed <= in-scope <= catalog must hold: {:?}",
            (
                counts.subset_passed,
                counts.subset_total,
                counts.grand_total
            )
        );
    }

    #[test]
    fn run_plan_summary_reads_a_clean_pass_run_as_full_not_artificially_partial() {
        // A clean PASS run whose infra stages no-op'd (no recorded outcome)
        // must read as complete, not dragged down by those phantom cells.
        let dir = tempfile::tempdir().unwrap();
        let report = dir.path().join("report");
        write_run_report(
            &report,
            SAMPLE_MANIFEST_JSON,
            r#"{"overall_status":"pass","outcomes":[
                {"stage":"preflight","status":"pass"},
                {"stage":"bootstrap_hosts","status":"pass"},
                {"stage":"check_a","status":"pass"},
                {"stage":"check_b","status":"pass"}
            ]}"#,
        );
        let mut run = sample_run_summary();
        run.report_dir = report.display().to_string();
        run.overall_result = "pass".to_owned();
        run.first_failed_stage = String::new();

        let counts = run_plan_summary(&PathBuf::from("/tmp"), &run).expect("manifest present");

        assert_eq!(counts.subset_passed, 4);
        assert_eq!(
            counts.subset_total, 4,
            "no artificial partial from no-op infra"
        );
        assert_eq!(counts.grand_total, 6);
        assert_eq!(counts.failing_section, None);
    }

    #[test]
    fn run_plan_summary_is_none_without_a_report_dir_or_manifest() {
        let run = sample_run_summary(); // empty report_dir
        assert!(run_plan_summary(&PathBuf::from("/tmp"), &run).is_none());

        let dir = tempfile::tempdir().unwrap();
        let mut run = sample_run_summary();
        run.report_dir = dir.path().join("no-such-report").display().to_string();
        assert!(
            run_plan_summary(&PathBuf::from("/tmp"), &run).is_none(),
            "a missing manifest must fall back, not panic"
        );
    }

    #[test]
    fn apply_position_based_failure_override_leaves_an_unrecognized_stage_name_untouched() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();
        let mut run = sample_run_summary();
        run.first_failed_stage = "totally_unknown_stage".to_owned();
        let before = run.clone();
        apply_position_based_failure_override(&groups, &mut run);
        assert_eq!(
            before, run,
            "an unresolvable stage name must leave the CSV-column-based approximation intact"
        );
    }

    #[test]
    fn available_models_never_offers_the_confirmed_broken_free_proxy() {
        // Regression: opencode/deepseek-v4-flash-free (OpenCode's hosted
        // free-tier proxy) hangs indefinitely with zero output when invoked
        // headlessly. Since available_models is indexed positionally by
        // patch_model_idx/review_model_idx (persisted in monitor-config.toml),
        // even briefly offering it risks a saved index silently landing on
        // it and breaking the whole "s" (start) loop -- as it did on a real
        // repo checkout where the project has no .opencode/opencode.json
        // deepseek models block, so this was the ONLY model ever returned,
        // and both persisted indices resolved to it after clamping.
        let dir = tempfile::tempdir().unwrap();
        let models = load_available_models(dir.path());
        assert!(
            !models.iter().any(|m| m.contains("flash-free")),
            "must never offer the hanging free-tier proxy: {models:?}"
        );
    }

    #[test]
    fn available_models_always_includes_working_deepseek_direct_options() {
        // deepseek-direct/* needs no project-local config or env var --
        // it's a fixed, always-usable provider from the user's global
        // opencode config -- so it must be available even in a completely
        // empty repo (no .opencode/opencode.json at all).
        let dir = tempfile::tempdir().unwrap();
        let models = load_available_models(dir.path());
        assert!(!models.is_empty());
        assert!(
            models.iter().all(|m| m.starts_with("deepseek-direct/")),
            "with no project-local deepseek config, every option must be a \
             known-working deepseek-direct model: {models:?}"
        );
        assert!(
            models
                .iter()
                .any(|m| m == "deepseek-direct/deepseek-v4-flash")
        );
        assert!(
            models
                .iter()
                .any(|m| m == "deepseek-direct/deepseek-v4-pro")
        );
    }

    #[test]
    fn inventory_loader_keeps_local_utm_hostnames_and_excludes_non_utm_entries() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(
            &path,
            serde_json::json!({"entries": [
                {"alias": "utm-vm", "ssh_target": "utm-vm.local", "os": "Debian/Linux",
                 "controller": {"type": "local_utm", "utm_name": "UTM VM"}},
                {"alias": "lan-vm", "ssh_target": "lan-vm.local", "os": "Debian/Linux"}
            ]})
            .to_string(),
        )
        .unwrap();

        let entries = load_inventory_vms(&path).expect("inventory");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "utm-vm");
        assert_eq!(entries[0].utm_name, "UTM VM");
        assert_eq!(entries[0].ip, "utm-vm.local");
    }

    #[test]
    fn inventory_loader_treats_a_missing_file_as_empty_not_an_error() {
        // A missing inventory is a legitimate cold-start state, not a
        // defect -- the VM panel just shows the host-only UTM VMs. It must
        // NOT surface a `data_errors` entry for this case.
        let dir = tempfile::tempdir().unwrap();
        let entries = load_inventory_vms(&dir.path().join("nope.json")).expect("missing is ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn inventory_loader_fails_loud_on_corrupt_json_never_silently_empty() {
        // A corrupt inventory must be a VISIBLE error (surfaced as a
        // `data_errors` entry by the caller), never silently swallowed into
        // an empty list that would look like "no VMs configured".
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(&path, "{ this is not json").unwrap();
        assert!(load_inventory_vms(&path).is_err());

        // Non-UTF8 bytes are equally a hard, visible error.
        std::fs::write(&path, [0x7b, 0xff, 0xfe, 0x00]).unwrap();
        assert!(load_inventory_vms(&path).is_err());
    }

    #[test]
    fn inventory_loader_missing_entries_array_is_a_visible_error() {
        // Valid JSON but the wrong shape (no `entries` array at all) is a
        // schema defect the operator needs to see, not a silent empty read.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(&path, r#"{"something_else": true}"#).unwrap();
        assert!(load_inventory_vms(&path).is_err());
    }

    #[test]
    fn inventory_loader_empty_entries_array_is_ok_and_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(&path, r#"{"entries": []}"#).unwrap();
        let entries = load_inventory_vms(&path).expect("empty entries is ok");
        assert!(entries.is_empty());
    }

    #[test]
    fn inventory_loader_skips_entries_missing_required_fields_without_erroring() {
        // A partially-written entry (added to the array before its `alias`
        // was filled in) must be skipped, not abort the whole load or crash
        // -- the other, complete entries still render.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.json");
        std::fs::write(
            &path,
            serde_json::json!({"entries": [
                {"ssh_target": "no-alias.local",
                 "controller": {"type": "local_utm", "utm_name": "No Alias"}},
                {"alias": "good-vm", "ssh_target": "good.local",
                 "controller": {"type": "local_utm", "utm_name": "Good"}}
            ]})
            .to_string(),
        )
        .unwrap();

        let entries = load_inventory_vms(&path).expect("inventory");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].alias, "good-vm");
    }

    #[test]
    fn assigning_macos_exit_sets_promote_exit_and_rebuild_node() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "macos-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "macos".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        };

        app.assign_vm_role(&vm, "exit");

        assert_eq!(app.config.macos_vm, "macos-utm-1");
        assert!(app.config.macos_promote_exit);
        assert_eq!(app.config.rebuild_nodes, "macos-utm-1");
        assert_eq!(app.role_for_vm("macos-utm-1"), "exit");
    }

    fn dummy_stage_entries(n: usize) -> Vec<crate::data::run_matrix::StageMatrixEntry> {
        (0..n)
            .map(|i| crate::data::run_matrix::StageMatrixEntry {
                name: format!("stage-{i}"),
                state: ParityState::Proven,
                latest_pass: true,
            })
            .collect()
    }

    #[test]
    fn stage_matrix_scroll_clamps_immediately_at_the_bottom_not_just_on_render() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageMatrix;
        app.stage_matrix_os_col = 0;
        app.full_stage_matrix.linux = dummy_stage_entries(20);
        app.stage_matrix_visible_rows.set(5);

        // Scroll down far past the bottom -- must stop at max_scroll (15),
        // not run away to some much larger raw increment count.
        for _ in 0..30 {
            app.handle_key(KeyCode::Down, KeyModifiers::empty());
        }
        assert_eq!(app.stage_matrix_scroll[0], 15);

        // One Up press from the clamped bottom must move the view by
        // exactly one row immediately, not require many presses to first
        // undo an inflated scroll value.
        app.handle_key(KeyCode::Up, KeyModifiers::empty());
        assert_eq!(app.stage_matrix_scroll[0], 14);
    }

    #[test]
    fn stage_matrix_scroll_clamps_on_column_switch_after_a_resize() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageMatrix;
        app.stage_matrix_os_col = 0;
        app.full_stage_matrix.macos = dummy_stage_entries(5);
        app.stage_matrix_scroll[1] = 100; // stale from a taller terminal
        app.stage_matrix_visible_rows.set(3);

        app.handle_key(KeyCode::Right, KeyModifiers::empty());

        assert_eq!(app.stage_matrix_os_col, 1);
        assert_eq!(app.stage_matrix_scroll[1], 2);
    }

    #[test]
    fn stage_grid_row_does_not_spill_into_the_next_column_at_the_bottom() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageGrid;
        app.stage_grid_col = 0; // PRE group: 5 stages

        for _ in 0..10 {
            app.handle_key(KeyCode::Down, KeyModifiers::empty());
        }

        // Must stop at the last row of PRE (index 4), never spill the
        // column focus or cursor into BOOTSTRAP just because Down was
        // pressed more times than PRE has stages.
        assert_eq!(app.stage_grid_col, 0);
        assert_eq!(app.stage_grid_row[0], 4);
    }

    #[test]
    fn stage_grid_left_right_switches_column_with_independent_cursors() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageGrid;
        app.stage_grid_col = 0;

        app.handle_key(KeyCode::Down, KeyModifiers::empty());
        app.handle_key(KeyCode::Down, KeyModifiers::empty());
        assert_eq!(app.stage_grid_row[0], 2);

        app.handle_key(KeyCode::Right, KeyModifiers::empty());
        assert_eq!(app.stage_grid_col, 1);
        // BOOTSTRAP's own cursor starts fresh at 0, unaffected by PRE's.
        assert_eq!(app.stage_grid_row[1], 0);

        app.handle_key(KeyCode::Down, KeyModifiers::empty());
        assert_eq!(app.stage_grid_row[1], 1);

        app.handle_key(KeyCode::Left, KeyModifiers::empty());
        // Switching back to PRE keeps its own cursor exactly where it was.
        assert_eq!(app.stage_grid_col, 0);
        assert_eq!(app.stage_grid_row[0], 2);
    }

    #[test]
    fn stage_grid_row_clamps_when_switching_to_a_shorter_column() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageGrid;
        app.stage_grid_col = 1;
        // PRE (column 0) has only 5 stages (indices 0-4); simulate a stale
        // row left over from e.g. a taller terminal that could once fit
        // that far, or a config change that shrank the group.
        app.stage_grid_row[0] = 20;

        app.handle_key(KeyCode::Left, KeyModifiers::empty());

        assert_eq!(app.stage_grid_col, 0);
        assert_eq!(app.stage_grid_row[0], 4);
    }

    #[test]
    fn stage_grid_down_moves_freely_onto_disabled_stages() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageGrid;
        // Default target is macOS exit (macos_promote_exit: true) -- clear
        // it so only Windows is wanted here.
        app.config.area = "Windows exit".to_owned();
        app.config.macos_promote_exit = false;
        app.config.exit_platform = "windows".to_owned(); // wants_windows() true, wants_macos() false
        app.stage_grid_col = 1; // BOOTSTRAP: 9 base + 5 macos (disabled) + 5 windows (enabled)
        app.stage_grid_row[1] = 8; // last base stage, "validate_baseline_runtime"

        app.handle_key(KeyCode::Down, KeyModifiers::empty());

        // Must land on index 9, the first (disabled) macOS bootstrap stage
        // -- the user can see and navigate to it, it's just not toggleable.
        let group = &app.planned_stage_groups()[1];
        assert_eq!(app.stage_grid_row[1], 9);
        assert!(!app.stage_enabled(&group.stages[9]));
        assert_eq!(group.stages[9], "bootstrap_macos_host");
    }

    #[test]
    fn stage_grid_up_moves_freely_onto_disabled_stages() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.focused_panel = Panel::StageGrid;
        app.config.area = "Windows exit".to_owned();
        app.config.macos_promote_exit = false;
        app.config.exit_platform = "windows".to_owned();
        app.stage_grid_col = 1;
        app.stage_grid_row[1] = 14; // first enabled Windows bootstrap stage

        app.handle_key(KeyCode::Up, KeyModifiers::empty());

        // Must land on index 13, the last (disabled) macOS bootstrap stage
        // -- not skip straight back to the last enabled base stage (8).
        assert_eq!(app.stage_grid_row[1], 13);
    }

    #[test]
    fn toggle_selected_stage_is_a_noop_on_a_not_possible_stage() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.page = Page::Run; // Space only toggles on the Run page
        app.focused_panel = Panel::StageGrid;
        app.config.area = "Windows exit".to_owned();
        app.config.macos_promote_exit = false;
        app.config.exit_platform = "windows".to_owned();
        app.stage_grid_col = 1;
        app.stage_grid_row[1] = 9; // bootstrap_macos_host: not possible here

        app.handle_key(KeyCode::Char(' '), KeyModifiers::empty());

        assert!(
            !app.config
                .disabled_stages
                .contains(&"bootstrap_macos_host".to_owned()),
            "toggling a not-possible stage must not add it to disabled_stages: {:?}",
            app.config.disabled_stages
        );
    }

    #[test]
    fn toggle_selected_stage_still_works_on_a_possible_stage() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.page = Page::Run; // Space only toggles on the Run page
        app.focused_panel = Panel::StageGrid;
        app.stage_grid_col = 0; // PRE: all 5 stages are always possible
        app.stage_grid_row[0] = 0; // "preflight"

        app.handle_key(KeyCode::Char(' '), KeyModifiers::empty());
        assert!(app.config.disabled_stages.contains(&"preflight".to_owned()));

        app.handle_key(KeyCode::Char(' '), KeyModifiers::empty());
        assert!(!app.config.disabled_stages.contains(&"preflight".to_owned()));
    }

    #[test]
    fn app_new_prunes_unknown_stage_names_from_disabled_stages_and_persists_the_prune() {
        // disabled_stages is hand-editable TOML with no schema enforcement
        // -- a renamed/removed stage, or a typo, must not linger forever
        // silently. Uses an isolated tempdir (not the shared "/tmp" literal
        // other tests in this file use) since this test writes and re-reads
        // a real config file on disk.
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let state = repo.join("state");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(
            state.join("monitor-config.toml"),
            r#"
                area = "macOS exit"
                exit_vm = "debian-headless-1"
                client_vm = "debian-headless-2"
                entry_vm = "debian-headless-3"
                macos_vm = "macos-utm-1"
                windows_vm = "windows-utm-1"
                relay_platform = ""
                anchor_platform = ""
                exit_platform = ""
                admin_platform = ""
                blind_exit_platform = ""
                macos_promote_exit = true
                rebuild_nodes = ""
                disabled_stages = ["preflight", "validate_macos_mesh_join", "this_stage_was_renamed_away"]
            "#,
        )
        .unwrap();

        let app = App::new(repo.to_path_buf()).expect("app");

        assert!(app.config.disabled_stages.contains(&"preflight".to_owned()));
        assert!(
            app.config
                .disabled_stages
                .contains(&"validate_macos_mesh_join".to_owned())
        );
        assert!(
            !app.config
                .disabled_stages
                .contains(&"this_stage_was_renamed_away".to_owned()),
            "unknown stage name must be pruned: {:?}",
            app.config.disabled_stages
        );

        // The prune must be written back, not just held in memory -- else
        // the stale entry reappears on every reload.
        let persisted = std::fs::read_to_string(state.join("monitor-config.toml")).unwrap();
        assert!(!persisted.contains("this_stage_was_renamed_away"));
    }

    fn manifest_from_json(json: &str) -> crate::data::stage_manifest::RunStageManifest {
        serde_json::from_str(json).expect("manifest fixture parses")
    }

    #[test]
    fn stage_grid_derives_from_the_runs_manifest_when_present() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        // A stage name this binary's fallback catalog has never heard of —
        // exactly the "invisible failure-causing stage" class. With a
        // manifest it MUST get a cell.
        app.run_manifest = Some(manifest_from_json(
            r#"{"run_mode": "full", "stages": [
                {"name": "preflight", "group": "pre", "enabled": true},
                {"name": "membership_setup", "group": "bootstrap", "enabled": true},
                {"name": "validate_linux_hello_limiter_flood", "group": "live", "enabled": true},
                {"name": "some_brand_new_stage", "group": "live", "enabled": true},
                {"name": "chaos_daemon_fault", "group": "chaos", "enabled": false,
                 "skip_reason": "chaos suite not selected"}
            ]}"#,
        ));

        let groups = app.planned_stage_groups();
        assert_eq!(groups[0].stages, vec!["preflight".to_owned()]);
        assert_eq!(groups[1].stages, vec!["membership_setup".to_owned()]);
        assert_eq!(
            groups[2].stages,
            vec![
                "validate_linux_hello_limiter_flood".to_owned(),
                "some_brand_new_stage".to_owned(),
                "chaos_daemon_fault".to_owned(),
            ],
            "live + chaos both render in the LIVE LAB pane, manifest order"
        );

        // Enablement comes from the manifest's resolved plan, not from
        // this monitor's local config heuristics.
        assert!(app.stage_selected_for_current_target("some_brand_new_stage"));
        assert!(!app.stage_selected_for_current_target("chaos_daemon_fault"));
        // User-level disables still layer on top.
        app.config
            .disabled_stages
            .push("some_brand_new_stage".to_owned());
        assert!(!app.stage_enabled("some_brand_new_stage"));
    }

    #[test]
    fn selected_run_without_manifest_never_uses_local_fallback_catalog() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.run_manifest_dir = Some(PathBuf::from("/tmp/active-report"));
        app.run_manifest = None;

        let groups = app.planned_stage_groups();

        assert!(groups.iter().all(|group| group.stages.is_empty()));
        assert_eq!(app.plan_source_label(), "WAITING FOR MANIFEST");
    }

    #[test]
    fn run_test_count_comes_only_from_manifest_metadata() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.run_manifest = Some(manifest_from_json(
            r#"{"schema_version": 2, "run_mode": "full", "stages": [
                {"name": "prepare", "group": "pre", "enabled": true,
                 "counts_as_check": false},
                {"name": "validate", "group": "live", "enabled": true,
                 "counts_as_check": true},
                {"name": "disabled_check", "group": "live", "enabled": false,
                 "counts_as_check": true}
            ]}"#,
        ));
        app.stage_outcomes = vec![crate::data::stage_reader::StageOutcome {
            stage: "validate".to_owned(),
            status: "reused".to_owned(),
            summary: String::new(),
            artifacts: Vec::new(),
        }];

        assert_eq!(app.current_run_check_progress(), Some((1, 1)));
    }

    #[test]
    fn vm_role_comes_from_the_runs_own_manifest_topology() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        // Baseline: with no manifest, an alias the monitor's default slots +
        // the previous run's CSV roles don't name resolves however it resolves.
        let baseline_absent = app.role_for_vm("debian-headless-5");

        // A Rust `--node` run that elected dh-1 exit, dh-2/3 client. The
        // emitted topology must win over every inference below role_for_vm.
        app.run_manifest = Some(manifest_from_json(
            r#"{"run_mode": "full",
                "stages": [{"name": "preflight", "group": "pre", "enabled": true}],
                "node_assignments": [
                    {"alias": "debian-headless-1", "role": "exit"},
                    {"alias": "debian-headless-2", "role": "client"},
                    {"alias": "debian-headless-3", "role": "client"}
                ]}"#,
        ));
        assert_eq!(app.role_for_vm("debian-headless-1"), "exit");
        assert_eq!(app.role_for_vm("debian-headless-2"), "client");
        // The bug this fixes: dh-3 is a client in the run but was absent from
        // the previous run's roles, so it used to show blank. Now it's correct.
        assert_eq!(app.role_for_vm("debian-headless-3"), "client");
        // An alias the run does NOT name is unaffected — falls through to the
        // same inference as with no manifest (no blanking, no override).
        assert_eq!(app.role_for_vm("debian-headless-5"), baseline_absent);
    }

    #[test]
    fn vm_status_roles_only_describe_actual_current_or_previous_run_use() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");

        // Default config plans these roles, but no run used them yet.
        assert_eq!(app.actual_role_for_vm("debian-headless-1"), "—");
        assert_eq!(app.run_use_for_vm("debian-headless-1"), "—");

        app.latest_run_roles
            .insert("debian-headless-5".to_owned(), "relay".to_owned());
        assert_eq!(app.actual_role_for_vm("debian-headless-5"), "relay");
        assert_eq!(app.run_use_for_vm("debian-headless-5"), "PREVIOUS");

        app.active_job = Some(JobState {
            job_id: "labrun-current".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "current".to_owned(),
            report_dir: "state/current".to_owned(),
            request_args: None,
        });
        app.run_manifest = Some(manifest_from_json(
            r#"{"run_mode":"full","stages":[],"node_assignments":[
                {"alias":"debian-headless-2","role":"client"}
            ]}"#,
        ));

        assert_eq!(app.actual_role_for_vm("debian-headless-2"), "client");
        assert_eq!(app.run_use_for_vm("debian-headless-2"), "CURRENT");
        // Previous role must not leak into active run membership.
        assert_eq!(app.actual_role_for_vm("debian-headless-5"), "—");
        assert_eq!(app.run_use_for_vm("debian-headless-5"), "—");
    }

    #[test]
    fn empty_node_assignments_do_not_change_role_inference() {
        // A bash/wrapper run emits no node_assignments; role_for_vm must be
        // byte-identical to the pre-manifest behaviour (no regression).
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let before = app.role_for_vm("debian-headless-1");
        app.run_manifest = Some(manifest_from_json(
            r#"{"run_mode": "full",
                "stages": [{"name": "preflight", "group": "pre", "enabled": true}],
                "node_assignments": []}"#,
        ));
        assert_eq!(app.role_for_vm("debian-headless-1"), before);
    }

    #[test]
    fn held_run_display_is_pinned_to_its_manifest_not_live_config() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.run_manifest = Some(manifest_from_json(
            r#"{"run_mode": "full", "stages": [
                {"name": "validate_macos_blind_exit", "group": "live", "enabled": true}
            ]}"#,
        ));
        assert!(app.stage_selected_for_current_target("validate_macos_blind_exit"));

        // An external config edit while the run is held must not change
        // what the held run's grid says was planned (finding 7's
        // config-reload divergence).
        app.config.blind_exit_platform.clear();
        app.config.macos_promote_exit = false;
        app.config.exit_platform = "windows".to_owned();
        assert!(
            app.stage_selected_for_current_target("validate_macos_blind_exit"),
            "held-run enablement must read the manifest, not live config"
        );
    }

    #[test]
    fn fallback_catalog_still_governs_pre_manifest_report_dirs() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.run_manifest = None;
        // Default target is macOS exit: the macOS exit cells are planned,
        // the Windows exit cells are not — the pre-manifest logic intact.
        assert!(app.stage_selected_for_current_target("activate_macos_exit_role"));
        assert!(!app.stage_selected_for_current_target("promote_windows_exit_active"));
        let groups = app.planned_stage_groups();
        assert_eq!(groups.len(), 3);
        assert!(
            groups[1]
                .stages
                .contains(&"stage_windows_bundles_for_distribution".to_owned())
        );
    }

    #[tokio::test]
    async fn refresh_state_prunes_unknown_disabled_stages_on_hot_reload() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        let state = repo.join("state");
        std::fs::create_dir_all(&state).unwrap();

        let mut app = App::new(repo.to_path_buf()).expect("app");
        // Fresh config still defaults to the macOS-exit target, so
        // apply_fast_stage_defaults() already seeded a real, valid entry.
        assert_eq!(
            app.config.disabled_stages,
            vec!["linux_live_suite".to_owned()]
        );

        std::fs::write(
            state.join("monitor-config.toml"),
            r#"
                area = "macOS exit"
                exit_vm = "debian-headless-1"
                client_vm = "debian-headless-2"
                entry_vm = "debian-headless-3"
                macos_vm = "macos-utm-1"
                windows_vm = "windows-utm-1"
                relay_platform = ""
                anchor_platform = ""
                exit_platform = ""
                admin_platform = ""
                blind_exit_platform = ""
                macos_promote_exit = true
                rebuild_nodes = ""
                disabled_stages = ["stale_entry_from_an_old_version"]
            "#,
        )
        .unwrap();

        app.refresh_state().await;

        assert!(
            !app.config
                .disabled_stages
                .contains(&"stale_entry_from_an_old_version".to_owned()),
            "hot-reloaded config must also be pruned, not just the App::new path: {:?}",
            app.config.disabled_stages
        );
    }

    #[test]
    fn linux_oneoff_security_stages_are_listed_and_gated_with_linux_live_suite() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.config.skip_linux_live_suite = true;

        assert!(
            app.planned_stages()
                .contains(&"validate_linux_membership_revoke_applies".to_owned())
        );
        assert!(!app.stage_enabled("validate_linux_membership_revoke_applies"));

        app.config.skip_linux_live_suite = false;
        assert!(app.stage_enabled("validate_linux_membership_revoke_applies"));
        assert!(app.stage_enabled("validate_linux_hello_limiter_flood"));
    }

    #[test]
    fn assigning_linux_non_exit_role_is_not_displayed_as_exit() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "debian-headless-2".into(),
            ip: "192.168.0.201".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        };

        app.assign_vm_role(&vm, "relay");

        assert_eq!(app.config.exit_vm, "debian-headless-2");
        assert_eq!(app.config.relay_platform, "linux");
        assert_eq!(app.role_for_vm("debian-headless-2"), "relay");
    }

    #[test]
    fn assigning_one_linux_vm_does_not_clear_other_displayed_exit() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "debian-headless-2".into(),
            ip: "192.168.0.201".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        };

        app.assign_vm_role(&vm, "relay");

        assert_eq!(app.role_for_vm("debian-headless-1"), "exit");
        assert_eq!(app.role_for_vm("debian-headless-2"), "relay");
    }

    #[test]
    fn linux_exit_can_be_unset_by_cycling_to_another_role() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "debian-headless-1".into(),
            ip: "192.168.0.200".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        };

        app.assign_vm_role(&vm, "relay");

        assert_eq!(app.role_for_vm("debian-headless-1"), "relay");
    }

    #[test]
    fn active_lab_roles_ignore_stale_user_overrides() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.vm_role_overrides
            .insert("windows-utm-1".to_owned(), "relay".to_owned());
        app.active_job = Some(JobState {
            job_id: "labrun-test".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "Windows admin".to_owned(),
            report_dir: "state/deepseek-lab-labrun-test".to_owned(),
            request_args: Some(HashMap::from([
                ("area".to_owned(), json!("Windows admin")),
                ("windows_vm".to_owned(), json!("windows-utm-1")),
                ("admin_platform".to_owned(), json!("windows")),
            ])),
        });

        assert_eq!(app.role_for_vm("windows-utm-1"), "admin");
    }

    #[test]
    fn role_for_vm_falls_back_to_the_last_runs_actual_assignment_for_unconfigured_nodes() {
        // A node the last run elected but that the monitor's own config slots
        // don't name (e.g. debian-headless-3 as relay) must show that real
        // role -- and therefore its parity glyph -- instead of a blank "—".
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        // debian-headless-3 is entry_vm by default -> role_for_vm_from_config
        // returns the "—" placeholder for it.
        assert_eq!(app.role_for_vm("debian-headless-3"), "—");
        app.latest_run_roles
            .insert("debian-headless-3".to_owned(), "relay".to_owned());
        app.latest_run_roles
            .insert("debian-headless-5".to_owned(), "client".to_owned());

        assert_eq!(app.role_for_vm("debian-headless-3"), "relay");
        assert_eq!(app.role_for_vm("debian-headless-5"), "client");
    }

    #[test]
    fn last_run_roles_never_override_a_config_named_role_or_a_manual_override() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        // exit_vm is a real config-named role; the last-run map must not
        // clobber it even if that node also served something else.
        app.latest_run_roles
            .insert("debian-headless-1".to_owned(), "anchor".to_owned());
        assert_eq!(
            app.role_for_vm("debian-headless-1"),
            "exit",
            "config-named role wins over the last-run fallback"
        );
        // A manual override wins over both.
        app.vm_role_overrides
            .insert("debian-headless-3".to_owned(), "admin".to_owned());
        app.latest_run_roles
            .insert("debian-headless-3".to_owned(), "relay".to_owned());
        assert_eq!(app.role_for_vm("debian-headless-3"), "admin");
    }

    #[test]
    fn active_lab_blocks_vm_role_cycling() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.vm_statuses.push(crate::data::vm_prober::VmStatus {
            alias: "debian-headless-1".into(),
            ip: "192.168.0.200".into(),
            platform: "linux".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        });
        let overrides_before = app.vm_role_overrides.clone();
        app.active_job = Some(JobState {
            job_id: "labrun-test".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "macOS exit".to_owned(),
            report_dir: "state/deepseek-lab-labrun-test".to_owned(),
            request_args: None,
        });

        app.cycle_selected_vm_role(1);

        assert_eq!(app.role_for_vm("debian-headless-1"), "exit");
        assert_eq!(app.vm_role_overrides, overrides_before);
        assert_eq!(
            app.log_lines,
            vec!["VM roles locked to active live lab; wait for lab to finish".to_owned()]
        );
    }

    #[test]
    fn auto_select_next_target_prefers_failed_macos_cell() {
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(
            docs.join("live_lab_run_matrix.csv"),
            "overall_result,macos_stage_exit\npass,fail\n",
        )
        .unwrap();

        let mut app = App::new(dir.path().to_path_buf()).expect("app");
        app.vm_statuses.push(crate::data::vm_prober::VmStatus {
            alias: "macos-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "macos".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        });

        app.auto_select_next_target();

        assert_eq!(app.config.area, "macOS exit");
        assert_eq!(app.config.macos_vm, "macos-utm-1");
        assert!(app.config.macos_promote_exit);
        assert_eq!(app.config.rebuild_nodes, "macos-utm-1");
    }

    #[test]
    fn auto_select_next_target_does_not_steal_focus_from_the_current_panel() {
        // Regression: auto_select_next_target used to force
        // focused_panel = Panel::VmStatus unconditionally. It runs both on
        // the 'a' keypress and silently from the periodic advance-when-proven
        // refresh tick, so it must never yank focus away from whatever panel
        // (e.g. StageGrid) the user is actively working in.
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(
            docs.join("live_lab_run_matrix.csv"),
            "overall_result,macos_stage_exit\npass,fail\n",
        )
        .unwrap();

        let mut app = App::new(dir.path().to_path_buf()).expect("app");
        app.vm_statuses.push(crate::data::vm_prober::VmStatus {
            alias: "macos-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "macos".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        });
        app.page = Page::Run;
        app.focused_panel = Panel::StageGrid;

        app.handle_key(KeyCode::Char('a'), KeyModifiers::empty());

        assert_eq!(app.config.area, "macOS exit");
        assert_eq!(app.focused_panel, Panel::StageGrid);
    }

    #[test]
    fn configuring_a_linux_blind_exit_target_clears_stale_macos_selection() {
        // Regression: an externally-launched job (raw CLI, another user's
        // session) has no request_args, so refresh_state's fallback parses
        // the job's report-dir name (job_watcher::
        // infer_role_and_platform_from_report_dir) and calls this same
        // configure_target -- reproduce that here directly. Before the fix,
        // a monitor left showing a stale local "macOS admin" target kept
        // every macOS-only stage enabled and every Linux stage disabled
        // even while the actually-running job was a Linux blind_exit run.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.config.area = "macOS admin".to_owned();
        app.config.admin_platform = "macos".to_owned();
        app.config.macos_promote_exit = false;

        app.configure_target("blind_exit", "linux", None);

        assert_eq!(app.config.blind_exit_platform, "linux");
        assert!(app.config.admin_platform.is_empty());
        assert!(!app.config.area.to_ascii_lowercase().contains("macos"));
        assert!(!app.config.wants_macos());
        // The macOS-only validator must now read as impossible for this
        // target (grayed out), not just "not selected".
        assert!(!app.stage_selected_for_current_target("validate_macos_admin_issue"));
    }

    #[test]
    fn auto_target_disables_linux_suite_for_platform_specific_cell() {
        let dir = tempfile::tempdir().unwrap();
        let docs = dir.path().join("documents").join("operations");
        std::fs::create_dir_all(&docs).unwrap();
        std::fs::write(
            docs.join("live_lab_run_matrix.csv"),
            "overall_result,windows_stage_exit_handoff\npass,fail\n",
        )
        .unwrap();

        let mut app = App::new(dir.path().to_path_buf()).expect("app");
        app.vm_statuses.push(crate::data::vm_prober::VmStatus {
            alias: "windows-utm-1".into(),
            ip: "192.168.0.220".into(),
            platform: "windows".into(),
            ssh_ok: true,
            power_state: "started".into(),
            inventory_registered: true,
            lab_readiness: crate::data::vm_prober::LabReadiness::checking(),
        });

        app.auto_select_next_target();

        assert_eq!(app.config.area, "Windows exit");
        assert_eq!(app.config.exit_platform, "windows");
        assert!(app.config.skip_linux_live_suite);
        assert!(
            app.config
                .disabled_stages
                .contains(&"linux_live_suite".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"validate_windows_exit_nat_lifecycle".to_owned())
        );
        // linux_live_suite is always listed (the grid shows the full
        // catalog now), it just reads as disabled/grayed for this config.
        assert!(
            app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
        assert!(!app.stage_enabled("linux_live_suite"));
    }

    #[test]
    fn default_macos_target_disables_linux_suite_but_still_lists_every_stage() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");

        assert!(app.config.skip_linux_live_suite);
        // The full catalog is always listed regardless of what the
        // current config actually plans to run -- stage_enabled (styling)
        // is how the grid distinguishes "will run" from "grayed out",
        // not list membership.
        assert!(
            app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
        assert!(!app.stage_enabled("linux_live_suite"));
        assert!(
            app.planned_stages()
                .contains(&"bootstrap_macos_host".to_owned())
        );
        assert!(app.stage_enabled("bootstrap_macos_host"));
        assert!(
            app.planned_stages()
                .contains(&"validate_macos_blind_exit".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"validate_macos_anchor_bundle_pull".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"validate_macos_exit_killswitch_precedence".to_owned())
        );
        // Windows stages are listed too now, just not enabled by default.
        assert!(
            app.planned_stages()
                .contains(&"bootstrap_windows_host".to_owned())
        );
        assert!(!app.stage_enabled("bootstrap_windows_host"));
    }

    #[test]
    fn active_job_request_args_update_visible_stage_plan() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let mut args = std::collections::HashMap::new();
        args.insert("area".to_owned(), serde_json::json!("Windows relay"));
        args.insert("relay_platform".to_owned(), serde_json::json!("windows"));
        args.insert("windows_vm".to_owned(), serde_json::json!("windows-utm-1"));

        app.active_job = Some(JobState {
            job_id: "labrun-1-2-3".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "Windows relay".to_owned(),
            report_dir: "state/deepseek-lab-labrun-1-2-3".to_owned(),
            request_args: Some(args.clone()),
        });
        app.config.apply_request_args(&args);

        assert_eq!(app.config.relay_platform, "windows");
        assert!(app.config.skip_linux_live_suite);
        assert!(
            app.planned_stages()
                .contains(&"validate_windows_relay_service_lifecycle".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
        assert!(!app.stage_enabled("linux_live_suite"));
    }

    #[test]
    fn normalizes_duplicate_linux_support_vms_before_launch() {
        let mut config = MonitorConfig {
            client_vm: "debian-headless-3".into(),
            entry_vm: "debian-headless-3".into(),
            ..MonitorConfig::default()
        };
        let linux_aliases = vec![
            "debian-headless-1".to_owned(),
            "debian-headless-2".to_owned(),
            "debian-headless-3".to_owned(),
        ];

        crate::config::normalize_linux_lab_vms(&mut config, &linux_aliases).unwrap();

        assert_eq!(config.exit_vm, "debian-headless-1");
        assert_eq!(config.client_vm, "debian-headless-2");
        assert_eq!(config.entry_vm, "debian-headless-3");
    }

    #[test]
    fn numeric_focus_hotkeys_switch_to_owning_page() {
        // 1-3 Overview, 4-6 Run, 7 Matrix -- grouped by page, matching each
        // page's own on-screen top-to-bottom/left-to-right panel order.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");

        app.page = Page::Run;
        app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::VmStatus);

        app.handle_key(KeyCode::Char('2'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::Parity);

        app.handle_key(KeyCode::Char('3'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::Agents);

        app.handle_key(KeyCode::Char('4'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Run);
        assert_eq!(app.focused_panel, Panel::StageGrid);

        app.handle_key(KeyCode::Char('5'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Run);
        assert_eq!(app.focused_panel, Panel::Log);

        app.handle_key(KeyCode::Char('6'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Run);
        assert_eq!(app.focused_panel, Panel::Jobs);

        app.handle_key(KeyCode::Char('7'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Matrix);
        assert_eq!(app.focused_panel, Panel::StageMatrix);
    }

    #[test]
    fn letter_shortcuts_no_longer_focus_a_window() {
        // Window focus is numbers-only now -- the old l/p/v/j/m aliases
        // must be inert (not silently still switching pages/panels).
        for letter in ['l', 'p', 'v', 'j', 'm'] {
            let mut app = App::new(PathBuf::from("/tmp")).expect("app");
            app.page = Page::Run;
            app.focused_panel = Panel::Log;
            app.handle_key(KeyCode::Char(letter), KeyModifiers::NONE);
            assert_eq!(
                app.page,
                Page::Run,
                "'{letter}' must not change the page anymore"
            );
            assert_eq!(
                app.focused_panel,
                Panel::Log,
                "'{letter}' must not change the focused panel anymore"
            );
        }
    }

    #[test]
    fn pipeline_phase_tracks_active_stage() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");

        app.active_stage = Some("cleanup_hosts".to_owned());
        let steps = app.pipeline_steps();
        assert!(steps[0].1);

        app.active_stage = Some("bootstrap_hosts".to_owned());
        let steps = app.pipeline_steps();
        assert!(steps[0].2);
        assert!(steps[1].1);

        app.active_stage = Some("distribute_membership_state".to_owned());
        let steps = app.pipeline_steps();
        assert!(steps[2].1);

        app.active_stage = Some("validate_macos_exit_nat_lifecycle".to_owned());
        let steps = app.pipeline_steps();
        assert!(steps[3].1);
    }

    fn running_job() -> JobState {
        JobState {
            job_id: "monitor-1".to_owned(),
            state: "running".to_owned(),
            pid: Some(1),
            started_unix: Some(1),
            area: "test".to_owned(),
            report_dir: "state/monitor-loop-monitor-1".to_owned(),
            request_args: None,
        }
    }

    #[test]
    fn lab_is_actively_running_requires_a_job_in_the_running_state() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        assert!(
            !app.lab_is_actively_running(),
            "no job at all -> not running"
        );

        app.active_job = Some(running_job());
        assert!(app.lab_is_actively_running());

        let mut done_job = running_job();
        done_job.state = "done".to_owned();
        app.active_job = Some(done_job);
        assert!(
            !app.lab_is_actively_running(),
            "a job record that finished must not count as actively running"
        );
    }

    #[test]
    fn clear_stale_active_run_state_strips_only_the_synthetic_running_placeholder() {
        // Regression: a lab started then immediately stopped (before any
        // real orchestrate_result.json/stages.tsv existed) left a
        // synthetic "running" placeholder (pushed by
        // ensure_active_stage_visible) sitting in stage_outcomes forever,
        // since the idle-transition's conditional refresh only replaces
        // stage_outcomes when a fresh read finds something -- it never
        // fires when there's genuinely nothing to read yet. That
        // placeholder kept Stage Grid / Stage Detail spinning on
        // "preflight" long after the monitor had gone IDLE.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.stage_outcomes = vec![
            crate::data::stage_reader::StageOutcome {
                stage: "preflight".to_owned(),
                status: "running".to_owned(),
                summary: "active stage".to_owned(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "prepare_source_archive".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
        ];
        app.active_stage = Some("preflight".to_owned());
        app.active_stage_start = Some(std::time::Instant::now());
        app.orchestrator_pgid = Some(1234);

        app.clear_stale_active_run_state();

        assert_eq!(app.stage_outcomes.len(), 1);
        assert_eq!(app.stage_outcomes[0].stage, "prepare_source_archive");
        assert!(app.active_stage.is_none());
        assert!(app.active_stage_start.is_none());
        assert!(app.orchestrator_pgid.is_none());
    }

    fn outcome(stage: &str, status: &str) -> crate::data::stage_reader::StageOutcome {
        crate::data::stage_reader::StageOutcome {
            stage: stage.to_owned(),
            status: status.to_owned(),
            summary: String::new(),
            artifacts: Vec::new(),
        }
    }

    #[test]
    fn implicitly_completed_stages_covers_passed_over_infra_but_not_pending_stages() {
        // A stage with no recorded outcome that sits BEFORE the furthest
        // completed stage in pipeline order is treated as satisfied so its
        // column can clear; a stage AFTER the furthest completed one stays
        // genuinely pending (not swallowed).
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        // preflight passed, then a BOOTSTRAP stage passed -- the PRE steps in
        // between never recorded (fallback catalog has no infra stages, but
        // the mechanism is identical). collect_pubkeys sits AFTER the
        // furthest completed stage, so it must NOT be implicit.
        app.stage_outcomes = vec![
            outcome("preflight", "pass"),
            outcome("bootstrap_hosts", "pass"),
        ];

        let implicit = app.implicitly_completed_stages();

        for passed_over in [
            "prepare_source_archive",
            "verify_ssh_reachability",
            "prime_remote_access",
            "cleanup_hosts",
        ] {
            assert!(
                implicit.contains(passed_over),
                "{passed_over} was passed over and must clear: {implicit:?}"
            );
        }
        assert!(
            !implicit.contains("preflight"),
            "a stage with a real outcome is never implicit"
        );
        assert!(
            !implicit.contains("bootstrap_hosts"),
            "the furthest completed stage is not implicit"
        );
        assert!(
            !implicit.contains("collect_pubkeys"),
            "a stage after the furthest completed one is still genuinely pending"
        );
    }

    #[test]
    fn implicitly_completed_stages_is_empty_before_any_outcome() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        assert!(app.implicitly_completed_stages().is_empty());
    }

    #[test]
    fn final_stage_for_idle_log_prefers_the_failing_stage() {
        // Regression: a real run's last live poll caught "bootstrap_macos_host,
        // no log file yet" as the active stage, then the real run went on to
        // finish 25 more stages and conclude -- but log_lines was never told
        // to look again once the job went idle, so it kept showing that exact
        // stale placeholder for 5+ minutes after the run had actually failed
        // much further along. The failing stage is what a human needs to see
        // first, regardless of where in the outcome list it sits.
        let outcomes = vec![
            outcome("bootstrap_macos_host", "pass"),
            outcome("collect_macos_pubkey", "pass"),
            outcome("validate_macos_enrollment_replay", "fail"),
            outcome("validate_macos_hello_limiter_flood", "pass"),
        ];
        assert_eq!(
            final_stage_for_idle_log(&outcomes).as_deref(),
            Some("validate_macos_enrollment_replay")
        );
    }

    #[test]
    fn final_stage_for_idle_log_falls_back_to_the_last_stage_when_nothing_failed() {
        let outcomes = vec![
            outcome("bootstrap_macos_host", "pass"),
            outcome("collect_macos_pubkey", "pass"),
            outcome("validate_macos_blind_exit_reversal_denied", "pass"),
        ];
        assert_eq!(
            final_stage_for_idle_log(&outcomes).as_deref(),
            Some("validate_macos_blind_exit_reversal_denied"),
            "the most recently completed stage is the most useful final snapshot, \
             not an arbitrary early one"
        );
    }

    #[test]
    fn final_stage_for_idle_log_is_none_when_nothing_ran() {
        assert_eq!(final_stage_for_idle_log(&[]), None);
    }

    #[test]
    fn cleanup_hosts_is_shown_in_pre_group() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");
        let groups = app.planned_stage_groups();

        assert!(groups[0].stages.contains(&"cleanup_hosts".to_owned()));
        assert!(!groups[1].stages.contains(&"cleanup_hosts".to_owned()));
    }

    #[test]
    fn stage_timer_for_completed_group_is_zero() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.stage_outcomes = vec![
            crate::data::stage_reader::StageOutcome {
                stage: "preflight".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "prepare_source_archive".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "verify_ssh_reachability".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "prime_remote_access".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "cleanup_hosts".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
        ];

        let labels = app.stage_timer_labels();

        assert_eq!(labels[0], ("PRE", "0s".to_owned()));
        assert_ne!(labels[1].1, "0s");
    }

    #[test]
    fn macos_exit_lab_default_timer_is_not_hours_without_history() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.stage_timings.clear();
        app.config.macos_promote_exit = true;
        app.config.skip_linux_live_suite = true;

        let labels = app.stage_timer_labels();

        // 21m, not the pre-catalog-expansion 18m: validate_macos_key_custody
        // is now a real, always-listed LIVE LAB stage (previously missing
        // from macos_live_lab_catalog entirely), and it's enabled here via
        // macos_promote_exit -> wants_macos().
        // 21m of role-cell stages + the 13 macOS audit stages (180s
        // defaults each) that really run on a macOS-guest lab: 1h0m.
        assert_eq!(labels[2], ("LAB", "1h0m".to_owned()));
    }

    #[test]
    fn group_eta_is_based_on_the_enabled_subset_not_the_full_group_catalog() {
        // The BOOTSTRAP header line shows "x/y" against the enabled subset
        // (see stage_group_header_spans); the top-bar timer must agree --
        // narrowing the target to Linux-only must shrink the BOOTSTRAP
        // estimate below what it'd be with macOS also enabled, not silently
        // sum the whole 19-stage catalog (base + macos + windows
        // candidates) regardless of what's actually planned to run.
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.stage_timings.clear();
        app.config.area = "Linux exit".to_owned();
        app.config.macos_promote_exit = false;
        let linux_only_boot = app.stage_timer_labels()[1].1.clone();

        app.config.area = "macOS exit".to_owned();
        app.config.macos_promote_exit = true;
        let with_macos_boot = app.stage_timer_labels()[1].1.clone();

        assert_ne!(
            linux_only_boot, with_macos_boot,
            "enabling macOS must change the BOOTSTRAP estimate, proving it's not a fixed full-catalog number"
        );
    }

    #[test]
    fn stage_timers_do_not_subtract_whole_job_elapsed_before_live_lab() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.config.macos_promote_exit = true;
        app.config.skip_linux_live_suite = true;
        app.active_job = Some(JobState {
            job_id: "labrun-1-2-3".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "macOS exit".to_owned(),
            report_dir: "state/deepseek-lab-labrun-1-2-3".to_owned(),
            request_args: None,
        });
        app.active_stage = Some("bootstrap_hosts".to_owned());
        app.stage_outcomes = vec![
            crate::data::stage_reader::StageOutcome {
                stage: "preflight".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
            crate::data::stage_reader::StageOutcome {
                stage: "prepare_source_archive".to_owned(),
                status: "pass".to_owned(),
                summary: String::new(),
                artifacts: Vec::new(),
            },
        ];

        let labels = app.stage_timer_labels();

        assert_ne!(labels[0].1, "0s");
        assert_ne!(labels[1].1, "0s");
        assert_ne!(labels[2].1, "0s");
    }

    #[test]
    fn timers_use_selected_target_stages_not_whole_platform_catalog() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.config.area = "macOS blind_exit".to_owned();
        app.config.macos_promote_exit = false; // isolate blind_exit from the default macOS-exit target
        app.config.blind_exit_platform = "macos".to_owned();
        app.config.skip_linux_live_suite = true;

        assert!(
            app.planned_stages()
                .contains(&"validate_macos_exit_nat_lifecycle".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"validate_macos_blind_exit".to_owned())
        );
        let enabled = app
            .planned_stages()
            .into_iter()
            .filter(|stage| app.stage_enabled(stage))
            .collect::<Vec<_>>();
        assert!(!enabled.contains(&"validate_macos_exit_nat_lifecycle".to_owned()));
        assert!(enabled.contains(&"validate_macos_blind_exit".to_owned()));
    }

    #[test]
    fn stage_outcomes_persist_after_job_finishes() {
        let dir = tempfile::tempdir().unwrap();

        // Write a completed orchestrate_result so the final read succeeds.
        let report_dir = dir.path().join("state/deepseek-lab-labrun-done-1");
        let orch_dir = report_dir.join("orchestration");
        std::fs::create_dir_all(&orch_dir).unwrap();
        std::fs::write(
            orch_dir.join("orchestrate_result.json"),
            r#"{"overall_status":"pass","report_dir":"","outcomes":[
                {"stage":"bootstrap_hosts","status":"pass","summary":"ok","artifacts":[]},
                {"stage":"validate_baseline_runtime","status":"fail","summary":"fail","artifacts":[]}
            ]}"#,
        )
        .unwrap();

        let mut app = App::new(dir.path().to_path_buf()).expect("app");
        app.active_job = Some(JobState {
            job_id: "labrun-done-1".to_owned(),
            state: "done".to_owned(),
            pid: None,
            started_unix: Some(1),
            area: "macOS exit".to_owned(),
            report_dir: "state/deepseek-lab-labrun-done-1".to_owned(),
            request_args: None,
        });
        // Simulate: job was just read by the watcher, now it reports None (job finished).
        // Manually call the None-transition logic by taking the job and re-reading.
        let prev_job = app.active_job.take().unwrap();
        let final_report_dir = app.repo_root.join(&prev_job.report_dir);
        if let Ok(result) = crate::data::stage_reader::read_orchestrate_result(&final_report_dir)
            && !result.outcomes.is_empty()
        {
            app.stage_outcomes = result.outcomes;
        }
        app.active_stage = None;

        // Outcomes must be retained with correct statuses — not cleared.
        assert_eq!(app.stage_outcomes.len(), 2);
        assert_eq!(app.stage_outcomes[0].stage, "bootstrap_hosts");
        assert_eq!(app.stage_outcomes[0].status, "pass");
        assert_eq!(app.stage_outcomes[1].stage, "validate_baseline_runtime");
        assert_eq!(app.stage_outcomes[1].status, "fail");
        assert!(app.active_job.is_none());
        assert!(app.active_stage.is_none());
    }

    #[test]
    fn stage_timers_are_zero_while_acting_on_report() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.active_job = Some(JobState {
            job_id: "monitor-1".to_owned(),
            state: "running".to_owned(),
            pid: Some(std::process::id()),
            started_unix: Some(1),
            area: "macOS blind_exit".to_owned(),
            report_dir: "state/monitor-loop-monitor-1".to_owned(),
            request_args: None,
        });
        app.log_lines = vec!["OpenCode main agent patching".to_owned()];

        assert_eq!(
            app.stage_timer_labels(),
            vec![
                ("PRE", "0s".to_owned()),
                ("BOOT", "0s".to_owned()),
                ("LAB", "0s".to_owned())
            ]
        );
    }
}
