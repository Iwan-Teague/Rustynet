use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Layout, Rect},
};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::net::IpAddr;
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

/// For a FAILED run, locates `first_failed_stage` (alias-prefix stripped)
/// directly in the canonical PRE/BOOTSTRAP/LIVE LAB pipeline order (`groups`,
/// i.e. `App::planned_stage_groups`) and derives (passed, total) per group
/// from ITS POSITION: the pipeline is serial, so every step strictly before
/// the failure is known to have passed, the failing step and everything
/// after it did not. Returns `None` if the bare stage name isn't found in
/// any group at all (e.g. an unrecognized name), in which case the caller
/// should keep whatever CSV-column-based approximation it already had.
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

/// Applies `position_based_failure_breakdown` to a single `RunSummary` in
/// place, for a FAILED run whose `first_failed_stage` resolves to a known
/// pipeline position: overrides `section_stages`/`failing_section` and the
/// LEFT-hand `subset_passed_stages`/`subset_total_stages` fraction (now
/// measured against the canonical pipeline). Deliberately does NOT touch
/// `total_stages` -- that stays the CSV-column-based full project catalog
/// size (see `RunSummary::total_stages`), the constant "how big is the
/// whole possible test surface" reference shown after the divider,
/// regardless of how far any single run's pipeline got. A no-op for a
/// passing run or an unrecognized stage name.
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
}

pub struct App {
    pub repo_root: PathBuf,
    pub config: MonitorConfig,

    pub active_job: Option<JobState>,
    pub stage_outcomes: Vec<crate::data::stage_reader::StageOutcome>,
    pub active_stage: Option<String>,
    pub log_lines: Vec<String>,
    /// Lines above the bottom (0 = follow tail). Positive = user scrolled up / pinned.
    pub log_scroll: usize,
    /// Total line count when the user first scrolled away from the tail.
    pub log_scroll_anchor: usize,
    pub recent_runs: Vec<RunSummary>,

    pub vm_statuses: Vec<crate::data::vm_prober::VmStatus>,
    pub selected_vm: usize,
    pub vm_role_overrides: HashMap<String, String>,

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

    active_stage_start: Option<std::time::Instant>,
    last_vm_probe: Option<std::time::Instant>,
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
        .find(|o| o.status == "fail")
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

        Ok(Self {
            repo_root,
            config,
            active_job: None,
            stage_outcomes: Vec::new(),
            active_stage: None,
            log_lines: Vec::new(),
            log_scroll: 0,
            log_scroll_anchor: 0,
            recent_runs,
            vm_statuses: Vec::new(),
            selected_vm: 0,
            vm_role_overrides,
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
            active_stage_start: None,
            last_vm_probe: None,
        })
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

    fn estimated_group_remaining_secs(&self, group_name: &str) -> u64 {
        let completed = self
            .stage_outcomes
            .iter()
            .filter(|o| matches!(o.status.as_str(), "pass" | "fail" | "skipped"))
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

    fn estimate_stage_secs(&self, stage: &str) -> u64 {
        self.stage_timings
            .get(stage)
            .copied()
            .filter(|secs| *secs > 0)
            .unwrap_or_else(|| default_stage_secs(stage))
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
                | "collect_windows_pubkey"
                | "amend_membership_for_windows"
                | "distribute_windows_bundles"
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
            "validate_windows_exit_nat_lifecycle"
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
                "bootstrap_windows_host",
                "collect_windows_pubkey",
                "amend_membership_for_windows",
                "distribute_windows_bundles",
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

    pub async fn refresh_state(&mut self) {
        if self.active_job.is_none()
            && let Ok(mut config) = MonitorConfig::load(&self.repo_root)
        {
            config.apply_fast_stage_defaults();
            self.config = config;
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
                let report_dir = self.repo_root.join(&job.report_dir);
                if let Ok(result) = crate::data::stage_reader::read_orchestrate_result(&report_dir)
                {
                    self.stage_outcomes = result.outcomes;
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
                self.active_job = Some(job);
            }
            Ok(None) => {
                if let Some(prev_job) = self.active_job.take() {
                    // Do one final read to replace any synthetic "running" entries
                    // with the definitive pass/fail outcomes before going idle.
                    let report_dir = self.repo_root.join(&prev_job.report_dir);
                    if let Ok(result) =
                        crate::data::stage_reader::read_orchestrate_result(&report_dir)
                        && !result.outcomes.is_empty()
                    {
                        self.stage_outcomes = result.outcomes;
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
            Err(_) => {}
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

        // Probe VMs every 30s (run concurrently, don't block)
        let now = std::time::Instant::now();
        let should_probe = self
            .last_vm_probe
            .map(|t| now.duration_since(t).as_secs() >= 30)
            .unwrap_or(true);

        if should_probe {
            self.last_vm_probe = Some(now);
            self.vm_statuses = probe_vms_sync(&self.repo_root).await;
            if self.selected_vm >= self.vm_statuses.len() {
                self.selected_vm = self.vm_statuses.len().saturating_sub(1);
            }
        }

        if let Ok(matrix) = crate::data::run_matrix::load_parity_matrix(&self.repo_root) {
            self.parity_matrix = matrix;
        }
        if let Ok(sparklines) = crate::data::run_matrix::load_sparklines(&self.repo_root, 8) {
            self.parity_sparklines = sparklines;
        }
        if let Ok(progress) = crate::data::run_matrix::load_stage_progress(&self.repo_root) {
            self.stage_progress = progress;
        }
        if let Ok(stage_timings) = crate::data::timings::load_stage_timings(&self.repo_root) {
            self.stage_timings = stage_timings;
        }
        if let Ok(full_stage_matrix) =
            crate::data::run_matrix::load_full_stage_matrix(&self.repo_root)
        {
            self.full_stage_matrix = full_stage_matrix;
        }
        if let Ok(runs) = crate::data::run_matrix::load_recent_runs(&self.repo_root, 3) {
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
            let groups = self.planned_stage_groups();
            for run in &mut self.recent_runs {
                apply_position_based_failure_override(&groups, run);
            }
        }
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

    pub fn role_for_vm(&self, alias: &str) -> String {
        let config = self.config_for_role_display();
        if !self.roles_locked_by_active_lab()
            && let Some(role) = self.vm_role_overrides.get(alias)
        {
            return role.clone();
        }
        role_for_vm_from_config(alias, &config)
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
        self.config.macos_promote_exit = false;

        match platform {
            "macos" => {
                if let Some(alias) = alias.clone() {
                    self.config.macos_vm = alias;
                }
                if role == "exit" {
                    self.config.macos_promote_exit = true;
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
                set_role_platform(&mut self.config, role, platform);
                self.config.area = format!("Windows {role}");
                self.config.skip_linux_live_suite = true;
            }
            _ => {
                if role == "client" {
                    if let Some(alias) = alias.clone() {
                        self.config.client_vm = alias;
                    }
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
        ] {
            let os = match platform {
                "linux" => Os::Linux,
                "macos" => Os::Macos,
                "windows" => Os::Windows,
                _ => continue,
            };
            return Some((role, os));
        }
        let area = self.config.area.to_ascii_lowercase();
        let os = if area.contains("windows") {
            Os::Windows
        } else if area.contains("macos") {
            Os::Macos
        } else if area.contains("linux") {
            Os::Linux
        } else {
            return None;
        };
        let role = if area.contains("blind") {
            Role::BlindExit
        } else if area.contains("relay") {
            Role::Relay
        } else if area.contains("anchor") {
            Role::Anchor
        } else if area.contains("admin") {
            Role::Admin
        } else if area.contains("exit") {
            Role::Exit
        } else {
            Role::Client
        };
        Some((role, os))
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
    } else if stage.contains("bootstrap")
        || stage.contains("membership")
        || stage.contains("distribute")
        || stage.contains("assignment")
        || stage.contains("traversal")
        || stage.contains("dns_zone")
        || stage.contains("baseline")
        || stage.contains("pubkey")
        || stage == "enforce_baseline_runtime"
        || stage == "validate_baseline_runtime"
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

async fn probe_vms_sync(repo_root: &std::path::Path) -> Vec<crate::data::vm_prober::VmStatus> {
    let inventory_path = repo_root
        .join("documents")
        .join("operations")
        .join("active")
        .join("vm_lab_inventory.json");

    if !inventory_path.exists() {
        return Vec::new();
    }

    let raw = match std::fs::read_to_string(&inventory_path) {
        Ok(r) => r,
        Err(_) => return Vec::new(),
    };

    let val: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };

    let entries = match val.get("entries").and_then(|e| e.as_array()) {
        Some(arr) => arr,
        None => return Vec::new(),
    };

    // Launch all probes concurrently
    let mut tasks = Vec::new();
    for entry in entries {
        let alias = entry
            .get("alias")
            .and_then(|a| a.as_str())
            .unwrap_or("?")
            .to_string();
        let ip = entry
            .get("ssh_target")
            .and_then(|a| a.as_str())
            .unwrap_or("")
            .to_string();
        if !is_real_lab_vm_entry(entry, &alias, &ip) {
            continue;
        }
        let utm_name = entry
            .get("controller")
            .and_then(|c| c.get("utm_name"))
            .and_then(|n| n.as_str())
            .unwrap_or(&alias)
            .to_string();
        let ssh_user = entry
            .get("ssh_user")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        if !ip.is_empty() {
            tasks.push(tokio::spawn(async move {
                crate::data::vm_prober::probe_vm(&alias, &ip, &utm_name, &ssh_user).await
            }));
        }
    }

    let mut statuses = Vec::new();
    for task in tasks {
        if let Ok(status) = task.await {
            statuses.push(status);
        }
    }

    statuses
}

fn is_real_lab_vm_entry(entry: &serde_json::Value, alias: &str, ssh_target: &str) -> bool {
    if alias.is_empty() || alias == "?" || ssh_target.parse::<IpAddr>().is_err() {
        return false;
    }
    entry
        .get("controller")
        .and_then(|c| c.get("type"))
        .and_then(|t| t.as_str())
        == Some("local_utm")
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
            (14, 19),
            "14 BOOTSTRAP steps (9 base + 5 macos) precede bootstrap_windows_host"
        );
        assert_eq!(sections[2], (0, 40), "LIVE LAB never reached");
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
            (9, 19),
            "the 9 base BOOTSTRAP steps precede bootstrap_macos_host"
        );
        assert_eq!(sections[2], (0, 40));
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
        assert_eq!(sections[1], (0, 19), "BOOTSTRAP never reached");
        assert_eq!(sections[2], (0, 40), "LIVE LAB never reached");
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
            overall_result: "fail".to_owned(),
            first_failed_stage: "bootstrap_windows_host".to_owned(),
            passed_stages: 5,
            total_stages: 97,
            last_passed_stage: "validate_baseline_runtime".to_owned(),
            section_stages: [(0, 5), (0, 12), (0, 40)],
            subset_passed_stages: 5,
            subset_total_stages: 57,
            failing_section: Some(2),
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
        let original_total_stages = run.total_stages;
        apply_position_based_failure_override(&groups, &mut run);

        assert_eq!(
            run.failing_section,
            Some(1),
            "bootstrap_windows_host must be attributed to BOOTSTRAP"
        );
        assert_eq!(run.section_stages, [(5, 5), (14, 19), (0, 40)]);
        assert_eq!(run.subset_passed_stages, 19);
        assert_eq!(run.subset_total_stages, 64);
        assert_eq!(
            run.total_stages, original_total_stages,
            "total_stages is the CSV-column project catalog size and must \
             stay untouched by the pipeline-position override"
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
    fn inventory_filter_rejects_hostname_without_utm_controller() {
        let entry = json!({
            "alias": "debian-lan-11",
            "ssh_target": "debian-lan-11",
            "ssh_user": "debian"
        });

        assert!(!is_real_lab_vm_entry(
            &entry,
            "debian-lan-11",
            "debian-lan-11"
        ));
    }

    #[test]
    fn inventory_filter_accepts_local_utm_ip_entry() {
        let entry = json!({
            "alias": "debian-headless-1",
            "ssh_target": "192.168.0.200",
            "controller": {"type": "local_utm", "utm_name": "debian-headless-1"}
        });

        assert!(is_real_lab_vm_entry(
            &entry,
            "debian-headless-1",
            "192.168.0.200"
        ));
    }

    #[test]
    fn assigning_macos_exit_sets_promote_exit_and_rebuild_node() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "macos-utm-1".into(),
            ip: "192.168.0.210".into(),
            platform: "macos".into(),
            ssh_ok: true,
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
        // Default area is "macOS exit", which makes wants_macos() true --
        // override it so only Windows is wanted here.
        app.config.area = "Windows exit".to_owned();
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
    fn active_lab_blocks_vm_role_cycling() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.vm_statuses.push(crate::data::vm_prober::VmStatus {
            alias: "debian-headless-1".into(),
            ip: "192.168.0.200".into(),
            platform: "linux".into(),
            ssh_ok: true,
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
        assert_eq!(labels[2], ("LAB", "21m".to_owned()));
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
        let linux_only_boot = app.stage_timer_labels()[1].1.clone();

        app.config.area = "macOS exit".to_owned();
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

    #[test]
    #[ignore]
    fn probe_real_repo_idle_log_catchup() {
        let repo_root = PathBuf::from("/Users/iwan/Desktop/Rustynet");
        let report_dir =
            repo_root.join("state/deepseek-lab-labrun-1783089250895-6139-0");
        let result =
            crate::data::stage_reader::read_orchestrate_result(&report_dir).expect("read result");
        let stage = final_stage_for_idle_log(&result.outcomes);
        eprintln!("picked stage: {stage:?}");
        if let Some(stage) = &stage {
            let lines =
                crate::data::log_tailer::summarize_stage_lines(&repo_root, &report_dir, stage)
                    .expect("summarize");
            for line in lines.iter().take(5) {
                eprintln!("  {line}");
            }
        }
    }
}
