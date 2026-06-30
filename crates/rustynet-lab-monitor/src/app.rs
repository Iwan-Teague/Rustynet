use anyhow::{Context, Result};
use crossterm::event::{Event, KeyCode, KeyModifiers};
use ratatui::{
    Frame, Terminal,
    layout::{Constraint, Layout, Rect},
};
use std::collections::{HashMap, HashSet};
use std::io;
use std::net::IpAddr;
use std::path::PathBuf;

use crate::config::MonitorConfig;
use crate::data::job_watcher::JobState;
use crate::data::run_matrix::{CellOutcome, Os, ParityState, Role, RunSummary, StageProgress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Panel {
    StageGrid,
    VmStatus,
    Parity,
    Log,
    Jobs,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Page {
    Overview,
    Run,
}

#[derive(Debug, Clone)]
pub struct StageGroup {
    pub name: &'static str,
    pub stages: Vec<String>,
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

    pub focused_panel: Panel,
    pub page: Page,
    pub stage_cursor: usize,
    pub show_help: bool,
    pub show_stage_detail: bool,
    pub stage_detail_scroll: usize,
    pub should_quit: bool,

    pub orchestrator_pgid: Option<u32>,
    pub stop_after_current: bool,

    active_stage_start: Option<std::time::Instant>,
    last_vm_probe: Option<std::time::Instant>,
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

        let vm_role_overrides = default_vm_role_overrides(&config);
        let recent_runs =
            crate::data::run_matrix::load_recent_runs(&repo_root, 3).unwrap_or_default();

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
            focused_panel: Panel::VmStatus,
            page: Page::Overview,
            stage_cursor: 0,
            show_help: false,
            show_stage_detail: false,
            stage_detail_scroll: 0,
            should_quit: false,
            orchestrator_pgid: None,
            stop_after_current: false,
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

    pub fn selected_stage_outcome(
        &self,
    ) -> Option<&crate::data::stage_reader::StageOutcome> {
        let stages = self.planned_stages();
        let stage = stages.get(self.stage_cursor)?;
        self.stage_outcomes.iter().find(|o| &o.stage == stage)
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

    fn stage_selected_for_current_target(&self, stage: &str) -> bool {
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
        stage == "linux_live_suite" && !self.config.skip_linux_live_suite
    }

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
        let mut live_lab = Vec::new();

        if self.config.wants_macos() {
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
        }
        if self.config.wants_macos() {
            live_lab.extend(
                macos_live_lab_catalog()
                    .iter()
                    .map(|stage| (*stage).to_owned()),
            );
        }

        if self.config.wants_windows() {
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
        }
        if self.config.wants_windows() {
            live_lab.extend(
                windows_live_lab_catalog()
                    .iter()
                    .map(|stage| (*stage).to_owned()),
            );
        }
        if !self.config.skip_linux_live_suite {
            live_lab.push("linux_live_suite".to_owned());
        }

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
                if let Some(args) = &job.request_args {
                    let mut config = self.config.clone();
                    config.apply_request_args(args);
                    self.config = config;
                }
                let report_dir = self.repo_root.join(&job.report_dir);
                if let Ok(result) = crate::data::stage_reader::read_orchestrate_result(&report_dir)
                {
                    self.stage_outcomes = result.outcomes;
                }
                if let Ok(active) = crate::data::stage_reader::infer_active_stage(&report_dir) {
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
                    self.active_stage = None;
                    self.active_stage_start = None;
                    self.orchestrator_pgid = None;
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
        if let Ok(runs) = crate::data::run_matrix::load_recent_runs(&self.repo_root, 3) {
            self.recent_runs = runs;
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
            KeyCode::Char('1') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
            }
            KeyCode::Char('2') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::Parity;
            }
            KeyCode::Char('3') => {
                self.page = Page::Run;
                self.focused_panel = Panel::StageGrid;
            }
            KeyCode::Char('4') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Log;
            }
            KeyCode::Char('5') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Jobs;
            }

            // Single letter shortcuts. Accept plain, Shift, or Ctrl variants.
            KeyCode::Char(_) if plain_char == Some('l') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Log;
            }
            KeyCode::Char(_) if plain_char == Some('p') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::Parity;
            }
            KeyCode::Char(_) if plain_char == Some('v') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
            }
            KeyCode::Char(_) if plain_char == Some('j') => {
                self.page = Page::Run;
                self.focused_panel = Panel::Jobs;
            }
            KeyCode::Char(_) if plain_char == Some('a') => {
                if self.roles_locked_by_active_lab() {
                    self.log_lines =
                        vec!["VM roles locked to active live lab; cannot auto-reassign".into()];
                    return;
                }
                self.auto_select_next_target();
            }
            KeyCode::Char(_) if plain_char == Some('c') => {
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
                self.last_vm_probe = None;
                self.log_lines = vec!["fetching VM commits from inventory SSH targets".into()];
            }
            KeyCode::Char(_) if plain_char == Some('r') => {
                self.last_vm_probe = None;
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
                Panel::StageGrid if self.stage_cursor > 0 => {
                    self.stage_cursor -= 1;
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
                _ => {}
            },
            KeyCode::Down => match self.focused_panel {
                Panel::StageGrid => {
                    let max = self.planned_stages().len().saturating_sub(1);
                    self.stage_cursor = (self.stage_cursor + 1).min(max);
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
                self.page = Page::Overview;
                self.focused_panel = Panel::VmStatus;
            }
        }
    }

    fn toggle_selected_stage(&mut self) {
        if self.active_job.is_some() {
            return;
        }
        let Some(stage) = self.planned_stages().get(self.stage_cursor).cloned() else {
            return;
        };
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
        match crate::control::launcher::spawn_orchestrator(&repo_root, &config) {
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

    fn config_for_role_display(&self) -> MonitorConfig {
        let mut config = self.config.clone();
        if let Some(job) = &self.active_job
            && let Some(args) = &job.request_args
        {
            config.apply_request_args(args);
        }
        config
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
                    self.focused_panel = Panel::VmStatus;
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

    fn save_config_best_effort(&self) {
        if let Err(e) = self.config.save(&self.repo_root) {
            tracing::error!(%e, "failed to save monitor config");
        }
    }
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
        let src_dir = entry
            .get("rustynet_src_dir")
            .and_then(|d| d.as_str())
            .unwrap_or("")
            .to_string();
        if !ip.is_empty() {
            tasks.push(tokio::spawn(async move {
                crate::data::vm_prober::probe_vm(&alias, &ip, &utm_name, &ssh_user, &src_dir).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
            git_commit: Some("abc1234".into()),
        };

        app.assign_vm_role(&vm, "exit");

        assert_eq!(app.config.macos_vm, "macos-utm-1");
        assert!(app.config.macos_promote_exit);
        assert_eq!(app.config.rebuild_nodes, "macos-utm-1");
        assert_eq!(app.role_for_vm("macos-utm-1"), "exit");
    }

    #[test]
    fn c_key_forces_vm_commit_probe() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        app.last_vm_probe = Some(std::time::Instant::now());
        app.page = Page::Run;
        app.focused_panel = Panel::Log;

        app.handle_key(KeyCode::Char('c'), KeyModifiers::empty());

        assert!(app.last_vm_probe.is_none());
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::VmStatus);
        assert_eq!(
            app.log_lines,
            vec!["fetching VM commits from inventory SSH targets".to_owned()]
        );
    }

    #[test]
    fn assigning_linux_non_exit_role_is_not_displayed_as_exit() {
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");
        let vm = crate::data::vm_prober::VmStatus {
            alias: "debian-headless-2".into(),
            ip: "192.168.0.201".into(),
            platform: "linux".into(),
            ssh_ok: true,
            git_commit: Some("abc1234".into()),
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
            git_commit: Some("abc1234".into()),
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
            git_commit: Some("abc1234".into()),
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
            git_commit: Some("abc1234".into()),
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
            git_commit: Some("abc1234".into()),
        });

        app.auto_select_next_target();

        assert_eq!(app.config.area, "macOS exit");
        assert_eq!(app.config.macos_vm, "macos-utm-1");
        assert!(app.config.macos_promote_exit);
        assert_eq!(app.config.rebuild_nodes, "macos-utm-1");
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
            git_commit: Some("abc1234".into()),
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
        assert!(
            !app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
    }

    #[test]
    fn default_macos_target_hides_linux_suite_and_keeps_only_macos_bootstrap() {
        let app = App::new(PathBuf::from("/tmp")).expect("app");

        assert!(app.config.skip_linux_live_suite);
        assert!(
            !app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
        assert!(
            app.planned_stages()
                .contains(&"bootstrap_macos_host".to_owned())
        );
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
        assert!(
            !app.planned_stages()
                .contains(&"bootstrap_windows_host".to_owned())
        );
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
            !app.planned_stages()
                .contains(&"linux_live_suite".to_owned())
        );
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
        let mut app = App::new(PathBuf::from("/tmp")).expect("app");

        app.page = Page::Run;
        app.handle_key(KeyCode::Char('1'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::VmStatus);

        app.handle_key(KeyCode::Char('2'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Overview);
        assert_eq!(app.focused_panel, Panel::Parity);

        app.handle_key(KeyCode::Char('3'), KeyModifiers::NONE);
        assert_eq!(app.page, Page::Run);
        assert_eq!(app.focused_panel, Panel::StageGrid);
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

        assert_eq!(labels[2], ("LAB", "18m".to_owned()));
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
}
