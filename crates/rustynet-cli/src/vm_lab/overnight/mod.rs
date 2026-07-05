//! Overnight Autonomous Verified-Plane March — driver.
//!
//! Marches the verified-working plane (every role × every OS) toward green,
//! unattended. This module is the thin **driver**: it owns the frontier
//! backlog + scheduler + safety rails and spawns one fresh agent per work-unit.
//! It contains no LLM client — the engineering happens inside the per-unit
//! agent (see `agent.rs` / `executor.rs`).
//!
//! Design: `documents/operations/active/OvernightAutonomousBugHuntProposal_2026-06-08.md`.
//!
//! `--dry-run` (planning) is fully implemented and side-effect-free. The live
//! path (`run_loop` + `LiveExecutor`) is implemented and type-checked but is
//! only reached when invoked without `--dry-run`; the unit tests exercise the
//! loop logic through a mock executor and never spawn an agent or run the lab.

pub mod agent;
pub mod backlog;
pub mod executor;
pub mod manifest;
pub mod safety;
pub mod scheduler;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::vm_lab::VmGuestPlatform;

use backlog::{FrontierBacklog, PriorVerdicts};
use executor::{LiveExecutor, LiveExecutorConfig, LoopConfig, SystemClock, UnitContext, run_loop};
use manifest::RunManifest;
use safety::{assert_safe_target_branch, overnight_branch_name};
use scheduler::{Rotation, SchedulerConfig, dry_run_plan};

/// The three desktop platforms the live lab covers, in canonical order.
const DESKTOP_PLATFORMS: &[VmGuestPlatform] = &[
    VmGuestPlatform::Linux,
    VmGuestPlatform::Macos,
    VmGuestPlatform::Windows,
];

/// Default overnight run length (10 hours).
pub const DEFAULT_MAX_DURATION_SECS: u64 = 36_000;
/// Default per-cell attempt budget.
pub const DEFAULT_MAX_ATTEMPTS_PER_CELL: u32 = 3;
/// Default per-work-unit agent timeout (1 hour).
pub const DEFAULT_AGENT_TIMEOUT_SECS: u64 = 3_600;

/// Default tool allowlist for a spawned overnight agent — the core edit/inspect
/// tools plus the three Rustynet MCP servers its cell prompt drives (gate
/// runner, lab-state, repo-context). A conservative, functional starting set;
/// the security-crate write guard + branch guard (safety.rs) still bound what a
/// committed diff may touch regardless of this list.
fn default_overnight_allowed_tools() -> Vec<String> {
    [
        "Bash",
        "Read",
        "Edit",
        "Write",
        "Grep",
        "Glob",
        "mcp__rustynet-gate-runner",
        "mcp__rustynet-lab-state",
        "mcp__rustynet-repo-context",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

/// CLI configuration for `ops vm-lab-overnight`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VmLabOvernightConfig {
    pub inventory_path: PathBuf,
    pub ssh_identity_file: PathBuf,
    pub known_hosts_path: Option<PathBuf>,
    pub branch_prefix: String,
    /// Persisted frontier backlog (resume across nights when present).
    pub backlog_path: Option<PathBuf>,
    pub max_duration_secs: u64,
    pub max_attempts_per_cell: u32,
    /// `breadth-first` (default) | `deep-first`.
    pub rotation_raw: Option<String>,
    pub auto_merge_safe_cells: bool,
    pub agent_cmd: String,
    pub agent_timeout_secs: u64,
    /// Optional `os:role=status,...` seed of known prior verdicts.
    pub seed_status: Option<String>,
    pub dry_run: bool,
}

/// Resolve the lab's platforms: the desktop platforms present in the inventory,
/// or all three if the inventory is unreadable or names none.
fn resolve_platforms(inventory_path: &Path) -> Vec<VmGuestPlatform> {
    let present: Vec<VmGuestPlatform> = match super::load_inventory(inventory_path) {
        Ok(entries) => entries
            .iter()
            .map(|e| e.platform_profile().platform)
            .collect(),
        Err(_) => Vec::new(),
    };
    let filtered: Vec<VmGuestPlatform> = DESKTOP_PLATFORMS
        .iter()
        .copied()
        .filter(|p| present.contains(p))
        .collect();
    if filtered.is_empty() {
        DESKTOP_PLATFORMS.to_vec()
    } else {
        filtered
    }
}

/// Build a fresh backlog (seeded with any prior verdicts), or resume a
/// persisted one if `backlog_path` exists.
fn load_or_build_backlog(
    config: &VmLabOvernightConfig,
    platforms: &[VmGuestPlatform],
    priors: &PriorVerdicts,
) -> Result<FrontierBacklog, String> {
    if let Some(path) = config.backlog_path.as_ref().filter(|p| p.exists()) {
        let raw = std::fs::read_to_string(path)
            .map_err(|e| format!("read backlog {}: {e}", path.display()))?;
        return FrontierBacklog::from_json_str(&raw);
    }
    // Fresh build. A fresh backlog types supported cells as `unknown` and
    // unsupported-but-assignable cells as `unbuilt`, overridden by any
    // operator-supplied `--seed-status` verdicts.
    Ok(FrontierBacklog::build(platforms, priors))
}

fn scheduler_config(config: &VmLabOvernightConfig) -> Result<SchedulerConfig, String> {
    let rotation = match &config.rotation_raw {
        Some(raw) => Rotation::parse(raw)?,
        None => Rotation::BreadthFirst,
    };
    Ok(SchedulerConfig {
        max_attempts_per_cell: config.max_attempts_per_cell,
        rotation,
    })
}

fn render_dry_run(
    config: &VmLabOvernightConfig,
    platforms: &[VmGuestPlatform],
    backlog: &FrontierBacklog,
    sched: &SchedulerConfig,
) -> String {
    let plan = dry_run_plan(backlog, sched);
    let platform_list = platforms
        .iter()
        .map(|p| p.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let mut out = String::new();
    out.push_str(
        "=== overnight verified-plane march — DRY RUN (plan only, nothing executed) ===\n",
    );
    out.push_str(&format!("platforms:        {platform_list}\n"));
    out.push_str(&format!("rotation:         {}\n", sched.rotation.as_str()));
    out.push_str(&format!(
        "max attempts/cell:{}\n",
        sched.max_attempts_per_cell
    ));
    out.push_str(&format!(
        "max duration:     {}s\n",
        config.max_duration_secs
    ));
    out.push_str(&format!(
        "agent:            {} (timeout {}s)\n",
        config.agent_cmd, config.agent_timeout_secs
    ));
    out.push_str(&format!(
        "auto-merge safe:  {}\n",
        config.auto_merge_safe_cells
    ));
    out.push('\n');
    out.push_str(&backlog.summary());
    out.push('\n');
    out.push_str(&format!(
        "schedule (pessimistic projection — assumes every attempt fails its budget): {} work-units\n",
        plan.len()
    ));
    for (i, &idx) in plan.iter().enumerate() {
        let cell = &backlog.cells[idx];
        out.push_str(&format!(
            "  {:>3}. {:<18} [{}] {}\n",
            i + 1,
            cell.id(),
            cell.state.as_str(),
            cell.stage_hint
        ));
    }
    out.push_str("\nblind_exit cells are permanently parked (irreversible) and never scheduled.\n");
    out
}

fn run_token() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", std::process::id(), nanos)
}

/// Entry point for `ops vm-lab-overnight`.
pub fn execute_ops_vm_lab_overnight(config: VmLabOvernightConfig) -> Result<String, String> {
    let platforms = resolve_platforms(&config.inventory_path);
    let sched = scheduler_config(&config)?;
    let priors = match &config.seed_status {
        Some(raw) => backlog::parse_seed_status(raw)?,
        None => PriorVerdicts::new(),
    };
    let mut backlog = load_or_build_backlog(&config, &platforms, &priors)?;

    if config.dry_run {
        return Ok(render_dry_run(&config, &platforms, &backlog, &sched));
    }

    // -- live path (unattended execution). Reachable but intentionally not run
    //    during development verification — running it IS running the loop. --
    let token = run_token();
    let branch = overnight_branch_name(&config.branch_prefix, &token, &token);
    assert_safe_target_branch(&branch)?;

    let cli_binary = std::env::current_exe()
        .map_err(|e| format!("resolve current exe for orchestrate oracle: {e}"))?;
    let report_root = super::workspace_root_path()
        .join("artifacts/overnight")
        .join(&token);

    // Point the spawned agent at the repo's MCP config (so its prompt's
    // gate-runner / lab-state / repo-context calls resolve) and give it a
    // working default tool allowlist + the hard per-agent timeout. Previously
    // these were empty/dead, so the agent launched with no MCP + no timeout.
    let mcp_config = {
        let p = super::workspace_root_path().join("mcp/mcp.json");
        if p.is_file() {
            p.to_string_lossy().into_owned()
        } else {
            String::new()
        }
    };
    let exec_cfg = LiveExecutorConfig {
        cli_binary,
        inventory_path: config.inventory_path.clone(),
        ssh_identity_file: config.ssh_identity_file.clone(),
        known_hosts_path: config.known_hosts_path.clone(),
        report_root: report_root.clone(),
        agent_cmd: config.agent_cmd.clone(),
        mcp_config_path: mcp_config,
        allowed_tools: default_overnight_allowed_tools(),
        agent_timeout_secs: config.agent_timeout_secs,
    };
    let executor = LiveExecutor::new(exec_cfg);
    let ctx = UnitContext {
        branch: branch.clone(),
        journal_pointer: "write_loop_note (rustynet-lab-state MCP)".to_owned(),
    };
    let loop_cfg = LoopConfig {
        scheduler: sched,
        max_duration_secs: config.max_duration_secs,
    };

    let clock = SystemClock::started_now();
    let started_at = token.clone();
    let summary = run_loop(&mut backlog, &loop_cfg, &ctx, &executor, &clock)?;

    let manifest = RunManifest {
        started_at,
        ended_at: Some(run_token()),
        branch: branch.clone(),
        run_id: token.clone(),
        units_run: summary.units_run,
        cells_verified_this_run: summary.verified_this_run,
        cells_escalated: summary.escalations.len() as u32,
        counts: backlog.counts(),
        running: false,
    };
    manifest::write_run_artifacts(&report_root, &manifest, &backlog, &summary.escalations)?;

    if let Some(path) = &config.backlog_path {
        std::fs::write(path, backlog.to_json_string()?)
            .map_err(|e| format!("persist backlog {}: {e}", path.display()))?;
    }

    Ok(format!(
        "overnight run {token} on {branch}: {} units, {} verified this run, {} escalated; \
         artifacts at {}",
        summary.units_run,
        summary.verified_this_run,
        summary.escalations.len(),
        report_root.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dry_config(inventory: PathBuf) -> VmLabOvernightConfig {
        VmLabOvernightConfig {
            inventory_path: inventory,
            ssh_identity_file: PathBuf::from("/dev/null"),
            known_hosts_path: None,
            branch_prefix: "overnight".to_owned(),
            backlog_path: None,
            max_duration_secs: DEFAULT_MAX_DURATION_SECS,
            max_attempts_per_cell: DEFAULT_MAX_ATTEMPTS_PER_CELL,
            rotation_raw: None,
            auto_merge_safe_cells: false,
            agent_cmd: "claude".to_owned(),
            agent_timeout_secs: DEFAULT_AGENT_TIMEOUT_SECS,
            seed_status: None,
            dry_run: true,
        }
    }

    #[test]
    fn dry_run_falls_back_to_three_platforms_when_inventory_missing() {
        // Non-existent inventory -> resolve_platforms falls back to all three.
        let cfg = dry_config(PathBuf::from("/nonexistent/inventory-xyz.json"));
        let out = execute_ops_vm_lab_overnight(cfg).expect("dry run ok");
        assert!(out.contains("DRY RUN"));
        assert!(out.contains("linux, macos, windows"));
        assert!(out.contains("frontier:"));
        // The frontier includes the Windows relay unbuilt cell.
        assert!(out.contains("windows/relay"));
    }

    #[test]
    fn dry_run_never_schedules_blind_exit() {
        let cfg = dry_config(PathBuf::from("/nonexistent/inventory-xyz.json"));
        let out = execute_ops_vm_lab_overnight(cfg).expect("dry run ok");
        // blind_exit appears in the backlog summary as parked, but the schedule
        // section must not list it. Check no schedule line contains blind_exit.
        for line in out.lines() {
            if line.trim_start().starts_with(|c: char| c.is_ascii_digit())
                && line.contains('.')
                && line.contains('[')
            {
                assert!(
                    !line.contains("blind_exit"),
                    "blind_exit must never be scheduled: {line}"
                );
            }
        }
        assert!(out.contains("permanently parked"));
    }

    #[test]
    fn dry_run_rejects_bad_rotation() {
        let mut cfg = dry_config(PathBuf::from("/nonexistent/x.json"));
        cfg.rotation_raw = Some("sideways".to_owned());
        assert!(execute_ops_vm_lab_overnight(cfg).is_err());
    }

    #[test]
    fn dry_run_resumes_from_persisted_backlog() {
        // Persist a backlog where windows/relay is already verified; the dry-run
        // must reflect that (it should no longer be the top unbuilt frontier).
        let tmp = tempfile::tempdir().expect("tempdir");
        let backlog_path = tmp.path().join("backlog.json");

        let mut b = FrontierBacklog::build(DESKTOP_PLATFORMS, &PriorVerdicts::new());
        for i in 0..b.cells.len() {
            b.mark_verified(i); // everything green -> nothing to schedule
        }
        std::fs::write(&backlog_path, b.to_json_string().unwrap()).unwrap();

        let mut cfg = dry_config(PathBuf::from("/nonexistent/x.json"));
        cfg.backlog_path = Some(backlog_path);
        let out = execute_ops_vm_lab_overnight(cfg).expect("dry run ok");
        // Frontier exhausted -> zero work-units scheduled.
        assert!(out.contains("0 work-units"));
    }

    #[test]
    fn dry_run_reports_config_knobs() {
        let mut cfg = dry_config(PathBuf::from("/nonexistent/x.json"));
        cfg.auto_merge_safe_cells = true;
        cfg.rotation_raw = Some("deep-first".to_owned());
        let out = execute_ops_vm_lab_overnight(cfg).expect("dry run ok");
        assert!(out.contains("deep-first"));
        assert!(out.contains("auto-merge safe:  true"));
    }
}
