//! The per-work-unit state machine (`drive_unit`), the loop control flow
//! (`run_loop`), and the real `LiveExecutor`.
//!
//! The control plane (`drive_unit` / `run_loop`) is generic over the
//! [`WorkUnitExecutor`] trait so it is fully unit-tested with a mock, proving
//! the loop logic WITHOUT spawning agents or touching the live lab.
//! `LiveExecutor` is the real implementation: an argv-only subprocess spawn,
//! git for commit/diff/revert, and the existing orchestrate CLI as the oracle.
//! It is compiled and type-checked but never invoked by the tests.

use std::fs;
use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::overnight::agent::{AgentSpawnSpec, build_agent_argv, render_unit_prompt};
use crate::vm_lab::overnight::backlog::{Cell, CellState, FrontierBacklog, MarchRole};
use crate::vm_lab::overnight::manifest::Checkpoint;
use crate::vm_lab::overnight::safety::{
    assert_safe_target_branch, classify_touched_paths, revert_to_clean_argv,
};
use crate::vm_lab::overnight::scheduler::{SchedulerConfig, next_actionable};
use crate::vm_lab::{VmGuestPlatform, VmInventoryEntry};

/// The live-lab verdict for a cell after an agent attempt. The oracle is
/// authoritative — it overrides whatever the agent claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OracleVerdict {
    /// Stage green on the real VM.
    Green,
    /// Stage advanced (more substages passing) but not yet green. The
    /// conservative `LiveExecutor` does not emit this yet (substage-level
    /// diffing of orchestrate reports is a documented future refinement — it
    /// currently maps exit-code to Green/NoProgress); `drive_unit` handles it
    /// and the mock executor exercises the partial-credit path in tests.
    #[allow(dead_code)]
    Advanced { from: String, to: String },
    /// No measurable forward movement.
    NoProgress,
}

/// What the agent reported doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentOutcome {
    /// Did the agent land a commit on the overnight branch?
    pub committed: bool,
    /// Repo-relative paths the agent touched (for the security denylist).
    pub touched_paths: Vec<String>,
    /// The journal note the agent wrote (recorded into the run log).
    pub journal_note: String,
}

/// Outcome of one work-unit, after the oracle and the safety gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnitResult {
    Verified,
    Advanced {
        from: String,
        to: String,
    },
    NoProgress,
    /// Green/committed but the diff touched a security-sensitive crate — the
    /// commit was reverted and the cell escalated for adversarial review.
    NeedsReview,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecondReviewVerdict {
    Safe { rationale: String },
    Unsafe { rationale: String },
}

impl SecondReviewVerdict {
    fn is_safe(&self) -> bool {
        matches!(self, SecondReviewVerdict::Safe { .. })
    }

    fn unsafe_with(rationale: impl Into<String>) -> Self {
        SecondReviewVerdict::Unsafe {
            rationale: rationale.into(),
        }
    }
}

pub fn parse_second_review_verdict(raw: &str) -> SecondReviewVerdict {
    let value = match serde_json::from_str::<serde_json::Value>(raw) {
        Ok(value) => value,
        Err(err) => {
            return SecondReviewVerdict::unsafe_with(format!(
                "reviewer verdict was not valid JSON: {err}"
            ));
        }
    };
    let verdict = value
        .get("verdict")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .map(str::to_ascii_lowercase);
    let rationale = value
        .get("rationale")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("missing rationale")
        .to_owned();
    match verdict.as_deref() {
        Some("safe") => SecondReviewVerdict::Safe { rationale },
        Some("unsafe") => SecondReviewVerdict::Unsafe { rationale },
        Some(other) => SecondReviewVerdict::unsafe_with(format!("unknown verdict '{other}'")),
        None => SecondReviewVerdict::unsafe_with("missing verdict"),
    }
}

/// Per-unit context shared with the agent prompt.
#[derive(Debug, Clone)]
pub struct UnitContext {
    pub branch: String,
    pub journal_pointer: String,
}

/// The seam the control plane drives. `LiveExecutor` is the real impl; tests
/// use a mock.
pub trait WorkUnitExecutor {
    /// Spawn the agent against this cell with this prompt; report what it did.
    fn run_agent(&self, cell: &Cell, prompt: &str) -> Result<AgentOutcome, String>;
    /// Re-run the cell's stage on the live lab and return the verdict.
    fn verify_cell(&self, cell: &Cell) -> Result<OracleVerdict, String>;
    /// Independent adversarial review of the committed diff. Must fail closed.
    fn second_review(&self, cell: &Cell, outcome: &AgentOutcome) -> SecondReviewVerdict;
    /// Restore a clean tree (discard any uncommitted residue).
    fn revert_to_clean(&self) -> Result<(), String>;
}

/// Drive exactly one work-unit and update the backlog. The decision matrix:
///
/// - committed + security-sensitive diff -> revert the commit, escalate (NeedsReview)
/// - oracle Green + committed + safe     -> Verified (keep the commit)
/// - oracle Green + not committed        -> fail closed: count an attempt (nothing landed)
/// - oracle Advanced + committed         -> record partial progress (durable)
/// - oracle Advanced + not committed     -> count an attempt (progress not durable)
/// - oracle NoProgress                   -> count an attempt
///
/// Invariant: the tree is clean on return — if nothing was committed, residue
/// is reverted.
pub fn drive_unit(
    backlog: &mut FrontierBacklog,
    idx: usize,
    ctx: &UnitContext,
    executor: &dyn WorkUnitExecutor,
    cfg: &SchedulerConfig,
    auto_merge_safe_cells: bool,
) -> Result<UnitResult, String> {
    let cell = backlog
        .cells
        .get(idx)
        .ok_or_else(|| format!("drive_unit: cell index {idx} out of range"))?
        .clone();

    let prompt = render_unit_prompt(&cell, backlog, &ctx.branch, &ctx.journal_pointer);
    let outcome = executor.run_agent(&cell, &prompt)?;
    // The oracle is authoritative and is consulted regardless of the agent's claim.
    let verdict = executor.verify_cell(&cell)?;
    let safety = classify_touched_paths(&outcome.touched_paths);

    // Security gate first: a committed security-sensitive diff is never kept
    // unreviewed, even if the oracle is green.
    if outcome.committed && !safety.is_safe() {
        executor.revert_to_clean()?;
        let reason = "security-sensitive diff requires adversarial review";
        log_blocked_cell(&cell, reason);
        backlog.park(idx, reason);
        return Ok(UnitResult::NeedsReview);
    }

    let result = match verdict {
        OracleVerdict::Green => {
            if outcome.committed {
                if auto_merge_safe_cells
                    && let Err(reason) = auto_merge_safe_gate(&cell, ctx, executor, &outcome)
                {
                    executor.revert_to_clean()?;
                    log_blocked_cell(&cell, &reason);
                    backlog.park(idx, &reason);
                    return Ok(UnitResult::NeedsReview);
                }
                backlog.mark_verified(idx);
                UnitResult::Verified
            } else {
                // Green but nothing landed — fail closed, do not mark verified.
                backlog.attempt_failed(idx, cfg.max_attempts_per_cell);
                UnitResult::NoProgress
            }
        }
        OracleVerdict::Advanced { from, to } => {
            if outcome.committed {
                backlog.record_progress(idx, &from, &to);
                UnitResult::Advanced { from, to }
            } else {
                backlog.attempt_failed(idx, cfg.max_attempts_per_cell);
                UnitResult::NoProgress
            }
        }
        OracleVerdict::NoProgress => {
            backlog.attempt_failed(idx, cfg.max_attempts_per_cell);
            if outcome.committed {
                executor.revert_to_clean()?;
            }
            UnitResult::NoProgress
        }
    };

    // Clean-tree invariant: discard any uncommitted residue.
    if !outcome.committed {
        executor.revert_to_clean()?;
    }
    Ok(result)
}

fn auto_merge_safe_gate(
    cell: &Cell,
    ctx: &UnitContext,
    executor: &dyn WorkUnitExecutor,
    outcome: &AgentOutcome,
) -> Result<(), String> {
    assert_safe_target_branch(&ctx.branch)?;
    if cell.role == MarchRole::BlindExit {
        return Err("blind_exit cells are irreversible and never auto-merged".to_owned());
    }
    let verdict = executor.second_review(cell, outcome);
    if !verdict.is_safe() {
        return Err(match verdict {
            SecondReviewVerdict::Safe { .. } => "second review invariant failure".to_owned(),
            SecondReviewVerdict::Unsafe { rationale } => {
                format!("second review unsafe: {rationale}")
            }
        });
    }
    Ok(())
}

fn log_blocked_cell(cell: &Cell, reason: &str) {
    eprintln!("[overnight] blocked {}: {reason}", cell.id());
}

/// Abstract clock so the time budget is testable without sleeping.
pub trait Clock {
    fn elapsed_secs(&self) -> u64;
}

/// Real wall-clock.
pub struct SystemClock {
    start: Instant,
}

impl SystemClock {
    pub fn started_now() -> Self {
        SystemClock {
            start: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn elapsed_secs(&self) -> u64 {
        self.start.elapsed().as_secs()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoopConfig {
    pub scheduler: SchedulerConfig,
    pub max_duration_secs: u64,
    pub auto_merge_safe_cells: bool,
}

/// Summary of one overnight run (feeds the manifest).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunSummary {
    pub units_run: u32,
    pub verified_this_run: u32,
    pub escalations: Vec<Checkpoint>,
}

/// The overnight loop: pick the highest-value actionable cell, drive one unit,
/// repeat until the frontier is exhausted or the time budget is spent.
pub fn run_loop(
    backlog: &mut FrontierBacklog,
    cfg: &LoopConfig,
    ctx: &UnitContext,
    executor: &dyn WorkUnitExecutor,
    clock: &dyn Clock,
) -> Result<RunSummary, String> {
    let mut summary = RunSummary {
        units_run: 0,
        verified_this_run: 0,
        escalations: Vec::new(),
    };

    while clock.elapsed_secs() < cfg.max_duration_secs {
        let idx = match next_actionable(backlog, &cfg.scheduler) {
            Some(idx) => idx,
            None => break, // frontier exhausted
        };

        let was_parked = backlog.cells[idx].state == CellState::Parked;
        let result = drive_unit(
            backlog,
            idx,
            ctx,
            executor,
            &cfg.scheduler,
            cfg.auto_merge_safe_cells,
        )?;
        summary.units_run += 1;

        match &result {
            UnitResult::Verified => summary.verified_this_run += 1,
            UnitResult::NeedsReview => {
                summary.escalations.push(Checkpoint::from_cell(
                    &backlog.cells[idx],
                    "needs adversarial review",
                ));
            }
            UnitResult::Advanced { .. } | UnitResult::NoProgress => {
                // A cell that just transitioned into Parked (budget exhausted)
                // is an escalation for morning review.
                if !was_parked && backlog.cells[idx].state == CellState::Parked {
                    let reason = backlog.cells[idx]
                        .parked_reason
                        .clone()
                        .unwrap_or_else(|| "parked".to_owned());
                    summary
                        .escalations
                        .push(Checkpoint::from_cell(&backlog.cells[idx], &reason));
                }
            }
        }
    }

    Ok(summary)
}

// ---------------------------------------------------------------------------
// LiveExecutor: real implementation. Compiled and type-checked; not exercised
// by tests (running it IS running the overnight loop).
// ---------------------------------------------------------------------------

/// Configuration the real executor needs to spawn agents and run the oracle.
#[derive(Debug, Clone)]
pub struct LiveExecutorConfig {
    /// `rustynet-cli` binary used to invoke the orchestrate oracle (usually the
    /// current exe).
    pub cli_binary: PathBuf,
    pub inventory_path: PathBuf,
    pub ssh_identity_file: PathBuf,
    pub known_hosts_path: Option<PathBuf>,
    /// Where per-verify orchestrate reports are written.
    pub report_root: PathBuf,
    /// Headless agent binary (default `claude`).
    pub agent_cmd: String,
    pub mcp_config_path: String,
    pub allowed_tools: Vec<String>,
    /// Hard wall-clock cap per spawned agent. On expiry the agent's whole
    /// process group is killed (so a mid-orchestrate lab child dies too) and the
    /// cell is treated as a failed attempt — a wedged agent must never hang the
    /// whole multi-hour run. `0` disables the cap (test/interactive use only).
    pub agent_timeout_secs: u64,
}

pub struct LiveExecutor {
    cfg: LiveExecutorConfig,
}

impl LiveExecutor {
    pub fn new(cfg: LiveExecutorConfig) -> Self {
        LiveExecutor { cfg }
    }

    fn current_head() -> Result<String, String> {
        let out = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .map_err(|e| format!("git rev-parse failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git rev-parse HEAD exited {}",
                out.status.code().unwrap_or(-1)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
    }

    fn verify_argv_for_cell(&self, cell: &Cell) -> Result<Vec<String>, String> {
        let inventory = super::super::load_inventory(self.cfg.inventory_path.as_path())?;
        let report_dir = self
            .cfg
            .report_root
            .join(format!("verify_{}", cell.id().replace('/', "_")));
        orchestrate_argv_for_cell(
            self.cfg.cli_binary.as_path(),
            self.cfg.inventory_path.as_path(),
            self.cfg.ssh_identity_file.as_path(),
            self.cfg.known_hosts_path.as_deref(),
            report_dir.as_path(),
            &inventory,
            cell,
        )
    }

    fn current_diff_for_review(cell: &Cell) -> Result<String, String> {
        let out = Command::new("git")
            .args(["show", "--format=fuller", "--stat", "--patch", "HEAD"])
            .output()
            .map_err(|e| format!("git show for second review failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "git show for second review of {} exited {}",
                cell.id(),
                out.status.code().unwrap_or(-1)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run_second_review_agent(&self, cell: &Cell, diff: &str) -> SecondReviewVerdict {
        let prompt = format!(
            "You are the independent adversarial second reviewer for Rustynet overnight automation.\n\
Refute this change if possible. Find any correctness, security, test, scope, or live-lab reason it is unsafe.\n\
Return ONLY JSON: {{\"verdict\":\"safe|unsafe\",\"rationale\":\"one concise reason\"}}.\n\
Cell: {}\n\nDiff:\n{}",
            cell.id(),
            diff
        );
        let spec = AgentSpawnSpec {
            agent_cmd: self.cfg.agent_cmd.clone(),
            mcp_config_path: self.cfg.mcp_config_path.clone(),
            allowed_tools: self.cfg.allowed_tools.clone(),
            prompt,
        };
        let argv = build_agent_argv(&spec);
        let Some((program, args)) = argv.split_first() else {
            return SecondReviewVerdict::unsafe_with("empty reviewer argv");
        };
        match spawn_capture_with_timeout(program, args, self.cfg.agent_timeout_secs) {
            Ok(AgentCapturedStatus::Exited {
                status,
                stdout,
                stderr,
            }) => {
                if !status.success() {
                    return SecondReviewVerdict::unsafe_with(format!(
                        "reviewer exited {}: {}",
                        status.code().unwrap_or(-1),
                        stderr.trim()
                    ));
                }
                parse_second_review_verdict(stdout.as_str())
            }
            Ok(AgentCapturedStatus::TimedOut) => SecondReviewVerdict::unsafe_with(format!(
                "reviewer timed out after {}s",
                self.cfg.agent_timeout_secs
            )),
            Err(err) => SecondReviewVerdict::unsafe_with(format!("reviewer spawn failed: {err}")),
        }
    }
}

fn march_role_to_node_role(role: MarchRole) -> Option<NodeRole> {
    match role {
        MarchRole::Client => Some(NodeRole::Client),
        MarchRole::Exit => Some(NodeRole::Exit),
        MarchRole::Relay => Some(NodeRole::Relay),
        MarchRole::Anchor => Some(NodeRole::Anchor),
        MarchRole::Admin => Some(NodeRole::Admin),
        MarchRole::BlindExit => Some(NodeRole::BlindExit),
    }
}

fn role_matches_entry(entry: &VmInventoryEntry, platform: VmGuestPlatform, role: NodeRole) -> bool {
    if entry.platform_profile().platform != platform {
        return false;
    }
    let role_name = role.as_str();
    if let Some(lab_role) = entry.lab_role.as_deref() {
        let normalized = lab_role.trim().to_ascii_lowercase().replace('-', "_");
        if normalized == role_name
            || normalized == format!("{}_{}", platform.as_str(), role_name)
            || (role == NodeRole::Client && normalized.ends_with("_client"))
        {
            return true;
        }
    }
    match role {
        NodeRole::Exit => entry.exit_capable.unwrap_or(false),
        NodeRole::Relay => entry.relay_capable.unwrap_or(false),
        _ => false,
    }
}

fn resolve_alias_for_role(
    inventory: &[VmInventoryEntry],
    platform: VmGuestPlatform,
    role: NodeRole,
) -> Result<String, String> {
    let mut matches = inventory
        .iter()
        .filter(|entry| role_matches_entry(entry, platform, role.clone()))
        .map(|entry| entry.alias.clone())
        .collect::<Vec<_>>();
    matches.sort();
    matches.dedup();
    match matches.as_slice() {
        [alias] => Ok(alias.clone()),
        [] => Err(format!(
            "no inventory alias maps to {}:{} for overnight --node verification",
            platform.as_str(),
            role.as_str()
        )),
        many => Err(format!(
            "ambiguous inventory aliases for {}:{}: {}",
            platform.as_str(),
            role.as_str(),
            many.join(", ")
        )),
    }
}

fn node_assignments_for_cell(
    inventory: &[VmInventoryEntry],
    cell: &Cell,
) -> Result<Vec<(String, NodeRole)>, String> {
    let target_role = march_role_to_node_role(cell.role).ok_or_else(|| {
        format!(
            "{} cells await first-class --node role support and are kept out of the Rust engine path",
            cell.role.as_str()
        )
    })?;
    let target_alias = resolve_alias_for_role(inventory, cell.platform, target_role.clone())?;
    let mut assignments = vec![(target_alias, target_role)];
    for (platform, role) in [
        (VmGuestPlatform::Linux, NodeRole::Exit),
        (VmGuestPlatform::Linux, NodeRole::Client),
    ] {
        let alias = resolve_alias_for_role(inventory, platform, role.clone())?;
        if !assignments.iter().any(|(existing, _)| existing == &alias) {
            assignments.push((alias, role));
        }
    }
    assignments.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.as_str().cmp(b.1.as_str())));
    Ok(assignments)
}

fn orchestrate_argv_for_cell(
    cli_binary: &Path,
    inventory_path: &Path,
    ssh_identity_file: &Path,
    known_hosts_path: Option<&Path>,
    report_dir: &Path,
    inventory: &[VmInventoryEntry],
    cell: &Cell,
) -> Result<Vec<String>, String> {
    let known_hosts_path = known_hosts_path.ok_or_else(|| {
        "--known-hosts-file is required for overnight Rust --node verification".to_owned()
    })?;
    let mut argv: Vec<String> = vec![
        cli_binary.to_string_lossy().into_owned(),
        "ops".to_owned(),
        "vm-lab-orchestrate-live-lab".to_owned(),
        "--inventory".to_owned(),
        inventory_path.to_string_lossy().into_owned(),
        "--ssh-identity-file".to_owned(),
        ssh_identity_file.to_string_lossy().into_owned(),
        "--known-hosts-file".to_owned(),
        known_hosts_path.to_string_lossy().into_owned(),
        "--report-dir".to_owned(),
        report_dir.to_string_lossy().into_owned(),
    ];
    for (alias, role) in node_assignments_for_cell(inventory, cell)? {
        argv.push("--node".to_owned());
        argv.push(format!("{alias}:{}", role.as_str()));
    }
    Ok(argv)
}

/// Result of a timeout-bounded agent spawn.
enum AgentRunStatus {
    Exited(std::process::ExitStatus),
    TimedOut,
}

enum AgentCapturedStatus {
    Exited {
        status: std::process::ExitStatus,
        stdout: String,
        stderr: String,
    },
    TimedOut,
}

/// Spawn `program args` in its OWN process group and wait up to `timeout_secs`.
/// On expiry, SIGKILL the whole group (the agent plus any orchestrate / lab
/// grandchild it spawned) so a wedged agent cannot strand a mid-run lab or hang
/// the multi-hour loop. `timeout_secs == 0` waits forever (test/interactive).
fn spawn_with_timeout(
    program: &str,
    args: &[String],
    timeout_secs: u64,
) -> Result<AgentRunStatus, String> {
    let mut child = Command::new(program)
        .args(args)
        // Child leads its own process group so grandchildren inherit it and the
        // whole tree can be killed via the negative pgid on timeout.
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;

    if timeout_secs == 0 {
        let status = child.wait().map_err(|e| e.to_string())?;
        return Ok(AgentRunStatus::Exited(status));
    }

    let pgid = child.id() as i64; // == the new group id because process_group(0)
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => return Ok(AgentRunStatus::Exited(status)),
            None => {
                if Instant::now() >= deadline {
                    // Kill the whole group (negative pgid via the `kill` binary
                    // — no unsafe/libc). Best-effort, then reap the direct child.
                    let _ = Command::new("kill")
                        .arg("-KILL")
                        .arg(format!("-{pgid}"))
                        .status();
                    let _ = child.wait();
                    return Ok(AgentRunStatus::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn spawn_capture_with_timeout(
    program: &str,
    args: &[String],
    timeout_secs: u64,
) -> Result<AgentCapturedStatus, String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        match child.try_wait().map_err(|e| e.to_string())? {
            Some(status) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_string(&mut stdout)
                        .map_err(|e| format!("read reviewer stdout failed: {e}"))?;
                }
                let mut stderr = String::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_string(&mut stderr)
                        .map_err(|e| format!("read reviewer stderr failed: {e}"))?;
                }
                return Ok(AgentCapturedStatus::Exited {
                    status,
                    stdout,
                    stderr,
                });
            }
            None => {
                if timeout_secs != 0 && Instant::now() >= deadline {
                    let pgid = child.id() as i64;
                    let _ = Command::new("kill")
                        .arg("-KILL")
                        .arg(format!("-{pgid}"))
                        .status();
                    let _ = child.wait();
                    return Ok(AgentCapturedStatus::TimedOut);
                }
                std::thread::sleep(Duration::from_millis(500));
            }
        }
    }
}

fn run_command_status(argv: Vec<String>, label: &str, cell: &Cell) -> Result<bool, String> {
    let (program, args) = argv
        .split_first()
        .ok_or_else(|| format!("{label} argv for {} was empty", cell.id()))?;
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|e| format!("{label} for {} failed: {e}", cell.id()))?;
    Ok(status.success())
}

fn ensure_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path)
        .map_err(|e| format!("create overnight verify dir {} failed: {e}", path.display()))
}

fn seed_run_matrix_scaffold(report_dir: &Path, cell: &Cell, argv: &[String]) -> Result<(), String> {
    let state_dir = report_dir.join("state");
    ensure_dir(state_dir.as_path())?;
    let payload = serde_json::json!({
        "schema_version": 1,
        "purpose": "overnight_verify_scaffold",
        "cell": cell.id(),
        "platform": cell.platform.as_str(),
        "role": cell.role.as_str(),
        "orchestrate_argv": argv,
    });
    let body = serde_json::to_string_pretty(&payload)
        .map_err(|e| format!("serialize overnight run-matrix scaffold failed: {e}"))?;
    fs::write(state_dir.join("live_lab_run_matrix_seed.json"), body)
        .map_err(|e| format!("write overnight run-matrix scaffold failed: {e}"))
}

fn selected_aliases_from_orchestrate_argv(argv: &[String]) -> Vec<String> {
    argv.windows(2)
        .filter_map(|pair| {
            if pair[0] == "--node" {
                pair[1].split_once(':').map(|(alias, _)| alias.to_owned())
            } else {
                None
            }
        })
        .collect()
}

fn vm_flag_argv(
    base: &[String],
    command: &str,
    aliases: &[String],
    report_dir: &Path,
) -> Vec<String> {
    let mut argv = vec![base[0].clone(), "ops".to_owned(), command.to_owned()];
    let mut iter = base.iter().skip(3);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--inventory" | "--ssh-identity-file" | "--known-hosts-file" => {
                argv.push(arg.clone());
                if let Some(value) = iter.next() {
                    argv.push(value.clone());
                }
            }
            _ => {}
        }
    }
    for alias in aliases {
        argv.push("--vm".to_owned());
        argv.push(alias.clone());
    }
    argv.push("--report-dir".to_owned());
    argv.push(report_dir.to_string_lossy().into_owned());
    argv
}

fn bootstrap_cache_argv(base: &[String], aliases: &[String]) -> Vec<String> {
    let mut argv = vec![
        base[0].clone(),
        "ops".to_owned(),
        "vm-lab-bootstrap-phase".to_owned(),
    ];
    let mut iter = base.iter().skip(3);
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--inventory" | "--ssh-identity-file" | "--known-hosts-file" => {
                argv.push(arg.clone());
                if let Some(value) = iter.next() {
                    argv.push(value.clone());
                }
            }
            _ => {}
        }
    }
    for alias in aliases {
        argv.push("--vm".to_owned());
        argv.push(alias.clone());
    }
    argv.push("--phase".to_owned());
    argv.push("build-release".to_owned());
    argv
}

impl WorkUnitExecutor for LiveExecutor {
    fn run_agent(&self, cell: &Cell, prompt: &str) -> Result<AgentOutcome, String> {
        let head_before = Self::current_head()?;

        let spec = AgentSpawnSpec {
            agent_cmd: self.cfg.agent_cmd.clone(),
            mcp_config_path: self.cfg.mcp_config_path.clone(),
            allowed_tools: self.cfg.allowed_tools.clone(),
            prompt: prompt.to_owned(),
        };
        let argv = build_agent_argv(&spec);
        let (program, args) = argv
            .split_first()
            .ok_or_else(|| "empty agent argv".to_owned())?;

        let status = spawn_with_timeout(program, args, self.cfg.agent_timeout_secs)
            .map_err(|e| format!("spawn agent for {} failed: {e}", cell.id()))?;
        let status = match status {
            AgentRunStatus::Exited(s) => s,
            AgentRunStatus::TimedOut => {
                return Err(format!(
                    "agent for {} timed out after {}s (process group killed)",
                    cell.id(),
                    self.cfg.agent_timeout_secs
                ));
            }
        };
        if !status.success() {
            return Err(format!(
                "agent for {} exited {}",
                cell.id(),
                status.code().unwrap_or(-1)
            ));
        }

        let head_after = Self::current_head()?;
        let committed = head_before != head_after;

        let touched_paths = if committed {
            let out = Command::new("git")
                .args(["diff", "--name-only", &head_before, &head_after])
                .output()
                .map_err(|e| format!("git diff --name-only failed: {e}"))?;
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::to_owned)
                .collect()
        } else {
            let out = Command::new("git")
                .args(["status", "--porcelain"])
                .output()
                .map_err(|e| format!("git status --porcelain failed: {e}"))?;
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.get(3..).map(str::to_owned))
                .collect()
        };

        Ok(AgentOutcome {
            committed,
            touched_paths,
            journal_note: format!("agent run for {}", cell.id()),
        })
    }

    fn verify_cell(&self, cell: &Cell) -> Result<OracleVerdict, String> {
        // Conservative live oracle: orchestrate the cell's role; exit 0 = Green,
        // non-zero = NoProgress. (Substage-level `Advanced` detection is a
        // future refinement — the mock exercises that path in tests.)
        let argv = match self.verify_argv_for_cell(cell) {
            Ok(argv) => argv,
            Err(err) if matches!(cell.role, MarchRole::Admin | MarchRole::BlindExit) => {
                eprintln!(
                    "[overnight] {} kept out of Rust --node verify path: {err}",
                    cell.id()
                );
                return Ok(OracleVerdict::NoProgress);
            }
            Err(err) => return Err(err),
        };
        let report_dir = argv
            .windows(2)
            .find_map(|pair| {
                if pair[0] == "--report-dir" {
                    Some(PathBuf::from(pair[1].clone()))
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("verify argv for {} missing --report-dir", cell.id()))?;
        ensure_dir(report_dir.as_path())?;
        seed_run_matrix_scaffold(report_dir.as_path(), cell, &argv)?;
        let aliases = selected_aliases_from_orchestrate_argv(&argv);
        let preflight_dir = report_dir.join("preflight");
        let preflight_argv = vm_flag_argv(
            &argv,
            "vm-lab-readiness-check",
            &aliases,
            preflight_dir.as_path(),
        );
        if !run_command_status(preflight_argv.clone(), "preflight", cell)? {
            let recover_dir = report_dir.join("recover");
            let mut recover_argv =
                vm_flag_argv(&argv, "vm-lab-restart", &aliases, recover_dir.as_path());
            recover_argv.push("--wait-ready".to_owned());
            if !run_command_status(recover_argv, "recover", cell)? {
                return Ok(OracleVerdict::NoProgress);
            }
            if !run_command_status(preflight_argv, "preflight after recover", cell)? {
                return Ok(OracleVerdict::NoProgress);
            }
        }
        if !run_command_status(
            bootstrap_cache_argv(&argv, &aliases),
            "cargo cache warm",
            cell,
        )? {
            return Ok(OracleVerdict::NoProgress);
        }

        let (program, args) = argv
            .split_first()
            .ok_or_else(|| "empty orchestrate argv".to_owned())?;
        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|e| format!("orchestrate verify for {} failed: {e}", cell.id()))?;

        if status.success() {
            Ok(OracleVerdict::Green)
        } else {
            Ok(OracleVerdict::NoProgress)
        }
    }

    fn second_review(&self, cell: &Cell, _outcome: &AgentOutcome) -> SecondReviewVerdict {
        let diff = match Self::current_diff_for_review(cell) {
            Ok(diff) => diff,
            Err(err) => return SecondReviewVerdict::unsafe_with(err),
        };
        self.run_second_review_agent(cell, diff.as_str())
    }

    fn revert_to_clean(&self) -> Result<(), String> {
        let base = Self::current_head()?;
        for argv in revert_to_clean_argv(&base) {
            let (program, args) = argv
                .split_first()
                .ok_or_else(|| "empty revert argv".to_owned())?;
            let status = Command::new(program)
                .args(args)
                .status()
                .map_err(|e| format!("revert step {program} failed: {e}"))?;
            if !status.success() {
                return Err(format!(
                    "revert step {program} exited {}",
                    status.code().unwrap_or(-1)
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::VmGuestPlatform;
    use crate::vm_lab::overnight::backlog::{MarchRole, PriorVerdicts};
    use std::cell::RefCell;

    #[test]
    fn spawn_with_timeout_kills_a_wedged_process() {
        // A sleep far exceeding the 1s cap must be killed and reported TimedOut,
        // and control must return near the deadline, not after the full sleep.
        let start = Instant::now();
        let r = spawn_with_timeout("sleep", &["30".to_owned()], 1).expect("spawn");
        assert!(matches!(r, AgentRunStatus::TimedOut));
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout must fire promptly, took {:?}",
            start.elapsed()
        );
    }

    #[test]
    fn spawn_with_timeout_returns_exit_status_for_a_fast_command() {
        match spawn_with_timeout("true", &[], 30).expect("spawn") {
            AgentRunStatus::Exited(s) => assert!(s.success()),
            AgentRunStatus::TimedOut => panic!("a fast command must not time out"),
        }
    }

    #[test]
    fn zero_timeout_waits_for_completion() {
        match spawn_with_timeout("true", &[], 0).expect("spawn") {
            AgentRunStatus::Exited(s) => assert!(s.success()),
            AgentRunStatus::TimedOut => panic!("zero timeout must wait, not time out"),
        }
    }

    /// Scripted executor: returns a queued (outcome, verdict) per call and
    /// records reverts. No process is ever spawned.
    struct MockExecutor {
        outcomes: RefCell<Vec<AgentOutcome>>,
        verdicts: RefCell<Vec<OracleVerdict>>,
        reviews: RefCell<Vec<SecondReviewVerdict>>,
        reverts: RefCell<u32>,
    }

    impl MockExecutor {
        fn new(pairs: Vec<(AgentOutcome, OracleVerdict)>) -> Self {
            let (o, v): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            MockExecutor {
                outcomes: RefCell::new(o),
                verdicts: RefCell::new(v),
                reviews: RefCell::new(vec![SecondReviewVerdict::Safe {
                    rationale: "mock safe".to_owned(),
                }]),
                reverts: RefCell::new(0),
            }
        }

        fn with_reviews(
            pairs: Vec<(AgentOutcome, OracleVerdict)>,
            reviews: Vec<SecondReviewVerdict>,
        ) -> Self {
            let exec = Self::new(pairs);
            *exec.reviews.borrow_mut() = reviews;
            exec
        }
    }

    impl WorkUnitExecutor for MockExecutor {
        fn run_agent(&self, _cell: &Cell, _prompt: &str) -> Result<AgentOutcome, String> {
            Ok(self.outcomes.borrow_mut().remove(0))
        }
        fn verify_cell(&self, _cell: &Cell) -> Result<OracleVerdict, String> {
            Ok(self.verdicts.borrow_mut().remove(0))
        }
        fn second_review(&self, _cell: &Cell, _outcome: &AgentOutcome) -> SecondReviewVerdict {
            self.reviews.borrow_mut().remove(0)
        }
        fn revert_to_clean(&self) -> Result<(), String> {
            *self.reverts.borrow_mut() += 1;
            Ok(())
        }
    }

    struct ScriptedClock {
        ticks: RefCell<Vec<u64>>,
        last: RefCell<u64>,
    }
    impl ScriptedClock {
        fn new(ticks: Vec<u64>) -> Self {
            ScriptedClock {
                ticks: RefCell::new(ticks),
                last: RefCell::new(0),
            }
        }
    }
    impl Clock for ScriptedClock {
        fn elapsed_secs(&self) -> u64 {
            let mut t = self.ticks.borrow_mut();
            if t.is_empty() {
                return *self.last.borrow();
            }
            let v = t.remove(0);
            *self.last.borrow_mut() = v;
            v
        }
    }

    fn backlog() -> FrontierBacklog {
        FrontierBacklog::build(
            &[VmGuestPlatform::Linux, VmGuestPlatform::Windows],
            &PriorVerdicts::new(),
        )
    }

    fn idx_of(b: &FrontierBacklog, p: VmGuestPlatform, r: MarchRole) -> usize {
        b.cells
            .iter()
            .position(|c| c.platform == p && c.role == r)
            .expect("cell")
    }

    fn ctx() -> UnitContext {
        UnitContext {
            branch: "overnight/2026-06-09_t".to_owned(),
            journal_pointer: "write_loop_note".to_owned(),
        }
    }

    fn safe_paths() -> Vec<String> {
        vec!["crates/rustynet-relay/src/lib.rs".to_owned()]
    }

    fn inventory_entry(
        alias: &str,
        platform: VmGuestPlatform,
        lab_role: &str,
        exit_capable: bool,
        relay_capable: bool,
    ) -> VmInventoryEntry {
        VmInventoryEntry {
            alias: alias.to_owned(),
            ssh_target: format!("{alias}.local"),
            ssh_user: Some("lab".to_owned()),
            ssh_password: None,
            include_in_all: Some(true),
            os: Some(platform.as_str().to_owned()),
            last_known_ip: None,
            parent_device: None,
            last_known_network: None,
            network_group: Some("test-net".to_owned()),
            node_id: Some(format!("{alias}-id")),
            lab_role: Some(lab_role.to_owned()),
            mesh_ip: None,
            exit_capable: Some(exit_capable),
            relay_capable: Some(relay_capable),
            remote_temp_dir: None,
            utm_staging_dir: None,
            rustynet_src_dir: None,
            platform: Some(platform),
            remote_shell: None,
            guest_exec_mode: None,
            service_manager: None,
            controller: None,
        }
    }

    fn sample_inventory() -> Vec<VmInventoryEntry> {
        vec![
            inventory_entry("linux-exit", VmGuestPlatform::Linux, "exit", true, false),
            inventory_entry(
                "linux-client",
                VmGuestPlatform::Linux,
                "client",
                false,
                false,
            ),
            inventory_entry(
                "windows-client",
                VmGuestPlatform::Windows,
                "windows_client",
                false,
                false,
            ),
            inventory_entry("linux-relay", VmGuestPlatform::Linux, "relay", false, true),
            inventory_entry("linux-admin", VmGuestPlatform::Linux, "admin", false, false),
        ]
    }

    fn default_scheduler() -> SchedulerConfig {
        SchedulerConfig::default()
    }

    #[test]
    fn orchestrate_argv_for_cell_uses_rust_node_assignments() {
        let cell = Cell {
            platform: VmGuestPlatform::Windows,
            role: MarchRole::Client,
            state: CellState::Unknown,
            value: 30,
            attempts: 0,
            progress: None,
            stage_hint: "role_switch_matrix".to_owned(),
            sibling_reference: None,
            notes: None,
            parked_reason: None,
        };
        let argv = orchestrate_argv_for_cell(
            Path::new("/bin/rustynet"),
            Path::new("inventory.json"),
            Path::new("/id"),
            Some(Path::new("/known_hosts")),
            Path::new("reports/cell"),
            &sample_inventory(),
            &cell,
        )
        .expect("argv");
        assert_eq!(
            argv,
            vec![
                "/bin/rustynet",
                "ops",
                "vm-lab-orchestrate-live-lab",
                "--inventory",
                "inventory.json",
                "--ssh-identity-file",
                "/id",
                "--known-hosts-file",
                "/known_hosts",
                "--report-dir",
                "reports/cell",
                "--node",
                "linux-client:client",
                "--node",
                "linux-exit:exit",
                "--node",
                "windows-client:client",
            ]
        );
    }

    #[test]
    fn orchestrate_argv_for_cell_emits_node_for_admin_role() {
        let cell = Cell {
            platform: VmGuestPlatform::Linux,
            role: MarchRole::Admin,
            state: CellState::Unknown,
            value: 30,
            attempts: 0,
            progress: None,
            stage_hint: "role_switch_matrix".to_owned(),
            sibling_reference: None,
            notes: None,
            parked_reason: None,
        };
        let argv = orchestrate_argv_for_cell(
            Path::new("/bin/rustynet"),
            Path::new("inventory.json"),
            Path::new("/id"),
            Some(Path::new("/known_hosts")),
            Path::new("reports/cell"),
            &sample_inventory(),
            &cell,
        )
        .expect("admin is now a first-class --node role");
        assert!(argv.contains(&"--node".to_owned()));
    }

    #[test]
    fn green_committed_safe_marks_verified() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: true,
                touched_paths: safe_paths(),
                journal_note: "done".to_owned(),
            },
            OracleVerdict::Green,
        )]);
        let r = drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), false).unwrap();
        assert_eq!(r, UnitResult::Verified);
        assert_eq!(b.cells[i].state, CellState::Verified);
        // commit kept -> no revert.
        assert_eq!(*exec.reverts.borrow(), 0);
    }

    #[test]
    fn green_committed_but_security_diff_is_reverted_and_escalated() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: true,
                touched_paths: vec!["crates/rustynet-policy/src/eval.rs".to_owned()],
                journal_note: "touched policy".to_owned(),
            },
            OracleVerdict::Green,
        )]);
        let r = drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), true).unwrap();
        assert_eq!(r, UnitResult::NeedsReview);
        // NOT verified; parked for review; commit reverted.
        assert_eq!(b.cells[i].state, CellState::Parked);
        assert_eq!(*exec.reverts.borrow(), 1);
    }

    #[test]
    fn green_but_not_committed_fails_closed() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: false,
                touched_paths: vec![],
                journal_note: "n".to_owned(),
            },
            OracleVerdict::Green,
        )]);
        let r = drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), false).unwrap();
        assert_eq!(r, UnitResult::NoProgress);
        assert_ne!(b.cells[i].state, CellState::Verified);
        // nothing committed -> reverted to clean.
        assert_eq!(*exec.reverts.borrow(), 1);
    }

    #[test]
    fn advanced_committed_records_progress() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: true,
                touched_paths: safe_paths(),
                journal_note: "partial".to_owned(),
            },
            OracleVerdict::Advanced {
                from: "0/3".to_owned(),
                to: "2/3".to_owned(),
            },
        )]);
        let r = drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), false).unwrap();
        assert!(matches!(r, UnitResult::Advanced { .. }));
        assert_eq!(b.cells[i].progress.as_deref(), Some("0/3 -> 2/3"));
        assert_eq!(*exec.reverts.borrow(), 0);
    }

    #[test]
    fn no_progress_counts_attempt_and_reverts() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let before = b.cells[i].attempts;
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: false,
                touched_paths: vec![],
                journal_note: "stuck".to_owned(),
            },
            OracleVerdict::NoProgress,
        )]);
        drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), false).unwrap();
        assert_eq!(b.cells[i].attempts, before + 1);
        assert_eq!(*exec.reverts.borrow(), 1);
    }

    #[test]
    fn parse_second_review_safe_json() {
        let verdict =
            parse_second_review_verdict(r#"{"verdict":"safe","rationale":"tests cover it"}"#);
        assert_eq!(
            verdict,
            SecondReviewVerdict::Safe {
                rationale: "tests cover it".to_owned()
            }
        );
    }

    #[test]
    fn parse_second_review_fails_closed_on_bad_json() {
        let verdict = parse_second_review_verdict("not json");
        assert!(matches!(verdict, SecondReviewVerdict::Unsafe { .. }));
    }

    #[test]
    fn parse_second_review_fails_closed_on_missing_verdict() {
        let verdict = parse_second_review_verdict(r#"{"rationale":"no verdict"}"#);
        assert!(matches!(verdict, SecondReviewVerdict::Unsafe { .. }));
    }

    #[test]
    fn auto_merge_gate_refuses_unsafe_second_review() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::with_reviews(
            vec![(
                AgentOutcome {
                    committed: true,
                    touched_paths: safe_paths(),
                    journal_note: "done".to_owned(),
                },
                OracleVerdict::Green,
            )],
            vec![SecondReviewVerdict::Unsafe {
                rationale: "missing negative test".to_owned(),
            }],
        );
        let r = drive_unit(&mut b, i, &ctx(), &exec, &default_scheduler(), true).unwrap();
        assert_eq!(r, UnitResult::NeedsReview);
        assert_eq!(b.cells[i].state, CellState::Parked);
        assert_eq!(*exec.reverts.borrow(), 1);
    }

    #[test]
    fn auto_merge_gate_refuses_main_branch() {
        let mut b = backlog();
        let i = idx_of(&b, VmGuestPlatform::Windows, MarchRole::Relay);
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: true,
                touched_paths: safe_paths(),
                journal_note: "done".to_owned(),
            },
            OracleVerdict::Green,
        )]);
        let ctx = UnitContext {
            branch: "main".to_owned(),
            journal_pointer: "write_loop_note".to_owned(),
        };
        let r = drive_unit(&mut b, i, &ctx, &exec, &default_scheduler(), true).unwrap();
        assert_eq!(r, UnitResult::NeedsReview);
        assert_eq!(b.cells[i].state, CellState::Parked);
        assert_eq!(*exec.reverts.borrow(), 1);
    }

    #[test]
    fn run_loop_greens_then_exhausts() {
        let mut b = backlog();
        // Verify everything that's actionable as green/committed/safe.
        let actionable = b.cells.iter().filter(|c| c.state.is_actionable()).count();
        let pairs: Vec<_> = (0..actionable)
            .map(|_| {
                (
                    AgentOutcome {
                        committed: true,
                        touched_paths: safe_paths(),
                        journal_note: "ok".to_owned(),
                    },
                    OracleVerdict::Green,
                )
            })
            .collect();
        let exec = MockExecutor::new(pairs);
        let cfg = LoopConfig {
            scheduler: SchedulerConfig::default(),
            max_duration_secs: 100_000,
            auto_merge_safe_cells: false,
        };
        // Clock always returns 0 so the time budget never trips; the loop ends
        // by exhausting the frontier.
        let clock = ScriptedClock::new(vec![]);
        let summary = run_loop(&mut b, &cfg, &ctx(), &exec, &clock).unwrap();
        assert_eq!(summary.units_run as usize, actionable);
        assert_eq!(summary.verified_this_run as usize, actionable);
        assert_eq!(next_actionable(&b, &cfg.scheduler), None);
    }

    #[test]
    fn run_loop_respects_time_budget() {
        let mut b = backlog();
        // One unit fits (elapsed 0), then the clock jumps past the budget.
        let exec = MockExecutor::new(vec![(
            AgentOutcome {
                committed: true,
                touched_paths: safe_paths(),
                journal_note: "ok".to_owned(),
            },
            OracleVerdict::Green,
        )]);
        let cfg = LoopConfig {
            scheduler: SchedulerConfig::default(),
            max_duration_secs: 10,
            auto_merge_safe_cells: false,
        };
        // First check 0 (<10, run a unit), second check 999 (>=10, stop).
        let clock = ScriptedClock::new(vec![0, 999]);
        let summary = run_loop(&mut b, &cfg, &ctx(), &exec, &clock).unwrap();
        assert_eq!(summary.units_run, 1);
    }

    #[test]
    fn run_loop_escalates_budget_exhausted_cell() {
        let mut b = backlog();
        let cfg = LoopConfig {
            scheduler: SchedulerConfig {
                max_attempts_per_cell: 1,
                ..SchedulerConfig::default()
            },
            max_duration_secs: 100_000,
            auto_merge_safe_cells: false,
        };
        // Every unit makes no progress -> each cell parks after 1 attempt.
        let n = b.cells.iter().filter(|c| c.state.is_actionable()).count();
        let pairs: Vec<_> = (0..n)
            .map(|_| {
                (
                    AgentOutcome {
                        committed: false,
                        touched_paths: vec![],
                        journal_note: "stuck".to_owned(),
                    },
                    OracleVerdict::NoProgress,
                )
            })
            .collect();
        let exec = MockExecutor::new(pairs);
        let clock = ScriptedClock::new(vec![]);
        let summary = run_loop(&mut b, &cfg, &ctx(), &exec, &clock).unwrap();
        // Every actionable cell became an escalation.
        assert_eq!(summary.escalations.len(), n);
        assert_eq!(summary.verified_this_run, 0);
    }
}
