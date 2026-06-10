//! The per-work-unit state machine (`drive_unit`), the loop control flow
//! (`run_loop`), and the real `LiveExecutor`.
//!
//! The control plane (`drive_unit` / `run_loop`) is generic over the
//! [`WorkUnitExecutor`] trait so it is fully unit-tested with a mock, proving
//! the loop logic WITHOUT spawning agents or touching the live lab.
//! `LiveExecutor` is the real implementation: an argv-only subprocess spawn,
//! git for commit/diff/revert, and the existing orchestrate CLI as the oracle.
//! It is compiled and type-checked but never invoked by the tests.

use std::path::PathBuf;
use std::process::Command;
use std::time::Instant;

use crate::vm_lab::overnight::agent::{AgentSpawnSpec, build_agent_argv, render_unit_prompt};
use crate::vm_lab::overnight::backlog::{Cell, CellState, FrontierBacklog};
use crate::vm_lab::overnight::manifest::Checkpoint;
use crate::vm_lab::overnight::safety::{classify_touched_paths, revert_to_clean_argv};
use crate::vm_lab::overnight::scheduler::{SchedulerConfig, next_actionable};

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
        backlog.park(idx, "security-sensitive diff requires adversarial review");
        return Ok(UnitResult::NeedsReview);
    }

    let result = match verdict {
        OracleVerdict::Green => {
            if outcome.committed {
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
            UnitResult::NoProgress
        }
    };

    // Clean-tree invariant: discard any uncommitted residue.
    if !outcome.committed {
        executor.revert_to_clean()?;
    }
    Ok(result)
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
        let result = drive_unit(backlog, idx, ctx, executor, &cfg.scheduler)?;
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

    /// Role -> the orchestrate `--<role>-platform <os>` selector, reusing the
    /// existing flags. Client/admin map to no selector (default topology).
    fn platform_selector(cell: &Cell) -> Option<(String, String)> {
        use crate::vm_lab::overnight::backlog::MarchRole;
        let flag = match cell.role {
            MarchRole::Exit => "--exit-platform",
            MarchRole::Relay => "--relay-platform",
            MarchRole::Anchor => "--anchor-platform",
            MarchRole::Client | MarchRole::Admin | MarchRole::BlindExit => return None,
        };
        Some((flag.to_owned(), cell.platform.as_str().to_owned()))
    }
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

        let status = Command::new(program)
            .args(args)
            .status()
            .map_err(|e| format!("spawn agent for {} failed: {e}", cell.id()))?;
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
        let report_dir = self
            .cfg
            .report_root
            .join(format!("verify_{}", cell.id().replace('/', "_")));
        let mut argv: Vec<String> = vec![
            self.cfg.cli_binary.to_string_lossy().into_owned(),
            "ops".to_owned(),
            "vm-lab-orchestrate-live-lab".to_owned(),
            "--inventory".to_owned(),
            self.cfg.inventory_path.to_string_lossy().into_owned(),
            "--ssh-identity-file".to_owned(),
            self.cfg.ssh_identity_file.to_string_lossy().into_owned(),
            "--report-dir".to_owned(),
            report_dir.to_string_lossy().into_owned(),
        ];
        if let Some(kh) = &self.cfg.known_hosts_path {
            argv.push("--known-hosts-file".to_owned());
            argv.push(kh.to_string_lossy().into_owned());
        }
        if let Some((flag, value)) = Self::platform_selector(cell) {
            argv.push(flag);
            argv.push(value);
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

    /// Scripted executor: returns a queued (outcome, verdict) per call and
    /// records reverts. No process is ever spawned.
    struct MockExecutor {
        outcomes: RefCell<Vec<AgentOutcome>>,
        verdicts: RefCell<Vec<OracleVerdict>>,
        reverts: RefCell<u32>,
    }

    impl MockExecutor {
        fn new(pairs: Vec<(AgentOutcome, OracleVerdict)>) -> Self {
            let (o, v): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
            MockExecutor {
                outcomes: RefCell::new(o),
                verdicts: RefCell::new(v),
                reverts: RefCell::new(0),
            }
        }
    }

    impl WorkUnitExecutor for MockExecutor {
        fn run_agent(&self, _cell: &Cell, _prompt: &str) -> Result<AgentOutcome, String> {
            Ok(self.outcomes.borrow_mut().remove(0))
        }
        fn verify_cell(&self, _cell: &Cell) -> Result<OracleVerdict, String> {
            Ok(self.verdicts.borrow_mut().remove(0))
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
        let r = drive_unit(&mut b, i, &ctx(), &exec, &SchedulerConfig::default()).unwrap();
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
        let r = drive_unit(&mut b, i, &ctx(), &exec, &SchedulerConfig::default()).unwrap();
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
        let r = drive_unit(&mut b, i, &ctx(), &exec, &SchedulerConfig::default()).unwrap();
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
        let r = drive_unit(&mut b, i, &ctx(), &exec, &SchedulerConfig::default()).unwrap();
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
        drive_unit(&mut b, i, &ctx(), &exec, &SchedulerConfig::default()).unwrap();
        assert_eq!(b.cells[i].attempts, before + 1);
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
