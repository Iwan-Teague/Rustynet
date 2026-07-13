use std::collections::HashSet;
use std::fs;
use std::process::Command;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use serde_json::json;

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::evidence::RustNativeStageRecorder;
use crate::vm_lab::orchestrator::role::NodeRole;
use crate::vm_lab::orchestrator::runner::StageObserver;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageFanout, StageId};
use crate::vm_lab::{VmGuestPlatform, collected_at_utc_now, write_orchestration_artifact};

pub fn collect_failure_diagnostics(
    ctx: &OrchestrationContext,
    collect_diagnostics: bool,
    collect_artifacts: bool,
) -> Result<(), String> {
    if !collect_diagnostics && !collect_artifacts {
        return Ok(());
    }
    let diagnostics_dir = ctx.report_dir.join("diagnostics/rust-native-failure");
    fs::create_dir_all(&diagnostics_dir).map_err(|err| {
        format!(
            "create Rust-native diagnostics directory '{}': {err}",
            diagnostics_dir.display()
        )
    })?;

    let mut aliases = ctx.adapters.keys().cloned().collect::<Vec<_>>();
    aliases.sort();
    let mut nodes = serde_json::Map::new();
    let artifacts_dir = diagnostics_dir.join("artifacts");
    if collect_artifacts {
        fs::create_dir_all(&artifacts_dir).map_err(|err| {
            format!(
                "create Rust-native artifact directory '{}': {err}",
                artifacts_dir.display()
            )
        })?;
    }
    for alias in aliases {
        let adapter = ctx
            .adapters
            .get(&alias)
            .ok_or_else(|| format!("diagnostics adapter disappeared for '{alias}'"))?;
        let daemon_reason = if collect_diagnostics {
            match adapter.collect_daemon_failure_reason() {
                Ok(reason) => reason.unwrap_or_else(|| "no daemon failure marker found".to_owned()),
                Err(err) => format!("daemon diagnostic unavailable: {err}"),
            }
        } else {
            "diagnostic collection disabled".to_owned()
        };
        let artifact_path = if collect_artifacts {
            let extension = if adapter.platform() == VmGuestPlatform::Windows {
                "zip"
            } else {
                "tar.gz"
            };
            let path = artifacts_dir.join(format!("{alias}.{extension}"));
            adapter
                .collect_artifacts(&path)
                .map_err(|err| format!("collect failure artifacts for '{alias}': {err}"))?;
            Some(path.display().to_string())
        } else {
            None
        };
        nodes.insert(
            alias,
            json!({
                "platform": format!("{:?}", adapter.platform()).to_lowercase(),
                "daemon_reason": daemon_reason,
                "artifact": artifact_path,
            }),
        );
    }
    let summary = json!({
        "schema_version": 1,
        "collected_before_cleanup": true,
        "nodes": nodes,
    });
    write_orchestration_artifact(
        diagnostics_dir.join("summary.json").as_path(),
        &(serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("serialize Rust-native diagnostics: {err}"))?
            + "\n"),
    )
}

pub fn register_shutdown_handlers_with<F>(mut register: F) -> Result<Arc<AtomicBool>, String>
where
    F: FnMut(i32, Arc<AtomicBool>) -> Result<(), String>,
{
    let flag = Arc::new(AtomicBool::new(false));
    register(signal_hook::consts::SIGTERM, Arc::clone(&flag))?;
    register(signal_hook::consts::SIGINT, Arc::clone(&flag))?;
    Ok(flag)
}

pub fn register_shutdown_handlers() -> Result<Arc<AtomicBool>, String> {
    register_shutdown_handlers_with(|signal, flag| {
        signal_hook::flag::register(signal, flag)
            .map(|_| ())
            .map_err(|err| format!("register signal {signal} cleanup handler failed: {err}"))
    })
}

// ── RNQ-07: real cancellable per-stage deadlines ─────────────────────────────
//
// The Rust `--node` engine runs every stage in-process, so a "timeout" cannot
// be a detached thread that keeps mutating guests after the runner moves on
// (explicitly forbidden by the RNQ-07 audit row). Instead each stage runs as a
// cancellable unit:
//
//   1. `DeadlineEnforcedStage` executes the wrapped stage on a scoped worker
//      thread and watches the deadline from the calling thread.
//   2. On expiry the watchdog kills the stage's live subprocess tree (the ssh
//      / scp / cargo / tar children every long-running stage operation is
//      mediated by). Killing them unblocks the worker's `wait()`, so the
//      worker RETURNS — it is never abandoned mid-mutation.
//   3. The stage's own late outcome is discarded; the terminal outcome is
//      `StageOutcome::Failed` (fail-closed: a timeout can never pass, the run
//      fails, skip-cascade blocks dependents, always-run cleanup still runs)
//      and the shared [`StageTimeoutLedger`] marks the stage so the evidence
//      layer records the closed-taxonomy `timed_out` status instead of `fail`.
//
// SIGTERM/SIGINT fatal-signal handling above is untouched: deadlines are
// additive and never consult or modify the shutdown flag.

/// Per-stage deadline policy. `deadline == 0` disables enforcement entirely
/// (the pre-RNQ-07 behavior: stages run with no per-stage bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct StageDeadlinePolicy {
    /// Wall-clock budget for one stage. Zero = no deadline.
    pub deadline: Duration,
    /// Watchdog poll interval while the stage runs.
    pub poll: Duration,
    /// How long, after each subprocess-tree sweep, the watchdog waits for the
    /// cancelled worker to observe its dead children and return before it
    /// re-sweeps and warns again.
    pub grace: Duration,
}

impl StageDeadlinePolicy {
    pub(crate) fn for_timeout_secs(timeout_secs: u64) -> Self {
        StageDeadlinePolicy {
            deadline: Duration::from_secs(timeout_secs),
            poll: Duration::from_millis(200),
            grace: Duration::from_secs(5),
        }
    }

    pub(crate) fn is_disabled(&self) -> bool {
        self.deadline.is_zero()
    }
}

/// Stages that hit their deadline this run, keyed by wire stage name. Shared
/// between the deadline decorator (writer) and the evidence observer wrapper
/// (reader) so the terminal `stages.tsv` row is recorded with the registry's
/// closed-taxonomy `timed_out` status instead of a generic `fail`.
#[derive(Default)]
pub(crate) struct StageTimeoutLedger {
    entries: Mutex<std::collections::HashMap<String, String>>,
}

impl StageTimeoutLedger {
    fn lock_entries(&self) -> std::sync::MutexGuard<'_, std::collections::HashMap<String, String>> {
        // A poisoned mutex only means another thread panicked while holding
        // the lock; the map itself (String -> String) cannot be left in a
        // torn state, and losing timeout attribution would mis-record a
        // timed-out stage as a plain failure. Recover the guard.
        match self.entries.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    pub(crate) fn record(&self, stage: &str, summary: String) {
        self.lock_entries().insert(stage.to_owned(), summary);
    }

    pub(crate) fn timed_out_summary(&self, stage: &str) -> Option<String> {
        self.lock_entries().get(stage).cloned()
    }
}

/// One row of the live process table used for subprocess-tree computation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ProcessRecord {
    pub(crate) pid: i64,
    pub(crate) ppid: i64,
}

/// Pure kill-set computation: every live descendant of `roots` (transitively,
/// via ppid edges), `roots` themselves included iff `include_roots`. Subtrees
/// rooted at an `exclude` pid are pruned whole — they existed before the stage
/// started, so they are not this stage's to kill. Pid 0/1 and negative pids
/// are never returned regardless of table content (fail-closed guard against
/// a corrupt `ps` parse ever aiming at init or a process group).
pub(crate) fn descendant_kill_set(
    table: &[ProcessRecord],
    roots: &[i64],
    include_roots: bool,
    exclude: &HashSet<i64>,
) -> Vec<i64> {
    let mut children: std::collections::HashMap<i64, Vec<i64>> = std::collections::HashMap::new();
    for record in table {
        children.entry(record.ppid).or_default().push(record.pid);
    }
    let mut out: Vec<i64> = Vec::new();
    let mut seen: HashSet<i64> = HashSet::new();
    let mut queue: Vec<(i64, bool)> = roots.iter().map(|&pid| (pid, true)).collect();
    while let Some((pid, is_root)) = queue.pop() {
        if pid <= 1 || exclude.contains(&pid) || !seen.insert(pid) {
            continue;
        }
        if !is_root || include_roots {
            out.push(pid);
        }
        if let Some(kids) = children.get(&pid) {
            queue.extend(kids.iter().map(|&kid| (kid, false)));
        }
    }
    out.sort_unstable();
    out
}

/// Seam between the deadline watchdog and the OS: enumerate the pids that
/// belong to the running stage's cancellation domain, and kill them. The
/// production implementation sweeps the orchestrator process's own descendant
/// tree; tests inject a control scoped to the pids their fake stage spawned so
/// a parallel `cargo test` process never has unrelated children killed.
pub(crate) trait SubprocessTreeControl: Send + Sync {
    /// Live pids in the cancellation domain right now, minus `exclude` (and
    /// minus anything descended from an excluded pid).
    fn live_stage_pids(&self, exclude: &[i64]) -> Result<Vec<i64>, String>;
    /// Best-effort SIGKILL of `pids`. Already-exited pids are not an error.
    fn kill_pids(&self, pids: &[i64]) -> Result<(), String>;
}

/// Read the live process table via `ps` (argv-only exec, BSD+procps
/// compatible flags). The `ps` helper's own pid is excluded from the parsed
/// table so it can never enter a kill set through pid reuse.
fn read_process_table() -> Result<Vec<ProcessRecord>, String> {
    let child = Command::new("ps")
        .args(["-axo", "pid=,ppid="])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .stdin(std::process::Stdio::null())
        .spawn()
        .map_err(|err| format!("spawn ps for stage-deadline sweep failed: {err}"))?;
    let helper_pid = i64::from(child.id());
    let output = child
        .wait_with_output()
        .map_err(|err| format!("collect ps output for stage-deadline sweep failed: {err}"))?;
    if !output.status.success() {
        return Err(format!(
            "ps for stage-deadline sweep exited with {:?}",
            output.status.code()
        ));
    }
    let body = String::from_utf8_lossy(&output.stdout);
    let mut table = Vec::new();
    for line in body.lines() {
        let mut fields = line.split_whitespace();
        let (Some(pid), Some(ppid)) = (fields.next(), fields.next()) else {
            continue;
        };
        let (Ok(pid), Ok(ppid)) = (pid.parse::<i64>(), ppid.parse::<i64>()) else {
            continue;
        };
        if pid == helper_pid {
            continue;
        }
        table.push(ProcessRecord { pid, ppid });
    }
    Ok(table)
}

/// Best-effort SIGKILL via the `kill` binary (argv-only; no shell, no unsafe,
/// matching the overnight executor's hardened idiom). A non-zero exit is not
/// an error: members of the set may have already exited between enumeration
/// and delivery, and the next sweep re-verifies liveness either way.
fn sigkill_pids(pids: &[i64]) -> Result<(), String> {
    if pids.is_empty() {
        return Ok(());
    }
    // All pids are positive (guarded below), so no `--` separator is needed —
    // matching the overnight executor's proven `kill -KILL <pid>` idiom, which
    // is portable across GNU and BSD (macOS) `kill`.
    let mut cmd = Command::new("kill");
    cmd.arg("-KILL");
    for pid in pids {
        if *pid <= 1 {
            return Err(format!(
                "refusing stage-deadline kill of pid {pid} (fail-closed guard)"
            ));
        }
        cmd.arg(pid.to_string());
    }
    // Non-zero exit is tolerated (members may already be dead); the sweep loop
    // re-verifies liveness. Only a spawn failure propagates.
    cmd.stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_err(|err| format!("spawn kill for stage-deadline cancellation failed: {err}"))?;
    Ok(())
}

/// Production control: the cancellation domain is every live descendant of
/// the orchestrator process itself. Stages run sequentially in-process, so at
/// deadline time the orchestrator's descendants are exactly the timed-out
/// stage's subprocess tree (pre-stage residue is excluded via the snapshot
/// the watchdog takes before the stage starts).
pub(crate) struct OrchestratorSubprocessTree {
    root: i64,
}

impl OrchestratorSubprocessTree {
    pub(crate) fn for_current_process() -> Self {
        OrchestratorSubprocessTree {
            root: i64::from(std::process::id()),
        }
    }
}

impl SubprocessTreeControl for OrchestratorSubprocessTree {
    fn live_stage_pids(&self, exclude: &[i64]) -> Result<Vec<i64>, String> {
        let table = read_process_table()?;
        let exclude: HashSet<i64> = exclude.iter().copied().collect();
        Ok(descendant_kill_set(&table, &[self.root], false, &exclude))
    }

    fn kill_pids(&self, pids: &[i64]) -> Result<(), String> {
        sigkill_pids(pids)
    }
}

/// Outcome details of one deadline cancellation, used to build the terminal
/// message recorded to the ledger and the `Failed` outcome.
struct CancellationReport {
    killed: Vec<i64>,
    sweep_errors: Vec<String>,
}

/// Run `execute` with a hard wall-clock deadline. Under the deadline the
/// stage's own outcome (or panic) passes through untouched. On expiry the
/// stage's subprocess tree is killed and re-swept until the worker thread
/// returns, then the terminal outcome is a fail-closed `Failed` and `ledger`
/// marks the stage `timed_out` for the evidence layer.
///
/// The worker is a scoped thread: it is never detached, so a cancelled stage
/// can never keep mutating guests after the runner has moved on (RNQ-07 audit
/// constraint). Cancellation is subprocess-tree-mediated — every long-running
/// stage operation in this engine blocks on a child process (`ssh`, `scp`,
/// `cargo`, `tar`), and killing that child unblocks the worker. A stage that
/// busy-loops in pure Rust without any child has no cancellation point; the
/// watchdog then keeps re-sweeping and logging loudly every grace period
/// rather than abandoning a live mutating thread.
fn run_stage_with_deadline<F>(
    stage_name: &str,
    policy: &StageDeadlinePolicy,
    tree: &dyn SubprocessTreeControl,
    ledger: &StageTimeoutLedger,
    execute: F,
) -> StageOutcome
where
    F: FnOnce() -> StageOutcome + Send,
{
    // Snapshot pre-existing pids in the domain so the sweep only ever kills
    // processes this stage created. A failed snapshot degrades to an empty
    // exclusion (the sweep may then also reap earlier residue, which is
    // within our own process's descendant tree) rather than disabling
    // cancellation.
    let pre_stage: Vec<i64> = match tree.live_stage_pids(&[]) {
        Ok(pids) => pids,
        Err(err) => {
            eprintln!(
                "stage '{stage_name}': pre-stage subprocess snapshot failed ({err}); \
                 deadline sweep will treat every domain pid as stage-owned"
            );
            Vec::new()
        }
    };

    std::thread::scope(|scope| {
        let worker = scope.spawn(execute);
        let started = Instant::now();
        while !worker.is_finished() {
            let elapsed = started.elapsed();
            if elapsed >= policy.deadline {
                break;
            }
            std::thread::sleep(policy.poll.min(policy.deadline - elapsed));
        }

        if worker.is_finished() {
            return match worker.join() {
                Ok(outcome) => outcome,
                // Preserve the runner's existing panic contract: propagate so
                // its catch_unwind converts this to the canonical
                // "panicked during execute" Failed outcome.
                Err(panic) => std::panic::resume_unwind(panic),
            };
        }

        // Deadline exceeded: cancel. Kill the stage's live subprocess tree,
        // give the worker a grace window to observe its dead children and
        // return, and repeat (loudly) until it does.
        let mut report = CancellationReport {
            killed: Vec::new(),
            sweep_errors: Vec::new(),
        };
        let mut sweep = 0_u64;
        loop {
            sweep += 1;
            match tree.live_stage_pids(&pre_stage) {
                Ok(pids) => {
                    if !pids.is_empty() {
                        if let Err(err) = tree.kill_pids(&pids) {
                            report.sweep_errors.push(err);
                        }
                        for pid in pids {
                            if !report.killed.contains(&pid) {
                                report.killed.push(pid);
                            }
                        }
                    }
                }
                Err(err) => report.sweep_errors.push(err),
            }
            let grace_deadline = Instant::now() + policy.grace;
            while !worker.is_finished() && Instant::now() < grace_deadline {
                std::thread::sleep(policy.poll);
            }
            if worker.is_finished() {
                break;
            }
            eprintln!(
                "stage '{stage_name}': still running {:.0}s after its {}s deadline \
                 (cancellation sweep #{sweep}: {} subprocess(es) killed so far); re-sweeping — \
                 the worker is never detached, so a stage with no subprocess cancellation \
                 point keeps being reported here until it returns",
                started.elapsed().as_secs_f64(),
                policy.deadline.as_secs(),
                report.killed.len()
            );
        }
        // The worker returned only because we cancelled it; its late outcome
        // (even a `Passed`) is void. Join to reap the thread, discard the
        // value, and record the terminal timeout. A post-cancellation panic
        // is swallowed into the timeout (the timeout is the root cause).
        if worker.join().is_err() {
            report
                .sweep_errors
                .push("stage worker panicked after cancellation".to_owned());
        }
        let mut summary = format!(
            "stage '{stage_name}' exceeded its {}s deadline and was cancelled; \
             {} stage subprocess(es) killed",
            policy.deadline.as_secs(),
            report.killed.len()
        );
        if !report.killed.is_empty() {
            let pids: Vec<String> = report.killed.iter().map(ToString::to_string).collect();
            summary.push_str(&format!(" (pids {})", pids.join(", ")));
        }
        if !report.sweep_errors.is_empty() {
            summary.push_str(&format!(
                "; cancellation warnings: {}",
                report.sweep_errors.join("; ")
            ));
        }
        summary.push_str("; recorded as terminal timed_out (fail-closed)");
        ledger.record(stage_name, summary.clone());
        StageOutcome::Failed(summary)
    })
}

/// Deadline-enforcing decorator around one planned stage. All plan-facing
/// metadata (`id`, `dependencies`, `fanout`, `applies_to_roles`, `always_run`)
/// forwards to the wrapped stage so plan validation, topological order,
/// skip-cascade, evidence manifests, and always-run cleanup semantics are
/// byte-identical to an unwrapped plan.
pub(crate) struct DeadlineEnforcedStage {
    inner: Box<dyn OrchestrationStage>,
    policy: StageDeadlinePolicy,
    tree: Arc<dyn SubprocessTreeControl>,
    ledger: Arc<StageTimeoutLedger>,
}

impl OrchestrationStage for DeadlineEnforcedStage {
    fn id(&self) -> StageId {
        self.inner.id()
    }
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn dependencies(&self) -> &[StageId] {
        self.inner.dependencies()
    }
    fn applies_to_roles(&self) -> &[NodeRole] {
        self.inner.applies_to_roles()
    }
    fn fanout(&self) -> StageFanout {
        self.inner.fanout()
    }
    fn always_run(&self) -> bool {
        self.inner.always_run()
    }
    fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
        if self.policy.is_disabled() {
            return self.inner.execute(ctx);
        }
        let id = self.inner.id();
        run_stage_with_deadline(
            id.as_str(),
            &self.policy,
            self.tree.as_ref(),
            &self.ledger,
            || self.inner.execute(ctx),
        )
    }
}

/// Wrap one stage in a [`DeadlineEnforcedStage`]. With a disabled policy the
/// wrapper is still constructed but delegates `execute` directly (verified by
/// test), so callers get one uniform code path.
pub(crate) fn wrap_stage_with_deadline(
    stage: Box<dyn OrchestrationStage>,
    policy: StageDeadlinePolicy,
    tree: &Arc<dyn SubprocessTreeControl>,
    ledger: &Arc<StageTimeoutLedger>,
) -> Box<dyn OrchestrationStage> {
    Box::new(DeadlineEnforcedStage {
        inner: stage,
        policy,
        tree: Arc::clone(tree),
        ledger: Arc::clone(ledger),
    })
}

/// Apply the per-stage deadline policy to a whole plan. `timeout == 0`
/// returns the plan untouched — the documented "no deadline" contract.
pub(crate) fn apply_stage_deadlines(
    stages: Vec<Box<dyn OrchestrationStage>>,
    policy: StageDeadlinePolicy,
    tree: &Arc<dyn SubprocessTreeControl>,
    ledger: &Arc<StageTimeoutLedger>,
) -> Vec<Box<dyn OrchestrationStage>> {
    if policy.is_disabled() {
        return stages;
    }
    stages
        .into_iter()
        .map(|stage| wrap_stage_with_deadline(stage, policy, tree, ledger))
        .collect()
}

/// Mirror of `evidence::registry_severity_str` (private to the evidence
/// module): the registry severity string for a stage, defaulting `hard` for
/// an unregistered name.
fn timed_out_registry_severity(stage: &str) -> &'static str {
    match crate::live_lab_stage_registry::find_stage(stage).map(|spec| spec.severity) {
        Some(crate::live_lab_stage_registry::StageSeverity::Soft) => "soft",
        _ => "hard",
    }
}

/// [`StageObserver`] wrapper that records a deadline-cancelled stage's
/// terminal `stages.tsv` row with the registry's closed-taxonomy `timed_out`
/// status (via the SAME shared recorder primitive the inner recorder uses —
/// `live_lab_stage_recorder::record_stage_finish`) instead of the generic
/// `fail` the inner recorder would derive from `StageOutcome::Failed`. Every
/// other event delegates verbatim. Only a `Failed` outcome may be relabelled
/// `timed_out`: a ledger entry can never upgrade or downgrade any other
/// outcome (fail-closed).
pub(crate) struct TimeoutAwareStageRecorder<'a> {
    inner: &'a RustNativeStageRecorder<'a>,
    ledger: Arc<StageTimeoutLedger>,
}

impl<'a> TimeoutAwareStageRecorder<'a> {
    pub(crate) fn new(
        inner: &'a RustNativeStageRecorder<'a>,
        ledger: Arc<StageTimeoutLedger>,
    ) -> Self {
        TimeoutAwareStageRecorder { inner, ledger }
    }
}

impl StageObserver for TimeoutAwareStageRecorder<'_> {
    fn stage_started(&self, id: &StageId) {
        self.inner.stage_started(id);
    }

    fn stage_finished(&self, id: &StageId, outcome: &StageOutcome) {
        let name = id.as_str();
        let timed_out_summary = match outcome {
            StageOutcome::Failed(_) => self.ledger.timed_out_summary(name),
            _ => None,
        };
        let Some(summary) = timed_out_summary else {
            self.inner.stage_finished(id, outcome);
            return;
        };
        // Terminal `timed_out` row. Field shape mirrors the inner recorder's
        // terminal-row emission exactly (same log path scheme, same severity
        // source, same started_at continuity); rc 124 is the conventional
        // timeout exit code. Recorder failures are accumulated on the inner
        // recorder's error sink so evidence finalization still fails loud.
        let status = crate::live_lab_stage_registry::StageStatus::TimedOut.as_str();
        let log_path = self
            .inner
            .report_dir
            .join("logs")
            .join(format!("{name}.log"));
        if let Some(parent) = log_path.parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            self.inner.errors.borrow_mut().push(format!(
                "create log directory for stage '{name}' failed: {err}"
            ));
        }
        if let Err(err) = fs::write(
            &log_path,
            format!("[stage:{name}] {status} (rust --node engine)\n{summary}\n"),
        ) {
            self.inner.errors.borrow_mut().push(format!(
                "write terminal log for stage '{name}' failed: {err}"
            ));
        }
        let started = self
            .inner
            .started_at
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or_default();
        let now = collected_at_utc_now();
        if let Err(err) = crate::live_lab_stage_recorder::record_stage_finish(
            self.inner.report_dir,
            name,
            timed_out_registry_severity(name),
            status,
            "124",
            &log_path.to_string_lossy(),
            &summary,
            &started,
            &now,
        ) {
            self.inner.errors.borrow_mut().push(format!(
                "record terminal timed_out outcome for stage '{name}' failed: {err}"
            ));
        }
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use crate::vm_lab::orchestrator::runner::StateMachineRunner;
    use std::cell::RefCell;
    use std::collections::HashMap;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicI64, Ordering};

    fn make_ctx(report_dir: PathBuf) -> OrchestrationContext {
        OrchestrationContext::new(Vec::new(), report_dir, "rnq07-net".to_owned())
    }

    /// `kill -0 <pid>` liveness probe (exit 0 = the process still exists).
    fn pid_alive(pid: i64) -> bool {
        Command::new("kill")
            .arg("-0")
            .arg(pid.to_string())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
    }

    /// A stage that spawns `sleep <secs>` and BLOCKS on it. If the child is
    /// killed (deadline cancellation), `wait` returns and the stage returns
    /// `outcome` — which the deadline path must then VOID in favor of a
    /// terminal timeout. `secs == 0` returns almost immediately (under-deadline
    /// case). The spawned child's pid is published so a scoped tree control can
    /// target exactly it.
    struct SleepBlockingStage {
        id: StageId,
        deps: Vec<StageId>,
        secs: u64,
        outcome: StageOutcome,
        always_run: bool,
        spawned_pid: Arc<AtomicI64>,
    }

    impl OrchestrationStage for SleepBlockingStage {
        fn id(&self) -> StageId {
            self.id.clone()
        }
        fn name(&self) -> &str {
            "sleep-blocking"
        }
        fn dependencies(&self) -> &[StageId] {
            &self.deps
        }
        fn applies_to_roles(&self) -> &[NodeRole] {
            &[]
        }
        fn fanout(&self) -> StageFanout {
            StageFanout::Once
        }
        fn always_run(&self) -> bool {
            self.always_run
        }
        fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
            let mut child = match Command::new("sleep").arg(self.secs.to_string()).spawn() {
                Ok(child) => child,
                Err(err) => return StageOutcome::Failed(format!("spawn sleep failed: {err}")),
            };
            self.spawned_pid
                .store(i64::from(child.id()), Ordering::SeqCst);
            // Block until the child exits or is killed, then reap it (no orphan).
            let _ = child.wait();
            self.outcome.clone()
        }
    }

    /// A [`SubprocessTreeControl`] scoped to exactly one published pid, so a
    /// concurrent `cargo test` process's unrelated children are never killed by
    /// these tests (unlike the production `OrchestratorSubprocessTree`, which
    /// sweeps the whole real process tree).
    struct ScopedPidTree {
        pid: Arc<AtomicI64>,
    }

    impl SubprocessTreeControl for ScopedPidTree {
        fn live_stage_pids(&self, exclude: &[i64]) -> Result<Vec<i64>, String> {
            let pid = self.pid.load(Ordering::SeqCst);
            if pid <= 0 || exclude.contains(&pid) || !pid_alive(pid) {
                return Ok(Vec::new());
            }
            Ok(vec![pid])
        }
        fn kill_pids(&self, pids: &[i64]) -> Result<(), String> {
            sigkill_pids(pids)
        }
    }

    fn tsv_row<'a>(body: &'a str, stage: &str) -> Vec<&'a str> {
        body.lines()
            .find(|line| line.starts_with(&format!("{stage}\t")))
            .map(|line| line.split('\t').collect())
            .unwrap_or_default()
    }

    // ── descendant_kill_set (pure) ────────────────────────────────────────────

    #[test]
    fn descendant_kill_set_collects_transitive_children_and_prunes_excluded_subtrees() {
        // 100 (orchestrator root) -> 200 -> {300, 301}; 999 unrelated (ppid 1).
        let table = vec![
            ProcessRecord {
                pid: 200,
                ppid: 100,
            },
            ProcessRecord {
                pid: 300,
                ppid: 200,
            },
            ProcessRecord {
                pid: 301,
                ppid: 200,
            },
            ProcessRecord { pid: 999, ppid: 1 },
        ];
        // Descendants of the root, root itself excluded.
        assert_eq!(
            descendant_kill_set(&table, &[100], false, &HashSet::new()),
            vec![200, 300, 301]
        );
        // Excluding a pid prunes its whole subtree (pre-stage residue is not ours).
        let exclude: HashSet<i64> = [200].into_iter().collect();
        assert!(
            descendant_kill_set(&table, &[100], false, &exclude).is_empty(),
            "an excluded subtree must be pruned whole"
        );
        // include_roots yields the root too.
        assert_eq!(
            descendant_kill_set(&table, &[200], true, &HashSet::new()),
            vec![200, 300, 301]
        );
    }

    #[test]
    fn descendant_kill_set_never_targets_init_or_pid_zero() {
        // A corrupt table claiming pid 0/1 are children must never yield them.
        let table = vec![
            ProcessRecord { pid: 1, ppid: 100 },
            ProcessRecord { pid: 0, ppid: 100 },
            ProcessRecord {
                pid: 200,
                ppid: 100,
            },
        ];
        assert_eq!(
            descendant_kill_set(&table, &[100], false, &HashSet::new()),
            vec![200]
        );
        // Even a root of pid 1 (init) returns nothing.
        assert!(
            descendant_kill_set(&table, &[1], true, &HashSet::new()).is_empty(),
            "init must never be in a kill set"
        );
    }

    #[test]
    fn production_tree_enumerates_the_real_process_table_without_killing() {
        // Smoke: the real ps/descendant path enumerates live pids. Exclude
        // everything it returns so nothing is ever killed by this test.
        let tree = OrchestratorSubprocessTree::for_current_process();
        let first = tree
            .live_stage_pids(&[])
            .expect("ps sweep must succeed on a unix host");
        let excluded = tree
            .live_stage_pids(&first)
            .expect("second sweep must succeed");
        assert!(
            excluded.iter().all(|pid| !first.contains(pid)),
            "excluding the first sweep's pids must remove them from the second"
        );
    }

    // ── timeout == 0 → no deadline (unchanged behavior) ───────────────────────

    #[test]
    fn zero_timeout_is_disabled_and_leaves_the_plan_untouched() {
        let policy = StageDeadlinePolicy::for_timeout_secs(0);
        assert!(policy.is_disabled(), "timeout 0 must disable the deadline");

        let tree: Arc<dyn SubprocessTreeControl> = Arc::new(ScopedPidTree {
            pid: Arc::new(AtomicI64::new(0)),
        });
        let ledger = Arc::new(StageTimeoutLedger::default());
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![Box::new(SleepBlockingStage {
            id: StageId::Preflight,
            deps: Vec::new(),
            secs: 0,
            outcome: StageOutcome::Passed,
            always_run: false,
            spawned_pid: Arc::new(AtomicI64::new(0)),
        })];
        let wrapped = apply_stage_deadlines(stages, policy, &tree, &ledger);
        assert_eq!(wrapped.len(), 1, "disabled policy must not add/drop stages");
        assert_eq!(
            wrapped[0].id(),
            StageId::Preflight,
            "disabled policy must preserve plan identity/order"
        );

        // A disabled wrapper delegates execute directly; the ledger stays empty.
        let disabled = wrap_stage_with_deadline(
            Box::new(SleepBlockingStage {
                id: StageId::Preflight,
                deps: Vec::new(),
                secs: 0,
                outcome: StageOutcome::Passed,
                always_run: false,
                spawned_pid: Arc::new(AtomicI64::new(0)),
            }),
            policy,
            &tree,
            &ledger,
        );
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            disabled.execute(&mut make_ctx(dir.path().to_path_buf())),
            StageOutcome::Passed
        );
        assert!(ledger.timed_out_summary("preflight").is_none());
    }

    // ── under-deadline stage is unaffected ────────────────────────────────────

    #[test]
    fn under_deadline_stage_runs_normally_and_is_not_marked_timed_out() {
        let pid = Arc::new(AtomicI64::new(0));
        let tree: Arc<dyn SubprocessTreeControl> = Arc::new(ScopedPidTree {
            pid: Arc::clone(&pid),
        });
        let ledger = Arc::new(StageTimeoutLedger::default());
        // 30s budget, sleep 0 → finishes far under the deadline.
        let policy = StageDeadlinePolicy {
            deadline: Duration::from_secs(30),
            poll: Duration::from_millis(20),
            grace: Duration::from_millis(100),
        };
        let stage = wrap_stage_with_deadline(
            Box::new(SleepBlockingStage {
                id: StageId::Preflight,
                deps: Vec::new(),
                secs: 0,
                outcome: StageOutcome::Passed,
                always_run: false,
                spawned_pid: Arc::clone(&pid),
            }),
            policy,
            &tree,
            &ledger,
        );
        let dir = tempfile::tempdir().expect("tempdir");
        assert_eq!(
            stage.execute(&mut make_ctx(dir.path().to_path_buf())),
            StageOutcome::Passed,
            "an under-deadline stage keeps its real outcome"
        );
        assert!(
            ledger.timed_out_summary("preflight").is_none(),
            "an under-deadline stage must not be recorded as timed out"
        );
    }

    // ── over-deadline: cancelled + reaped + timed_out + run fails ──────────────

    #[test]
    fn over_deadline_stage_is_cancelled_reaped_timed_out_and_cleanup_still_runs() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report_dir = dir.path().to_path_buf();

        let pid = Arc::new(AtomicI64::new(0));
        let tree: Arc<dyn SubprocessTreeControl> = Arc::new(ScopedPidTree {
            pid: Arc::clone(&pid),
        });
        let ledger = Arc::new(StageTimeoutLedger::default());
        // 400ms budget; the stage blocks on `sleep 300` → must be cancelled.
        let policy = StageDeadlinePolicy {
            deadline: Duration::from_millis(400),
            poll: Duration::from_millis(50),
            grace: Duration::from_millis(150),
        };

        let plan: Vec<Box<dyn OrchestrationStage>> = vec![
            Box::new(SleepBlockingStage {
                id: StageId::Preflight,
                deps: Vec::new(),
                secs: 300,
                outcome: StageOutcome::Passed, // must be VOIDED by the timeout
                always_run: false,
                spawned_pid: Arc::clone(&pid),
            }),
            // always_run cleanup depending on the timed-out stage must STILL run.
            Box::new(SleepBlockingStage {
                id: StageId::Cleanup,
                deps: vec![StageId::Preflight],
                secs: 0,
                outcome: StageOutcome::Passed,
                always_run: true,
                spawned_pid: Arc::new(AtomicI64::new(0)),
            }),
        ];
        let stages = apply_stage_deadlines(plan, policy, &tree, &ledger);
        let runner = StateMachineRunner::new(stages).expect("valid plan");

        let recorder = RustNativeStageRecorder {
            report_dir: report_dir.as_path(),
            started_at: RefCell::new(HashMap::new()),
            errors: RefCell::new(Vec::new()),
        };
        let observer = TimeoutAwareStageRecorder::new(&recorder, Arc::clone(&ledger));
        let mut ctx = make_ctx(report_dir.clone());
        let results = runner
            .run_with_observer(&mut ctx, &observer)
            .expect("run must complete (cancellation unblocks the stage)");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        // 1) The over-deadline stage is a terminal FAILURE (fail-closed).
        assert!(
            matches!(
                outcome_of(&StageId::Preflight),
                Some(StageOutcome::Failed(_))
            ),
            "an over-deadline stage must fail closed, never pass: {:?}",
            outcome_of(&StageId::Preflight)
        );
        // 2) The run fails (at least one failed stage).
        assert!(
            results
                .iter()
                .any(|(_, o)| matches!(o, StageOutcome::Failed(_))),
            "a timeout must make the run fail"
        );
        // 3) The ledger marked it timed out.
        assert!(
            ledger.timed_out_summary("preflight").is_some(),
            "the deadline path must record the stage in the timeout ledger"
        );
        // 4) The subprocess tree was reaped — no orphaned `sleep`.
        let sleep_pid = pid.load(Ordering::SeqCst);
        assert!(sleep_pid > 0, "the stage must have spawned its child");
        assert!(
            !pid_alive(sleep_pid),
            "the cancelled stage's subprocess (pid {sleep_pid}) must be reaped, not orphaned"
        );
        // 5) always_run cleanup still executed.
        assert_eq!(
            outcome_of(&StageId::Cleanup),
            Some(&StageOutcome::Passed),
            "always_run cleanup MUST run after a timed-out dependency"
        );

        // 6) The recorded terminal row speaks the closed-taxonomy `timed_out`
        //    status (not a generic `fail`), rc 124, and no recorder errors.
        assert!(
            recorder.take_errors().is_empty(),
            "the timeout-aware recorder must not accumulate recording errors"
        );
        let stages_tsv = std::fs::read_to_string(report_dir.join("state/stages.tsv"))
            .expect("stages.tsv must exist");
        let preflight = tsv_row(&stages_tsv, "preflight");
        assert_eq!(
            preflight.get(2).copied(),
            Some("timed_out"),
            "the cancelled stage's terminal status must be timed_out: {preflight:?}"
        );
        assert_eq!(
            preflight.get(3).copied(),
            Some("124"),
            "a timed-out stage records the conventional 124 rc"
        );
        let cleanup = tsv_row(&stages_tsv, "cleanup");
        assert_eq!(
            cleanup.get(2).copied(),
            Some("pass"),
            "cleanup must record a normal pass, unaffected by the timeout relabel"
        );
    }
}
