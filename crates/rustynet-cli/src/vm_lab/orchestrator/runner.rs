#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageId};

/// Notified as each stage starts and finishes so a caller can emit realtime
/// per-stage status (the recorder's `running`/terminal `stages.tsv` rows)
/// WITHOUT the runner depending on the recording layer. `stage_started` fires
/// immediately before a stage executes; `stage_finished` fires for every
/// stage including the skip-cascade branches (which never "start").
pub trait StageObserver {
    fn stage_started(&self, id: &StageId);
    fn stage_finished(&self, id: &StageId, outcome: &StageOutcome);
}

/// The default observer for callers (and tests) that don't record realtime.
struct NoopObserver;
impl StageObserver for NoopObserver {
    fn stage_started(&self, _id: &StageId) {}
    fn stage_finished(&self, _id: &StageId, _outcome: &StageOutcome) {}
}

type PreCleanupHook<'a> =
    dyn Fn(&OrchestrationContext, &[(StageId, StageOutcome)]) -> Result<(), String> + 'a;

/// Drives stages in dependency order with skip-cascade.
///
/// Skip-cascade rule: if a stage fails or is skipped, every stage that lists
/// it in `dependencies()` is also skipped (recursively).
pub struct StateMachineRunner {
    stages: Vec<Box<dyn OrchestrationStage>>,
    /// Stage IDs explicitly requested to skip via `--skip-stage`.
    explicit_skips: HashSet<StageId>,
    reused_skips: HashMap<StageId, String>,
    /// When set, the runner checks this flag before each stage. On true, it
    /// skips non-`always_run` stages and runs teardown stages so the guest
    /// killswitch/NAT residue is cleaned up even after a SIGTERM/SIGINT.
    shutdown_flag: Option<Arc<AtomicBool>>,
}

impl StateMachineRunner {
    pub fn new(stages: Vec<Box<dyn OrchestrationStage>>) -> Result<Self, String> {
        validate_plan(&stages)?;
        Ok(StateMachineRunner {
            stages,
            explicit_skips: HashSet::new(),
            reused_skips: HashMap::new(),
            shutdown_flag: None,
        })
    }

    pub fn with_explicit_skips(mut self, skips: impl IntoIterator<Item = StageId>) -> Self {
        self.explicit_skips.extend(skips);
        self
    }

    /// Mark selected skips as satisfied by validated prior evidence. The
    /// digest binds every reused outcome to that evidence; unlisted explicit
    /// skips remain `NotRun` and block their dependents.
    pub fn with_reused_skips(
        mut self,
        skips: impl IntoIterator<Item = StageId>,
        evidence_sha256: String,
    ) -> Self {
        for id in skips {
            self.explicit_skips.insert(id.clone());
            self.reused_skips.insert(id, evidence_sha256.clone());
        }
        self
    }

    pub fn with_shutdown_flag(mut self, flag: Arc<AtomicBool>) -> Self {
        self.shutdown_flag = Some(flag);
        self
    }

    /// Execute all stages in dependency order, applying skip-cascade.
    /// Returns a list of (`StageId`, `StageOutcome`) in execution order.
    pub fn run(
        &self,
        ctx: &mut OrchestrationContext,
    ) -> Result<Vec<(StageId, StageOutcome)>, String> {
        self.run_with_observer(ctx, &NoopObserver)
    }

    /// Like [`run`](Self::run) but notifies `observer` of each stage's start
    /// (before execute) and finish (after outcome, including skips) — the seam
    /// the `--node` path uses to emit realtime `stages.tsv` rows.
    pub fn run_with_observer(
        &self,
        ctx: &mut OrchestrationContext,
        observer: &dyn StageObserver,
    ) -> Result<Vec<(StageId, StageOutcome)>, String> {
        self.run_with_observer_and_pre_cleanup_hook(ctx, observer, None)
    }

    /// Run with an optional hook invoked immediately before the first
    /// `always_run` teardown stage. This lets callers capture failure
    /// diagnostics while runtime state still exists, without weakening the
    /// guarantee that cleanup runs even when capture itself fails.
    pub fn run_with_observer_and_pre_cleanup_hook(
        &self,
        ctx: &mut OrchestrationContext,
        observer: &dyn StageObserver,
        pre_cleanup_hook: Option<&PreCleanupHook<'_>>,
    ) -> Result<Vec<(StageId, StageOutcome)>, String> {
        let ordered = topological_order(&self.stages)?;
        let mut results: Vec<(StageId, StageOutcome)> = Vec::new();
        let mut blocked: HashSet<StageId> = HashSet::new();
        let mut hook_ran = false;
        let mut hook_error: Option<String> = None;

        for idx in ordered {
            let stage = &self.stages[idx];
            let id = stage.id();

            if stage.always_run() && !hook_ran {
                hook_ran = true;
                if let Some(hook) = pre_cleanup_hook
                    && let Err(err) = hook(ctx, &results)
                {
                    hook_error = Some(err);
                }
            }

            if self.explicit_skips.contains(&id) {
                let outcome = self
                    .reused_skips
                    .get(&id)
                    .map_or(StageOutcome::NotRun, |digest| StageOutcome::Reused {
                        evidence_sha256: digest.clone(),
                    });
                if outcome.is_blocking() || matches!(outcome, StageOutcome::Skipped) {
                    blocked.insert(id.clone());
                }
                observer.stage_finished(&id, &outcome);
                results.push((id.clone(), outcome.clone()));
                ctx.record_outcome(id, outcome);
                continue;
            }

            let dep_blocked = stage.dependencies().iter().any(|dep| {
                blocked.contains(dep)
                    || ctx
                        .outcome_of(dep)
                        .is_some_and(super::error::StageOutcome::is_blocking)
            });

            // `always_run` teardown stages (e.g. final cleanup) are exempt from
            // the dependency skip-cascade: they must run even when an earlier
            // stage failed, so this run's killswitch / exit-NAT residue is
            // always removed from the guests (leaving it is a release-blocker).
            // They still respect the explicit-skip set handled above.
            if dep_blocked && !stage.always_run() {
                blocked.insert(id.clone());
                observer.stage_finished(&id, &StageOutcome::Skipped);
                results.push((id.clone(), StageOutcome::Skipped));
                ctx.record_outcome(id, StageOutcome::Skipped);
                continue;
            }

            // Shutdown-requested: skip non-teardown stages but still run
            // `always_run` cleanup stages so guest killswitch/NAT residue is
            // torn down (leaving it is a release-blocker per F5-4).
            if let Some(ref flag) = self.shutdown_flag
                && flag.load(Ordering::Acquire)
                && !stage.always_run()
            {
                observer.stage_finished(&id, &StageOutcome::Skipped);
                results.push((id.clone(), StageOutcome::Skipped));
                ctx.record_outcome(id, StageOutcome::Skipped);
                continue;
            }

            observer.stage_started(&id);
            // Guard `execute` so a panicking stage becomes a `Failed` outcome
            // instead of unwinding out of the runner — otherwise a panic would
            // abort past finalize AND skip the always-run cleanup, the worst
            // residue case. The mutable `ctx` borrow ends when `catch_unwind`
            // returns; `assignments`/`adapters` (all cleanup needs) are set
            // before the run and untouched by stage execution.
            let mut outcome =
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| stage.execute(ctx)))
                    .unwrap_or_else(|_| {
                        StageOutcome::Failed(format!(
                            "stage '{}' panicked during execute",
                            id.as_str()
                        ))
                    });

            if stage.always_run()
                && let Some(diagnostic_error) = hook_error.take()
            {
                outcome = match outcome {
                    StageOutcome::Failed(cleanup_error) => StageOutcome::Failed(format!(
                        "pre-cleanup diagnostics failed: {diagnostic_error}; cleanup failed: {cleanup_error}"
                    )),
                    _ => StageOutcome::Failed(format!(
                        "pre-cleanup diagnostics failed: {diagnostic_error}; cleanup completed"
                    )),
                };
            }

            if outcome.is_blocking() {
                blocked.insert(id.clone());
            }

            observer.stage_finished(&id, &outcome);
            ctx.record_outcome(id.clone(), outcome.clone());
            results.push((id, outcome));
        }

        Ok(results)
    }
}

/// Topological sort of stages by `dependencies()`.
/// Returns indices into `stages` in dependency-first order.
/// Stages with no dependency relationship preserve insertion order.
fn validate_plan(stages: &[Box<dyn OrchestrationStage>]) -> Result<(), String> {
    let mut ids = HashSet::with_capacity(stages.len());
    for stage in stages {
        let id = stage.id();
        if !ids.insert(id.clone()) {
            return Err(format!(
                "orchestration plan contains duplicate stage '{}'",
                id.as_str()
            ));
        }
    }
    for stage in stages {
        for dependency in stage.dependencies() {
            if !ids.contains(dependency) {
                return Err(format!(
                    "orchestration stage '{}' depends on missing stage '{}'",
                    stage.id().as_str(),
                    dependency.as_str()
                ));
            }
        }
    }
    topological_order_unchecked(stages).map(|_| ())
}

fn topological_order(stages: &[Box<dyn OrchestrationStage>]) -> Result<Vec<usize>, String> {
    validate_plan(stages)?;
    topological_order_unchecked(stages)
}

fn topological_order_unchecked(
    stages: &[Box<dyn OrchestrationStage>],
) -> Result<Vec<usize>, String> {
    let id_to_idx: HashMap<StageId, usize> = stages
        .iter()
        .enumerate()
        .map(|(i, stage)| (stage.id(), i))
        .collect();

    let n = stages.len();
    let mut in_degree: Vec<usize> = vec![0; n];
    let mut adj: Vec<Vec<usize>> = vec![vec![]; n];

    for (i, stage) in stages.iter().enumerate() {
        for dep in stage.dependencies() {
            if let Some(&dep_idx) = id_to_idx.get(dep) {
                adj[dep_idx].push(i);
                in_degree[i] += 1;
            }
        }
    }

    let mut ready: std::collections::BTreeSet<usize> =
        (0..n).filter(|&i| in_degree[i] == 0).collect();

    let mut order = Vec::with_capacity(n);
    while let Some(node) = ready.pop_first() {
        order.push(node);
        for &next in &adj[node] {
            in_degree[next] -= 1;
            if in_degree[next] == 0 {
                ready.insert(next);
            }
        }
    }

    if order.len() < n {
        let cyclic = (0..n)
            .filter(|index| !order.contains(index))
            .map(|index| stages[index].id().as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "orchestration plan contains dependency cycle: {cyclic}"
        ));
    }

    Ok(order)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::orchestrator::stage::StageFanout;
    use std::path::PathBuf;

    // ── Mock stage helpers ────────────────────────────────────────────────────

    struct MockStage {
        id: StageId,
        name: &'static str,
        deps: Vec<StageId>,
        outcome: StageOutcome,
        always_run: bool,
        panics: bool,
    }

    impl OrchestrationStage for MockStage {
        fn id(&self) -> StageId {
            self.id.clone()
        }
        fn name(&self) -> &str {
            self.name
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
        fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
            assert!(
                !self.panics,
                "mock stage '{}' panicking on purpose",
                self.name
            );
            self.outcome.clone()
        }
        fn always_run(&self) -> bool {
            self.always_run
        }
    }

    fn pass_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "pass",
            deps,
            outcome: StageOutcome::Passed,
            always_run: false,
            panics: false,
        })
    }

    fn fail_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "fail",
            deps,
            outcome: StageOutcome::Failed("test failure".to_owned()),
            always_run: false,
            panics: false,
        })
    }

    /// A teardown stage (`always_run = true`) that passes when it executes —
    /// used to prove cleanup runs despite a failed/panicking dependency.
    fn always_run_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "always_run",
            deps,
            outcome: StageOutcome::Passed,
            always_run: true,
            panics: false,
        })
    }

    /// A stage that panics inside `execute` — used to prove the runner's
    /// panic guard converts it to `Failed` instead of aborting the run.
    fn panic_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "panic",
            deps,
            outcome: StageOutcome::Passed,
            always_run: false,
            panics: true,
        })
    }

    fn make_ctx() -> OrchestrationContext {
        OrchestrationContext::new(
            vec![],
            PathBuf::from("/tmp/test-report"),
            "test-net".to_owned(),
        )
    }

    // ── Skip-cascade tests ────────────────────────────────────────────────────

    #[test]
    fn skip_cascade_blocks_dependents_of_failing_stage() {
        // A (pass) → B (fail) → C (should be skipped)
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            fail_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            pass_stage(
                StageId::VerifySshReachability,
                vec![StageId::PrepareSourceArchive],
            ),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        assert_eq!(results.len(), 3);

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(outcome_of(&StageId::Preflight), Some(&StageOutcome::Passed));
        assert!(
            matches!(
                outcome_of(&StageId::PrepareSourceArchive),
                Some(StageOutcome::Failed(_))
            ),
            "expected Failed for PrepareSourceArchive"
        );
        assert_eq!(
            outcome_of(&StageId::VerifySshReachability),
            Some(&StageOutcome::Skipped),
            "stage depending on failed stage must be skipped"
        );
    }

    #[test]
    fn always_run_stage_runs_even_when_dependency_failed() {
        // A(pass) → B(fail) → cleanup(always_run, depends on B).
        // cleanup must STILL run (Passed), not be cascade-skipped — otherwise a
        // mid-pipeline failure leaves killswitch/NAT residue on the guests.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            fail_stage(StageId::ExitHandoff, vec![StageId::Preflight]),
            always_run_stage(StageId::Cleanup, vec![StageId::ExitHandoff]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut make_ctx())
            .expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);
        assert!(matches!(
            outcome_of(&StageId::ExitHandoff),
            Some(StageOutcome::Failed(_))
        ));
        assert_eq!(
            outcome_of(&StageId::Cleanup),
            Some(&StageOutcome::Passed),
            "always_run cleanup MUST run despite a failed dependency"
        );
    }

    #[test]
    fn panicking_stage_becomes_failed_and_always_run_cleanup_still_executes() {
        // A stage that panics must be caught as Failed (not abort the runner),
        // and the always_run cleanup must still run afterwards.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            panic_stage(StageId::ExitHandoff, vec![]),
            always_run_stage(StageId::Cleanup, vec![StageId::ExitHandoff]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut make_ctx())
            .expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);
        assert!(
            matches!(
                outcome_of(&StageId::ExitHandoff),
                Some(StageOutcome::Failed(_))
            ),
            "a panicking stage must be converted to Failed, not abort the run"
        );
        assert_eq!(
            outcome_of(&StageId::Cleanup),
            Some(&StageOutcome::Passed),
            "always_run cleanup MUST run after a panicking stage"
        );
    }

    #[test]
    fn failure_diagnostic_hook_runs_before_cleanup_and_hook_failure_does_not_skip_cleanup() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        struct HookAwareCleanup(Arc<AtomicBool>);
        impl OrchestrationStage for HookAwareCleanup {
            fn id(&self) -> StageId {
                StageId::Cleanup
            }
            fn name(&self) -> &str {
                "cleanup"
            }
            fn dependencies(&self) -> &[StageId] {
                &[StageId::ExitHandoff]
            }
            fn applies_to_roles(&self) -> &[NodeRole] {
                &[]
            }
            fn fanout(&self) -> StageFanout {
                StageFanout::Once
            }
            fn execute(&self, _ctx: &mut OrchestrationContext) -> StageOutcome {
                assert!(self.0.load(Ordering::SeqCst), "hook must precede cleanup");
                StageOutcome::Passed
            }
            fn always_run(&self) -> bool {
                true
            }
        }

        let hook_called = Arc::new(AtomicBool::new(false));
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            fail_stage(StageId::ExitHandoff, vec![]),
            Box::new(HookAwareCleanup(Arc::clone(&hook_called))),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let hook_flag = Arc::clone(&hook_called);
        let hook = move |_ctx: &OrchestrationContext,
                         prior: &[(StageId, StageOutcome)]|
              -> Result<(), String> {
            assert!(
                prior
                    .iter()
                    .any(|(_, outcome)| matches!(outcome, StageOutcome::Failed(_)))
            );
            hook_flag.store(true, Ordering::SeqCst);
            Err("diagnostic writer failed".to_owned())
        };
        let results = runner
            .run_with_observer_and_pre_cleanup_hook(&mut make_ctx(), &NoopObserver, Some(&hook))
            .expect("run");
        assert!(hook_called.load(Ordering::SeqCst));
        assert!(matches!(
            results.last(),
            Some((StageId::Cleanup, StageOutcome::Failed(message)))
                if message.contains("diagnostic writer failed")
        ));
    }

    #[test]
    fn topological_order_prefers_original_order_for_newly_ready_stages() {
        // Regression: with the old FIFO ready queue, a late cleanup stage whose
        // dependency was filtered out by --skip-linux-live-suite started ready at
        // time zero. After preflight passed, it ran before prepare_source_archive
        // because prepare was appended behind cleanup in the queue. Cleanup must
        // stay last in the retained vector unless a real dependency says
        // otherwise.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            pass_stage(
                StageId::VerifySshReachability,
                vec![StageId::PrepareSourceArchive],
            ),
            always_run_stage(StageId::Cleanup, vec![]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut make_ctx())
            .expect("run");
        let ids: Vec<StageId> = results.into_iter().map(|(id, _)| id).collect();
        assert_eq!(
            ids,
            vec![
                StageId::Preflight,
                StageId::PrepareSourceArchive,
                StageId::VerifySshReachability,
                StageId::Cleanup,
            ]
        );
    }

    #[test]
    fn observer_sees_start_then_finish_for_executed_stages_and_only_finish_for_skips() {
        use std::cell::RefCell;
        #[derive(Default)]
        struct RecordingObserver {
            events: RefCell<Vec<(String, &'static str)>>,
        }
        impl StageObserver for RecordingObserver {
            fn stage_started(&self, id: &StageId) {
                self.events
                    .borrow_mut()
                    .push((id.as_str().to_owned(), "start"));
            }
            fn stage_finished(&self, id: &StageId, _outcome: &StageOutcome) {
                self.events
                    .borrow_mut()
                    .push((id.as_str().to_owned(), "finish"));
            }
        }

        // A (fail) → B (skipped via cascade); C (pass, independent).
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            fail_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            pass_stage(StageId::CleanupHosts, vec![]),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let mut ctx = make_ctx();
        let observer = RecordingObserver::default();
        runner.run_with_observer(&mut ctx, &observer).expect("run");
        let events = observer.events.borrow();

        // An executed stage emits start then finish.
        for executed in ["preflight", "cleanup_hosts"] {
            let start = events
                .iter()
                .position(|(n, e)| n == executed && *e == "start");
            let finish = events
                .iter()
                .position(|(n, e)| n == executed && *e == "finish");
            assert!(start.is_some(), "{executed} must start");
            assert!(
                start < finish,
                "{executed}: start must precede finish (start={start:?} finish={finish:?})"
            );
        }
        // A cascade-skipped stage finishes without ever starting — so no stray
        // `running` row is left behind.
        assert!(
            !events
                .iter()
                .any(|(n, e)| n == "prepare_source_archive" && *e == "start"),
            "a skipped stage must never emit a start (running) event"
        );
        assert!(
            events
                .iter()
                .any(|(n, e)| n == "prepare_source_archive" && *e == "finish"),
            "a skipped stage must still emit a finish (terminal) event"
        );
    }

    #[test]
    fn skip_cascade_does_not_affect_independent_stages() {
        // A (fail) → B (skip); C (no deps, should pass)
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            fail_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            pass_stage(StageId::CleanupHosts, vec![]),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert!(matches!(
            outcome_of(&StageId::Preflight),
            Some(StageOutcome::Failed(_))
        ));
        assert_eq!(
            outcome_of(&StageId::PrepareSourceArchive),
            Some(&StageOutcome::Skipped)
        );
        assert_eq!(
            outcome_of(&StageId::CleanupHosts),
            Some(&StageOutcome::Passed),
            "independent stage must not be affected by unrelated failure"
        );
    }

    // ── Dependency ordering tests ─────────────────────────────────────────────

    #[test]
    fn stages_execute_in_dependency_order_not_insertion_order() {
        // Insert in order: C (depends on A), B (no deps), A (no deps)
        // Expected execution order: A and B before C (A before C, B anywhere)
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::VerifySshReachability, vec![StageId::Preflight]),
            pass_stage(StageId::PrepareSourceArchive, vec![]),
            pass_stage(StageId::Preflight, vec![]),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let pos = |id: &StageId| results.iter().position(|(i, _)| i == id).unwrap();

        // Preflight (A) must execute before VerifySshReachability (C)
        assert!(
            pos(&StageId::Preflight) < pos(&StageId::VerifySshReachability),
            "Preflight must run before VerifySshReachability (dependency)"
        );
        // All should pass since no failures
        assert!(results.iter().all(|(_, o)| *o == StageOutcome::Passed));
    }

    // ── Explicit skip tests ───────────────────────────────────────────────────

    #[test]
    fn explicit_skip_cascades_to_dependents() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
        ];
        let runner = StateMachineRunner::new(stages)
            .expect("valid plan")
            .with_explicit_skips([StageId::Preflight]);
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(outcome_of(&StageId::Preflight), Some(&StageOutcome::NotRun));
        assert_eq!(
            outcome_of(&StageId::PrepareSourceArchive),
            Some(&StageOutcome::Skipped),
            "dependent of explicitly-skipped stage must also be skipped"
        );
    }

    #[test]
    fn validated_reused_skip_does_not_cascade_or_claim_fresh_pass() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::ValidateBaselineRuntime, vec![]),
            pass_stage(
                StageId::TrafficTestMatrix,
                vec![StageId::ValidateBaselineRuntime],
            ),
        ];
        let runner = StateMachineRunner::new(stages)
            .expect("valid plan")
            .with_reused_skips([StageId::ValidateBaselineRuntime], "abc123".to_owned());
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(
            outcome_of(&StageId::ValidateBaselineRuntime),
            Some(&StageOutcome::Reused {
                evidence_sha256: "abc123".to_owned()
            }),
            "reused setup dependency must retain its evidence binding"
        );
        assert_eq!(
            outcome_of(&StageId::TrafficTestMatrix),
            Some(&StageOutcome::Passed),
            "dependent live stage must run when setup dependency was injected Passed"
        );
    }

    #[test]
    fn duplicate_stage_ids_are_rejected_before_execution() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::Preflight, vec![]),
        ];
        let err = StateMachineRunner::new(stages)
            .err()
            .expect("duplicate IDs must fail");
        assert!(err.contains("duplicate stage 'preflight'"));
    }

    #[test]
    fn missing_dependency_is_rejected_before_execution() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![pass_stage(
            StageId::PrepareSourceArchive,
            vec![StageId::Preflight],
        )];
        let err = StateMachineRunner::new(stages)
            .err()
            .expect("missing dependency must fail");
        assert!(err.contains("depends on missing stage 'preflight'"));
    }

    #[test]
    fn dependency_cycle_is_rejected_before_execution() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![StageId::PrepareSourceArchive]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
        ];
        let err = StateMachineRunner::new(stages)
            .err()
            .expect("cycle must fail");
        assert!(err.contains("dependency cycle"));
    }
}
