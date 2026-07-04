#![allow(dead_code)]
use std::collections::{HashMap, HashSet};

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

/// Drives stages in dependency order with skip-cascade.
///
/// Skip-cascade rule: if a stage fails or is skipped, every stage that lists
/// it in `dependencies()` is also skipped (recursively).
pub struct StateMachineRunner {
    stages: Vec<Box<dyn OrchestrationStage>>,
    /// Stage IDs explicitly requested to skip via `--skip-stage`.
    explicit_skips: HashSet<StageId>,
}

impl StateMachineRunner {
    pub fn new(stages: Vec<Box<dyn OrchestrationStage>>) -> Self {
        StateMachineRunner {
            stages,
            explicit_skips: HashSet::new(),
        }
    }

    pub fn with_explicit_skips(mut self, skips: impl IntoIterator<Item = StageId>) -> Self {
        self.explicit_skips.extend(skips);
        self
    }

    /// Execute all stages in dependency order, applying skip-cascade.
    /// Returns a list of (`StageId`, `StageOutcome`) in execution order.
    pub fn run(&self, ctx: &mut OrchestrationContext) -> Vec<(StageId, StageOutcome)> {
        self.run_with_observer(ctx, &NoopObserver)
    }

    /// Like [`run`](Self::run) but notifies `observer` of each stage's start
    /// (before execute) and finish (after outcome, including skips) — the seam
    /// the `--node` path uses to emit realtime `stages.tsv` rows.
    pub fn run_with_observer(
        &self,
        ctx: &mut OrchestrationContext,
        observer: &dyn StageObserver,
    ) -> Vec<(StageId, StageOutcome)> {
        let ordered = topological_order(&self.stages);
        let mut results: Vec<(StageId, StageOutcome)> = Vec::new();
        let mut blocked: HashSet<StageId> = self.explicit_skips.clone();

        for idx in ordered {
            let stage = &self.stages[idx];
            let id = stage.id();

            if blocked.contains(&id) {
                observer.stage_finished(&id, &StageOutcome::Skipped);
                results.push((id.clone(), StageOutcome::Skipped));
                ctx.record_outcome(id, StageOutcome::Skipped);
                continue;
            }

            let dep_blocked = stage.dependencies().iter().any(|dep| {
                blocked.contains(dep)
                    || ctx
                        .outcome_of(dep)
                        .is_some_and(super::error::StageOutcome::is_blocking)
            });

            if dep_blocked {
                blocked.insert(id.clone());
                observer.stage_finished(&id, &StageOutcome::Skipped);
                results.push((id.clone(), StageOutcome::Skipped));
                ctx.record_outcome(id, StageOutcome::Skipped);
                continue;
            }

            observer.stage_started(&id);
            let outcome = stage.execute(ctx);

            if outcome.is_blocking() {
                blocked.insert(id.clone());
            }

            observer.stage_finished(&id, &outcome);
            ctx.record_outcome(id.clone(), outcome.clone());
            results.push((id, outcome));
        }

        results
    }
}

/// Topological sort of stages by `dependencies()`.
/// Returns indices into `stages` in dependency-first order.
/// Stages with no dependency relationship preserve insertion order.
fn topological_order(stages: &[Box<dyn OrchestrationStage>]) -> Vec<usize> {
    let id_to_idx: HashMap<StageId, usize> = stages
        .iter()
        .enumerate()
        .map(|(i, s)| (s.id(), i))
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

    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| in_degree[i] == 0).collect();

    let mut order = Vec::with_capacity(n);
    while let Some(node) = queue.pop_front() {
        order.push(node);
        for &next in &adj[node] {
            in_degree[next] -= 1;
            if in_degree[next] == 0 {
                queue.push_back(next);
            }
        }
    }

    // Append any nodes not reached (cycles or missing deps) at the end.
    // In practice the stage list is acyclic; this is a safety net.
    if order.len() < n {
        for i in 0..n {
            if !order.contains(&i) {
                order.push(i);
            }
        }
    }

    order
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
            self.outcome.clone()
        }
    }

    fn pass_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "pass",
            deps,
            outcome: StageOutcome::Passed,
        })
    }

    fn fail_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "fail",
            deps,
            outcome: StageOutcome::Failed("test failure".to_owned()),
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
        let runner = StateMachineRunner::new(stages);
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx);

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
    fn observer_sees_start_then_finish_for_executed_stages_and_only_finish_for_skips() {
        use std::cell::RefCell;
        #[derive(Default)]
        struct RecordingObserver {
            events: RefCell<Vec<(String, &'static str)>>,
        }
        impl StageObserver for RecordingObserver {
            fn stage_started(&self, id: &StageId) {
                self.events.borrow_mut().push((id.as_str().to_owned(), "start"));
            }
            fn stage_finished(&self, id: &StageId, _outcome: &StageOutcome) {
                self.events.borrow_mut().push((id.as_str().to_owned(), "finish"));
            }
        }

        // A (fail) → B (skipped via cascade); C (pass, independent).
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            fail_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            pass_stage(StageId::CleanupHosts, vec![]),
        ];
        let runner = StateMachineRunner::new(stages);
        let mut ctx = make_ctx();
        let observer = RecordingObserver::default();
        runner.run_with_observer(&mut ctx, &observer);
        let events = observer.events.borrow();

        // An executed stage emits start then finish.
        for executed in ["preflight", "cleanup_hosts"] {
            let start = events.iter().position(|(n, e)| n == executed && *e == "start");
            let finish = events.iter().position(|(n, e)| n == executed && *e == "finish");
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
        let runner = StateMachineRunner::new(stages);
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx);

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
        let runner = StateMachineRunner::new(stages);
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx);

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
        let runner = StateMachineRunner::new(stages).with_explicit_skips([StageId::Preflight]);
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx);

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(
            outcome_of(&StageId::Preflight),
            Some(&StageOutcome::Skipped)
        );
        assert_eq!(
            outcome_of(&StageId::PrepareSourceArchive),
            Some(&StageOutcome::Skipped),
            "dependent of explicitly-skipped stage must also be skipped"
        );
    }
}
