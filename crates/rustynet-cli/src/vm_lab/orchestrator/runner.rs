#![allow(dead_code)]
use std::collections::{HashMap, HashSet};

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::StageOutcome;
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageId};

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
    /// Returns a list of (StageId, StageOutcome) in execution order.
    pub fn run(&self, ctx: &mut OrchestrationContext) -> Vec<(StageId, StageOutcome)> {
        let ordered = topological_order(&self.stages);
        let mut results: Vec<(StageId, StageOutcome)> = Vec::new();
        let mut blocked: HashSet<StageId> = self.explicit_skips.clone();

        for idx in ordered {
            let stage = &self.stages[idx];
            let id = stage.id();

            if blocked.contains(&id) {
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
                results.push((id.clone(), StageOutcome::Skipped));
                ctx.record_outcome(id, StageOutcome::Skipped);
                continue;
            }

            let outcome = stage.execute(ctx);

            if outcome.is_blocking() {
                blocked.insert(id.clone());
            }

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
