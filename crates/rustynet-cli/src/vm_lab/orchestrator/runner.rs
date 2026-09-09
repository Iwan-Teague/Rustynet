#![allow(dead_code)]
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use crate::vm_lab::orchestrator::context::OrchestrationContext;
use crate::vm_lab::orchestrator::error::{ReasonCode, StageOutcome};
use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageEvidence, StageId};

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

/// The result of [`StateMachineRunner::skip_decision`]: the terminal outcome to
/// record for a skipped stage, plus whether it should mark the stage `blocked`
/// so its own dependents cascade. `None` from `skip_decision` means "do not
/// skip — execute the stage".
struct SkipDecision {
    outcome: StageOutcome,
    mark_blocked: bool,
}

/// Drives stages in dependency order with skip-cascade.
///
/// Skip-cascade rule: if a stage fails or is skipped, every stage that lists
/// it in `dependencies()` is also skipped (recursively).
pub struct StateMachineRunner {
    stages: Vec<Box<dyn OrchestrationStage>>,
    /// Stage IDs explicitly requested to skip via `--skip-stage`.
    explicit_skips: HashSet<StageId>,
    reused_skips: HashMap<StageId, super::evidence::ReuseDigest>,
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
    /// digest is a pre-validated [`super::evidence::ReuseDigest`] — only
    /// `validate_rust_native_reuse_evidence` can mint one, so an arbitrary
    /// string cannot enter a `Reused` outcome (audit F2). The digest binds
    /// every reused outcome to that evidence; unlisted explicit skips remain
    /// `NotRun` and block their dependents.
    pub fn with_reused_skips(
        mut self,
        skips: impl IntoIterator<Item = StageId>,
        evidence_sha256: super::evidence::ReuseDigest,
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

            // Every skip source is funnelled through one decision so the
            // `always_run` exemption is applied EXACTLY ONCE, ahead of them all
            // (see `skip_decision`). Previously the explicit-skip branch was
            // checked before the exemption, so `--rerun-stage X` — which marks
            // every stage after X as an explicit skip — silently skipped a
            // trailing `always_run` cleanup stage and left this run's
            // killswitch/NAT residue on the guest (a release-blocker fail-open).
            if let Some(decision) = self.skip_decision(stage.as_ref(), ctx, &blocked) {
                if decision.mark_blocked {
                    blocked.insert(id.clone());
                }
                observer.stage_finished(&id, &decision.outcome);
                results.push((id.clone(), decision.outcome.clone()));
                ctx.record_outcome(id, decision.outcome);
                continue;
            }

            observer.stage_started(&id);

            // QH-83 freshness: a declared `File` witness must be produced by
            // THIS execute, never inherited from a prior invocation in the
            // same report directory (--run-only / --resume-from /
            // --rerun-stage reuse the dir, unlike a fresh run whose report
            // dir is required empty). The recorder truncates the stage log at
            // `stage_started` for exactly this reason; the `File` arm needs
            // the same clear or the witness check below could read a
            // generation-N artifact and uphold a pass this run never earned.
            // If the stale file cannot be removed the stage must NOT execute
            // (its verdict could not be trusted either way): fail closed as
            // blocking `NotProven { StaleEvidence }` so dependents cascade.
            if let StageEvidence::File(relative) = id.evidence() {
                let witness = ctx.report_dir.join(relative);
                if let Err(err) = std::fs::remove_file(&witness)
                    && err.kind() != std::io::ErrorKind::NotFound
                {
                    let outcome = StageOutcome::NotProven {
                        reason: ReasonCode::StaleEvidence,
                        detail: format!(
                            "stage '{}': stale witness '{}' from a prior generation could not be cleared before execute: {err}",
                            id.as_str(),
                            witness.display()
                        ),
                    };
                    blocked.insert(id.clone());
                    observer.stage_finished(&id, &outcome);
                    ctx.record_outcome(id.clone(), outcome.clone());
                    results.push((id, outcome));
                    continue;
                }
            }

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

            // QH-83 evidence-on-pass: a stage recording `Passed` must have
            // written the on-disk witness its catalog row declares. The check
            // runs HERE — after execute, before `stage_finished` — because the
            // recorder truncates the log at `stage_started` and appends the
            // verdict at `stage_finished`, so checking after the observer
            // fires would read the verdict's own echo and always succeed. An
            // absent/empty/unreadable witness demotes the outcome to
            // `NotProven`, which is blocking like any failure.
            if matches!(outcome, StageOutcome::Passed) {
                outcome = verify_declared_evidence(&id, ctx, outcome);
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

    /// The single gate for every reason a stage might be skipped. `None` means
    /// "execute the stage".
    ///
    /// The `always_run()` exemption is checked FIRST and short-circuits to
    /// `None` for teardown stages, ahead of explicit-skip, dependency-cascade,
    /// and shutdown. That ordering is the invariant: an `always_run` cleanup
    /// stage must run so this run's killswitch / exit-NAT residue is torn down
    /// (leaving it is a release-blocker), and funnelling every skip source
    /// through one exemption means a skip source added later cannot
    /// reintroduce the fail-open by forgetting the `!always_run()` guard the
    /// way the old explicit-skip branch did.
    ///
    /// Non-teardown precedence is preserved exactly as before: explicit skip →
    /// dependency cascade → shutdown.
    fn skip_decision(
        &self,
        stage: &dyn OrchestrationStage,
        ctx: &OrchestrationContext,
        blocked: &HashSet<StageId>,
    ) -> Option<SkipDecision> {
        // Teardown stages are never skipped — checked ahead of every source.
        if stage.always_run() {
            return None;
        }

        let id = stage.id();

        // 1) Explicit operator omission (`--skip-stage`, or the `--rerun-stage`
        //    tail). A listed-but-reused skip carries its validated digest and
        //    does not block; a bare `NotRun` blocks its dependents.
        if self.explicit_skips.contains(&id) {
            let outcome = self
                .reused_skips
                .get(&id)
                .map_or(StageOutcome::NotRun, |digest| StageOutcome::Reused {
                    evidence_sha256: digest.as_str().to_owned(),
                });
            let mark_blocked =
                outcome.is_blocking() || matches!(outcome, StageOutcome::Skipped(..));
            return Some(SkipDecision {
                outcome,
                mark_blocked,
            });
        }

        // 2) Dependency cascade — keep the blocking dependency's NAME, not just
        //    the fact that one exists: a cascade skip that cannot say what it is
        //    waiting on is indistinguishable from "this role was never
        //    elected", and those have opposite remedies. A cascade-skipped
        //    stage is itself marked blocked so its own dependents cascade too.
        if let Some(dep) = stage.dependencies().iter().find(|dep| {
            blocked.contains(*dep)
                || ctx
                    .outcome_of(dep)
                    .is_some_and(super::error::StageOutcome::is_blocking)
        }) {
            return Some(SkipDecision {
                outcome: StageOutcome::Skipped(format!(
                    "dependency `{dep}` did not pass, so this stage never ran"
                )),
                mark_blocked: true,
            });
        }

        // 3) Shutdown requested before this stage started. Unlike a cascade,
        //    this does NOT block dependents — the whole run is winding down.
        if let Some(ref flag) = self.shutdown_flag
            && flag.load(Ordering::Acquire)
        {
            return Some(SkipDecision {
                outcome: StageOutcome::Skipped(
                    "shutdown was requested before this stage started".to_owned(),
                ),
                mark_blocked: false,
            });
        }

        None
    }
}

/// Verify the declared pass-verdict witness for a stage that just recorded
/// `Passed`, demoting the outcome to `NotProven` when the witness is absent,
/// empty, or unreadable (QH-83). `StageEvidence::None` rows carry a recorded
/// opt-out reason and pass through unchanged.
fn verify_declared_evidence(
    id: &StageId,
    ctx: &OrchestrationContext,
    outcome: StageOutcome,
) -> StageOutcome {
    debug_assert!(matches!(outcome, StageOutcome::Passed));
    match id.evidence() {
        StageEvidence::None { .. } => outcome,
        StageEvidence::StageLog => {
            // Same path the recorder owns (`evidence.rs`), so the witness
            // checked here is exactly the log a stage writes via
            // `append_stage_evidence_line`.
            let path = super::evidence::rust_native_stage_log_path(&ctx.report_dir, id.as_str());
            verify_evidence_file_at(
                path.as_path(),
                &|state| {
                    format!(
                        "stage '{}' passed but its stage log {state} — no witness written during execute",
                        id.as_str()
                    )
                },
                outcome,
            )
        }
        StageEvidence::File(relative) => verify_evidence_file_at(
            ctx.report_dir.join(relative).as_path(),
            &|state| format!("declared artifact '{relative}' {state}"),
            outcome,
        ),
    }
}

/// One evidence-file check, parameterized only by how the failure message
/// names the artifact. Absent/not-a-file/empty-after-trim are
/// `MissingWitness` (the stage passed but nothing backs the verdict); an I/O
/// error reading an existing witness is `UnreadableEvidence` (fail closed on
/// a race we cannot adjudicate).
fn verify_evidence_file_at(
    path: &Path,
    describe: &dyn Fn(&str) -> String,
    outcome: StageOutcome,
) -> StageOutcome {
    // symlink_metadata, not metadata: a symlink to some other regular file
    // (another run's artifact, another stage's log) must not stand in for
    // the witness this stage was supposed to write.
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            return StageOutcome::NotProven {
                reason: ReasonCode::MissingWitness,
                detail: describe("is a symlink, not a regular file"),
            };
        }
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return StageOutcome::NotProven {
                reason: ReasonCode::MissingWitness,
                detail: describe("not found"),
            };
        }
        Err(err) => {
            return StageOutcome::NotProven {
                reason: ReasonCode::UnreadableEvidence,
                detail: format!("{}: {err}", describe("could not be inspected")),
            };
        }
    };
    if !metadata.is_file() {
        return StageOutcome::NotProven {
            reason: ReasonCode::MissingWitness,
            detail: describe("is not a regular file"),
        };
    }
    match std::fs::read(path) {
        Ok(bytes) if String::from_utf8_lossy(&bytes).trim().is_empty() => StageOutcome::NotProven {
            reason: ReasonCode::MissingWitness,
            detail: describe("is empty"),
        },
        Ok(_) => outcome,
        Err(err) => StageOutcome::NotProven {
            reason: ReasonCode::UnreadableEvidence,
            detail: format!("{}: {err}", describe("could not be read")),
        },
    }
}

/// Fail-closed validation of a `File` evidence declaration: the path must be
/// non-empty, report-dir relative, and free of `..` traversal so a malformed
/// declaration can never silently point outside the report directory while
/// the stage passes.
fn validate_evidence_artifact_path(stage: &str, relative: &str) -> Result<(), String> {
    if relative.trim().is_empty() {
        return Err(format!(
            "stage '{stage}' declares an empty File evidence path"
        ));
    }
    let path = Path::new(relative);
    if path.is_absolute() {
        return Err(format!(
            "stage '{stage}' declares an absolute File evidence path '{relative}' (must be report-dir relative)"
        ));
    }
    if path
        .components()
        .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(format!(
            "stage '{stage}' File evidence path '{relative}' escapes the report dir via '..'"
        ));
    }
    Ok(())
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
        // QH-83: reject malformed `File` evidence declarations up front so
        // the runner's witness check can never be pointed outside the report
        // dir by a typo'd catalog row. The stage catalog is compile-valid, so
        // this is the belt-and-braces arm (and the only one unit-testable —
        // see `evidence_declaration_validation_rejects_malformed_paths`).
        if let StageEvidence::File(relative) = id.evidence() {
            validate_evidence_artifact_path(id.as_str(), relative)?;
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
        // The topological order is the UNION of truth-prerequisite edges
        // (`dependencies`) and ordering-only edges (`ordering_after`). Both
        // constrain WHEN a stage runs; only `dependencies` gates on the
        // predecessor's outcome (skip-cascade lives in `skip_decision`, which
        // reads only `dependencies`). An `ordering_after` edge to a stage not
        // in this plan is silently ignored — the same `if let Some` guard the
        // dependency loop uses — so an omitted ordering predecessor never
        // becomes an implicit requirement (§3.1 rule 3).
        for edge in stage.dependencies().iter().chain(stage.ordering_after()) {
            if let Some(&dep_idx) = id_to_idx.get(edge) {
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
        ordering_after: Vec<StageId>,
        outcome: StageOutcome,
        always_run: bool,
        panics: bool,
        /// When set, `execute` writes the pass-verdict witness declared by
        /// this stage's catalog `evidence()` row (a `StageLog` line or a
        /// `File` artifact) into `ctx.report_dir`, so a `Passed` outcome
        /// satisfies the runner's QH-83 evidence check.
        write_witness: bool,
    }

    impl MockStage {
        fn write_declared_witness(&self, ctx: &OrchestrationContext) {
            match self.id.evidence() {
                StageEvidence::StageLog => {
                    super::super::evidence::append_stage_evidence_line(
                        &ctx.report_dir,
                        self.id.as_str(),
                        &format!("mock witness for {}", self.id.as_str()),
                    )
                    .expect("write mock stage-log witness");
                }
                StageEvidence::File(relative) => {
                    let path = ctx.report_dir.join(relative);
                    let parent = path.parent().expect("witness path has a parent");
                    std::fs::create_dir_all(parent).expect("create witness parent dir");
                    std::fs::write(&path, format!("mock witness for {}\n", self.id.as_str()))
                        .expect("write mock file witness");
                }
                StageEvidence::None { .. } => {}
            }
        }
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
        fn ordering_after(&self) -> &[StageId] {
            &self.ordering_after
        }
        fn applies_to_roles(&self) -> &[NodeRole] {
            &[]
        }
        fn fanout(&self) -> StageFanout {
            StageFanout::Once
        }
        fn execute(&self, ctx: &mut OrchestrationContext) -> StageOutcome {
            assert!(
                !self.panics,
                "mock stage '{}' panicking on purpose",
                self.name
            );
            if self.write_witness {
                self.write_declared_witness(ctx);
            }
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
            ordering_after: vec![],
            outcome: StageOutcome::Passed,
            always_run: false,
            panics: false,
            write_witness: false,
        })
    }

    /// A passing stage that writes the witness its catalog row declares —
    /// the honest-pass fixture for the QH-83 evidence-on-pass tests.
    fn witnessed_pass_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "witnessed_pass",
            deps,
            ordering_after: vec![],
            outcome: StageOutcome::Passed,
            always_run: false,
            panics: false,
            write_witness: true,
        })
    }

    fn fail_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "fail",
            deps,
            ordering_after: vec![],
            outcome: StageOutcome::Failed("test failure".to_owned()),
            always_run: false,
            panics: false,
            write_witness: false,
        })
    }

    /// A teardown stage (`always_run = true`) that passes when it executes —
    /// used to prove cleanup runs despite a failed/panicking dependency.
    fn always_run_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "always_run",
            deps,
            ordering_after: vec![],
            outcome: StageOutcome::Passed,
            always_run: true,
            panics: false,
            write_witness: false,
        })
    }

    /// A stage that panics inside `execute` — used to prove the runner's
    /// panic guard converts it to `Failed` instead of aborting the run.
    fn panic_stage(id: StageId, deps: Vec<StageId>) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "panic",
            deps,
            ordering_after: vec![],
            outcome: StageOutcome::Passed,
            always_run: false,
            panics: true,
            write_witness: false,
        })
    }

    /// A stage with a pure ordering-only edge (never skip-cascaded). `outcome`
    /// lets a test set the DEPENDENT's own result.
    fn ordering_after_stage(
        id: StageId,
        ordering_after: Vec<StageId>,
        outcome: StageOutcome,
    ) -> Box<dyn OrchestrationStage> {
        Box::new(MockStage {
            id,
            name: "ordering_after",
            deps: vec![],
            ordering_after,
            outcome,
            always_run: false,
            panics: false,
            write_witness: true,
        })
    }

    /// Every test gets its own report dir: nextest runs tests as concurrent
    /// processes, and a shared `/tmp/test-report` let one test's runner
    /// clear the File witness another test's stage had just written.
    fn make_ctx() -> OrchestrationContext {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "rustynet-runner-test-{}-{stamp}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create per-test report dir");
        OrchestrationContext::new(vec![], dir, "test-net".to_owned())
    }

    /// Report dir backed by a real tempdir so witness files can be written
    /// and inspected. Keep the `TempDir` alive for the test's duration.
    fn tempdir_ctx() -> (OrchestrationContext, tempfile::TempDir) {
        let dir = tempfile::tempdir().expect("create report tempdir");
        let ctx =
            OrchestrationContext::new(vec![], dir.path().to_path_buf(), "test-net".to_owned());
        (ctx, dir)
    }

    // ── §3.1 prerequisite/order split ─────────────────────────────────────────

    #[test]
    fn ordering_after_does_not_skip_cascade_on_a_failed_predecessor() {
        // A(fail); B is ordered-after A. B must STILL run — an ordering-only
        // edge serialises B after A but does not gate on A's outcome (§3.1).
        // Contrast `skip_cascade_blocks_dependents_of_failing_stage`, where a
        // `dependencies` edge to a failed stage DOES cascade-skip the dependent.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            fail_stage(StageId::Preflight, vec![]),
            ordering_after_stage(
                StageId::VerifySshReachability,
                vec![StageId::Preflight],
                StageOutcome::Passed,
            ),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut make_ctx())
            .expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);
        assert!(matches!(
            outcome_of(&StageId::Preflight),
            Some(StageOutcome::Failed(_))
        ));
        assert_eq!(
            outcome_of(&StageId::VerifySshReachability),
            Some(&StageOutcome::Passed),
            "an ordering_after edge must NOT skip-cascade when its predecessor fails"
        );
    }

    #[test]
    fn ordering_after_still_orders_the_dependent_after_its_predecessor() {
        // Insert the dependent FIRST to prove ordering is by edges, not
        // insertion order: it must still run after its ordering predecessor.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            ordering_after_stage(
                StageId::VerifySshReachability,
                vec![StageId::Preflight],
                StageOutcome::Passed,
            ),
            pass_stage(StageId::Preflight, vec![]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut make_ctx())
            .expect("run");
        let order: Vec<&StageId> = results.iter().map(|(i, _)| i).collect();
        let pos = |id: &StageId| order.iter().position(|x| *x == id).unwrap();
        assert!(
            pos(&StageId::Preflight) < pos(&StageId::VerifySshReachability),
            "ordering_after must place the dependent after its predecessor; order was {order:?}"
        );
    }

    #[test]
    fn ordering_after_to_a_stage_not_in_the_plan_is_ignored_not_an_error() {
        // An ordering edge to an absent stage is silently dropped (rule 3),
        // unlike a missing `dependencies` target which fails plan validation.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![ordering_after_stage(
            StageId::Preflight,
            vec![StageId::ExitHandoff],
            StageOutcome::Passed,
        )];
        let results = StateMachineRunner::new(stages)
            .expect("an ordering edge to an absent stage must not fail plan validation")
            .run(&mut make_ctx())
            .expect("run");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, StageOutcome::Passed);
    }

    // ── Skip-cascade tests ────────────────────────────────────────────────────

    #[test]
    fn skip_cascade_blocks_dependents_of_failing_stage() {
        // A (pass) → B (fail) → C (should be skipped)
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            witnessed_pass_stage(StageId::Preflight, vec![]),
            fail_stage(StageId::PrepareSourceArchive, vec![StageId::Preflight]),
            witnessed_pass_stage(
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
        assert!(
            matches!(
                outcome_of(&StageId::VerifySshReachability),
                Some(StageOutcome::Skipped(_))
            ),
            "stage depending on failed stage must be skipped; got {:?}",
            outcome_of(&StageId::VerifySshReachability)
        );
    }

    #[test]
    fn always_run_stage_runs_even_when_dependency_failed() {
        // A(pass) → B(fail) → cleanup(always_run, depends on B).
        // cleanup must STILL run (Passed), not be cascade-skipped — otherwise a
        // mid-pipeline failure leaves killswitch/NAT residue on the guests.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            witnessed_pass_stage(StageId::Preflight, vec![]),
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
    fn always_run_cleanup_runs_even_when_explicitly_skipped() {
        // The `--rerun-stage` tail marks every stage after the target as an
        // explicit skip — INCLUDING a trailing `always_run` cleanup stage.
        // Before the `skip_decision` unification the explicit-skip branch was
        // evaluated ahead of the `always_run` exemption, so cleanup was skipped
        // (`NotRun`) and this run's killswitch / exit-NAT residue was left on
        // the guest — a release-blocker fail-open reachable from a shipped CLI
        // flag. Cleanup must now still run.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            always_run_stage(StageId::Cleanup, vec![StageId::Preflight]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            // Simulate `--rerun-stage Preflight`: everything after the target is
            // explicit-skipped, which includes the `always_run` Cleanup.
            .with_explicit_skips([StageId::Cleanup])
            .run(&mut make_ctx())
            .expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);
        assert_eq!(
            outcome_of(&StageId::Cleanup),
            Some(&StageOutcome::Passed),
            "always_run cleanup MUST run even when it is in the explicit-skip set"
        );
    }

    #[test]
    fn non_cleanup_stage_still_honors_explicit_skip() {
        // The exemption is scoped to `always_run`: an ordinary stage in the
        // explicit-skip set is still skipped (`NotRun`), so the fix did not
        // turn the skip set into a no-op.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::Preflight, vec![]),
            pass_stage(StageId::VerifySshReachability, vec![StageId::Preflight]),
        ];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .with_explicit_skips([StageId::VerifySshReachability])
            .run(&mut make_ctx())
            .expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);
        assert_eq!(
            outcome_of(&StageId::VerifySshReachability),
            Some(&StageOutcome::NotRun),
            "a non-always_run stage in the explicit-skip set is still skipped"
        );
    }

    // ── RNQ-09: shutdown-flag skip-cascade (in-process, deterministic) ───────
    //
    // `with_shutdown_flag` (used by the production `--node` path in
    // `orchestrator/native.rs` and exercised end-to-end with a REAL
    // SIGTERM/SIGINT by `tests/rnq09_signal_cleanup.rs`) had no coverage at
    // any level before this test: nothing proved the runner's own
    // between-stage shutdown check (`run_with_observer_and_pre_cleanup_hook`'s
    // `flag.load(Ordering::Acquire) && !stage.always_run()` branch) actually
    // skips a pending non-`always_run` stage while still running `always_run`
    // cleanup. This test pre-sets the flag BEFORE the run starts, so the
    // outcome is fully deterministic — no signal, no timing, no thread
    // scheduling — complementing the subprocess test's proof that a real OS
    // signal reaches this same flag in the first place.
    #[test]
    fn shutdown_flag_skips_pending_non_always_run_stage_but_always_run_cleanup_still_executes() {
        use std::sync::atomic::AtomicUsize;

        /// Counts real `execute` invocations so the assertions below prove
        /// the skipped stage's body never ran — not merely that its outcome
        /// happens to equal `Skipped` (which a different bug could also
        /// produce).
        struct CountingStage {
            id: StageId,
            deps: Vec<StageId>,
            always_run: bool,
            executed: Arc<AtomicUsize>,
        }
        impl OrchestrationStage for CountingStage {
            fn id(&self) -> StageId {
                self.id.clone()
            }
            fn name(&self) -> &str {
                "counting"
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
                self.executed.fetch_add(1, Ordering::SeqCst);
                StageOutcome::Passed
            }
        }

        let shutdown_flag = Arc::new(AtomicBool::new(true));
        let pending_runs = Arc::new(AtomicUsize::new(0));
        let cleanup_runs = Arc::new(AtomicUsize::new(0));
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            Box::new(CountingStage {
                id: StageId::Preflight,
                deps: vec![],
                always_run: false,
                executed: Arc::clone(&pending_runs),
            }),
            Box::new(CountingStage {
                id: StageId::Cleanup,
                deps: vec![StageId::Preflight],
                always_run: true,
                executed: Arc::clone(&cleanup_runs),
            }),
        ];
        let runner = StateMachineRunner::new(stages)
            .expect("valid plan")
            .with_shutdown_flag(Arc::clone(&shutdown_flag));
        let results = runner.run(&mut make_ctx()).expect("run");
        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(
            pending_runs.load(Ordering::SeqCst),
            0,
            "a pre-set shutdown flag must prevent a non-always_run stage's execute() from \
             ever being called"
        );
        assert!(
            matches!(
                outcome_of(&StageId::Preflight),
                Some(StageOutcome::Skipped(_))
            ),
            "a pending stage must be recorded Skipped once the shutdown flag is observed; got {:?}",
            outcome_of(&StageId::Preflight)
        );
        assert_eq!(
            cleanup_runs.load(Ordering::SeqCst),
            1,
            "always_run cleanup must still execute exactly once despite the shutdown flag"
        );
        assert_eq!(
            outcome_of(&StageId::Cleanup),
            Some(&StageOutcome::Passed),
            "always_run cleanup MUST run despite the shutdown flag"
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
            witnessed_pass_stage(StageId::CleanupHosts, vec![]),
        ];
        let runner = StateMachineRunner::new(stages).expect("valid plan");
        let mut ctx = make_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert!(matches!(
            outcome_of(&StageId::Preflight),
            Some(StageOutcome::Failed(_))
        ));
        assert!(
            matches!(
                outcome_of(&StageId::PrepareSourceArchive),
                Some(StageOutcome::Skipped(_))
            ),
            "expected a skip; got {:?}",
            outcome_of(&StageId::PrepareSourceArchive)
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
            witnessed_pass_stage(StageId::VerifySshReachability, vec![StageId::Preflight]),
            witnessed_pass_stage(StageId::PrepareSourceArchive, vec![]),
            witnessed_pass_stage(StageId::Preflight, vec![]),
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
        assert!(
            matches!(
                outcome_of(&StageId::PrepareSourceArchive),
                Some(StageOutcome::Skipped(_))
            ),
            "dependent of explicitly-skipped stage must also be skipped; got {:?}",
            outcome_of(&StageId::PrepareSourceArchive)
        );
    }

    #[test]
    fn validated_reused_skip_does_not_cascade_or_claim_fresh_pass() {
        // The dependent is a WITNESSED pass: TrafficTestMatrix declares a
        // `File` evidence witness (QH-83), so a plain mock pass would demote
        // to NotProven under the evidence check.
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::ValidateBaselineRuntime, vec![]),
            witnessed_pass_stage(
                StageId::TrafficTestMatrix,
                vec![StageId::ValidateBaselineRuntime],
            ),
        ];
        // Audit F2: the digest must arrive pre-validated — a placeholder like
        // "abc123" is unrepresentable at the type level, so this test mints
        // its binding through `ReuseDigest::parse` exactly like the
        // production `--run-only`/`--resume-from`/`--rerun-stage` paths do.
        let digest = crate::vm_lab::orchestrator::evidence::ReuseDigest::parse(&"a".repeat(64))
            .expect("valid digest");
        let runner = StateMachineRunner::new(stages)
            .expect("valid plan")
            .with_reused_skips([StageId::ValidateBaselineRuntime], digest);
        let (mut ctx, _dir) = tempdir_ctx();
        let results = runner.run(&mut ctx).expect("run");

        let outcome_of = |id: &StageId| results.iter().find(|(i, _)| i == id).map(|(_, o)| o);

        assert_eq!(
            outcome_of(&StageId::ValidateBaselineRuntime),
            Some(&StageOutcome::Reused {
                evidence_sha256: "a".repeat(64)
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

    // ── QH-83 evidence-on-pass ────────────────────────────────────────────────

    /// Mutation caught: an evidence check that demotes EVERY `StageLog`
    /// stage regardless of whether the witness exists. A stage that wrote
    /// its log witness must keep its `Passed` verdict.
    #[test]
    fn stage_log_witness_upholds_pass() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![witnessed_pass_stage(StageId::MembershipInit, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert_eq!(results.len(), 1);
        assert!(matches!(results[0].1, StageOutcome::Passed));
    }

    /// Mutation caught: removing the `verify_declared_evidence` call from
    /// the run loop (or gating it on anything other than `Passed`). A pass
    /// with no stage log behind it must demote to
    /// `NotProven { MissingWitness }`.
    #[test]
    fn pass_without_stage_log_witness_is_demoted_to_not_proven() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::MembershipInit, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(
                    detail.contains("stage log"),
                    "detail must name the stage log witness: {detail}"
                );
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: a wrapper that checks only EXISTENCE of the log.
    /// An existing-but-empty (whitespace-only) log is no witness — the
    /// verdict still demotes to `NotProven { MissingWitness }`.
    #[test]
    fn empty_stage_log_witness_is_demoted_to_not_proven() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::MembershipInit, vec![])];
        let (mut ctx, dir) = tempdir_ctx();
        let log_path = crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
            dir.path(),
            "membership_init",
        );
        std::fs::create_dir_all(log_path.parent().expect("log parent")).expect("create log dir");
        std::fs::write(&log_path, "   \n\t\n").expect("write whitespace-only log");
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(
                    detail.contains("is empty"),
                    "detail must call out the empty witness: {detail}"
                );
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: a missing `File` arm in `verify_declared_evidence`.
    /// A pass whose declared file artifact was never written must demote to
    /// `NotProven { MissingWitness }` naming the artifact.
    #[test]
    fn pass_without_declared_file_witness_is_demoted_to_not_proven() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::TrafficTestMatrix, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(
                    detail.contains(
                        "declared artifact 'logs/traffic_test_matrix.pair_results.log' not found"
                    ),
                    "detail must name the declared artifact: {detail}"
                );
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: a `File` check without the content check. An
    /// existing-but-empty declared artifact is no witness. Exercised
    /// directly on the predicate — the runner clears a pre-existing `File`
    /// artifact before execute (QH-83 freshness), so an empty artifact can
    /// only reach this check on the `StageLog` path or via a direct call.
    #[test]
    fn empty_declared_file_witness_is_demoted_to_not_proven() {
        let (ctx, dir) = tempdir_ctx();
        let artifact = dir.path().join("logs/traffic_test_matrix.pair_results.log");
        std::fs::create_dir_all(artifact.parent().expect("artifact parent"))
            .expect("create artifact dir");
        std::fs::write(&artifact, "\n").expect("write empty artifact");
        match verify_declared_evidence(&StageId::TrafficTestMatrix, &ctx, StageOutcome::Passed) {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(
                    detail.contains("is empty"),
                    "detail must call out the empty artifact: {detail}"
                );
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: `fs::metadata` (follows symlinks) instead of
    /// `symlink_metadata` — a symlink to a real, non-empty file would then
    /// uphold the pass. Exercised directly on the predicate (see
    /// `empty_declared_file_witness_is_demoted_to_not_proven` for why).
    #[test]
    fn symlinked_file_witness_is_demoted_to_not_proven() {
        let (ctx, dir) = tempdir_ctx();
        let real = dir.path().join("elsewhere.log");
        std::fs::write(&real, "real content\n").expect("write real file");
        let artifact = dir.path().join("logs/traffic_test_matrix.pair_results.log");
        std::fs::create_dir_all(artifact.parent().expect("artifact parent"))
            .expect("create artifact dir");
        std::os::unix::fs::symlink(&real, &artifact).expect("symlink witness");
        match verify_declared_evidence(&StageId::TrafficTestMatrix, &ctx, StageOutcome::Passed) {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(detail.contains("symlink"), "{detail}");
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: mapping a read error to `Ok`/pass, or dropping the
    /// `UnreadableEvidence` arm. Skipped (with a note) when running as root,
    /// where mode 0o000 does not deny the read. Exercised directly on the
    /// predicate (see `empty_declared_file_witness_is_demoted_to_not_proven`
    /// for why).
    #[test]
    fn unreadable_file_witness_is_demoted_to_unreadable_evidence() {
        use std::os::unix::fs::PermissionsExt;
        let (ctx, dir) = tempdir_ctx();
        let artifact = dir.path().join("logs/traffic_test_matrix.pair_results.log");
        std::fs::create_dir_all(artifact.parent().expect("artifact parent"))
            .expect("create artifact dir");
        std::fs::write(&artifact, "content\n").expect("write artifact");
        std::fs::set_permissions(&artifact, std::fs::Permissions::from_mode(0o000))
            .expect("chmod 000");
        if std::fs::read(&artifact).is_ok() {
            eprintln!("running with read access despite mode 000 (root?); skipping");
            return;
        }
        match verify_declared_evidence(&StageId::TrafficTestMatrix, &ctx, StageOutcome::Passed) {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::UnreadableEvidence));
                assert!(detail.contains("could not be read"), "{detail}");
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// Mutation caught: a `File` arm that never upholds a real witness. A
    /// stage that wrote its declared artifact keeps `Passed`.
    #[test]
    fn witnessed_file_evidence_upholds_pass() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![witnessed_pass_stage(StageId::TrafficTestMatrix, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert!(matches!(results[0].1, StageOutcome::Passed));
    }

    /// Mutation caught: skipping the pre-execute witness clear (revert the
    /// `remove_file` block in the run loop). A `File` witness left in the
    /// report dir by a PRIOR generation — reachable via `--run-only` /
    /// `--resume-from` / `--rerun-stage`, which reuse an existing report
    /// dir — must not back this run's `Passed` when this execute writes
    /// nothing. The runner must clear it at stage start; the pass then
    /// demotes to `NotProven { MissingWitness }` and the stale artifact is
    /// gone.
    #[test]
    fn file_witness_from_a_prior_generation_is_not_accepted() {
        let (mut ctx, dir) = tempdir_ctx();
        let witness = dir.path().join("logs/traffic_test_matrix.pair_results.log");
        std::fs::create_dir_all(witness.parent().expect("witness parent"))
            .expect("create witness dir");
        std::fs::write(&witness, b"generation-N artifact\n").expect("write stale witness");
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::TrafficTestMatrix, vec![])];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(
                    detail.contains("not found"),
                    "stale witness must have been cleared before the check: {detail}"
                );
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
        assert!(
            !witness.exists(),
            "the prior generation's artifact must have been removed before execute"
        );
    }

    /// Mutation caught: a pre-execute clear so aggressive the honest path
    /// cannot recover (e.g. clearing without letting the stage rewrite, or
    /// failing the stage because an artifact existed). A stage that writes
    /// its declared artifact during execute still earns `Passed` even when
    /// a prior generation's artifact was present at stage start.
    #[test]
    fn witnessed_file_evidence_replaces_a_prior_generations_artifact() {
        let (mut ctx, dir) = tempdir_ctx();
        let witness = dir.path().join("logs/traffic_test_matrix.pair_results.log");
        std::fs::create_dir_all(witness.parent().expect("witness parent"))
            .expect("create witness dir");
        std::fs::write(&witness, b"generation-N artifact\n").expect("write stale witness");
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![witnessed_pass_stage(StageId::TrafficTestMatrix, vec![])];
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert!(matches!(results[0].1, StageOutcome::Passed));
        let fresh = std::fs::read_to_string(&witness).expect("read this generation's artifact");
        assert!(
            fresh.contains("traffic_test_matrix"),
            "the artifact on disk must be THIS execute's witness, not generation N: {fresh}"
        );
    }

    /// Mutation caught: an evidence check applied to `StageEvidence::None`
    /// rows (or to non-Passed outcomes). Opt-out rows — both the phase-1
    /// pending bulk and the teardown exemption — must pass without any
    /// on-disk witness.
    #[test]
    fn evidence_opt_out_stages_pass_without_witness() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            // Cleanup declares no evidence (the teardown exemption below);
            // the QH-83 Setup batch moved validate_baseline_runtime to a
            // StageLog witness, so it no longer appears here as an opt-out.
            always_run_stage(StageId::Cleanup, vec![]),
        ];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert!(matches!(results[0].1, StageOutcome::Passed));
    }

    /// QH-83 Setup batch mutation caught: a plain (unwitnessed) pass on a
    /// row that NOW declares `StageEvidence::StageLog` —
    /// validate_baseline_runtime was the last Setup-phase opt-out. Reverting
    /// its catalog row to
    /// `StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }` re-arms
    /// this test.
    #[test]
    fn validate_baseline_runtime_pass_without_witness_is_demoted() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::ValidateBaselineRuntime, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(detail.contains("stage log"), "{detail}");
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// F4 mutation caught: reverting the BlindExit catalog row
    /// (stage::mod `BlindExit => ...`) from `StageEvidence::StageLog` back to
    /// `StageEvidence::None { reason: PHASE1_EVIDENCE_PENDING }` re-arms this
    /// test — the stage would then PASS with no witness on disk and never be
    /// demoted, which is exactly the gap the blind_exit witness work closes.
    #[test]
    fn blind_exit_pass_without_witness_is_demoted() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![pass_stage(StageId::BlindExit, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        match &results[0].1 {
            StageOutcome::NotProven { reason, detail } => {
                assert!(matches!(reason, super::ReasonCode::MissingWitness));
                assert!(detail.contains("stage log"), "{detail}");
            }
            other => panic!("expected NotProven, got {other:?}"),
        }
    }

    /// F4: a blind_exit PASS whose stage log carries the per-node witness
    /// lines upholds `Passed` — the demotion above only fires on missing
    /// evidence, not on legitimate proofs.
    #[test]
    fn blind_exit_stage_log_witness_upholds_pass() {
        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![witnessed_pass_stage(StageId::BlindExit, vec![])];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert!(matches!(results[0].1, StageOutcome::Passed));
    }

    /// Design §9 test 5 (adapted): the stage catalog is compile-valid, so
    /// malformed `File` declarations cannot exist in it — the validator is
    /// exercised directly. Mutation caught: dropping the traversal/absolute/
    /// empty rejection from `validate_evidence_artifact_path`.
    #[test]
    fn evidence_declaration_validation_rejects_malformed_paths() {
        assert!(validate_evidence_artifact_path("traffic_test_matrix", "").is_err());
        assert!(validate_evidence_artifact_path("traffic_test_matrix", "  ").is_err());
        assert!(validate_evidence_artifact_path("traffic_test_matrix", "/etc/passwd").is_err());
        assert!(validate_evidence_artifact_path("traffic_test_matrix", "a/../b.log").is_err());
        assert!(
            validate_evidence_artifact_path(
                "traffic_test_matrix",
                "logs/traffic_test_matrix.pair_results.log"
            )
            .is_ok()
        );
    }

    /// Mutation caught: moving the evidence check AFTER
    /// `observer.stage_finished`. The real recorder truncates the log at
    /// `stage_started` and appends the terminal verdict at `stage_finished`;
    /// this observer reproduces that shape. A stage that wrote no witness
    /// must STILL demote — checking after the observer would read the
    /// verdict's own echo and pass vacuously.
    #[test]
    fn demotion_fires_before_observer_appends_verdict() {
        struct VerdictEchoObserver {
            report_dir: PathBuf,
        }
        impl StageObserver for VerdictEchoObserver {
            fn stage_started(&self, id: &StageId) {
                let path = crate::vm_lab::orchestrator::evidence::rust_native_stage_log_path(
                    &self.report_dir,
                    id.as_str(),
                );
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let _ = std::fs::write(&path, ""); // truncate, like the recorder
            }
            fn stage_finished(&self, id: &StageId, outcome: &StageOutcome) {
                let verdict = if matches!(outcome, StageOutcome::Passed) {
                    "pass"
                } else {
                    "not-pass"
                };
                let _ = crate::vm_lab::orchestrator::evidence::append_stage_evidence_line(
                    &self.report_dir,
                    id.as_str(),
                    &format!("terminal verdict recorded: {verdict}"),
                );
            }
        }

        let stages: Vec<Box<dyn OrchestrationStage>> =
            vec![pass_stage(StageId::MembershipInit, vec![])];
        let (mut ctx, dir) = tempdir_ctx();
        let observer = VerdictEchoObserver {
            report_dir: dir.path().to_path_buf(),
        };
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run_with_observer(&mut ctx, &observer)
            .expect("run");
        // The verdict echo observer appended a line at stage_finished — by
        // which time the runner's check had already run and demoted.
        assert!(matches!(
            &results[0].1,
            StageOutcome::NotProven { reason, .. }
                if matches!(reason, super::ReasonCode::MissingWitness)
        ));
    }

    /// Mutation caught: a demoted pass that is not treated as blocking (or
    /// the wrapper skipping the `blocked` bookkeeping). An unwitnessed pass
    /// must cascade-skip its dependents exactly like a failure.
    #[test]
    fn unwitnessed_pass_blocks_dependents() {
        let stages: Vec<Box<dyn OrchestrationStage>> = vec![
            pass_stage(StageId::MembershipInit, vec![]),
            pass_stage(StageId::MeshStatusValidation, vec![StageId::MembershipInit]),
        ];
        let (mut ctx, _dir) = tempdir_ctx();
        let results = StateMachineRunner::new(stages)
            .expect("valid plan")
            .run(&mut ctx)
            .expect("run");
        assert!(matches!(
            &results[0].1,
            StageOutcome::NotProven { reason, .. }
                if matches!(reason, super::ReasonCode::MissingWitness)
        ));
        match &results[1].1 {
            StageOutcome::Skipped(detail) => {
                assert!(
                    detail.contains("membership_init"),
                    "skip detail must name the blocking dependency: {detail}"
                );
            }
            other => panic!("expected Skipped dependent, got {other:?}"),
        }
    }
}
