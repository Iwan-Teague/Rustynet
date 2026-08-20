//! Plan resolution: a [`PlanSelection`] plus the stage graph resolve to an
//! immutable [`ResolvedPlan`] with a stable digest, BEFORE any mutation (L0.4 of
//! the truth-preserving framework,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §3.1.3 / §3.2).
//!
//! The resolver is where a focused/adjudication run is fenced so it cannot
//! silently shrink its own claim: the truth-prerequisite closure is mandatory,
//! cleanup is unconditional, and an explicit skip of a selected target or its
//! closure is refused. The manifest and `node_stage_plan.json` must later equal
//! this resolved plan exactly, and the verifier reconstructs it independently to
//! detect a shrunk plan (that wiring + the independent reconstruction is L0.4c).
//!
//! Determinism: every id list the resolver emits is sorted by `as_str()`, and
//! the digest is a SHA-256 over that canonical form, so the same selection over
//! the same graph always produces the same digest regardless of input order.
#![allow(dead_code)] // consumed by native.rs plan construction + the verifier in L0.4c

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use crate::vm_lab::orchestrator::stage::{OrchestrationStage, StageId};

/// `<report_dir>`-relative path of the resolved-plan artifact.
pub const RESOLVED_PLAN_RELATIVE_PATH: &str = "state/resolved_plan.json";

/// Schema version of `resolved_plan.json`. The verifier rejects an unknown
/// version rather than guessing (§3.1.3).
pub const RESOLVED_PLAN_SCHEMA_VERSION: u64 = 1;

/// One stage's edges, as the resolver needs them.
#[derive(Debug, Clone)]
struct StageNode {
    /// Must PASS before this stage — the closure follows these transitively.
    truth_prereqs: Vec<StageId>,
    /// Ordering-only predecessors (do not gate; not part of the required set).
    ordering_after: Vec<StageId>,
    /// `always_run` teardown: mandatory in every plan, never skippable or
    /// reusable (§3.2 rule 4).
    is_cleanup: bool,
}

/// The plan graph the resolver closes over.
#[derive(Debug, Clone, Default)]
pub struct StageGraph {
    nodes: HashMap<StageId, StageNode>,
}

impl StageGraph {
    /// Build from the catalog of stages actually constructed for a run, reading
    /// each stage's truth/ordering edges and teardown flag.
    pub fn from_stages(stages: &[Box<dyn OrchestrationStage>]) -> Self {
        let mut nodes = HashMap::with_capacity(stages.len());
        for stage in stages {
            nodes.insert(
                stage.id(),
                StageNode {
                    truth_prereqs: stage.dependencies().to_vec(),
                    ordering_after: stage.ordering_after().to_vec(),
                    is_cleanup: stage.always_run(),
                },
            );
        }
        StageGraph { nodes }
    }

    fn contains(&self, id: &StageId) -> bool {
        self.nodes.contains_key(id)
    }

    fn cleanup_ids(&self) -> Vec<StageId> {
        let mut ids: Vec<StageId> = self
            .nodes
            .iter()
            .filter(|(_, n)| n.is_cleanup)
            .map(|(id, _)| id.clone())
            .collect();
        sort_ids(&mut ids);
        ids
    }
}

/// The kind of plan — fixes whether it can present as release-green (§3.2 rule 6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanKind {
    Standard,
    Focused,
    Adjudication,
}

impl PlanKind {
    pub fn as_str(self) -> &'static str {
        match self {
            PlanKind::Standard => "standard",
            PlanKind::Focused => "focused",
            PlanKind::Adjudication => "adjudication",
        }
    }

    /// Only a Standard plan can be a release candidate; a Focused or
    /// Adjudication plan proves its named stage/control only and never presents
    /// as a full-suite or release-green run (§3.2 rule 6).
    pub fn is_release_candidate(self) -> bool {
        matches!(self, PlanKind::Standard)
    }
}

/// A closed selection of what to run.
#[derive(Debug, Clone)]
pub enum PlanSelection {
    /// The normal suite-selected set (what `PlanBuilder` produces today).
    Standard { stages: Vec<StageId> },
    /// A focused subset: these targets, their truth closure, required setup, and
    /// always-run cleanup only.
    Focused { targets: Vec<StageId> },
    /// Selected T5 negative controls, their truth baseline, and cleanup only.
    Adjudication { controls: Vec<StageId> },
}

impl PlanSelection {
    pub fn kind(&self) -> PlanKind {
        match self {
            PlanSelection::Standard { .. } => PlanKind::Standard,
            PlanSelection::Focused { .. } => PlanKind::Focused,
            PlanSelection::Adjudication { .. } => PlanKind::Adjudication,
        }
    }

    fn requested(&self) -> &[StageId] {
        match self {
            PlanSelection::Standard { stages } => stages,
            PlanSelection::Focused { targets } => targets,
            PlanSelection::Adjudication { controls } => controls,
        }
    }
}

/// The resolved, immutable plan — produced before mutation, with a stable
/// digest. The manifest and node-stage plan must equal this exactly (§3.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPlan {
    pub kind: PlanKind,
    /// The ids the caller explicitly asked for (sorted).
    pub selected: Vec<StageId>,
    /// `selected` plus the transitive truth-prerequisite closure (sorted).
    pub truth_closure: Vec<StageId>,
    /// Mandatory cleanup ids, included unconditionally (sorted).
    pub cleanup: Vec<StageId>,
    /// The full set that will run = `truth_closure` ∪ `cleanup` (sorted).
    pub enabled: Vec<StageId>,
    /// SHA-256 over the canonical (kind + sorted id lists) form.
    pub digest: String,
}

impl ResolvedPlan {
    pub fn is_release_candidate(&self) -> bool {
        self.kind.is_release_candidate()
    }

    /// The canonical JSON form written to `resolved_plan.json` and reconstructed
    /// by the verifier. Ids are their `as_str` tokens, already sorted.
    fn to_json(&self) -> serde_json::Value {
        let ids = |v: &[StageId]| v.iter().map(StageId::as_str).collect::<Vec<_>>();
        serde_json::json!({
            "schema_version": RESOLVED_PLAN_SCHEMA_VERSION,
            "kind": self.kind.as_str(),
            "selected": ids(&self.selected),
            "truth_closure": ids(&self.truth_closure),
            "cleanup": ids(&self.cleanup),
            "enabled": ids(&self.enabled),
            "digest": self.digest,
        })
    }
}

/// Atomically write `resolved_plan.json` under `report_dir` (tmp + rename), the
/// immutable record of the plan resolved for this run. Consumers (the verifier,
/// the finalizer) read it back to detect a shrunk or mismatched plan (§3.1.3).
pub fn write_resolved_plan(report_dir: &Path, plan: &ResolvedPlan) -> Result<(), String> {
    let path = report_dir.join(RESOLVED_PLAN_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("resolved_plan path has no parent: {}", path.display()))?;
    std::fs::create_dir_all(parent).map_err(|e| {
        format!(
            "create state dir for resolved_plan failed ({}): {e}",
            parent.display()
        )
    })?;
    let body = serde_json::to_vec_pretty(&plan.to_json())
        .map_err(|e| format!("serialize resolved_plan failed: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, body)
        .map_err(|e| format!("write resolved_plan tmp failed ({}): {e}", tmp.display()))?;
    std::fs::rename(&tmp, &path).map_err(|e| {
        format!(
            "rename resolved_plan into place failed ({}): {e}",
            path.display()
        )
    })
}

/// The recorded resolved plan, read back from `resolved_plan.json`. Kept as
/// strings (not `StageId`) because the verifier compares against an
/// independently-derived plan by digest and by the enabled id set, and a
/// recorded id that is not even a known stage must be reportable rather than a
/// parse failure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPlan {
    pub schema_version: u64,
    pub kind: String,
    pub digest: String,
    pub enabled: Vec<String>,
}

/// Read back `resolved_plan.json`. A missing file, malformed JSON, or an unknown
/// schema version is an error — the verifier fails closed rather than treating
/// an unreadable plan as "no shrink".
pub fn read_recorded_plan(report_dir: &Path) -> Result<RecordedPlan, String> {
    let path = report_dir.join(RESOLVED_PLAN_RELATIVE_PATH);
    let body = std::fs::read_to_string(&path)
        .map_err(|e| format!("read resolved_plan {}: {e}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| format!("parse resolved_plan {}: {e}", path.display()))?;
    let schema_version = v
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("resolved_plan {} missing schema_version", path.display()))?;
    if schema_version != RESOLVED_PLAN_SCHEMA_VERSION {
        return Err(format!(
            "resolved_plan {} has unsupported schema_version {schema_version} (expected {RESOLVED_PLAN_SCHEMA_VERSION})",
            path.display()
        ));
    }
    let kind = v
        .get("kind")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("resolved_plan {} missing kind", path.display()))?
        .to_owned();
    let digest = v
        .get("digest")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| format!("resolved_plan {} missing digest", path.display()))?
        .to_owned();
    let enabled = v
        .get("enabled")
        .and_then(serde_json::Value::as_array)
        .ok_or_else(|| format!("resolved_plan {} missing enabled list", path.display()))?
        .iter()
        .map(|x| {
            x.as_str().map(str::to_owned).ok_or_else(|| {
                format!(
                    "resolved_plan {} enabled has a non-string id",
                    path.display()
                )
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(RecordedPlan {
        schema_version,
        kind,
        digest,
        enabled,
    })
}

/// Verify the runner's RECORDED plan matches an INDEPENDENTLY-derived expected
/// plan (§3.1.3). The `expected` plan must be resolved fresh from
/// `StageId::ALL` + the raw selectors — NOT read from the recorded artifact —
/// so this comparison detects a plan the runner shrank (or grew) between
/// selection and recording, which a self-consistency check on the manifest
/// alone cannot see.
///
/// Exact digest equality is the pass condition. On mismatch it names the
/// specific stages the recorded plan DROPPED (a shrink — the dangerous case) or
/// ADDED, so the failure points at the exact divergence rather than just "the
/// digests differ".
pub fn verify_recorded_matches_expected(
    expected: &ResolvedPlan,
    recorded: &RecordedPlan,
) -> Result<(), String> {
    if recorded.schema_version != RESOLVED_PLAN_SCHEMA_VERSION {
        return Err(format!(
            "recorded plan schema_version {} is unsupported (expected {RESOLVED_PLAN_SCHEMA_VERSION})",
            recorded.schema_version
        ));
    }
    if recorded.digest == expected.digest {
        return Ok(());
    }
    let expected_enabled: BTreeSet<&str> = expected.enabled.iter().map(StageId::as_str).collect();
    let recorded_enabled: BTreeSet<&str> = recorded.enabled.iter().map(String::as_str).collect();
    let dropped: Vec<&str> = expected_enabled
        .difference(&recorded_enabled)
        .copied()
        .collect();
    let added: Vec<&str> = recorded_enabled
        .difference(&expected_enabled)
        .copied()
        .collect();
    Err(format!(
        "recorded plan does not match the independently-derived expected plan \
         (digest {} != {}); dropped/shrunk stages: [{}]; unexpected added stages: [{}]",
        recorded.digest,
        expected.digest,
        dropped.join(", "),
        added.join(", "),
    ))
}

fn sort_ids(ids: &mut [StageId]) {
    ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
}

fn dedup_sorted(mut ids: Vec<StageId>) -> Vec<StageId> {
    sort_ids(&mut ids);
    ids.dedup_by(|a, b| a.as_str() == b.as_str());
    ids
}

/// Resolve a selection over the graph into a [`ResolvedPlan`], enforcing the
/// §3.2 resolver rules. Returns a named error (no mutation) on any violation.
///
/// `explicit_skips` are the operator's `--skip-stage` / `--rerun-stage` set. A
/// skip that would remove a selected target or a member of its truth closure is
/// refused (rule 5) — that would silently shrink the claim. Cleanup is never
/// removable: it is included unconditionally (rule 4) and the runner runs it
/// regardless of the skip set via the `always_run` exemption, so a skip that
/// happens to name a cleanup stage (e.g. `--rerun-stage` marking the tail) is a
/// runtime no-op, not a plan the resolver must reject.
pub fn resolve(
    graph: &StageGraph,
    selection: &PlanSelection,
    explicit_skips: &[StageId],
) -> Result<ResolvedPlan, String> {
    let requested = selection.requested();

    // Rule 1: reject unknown / duplicate targets before anything else.
    let mut seen: HashSet<&str> = HashSet::new();
    for id in requested {
        if !graph.contains(id) {
            return Err(format!(
                "plan target `{}` is not a known stage",
                id.as_str()
            ));
        }
        if !seen.insert(id.as_str()) {
            return Err(format!(
                "plan target `{}` is selected more than once",
                id.as_str()
            ));
        }
    }

    // Rule 2: transitive truth-prerequisite closure. A truth prerequisite that
    // is not in the graph is a broken plan (unlike an ordering edge, which is
    // ignored when absent).
    let mut closure: HashMap<&str, StageId> = HashMap::new();
    let mut stack: Vec<StageId> = requested.to_vec();
    while let Some(id) = stack.pop() {
        if closure.contains_key(id.as_str()) {
            continue;
        }
        let node = graph
            .nodes
            .get(&id)
            .ok_or_else(|| format!("plan stage `{}` is not a known stage", id.as_str()))?;
        for prereq in &node.truth_prereqs {
            if !graph.contains(prereq) {
                return Err(format!(
                    "truth prerequisite `{}` of `{}` is not a known stage",
                    prereq.as_str(),
                    id.as_str()
                ));
            }
            stack.push(prereq.clone());
        }
        closure.insert(id.as_str(), id.clone());
    }
    let truth_closure = dedup_sorted(closure.values().cloned().collect());

    // Rule 4: cleanup is included unconditionally; a graph with no cleanup stage
    // cannot be resolved (a plan that could leave residue is refused).
    let cleanup = graph.cleanup_ids();
    if cleanup.is_empty() {
        return Err(
            "resolved plan has no always-run cleanup stage; refusing a plan that could \
             leave killswitch / NAT residue on the guests"
                .to_owned(),
        );
    }

    // Rule 5: an explicit skip may not remove a selected target or a member of
    // its truth closure — that would silently shrink the claim.
    for skip in explicit_skips {
        if closure.contains_key(skip.as_str()) {
            return Err(format!(
                "refusing to skip `{}`: it is a selected target or a truth prerequisite of one \
                 (skipping it would shrink the plan's claim)",
                skip.as_str()
            ));
        }
    }

    let selected = dedup_sorted(requested.to_vec());
    let enabled = {
        let mut all = truth_closure.clone();
        all.extend(cleanup.iter().cloned());
        dedup_sorted(all)
    };

    let digest = plan_digest(
        selection.kind(),
        &selected,
        &truth_closure,
        &cleanup,
        &enabled,
    );

    Ok(ResolvedPlan {
        kind: selection.kind(),
        selected,
        truth_closure,
        cleanup,
        enabled,
        digest,
    })
}

/// A stable SHA-256 over the canonical resolved-plan form. Each id list is
/// already sorted by `as_str`; the labelled, newline-delimited layout means a
/// stage moving between lists changes the digest.
fn plan_digest(
    kind: PlanKind,
    selected: &[StageId],
    truth_closure: &[StageId],
    cleanup: &[StageId],
    enabled: &[StageId],
) -> String {
    let mut canonical = String::new();
    canonical.push_str("kind=");
    canonical.push_str(kind.as_str());
    canonical.push('\n');
    for (label, ids) in [
        ("selected", selected),
        ("truth_closure", truth_closure),
        ("cleanup", cleanup),
        ("enabled", enabled),
    ] {
        canonical.push_str(label);
        canonical.push('=');
        canonical.push_str(
            &ids.iter()
                .map(StageId::as_str)
                .collect::<Vec<_>>()
                .join(","),
        );
        canonical.push('\n');
    }
    crate::vm_lab::sha256_hex_bytes(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a graph from `(id, truth_prereqs, is_cleanup)` triples. Ordering
    /// edges default empty (exercised separately by the runner tests).
    fn graph(rows: &[(StageId, &[StageId], bool)]) -> StageGraph {
        let mut nodes = HashMap::new();
        for (id, prereqs, is_cleanup) in rows {
            nodes.insert(
                id.clone(),
                StageNode {
                    truth_prereqs: prereqs.to_vec(),
                    ordering_after: vec![],
                    is_cleanup: *is_cleanup,
                },
            );
        }
        StageGraph { nodes }
    }

    // A small graph: Preflight -> Bootstrap -> ExitHandoff, plus a Cleanup
    // teardown. (Edge = "depends on / must pass first".)
    fn sample_graph() -> StageGraph {
        graph(&[
            (StageId::Preflight, &[], false),
            (StageId::BootstrapHosts, &[StageId::Preflight], false),
            (StageId::ExitHandoff, &[StageId::BootstrapHosts], false),
            (StageId::Cleanup, &[], true),
        ])
    }

    #[test]
    fn focused_pulls_in_the_transitive_truth_closure_and_cleanup() {
        let g = sample_graph();
        let plan = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff],
            },
            &[],
        )
        .expect("resolve");
        // ExitHandoff's closure is {Preflight, BootstrapHosts, ExitHandoff}.
        assert_eq!(
            plan.truth_closure,
            dedup_sorted(vec![
                StageId::Preflight,
                StageId::BootstrapHosts,
                StageId::ExitHandoff
            ])
        );
        // Cleanup is always included.
        assert_eq!(plan.cleanup, vec![StageId::Cleanup]);
        assert!(plan.enabled.contains(&StageId::Cleanup));
        assert!(plan.enabled.contains(&StageId::Preflight));
        assert_eq!(plan.kind, PlanKind::Focused);
        assert!(
            !plan.is_release_candidate(),
            "focused is never release-green"
        );
    }

    #[test]
    fn unknown_and_duplicate_targets_are_rejected_before_mutation() {
        let g = sample_graph();
        assert!(
            resolve(
                &g,
                &PlanSelection::Focused {
                    targets: vec![StageId::CollectPubkeys]
                },
                &[]
            )
            .is_err(),
            "an unknown target must be rejected"
        );
        let dup = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff, StageId::ExitHandoff],
            },
            &[],
        );
        assert!(dup.is_err(), "a duplicate target must be rejected");
    }

    #[test]
    fn a_graph_without_cleanup_cannot_be_resolved() {
        let g = graph(&[(StageId::Preflight, &[], false)]);
        let err = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::Preflight],
            },
            &[],
        )
        .unwrap_err();
        assert!(
            err.contains("cleanup"),
            "must name the missing cleanup: {err}"
        );
    }

    #[test]
    fn skipping_a_selected_target_or_its_prerequisite_is_refused() {
        let g = sample_graph();
        // Skip the target itself.
        assert!(
            resolve(
                &g,
                &PlanSelection::Focused {
                    targets: vec![StageId::ExitHandoff]
                },
                &[StageId::ExitHandoff],
            )
            .is_err(),
            "skipping the selected target must be refused"
        );
        // Skip a transitive prerequisite.
        let err = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff],
            },
            &[StageId::Preflight],
        )
        .unwrap_err();
        assert!(
            err.contains("shrink"),
            "skipping a prerequisite must be refused as a plan-shrink: {err}"
        );
    }

    #[test]
    fn digest_is_stable_across_input_order_and_changes_with_the_plan() {
        let g = sample_graph();
        let a = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff, StageId::BootstrapHosts],
            },
            &[],
        )
        .unwrap();
        // Same targets, different input order -> identical digest.
        let b = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::BootstrapHosts, StageId::ExitHandoff],
            },
            &[],
        )
        .unwrap();
        assert_eq!(a.digest, b.digest, "digest must be order-independent");
        assert_eq!(a.digest.len(), 64, "sha-256 hex");

        // A different selection (a Standard plan of just Preflight+Cleanup) must
        // produce a different digest.
        let c = resolve(
            &g,
            &PlanSelection::Standard {
                stages: vec![StageId::Preflight],
            },
            &[],
        )
        .unwrap();
        assert_ne!(
            a.digest, c.digest,
            "a different plan must digest differently"
        );
    }

    #[test]
    fn standard_is_the_only_release_candidate_kind() {
        assert!(PlanKind::Standard.is_release_candidate());
        assert!(!PlanKind::Focused.is_release_candidate());
        assert!(!PlanKind::Adjudication.is_release_candidate());
    }

    #[test]
    fn write_resolved_plan_emits_canonical_json_that_reads_back() {
        let g = sample_graph();
        let plan = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff],
            },
            &[],
        )
        .unwrap();
        let dir = std::env::temp_dir().join(format!(
            "rustynet-resolved-plan-test-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        write_resolved_plan(&dir, &plan).expect("write resolved_plan");
        let body =
            std::fs::read_to_string(dir.join(RESOLVED_PLAN_RELATIVE_PATH)).expect("read back");
        let v: serde_json::Value = serde_json::from_str(&body).expect("valid json");
        assert_eq!(v["schema_version"], RESOLVED_PLAN_SCHEMA_VERSION);
        assert_eq!(v["kind"], "focused");
        assert_eq!(v["digest"], plan.digest);
        let enabled: Vec<String> = v["enabled"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_str().unwrap().to_owned())
            .collect();
        let expected: Vec<String> = plan.enabled.iter().map(|s| s.as_str().to_owned()).collect();
        assert_eq!(enabled, expected, "enabled list must round-trip exactly");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn recorded_from(plan: &ResolvedPlan) -> RecordedPlan {
        RecordedPlan {
            schema_version: RESOLVED_PLAN_SCHEMA_VERSION,
            kind: plan.kind.as_str().to_owned(),
            digest: plan.digest.clone(),
            enabled: plan.enabled.iter().map(|s| s.as_str().to_owned()).collect(),
        }
    }

    #[test]
    fn a_faithfully_recorded_plan_verifies() {
        let g = sample_graph();
        let expected = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff],
            },
            &[],
        )
        .unwrap();
        let recorded = recorded_from(&expected);
        assert!(verify_recorded_matches_expected(&expected, &recorded).is_ok());
    }

    #[test]
    fn a_shrunk_recorded_plan_is_rejected_and_names_the_dropped_stage() {
        let g = sample_graph();
        let expected = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::ExitHandoff],
            },
            &[],
        )
        .unwrap();
        // Simulate the runner recording a plan that dropped a truth prerequisite
        // (the P0 shrink): recompute enabled without Preflight, with a stale
        // digest that no longer matches.
        let mut recorded = recorded_from(&expected);
        recorded
            .enabled
            .retain(|s| s != StageId::Preflight.as_str());
        recorded.digest = "0".repeat(64); // any digest != expected
        let err = verify_recorded_matches_expected(&expected, &recorded).unwrap_err();
        assert!(
            err.contains(StageId::Preflight.as_str()) && err.contains("dropped"),
            "the rejection must name the dropped stage: {err}"
        );
    }

    #[test]
    fn an_injected_stage_in_the_recorded_plan_is_rejected_and_named() {
        let g = sample_graph();
        let expected = resolve(
            &g,
            &PlanSelection::Focused {
                targets: vec![StageId::Preflight],
            },
            &[],
        )
        .unwrap();
        let mut recorded = recorded_from(&expected);
        recorded
            .enabled
            .push(StageId::ExitHandoff.as_str().to_owned());
        recorded.digest = "1".repeat(64);
        let err = verify_recorded_matches_expected(&expected, &recorded).unwrap_err();
        assert!(
            err.contains(StageId::ExitHandoff.as_str()) && err.contains("added"),
            "the rejection must name the unexpected added stage: {err}"
        );
    }

    #[test]
    fn read_recorded_plan_rejects_an_unknown_schema_version() {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-recorded-plan-schema-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("state")).unwrap();
        std::fs::write(
            dir.join(RESOLVED_PLAN_RELATIVE_PATH),
            br#"{"schema_version": 999, "kind": "standard", "digest": "x", "enabled": []}"#,
        )
        .unwrap();
        let err = read_recorded_plan(&dir).unwrap_err();
        assert!(
            err.contains("schema_version"),
            "must reject unknown version: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
