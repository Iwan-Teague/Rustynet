#![forbid(unsafe_code)]

//! Run-scoped stage manifest (Finding 1B of the 2026-07-03 live-lab
//! findings): the resolved plan for ONE run, written to
//! `<report_dir>/orchestration/stage_manifest.json` at run start.
//!
//! The manifest is the run-time data contract between the orchestrators
//! (which know the plan) and every consumer that previously hand-copied the
//! stage vocabulary — most importantly the monitor TUI, which is
//! deliberately excluded from the cargo workspace and therefore cannot
//! share the registry at build time. Consumers render/validate against the
//! manifest found in the report dir; a held run's display is thereby pinned
//! to the config that launched it, immune to later config edits.
//!
//! Every stage the registry knows appears exactly once, resolved to
//! `enabled: true` or `enabled: false` + `skip_reason` from the run's
//! actual selectors. Synthetic display aggregates are marked so recorders
//! know they never appear in outcomes.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::live_lab_stage_registry::{self, STAGES, TargetSelectors};

pub const STAGE_MANIFEST_RELATIVE_PATH: &str = "orchestration/stage_manifest.json";
pub const STAGE_MANIFEST_SCHEMA_VERSION: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct StageManifest {
    pub schema_version: u64,
    pub generated_at_unix: u64,
    /// The command that resolved this plan (`vm-lab-orchestrate-live-lab`,
    /// `live-linux-lab-orchestrator`, ...).
    pub run_command: String,
    /// `full` | `setup_only` | `validate_only` | `dry_run`. The conclusion
    /// barrier only synthesizes `aborted` outcomes for planned-but-
    /// unrecorded stages on `full` runs — a setup-only run legitimately
    /// records nothing for the live suite.
    #[serde(default = "default_run_mode")]
    pub run_mode: String,
    pub selectors: ManifestSelectors,
    pub stages: Vec<ManifestStage>,
    /// The node→role topology this run was launched with (the Rust `--node`
    /// path's explicit assignments). Emitted so a consumer — chiefly the
    /// monitor — can show THIS run's live roles instead of inferring them from
    /// the previous finalized run's matrix row. Empty on the bash/wrapper path
    /// (whose topology comes from selectors + inventory, not `--node`).
    #[serde(default)]
    pub node_assignments: Vec<ManifestNodeAssignment>,
    /// Present only for a Rust `--node` (native) run; `None` on the bash/wrapper
    /// path. It carries the run-identity and resolved-plan binding the monitor
    /// needs to evaluate a stage/run for `VerifiedPass` under the strict native
    /// rules (execution dialect, run instance, plan kind + digest, required
    /// cleanup). `#[serde(default)]` keeps a bash manifest — which never emits
    /// this block — readable, and its presence is itself the dialect signal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub native_run: Option<NativeRunManifest>,
}

/// The native-dialect run binding recorded in the manifest (§3.4). The stage
/// selection/omission itself is NOT duplicated here — it is the existing
/// `stages` list's `enabled`/`skip_reason` — so there is one source for
/// enablement. This block adds only what the shared manifest did not already
/// carry: the dialect marker and the run/plan identity a monitor cross-checks
/// against `state/stages.tsv` (generation) and `state/resolved_plan.json`
/// (digest, kind, cleanup) before rendering a stage green.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NativeRunManifest {
    /// Always `native_node_v1` when emitted; a legacy dialect presented as
    /// native, or any other value, is a producer error to the monitor.
    pub execution_dialect: String,
    /// This run's instance id (the report-dir lease id, §3.1.1). Must match the
    /// `run_instance_id` on the current-generation `stages.tsv` rows.
    pub run_instance_id: String,
    /// `standard` | `focused` | `adjudication` — the resolved plan kind.
    pub plan_kind: String,
    /// SHA-256 digest of the resolved plan (`state/resolved_plan.json`). Binds
    /// the manifest to the exact plan the run was resolved from.
    pub resolved_plan_digest: String,
    /// The canonical stage ids the resolved plan marks as mandatory cleanup —
    /// each must be a current-generation pass for the run to be a release pass.
    pub required_cleanup_stage_ids: Vec<String>,
}

/// The one accepted native execution dialect. A manifest `native_run` whose
/// `execution_dialect` is any other value is a producer/version error.
pub const NATIVE_EXECUTION_DIALECT: &str = "native_node_v1";

/// One `<alias>:<role>` assignment from a Rust `--node` run, recorded in the
/// manifest so consumers render the current run's topology (emit-don't-infer).
/// Platform is intentionally absent — a consumer already knows each alias's OS
/// from the inventory; the run only adds the role.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestNodeAssignment {
    pub alias: String,
    pub role: String,
}

/// Snapshot of the selectors the plan was resolved from — recorded so a
/// consumer can re-derive or audit the enablement decisions.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestSelectors {
    pub wants_macos: bool,
    pub wants_windows: bool,
    pub macos_promote_exit: bool,
    #[serde(default)]
    pub exit_platform: String,
    #[serde(default)]
    pub relay_platform: String,
    #[serde(default)]
    pub anchor_platform: String,
    #[serde(default)]
    pub admin_platform: String,
    #[serde(default)]
    pub blind_exit_platform: String,
    #[serde(default)]
    pub role_switch_platform: String,
    pub skip_linux_live_suite: bool,
    pub chaos_suite: bool,
    pub cross_network_suite: bool,
    // The remaining suite selectors, recorded so a verifier can re-derive the
    // full enablement decision from the manifest alone (anti-shrink cross-check).
    // `#[serde(default)]` keeps a pre-existing manifest without them readable.
    #[serde(default)]
    pub soak_suite: bool,
    #[serde(default)]
    pub negative_control_suite: bool,
    #[serde(default)]
    pub relay_forwarding_validation: bool,
    #[serde(default)]
    pub local_gate_suite: bool,
}

impl From<&TargetSelectors> for ManifestSelectors {
    fn from(selectors: &TargetSelectors) -> Self {
        Self {
            wants_macos: selectors.wants_macos,
            wants_windows: selectors.wants_windows,
            macos_promote_exit: selectors.macos_promote_exit,
            exit_platform: selectors.exit_platform.clone(),
            relay_platform: selectors.relay_platform.clone(),
            anchor_platform: selectors.anchor_platform.clone(),
            admin_platform: selectors.admin_platform.clone(),
            blind_exit_platform: selectors.blind_exit_platform.clone(),
            role_switch_platform: selectors.role_switch_platform.clone(),
            skip_linux_live_suite: selectors.skip_linux_live_suite,
            chaos_suite: selectors.chaos_suite,
            cross_network_suite: selectors.cross_network_suite,
            soak_suite: selectors.soak_suite,
            negative_control_suite: selectors.negative_control_suite,
            relay_forwarding_validation: selectors.relay_forwarding_validation,
            local_gate_suite: selectors.local_gate_suite,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManifestStage {
    pub name: String,
    /// pre | bootstrap | live | chaos | job
    pub group: String,
    /// common | linux | macos | windows
    pub stream: String,
    pub enabled: bool,
    /// Present exactly when `enabled` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skip_reason: Option<String>,
    /// Cold-start time budget in seconds.
    pub budget_secs: u64,
    /// hard | soft
    pub severity: String,
    /// Display-only aggregate; never appears in recorded outcomes.
    #[serde(default)]
    pub synthetic: bool,
    /// This execution contributes a real pass/fail check to the run-matrix
    /// evidence model. Consumers use this emitted fact for run-local test
    /// counts instead of guessing from names/groups.
    #[serde(default)]
    pub counts_as_check: bool,
    /// Exempt from the conclusion barrier: job-level bookkeeping stages
    /// and stages whose dispatch is runtime-gated beyond the selectors
    /// (audit sub-passes, cross-network auto mode) — a missing outcome is
    /// not evidence of abnormal termination for these.
    #[serde(default)]
    pub barrier_exempt: bool,
}

fn default_run_mode() -> String {
    "full".to_owned()
}

/// Resolve the full registry into this run's plan.
///
/// `active_plan` is the set of canonical stage names the Rust state-machine
/// `--node` runner will actually dispatch (from `PlanBuilder`) — the only
/// dialect since the W5.7 bash deletion. Enablement is plan membership; a
/// planned stage that records no outcome is caught by the conclusion barrier
/// (Finding 3).
pub fn build_stage_manifest(
    run_command: &str,
    run_mode: &str,
    selectors: &TargetSelectors,
    active_plan: &std::collections::HashSet<String>,
) -> StageManifest {
    let stages = STAGES
        .iter()
        .map(|spec| {
            let (enabled, skip_reason, barrier_exempt) = {
                let plan = active_plan;
                {
                    let enabled = plan.contains(spec.name);
                    let skip_reason = (!enabled)
                        .then(|| "not part of the Rust state-machine plan for this run".to_owned());
                    let barrier_exempt = spec.conditional_dispatch
                        || spec.group == live_lab_stage_registry::StageGroup::Job;
                    (enabled, skip_reason, barrier_exempt)
                }
            };
            ManifestStage {
                name: spec.name.to_owned(),
                group: spec.group.as_str().to_owned(),
                stream: spec.stream.as_str().to_owned(),
                enabled,
                skip_reason,
                budget_secs: spec.budget_secs,
                severity: match spec.severity {
                    live_lab_stage_registry::StageSeverity::Hard => "hard".to_owned(),
                    live_lab_stage_registry::StageSeverity::Soft => "soft".to_owned(),
                },
                synthetic: spec.synthetic,
                counts_as_check: spec.direct_platform.is_some()
                    || spec.logical.is_some()
                    || spec.cross_os.is_some()
                    || spec.special.is_some(),
                barrier_exempt,
            }
        })
        .collect();
    StageManifest {
        schema_version: STAGE_MANIFEST_SCHEMA_VERSION,
        generated_at_unix: unix_now(),
        run_command: run_command.to_owned(),
        run_mode: run_mode.to_owned(),
        selectors: ManifestSelectors::from(selectors),
        stages,
        // Populated by the Rust `--node` path via
        // `ensure_stage_manifest_with_plan`; empty on the bash/wrapper path.
        node_assignments: Vec::new(),
        // Native-dialect binding, set by the `--node` full-run path (see
        // `ensure_stage_manifest_with_plan`); `None` on the bash/wrapper path and
        // on a native setup-only/run-only run (no resolved plan, no release claim).
        native_run: None,
    }
}

/// Write the manifest into `<report_dir>/orchestration/stage_manifest.json`
/// (atomic tmp+rename). Returns the written path.
pub fn write_stage_manifest(
    report_dir: &Path,
    manifest: &StageManifest,
) -> Result<PathBuf, String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("stage manifest path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create orchestration dir failed ({}): {err}",
            parent.display()
        )
    })?;
    let body = serde_json::to_string_pretty(manifest)
        .map_err(|err| format!("serialize stage manifest failed: {err}"))?;
    let tmp_path = path.with_extension("json.tmp");
    fs::write(tmp_path.as_path(), body).map_err(|err| {
        format!(
            "write stage manifest tmp failed ({}): {err}",
            tmp_path.display()
        )
    })?;
    fs::rename(tmp_path.as_path(), path.as_path()).map_err(|err| {
        format!(
            "rename stage manifest into place failed ({}): {err}",
            path.display()
        )
    })?;
    Ok(path)
}

/// Read a previously emitted manifest, if one exists.
pub fn read_stage_manifest(report_dir: &Path) -> Result<Option<StageManifest>, String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    if !path.exists() {
        return Ok(None);
    }
    let body = fs::read_to_string(path.as_path())
        .map_err(|err| format!("read stage manifest failed ({}): {err}", path.display()))?;
    serde_json::from_str(&body)
        .map(Some)
        .map_err(|err| format!("parse stage manifest failed ({}): {err}", path.display()))
}

/// Emit a manifest for the Rust state-machine `--node` path, whose plan is
/// the explicit set of stage names the runner will dispatch. Unlike the bash
/// wrapper's first-writer-wins helper, this REPLACES an existing manifest:
/// run-only/resume/rerun reuse one report directory for multiple invocations,
/// and every invocation must publish its own resolved plan before execution.
pub fn ensure_stage_manifest_with_plan(
    report_dir: &Path,
    run_command: &str,
    run_mode: &str,
    selectors: &TargetSelectors,
    active_plan: &std::collections::HashSet<String>,
    node_assignments: &[ManifestNodeAssignment],
    native_run: Option<NativeRunManifest>,
) -> Result<(PathBuf, bool), String> {
    let path = report_dir.join(STAGE_MANIFEST_RELATIVE_PATH);
    let newly_created = !path.exists();
    let mut manifest = build_stage_manifest(run_command, run_mode, selectors, active_plan);
    manifest.node_assignments = node_assignments.to_vec();
    manifest.native_run = native_run;
    let path = write_stage_manifest(report_dir, &manifest)?;
    Ok((path, newly_created))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_selectors() -> TargetSelectors {
        TargetSelectors {
            wants_macos: true,
            wants_windows: true,
            macos_promote_exit: true,
            exit_platform: "macos".to_owned(),
            relay_platform: "windows".to_owned(),
            anchor_platform: "macos".to_owned(),
            admin_platform: "windows".to_owned(),
            blind_exit_platform: "macos".to_owned(),
            role_switch_platform: "macos".to_owned(),
            skip_linux_live_suite: false,
            chaos_suite: true,
            cross_network_suite: true,
            soak_suite: true,
            local_gate_suite: true,
            negative_control_suite: true,
            relay_forwarding_validation: true,
        }
    }

    #[test]
    fn manifest_covers_every_registry_stage_exactly_once() {
        let manifest = build_stage_manifest(
            "test-run",
            "full",
            &TargetSelectors::default(),
            &std::collections::HashSet::new(),
        );
        let mut names: Vec<&str> = manifest.stages.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), manifest.stages.len(), "duplicate stage names");
        assert_eq!(
            manifest.stages.len(),
            crate::live_lab_stage_registry::STAGES.len()
        );
    }

    #[test]
    fn synthetic_aggregates_are_marked_in_manifest() {
        let manifest = build_stage_manifest(
            "test-run",
            "full",
            &TargetSelectors::default(),
            &std::collections::HashSet::new(),
        );
        let synthetic: Vec<&str> = manifest
            .stages
            .iter()
            .filter(|stage| stage.synthetic)
            .map(|stage| stage.name.as_str())
            .collect();
        assert_eq!(synthetic, vec!["linux_live_suite"]);
    }

    fn rust_plan() -> std::collections::HashSet<String> {
        // A representative Rust state-machine plan: some state_machine_only
        // dialect stages + some shared names.
        [
            "preflight",
            "collect_pubkeys",
            "membership_init",
            "anchor_validation",
            "traffic_test_matrix",
            "active_exit",
            "cleanup",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect()
    }

    #[test]
    fn manifest_selectors_carry_every_suite_flag() {
        // The recorded selector snapshot must include the soak / negative-control
        // / local-gate suites, or a verifier reconstructing the expected plan from
        // the manifest under-counts the enabled set (the L0.4c-iii anti-shrink
        // cross-check reads these).
        let selectors = ManifestSelectors::from(&full_selectors());
        assert!(selectors.soak_suite);
        assert!(selectors.negative_control_suite);
        assert!(selectors.local_gate_suite);
        let json = serde_json::to_string(&selectors).expect("serialize");
        let back: ManifestSelectors = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(selectors, back);
        assert!(back.soak_suite && back.negative_control_suite && back.local_gate_suite);
    }

    #[test]
    fn rust_plan_manifest_enables_planned_dialect_stages_and_makes_them_barrier_eligible() {
        // The dialect inversion: state_machine_only stages that ARE in the
        // Rust plan become enabled with no skip_reason and barrier-ELIGIBLE
        // (barrier_exempt=false), so a vanished Rust stage is caught by the
        // conclusion barrier (Finding 3) instead of hiding.
        let plan = rust_plan();
        let manifest = build_stage_manifest(
            "vm-lab-orchestrate-live-lab",
            "full",
            &TargetSelectors::default(),
            &plan,
        );
        let by_name = |name: &str| {
            manifest
                .stages
                .iter()
                .find(|stage| stage.name == name)
                .unwrap_or_else(|| panic!("{name} missing from manifest"))
        };
        for planned in [
            "membership_init",
            "anchor_validation",
            "active_exit",
            "cleanup",
        ] {
            let stage = by_name(planned);
            assert!(stage.enabled, "{planned} is in the plan => enabled");
            assert_eq!(stage.skip_reason, None, "{planned} has no skip_reason");
            assert!(
                !stage.barrier_exempt,
                "{planned} is barrier-eligible on the Rust path"
            );
        }
    }

    #[test]
    fn rust_plan_manifest_marks_unplanned_bash_dialect_not_planned() {
        // Bash-dialect / sidecar stages the Rust runner does NOT dispatch are
        // enabled=false with the Rust-path skip_reason (the mirror image of
        // the bash-path dead-dialect marking).
        let plan = rust_plan();
        let manifest = build_stage_manifest(
            "vm-lab-orchestrate-live-lab",
            "full",
            &TargetSelectors::default(),
            &plan,
        );
        for unplanned in [
            "membership_setup",
            "distribute_membership_state",
            "validate_linux_hello_limiter_flood",
            "live_managed_dns",
        ] {
            let stage = manifest
                .stages
                .iter()
                .find(|stage| stage.name == unplanned)
                .unwrap_or_else(|| panic!("{unplanned} missing"));
            assert!(
                !stage.enabled,
                "{unplanned} not in the Rust plan => not-planned"
            );
            assert_eq!(
                stage.skip_reason.as_deref(),
                Some("not part of the Rust state-machine plan for this run"),
                "{unplanned} skip_reason"
            );
        }
    }

    #[test]
    fn rust_plan_manifest_still_covers_every_registry_stage_exactly_once() {
        let plan = rust_plan();
        let manifest = build_stage_manifest("test-run", "full", &TargetSelectors::default(), &plan);
        let mut names: Vec<&str> = manifest.stages.iter().map(|s| s.name.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), manifest.stages.len(), "duplicate stage names");
        assert_eq!(
            manifest.stages.len(),
            crate::live_lab_stage_registry::STAGES.len()
        );
    }
}
