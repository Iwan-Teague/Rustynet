//! Evidence emission + finalization for the Rust-native `--node` engine.
//!
//! Extracted from `vm_lab/mod.rs` (RNQ-15, behavior-preserving move): the
//! realtime `stages.tsv` recorder, per-stage log writer, node-stage plan,
//! run-summary/nodes.tsv writer, failure digest, reuse-evidence sealing +
//! validation, and the manifest target-selector resolution. Everything here
//! observes the SAME evidence contract as the bash engine (one schema, one
//! stage-vocabulary owner) so downstream consumers cannot tell the engines
//! apart by artifact shape.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::vm_lab::orchestrator;
use crate::vm_lab::orchestrator::stage::scenario;
use crate::vm_lab::{
    LiveLabFileBinding, LiveLabReportState, LiveLabRunModeFlags, LiveLabRunProvenance,
    REPORT_STATE_RELATIVE_PATH, VmGuestPlatform, VmLabOrchestrateLiveLabConfig, VmLabStageOutcome,
    VmLabStageStatus, collected_at_utc_now, current_git_provenance, current_wrapper_source_binding,
    extract_iteration_likely_reason, git_head_commit, git_worktree_is_dirty,
    normalize_manifest_path, parse_live_lab_stage_records, read_report_state, report_dir_sha256,
    setup_manifest_sha256, validate_live_lab_run_artifacts,
};

/// Serialize a report-state envelope and commit it durably (RNQ-05): the
/// report_state.json write goes through the shared atomic temp+fsync+dir-fsync
/// primitive so the run's commit marker (`run_passed`) can never be observed
/// torn and survives a crash the instant after it returns `Ok`. This is the
/// durable equivalent of the bash-path `write_report_state` plain write.
fn write_report_state_durable(report_dir: &Path, state: &LiveLabReportState) -> Result<(), String> {
    let path = report_dir.join(REPORT_STATE_RELATIVE_PATH);
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|err| format!("serialize rust-native report state failed: {err}"))?;
    orchestrator::context::atomic_write_fsync(&path, &bytes, None)
}

pub(crate) fn write_rust_native_report_state_initial(
    report_dir: &Path,
    _source_mode: &str,
    _repo_ref: Option<&str>,
) -> Result<(), String> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock failure while building rust-native report state: {err}"))?
        .as_secs();
    let setup_manifest_sha256 = setup_manifest_sha256(report_dir)
        .unwrap_or_else(|_| "rust-native-no-setup-manifest".to_owned());
    let state = LiveLabReportState {
        version: 1,
        created_at_unix: now,
        updated_at_unix: now,
        report_dir_path: normalize_manifest_path(report_dir),
        report_dir_sha256: report_dir_sha256(report_dir),
        setup_manifest_sha256,
        setup_complete: false,
        run_complete: false,
        run_passed: false,
        full_release_gate_requested: false,
        full_release_evidence_complete: false,
        last_run: None,
        // QH-34: sample worktree cleanliness HERE, at run start. This function is
        // called immediately before readiness, which is the first thing that
        // rewrites `vm_lab_inventory.json` with live guest IPs; every later
        // sample (the run summary's `git_tree_clean`, `last_run.git`, and the
        // run-matrix renderer's own fallback `git status`) therefore reads the
        // orchestrator's own inventory write as operator dirt and reports
        // `dirty:worktree` on a run that started from a clean, committed tree.
        // Sampling before the mutation is what keeps the signal meaningful for
        // genuinely dirty trees instead of excluding the inventory and letting a
        // hand-edited one go unflagged.
        run_start_git_tree_clean: git_worktree_is_dirty().ok().map(|dirty| !dirty),
    };
    write_report_state_durable(report_dir, &state)
}

pub(crate) fn write_rust_native_report_state_final(
    report_dir: &Path,
    run_passed: bool,
    source_mode: &str,
    repo_ref: Option<&str>,
    _skip_live_suite: bool,
    skip_soak: bool,
    skip_cross_network: bool,
) -> Result<(), String> {
    let mut state = read_report_state(report_dir)?;
    state.updated_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("clock failure while updating rust-native run state: {err}"))?
        .as_secs();
    state.run_complete = true;
    state.run_passed = run_passed;
    let run_flags = LiveLabRunModeFlags {
        dry_run: false,
        skip_setup: false,
        skip_gates: false,
        skip_soak,
        skip_cross_network,
    };
    let provenance = LiveLabRunProvenance {
        invoked_at_unix: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("clock failure: {err}"))?
            .as_secs(),
        profile: LiveLabFileBinding {
            path: "rust-native-orchestrator".to_owned(),
            sha256: "rust-native-no-profile".to_owned(),
        },
        profile_semantic_sha256: "rust-native-no-profile".to_owned(),
        script: LiveLabFileBinding {
            path: "rust-native-orchestrator".to_owned(),
            sha256: "rust-native-no-script".to_owned(),
        },
        wrapper_source: current_wrapper_source_binding()?,
        wrapper_version: env!("CARGO_PKG_VERSION").to_owned(),
        git: current_git_provenance(source_mode, repo_ref)?,
        run_flags,
    };
    state.last_run = Some(provenance);
    write_report_state_durable(report_dir, &state)
}

/// Resolve this orchestrate invocation's flags into the registry's
/// [`TargetSelectors`], mirroring the monitor's `wants_macos`/`wants_windows`
/// gating: a platform stream is wanted when its guest VM is selected or any
/// role is elected onto that platform.
pub(crate) fn orchestrate_manifest_selectors(
    config: &VmLabOrchestrateLiveLabConfig,
) -> crate::live_lab_stage_registry::TargetSelectors {
    let platform_elected = |platform: &str| {
        [
            config.exit_platform.as_deref(),
            config.relay_platform.as_deref(),
            config.anchor_platform.as_deref(),
            config.admin_platform.as_deref(),
            config.blind_exit_platform.as_deref(),
            config.role_switch_platform.as_deref(),
        ]
        .into_iter()
        .any(|selector| selector == Some(platform))
    };
    crate::live_lab_stage_registry::TargetSelectors {
        wants_macos: config.macos_vm.is_some()
            || config.macos_promote_exit
            || platform_elected("macos"),
        wants_windows: config.windows_vm.is_some()
            || config.windows_only
            || platform_elected("windows"),
        macos_promote_exit: config.macos_promote_exit,
        exit_platform: config.exit_platform.clone().unwrap_or_default(),
        relay_platform: config.relay_platform.clone().unwrap_or_default(),
        anchor_platform: config.anchor_platform.clone().unwrap_or_default(),
        admin_platform: config.admin_platform.clone().unwrap_or_default(),
        blind_exit_platform: config.blind_exit_platform.clone().unwrap_or_default(),
        role_switch_platform: config.role_switch_platform.clone().unwrap_or_default(),
        skip_linux_live_suite: config.skip_linux_live_suite,
        chaos_suite: config.enable_chaos_suite,
        cross_network_suite: !config.skip_cross_network,
        soak_suite: !config.skip_soak,
        local_gate_suite: !config.skip_gates,
        negative_control_suite: config.enable_negative_control,
        relay_forwarding_validation: config.enable_relay_forwarding_validation,
    }
}

/// The registry severity string for a stage (defaults `hard` for an
/// unregistered name — every Rust `StageId` is registered, drift-gated).
fn registry_severity_str(stage: &str) -> &'static str {
    match crate::live_lab_stage_registry::find_stage(stage).map(|spec| spec.severity) {
        Some(crate::live_lab_stage_registry::StageSeverity::Soft) => "soft",
        _ => "hard",
    }
}

fn rust_native_stage_log_path(report_dir: &Path, stage: &str) -> PathBuf {
    report_dir.join("logs").join(format!("{stage}.log"))
}

const RUST_NATIVE_REUSE_SEAL_RELATIVE_PATH: &str = "state/reuse_evidence.sha256";

fn rust_native_reuse_evidence_digest(report_dir: &Path) -> Result<String, String> {
    let mut hasher = Sha256::new();
    for relative in [
        crate::live_lab_stage_manifest::STAGE_MANIFEST_RELATIVE_PATH,
        crate::live_lab_stage_recorder::STAGES_TSV_RELATIVE_PATH,
        "state/orchestration_context.json",
    ] {
        let path = report_dir.join(relative);
        let bytes = fs::read(&path).map_err(|err| {
            format!(
                "read reuse evidence component '{}' failed: {err}",
                path.display()
            )
        })?;
        hasher.update(relative.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    let mut records = parse_live_lab_stage_records(report_dir)?;
    records.sort_by(|a, b| a.name.cmp(&b.name));
    for record in records {
        let bytes = fs::read(&record.log_path).map_err(|err| {
            format!(
                "read reuse stage log '{}' failed: {err}",
                record.log_path.display()
            )
        })?;
        hasher.update(record.name.as_bytes());
        hasher.update([0]);
        hasher.update(bytes);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

pub(crate) fn write_rust_native_reuse_evidence_seal(report_dir: &Path) -> Result<(), String> {
    let digest = rust_native_reuse_evidence_digest(report_dir)?;
    let path = report_dir.join(RUST_NATIVE_REUSE_SEAL_RELATIVE_PATH);
    let parent = path
        .parent()
        .ok_or_else(|| format!("reuse seal has no parent: {}", path.display()))?;
    fs::create_dir_all(parent)
        .map_err(|err| format!("create reuse seal directory '{}': {err}", parent.display()))?;
    let tmp = path.with_extension("sha256.tmp");
    fs::write(&tmp, format!("{digest}\n"))
        .map_err(|err| format!("write reuse seal temp '{}': {err}", tmp.display()))?;
    fs::rename(&tmp, &path).map_err(|err| format!("install reuse seal '{}': {err}", path.display()))
}

/// Validate every stage selected for reuse against terminal evidence from the
/// prior invocation, then return one digest binding the manifest, stage rows,
/// and persisted orchestration context. Missing, non-pass, or tampered inputs
/// fail before the runner can mutate a guest.
pub(crate) fn validate_rust_native_reuse_evidence(
    report_dir: &Path,
    stage_ids: &[orchestrator::stage::StageId],
) -> Result<String, String> {
    let state = read_report_state(report_dir)?;
    if !state.run_complete || !state.run_passed {
        return Err("reuse requires a prior completed, passing run state".to_owned());
    }
    let manifest = crate::live_lab_stage_manifest::read_stage_manifest(report_dir)?
        .ok_or_else(|| "reuse requires orchestration/stage_manifest.json".to_owned())?;
    let records = parse_live_lab_stage_records(report_dir)?;
    for id in stage_ids {
        let name = id.as_str();
        if !manifest
            .stages
            .iter()
            .any(|stage| stage.name == name && stage.enabled)
        {
            return Err(format!(
                "cannot reuse stage '{name}': prior manifest did not enable it"
            ));
        }
        let record = records
            .iter()
            .find(|record| record.name == name)
            .ok_or_else(|| format!("cannot reuse stage '{name}': no prior terminal record"))?;
        if record.status != "pass" && record.status != "reused" {
            return Err(format!(
                "cannot reuse stage '{name}': prior status is '{}' (pass/reused required)",
                record.status
            ));
        }
        if !record.log_path.is_file() {
            return Err(format!(
                "cannot reuse stage '{name}': prior log missing ({})",
                record.log_path.display()
            ));
        }
    }

    let sealed = fs::read_to_string(report_dir.join(RUST_NATIVE_REUSE_SEAL_RELATIVE_PATH))
        .map_err(|err| format!("reuse evidence seal missing or unreadable: {err}"))?;
    let sealed = sealed.trim();
    if sealed.len() != 64 || !sealed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("reuse evidence seal is malformed".to_owned());
    }
    let actual = rust_native_reuse_evidence_digest(report_dir)?;
    if sealed != actual {
        return Err(format!(
            "reuse evidence digest mismatch: sealed={sealed} actual={actual}"
        ));
    }
    Ok(actual)
}

pub(crate) fn rust_native_vm_lab_stage_outcome(
    report_dir: &Path,
    parity_path: &Path,
    id: &orchestrator::stage::StageId,
    outcome: &orchestrator::error::StageOutcome,
) -> VmLabStageOutcome {
    use orchestrator::error::StageOutcome;

    VmLabStageOutcome {
        stage: id.as_str().to_owned(),
        status: match outcome {
            StageOutcome::Passed => VmLabStageStatus::Pass,
            StageOutcome::Failed(_) => VmLabStageStatus::Fail,
            StageOutcome::NotProven { .. } => VmLabStageStatus::NotProven,
            StageOutcome::Skipped(..) | StageOutcome::NotRun | StageOutcome::Reused { .. } => {
                VmLabStageStatus::Skipped
            }
        },
        summary: match outcome {
            StageOutcome::Passed => String::new(),
            StageOutcome::Failed(err) => err.clone(),
            StageOutcome::Skipped(reason) => format!("skipped: {reason}"),
            StageOutcome::NotRun => "not_run: omitted by focused invocation".to_owned(),
            StageOutcome::Reused { evidence_sha256 } => {
                format!("reused prior pass evidence sha256={evidence_sha256}")
            }
            StageOutcome::NotProven { reason, detail } => {
                if detail.is_empty() {
                    format!("not_proven: {}", reason.as_str())
                } else {
                    format!("not_proven: {} ({detail})", reason.as_str())
                }
            }
        },
        artifacts: vec![
            rust_native_stage_log_path(report_dir, id.as_str())
                .display()
                .to_string(),
            parity_path.display().to_string(),
        ],
    }
}

/// [`StageObserver`](orchestrator::runner::StageObserver) that emits the
/// realtime `stages.tsv` contract for a `--node` run: a `running` row when a
/// stage starts, replaced by its terminal outcome when it finishes. Recorder
/// failures are accumulated and fail evidence finalization. `started_at` is
/// remembered across the start→finish pair so the terminal row keeps it.
pub(crate) struct RustNativeStageRecorder<'a> {
    pub(crate) report_dir: &'a Path,
    pub(crate) started_at: std::cell::RefCell<std::collections::HashMap<String, String>>,
    pub(crate) errors: std::cell::RefCell<Vec<String>>,
    /// The run instance minted by this invocation's report-dir lease. Every
    /// `stages.tsv` row this recorder writes is stamped with it so a later
    /// generation cannot read the row as fresh evidence (L0.2 §3.1.1). `None`
    /// only in tests that exercise the recorder without a lease.
    pub(crate) run_instance_id: Option<String>,
}

pub(crate) fn write_rust_native_node_stage_plan(
    report_dir: &Path,
    stages: &[Box<dyn orchestrator::stage::OrchestrationStage>],
) -> Result<(), String> {
    use orchestrator::stage::StageFanout;

    let entries: Vec<serde_json::Value> = stages
        .iter()
        .map(|stage| {
            let fanout = match stage.fanout() {
                StageFanout::Once => "once",
                StageFanout::PerNode => "per_node",
            };
            serde_json::json!({
                "stage": stage.id().as_str(),
                "fanout": fanout,
                "roles": stage
                    .applies_to_roles()
                    .iter()
                    .map(orchestrator::role::NodeRole::as_str)
                    .collect::<Vec<_>>(),
            })
        })
        .collect();
    let body = serde_json::to_vec_pretty(&serde_json::json!({
        "schema_version": 1,
        "source": "resolved Rust --node orchestration plan",
        "stages": entries,
    }))
    .map_err(|err| format!("serialize node-stage plan failed: {err}"))?;
    let path = report_dir.join("state/node_stage_plan.json");
    let parent = path
        .parent()
        .ok_or_else(|| format!("node-stage plan path has no parent: {}", path.display()))?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create node-stage plan directory failed ({}): {err}",
            parent.display()
        )
    })?;
    fs::write(&path, body)
        .map_err(|err| format!("write node-stage plan failed ({}): {err}", path.display()))
}

impl RustNativeStageRecorder<'_> {
    /// Per-stage log file: `<report_dir>/logs/<stage>.log`. The Rust stages run
    /// in-process, so (unlike the bash stage wrappers) their output is not
    /// captured to a file by default — this gives get_stage_log / diagnose /
    /// the monitor tail / validate_live_lab_run_artifacts a real path to read.
    fn stage_log_path(&self, name: &str) -> PathBuf {
        rust_native_stage_log_path(self.report_dir, name)
    }

    fn record_error(&self, operation: &str, stage: &str, err: impl std::fmt::Display) {
        self.errors
            .borrow_mut()
            .push(format!("{operation} for stage '{stage}' failed: {err}"));
    }

    pub(crate) fn take_errors(&self) -> Vec<String> {
        std::mem::take(&mut *self.errors.borrow_mut())
    }
}

/// The QH-32 heartbeat line for a stage start, as a pure function so its
/// exact shape is unit-testable: one line, timestamped, naming the stage.
fn stage_started_heartbeat_line(now: &str, stage: &str) -> String {
    format!("[stage] {now} {stage} started")
}

/// The QH-32 heartbeat line for a stage finish. An outcome with no summary
/// (e.g. a pass) prints bare; anything else carries the first line of the
/// summary truncated to 200 characters plus a pointer to the full stage log,
/// so a terminal watcher learns what failed without leaving the console.
fn stage_finished_heartbeat_line(
    now: &str,
    stage: &str,
    status: &str,
    summary: &str,
    log_path: &std::path::Path,
) -> String {
    if summary.trim().is_empty() {
        format!("[stage] {now} {stage} {status}")
    } else {
        let first_line = summary.lines().next().unwrap_or_default();
        let brief: String = first_line.chars().take(200).collect();
        format!(
            "[stage] {now} {stage} {status}: {brief} (complete stage log: {})",
            log_path.display()
        )
    }
}

impl orchestrator::runner::StageObserver for RustNativeStageRecorder<'_> {
    fn stage_started(&self, id: &orchestrator::stage::StageId) {
        let name = id.as_str();
        let now = collected_at_utc_now();
        // QH-32: echo progress to stderr. Without this a run prints a few
        // banner lines at launch and then NOTHING for 30-45 minutes, because
        // all progress goes to state/stages.tsv and per-stage log files. From a
        // terminal "working" and "hung" are then indistinguishable, and a
        // healthy run has been diagnosed as crashed on exactly that basis.
        // stderr, not stdout, so machine-readable stdout contracts are
        // unaffected.
        eprintln!("{}", stage_started_heartbeat_line(&now, name));
        self.started_at
            .borrow_mut()
            .insert(name.to_owned(), now.clone());
        let log_path = self.stage_log_path(name);
        // record_stage_start's positional args are (.., log_path, summary, ..)
        // -- these two used to be swapped here, so every `running` row wrote
        // an empty log_path and put the log path itself into the summary
        // column instead. Any reader positionally trusting column 4 as
        // log_path (the recorder's own documented 8-column contract) saw
        // garbage for whichever stage was actively running.
        if let Err(err) = crate::live_lab_stage_recorder::record_stage_start(
            self.report_dir,
            name,
            registry_severity_str(name),
            &log_path.to_string_lossy(),
            "",
            &now,
            // Generation binding: stamp the row with this invocation's run id.
            self.run_instance_id.as_deref(),
        ) {
            self.record_error("record start", name, err);
        }
    }

    fn stage_finished(
        &self,
        id: &orchestrator::stage::StageId,
        outcome: &orchestrator::error::StageOutcome,
    ) {
        use orchestrator::error::StageOutcome;
        let name = id.as_str();
        let (status, rc, summary) = match outcome {
            StageOutcome::Passed => ("pass", "0", String::new()),
            StageOutcome::Failed(err) => ("fail", "1", err.clone()),
            StageOutcome::Skipped(reason) => ("skipped", "", reason.clone()),
            StageOutcome::NotRun => ("not_run", "", "omitted by focused invocation".to_owned()),
            StageOutcome::Reused { evidence_sha256 } => (
                "reused",
                "",
                format!("validated prior pass sha256={evidence_sha256}"),
            ),
            // A blocking non-pass, but not a process-exit failure — rc stays
            // empty like the other non-`fail` states; the `not_proven` status
            // token carries the non-green verdict, and the reason code leads
            // the summary so the classification is never lost.
            StageOutcome::NotProven { reason, detail } => (
                "not_proven",
                "",
                if detail.is_empty() {
                    reason.as_str().to_owned()
                } else {
                    format!("{} ({detail})", reason.as_str())
                },
            ),
        };
        let started = self
            .started_at
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or_default();
        let now = collected_at_utc_now();
        // QH-32 (see stage_started). The failure summary is included because a
        // terminal watcher otherwise learns only that something failed, and has
        // to go find the per-stage log to learn what — the first question asked
        // every time. Truncated so one pathological error cannot flood the
        // console; QH-09: the console line NAMES the stage log so the brief is
        // never read as the whole evidence when the full text sits beside it.
        let log_path = self.stage_log_path(name);
        eprintln!(
            "{}",
            stage_finished_heartbeat_line(&now, name, status, &summary, &log_path)
        );
        // Write the per-stage log so downstream readers (get_stage_log, diagnose,
        // the monitor tail, validate_live_lab_run_artifacts) have a real file.
        // A Rust stage runs in-process; its outcome detail IS the log content
        // (the Failed error carries the per-node failure reason). Best-effort.
        if let Some(parent) = log_path.parent()
            && let Err(err) = fs::create_dir_all(parent)
        {
            self.record_error("create log directory", name, err);
        }
        let log_body = if summary.is_empty() {
            format!("[stage:{name}] {status} (rust --node engine)\n")
        } else {
            format!("[stage:{name}] {status} (rust --node engine)\n{summary}\n")
        };
        if let Err(err) = fs::write(&log_path, log_body) {
            self.record_error("write terminal log", name, err);
        }
        if let Err(err) = crate::live_lab_stage_recorder::record_stage_finish(
            self.report_dir,
            name,
            registry_severity_str(name),
            status,
            rc,
            &log_path.to_string_lossy(),
            &summary,
            &started,
            &now,
            // Generation binding: stamp the row with this invocation's run id.
            self.run_instance_id.as_deref(),
        ) {
            self.record_error("record terminal outcome", name, err);
        }
    }
}

/// Bucket 2 (evidence parity): write `state/nodes.tsv` + `run_summary.json` +
/// `run_summary.md` for a Rust `--node` run, reusing the canonical bash-path
/// writer so both engines produce the SAME evidence shape. Populates `run_note`
/// (read back by the run-matrix append from run_summary.json) so it is no longer
/// dropped for --node runs, and satisfies `validate_live_lab_run_artifacts`
/// (which requires run_summary.json/.md + state/nodes.tsv).
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_rust_native_run_summary(
    report_dir: &Path,
    node_targets: &[(String, String, String, String)],
    node_ids: &std::collections::HashMap<String, String>,
    network_id: &str,
    passed: usize,
    failed: usize,
    skipped: usize,
    total_stages: usize,
    started_unix: u64,
    started_utc: &str,
    source_mode: &str,
    repo_ref: Option<&str>,
    os_versions: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let state_dir = report_dir.join("state");
    fs::create_dir_all(&state_dir)
        .map_err(|err| format!("create state dir for nodes.tsv: {err}"))?;

    // nodes.tsv: label \t target \t node_id \t bootstrap_role \t platform \t os_version
    // — the 6-column shape. Sanitize each field (strip \t/\n/\r → space) so a tab or
    // newline in an operator-supplied inventory alias/target can't shift or split
    // the fixed columns.
    let tsv_safe = |v: &str| v.replace(['\t', '\n', '\r'], " ");
    let nodes_tsv = state_dir.join("nodes.tsv");
    let mut body = String::with_capacity(node_targets.len() * 64);
    for (alias, target, role, platform) in node_targets {
        let node_id = node_ids
            .get(alias)
            .cloned()
            .unwrap_or_else(|| format!("{alias}-bootstrap"));
        body.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            tsv_safe(alias),
            tsv_safe(target),
            tsv_safe(&node_id),
            tsv_safe(role),
            tsv_safe(platform),
            tsv_safe(
                os_versions
                    .get(alias)
                    .map(|s| s.as_str())
                    .unwrap_or(platform)
            ),
        ));
    }
    fs::write(&nodes_tsv, body).map_err(|err| format!("write nodes.tsv: {err}"))?;

    let overall_status = if failed > 0 {
        "fail"
    } else if skipped > 0 {
        "partial"
    } else {
        "pass"
    };
    let run_note = format!(
        "rust --node orchestration: {} node(s), {total_stages} stage(s); \
         passed={passed} failed={failed} skipped={skipped}",
        node_targets.len()
    );

    let finished_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let finished_utc = collected_at_utc_now();
    let elapsed_secs = finished_unix.saturating_sub(started_unix);
    let elapsed_human = format!("{:02}m {:02}s", elapsed_secs / 60, elapsed_secs % 60);

    let config = crate::ops_live_lab_orchestrator::WriteLiveLinuxLabRunSummaryConfig {
        nodes_tsv,
        stages_tsv: report_dir.join("state/stages.tsv"),
        summary_json: report_dir.join("run_summary.json"),
        summary_md: report_dir.join("run_summary.md"),
        run_id: format!("rust-{started_unix}"),
        network_id: network_id.to_owned(),
        report_dir: report_dir.display().to_string(),
        overall_status: overall_status.to_owned(),
        started_at_local: started_utc.to_owned(),
        started_at_utc: started_utc.to_owned(),
        started_at_unix: started_unix,
        finished_at_local: finished_utc.clone(),
        finished_at_utc: finished_utc,
        finished_at_unix: finished_unix,
        elapsed_secs,
        elapsed_human,
        run_note,
        git_commit: git_head_commit().ok(),
        git_tree_clean: git_worktree_is_dirty().ok().map(|dirty| !dirty),
        source_mode: Some(source_mode.to_owned()),
        repo_ref: repo_ref.map(ToOwned::to_owned),
    };
    crate::ops_live_lab_orchestrator::execute_ops_write_live_linux_lab_run_summary(config)
        .map(|_| ())
}

pub(crate) fn write_rust_native_failure_digest(
    report_dir: &Path,
    run_id: &str,
    network_id: &str,
    overall_status: &str,
) -> Result<(), String> {
    let records = parse_live_lab_stage_records(report_dir)?;
    let nodes_path = report_dir.join("state/nodes.tsv");
    let nodes_body = fs::read_to_string(&nodes_path)
        .map_err(|err| format!("read nodes.tsv '{}': {err}", nodes_path.display()))?;
    let nodes = nodes_body
        .lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| {
            let cols = line.split('\t').collect::<Vec<_>>();
            (cols.len() >= 4).then(|| {
                let mut extra = serde_json::Map::new();
                if cols.len() >= 5 {
                    extra.insert("platform".to_owned(), Value::String(cols[4].to_owned()));
                }
                if cols.len() >= 6 {
                    extra.insert("os_version".to_owned(), Value::String(cols[5].to_owned()));
                }
                json!({
                    "label": cols[0],
                    "target": cols[1],
                    "node_id": cols[2],
                    "bootstrap_role": cols[3],
                    "extra": extra,
                })
            })
        })
        .collect::<Vec<_>>();

    let stages = records
        .iter()
        .map(|record| {
            let likely_reason = if record.status == "fail" {
                extract_iteration_likely_reason(record.log_path.as_path())
            } else {
                record.description.clone()
            };
            json!({
                "stage": record.name,
                "severity": record.severity,
                "status": record.status,
                "rc": record.rc.parse::<i64>().unwrap_or(1),
                "description": record.description,
                "log_path": record.log_path.display().to_string(),
                "condensed_result": if record.description.is_empty() {
                    format!("stage {}", record.status)
                } else {
                    record.description.clone()
                },
                "primary_failure_reason": likely_reason,
                "likely_reason": likely_reason,
                "failed_workers": [],
                "extra": {},
            })
        })
        .collect::<Vec<_>>();
    let failed_stages = stages
        .iter()
        .filter(|stage| stage.get("status").and_then(Value::as_str) == Some("fail"))
        .cloned()
        .collect::<Vec<_>>();
    let first_failure = failed_stages.first().cloned().unwrap_or(Value::Null);
    let digest = json!({
        "schema_version": 1,
        "run_id": run_id,
        "network_id": network_id,
        "report_dir": report_dir.display().to_string(),
        "overall_status": overall_status,
        "node_count": nodes.len() as u64,
        "nodes": nodes,
        "stages": stages,
        "failed_stage_count": failed_stages.len() as u64,
        "first_failure": first_failure,
        "extra": {},
    });

    let output_json = report_dir.join("failure_digest.json");
    let output_md = report_dir.join("failure_digest.md");
    fs::write(
        output_json.as_path(),
        serde_json::to_string_pretty(&digest)
            .map_err(|err| format!("serialize failure digest: {err}"))?
            + "\n",
    )
    .map_err(|err| {
        format!(
            "write failure digest json '{}': {err}",
            output_json.display()
        )
    })?;

    let mut lines = vec![
        format!("# Live Lab Failure Digest ({run_id})"),
        String::new(),
        format!("- overall_status: `{overall_status}`"),
        format!("- report_dir: `{}`", report_dir.display()),
        format!(
            "- node_count: `{}`",
            nodes_body.lines().filter(|l| !l.trim().is_empty()).count()
        ),
        String::new(),
        "## Condensed Checks".to_owned(),
        String::new(),
    ];
    for record in &records {
        let detail = if record.description.is_empty() {
            format!("stage {}", record.status)
        } else {
            record.description.clone()
        };
        lines.push(format!(
            "- `{}` `{}`: {}",
            record.status.to_ascii_uppercase(),
            record.name,
            detail
        ));
    }
    lines.extend([String::new(), "## Failure Focus".to_owned(), String::new()]);
    if let Some(first) = records.iter().find(|record| record.status == "fail") {
        lines.push(format!("- first_failed_stage: `{}`", first.name));
        lines.push(format!("- severity: `{}`", first.severity));
        lines.push(format!("- rc: `{}`", first.rc));
        lines.push(format!(
            "- likely_reason: {}",
            extract_iteration_likely_reason(first.log_path.as_path())
        ));
        lines.push(format!("- full_log: `{}`", first.log_path.display()));
    } else {
        lines.push("- no failed stage recorded".to_owned());
    }
    fs::write(output_md.as_path(), lines.join("\n") + "\n").map_err(|err| {
        format!(
            "write failure digest markdown '{}': {err}",
            output_md.display()
        )
    })?;
    Ok(())
}

/// Validate a per-node OS-version string collected for `nodes.tsv` evidence.
///
/// Evidence truth (§4.1, ledger 2026-07-11): a Linux/macOS/Windows node must
/// yield a real, attributable distro+version. A transient first-connection SSH
/// probe used to degrade silently to a bare platform placeholder
/// (`"linux"`/`"macos"`/`"windows"`), which the run-matrix finalizer then
/// refused — silently dropping the ENTIRE per-node append so even a green run
/// left no §10.9 row. This fails loud, early, and attributably against the
/// single `normalize_os_family` authority instead. Unsupported-by-design mobile
/// adapters (iOS/Android) do not assert attributable OS evidence and are exempt.
pub(crate) fn validate_collected_os_version(
    platform: VmGuestPlatform,
    alias: &str,
    version: &str,
) -> Result<(), String> {
    if !matches!(
        platform,
        VmGuestPlatform::Linux | VmGuestPlatform::Macos | VmGuestPlatform::Windows
    ) {
        return Ok(());
    }
    let platform_str = format!("{platform:?}").to_ascii_lowercase();
    crate::live_lab_run_matrix::normalize_os_family(&platform_str, version).map_err(|err| {
        format!(
            "node '{alias}': OS-version probe did not resolve an attributable distro+version \
             (got '{version}'): {err}. The read-only SSH probe likely failed transiently after \
             retries; refusing to record umbrella placeholder evidence that would silently void \
             the run-matrix append."
        )
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// RNQ-05: single durable commit-marker finalizer + per-writer fault injection
// ---------------------------------------------------------------------------

/// The evidence writers a `--node` run's finalization drives, in order. Every
/// one must succeed before the run may claim a pass; a failure at ANY of them
/// demotes the run (no matrix pass row, no `run_passed=true` marker). The
/// [`EvidenceWriter`] tag lets a test inject a fault at exactly one writer and
/// prove that demotion (see [`set_evidence_fault`]).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EvidenceWriter {
    RunSummary,
    FailureDigest,
    ParityInput,
    ArtifactCompleteness,
    ContextPersist,
    PlanIntegrity,
    ReuseSeal,
    CandidateVerdict,
    MatrixAppend,
    DurabilityBarrier,
    CommitMarker,
}

#[cfg(test)]
thread_local! {
    static EVIDENCE_FAULT: std::cell::Cell<Option<EvidenceWriter>> =
        const { std::cell::Cell::new(None) };
}

/// Test-only: arm the next [`finalize_rust_native_run`] to fail at `writer`
/// (or clear the injection with `None`). Thread-local so parallel tests do not
/// contend, and `#[cfg(test)]` so it is never compiled into a release build.
#[cfg(test)]
pub(crate) fn set_evidence_fault(writer: Option<EvidenceWriter>) {
    EVIDENCE_FAULT.with(|cell| cell.set(writer));
}

/// Fault seam consulted at every evidence-writer call site in the finalizer.
/// In a non-test build this is a zero-cost `Ok(())`; under `cfg(test)` it
/// returns an injected error when its tag matches the armed writer.
fn evidence_fault_gate(writer: EvidenceWriter) -> Result<(), String> {
    #[cfg(test)]
    {
        if EVIDENCE_FAULT.with(std::cell::Cell::get) == Some(writer) {
            return Err(format!("injected evidence fault at {writer:?}"));
        }
    }
    let _ = writer;
    Ok(())
}

/// Inputs to [`finalize_rust_native_run`]. Borrowed from the executor's live
/// state so the finalizer owns only the write sequence, not the run.
pub(crate) struct RustNativeFinalizeInputs<'a> {
    /// The run's orchestration context (source of `report_dir`, `node_ids`,
    /// `network_id`, and the persisted-context payload).
    pub ctx: &'a orchestrator::context::OrchestrationContext,
    /// This run's instance id (§3.1.1). The candidate verdict binds to it, so a
    /// release-pass promotion cannot be authorized by a verdict from another run.
    pub run_instance_id: &'a str,
    /// Terminal per-stage outcomes for the whole run.
    pub results: &'a [(
        orchestrator::stage::StageId,
        orchestrator::error::StageOutcome,
    )],
    /// `(alias, target, role, platform)` rows for `nodes.tsv`.
    pub node_targets: &'a [(String, String, String, String)],
    /// Per-alias OS-version strings for `nodes.tsv` evidence.
    pub os_versions: &'a std::collections::HashMap<String, String>,
    /// Outcomes from the readiness phase, prepended to the matrix outcomes.
    pub readiness_outcomes: Vec<VmLabStageOutcome>,
    /// Binding used to persist the run's orchestration context; `Some` for a
    /// full run (not `--setup-only`/`--run-only`), else `None`.
    pub context_binding: Option<orchestrator::context::OrchestrationContextBinding>,
    /// Evidence errors accumulated before finalization (e.g. the stage
    /// recorder's `take_errors()`); any non-empty value demotes the run.
    pub prior_evidence_errors: Vec<String>,
    pub run_started_unix: u64,
    pub run_started_utc: &'a str,
    pub source_mode: &'a str,
    pub repo_ref: Option<&'a str>,
    pub skip_live_suite: bool,
    pub skip_soak: bool,
    pub skip_cross_network: bool,
}

fn write_report_state_marker(
    report_dir: &Path,
    run_passed: bool,
    inputs: &RustNativeFinalizeInputs<'_>,
) -> Result<(), String> {
    write_rust_native_report_state_final(
        report_dir,
        run_passed,
        inputs.source_mode,
        inputs.repo_ref,
        inputs.skip_live_suite,
        inputs.skip_soak,
        inputs.skip_cross_network,
    )
}

/// RNQ-05 durability barrier: force every evidence artifact under the report
/// directory durable before the pass marker itself becomes durable. The
/// commit marker's own fsync makes only `report_state.json` durable — most
/// evidence writers (stage logs, `nodes.tsv`, run summaries, the stage
/// manifest/rows, `orchestrate_result.json`) are plain or rename-only writes
/// whose pages a power loss can still drop, which would leave a durable
/// `run_passed=true` vouching for torn or vanished evidence — exactly the
/// partial pass RNQ-05 forbids. Walks the tree syncing regular files, then
/// syncs every directory. Symlinks are never followed: an evidence tree
/// contains none, and following one could traverse outside the report dir.
/// Unix-only, matching the directory-fsync precedent in
/// [`orchestrator::context::atomic_write_fsync`] (the orchestrator host is
/// macOS/Linux; Windows guests never drive a `--node` run).
fn sync_report_dir_tree(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut pending = vec![root.to_path_buf()];
        let mut directories = Vec::new();
        while let Some(dir) = pending.pop() {
            let entries = fs::read_dir(&dir)
                .map_err(|err| format!("read evidence directory '{}': {err}", dir.display()))?;
            for entry in entries {
                let entry = entry.map_err(|err| {
                    format!(
                        "read evidence directory entry in '{}': {err}",
                        dir.display()
                    )
                })?;
                let file_type = entry.file_type().map_err(|err| {
                    format!("stat evidence entry '{}': {err}", entry.path().display())
                })?;
                if file_type.is_symlink() {
                    continue;
                }
                if file_type.is_dir() {
                    pending.push(entry.path());
                } else if file_type.is_file() {
                    let path = entry.path();
                    fs::File::open(&path)
                        .and_then(|file| file.sync_all())
                        .map_err(|err| format!("sync evidence file '{}': {err}", path.display()))?;
                }
            }
            directories.push(dir);
        }
        for dir in directories {
            fs::File::open(&dir)
                .and_then(|handle| handle.sync_all())
                .map_err(|err| format!("sync evidence directory '{}': {err}", dir.display()))?;
        }
    }
    #[cfg(not(unix))]
    {
        let _ = root;
    }
    Ok(())
}

/// Finalize a `--node` run's evidence as one transaction whose LAST fsync'd
/// write is `report_state.json` with `run_passed=true` — the run's single
/// durable commit marker (RNQ-05).
///
/// Ordering (each write is durable before the next):
/// 1. `run_summary.json`/`.md` + `nodes.tsv`
/// 2. `failure_digest.json`/`.md` (only when a stage failed)
/// 3. `parity_input.json`
/// 4. artifact-completeness validation
/// 5. persist the orchestration context (full run only)
/// 6. reuse-evidence seal (pass candidates only)
/// 7. **fail-closed gate** — if ANY of 1-6 errored, write the not-passed marker
///    and return `Err` WITHOUT appending a matrix row (no pass row is produced)
/// 8. matrix append + `orchestrate_result.json` (`matrix_finalize`)
/// 9. **durability barrier** (pass path only) — fsync every artifact under the
///    report dir so nothing the marker vouches for can be lost to power fail
/// 10. **commit marker LAST** — `report_state.json run_passed = candidate_pass
///     && matrix_finalize succeeded && barrier held`
///
/// A crash anywhere before step 10 leaves `run_passed=false`, so an
/// interrupted run is never mistaken for a pass. `matrix_finalize` is injected
/// so the real run-matrix append (which mutates the repo CSV) stays out of
/// unit tests, and so tests can observe that the marker is written strictly
/// after it.
pub(crate) fn finalize_rust_native_run<F>(
    mut inputs: RustNativeFinalizeInputs<'_>,
    matrix_finalize: F,
) -> Result<String, String>
where
    F: FnOnce(Vec<VmLabStageOutcome>) -> Result<String, String>,
{
    use orchestrator::error::StageOutcome;

    let report_dir = inputs.ctx.report_dir.as_path();
    let mut evidence_errors = std::mem::take(&mut inputs.prior_evidence_errors);

    let passed = inputs
        .results
        .iter()
        .filter(|(_, o)| matches!(o, StageOutcome::Passed))
        .count();
    let failed = inputs
        .results
        .iter()
        .filter(|(_, o)| matches!(o, StageOutcome::Failed(_)))
        .count();
    let skipped = inputs
        .results
        .iter()
        .filter(|(_, o)| {
            matches!(
                o,
                StageOutcome::Skipped(..) | StageOutcome::NotRun | StageOutcome::Reused { .. }
            )
        })
        .count();

    // 1. run_summary.json/.md + state/nodes.tsv
    if let Err(err) = evidence_fault_gate(EvidenceWriter::RunSummary).and_then(|()| {
        write_rust_native_run_summary(
            report_dir,
            inputs.node_targets,
            &inputs.ctx.node_ids,
            inputs.ctx.network_id.as_str(),
            passed,
            failed,
            skipped,
            inputs.results.len(),
            inputs.run_started_unix,
            inputs.run_started_utc,
            inputs.source_mode,
            inputs.repo_ref,
            inputs.os_versions,
        )
    }) {
        evidence_errors.push(format!("write run summary failed: {err}"));
    }

    // 2. failure digest when any stage failed
    if failed > 0 {
        let run_id = format!("rust-{}", inputs.run_started_unix);
        if let Err(err) = evidence_fault_gate(EvidenceWriter::FailureDigest).and_then(|()| {
            write_rust_native_failure_digest(
                report_dir,
                run_id.as_str(),
                inputs.ctx.network_id.as_str(),
                "fail",
            )
        }) {
            evidence_errors.push(format!("write failure digest failed: {err}"));
        }
    }

    // 3. parity_input.json
    let parity_path = report_dir.join("parity_input.json");
    {
        let timestamp_utc = format!(
            "{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        );
        let run_id = format!("rust-{timestamp_utc}");
        let report = orchestrator::parity::build_live_lab_run_report(
            run_id,
            timestamp_utc,
            inputs.ctx,
            inputs.results,
        );
        let write = evidence_fault_gate(EvidenceWriter::ParityInput).and_then(|()| {
            let bytes = serde_json::to_vec_pretty(&report)
                .map_err(|err| format!("serialize snapshot failed: {err}"))?;
            fs::write(&parity_path, &bytes)
                .map_err(|err| format!("at {} failed: {err}", parity_path.display()))
        });
        if let Err(err) = write {
            evidence_errors.push(format!("write parity input snapshot failed: {err}"));
        }
    }

    // Per-stage vm-lab outcomes for the matrix append (readiness first).
    let mut vm_lab_outcomes = std::mem::take(&mut inputs.readiness_outcomes);
    vm_lab_outcomes.extend(inputs.results.iter().map(|(id, outcome)| {
        rust_native_vm_lab_stage_outcome(report_dir, &parity_path, id, outcome)
    }));

    // 4. artifact completeness
    if let Err(err) = evidence_fault_gate(EvidenceWriter::ArtifactCompleteness)
        .and_then(|()| validate_live_lab_run_artifacts(report_dir))
    {
        evidence_errors.push(format!("artifact completeness check failed: {err}"));
    }

    // 5. persist orchestration context (full run only)
    if let Some(binding) = inputs.context_binding.as_ref() {
        let context_path = report_dir.join("state/orchestration_context.json");
        if let Err(err) = evidence_fault_gate(EvidenceWriter::ContextPersist)
            .and_then(|()| inputs.ctx.save_bound(context_path.as_path(), binding))
        {
            evidence_errors.push(format!("persist orchestration context failed: {err}"));
        }
    }

    // 5.5. Anti-plan-shrink gate (§3.1.3, L0.4c-iii): independently reconstruct
    // the expected plan from the recorded selectors and reject a recorded
    // resolved_plan.json that was shrunk (dropped a required stage) or grown.
    // Full native runs only — the check no-ops for setup-only/run-only/bash — so
    // it is gated on `context_binding` (present only for a full run). A mismatch
    // is an evidence error, so the run demotes: no pass verdict, no
    // run_passed=true, no matrix pass row.
    if inputs.context_binding.is_some()
        && let Err(err) = evidence_fault_gate(EvidenceWriter::PlanIntegrity)
            .and_then(|()| orchestrator::resolved_plan::verify_recorded_plan_not_shrunk(report_dir))
    {
        evidence_errors.push(format!("recorded plan integrity check failed: {err}"));
    }

    let not_proven = inputs
        .results
        .iter()
        .filter(|(_, o)| matches!(o, StageOutcome::NotProven { .. }))
        .count();
    // A run is a pass candidate only if NO stage produced a BLOCKING outcome —
    // Failed, NotRun, OR NotProven — and no evidence error occurred. Gating on
    // `is_blocking()` (rather than an ad-hoc failed/not_run pair) is what makes a
    // NotProven leaf demote the run (§2.2: NotProven never converts to pass) and
    // auto-covers any future blocking variant. The prior `failed == 0 &&
    // !has_not_run` form silently omitted NotProven, letting a NotProven leaf
    // reach run_passed=true — the exact non-pass collapse L0 forbids.
    let has_blocking = inputs.results.iter().any(|(_, o)| o.is_blocking());
    let candidate_pass = !has_blocking && evidence_errors.is_empty();

    // 6. reuse-evidence seal — only meaningful for a pass candidate.
    if candidate_pass
        && let Err(err) = evidence_fault_gate(EvidenceWriter::ReuseSeal)
            .and_then(|()| write_rust_native_reuse_evidence_seal(report_dir))
    {
        evidence_errors.push(format!("write reuse evidence seal failed: {err}"));
    }

    // 6.5. Candidate verdict (L0.6): persist the run's durable, run+plan-bound
    // EvidenceVerdict BEFORE the matrix append, so promotion is gated on a
    // verdict that does not depend on the matrix row (removing the old circular
    // ordering). For the L0 baseline — no scenario contracts exist yet — the
    // verdict reflects the finalizer's structural pass determination; L1 layers
    // independent per-scenario re-derivation on top. `will_pass` re-checks the
    // errors accumulated through step 6 (a failed reuse seal must not leave a
    // Passed verdict). The verdict is written on EVERY terminal path: a demote
    // writes a Rejected verdict, and the run_passed=true marker is minted only
    // from a `ReleaseAuthorization`, which exists only for a Passed verdict bound
    // to this run instance and plan digest.
    let plan_digest = orchestrator::resolved_plan::read_recorded_plan(report_dir)
        .map(|plan| plan.digest)
        .unwrap_or_else(|_| scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST.to_owned());

    // L1: INDEPENDENT per-scenario re-derivation (the first non-test caller of
    // pass_certificate::evaluate). Every wired T5 control that emitted a
    // scenario.v1 this run is resolved to its independent contract and its
    // required assertions recomputed from the raw witnesses. The aggregate both
    // binds the durable verdict to the set of contracts + artifacts evaluated
    // and, when ANY scenario does not prove out, DEMOTES the run even if it was
    // structurally green — an independent NotProven/Failed always wins over the
    // scenario's self-report. A scenario present but unbindable (unknown stage /
    // digest mismatch / unreadable evidence) is an integrity fault surfaced as an
    // evidence error (fail closed).
    let scenario_eval =
        match scenario::finalize::evaluate_wired_scenarios(report_dir, inputs.run_instance_id) {
            Ok(eval) => eval,
            Err(err) => {
                evidence_errors.push(format!("scenario evidence present but unresolvable: {err}"));
                None
            }
        };
    let scenario_pass = scenario_eval.as_ref().is_none_or(|e| e.all_passed);
    let will_pass = candidate_pass && evidence_errors.is_empty() && scenario_pass;
    let verdict_detail = format!(
        "{passed} passed, {failed} failed, {not_proven} not_proven, {skipped} skipped; {} evidence error(s)",
        evidence_errors.len()
    );
    let candidate_verdict = match scenario_eval {
        Some(eval) => {
            // The verdict follows the WHOLE run's `will_pass`, bound to the set of
            // contracts + artifacts evaluated. When the scenarios passed but the
            // run failed structurally, the demotion reason is generic; when a
            // scenario failed, its own reason (naming the stage) is carried.
            let (reason_codes, detail) = if will_pass {
                (Vec::new(), String::new())
            } else if eval.all_passed {
                (
                    vec!["failed".to_owned()],
                    "run demoted by a non-scenario stage or evidence failure".to_owned(),
                )
            } else {
                (eval.reason_codes, eval.detail)
            };
            scenario::verdict::EvidenceVerdict::bound(
                inputs.run_instance_id,
                plan_digest.as_str(),
                &eval.contract_digest,
                will_pass,
                reason_codes,
                &detail,
                eval.artifact_digests,
            )
        }
        None => scenario::verdict::EvidenceVerdict::run_level(
            inputs.run_instance_id,
            plan_digest.as_str(),
            will_pass,
            verdict_detail.as_str(),
        ),
    };
    if let Err(err) = evidence_fault_gate(EvidenceWriter::CandidateVerdict)
        .and_then(|()| scenario::verdict::write_evidence_verdict(report_dir, &candidate_verdict))
    {
        evidence_errors.push(format!("write candidate verdict failed: {err}"));
    }
    // The type-level promotion gate: `Some` only when the verdict is Passed and
    // bound to this run instance + plan digest. `None` (a rejected verdict, or a
    // run/plan mismatch) makes a release-pass promotion impossible below.
    let release_auth = scenario::verdict::authorize_release(
        &candidate_verdict,
        inputs.run_instance_id,
        plan_digest.as_str(),
    );

    // 7. Fail-closed gate: any evidence error demotes the run BEFORE the matrix
    // append, so neither a pass row nor a run_passed=true marker is produced.
    if !evidence_errors.is_empty() {
        let _ = write_report_state_marker(report_dir, false, &inputs);
        return Err(format!(
            "Rust --node evidence finalization failed: {}",
            evidence_errors.join("; ")
        ));
    }

    // 8. Matrix append + orchestrate_result.json (the run's Final matrix row).
    let finalized = match evidence_fault_gate(EvidenceWriter::MatrixAppend) {
        Ok(()) => matrix_finalize(vm_lab_outcomes),
        Err(err) => Err(err),
    };
    // The commit marker's `run_passed=true` requires the release authorization
    // (a Passed verdict bound to this run + plan) AND a successful matrix append.
    // `release_auth.is_some()` equals the old `candidate_pass` here — we only
    // reach this line past the step-7 fail-closed gate, so evidence_errors is
    // empty and `will_pass == candidate_pass` — but the promotion is now routed
    // through the type-level token and the durable verdict rather than a bare
    // bool.
    let committed = release_auth.is_some() && finalized.is_ok();

    // 9. Durability barrier, pass path only: the marker's own fsync makes only
    // report_state.json durable, so every artifact it vouches for — stage
    // logs, nodes.tsv, summaries, the manifest/rows, orchestrate_result.json —
    // must be forced durable FIRST, or a power cut after the marker could keep
    // a durable run_passed=true over torn evidence. A demoting run skips the
    // barrier: its marker is written false, which the initial state already
    // holds durably.
    if committed
        && let Err(err) = evidence_fault_gate(EvidenceWriter::DurabilityBarrier)
            .and_then(|()| sync_report_dir_tree(report_dir))
    {
        // The evidence was pass-worthy but could not be made durable, so the run
        // demotes. Rewrite the verdict Rejected before the false marker so the
        // durable verdict and the commit marker agree (a Passed verdict beside a
        // run_passed=false marker would read as a contradiction to the monitor).
        let demoted = scenario::verdict::EvidenceVerdict::run_level(
            inputs.run_instance_id,
            plan_digest.as_str(),
            false,
            "durability barrier failed",
        );
        let _ = scenario::verdict::write_evidence_verdict(report_dir, &demoted);
        let _ = write_report_state_marker(report_dir, false, &inputs);
        return Err(format!("evidence durability barrier failed: {err}"));
    }

    // 10. Commit marker LAST: report_state.json run_passed=committed is the
    // final durable fsync'd write. If it fails, the prior not-passed state
    // persists (fail-closed) and we return Err rather than claim a pass.
    if let Err(err) = evidence_fault_gate(EvidenceWriter::CommitMarker)
        .and_then(|()| write_report_state_marker(report_dir, committed, &inputs))
    {
        return Err(format!("commit marker write failed: {err}"));
    }

    finalized
}

#[cfg(test)]
mod finalize_tests {
    use super::*;
    use crate::vm_lab::orchestrator::context::{OrchestrationContext, OrchestrationContextBinding};
    use crate::vm_lab::orchestrator::error::StageOutcome;
    use crate::vm_lab::orchestrator::role::NodeRole;
    use crate::vm_lab::orchestrator::role_assignment::NodeRoleAssignment;
    use crate::vm_lab::orchestrator::runner::StageObserver;
    use crate::vm_lab::orchestrator::stage::StageId;
    use std::cell::{Cell, RefCell};
    use std::collections::{HashMap, HashSet};
    use tempfile::tempdir;

    /// QH-34: the initial report state must carry a run-start worktree reading.
    ///
    /// This write happens immediately before readiness, which is the first thing
    /// that rewrites `vm_lab_inventory.json`. If the field is missing, the
    /// run-matrix row falls back to a post-mutation sample and reports
    /// `dirty:worktree` for every run, clean tree or not.
    #[test]
    fn initial_report_state_records_the_run_start_worktree_reading() {
        let dir = tempdir().expect("tempdir");
        let report_dir = dir.path();
        fs::create_dir_all(report_dir.join("state")).expect("state dir");

        write_rust_native_report_state_initial(report_dir, "working-tree", None)
            .expect("initial report state");

        let body = fs::read_to_string(report_dir.join("state/report_state.json"))
            .expect("report_state.json must exist");
        let state: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
        assert!(
            state
                .get("run_start_git_tree_clean")
                .is_some_and(|v| v.is_boolean()),
            "initial state must record a boolean run-start worktree reading, got: {state}"
        );
    }

    #[test]
    fn stage_started_writes_log_path_not_summary_in_the_running_row() {
        // Regression: record_stage_start's positional args are
        // (.., log_path, summary, ..). The call site here used to pass them
        // swapped -- every `running` row wrote an empty log_path (column 4
        // of the recorder's documented 8-column contract) and put the real
        // log path into the summary column (column 5) instead. Any
        // positional reader (the monitor's stage_reader.rs, get_stage_log,
        // diagnose) trusting column 4 as log_path saw garbage for whichever
        // stage was actively running.
        let dir = tempdir().expect("tempdir");
        let report_dir = dir.path();
        let recorder = RustNativeStageRecorder {
            report_dir,
            started_at: RefCell::new(HashMap::new()),
            errors: RefCell::new(Vec::new()),
            run_instance_id: None,
        };
        let id = StageId::Preflight;

        recorder.stage_started(&id);

        assert!(
            recorder.take_errors().is_empty(),
            "stage_started must record cleanly"
        );
        let tsv = fs::read_to_string(report_dir.join("state/stages.tsv"))
            .expect("stages.tsv must exist after stage_started");
        let line = tsv.lines().next().expect("one row");
        let cols: Vec<&str> = line.split('\t').collect();
        assert_eq!(cols[2], "running", "status column reads running");
        assert!(
            !cols[4].is_empty(),
            "log_path column (4) must hold the real per-stage log path, got: {cols:?}"
        );
        assert!(
            cols[4].ends_with("preflight.log") || cols[4].contains("preflight"),
            "log_path column must name this stage's log file, got: {cols:?}"
        );
        assert_eq!(
            cols[5], "",
            "summary column (5) must be empty for a just-started stage, got: {cols:?}"
        );
    }

    #[test]
    fn stage_finished_heartbeat_line_truncates_summary_to_first_line_200_chars() {
        let log = Path::new("/tmp/stage.log");

        // Long single-line summary: truncated to the first 200 characters.
        let long = format!("boom: {}", "y".repeat(500));
        let line = stage_finished_heartbeat_line("t", "preflight", "fail", &long, log);
        assert!(
            !line.contains('\n'),
            "heartbeat must stay one line, got: {line:?}"
        );
        assert_eq!(
            line.matches('y').count(),
            194,
            "brief must carry exactly the first 200 chars ('boom: ' + 194 y's), got: {line}"
        );
        assert!(line.contains("fail: boom:"), "got: {line}");
        assert!(
            line.ends_with("(complete stage log: /tmp/stage.log)"),
            "heartbeat must name the stage log, got: {line}"
        );

        // Multi-line summary: only the first line survives.
        let line = stage_finished_heartbeat_line("t", "preflight", "fail", "first\nsecond", log);
        assert!(line.contains("first"), "got: {line}");
        assert!(!line.contains("second"), "got: {line}");

        // Empty summary (a pass): bare line, no summary colon.
        let line = stage_finished_heartbeat_line("t", "preflight", "pass", "", log);
        assert_eq!(line, "[stage] t preflight pass");
    }

    /// QH-32: the observer tees exactly one stderr line per stage transition
    /// — start and finish — with the stage name and outcome present. The
    /// heartbeat is printed with `eprintln!` straight to process stderr, which
    /// an in-process test cannot capture, so this test re-execs this test
    /// binary in a child process (guarded by an env var), runs one
    /// start+finish pair there, and asserts on the captured stderr.
    #[test]
    fn stage_transitions_emit_exactly_one_stderr_line_each() {
        const CHILD_ENV: &str = "RUSTYNET_QH32_HEARTBEAT_CHILD";
        if std::env::var_os(CHILD_ENV).is_some() {
            // Child mode: emit one start + one finish, nothing else to assert.
            let dir = tempdir().expect("tempdir");
            let report_dir = dir.path();
            fs::create_dir_all(report_dir.join("state")).expect("state dir");
            let recorder = RustNativeStageRecorder {
                report_dir,
                started_at: RefCell::new(HashMap::new()),
                errors: RefCell::new(Vec::new()),
                run_instance_id: None,
            };
            let id = StageId::Preflight;
            recorder.stage_started(&id);
            recorder.stage_finished(&id, &StageOutcome::Passed);
            assert!(
                recorder.take_errors().is_empty(),
                "recorder must emit the stage cleanly"
            );
            return;
        }

        // NOTE: the filter is the bare fn name as a substring, not
        // `--exact <full path>` — full-path exact matching proved
        // binary-dependent under `cargo test` (registered vs module_path!()
        // naming diverged in one target), while the substring form matches
        // in every target that contains this test. The name is unique, so
        // the child runs exactly this one test.
        let output = std::process::Command::new(std::env::current_exe().expect("current_exe"))
            .args([
                "stage_transitions_emit_exactly_one_stderr_line_each",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .expect("re-exec this test binary");
        assert!(
            output.status.success(),
            "child harness failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        let lines: Vec<&str> = stderr
            .lines()
            .filter(|l| l.starts_with("[stage] "))
            .collect();
        assert_eq!(
            lines.len(),
            2,
            "start + finish must produce exactly two heartbeat lines, got: {lines:?} \
             (child stderr: {:?}, child stdout: {:?})",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(
            lines[0].contains("preflight") && lines[0].ends_with(" started"),
            "start line must name the stage and the transition, got: {:?}",
            lines[0]
        );
        assert!(
            lines[1].contains("preflight") && lines[1].ends_with(" pass"),
            "finish line must name the stage and the outcome, got: {:?}",
            lines[1]
        );
    }

    /// Emit a terminal stage row (+ its per-stage log) through the real
    /// recorder so `stages.tsv`, the logs, and the reuse-seal inputs are all
    /// consistent with the `results` the finalizer is given.
    fn emit_stage(report_dir: &Path, id: &StageId, outcome: &StageOutcome) {
        let recorder = RustNativeStageRecorder {
            report_dir,
            started_at: RefCell::new(HashMap::new()),
            errors: RefCell::new(Vec::new()),
            run_instance_id: None,
        };
        recorder.stage_started(id);
        recorder.stage_finished(id, outcome);
        assert!(
            recorder.take_errors().is_empty(),
            "recorder must emit the stage cleanly"
        );
    }

    /// Build a valid pre-finalization report dir: initial (not-passed) state,
    /// a stage manifest that enables the emitted stages, and the terminal stage
    /// rows themselves.
    fn prepare_report_dir(report_dir: &Path, emitted: &[(StageId, StageOutcome)]) {
        fs::create_dir_all(report_dir.join("state")).expect("state dir");
        write_rust_native_report_state_initial(report_dir, "working-tree", None)
            .expect("initial report state");
        let active: HashSet<String> = emitted
            .iter()
            .map(|(id, _)| id.as_str().to_owned())
            .collect();
        let manifest = crate::live_lab_stage_manifest::build_stage_manifest(
            "vm-lab-orchestrate-live-lab",
            "full",
            &crate::live_lab_stage_registry::TargetSelectors::default(),
            &active,
        );
        crate::live_lab_stage_manifest::write_stage_manifest(report_dir, &manifest)
            .expect("stage manifest");
        for (id, outcome) in emitted {
            emit_stage(report_dir, id, outcome);
        }
    }

    fn make_ctx(report_dir: &Path) -> OrchestrationContext {
        let mut ctx = OrchestrationContext::new(
            vec![NodeRoleAssignment {
                alias: "exit".to_owned(),
                role: NodeRole::Exit,
            }],
            report_dir.to_path_buf(),
            "net-rnq05".to_owned(),
        );
        ctx.node_ids
            .insert("exit".to_owned(), "exit-node-id".to_owned());
        ctx
    }

    fn make_binding(report_dir: &Path) -> OrchestrationContextBinding {
        OrchestrationContextBinding {
            report_dir: normalize_manifest_path(report_dir),
            inventory_sha256: "inventory-digest".to_owned(),
            source_mode: "working-tree".to_owned(),
            repo_ref: None,
        }
    }

    fn node_targets() -> Vec<(String, String, String, String)> {
        vec![(
            "exit".to_owned(),
            "exit@10.0.0.1".to_owned(),
            "exit".to_owned(),
            "linux".to_owned(),
        )]
    }

    /// Inject a fault at `writer` and assert the run demotes: `Err`, no
    /// `run_passed=true` marker, and — for every writer that runs before the
    /// matrix append — no matrix row was appended at all (no pass row).
    fn assert_fault_demotes(
        writer: EvidenceWriter,
        with_failed_stage: bool,
        expect_contains: &str,
    ) {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let mut emitted = vec![(StageId::Preflight, StageOutcome::Passed)];
        if with_failed_stage {
            emitted.push((
                StageId::TrafficTestMatrix,
                StageOutcome::Failed("client->client ping failed".to_owned()),
            ));
        }
        prepare_report_dir(dir, &emitted);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: Vec::new(),
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };

        let matrix_called = Cell::new(false);
        set_evidence_fault(Some(writer));
        let res = finalize_rust_native_run(inputs, |_outcomes| {
            matrix_called.set(true);
            Ok("stub-matrix".to_owned())
        });
        set_evidence_fault(None);

        let err = res.expect_err("an injected writer fault must demote the run to Err");
        assert!(
            err.contains(expect_contains),
            "fault at {writer:?} error must mention '{expect_contains}': {err}"
        );
        let state = read_report_state(dir).expect("report state must remain readable");
        assert!(
            !state.run_passed,
            "fault at {writer:?} must leave run_passed=false (no commit marker)"
        );
        // Any writer that runs before the matrix append must abort before it,
        // so no matrix pass row is ever produced. Only the DurabilityBarrier
        // and CommitMarker faults happen after the append (that row is
        // reconciled to non-pass by the false marker, RNQ-06).
        if matches!(
            writer,
            EvidenceWriter::DurabilityBarrier | EvidenceWriter::CommitMarker
        ) {
            assert!(
                matrix_called.get(),
                "fault at {writer:?} occurs after the matrix append"
            );
        } else {
            assert!(
                !matrix_called.get(),
                "fault at {writer:?} must abort before the matrix append (no pass row)"
            );
        }
    }

    #[test]
    fn fault_at_run_summary_demotes() {
        assert_fault_demotes(EvidenceWriter::RunSummary, false, "run summary");
    }

    #[test]
    fn fault_at_failure_digest_demotes() {
        assert_fault_demotes(EvidenceWriter::FailureDigest, true, "failure digest");
    }

    #[test]
    fn fault_at_parity_input_demotes() {
        assert_fault_demotes(EvidenceWriter::ParityInput, false, "parity input");
    }

    #[test]
    fn fault_at_artifact_completeness_demotes() {
        assert_fault_demotes(
            EvidenceWriter::ArtifactCompleteness,
            false,
            "artifact completeness",
        );
    }

    #[test]
    fn fault_at_context_persist_demotes() {
        assert_fault_demotes(
            EvidenceWriter::ContextPersist,
            false,
            "orchestration context",
        );
    }

    #[test]
    fn fault_at_plan_integrity_demotes() {
        assert_fault_demotes(EvidenceWriter::PlanIntegrity, false, "plan integrity");
    }

    #[test]
    fn fault_at_reuse_seal_demotes() {
        assert_fault_demotes(EvidenceWriter::ReuseSeal, false, "reuse evidence seal");
    }

    #[test]
    fn fault_at_candidate_verdict_demotes() {
        assert_fault_demotes(EvidenceWriter::CandidateVerdict, false, "candidate verdict");
    }

    #[test]
    fn fault_at_matrix_append_demotes() {
        assert_fault_demotes(EvidenceWriter::MatrixAppend, false, "MatrixAppend");
    }

    /// The barrier runs only on the pass path (after a successful matrix
    /// append); a barrier failure means durability of the evidence the marker
    /// would vouch for cannot be guaranteed, so the run demotes.
    #[test]
    fn fault_at_durability_barrier_demotes() {
        assert_fault_demotes(
            EvidenceWriter::DurabilityBarrier,
            false,
            "durability barrier",
        );
    }

    #[test]
    fn fault_at_commit_marker_demotes() {
        assert_fault_demotes(EvidenceWriter::CommitMarker, false, "commit marker");
    }

    /// The green path: the commit marker is the LAST durable write. At matrix
    /// append time it is still not passed; only after finalization is
    /// `run_passed=true` committed.
    #[test]
    fn green_run_writes_commit_marker_last() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let emitted = vec![(StageId::Preflight, StageOutcome::Passed)];
        prepare_report_dir(dir, &emitted);

        // Before finalization the initial marker is not passed.
        assert!(!read_report_state(dir).expect("initial state").run_passed);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: Vec::new(),
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };

        let marker_at_matrix = Cell::new(None);
        let res = finalize_rust_native_run(inputs, |_outcomes| {
            // The commit marker must NOT yet be true when the matrix row is
            // appended — proving report_state is the strictly-last write.
            let st = read_report_state(dir).expect("state readable at matrix time");
            marker_at_matrix.set(Some(st.run_passed));
            Ok("stub-matrix".to_owned())
        });

        assert!(res.is_ok(), "green run must finalize: {res:?}");
        assert_eq!(
            marker_at_matrix.get(),
            Some(false),
            "commit marker must be written strictly AFTER the matrix append"
        );
        let state = read_report_state(dir).expect("final state");
        assert!(
            state.run_passed && state.run_complete,
            "green finalize must commit run_passed=true last"
        );
    }

    /// The green path also writes a Passed candidate verdict bound to this run
    /// instance and (absent a resolved plan) the no-plan sentinel digest — the
    /// durable, run+plan-bound artifact the marker's promotion is gated on (L0.6).
    #[test]
    fn green_run_writes_a_passed_candidate_verdict() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let emitted = vec![(StageId::Preflight, StageOutcome::Passed)];
        prepare_report_dir(dir, &emitted);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: Vec::new(),
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };
        let res = finalize_rust_native_run(inputs, |_outcomes| Ok("stub-matrix".to_owned()));
        assert!(res.is_ok(), "green run must finalize: {res:?}");

        let verdict = scenario::verdict::read_evidence_verdict(dir).expect("verdict written");
        assert!(verdict.is_pass(), "green run must record a Passed verdict");
        assert_eq!(verdict.run_instance_id, "test-run-instance");
        assert_eq!(
            verdict.plan_digest,
            scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST
        );
        // The verdict must authorize a release for THIS run+plan, and refuse a
        // mismatched run id — proving the marker gate is bound, not a bare bool.
        assert!(
            scenario::verdict::authorize_release(
                &verdict,
                "test-run-instance",
                scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST,
            )
            .is_some()
        );
        assert!(
            scenario::verdict::authorize_release(
                &verdict,
                "some-other-run",
                scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST,
            )
            .is_none()
        );
    }

    /// A failed stage (not an evidence error) proceeds to the matrix append but
    /// records a Rejected verdict, so no release authorization is minted and the
    /// commit marker stays run_passed=false.
    #[test]
    fn failed_stage_writes_a_rejected_verdict_and_no_pass_marker() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let emitted = vec![
            (StageId::Preflight, StageOutcome::Passed),
            (
                StageId::TrafficTestMatrix,
                StageOutcome::Failed("client->client ping failed".to_owned()),
            ),
        ];
        prepare_report_dir(dir, &emitted);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: Vec::new(),
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };
        let res = finalize_rust_native_run(inputs, |_outcomes| Ok("stub-matrix".to_owned()));
        // A failed stage is not a finalization error — the fail row is appended.
        assert!(res.is_ok(), "a failed stage still finalizes: {res:?}");

        let verdict = scenario::verdict::read_evidence_verdict(dir).expect("verdict written");
        assert!(!verdict.is_pass(), "a failed stage must record a non-pass");
        assert!(
            scenario::verdict::authorize_release(
                &verdict,
                "test-run-instance",
                scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST,
            )
            .is_none(),
            "a rejected verdict must never authorize a release"
        );
        assert!(
            !read_report_state(dir).expect("state").run_passed,
            "a failed stage must leave run_passed=false"
        );
    }

    /// P0 regression: a NotProven leaf stage (no Failed, no NotRun, no evidence
    /// error) must NOT reach run_passed=true. NotProven is a blocking non-pass;
    /// the finalizer's pass gate previously omitted it (checked only failed==0 &&
    /// !has_not_run), so a NotProven run silently passed. It must now record a
    /// Rejected verdict and leave run_passed=false — §2.2 "NotProven never
    /// converts to pass".
    #[test]
    fn not_proven_stage_demotes_the_run_and_writes_a_rejected_verdict() {
        use crate::vm_lab::orchestrator::error::ReasonCode;
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let emitted = vec![
            (StageId::Preflight, StageOutcome::Passed),
            (
                StageId::TrafficTestMatrix,
                StageOutcome::NotProven {
                    reason: ReasonCode::MissingWitness,
                    detail: "no ping counter captured".to_owned(),
                },
            ),
        ];
        prepare_report_dir(dir, &emitted);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: Vec::new(),
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };
        let res = finalize_rust_native_run(inputs, |_outcomes| Ok("stub-matrix".to_owned()));
        assert!(res.is_ok(), "a not_proven stage still finalizes: {res:?}");

        let verdict = scenario::verdict::read_evidence_verdict(dir).expect("verdict written");
        assert!(
            !verdict.is_pass(),
            "a NotProven leaf must record a non-pass verdict"
        );
        assert!(
            scenario::verdict::authorize_release(
                &verdict,
                "test-run-instance",
                scenario::verdict::RUN_LEVEL_NO_PLAN_DIGEST,
            )
            .is_none(),
            "a NotProven run must never authorize a release"
        );
        assert!(
            !read_report_state(dir).expect("state").run_passed,
            "a NotProven leaf must leave run_passed=false (the P0 fail-open fix)"
        );
    }

    /// A recorder error carried in as `prior_evidence_errors` (e.g. the stage
    /// recorder's `take_errors()`) demotes the run before the matrix append.
    #[test]
    fn prior_recorder_error_demotes_before_matrix() {
        let tmp = tempdir().expect("tempdir");
        let dir = tmp.path();
        let emitted = vec![(StageId::Preflight, StageOutcome::Passed)];
        prepare_report_dir(dir, &emitted);

        let ctx = make_ctx(dir);
        let os_versions = HashMap::new();
        let targets = node_targets();
        let inputs = RustNativeFinalizeInputs {
            ctx: &ctx,
            run_instance_id: "test-run-instance",
            results: &emitted,
            node_targets: &targets,
            os_versions: &os_versions,
            readiness_outcomes: Vec::new(),
            context_binding: Some(make_binding(dir)),
            prior_evidence_errors: vec!["record start for stage 'preflight' failed".to_owned()],
            run_started_unix: 100,
            run_started_utc: "2026-01-01T00:00:00Z",
            source_mode: "working-tree",
            repo_ref: None,
            skip_live_suite: false,
            skip_soak: true,
            skip_cross_network: true,
        };

        let matrix_called = Cell::new(false);
        let res = finalize_rust_native_run(inputs, |_outcomes| {
            matrix_called.set(true);
            Ok("stub-matrix".to_owned())
        });

        assert!(res.is_err(), "a prior recorder error must demote the run");
        assert!(
            !matrix_called.get(),
            "a prior recorder error must abort before the matrix append"
        );
        assert!(!read_report_state(dir).expect("state").run_passed);
    }
}
