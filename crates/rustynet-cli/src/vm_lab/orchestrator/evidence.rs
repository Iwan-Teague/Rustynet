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
use crate::vm_lab::{
    LiveLabFileBinding, LiveLabReportState, LiveLabRunModeFlags, LiveLabRunProvenance,
    VmGuestPlatform, VmLabOrchestrateLiveLabConfig, VmLabStageOutcome, VmLabStageStatus,
    collected_at_utc_now, current_git_provenance, current_wrapper_source_binding,
    extract_iteration_likely_reason, git_head_commit, git_worktree_is_dirty,
    normalize_manifest_path, parse_live_lab_stage_records, read_report_state, report_dir_sha256,
    setup_manifest_sha256, write_report_state,
};

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
    };
    write_report_state(report_dir, &state)
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
    write_report_state(report_dir, &state)
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
            StageOutcome::Skipped | StageOutcome::NotRun | StageOutcome::Reused { .. } => {
                VmLabStageStatus::Skipped
            }
        },
        summary: match outcome {
            StageOutcome::Passed => String::new(),
            StageOutcome::Failed(err) => err.clone(),
            StageOutcome::Skipped => "skipped".to_owned(),
            StageOutcome::NotRun => "not_run: omitted by focused invocation".to_owned(),
            StageOutcome::Reused { evidence_sha256 } => {
                format!("reused prior pass evidence sha256={evidence_sha256}")
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

impl orchestrator::runner::StageObserver for RustNativeStageRecorder<'_> {
    fn stage_started(&self, id: &orchestrator::stage::StageId) {
        let name = id.as_str();
        let now = collected_at_utc_now();
        self.started_at
            .borrow_mut()
            .insert(name.to_owned(), now.clone());
        let log_path = self.stage_log_path(name);
        if let Err(err) = crate::live_lab_stage_recorder::record_stage_start(
            self.report_dir,
            name,
            registry_severity_str(name),
            "",
            &log_path.to_string_lossy(),
            &now,
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
            StageOutcome::Skipped => ("skipped", "", String::new()),
            StageOutcome::NotRun => ("not_run", "", "omitted by focused invocation".to_owned()),
            StageOutcome::Reused { evidence_sha256 } => (
                "reused",
                "",
                format!("validated prior pass sha256={evidence_sha256}"),
            ),
        };
        let started = self
            .started_at
            .borrow()
            .get(name)
            .cloned()
            .unwrap_or_default();
        let now = collected_at_utc_now();
        // Write the per-stage log so downstream readers (get_stage_log, diagnose,
        // the monitor tail, validate_live_lab_run_artifacts) have a real file.
        // A Rust stage runs in-process; its outcome detail IS the log content
        // (the Failed error carries the per-node failure reason). Best-effort.
        let log_path = self.stage_log_path(name);
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
