#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

const CHECKLIST_DOC_PATH: &str =
    "documents/operations/done/Phase5ReleaseReadinessChecklist_2026-04-12.md";
const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/ReleaseReadinessGuardrails.md",
    CHECKLIST_DOC_PATH,
    "documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md",
];
const DEFAULT_BUNDLE_PATH: &str = "artifacts/release/phase5_readiness_bundle.json";
const DEFAULT_PHASE5_REPORT_PATH: &str = "artifacts/release/phase5_gate_report.json";
const REQUIRED_PHASE5_STEP_IDS: &[&str] = &[
    "cargo_fmt",
    "cargo_clippy",
    "cargo_check",
    "cargo_test",
    "cargo_audit",
    "cargo_deny",
    "phase4_gates",
    "perf_regression_gate",
    "cargo_build",
    "generate_release_sbom",
    "create_release_provenance",
    "require_phase5_docs",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let bundle_path = env::var_os("RUSTYNET_RELEASE_READINESS_BUNDLE_PATH")
        .filter(|value| !value.is_empty())
        .map_or_else(|| root_dir.join(DEFAULT_BUNDLE_PATH), PathBuf::from);
    let phase5_report_path = env::var_os("RUSTYNET_PHASE5_GATE_REPORT_PATH")
        .filter(|value| !value.is_empty())
        .map_or_else(|| root_dir.join(DEFAULT_PHASE5_REPORT_PATH), PathBuf::from);

    let mut bundle = ReleaseReadinessBundle::new(&phase5_report_path);
    write_bundle(&bundle_path, &mut bundle)?;

    run_step(&mut bundle, &bundle_path, "phase5_gates", || {
        run_script(&root_dir, "scripts/ci/phase5_gates.sh", &[])
    })?;
    run_step(
        &mut bundle,
        &bundle_path,
        "validate_phase5_gate_report",
        || validate_phase5_gate_report(&phase5_report_path),
    )?;
    run_step(&mut bundle, &bundle_path, "phase10_gates", || {
        run_script(&root_dir, "scripts/ci/phase10_gates.sh", &[])
    })?;
    run_step(&mut bundle, &bundle_path, "require_readiness_docs", || {
        require_files(&root_dir, REQUIRED_DOCS, "required readiness document")
    })?;

    bundle.overall_status = GateRunStatus::ExecutedPassed;
    write_bundle(&bundle_path, &mut bundle)?;
    println!("Release readiness gates: PASS");
    Ok(())
}

fn run_step<F>(
    bundle: &mut ReleaseReadinessBundle,
    bundle_path: &Path,
    step_id: &str,
    action: F,
) -> Result<(), i32>
where
    F: FnOnce() -> Result<(), StepExecutionError>,
{
    let step = bundle.step_mut(step_id).ok_or_else(|| {
        eprintln!(
            "error [{}]: release readiness bundle is missing step definition: {step_id}",
            ExitCode::ConfigError
        );
        ExitCode::ConfigError.as_i32()
    })?;
    match action() {
        Ok(()) => {
            step.status = GateStepStatus::ExecutedPassed;
            step.exit_code = Some(0);
            step.detail = None;
            write_bundle(bundle_path, bundle)
        }
        Err(err) => {
            step.status = GateStepStatus::ExecutedFailed;
            step.exit_code = Some(err.exit_code);
            step.detail = Some(err.detail);
            bundle.overall_status = GateRunStatus::ExecutedFailed;
            write_bundle(bundle_path, bundle)?;
            Err(err.exit_code)
        }
    }
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), StepExecutionError> {
    let script_path = root_dir.join(script);
    let status = Command::new(&script_path)
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| StepExecutionError {
            // Spawning the script process itself failed (PATH, ENOENT,
            // permission). Classify as TransientFailure so retry-only-
            // on-70 CI loops can re-attempt without operator review.
            exit_code: ExitCode::TransientFailure.as_i32(),
            detail: format!("failed to execute script {}: {err}", script_path.display()),
        })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through the script's own exit code so an inner X6
        // verdict (e.g. PolicyReject from phase5_gates.sh) survives.
        Err(StepExecutionError {
            exit_code: status_code(status),
            detail: format!("script failed: {}", script_path.display()),
        })
    }
}

fn validate_phase5_gate_report(report_path: &Path) -> Result<(), StepExecutionError> {
    let report = read_phase5_gate_report(report_path)?;
    if report.gate != "phase5_ci_gates" {
        // Wrong gate name in the on-disk report = release evidence
        // does not match this release. Fail-closed: PolicyReject.
        return Err(StepExecutionError {
            exit_code: ExitCode::PolicyReject.as_i32(),
            detail: format!(
                "phase5 gate report at {} has unexpected gate name {}",
                report_path.display(),
                report.gate
            ),
        });
    }
    if report.overall_status != GateRunStatus::ExecutedPassed {
        // Release evidence on disk explicitly records a non-pass
        // overall verdict. PolicyReject so retry-only-on-70 loops do
        // not accidentally retry a real release failure.
        return Err(StepExecutionError {
            exit_code: ExitCode::PolicyReject.as_i32(),
            detail: format!(
                "phase5 gate report at {} does not record executed_passed status",
                report_path.display()
            ),
        });
    }
    for required_step in REQUIRED_PHASE5_STEP_IDS {
        if !report
            .required_step_ids
            .iter()
            .any(|step| step == required_step)
        {
            // Required-step set drifted from this binary's pinned list
            // → release evidence is incomplete. PolicyReject.
            return Err(StepExecutionError {
                exit_code: ExitCode::PolicyReject.as_i32(),
                detail: format!(
                    "phase5 gate report at {} is missing required step id {}",
                    report_path.display(),
                    required_step
                ),
            });
        }
        let step = report
            .steps
            .iter()
            .find(|step| step.id == *required_step)
            .ok_or_else(|| StepExecutionError {
                exit_code: ExitCode::PolicyReject.as_i32(),
                detail: format!(
                    "phase5 gate report at {} is missing required step {}",
                    report_path.display(),
                    required_step
                ),
            })?;
        if step.status != GateStepStatus::ExecutedPassed {
            // A required release-evidence step recorded a non-pass
            // status. This is the canonical fail-closed verdict.
            return Err(StepExecutionError {
                exit_code: ExitCode::PolicyReject.as_i32(),
                detail: format!(
                    "phase5 gate report at {} records {} as {:?}, expected executed_passed",
                    report_path.display(),
                    required_step,
                    step.status
                ),
            });
        }
    }
    Ok(())
}

fn read_phase5_gate_report(report_path: &Path) -> Result<Phase5GateReport, StepExecutionError> {
    let raw = fs::read_to_string(report_path).map_err(|err| StepExecutionError {
        // Report on disk could not be read (missing / unreadable).
        // Classify as ConfigError: the release input is malformed or
        // not where it's expected, operator must fix the path/schema.
        exit_code: ExitCode::ConfigError.as_i32(),
        detail: format!(
            "failed to read phase5 gate report {}: {err}",
            report_path.display()
        ),
    })?;
    serde_json::from_str(&raw).map_err(|err| StepExecutionError {
        // Bad JSON in the release evidence file = ConfigError, same
        // reasoning as the read failure above.
        exit_code: ExitCode::ConfigError.as_i32(),
        detail: format!(
            "failed to parse phase5 gate report {}: {err}",
            report_path.display()
        ),
    })
}

fn require_files(root_dir: &Path, paths: &[&str], label: &str) -> Result<(), StepExecutionError> {
    let missing: Vec<String> = paths
        .iter()
        .map(|path| root_dir.join(path))
        .filter(|path| !path.is_file())
        .map(|path| path.display().to_string())
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        // Missing required release-readiness docs = release sign-off
        // evidence is incomplete. Fail-closed: PolicyReject so CI
        // retry loops do not retry a real release-gate verdict.
        Err(StepExecutionError {
            exit_code: ExitCode::PolicyReject.as_i32(),
            detail: format!("missing {label}: {}", missing.join(", ")),
        })
    }
}

fn write_bundle(path: &Path, bundle: &mut ReleaseReadinessBundle) -> Result<(), i32> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            eprintln!(
                "error [{}]: failed to create bundle directory {}: {err}",
                ExitCode::TransientFailure,
                parent.display()
            );
            ExitCode::TransientFailure.as_i32()
        })?;
    }
    bundle.generated_at_unix = now_unix().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::TransientFailure);
        ExitCode::TransientFailure.as_i32()
    })?;
    let json = serde_json::to_vec_pretty(bundle).map_err(|err| {
        // Internal serialization error against a strongly typed
        // schema: there is no operator fix beyond a code change, so
        // surface as GenericFailure rather than ConfigError.
        eprintln!(
            "error [{}]: failed to serialize release readiness bundle: {err}",
            ExitCode::GenericFailure
        );
        ExitCode::GenericFailure.as_i32()
    })?;
    fs::write(path, json).map_err(|err| {
        eprintln!(
            "error [{}]: failed to write release readiness bundle {}: {err}",
            ExitCode::TransientFailure,
            path.display()
        );
        ExitCode::TransientFailure.as_i32()
    })
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("clock failure while generating release readiness bundle: {err}"))
}

fn repo_root() -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| {
            format!(
                "failed to resolve repository root from manifest dir {}",
                manifest_dir.display()
            )
        })
}

fn status_code(status: ExitStatus) -> i32 {
    match status.code() {
        Some(code) => code,
        None => {
            #[cfg(unix)]
            {
                use std::os::unix::process::ExitStatusExt;

                match status.signal() {
                    Some(signal) => 128 + signal,
                    None => 1,
                }
            }
            #[cfg(not(unix))]
            {
                1
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GateRunStatus {
    ExecutedPassed,
    ExecutedFailed,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GateStepStatus {
    ExecutedPassed,
    ExecutedFailed,
    NotExecuted,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReleaseGateStep {
    id: String,
    description: String,
    command: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    expected_paths: Vec<String>,
    status: GateStepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

impl ReleaseGateStep {
    fn new(id: &str, description: &str, command: &[&str]) -> Self {
        Self {
            id: id.to_owned(),
            description: description.to_owned(),
            command: command.iter().map(|item| (*item).to_owned()).collect(),
            expected_paths: Vec::new(),
            status: GateStepStatus::NotExecuted,
            exit_code: None,
            detail: None,
        }
    }

    fn with_expected_paths(mut self, paths: &[&str]) -> Self {
        self.expected_paths = paths.iter().map(|path| (*path).to_owned()).collect();
        self
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct ReleaseReadinessBundle {
    schema_version: u32,
    gate: String,
    overall_status: GateRunStatus,
    generated_at_unix: u64,
    summary_doc: String,
    checklist_doc: String,
    phase5_gate_report_path: String,
    required_phase5_step_ids: Vec<String>,
    steps: Vec<ReleaseGateStep>,
}

impl ReleaseReadinessBundle {
    fn new(phase5_gate_report_path: &Path) -> Self {
        Self {
            schema_version: 2,
            gate: "release_readiness_gates".to_owned(),
            overall_status: GateRunStatus::ExecutedFailed,
            generated_at_unix: 0,
            summary_doc:
                "documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md".to_owned(),
            checklist_doc: CHECKLIST_DOC_PATH.to_owned(),
            phase5_gate_report_path: phase5_gate_report_path.display().to_string(),
            required_phase5_step_ids: REQUIRED_PHASE5_STEP_IDS
                .iter()
                .map(|step| (*step).to_owned())
                .collect(),
            steps: vec![
                ReleaseGateStep::new(
                    "phase5_gates",
                    "run scripts/ci/phase5_gates.sh",
                    &["scripts/ci/phase5_gates.sh"],
                ),
                ReleaseGateStep::new(
                    "validate_phase5_gate_report",
                    "require the current phase5 gate report to record all required steps as executed_passed",
                    &["validate_phase5_gate_report"],
                )
                .with_expected_paths(&[phase5_gate_report_path.to_string_lossy().as_ref()]),
                ReleaseGateStep::new(
                    "phase10_gates",
                    "run scripts/ci/phase10_gates.sh",
                    &["scripts/ci/phase10_gates.sh"],
                ),
                ReleaseGateStep::new(
                    "require_readiness_docs",
                    "require readiness docs for release sign-off",
                    &["require_file"],
                )
                .with_expected_paths(REQUIRED_DOCS),
            ],
        }
    }

    fn step_mut(&mut self, step_id: &str) -> Option<&mut ReleaseGateStep> {
        self.steps.iter_mut().find(|step| step.id == step_id)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct Phase5GateReport {
    gate: String,
    overall_status: GateRunStatus,
    required_step_ids: Vec<String>,
    steps: Vec<Phase5GateStep>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
struct Phase5GateStep {
    id: String,
    status: GateStepStatus,
}

#[derive(Debug)]
struct StepExecutionError {
    exit_code: i32,
    detail: String,
}

#[cfg(test)]
mod tests {
    use super::{
        CHECKLIST_DOC_PATH, GateRunStatus, GateStepStatus, REQUIRED_DOCS, REQUIRED_PHASE5_STEP_IDS,
        ReleaseReadinessBundle, read_phase5_gate_report, repo_root, require_files,
        validate_phase5_gate_report,
    };
    use rustynetd::exit_codes::ExitCode;
    use std::env;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEMP_DIR_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDirGuard {
        path: PathBuf,
    }

    impl TempDirGuard {
        fn create() -> Result<Self, String> {
            let base_dir = env::temp_dir();
            let pid = std::process::id();
            let now_nanos = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|err| format!("clock failure while creating temp dir: {err}"))?
                .as_nanos();

            for attempt in 0..100u64 {
                let counter = TEMP_DIR_COUNTER.fetch_add(1, Ordering::Relaxed);
                let candidate = base_dir.join(format!(
                    "rustynet-release-readiness-test-{pid}-{now_nanos}-{counter}-{attempt}"
                ));
                match fs::create_dir(&candidate) {
                    Ok(()) => return Ok(Self { path: candidate }),
                    Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
                    Err(err) => {
                        return Err(format!(
                            "failed to create temp dir {}: {err}",
                            candidate.display()
                        ));
                    }
                }
            }

            Err("failed to create temp dir: exhausted unique path attempts".to_owned())
        }

        fn path(&self) -> &Path {
            self.path.as_path()
        }
    }

    impl Drop for TempDirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn write_phase5_report(temp_dir: &Path, audit_status: GateStepStatus) -> PathBuf {
        let report_path = temp_dir.join("phase5_gate_report.json");
        let steps: Vec<serde_json::Value> = REQUIRED_PHASE5_STEP_IDS
            .iter()
            .map(|step| {
                let status = if *step == "cargo_audit" {
                    audit_status
                } else {
                    GateStepStatus::ExecutedPassed
                };
                serde_json::json!({
                    "id": step,
                    "status": status,
                })
            })
            .collect();
        let report = serde_json::json!({
            "gate": "phase5_ci_gates",
            "overall_status": GateRunStatus::ExecutedPassed,
            "required_step_ids": REQUIRED_PHASE5_STEP_IDS,
            "steps": steps,
        });
        fs::write(
            &report_path,
            serde_json::to_vec_pretty(&report).expect("serialize phase5 report"),
        )
        .expect("write phase5 report");
        report_path
    }

    #[test]
    fn validate_phase5_gate_report_requires_audit_to_pass() {
        let temp_dir = TempDirGuard::create().expect("temp dir");
        let report_path = write_phase5_report(temp_dir.path(), GateStepStatus::ExecutedFailed);
        let err = validate_phase5_gate_report(&report_path).expect_err("audit should fail");
        assert!(err.detail.contains("cargo_audit"));
    }

    #[test]
    fn validate_phase5_gate_report_accepts_full_required_step_set() {
        let temp_dir = TempDirGuard::create().expect("temp dir");
        let report_path = write_phase5_report(temp_dir.path(), GateStepStatus::ExecutedPassed);
        validate_phase5_gate_report(&report_path).expect("phase5 report should validate");
        let parsed = read_phase5_gate_report(&report_path).expect("read report");
        assert_eq!(parsed.overall_status, GateRunStatus::ExecutedPassed);
    }

    #[test]
    fn release_bundle_starts_with_not_executed_steps() {
        let bundle =
            ReleaseReadinessBundle::new(Path::new("artifacts/release/phase5_gate_report.json"));
        assert_eq!(bundle.steps.len(), 4);
        assert!(
            bundle
                .steps
                .iter()
                .all(|step| step.status == GateStepStatus::NotExecuted)
        );
    }

    #[test]
    fn required_readiness_docs_all_exist_in_repo() {
        let root_dir = repo_root().expect("resolve repository root");
        let missing: Vec<String> = REQUIRED_DOCS
            .iter()
            .filter(|doc| !root_dir.join(doc).is_file())
            .map(|doc| (*doc).to_owned())
            .collect();
        assert!(
            missing.is_empty(),
            "required readiness docs missing on disk: {missing:?}"
        );
        assert!(
            REQUIRED_DOCS.contains(&CHECKLIST_DOC_PATH),
            "REQUIRED_DOCS must gate on the canonical checklist path constant"
        );
        let bundle =
            ReleaseReadinessBundle::new(Path::new("artifacts/release/phase5_gate_report.json"));
        assert_eq!(bundle.checklist_doc, CHECKLIST_DOC_PATH);
    }

    const RELEASE_WORKFLOW_PATH: &str = ".github/workflows/release.yml";
    const GATE_COMMAND: &str = "./scripts/ci/release_readiness_gates.sh";
    const DISPATCH_ONLY_CONTINUE: &str =
        "continue-on-error: ${{ github.event_name == 'workflow_dispatch' }}";

    /// Split the `jobs:` map of a workflow into `(job name, block lines)`.
    /// Line-based on purpose: the workspace carries no YAML parser and the
    /// workflow uses the plain two-space layout.
    fn workflow_jobs(text: &str) -> Vec<(String, Vec<String>)> {
        let mut jobs: Vec<(String, Vec<String>)> = Vec::new();
        let mut in_jobs = false;
        for line in text.lines() {
            if !line.starts_with(' ') && !line.trim().is_empty() && !line.starts_with('#') {
                in_jobs = line.trim_end() == "jobs:";
                continue;
            }
            if !in_jobs {
                continue;
            }
            let is_header = line.starts_with("  ")
                && !line.starts_with("   ")
                && line.trim_end().ends_with(':')
                && !line.trim_start().starts_with('#');
            if is_header {
                jobs.push((line.trim().trim_end_matches(':').to_owned(), Vec::new()));
            } else if let Some((_, block)) = jobs.last_mut() {
                block.push(line.to_owned());
            }
        }
        jobs
    }

    fn job_needs(block: &[String], needed: &str) -> bool {
        block.iter().any(|line| {
            let line = line.trim();
            line.strip_prefix("needs:").is_some_and(|rest| {
                let rest = rest.trim().trim_start_matches('[').trim_end_matches(']');
                rest.split(',').any(|item| item.trim() == needed)
            })
        })
    }

    fn indent_of(line: &str) -> usize {
        line.len() - line.trim_start().len()
    }

    /// Job-level (four-space) keys `if:` / `continue-on-error:` can skip or
    /// soften a whole job. For every job in the publish chain (the gate job,
    /// `build`, `manifest`) neither may appear except the gate job's
    /// dispatch-only `continue-on-error`. Step-level `if:` lines (deeper
    /// indent) are checked separately where they matter.
    fn reject_job_level_skips(
        name: &str,
        block: &[String],
        allow_dispatch_continue: bool,
    ) -> Result<(), String> {
        for line in block {
            let trimmed = line.trim();
            if indent_of(line) != 4 {
                continue;
            }
            if trimmed.starts_with("if:") {
                return Err(format!(
                    "job `{name}` must not carry a job-level if: (it can skip or bypass the gate chain), found: {trimmed}"
                ));
            }
            if trimmed.starts_with("continue-on-error")
                && !(allow_dispatch_continue && trimmed == DISPATCH_ONLY_CONTINUE)
            {
                return Err(format!(
                    "job `{name}` must not tolerate failure on a tag push, found: {trimmed}"
                ));
            }
        }
        Ok(())
    }

    /// Fail-closed classifier: the release workflow must run the readiness
    /// gate in a job that cannot be skipped or softened on a tag push, and the
    /// build -> manifest(publish) chain must depend on it and must not be able
    /// to run past a failed or skipped gate.
    fn check_release_workflow_wiring(text: &str) -> Result<(), String> {
        let jobs = workflow_jobs(text);
        let (gate_name, gate_block) = jobs
            .iter()
            .find(|(_, block)| {
                block.iter().any(|line| {
                    let trimmed = line.trim();
                    !trimmed.starts_with('#') && trimmed.contains(GATE_COMMAND)
                })
            })
            .ok_or_else(|| format!("no job runs {GATE_COMMAND}"))?;
        reject_job_level_skips(gate_name, gate_block, true)?;
        let inline_gate = format!("run: {GATE_COMMAND}");
        for (index, line) in gate_block.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.contains(GATE_COMMAND) && (trimmed.contains("||") || trimmed.contains('&')) {
                return Err(format!("gate command is softened: {trimmed}"));
            }
            if trimmed.starts_with("continue-on-error") && indent_of(line) != 4 {
                return Err(format!(
                    "continue-on-error may only be the job-level dispatch-only form, found: {trimmed}"
                ));
            }
            if trimmed.starts_with("if:") && trimmed != "if: always()" {
                return Err(format!(
                    "gate job must not be conditional, found: {trimmed}"
                ));
            }
            if trimmed != GATE_COMMAND && trimmed != inline_gate {
                continue;
            }
            // The step holding the command must not carry an `if:` either
            // (not even `always()` -- that is only for report upload).
            let step_start = gate_block[..index]
                .iter()
                .rposition(|candidate| candidate.trim_start().starts_with("- "))
                .unwrap_or(0);
            if gate_block[step_start..index]
                .iter()
                .any(|candidate| candidate.trim_start().starts_with("if:"))
            {
                return Err("the gate step must not carry an if: condition".to_owned());
            }
            if trimmed == GATE_COMMAND {
                // Block-scalar form: the command must be the ONLY line of the
                // run block, so nothing before it can change shell options and
                // nothing after it (`exit 0`, `true`, `:`) can mask its status.
                let before = gate_block[..index]
                    .iter()
                    .rev()
                    .find(|candidate| !candidate.trim().is_empty())
                    .map(|candidate| candidate.trim());
                if !matches!(before, Some("run: |") | Some("run: |-")) {
                    return Err(format!(
                        "the gate command must be the first line of its run block, found before it: {before:?}"
                    ));
                }
                let command_indent = indent_of(line);
                if let Some(extra) = gate_block[index + 1..]
                    .iter()
                    .take_while(|candidate| {
                        candidate.trim().is_empty() || indent_of(candidate) >= command_indent
                    })
                    .find(|candidate| !candidate.trim().is_empty())
                {
                    return Err(format!(
                        "extra command after the gate in the same run block: {}",
                        extra.trim()
                    ));
                }
            }
        }
        let build = jobs
            .iter()
            .find(|(name, _)| name == "build")
            .ok_or_else(|| "release workflow has no build job".to_owned())?;
        if !job_needs(&build.1, gate_name) {
            return Err(format!("build job does not need the {gate_name} job"));
        }
        reject_job_level_skips("build", &build.1, false)?;
        let manifest = jobs
            .iter()
            .find(|(name, _)| name == "manifest")
            .ok_or_else(|| "release workflow has no manifest (publish) job".to_owned())?;
        if !job_needs(&manifest.1, "build") {
            return Err("manifest (publish) job does not need build".to_owned());
        }
        reject_job_level_skips("manifest", &manifest.1, false)?;
        Ok(())
    }

    fn real_release_workflow() -> String {
        let path = repo_root()
            .expect("resolve repository root")
            .join(RELEASE_WORKFLOW_PATH);
        fs::read_to_string(&path).unwrap_or_else(|err| panic!("read {}: {err}", path.display()))
    }

    #[test]
    fn release_workflow_wires_the_readiness_gate() {
        check_release_workflow_wiring(&real_release_workflow())
            .expect("release.yml must run the readiness gate before build/publish");
        assert!(
            repo_root()
                .expect("repo root")
                .join(GATE_COMMAND.trim_start_matches("./"))
                .is_file(),
            "the wired gate wrapper script must exist"
        );
    }

    #[test]
    fn release_workflow_wiring_check_rejects_weakened_workflows() {
        let real = real_release_workflow();
        let mutations: [(&str, String); 12] = [
            (
                "gate command removed",
                real.replace(GATE_COMMAND, "./scripts/ci/phase5_gates.sh"),
            ),
            (
                "gate softened with || true",
                real.replace(GATE_COMMAND, &format!("{GATE_COMMAND} || true")),
            ),
            (
                "build no longer needs the gate",
                real.replace("    needs: release_gates\n", ""),
            ),
            (
                "gate job tolerates failure on tag push",
                real.replace(DISPATCH_ONLY_CONTINUE, "continue-on-error: true"),
            ),
            (
                "gate job skipped on push",
                real.replace(
                    "    runs-on: ubuntu-latest\n    continue-on-error",
                    "    runs-on: ubuntu-latest\n    if: github.event_name != 'push'\n    continue-on-error",
                ),
            ),
            (
                "manifest no longer needs build",
                real.replace("    needs: build\n", ""),
            ),
            (
                "build runs past a failed gate via if: always()",
                real.replace(
                    "    needs: release_gates\n",
                    "    needs: release_gates\n    if: always()\n",
                ),
            ),
            (
                "build runs past a failed gate via if: success() || failure()",
                real.replace(
                    "    needs: release_gates\n",
                    "    needs: release_gates\n    if: success() || failure()\n",
                ),
            ),
            (
                "manifest publishes past a failed build via if: always()",
                real.replace("    needs: build\n", "    needs: build\n    if: always()\n"),
            ),
            (
                "gate masked by exit 0 in the same run block",
                real.replace(
                    &format!("          {GATE_COMMAND}\n"),
                    &format!("          {GATE_COMMAND}\n          exit 0\n"),
                ),
            ),
            (
                "gate masked by a trailing `true` in the same run block",
                real.replace(
                    &format!("          {GATE_COMMAND}\n"),
                    &format!("          {GATE_COMMAND}\n          true\n"),
                ),
            ),
            (
                "gate masked by a trailing `:` in the same run block",
                real.replace(
                    &format!("          {GATE_COMMAND}\n"),
                    &format!("          {GATE_COMMAND}\n          :\n"),
                ),
            ),
        ];
        for (label, mutated) in mutations {
            assert_ne!(
                mutated, real,
                "mutation `{label}` did not change the workflow"
            );
            assert!(
                check_release_workflow_wiring(&mutated).is_err(),
                "mutation `{label}` must be rejected"
            );
        }
    }

    #[test]
    fn release_workflow_wiring_check_rejects_for_the_intended_reason() {
        // The mutation test above only proves "rejected"; pin the reason for
        // the bypasses a reviewer found so they cannot be rejected by accident.
        let real = real_release_workflow();
        let build_if = real.replace(
            "    needs: release_gates\n",
            "    needs: release_gates\n    if: always()\n",
        );
        let err = check_release_workflow_wiring(&build_if).expect_err("build if");
        assert!(
            err.contains("job `build`") && err.contains("job-level if"),
            "{err}"
        );
        let manifest_if =
            real.replace("    needs: build\n", "    needs: build\n    if: always()\n");
        let err = check_release_workflow_wiring(&manifest_if).expect_err("manifest if");
        assert!(
            err.contains("job `manifest`") && err.contains("job-level if"),
            "{err}"
        );
        for tail in ["exit 0", "true", ":"] {
            let masked = real.replace(
                &format!("          {GATE_COMMAND}\n"),
                &format!("          {GATE_COMMAND}\n          {tail}\n"),
            );
            let err = check_release_workflow_wiring(&masked).expect_err("masked gate");
            assert!(
                err.contains("extra command after the gate"),
                "{tail}: {err}"
            );
        }
    }

    #[test]
    fn require_readiness_docs_fail_closed_when_checklist_missing() {
        let temp_dir = TempDirGuard::create().expect("temp dir");
        let err = require_files(
            temp_dir.path(),
            REQUIRED_DOCS,
            "required readiness document",
        )
        .expect_err("missing readiness docs must fail closed");
        assert_eq!(err.exit_code, ExitCode::PolicyReject.as_i32());
        assert!(
            err.detail.contains(CHECKLIST_DOC_PATH),
            "failure detail should name the checklist path, got: {}",
            err.detail
        );
    }
}
