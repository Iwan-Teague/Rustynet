#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/ReleaseReadinessGuardrails.md",
    "documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md",
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
        eprintln!("{err}");
        1
    })?;
    let bundle_path = env::var_os("RUSTYNET_RELEASE_READINESS_BUNDLE_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| root_dir.join(DEFAULT_BUNDLE_PATH));
    let phase5_report_path = env::var_os("RUSTYNET_PHASE5_GATE_REPORT_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| root_dir.join(DEFAULT_PHASE5_REPORT_PATH));

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
        eprintln!("release readiness bundle is missing step definition: {step_id}");
        1
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
            exit_code: 1,
            detail: format!("failed to execute script {}: {err}", script_path.display()),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(StepExecutionError {
            exit_code: status_code(status),
            detail: format!("script failed: {}", script_path.display()),
        })
    }
}

fn validate_phase5_gate_report(report_path: &Path) -> Result<(), StepExecutionError> {
    let report = read_phase5_gate_report(report_path)?;
    if report.gate != "phase5_ci_gates" {
        return Err(StepExecutionError {
            exit_code: 1,
            detail: format!(
                "phase5 gate report at {} has unexpected gate name {}",
                report_path.display(),
                report.gate
            ),
        });
    }
    if report.overall_status != GateRunStatus::ExecutedPassed {
        return Err(StepExecutionError {
            exit_code: 1,
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
            return Err(StepExecutionError {
                exit_code: 1,
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
                exit_code: 1,
                detail: format!(
                    "phase5 gate report at {} is missing required step {}",
                    report_path.display(),
                    required_step
                ),
            })?;
        if step.status != GateStepStatus::ExecutedPassed {
            return Err(StepExecutionError {
                exit_code: 1,
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
        exit_code: 1,
        detail: format!(
            "failed to read phase5 gate report {}: {err}",
            report_path.display()
        ),
    })?;
    serde_json::from_str(&raw).map_err(|err| StepExecutionError {
        exit_code: 1,
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
        Err(StepExecutionError {
            exit_code: 1,
            detail: format!("missing {label}: {}", missing.join(", ")),
        })
    }
}

fn write_bundle(path: &Path, bundle: &mut ReleaseReadinessBundle) -> Result<(), i32> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            eprintln!(
                "failed to create bundle directory {}: {err}",
                parent.display()
            );
            1
        })?;
    }
    bundle.generated_at_unix = now_unix().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let json = serde_json::to_vec_pretty(bundle).map_err(|err| {
        eprintln!("failed to serialize release readiness bundle: {err}");
        1
    })?;
    fs::write(path, json).map_err(|err| {
        eprintln!(
            "failed to write release readiness bundle {}: {err}",
            path.display()
        );
        1
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
            id: id.to_string(),
            description: description.to_string(),
            command: command.iter().map(|item| (*item).to_string()).collect(),
            expected_paths: Vec::new(),
            status: GateStepStatus::NotExecuted,
            exit_code: None,
            detail: None,
        }
    }

    fn with_expected_paths(mut self, paths: &[&str]) -> Self {
        self.expected_paths = paths.iter().map(|path| (*path).to_string()).collect();
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
            gate: "release_readiness_gates".to_string(),
            overall_status: GateRunStatus::ExecutedFailed,
            generated_at_unix: 0,
            summary_doc:
                "documents/operations/active/Phase5ReleaseReadinessSummary_2026-04-12.md"
                    .to_string(),
            checklist_doc:
                "documents/operations/active/Phase5ReleaseReadinessChecklist_2026-04-12.md"
                    .to_string(),
            phase5_gate_report_path: phase5_gate_report_path.display().to_string(),
            required_phase5_step_ids: REQUIRED_PHASE5_STEP_IDS
                .iter()
                .map(|step| (*step).to_string())
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
        GateRunStatus, GateStepStatus, REQUIRED_PHASE5_STEP_IDS, ReleaseReadinessBundle,
        read_phase5_gate_report, validate_phase5_gate_report,
    };
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

            Err("failed to create temp dir: exhausted unique path attempts".to_string())
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
}
