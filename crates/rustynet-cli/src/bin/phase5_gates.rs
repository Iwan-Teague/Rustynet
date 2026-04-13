#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};
use std::time::{SystemTime, UNIX_EPOCH};

const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/VulnerabilityResponse.md",
    "documents/operations/PolicyRolloutRunbook.md",
    "documents/operations/SecretRedactionCoverage.md",
];

const DEFAULT_REPORT_PATH: &str = "artifacts/release/phase5_gate_report.json";
const RELEASE_ARTIFACT_PATH: &str = "target/debug/rustynetd";
const RELEASE_TRACK: &str = "beta";
const RELEASE_PROVENANCE_PATH: &str = "artifacts/release/rustynetd.provenance.json";
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
    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_string());
    let report_path = env::var_os("RUSTYNET_PHASE5_GATE_REPORT_PATH")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| root_dir.join(DEFAULT_REPORT_PATH));

    let mut report = GateExecutionReport::phase5();
    write_report(&report_path, &mut report)?;

    run_step(&mut report, &report_path, "cargo_fmt", || {
        run_command(&root_dir, "cargo", &["fmt", "--all", "--", "--check"], &[])
    })?;
    run_step(&mut report, &report_path, "cargo_clippy", || {
        run_command(
            &root_dir,
            "cargo",
            &[
                "clippy",
                "--workspace",
                "--all-targets",
                "--all-features",
                "--",
                "-D",
                "warnings",
            ],
            &[],
        )
    })?;
    run_step(&mut report, &report_path, "cargo_check", || {
        run_command(
            &root_dir,
            "cargo",
            &["check", "--workspace", "--all-targets", "--all-features"],
            &[],
        )
    })?;
    run_step(&mut report, &report_path, "cargo_test", || {
        run_command(
            &root_dir,
            "cargo",
            &["test", "--workspace", "--all-targets", "--all-features"],
            &[("RUST_TEST_THREADS", gate_threads.as_str())],
        )
    })?;
    run_step(&mut report, &report_path, "cargo_audit", || {
        run_command(&root_dir, "cargo", &["audit", "--deny", "warnings"], &[])
    })?;
    run_step(&mut report, &report_path, "cargo_deny", || {
        run_command(
            &root_dir,
            "cargo",
            &["deny", "check", "advisories", "bans", "licenses", "sources"],
            &[],
        )
    })?;
    run_step(&mut report, &report_path, "phase4_gates", || {
        run_script(&root_dir, "scripts/ci/phase4_gates.sh", &[])
    })?;
    run_step(&mut report, &report_path, "perf_regression_gate", || {
        run_script(&root_dir, "scripts/ci/perf_regression_gate.sh", &[])
    })?;
    run_step(&mut report, &report_path, "cargo_build", || {
        run_command(
            &root_dir,
            "cargo",
            &["build", "--workspace", "--all-targets", "--all-features"],
            &[],
        )
    })?;
    run_step(&mut report, &report_path, "generate_release_sbom", || {
        run_ops(&root_dir, "generate-release-sbom", &[])
    })?;
    run_step(
        &mut report,
        &report_path,
        "create_release_provenance",
        || {
            run_ops(
                &root_dir,
                "create-release-provenance",
                &[
                    RELEASE_ARTIFACT_PATH,
                    RELEASE_TRACK,
                    RELEASE_PROVENANCE_PATH,
                ],
            )
        },
    )?;
    run_step(&mut report, &report_path, "require_phase5_docs", || {
        require_files(&root_dir, REQUIRED_DOCS, "required operations document")
    })?;

    report.overall_status = GateRunStatus::ExecutedPassed;
    write_report(&report_path, &mut report)?;
    println!("Phase 5 CI gates: PASS");
    Ok(())
}

fn run_step<F>(
    report: &mut GateExecutionReport,
    report_path: &Path,
    step_id: &str,
    action: F,
) -> Result<(), i32>
where
    F: FnOnce() -> Result<(), StepExecutionError>,
{
    let step = report.step_mut(step_id).ok_or_else(|| {
        eprintln!("phase5 gate report is missing step definition: {step_id}");
        1
    })?;
    match action() {
        Ok(()) => {
            step.status = GateStepStatus::ExecutedPassed;
            step.exit_code = Some(0);
            step.detail = None;
            write_report(report_path, report)
        }
        Err(err) => {
            step.status = GateStepStatus::ExecutedFailed;
            step.exit_code = Some(err.exit_code);
            step.detail = Some(err.detail);
            report.overall_status = GateRunStatus::ExecutedFailed;
            write_report(report_path, report)?;
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

fn run_ops(root_dir: &Path, ops_subcommand: &str, args: &[&str]) -> Result<(), StepExecutionError> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            ops_subcommand,
        ])
        .args(args)
        .status()
        .map_err(|err| StepExecutionError {
            exit_code: 1,
            detail: format!("failed to run ops {ops_subcommand}: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(StepExecutionError {
            exit_code: status_code(status),
            detail: format!("ops {ops_subcommand} failed"),
        })
    }
}

fn run_command(
    root_dir: &Path,
    program: &str,
    args: &[&str],
    env_pairs: &[(&str, &str)],
) -> Result<(), StepExecutionError> {
    let status = Command::new(program)
        .current_dir(root_dir)
        .args(args)
        .envs(env_pairs.iter().copied())
        .status()
        .map_err(|err| StepExecutionError {
            exit_code: 1,
            detail: format!("failed to execute command {program}: {err}"),
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(StepExecutionError {
            exit_code: status_code(status),
            detail: format!("command failed: {program} {}", args.join(" ")),
        })
    }
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

fn write_report(path: &Path, report: &mut GateExecutionReport) -> Result<(), i32> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            eprintln!(
                "failed to create report directory {}: {err}",
                parent.display()
            );
            1
        })?;
    }
    report.generated_at_unix = now_unix().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let json = serde_json::to_vec_pretty(report).map_err(|err| {
        eprintln!("failed to serialize phase5 gate report: {err}");
        1
    })?;
    fs::write(path, json).map_err(|err| {
        eprintln!(
            "failed to write phase5 gate report {}: {err}",
            path.display()
        );
        1
    })
}

fn now_unix() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|err| format!("clock failure while generating phase5 gate report: {err}"))
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
struct GateStepReport {
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

impl GateStepReport {
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
struct GateExecutionReport {
    schema_version: u32,
    gate: String,
    overall_status: GateRunStatus,
    generated_at_unix: u64,
    required_step_ids: Vec<String>,
    steps: Vec<GateStepReport>,
}

impl GateExecutionReport {
    fn phase5() -> Self {
        Self {
            schema_version: 1,
            gate: "phase5_ci_gates".to_string(),
            overall_status: GateRunStatus::ExecutedFailed,
            generated_at_unix: 0,
            required_step_ids: REQUIRED_PHASE5_STEP_IDS
                .iter()
                .map(|step| (*step).to_string())
                .collect(),
            steps: vec![
                GateStepReport::new(
                    "cargo_fmt",
                    "run cargo fmt --all -- --check",
                    &["cargo", "fmt", "--all", "--", "--check"],
                ),
                GateStepReport::new(
                    "cargo_clippy",
                    "run cargo clippy --workspace --all-targets --all-features -- -D warnings",
                    &[
                        "cargo",
                        "clippy",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                        "--",
                        "-D",
                        "warnings",
                    ],
                ),
                GateStepReport::new(
                    "cargo_check",
                    "run cargo check --workspace --all-targets --all-features",
                    &[
                        "cargo",
                        "check",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                    ],
                ),
                GateStepReport::new(
                    "cargo_test",
                    "run cargo test --workspace --all-targets --all-features",
                    &[
                        "cargo",
                        "test",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                    ],
                ),
                GateStepReport::new(
                    "cargo_audit",
                    "run cargo audit --deny warnings",
                    &["cargo", "audit", "--deny", "warnings"],
                ),
                GateStepReport::new(
                    "cargo_deny",
                    "run cargo deny check advisories bans licenses sources",
                    &[
                        "cargo",
                        "deny",
                        "check",
                        "advisories",
                        "bans",
                        "licenses",
                        "sources",
                    ],
                ),
                GateStepReport::new(
                    "phase4_gates",
                    "run scripts/ci/phase4_gates.sh",
                    &["scripts/ci/phase4_gates.sh"],
                ),
                GateStepReport::new(
                    "perf_regression_gate",
                    "run scripts/ci/perf_regression_gate.sh",
                    &["scripts/ci/perf_regression_gate.sh"],
                ),
                GateStepReport::new(
                    "cargo_build",
                    "run cargo build --workspace --all-targets --all-features",
                    &[
                        "cargo",
                        "build",
                        "--workspace",
                        "--all-targets",
                        "--all-features",
                    ],
                ),
                GateStepReport::new(
                    "generate_release_sbom",
                    "run rustynet ops generate-release-sbom",
                    &[
                        "cargo",
                        "run",
                        "--quiet",
                        "-p",
                        "rustynet-cli",
                        "--",
                        "ops",
                        "generate-release-sbom",
                    ],
                ),
                GateStepReport::new(
                    "create_release_provenance",
                    "run rustynet ops create-release-provenance",
                    &[
                        "cargo",
                        "run",
                        "--quiet",
                        "-p",
                        "rustynet-cli",
                        "--",
                        "ops",
                        "create-release-provenance",
                        RELEASE_ARTIFACT_PATH,
                        RELEASE_TRACK,
                        RELEASE_PROVENANCE_PATH,
                    ],
                ),
                GateStepReport::new(
                    "require_phase5_docs",
                    "require phase5 operations documents",
                    &["require_file"],
                )
                .with_expected_paths(REQUIRED_DOCS),
            ],
        }
    }

    fn step_mut(&mut self, step_id: &str) -> Option<&mut GateStepReport> {
        self.steps.iter_mut().find(|step| step.id == step_id)
    }
}

#[derive(Debug)]
struct StepExecutionError {
    exit_code: i32,
    detail: String,
}

#[cfg(test)]
mod tests {
    use super::{
        GateExecutionReport, GateRunStatus, GateStepStatus, REQUIRED_PHASE5_STEP_IDS, write_report,
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
                    "rustynet-phase5-gates-test-{pid}-{now_nanos}-{counter}-{attempt}"
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

    #[test]
    fn phase5_required_steps_include_audit_and_deny() {
        assert!(REQUIRED_PHASE5_STEP_IDS.contains(&"cargo_audit"));
        assert!(REQUIRED_PHASE5_STEP_IDS.contains(&"cargo_deny"));

        let report = GateExecutionReport::phase5();
        let step_ids: Vec<&str> = report.steps.iter().map(|step| step.id.as_str()).collect();
        assert!(step_ids.contains(&"cargo_audit"));
        assert!(step_ids.contains(&"cargo_deny"));
    }

    #[test]
    fn phase5_report_preserves_failed_and_not_executed_states() {
        let mut report = GateExecutionReport::phase5();
        report.step_mut("cargo_fmt").unwrap().status = GateStepStatus::ExecutedPassed;
        report.step_mut("cargo_fmt").unwrap().exit_code = Some(0);
        report.step_mut("cargo_clippy").unwrap().status = GateStepStatus::ExecutedFailed;
        report.step_mut("cargo_clippy").unwrap().exit_code = Some(101);
        report.step_mut("cargo_clippy").unwrap().detail =
            Some("command failed: cargo clippy".to_string());
        report.overall_status = GateRunStatus::ExecutedFailed;

        assert_eq!(
            report.step_mut("cargo_check").unwrap().status,
            GateStepStatus::NotExecuted
        );
        assert_eq!(
            report.step_mut("cargo_clippy").unwrap().status,
            GateStepStatus::ExecutedFailed
        );
    }

    #[test]
    fn phase5_report_writer_serializes_truthful_statuses() {
        let temp_dir = TempDirGuard::create().expect("temp dir");
        let report_path = temp_dir.path().join("phase5_gate_report.json");
        let mut report = GateExecutionReport::phase5();
        report.step_mut("cargo_fmt").unwrap().status = GateStepStatus::ExecutedPassed;
        report.step_mut("cargo_fmt").unwrap().exit_code = Some(0);
        report.step_mut("cargo_clippy").unwrap().status = GateStepStatus::ExecutedFailed;
        report.step_mut("cargo_clippy").unwrap().exit_code = Some(101);
        report.step_mut("cargo_clippy").unwrap().detail =
            Some("command failed: cargo clippy".to_string());
        report.overall_status = GateRunStatus::ExecutedFailed;

        write_report(&report_path, &mut report).expect("write report");

        let written = fs::read_to_string(&report_path).expect("read report");
        let parsed: GateExecutionReport =
            serde_json::from_str(&written).expect("deserialize report");
        assert_eq!(parsed.gate, "phase5_ci_gates");
        assert_eq!(parsed.overall_status, GateRunStatus::ExecutedFailed);
        assert_eq!(
            parsed
                .steps
                .iter()
                .find(|step| step.id == "cargo_fmt")
                .expect("fmt step")
                .status,
            GateStepStatus::ExecutedPassed
        );
        assert_eq!(
            parsed
                .steps
                .iter()
                .find(|step| step.id == "cargo_clippy")
                .expect("clippy step")
                .status,
            GateStepStatus::ExecutedFailed
        );
        assert_eq!(
            parsed
                .steps
                .iter()
                .find(|step| step.id == "cargo_check")
                .expect("check step")
                .status,
            GateStepStatus::NotExecuted
        );
    }
}
