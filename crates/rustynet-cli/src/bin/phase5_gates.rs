#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/VulnerabilityResponse.md",
    "documents/operations/PolicyRolloutRunbook.md",
    "documents/operations/SecretRedactionCoverage.md",
];

const RELEASE_ARTIFACT_PATH: &str = "target/debug/rustynetd";
const RELEASE_TRACK: &str = "beta";
const RELEASE_PROVENANCE_PATH: &str = "artifacts/release/rustynetd.provenance.json";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_string());

    run_command(&root_dir, "cargo", &["fmt", "--all", "--", "--check"], &[])?;
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
    )?;
    run_command(
        &root_dir,
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        &[],
    )?;
    run_command(
        &root_dir,
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    run_script(&root_dir, "scripts/ci/phase4_gates.sh", &[])?;
    run_script(&root_dir, "scripts/ci/perf_regression_gate.sh", &[])?;

    run_command(
        &root_dir,
        "cargo",
        &["build", "--workspace", "--all-targets", "--all-features"],
        &[],
    )?;
    run_ops(&root_dir, "generate-release-sbom", &[])?;
    run_ops(
        &root_dir,
        "create-release-provenance",
        &[
            RELEASE_ARTIFACT_PATH,
            RELEASE_TRACK,
            RELEASE_PROVENANCE_PATH,
        ],
    )?;

    for required_doc in REQUIRED_DOCS {
        require_file(&root_dir.join(required_doc))?;
    }

    println!("Phase 5 CI gates: PASS");
    Ok(())
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), i32> {
    let status = Command::new(root_dir.join(script))
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!(
                "failed to execute script {}: {err}",
                root_dir.join(script).display()
            );
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_ops(root_dir: &Path, ops_subcommand: &str, args: &[&str]) -> Result<(), i32> {
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
        .map_err(|err| {
            eprintln!("failed to run ops {ops_subcommand}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_command(
    root_dir: &Path,
    program: &str,
    args: &[&str],
    env_pairs: &[(&str, &str)],
) -> Result<(), i32> {
    let status = Command::new(program)
        .current_dir(root_dir)
        .args(args)
        .envs(env_pairs.iter().copied())
        .status()
        .map_err(|err| {
            eprintln!("failed to execute command {program}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn require_file(path: &Path) -> Result<(), i32> {
    if path.is_file() {
        Ok(())
    } else {
        eprintln!("missing required operations document: {}", path.display());
        Err(1)
    }
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
