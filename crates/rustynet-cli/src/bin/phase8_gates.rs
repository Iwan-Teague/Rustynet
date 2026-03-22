#![forbid(unsafe_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const REQUIRED_DOCS: &[&str] = &[
    "documents/operations/SecurityAssuranceProgram.md",
    "documents/operations/DependencyExceptionPolicy.md",
    "documents/operations/PrivacyRetentionPolicy.md",
    "documents/operations/ComplianceControlMap.md",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let gate_threads = env::var("RUSTYNET_GATE_TEST_THREADS")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "1".to_string());

    run_cargo(&root_dir, &["fmt", "--all", "--", "--check"], &[])?;
    run_cargo(
        &root_dir,
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
    run_cargo(
        &root_dir,
        &["check", "--workspace", "--all-targets", "--all-features"],
        &[],
    )?;
    run_cargo(
        &root_dir,
        &["test", "--workspace", "--all-targets", "--all-features"],
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    run_script(&root_dir, "scripts/ci/phase7_gates.sh", &[])?;
    run_script(&root_dir, "scripts/ci/check_dependency_exceptions.sh", &[])?;
    run_script(&root_dir, "scripts/ci/supply_chain_integrity_gates.sh", &[])?;

    for required_doc in REQUIRED_DOCS {
        require_file(&root_dir.join(required_doc), required_doc)?;
    }

    println!("Phase 8 CI gates: PASS");
    Ok(())
}

fn require_file(path: &Path, label: &str) -> Result<(), i32> {
    if fs::metadata(path).is_ok() {
        Ok(())
    } else {
        eprintln!("missing phase8 operations artifact: {label}");
        Err(1)
    }
}

fn run_cargo(root_dir: &Path, args: &[&str], extra_env: &[(&str, &str)]) -> Result<(), i32> {
    let mut command = Command::new("cargo");
    command
        .current_dir(root_dir)
        .args(args)
        .stdin(Stdio::null());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let status = command.status().map_err(|err| {
        eprintln!("failed to run cargo {args:?}: {err}");
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn run_script(root_dir: &Path, script: &str, args: &[&str]) -> Result<(), i32> {
    let status = Command::new(script)
        .current_dir(root_dir)
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!("failed to run script {script}: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
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
