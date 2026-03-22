#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE1_SOURCE_PATH: &str = "artifacts/perf/phase1/source/performance_samples.ndjson";

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

    run_command(
        "cargo",
        &["fmt", "--all", "--", "--check"],
        Some(&root_dir),
        &[],
    )?;
    run_command(
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
        Some(&root_dir),
        &[],
    )?;

    let phase3_unsafe_rustflags = format!(
        "{} -Dunsafe_code -Dunsafe_op_in_unsafe_fn",
        env::var("RUSTFLAGS").unwrap_or_default()
    );
    run_command(
        "cargo",
        &["check", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUSTFLAGS", phase3_unsafe_rustflags.as_str())],
    )?;
    run_command(
        "cargo",
        &["test", "--workspace", "--all-targets", "--all-features"],
        Some(&root_dir),
        &[("RUST_TEST_THREADS", gate_threads.as_str())],
    )?;

    let phase1_source_path = resolve_source_path(
        &root_dir,
        env::var_os("RUSTYNET_PHASE1_PERF_SAMPLES_PATH")
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| OsString::from(DEFAULT_PHASE1_SOURCE_PATH)),
    );
    if !phase1_source_path.is_file() {
        return Err({
            eprintln!(
                "missing measured phase1 source: {}",
                phase1_source_path.display()
            );
            1
        });
    }
    let phase1_source_path_str = path_to_utf8(&phase1_source_path, "phase1 samples path")?;
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-phase1-baseline",
        ],
        Some(&root_dir),
        &[(
            "RUSTYNET_PHASE1_PERF_SAMPLES_PATH",
            phase1_source_path_str.as_str(),
        )],
    )?;
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-phase3-baseline",
        ],
        Some(&root_dir),
        &[],
    )?;

    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "check_backend_boundary_leakage",
            "--",
        ],
        Some(&root_dir),
        &[],
    )?;
    run_command(
        "cargo",
        &[
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--bin",
            "check_no_unsafe_code",
            "--",
        ],
        Some(&root_dir),
        &[],
    )?;

    println!("Phase 3 CI gates: PASS");
    Ok(())
}

fn resolve_source_path(root_dir: &Path, raw: OsString) -> PathBuf {
    let path = PathBuf::from(raw);
    if path.is_absolute() {
        path
    } else {
        root_dir.join(path)
    }
}

fn path_to_utf8(path: &Path, label: &str) -> Result<String, i32> {
    path.to_str().map(|value| value.to_string()).ok_or_else(|| {
        eprintln!("{label} is not valid UTF-8: {}", path.display());
        1
    })
}

fn run_command(
    program: &str,
    args: &[&str],
    cwd: Option<&Path>,
    extra_env: &[(&str, &str)],
) -> Result<(), i32> {
    let mut command = Command::new(program);
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }
    command.args(args).stdin(std::process::Stdio::null());
    for (key, value) in extra_env {
        command.env(key, value);
    }
    let status = command.status().map_err(|err| {
        eprintln!("failed to run {program}: {err}");
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
