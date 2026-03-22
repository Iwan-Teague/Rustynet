#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE1_SOURCE: &str = "artifacts/perf/phase1/source/performance_samples.ndjson";

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
    let mut phase1_source = PathBuf::from(
        env::var("RUSTYNET_PHASE1_PERF_SAMPLES_PATH")
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_PHASE1_SOURCE.to_string()),
    );
    if !phase1_source.is_absolute() {
        phase1_source = root_dir.join(phase1_source);
    }
    if !phase1_source.is_file() {
        eprintln!(
            "missing measured phase1 source: {}",
            phase1_source.display()
        );
        return Err(1);
    }

    let phase1_source_utf8 = phase1_source.to_str().ok_or_else(|| {
        eprintln!(
            "phase1 source path is not valid UTF-8: {}",
            phase1_source.display()
        );
        1
    })?;

    let status = Command::new("cargo")
        .current_dir(root_dir)
        .env("RUSTYNET_PHASE1_PERF_SAMPLES_PATH", phase1_source_utf8)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "run-phase1-baseline",
        ])
        .status()
        .map_err(|err| {
            eprintln!("failed to run run-phase1-baseline: {err}");
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
