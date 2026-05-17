#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE1_REPORT: &str = "artifacts/perf/phase1/baseline.json";
const DEFAULT_PHASE3_REPORT: &str = "artifacts/perf/phase3/mesh_baseline.json";

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
    let phase1_report = env::var_os("RUSTYNET_PHASE1_PERF_REPORT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PHASE1_REPORT));
    let phase3_report = env::var_os("RUSTYNET_PHASE3_PERF_REPORT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PHASE3_REPORT));

    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "check-perf-regression",
            "--phase1-report",
        ])
        .arg(&phase1_report)
        .arg("--phase3-report")
        .arg(&phase3_report)
        .status()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to execute performance regression gate: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;
    if status.success() {
        Ok(())
    } else {
        // A detected performance regression is a hard verdict —
        // PolicyReject — so retry-only-on-70 CI loops do not retry a
        // real regression failure. The inner ops command already emits
        // its own X6 code; if it returned 1 (generic) we upgrade to
        // PolicyReject (78) here; other taxonomy codes pass through.
        let inner = status_code(status);
        if inner == ExitCode::GenericFailure.as_i32() {
            eprintln!(
                "error [{}]: perf regression detected",
                ExitCode::PolicyReject
            );
            Err(ExitCode::PolicyReject.as_i32())
        } else {
            Err(inner)
        }
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
