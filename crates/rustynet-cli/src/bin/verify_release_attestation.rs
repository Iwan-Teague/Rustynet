#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

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
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;

    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "verify-release-artifact",
        ])
        .status()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to run verify-release-artifact command: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;

    if status.success() {
        Ok(())
    } else {
        // Release-attestation verification is a fail-closed security
        // verdict: a non-zero result means the signed artifact did not
        // match the reviewed root. Surface as PolicyReject so retry-
        // only-on-70 CI loops never accidentally retry a real
        // attestation failure. The inner `ops verify-release-artifact`
        // taxonomy is preserved when it already exits with 78; the
        // remap below only fires when the subprocess returns 1.
        let inner = status_code(status);
        if inner == ExitCode::GenericFailure.as_i32() {
            eprintln!(
                "error [{}]: release attestation verification failed",
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
