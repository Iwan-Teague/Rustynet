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
    let passthrough_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;

    let mut command = Command::new("cargo");
    command.current_dir(root_dir).args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--",
        "ops",
        "prepare-advisory-db",
    ]);
    command.args(passthrough_args);

    let status = command.status().map_err(|err| {
        eprintln!(
            "error [{}]: failed to run prepare-advisory-db command: {err}",
            ExitCode::TransientFailure
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through the subprocess's own exit code so the inner
        // taxonomy bubble (advisory DB fetch / verification) survives.
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
