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
    run_ops_with_passthrough("run-phase9-ci-gates")
}

fn run_ops_with_passthrough(ops_subcommand: &str) -> Result<(), i32> {
    let passthrough_args: Vec<String> = env::args().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        report_error(ExitCode::ConfigError, &err);
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
        ops_subcommand,
    ]);
    command.args(passthrough_args);
    let status = command.status().map_err(|err| {
        report_error(
            ExitCode::TransientFailure,
            &format!("failed to run phase9 gates command: {err}"),
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through the subprocess's own exit code so the caller
        // sees the inner cargo / rustynet-cli taxonomy code intact.
        Err(status_code(status))
    }
}

fn report_error(code: ExitCode, message: &str) {
    let hint = code.operator_hint();
    if hint.is_empty() {
        eprintln!("error [{code}]: {message}");
    } else {
        eprintln!("error [{code}]: {message}\n  hint: {hint}");
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
