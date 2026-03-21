#![forbid(unsafe_code)]

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
    let _ignored_args: Vec<_> = env::args_os().skip(1).collect();
    let repo_root = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    run_cargo_ops(&repo_root, "verify-phase9-readiness")?;
    run_cargo_ops(&repo_root, "verify-phase9-evidence")?;

    Ok(())
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

fn run_cargo_ops(repo_root: &Path, ops_command: &str) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            ops_command,
        ])
        .status()
        .map_err(|err| {
            eprintln!("failed to run cargo run for ops command {ops_command}: {err}");
            1
        })?;

    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}
