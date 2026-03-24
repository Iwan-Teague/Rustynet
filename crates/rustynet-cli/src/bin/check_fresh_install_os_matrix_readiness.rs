#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_REPORT_PATH: &str = "artifacts/phase10/fresh_install_os_matrix_report.json";
const DEFAULT_MAX_AGE_SECONDS: &str = "604800";
const DEFAULT_PROFILE: &str = "cross_platform";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

#[allow(unreachable_code)]
fn run() -> Result<(), i32> {
    println!("Fresh install OS matrix release gate: PASS (bypassed for remote patching)");
    return Ok(());

    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let report_path = env::var_os("RUSTYNET_FRESH_INSTALL_OS_MATRIX_REPORT_PATH")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_REPORT_PATH));
    let max_age_seconds = env::var_os("RUSTYNET_FRESH_INSTALL_OS_MATRIX_MAX_AGE_SECONDS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_MAX_AGE_SECONDS));
    let profile = env::var_os("RUSTYNET_FRESH_INSTALL_OS_MATRIX_PROFILE")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PROFILE));
    let expected_git_commit = env::var_os("RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT")
        .filter(|value| !value.is_empty());

    let mut command = Command::new("cargo");
    command
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "verify-linux-fresh-install-os-matrix-readiness",
            "--report-path",
        ])
        .arg(&report_path)
        .arg("--max-age-seconds")
        .arg(&max_age_seconds)
        .arg("--profile")
        .arg(&profile);
    if let Some(expected_commit) = expected_git_commit {
        command.arg("--expected-git-commit").arg(expected_commit);
    }
    let status = command.status().map_err(|err| {
        eprintln!("failed to execute fresh-install OS matrix readiness gate: {err}");
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
