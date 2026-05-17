#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_SCAN_ROOT: &str = "crates";

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
    let scan_root = env::var_os("RUSTYNET_UNSAFE_SCAN_ROOT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_SCAN_ROOT));
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "check-no-unsafe-rust-sources",
            "--root",
        ])
        .arg(&scan_root)
        .status()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to execute unsafe source scanner: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;
    if status.success() {
        Ok(())
    } else {
        // A scanner non-zero verdict means `unsafe` code was found —
        // a hard policy violation. If the inner ops command already
        // emitted a taxonomy code (64/65/70/78), pass it through;
        // otherwise re-classify a bare GenericFailure as PolicyReject
        // so CI retry-on-70 loops cannot mask a real `unsafe` find.
        let inner = status_code(status);
        if inner == ExitCode::GenericFailure.as_i32() {
            eprintln!(
                "error [{}]: unsafe Rust sources detected by scanner",
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
