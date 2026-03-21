#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_EXCEPTIONS_PATH: &str = "documents/operations/dependency_exceptions.json";

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
        eprintln!("{err}");
        1
    })?;
    let exceptions_path = env::var_os("RUSTYNET_DEPENDENCY_EXCEPTIONS_PATH")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_EXCEPTIONS_PATH));

    run_cargo(
        &root_dir,
        &[
            OsString::from("run"),
            OsString::from("--quiet"),
            OsString::from("-p"),
            OsString::from("rustynet-cli"),
            OsString::from("--"),
            OsString::from("ops"),
            OsString::from("check-dependency-exceptions"),
            OsString::from("--path"),
            exceptions_path,
        ],
    )
}

fn run_cargo(root_dir: &Path, args: &[OsString]) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args(args.iter().map(OsString::as_os_str))
        .status()
        .map_err(|err| {
            eprintln!("failed to execute cargo command: {err}");
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
