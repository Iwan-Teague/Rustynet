#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

const LEAKAGE_PATTERN: &str = "(wireguard|wg[-_]|wgctrl)";
const SCAN_TARGETS: &[&str] = &[
    "crates/rustynet-control/src",
    "crates/rustynet-policy/src",
    "crates/rustynet-crypto/src",
    "crates/rustynet-backend-api/src",
    "crates/rustynet-relay/src",
];

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let _ignored_args: Vec<OsString> = env::args_os().skip(1).collect();
    let repo_root = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    if !command_exists("rg") {
        eprintln!("missing required command: rg");
        return Err(1);
    }

    let status = Command::new("rg")
        .current_dir(&repo_root)
        .args(["-n", "-i", LEAKAGE_PATTERN])
        .args(SCAN_TARGETS)
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to execute rg backend boundary scan: {err}");
            1
        })?;

    if status.success() {
        println!("backend boundary leakage gate failed");
        return Err(1);
    }
    if status.code() == Some(1) {
        println!("Backend boundary leakage checks: PASS");
        return Ok(());
    }

    Err(status_code(status))
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

fn command_exists(name: &str) -> bool {
    if name.contains(std::path::MAIN_SEPARATOR) {
        return Path::new(name).is_file();
    }
    let Some(path_var) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_var).any(|dir| dir.join(name).is_file())
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
