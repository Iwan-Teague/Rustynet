#![forbid(unsafe_code)]

use std::env;
use std::process::{Command, ExitStatus, Stdio};

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let passthrough_args: Vec<String> = env::args().skip(1).collect();
    ensure_rustynet_in_path()?;

    let mut command = Command::new("rustynet");
    command.args(["ops", "run-debian-two-node-e2e"]);
    command.args(passthrough_args);
    let status = command.status().map_err(|err| {
        eprintln!("failed to execute rustynet ops run-debian-two-node-e2e: {err}");
        1
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn ensure_rustynet_in_path() -> Result<(), i32> {
    let status = Command::new("sh")
        .args(["-c", "command -v rustynet >/dev/null 2>&1"])
        .stdin(Stdio::null())
        .status()
        .map_err(|err| {
            eprintln!("failed to verify rustynet availability: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
        eprintln!("rustynet CLI is required in PATH");
        Err(1)
    }
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
