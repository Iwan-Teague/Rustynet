#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_REPORT_PATH: &str = "artifacts/phase10/no_leak_dataplane_report.json";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;

    if current_os() != "Linux" {
        eprintln!("no-leak dataplane gate requires Linux");
        return Err(1);
    }
    if current_uid()? != 0 {
        eprintln!("no-leak dataplane gate requires root privileges");
        return Err(1);
    }

    let report_path = env::var_os("RUSTYNET_NO_LEAK_REPORT_PATH")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_REPORT_PATH.into());

    let status = Command::new(root_dir.join("scripts/e2e/real_wireguard_no_leak_under_load.sh"))
        .current_dir(&root_dir)
        .env("RUSTYNET_NO_LEAK_REPORT_PATH", &report_path)
        .status()
        .map_err(|err| {
            eprintln!("failed to execute no-leak e2e script: {err}");
            1
        })?;
    if !status.success() {
        return Err(status_code(status));
    }

    let verify_status = Command::new("cargo")
        .current_dir(&root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "ops",
            "verify-no-leak-dataplane-report",
            "--report-path",
        ])
        .arg(&report_path)
        .status()
        .map_err(|err| {
            eprintln!("failed to verify no-leak dataplane report: {err}");
            1
        })?;
    if verify_status.success() {
        Ok(())
    } else {
        Err(status_code(verify_status))
    }
}

fn current_os() -> String {
    Command::new("uname")
        .arg("-s")
        .output()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .unwrap_or_else(|_| String::new())
}

fn current_uid() -> Result<u32, i32> {
    let output = Command::new("id").args(["-u"]).output().map_err(|err| {
        eprintln!("failed to determine uid: {err}");
        1
    })?;
    if !output.status.success() {
        eprintln!("failed to determine uid");
        return Err(1);
    }
    let value = String::from_utf8_lossy(&output.stdout);
    value.trim().parse::<u32>().map_err(|err| {
        eprintln!("failed to parse uid: {err}");
        1
    })
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
