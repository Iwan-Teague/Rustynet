#![forbid(unsafe_code)]

use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const HARDED_PATH: &str = "/usr/local/bin/rustynet";

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
    let rustynet_bin = env::var("RUSTYNET_BIN")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| HARDED_PATH.to_string());
    if rustynet_bin != HARDED_PATH {
        eprintln!(
            "[install-systemd] one hardened path is enforced; expected {HARDED_PATH}, got: {rustynet_bin}"
        );
        return Err(1);
    }

    let status = run_rustynet_ops(&rustynet_bin, &root_dir, &["verify-runtime-binary-custody"])?;
    if !status.success() {
        return Err(status_code(status));
    }
    let status = run_rustynet_ops(&rustynet_bin, &root_dir, &["install-systemd"])?;
    if !status.success() {
        return Err(status_code(status));
    }
    Ok(())
}

fn run_rustynet_ops(rustynet_bin: &str, root_dir: &Path, args: &[&str]) -> Result<ExitStatus, i32> {
    Command::new(rustynet_bin)
        .current_dir(root_dir)
        .env("RUSTYNET_INSTALL_SOURCE_ROOT", root_dir)
        .args(["ops"])
        .args(args)
        .status()
        .map_err(|err| {
            eprintln!("failed to execute {rustynet_bin} ops {args:?}: {err}");
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
