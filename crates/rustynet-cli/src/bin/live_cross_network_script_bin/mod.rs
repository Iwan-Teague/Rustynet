use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

pub fn run(script_relpath: &str) -> ExitCode {
    let root = repo_root();
    let script = root.join(script_relpath);
    if !script.is_file() {
        eprintln!(
            "missing cross-network validator script: {}",
            script.display()
        );
        return ExitCode::from(2);
    }

    let mut command = Command::new("bash");
    command.current_dir(&root).arg(&script);
    command.args(env::args_os().skip(1));

    match command.status() {
        Ok(status) if status.success() => ExitCode::SUCCESS,
        Ok(status) => ExitCode::from(status_code(status)),
        Err(err) => {
            eprintln!("failed to run {}: {err}", script.display());
            ExitCode::from(1)
        }
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn status_code(status: std::process::ExitStatus) -> u8 {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1)
}
