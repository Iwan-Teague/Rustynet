#![forbid(unsafe_code)]

use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE10_ARTIFACT_DIR: &str = "artifacts/phase10";
const DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS: &str = "2678400";

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
    let artifact_dir = phase10_artifact_dir();
    let max_evidence_age_seconds = phase10_max_evidence_age_seconds();

    run_phase10_ops_command(
        &repo_root,
        &artifact_dir,
        &max_evidence_age_seconds,
        "verify-phase10-provenance",
    )?;
    run_phase10_ops_command(
        &repo_root,
        &artifact_dir,
        &max_evidence_age_seconds,
        "verify-phase10-readiness",
    )?;

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

fn phase10_artifact_dir() -> OsString {
    env_default_or_chain(
        [
            env::var_os("RUSTYNET_PHASE10_ARTIFACT_DIR"),
            env::var_os("RUSTYNET_PHASE10_OUT_DIR"),
        ],
        DEFAULT_PHASE10_ARTIFACT_DIR,
    )
}

fn phase10_max_evidence_age_seconds() -> OsString {
    env_default_or_chain(
        [
            env::var_os("RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS"),
            None,
        ],
        DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS,
    )
}

fn env_default_or_chain<const N: usize>(values: [Option<OsString>; N], default: &str) -> OsString {
    for value in values.into_iter().flatten() {
        if !value.is_empty() {
            return value;
        }
    }
    OsString::from(default)
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

fn run_phase10_ops_command(
    repo_root: &Path,
    artifact_dir: &OsString,
    max_evidence_age_seconds: &OsString,
    ops_command: &str,
) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(repo_root)
        .env("RUSTYNET_PHASE10_ARTIFACT_DIR", artifact_dir)
        .env(
            "RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS",
            max_evidence_age_seconds,
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_default_or_chain_prefers_primary_non_empty_value() {
        let value = env_default_or_chain(
            [
                Some(OsString::from("primary")),
                Some(OsString::from("secondary")),
            ],
            "default",
        );
        assert_eq!(value, OsString::from("primary"));
    }

    #[test]
    fn env_default_or_chain_falls_back_to_secondary_when_primary_empty() {
        let value = env_default_or_chain(
            [Some(OsString::from("")), Some(OsString::from("secondary"))],
            "default",
        );
        assert_eq!(value, OsString::from("secondary"));
    }

    #[test]
    fn env_default_or_chain_falls_back_to_default_when_all_missing_or_empty() {
        let value = env_default_or_chain([None, Some(OsString::from(""))], "default");
        assert_eq!(value, OsString::from("default"));
    }
}
