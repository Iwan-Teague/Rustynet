#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE10_ARTIFACT_DIR: &str = "artifacts/phase10";
const DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS: &str = "604800";
const DEFAULT_REQUIRED_NAT_PROFILES: &str = "baseline_lan";
const DEFAULT_SCHEMA_OUTPUT_BASENAME: &str = "cross_network_remote_exit_schema_validation.md";
const DEFAULT_NAT_MATRIX_OUTPUT_BASENAME: &str =
    "cross_network_remote_exit_nat_matrix_validation.md";

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
        report_error(ExitCode::ConfigError, &err);
        ExitCode::ConfigError.as_i32()
    })?;

    require_command("cargo")?;
    require_command("git")?;

    let artifact_dir = env::var_os("RUSTYNET_PHASE10_ARTIFACT_DIR")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("RUSTYNET_PHASE10_OUT_DIR").filter(|value| !value.is_empty()))
        .unwrap_or_else(|| OsString::from(DEFAULT_PHASE10_ARTIFACT_DIR));
    let max_evidence_age_seconds = env::var_os("RUSTYNET_PHASE10_MAX_EVIDENCE_AGE_SECONDS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_PHASE10_MAX_EVIDENCE_AGE_SECONDS));
    let required_nat_profiles = env::var_os("RUSTYNET_PHASE10_CROSS_NETWORK_NAT_PROFILES")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_REQUIRED_NAT_PROFILES));
    let artifact_dir_path = PathBuf::from(&artifact_dir);

    let schema_output = env::var_os("RUSTYNET_PHASE10_CROSS_NETWORK_EXIT_SCHEMA_OUTPUT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            artifact_dir_path
                .join(DEFAULT_SCHEMA_OUTPUT_BASENAME)
                .as_os_str()
                .to_os_string()
        });
    let nat_matrix_output = env::var_os("RUSTYNET_PHASE10_CROSS_NETWORK_EXIT_NAT_MATRIX_OUTPUT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            artifact_dir_path
                .join(DEFAULT_NAT_MATRIX_OUTPUT_BASENAME)
                .as_os_str()
                .to_os_string()
        });

    let expected_commit = env::var_os("RUSTYNET_PHASE10_CROSS_NETWORK_EXIT_EXPECTED_GIT_COMMIT")
        .filter(|value| !value.is_empty())
        .unwrap_or(get_head_commit(&root_dir).map_err(|err| {
            report_error(ExitCode::TransientFailure, &err);
            ExitCode::TransientFailure.as_i32()
        })?);

    run_bin(
        &root_dir,
        "test_validate_cross_network_remote_exit_reports",
        &[],
    )?;
    run_bin(&root_dir, "test_validate_cross_network_nat_matrix", &[])?;
    run_bin(&root_dir, "test_validate_network_discovery_bundle", &[])?;
    run_bin(
        &root_dir,
        "test_cross_network_remote_exit_skeleton_validators",
        &[],
    )?;

    run_ops(
        &root_dir,
        "validate-cross-network-remote-exit-reports",
        &[
            OsString::from("--artifact-dir"),
            artifact_dir.clone(),
            OsString::from("--expected-git-commit"),
            expected_commit.clone(),
            OsString::from("--require-pass-status"),
            OsString::from("--max-evidence-age-seconds"),
            max_evidence_age_seconds.clone(),
            OsString::from("--output"),
            schema_output,
        ],
    )?;
    run_ops(
        &root_dir,
        "validate-cross-network-nat-matrix",
        &[
            OsString::from("--artifact-dir"),
            artifact_dir,
            OsString::from("--required-nat-profiles"),
            required_nat_profiles,
            OsString::from("--expected-git-commit"),
            expected_commit,
            OsString::from("--require-pass-status"),
            OsString::from("--max-evidence-age-seconds"),
            max_evidence_age_seconds,
            OsString::from("--output"),
            nat_matrix_output,
        ],
    )?;

    println!("Phase 10 cross-network remote-exit schema gates: PASS");
    Ok(())
}

fn require_command(command: &str) -> Result<(), i32> {
    if command_exists(command) {
        Ok(())
    } else {
        report_error(
            ExitCode::ConfigError,
            &format!("missing required command: {command}"),
        );
        Err(ExitCode::ConfigError.as_i32())
    }
}

fn command_exists(command: &str) -> bool {
    if Path::new(command).components().count() > 1 {
        return Path::new(command).is_file();
    }
    let Some(path_value) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path_value).any(|dir| dir.join(command).is_file())
}

fn get_head_commit(root_dir: &Path) -> Result<OsString, String> {
    let output = Command::new("git")
        .current_dir(root_dir)
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("failed to run git rev-parse HEAD: {err}"))?;
    if !output.status.success() {
        return Err("git rev-parse HEAD failed".to_string());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return Err("git rev-parse HEAD returned empty output".to_string());
    }
    Ok(OsString::from(trimmed))
}

fn run_bin(root_dir: &Path, bin_name: &str, args: &[OsString]) -> Result<(), i32> {
    let mut command = Command::new("cargo");
    command.current_dir(root_dir).args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--bin",
        bin_name,
        "--",
    ]);
    command.args(args.iter().map(OsString::as_os_str));
    let status = command.status().map_err(|err| {
        report_error(
            ExitCode::TransientFailure,
            &format!("failed to run bin {bin_name}: {err}"),
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through subprocess exit code so the inner taxonomy
        // bubble (e.g. PolicyReject from a downstream validator)
        // survives unchanged.
        Err(status_code(status))
    }
}

fn run_ops(root_dir: &Path, ops_subcommand: &str, args: &[OsString]) -> Result<(), i32> {
    let mut command = Command::new("cargo");
    command.current_dir(root_dir).args([
        "run",
        "--quiet",
        "-p",
        "rustynet-cli",
        "--",
        "ops",
        ops_subcommand,
    ]);
    command.args(args.iter().map(OsString::as_os_str));
    let status = command.status().map_err(|err| {
        report_error(
            ExitCode::TransientFailure,
            &format!("failed to run ops {ops_subcommand}: {err}"),
        );
        ExitCode::TransientFailure.as_i32()
    })?;
    if status.success() {
        Ok(())
    } else {
        Err(status_code(status))
    }
}

fn report_error(code: ExitCode, message: &str) {
    let hint = code.operator_hint();
    if hint.is_empty() {
        eprintln!("error [{code}]: {message}");
    } else {
        eprintln!("error [{code}]: {message}\n  hint: {hint}");
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
