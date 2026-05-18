#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_PHASE10_ARTIFACT_DIR: &str = "artifacts/phase10";
const DEFAULT_MAX_AGE_SECONDS: &str = "2678400";
const DEFAULT_OUTPUT_BASENAME: &str = "discovery-validation.md";
const DEFAULT_DISCOVERY_GLOB_PREFIX: &str = "discovery";
const DEFAULT_DISCOVERY_EXTENSION: &str = "json";

fn main() {
    if let Err(err) = run() {
        // X6 taxonomy: classify the error message body to pick the
        // right bucket. The CLI's `classify_cli_error` is private to
        // main.rs, so we mirror the precedence order here for the
        // small set of error shapes this binary emits.
        let code = classify_local_error(err.as_str());
        let hint = code.operator_hint();
        if hint.is_empty() {
            eprintln!("error [{code}]: {err}");
        } else {
            eprintln!("error [{code}]: {err}\n  hint: {hint}");
        }
        std::process::exit(code.as_i32());
    }
}

fn classify_local_error(message: &str) -> ExitCode {
    let lower = message.to_ascii_lowercase();
    if lower.contains("does not accept options") {
        ExitCode::BadArgs
    } else if lower.contains("missing required command")
        || lower.contains("no network discovery bundles found")
        || lower.contains("artifact directory")
        || lower.contains("failed to resolve repository root")
    {
        ExitCode::ConfigError
    } else if lower.contains("failed to run ops") {
        ExitCode::TransientFailure
    } else if lower.contains("ops ") && lower.contains("failed with status") {
        // Subprocess failure — surface as PolicyReject so retry-only-
        // on-70 CI loops do not retry a real validation failure.
        ExitCode::PolicyReject
    } else {
        ExitCode::GenericFailure
    }
}

fn run() -> Result<(), String> {
    let args: Vec<OsString> = env::args_os().skip(1).collect();
    if !args.is_empty() {
        return Err("test_validate_network_discovery_bundle does not accept options".to_owned());
    }

    let root_dir = repo_root()?;
    require_command("cargo")?;

    let artifact_dir = env::var_os("RUSTYNET_PHASE10_ARTIFACT_DIR")
        .filter(|value| !value.is_empty())
        .or_else(|| env::var_os("RUSTYNET_PHASE10_OUT_DIR").filter(|value| !value.is_empty()))
        .unwrap_or_else(|| OsString::from(DEFAULT_PHASE10_ARTIFACT_DIR));
    let artifact_dir_path = PathBuf::from(&artifact_dir);
    let max_age_seconds = env::var_os("RUSTYNET_PHASE10_NETWORK_DISCOVERY_MAX_AGE_SECONDS")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| OsString::from(DEFAULT_MAX_AGE_SECONDS));
    let output = env::var_os("RUSTYNET_PHASE10_NETWORK_DISCOVERY_OUTPUT")
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| {
            artifact_dir_path
                .join(DEFAULT_OUTPUT_BASENAME)
                .as_os_str()
                .to_os_string()
        });

    let bundles = bundle_args(&artifact_dir_path)?;
    if bundles.is_empty() {
        return Err(format!(
            "no network discovery bundles found under {}",
            artifact_dir_path.display()
        ));
    }

    let mut ops_args = Vec::with_capacity(2 + (bundles.len() * 2) + 4);
    for bundle in bundles {
        ops_args.push(OsString::from("--bundle"));
        ops_args.push(bundle);
    }
    ops_args.push(OsString::from("--max-age-seconds"));
    ops_args.push(max_age_seconds);
    ops_args.push(OsString::from("--require-verifier-keys"));
    ops_args.push(OsString::from("--require-daemon-active"));
    ops_args.push(OsString::from("--require-socket-present"));
    ops_args.push(OsString::from("--output"));
    ops_args.push(output);

    run_ops(&root_dir, "validate-network-discovery-bundle", &ops_args)?;
    println!("Network discovery bundle validation: PASS");
    Ok(())
}

fn bundle_args(artifact_dir: &Path) -> Result<Vec<OsString>, String> {
    if let Some(explicit) = env::var_os("RUSTYNET_PHASE10_NETWORK_DISCOVERY_BUNDLES") {
        let value = explicit.to_string_lossy();
        let mut out = Vec::new();
        for raw in value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
        {
            out.push(OsString::from(raw));
        }
        return Ok(out);
    }

    let mut bundles = Vec::new();
    let entries = fs::read_dir(artifact_dir).map_err(|err| {
        format!(
            "list artifact directory failed ({}): {err}",
            artifact_dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read directory entry failed: {err}"))?;
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        let Some(extension) = path.extension().and_then(|value| value.to_str()) else {
            continue;
        };
        if extension == DEFAULT_DISCOVERY_EXTENSION
            && file_name.starts_with(DEFAULT_DISCOVERY_GLOB_PREFIX)
        {
            bundles.push(path.into_os_string());
        }
    }
    bundles.sort();
    Ok(bundles)
}

fn require_command(command: &str) -> Result<(), String> {
    if command_exists(command) {
        Ok(())
    } else {
        Err(format!("missing required command: {command}"))
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

fn run_ops(root_dir: &Path, ops_subcommand: &str, args: &[OsString]) -> Result<(), String> {
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
    let status = command
        .status()
        .map_err(|err| format!("failed to run ops {ops_subcommand}: {err}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ops {ops_subcommand} failed with status {}",
            status_code(status)
        ))
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
