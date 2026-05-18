#![forbid(unsafe_code)]

use rustynetd::exit_codes::ExitCode;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

const DEFAULT_OUTPUT_DIR: &str = "artifacts/membership";
const DEFAULT_MEMBERSHIP_SNAPSHOT_PATH: &str = "/var/lib/rustynet/membership.snapshot";
const DEFAULT_MEMBERSHIP_LOG_PATH: &str = "/var/lib/rustynet/membership.log";
const DEFAULT_EVIDENCE_ENVIRONMENT: &str = "incident-drill";

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(code) => code,
    };
    std::process::exit(code);
}

fn run() -> Result<(), i32> {
    let mut args = env::args().skip(1);
    let output_dir_arg = args.next();
    if args.next().is_some() {
        eprintln!(
            "error [{}]: usage: membership_incident_drill [output-dir]",
            ExitCode::BadArgs
        );
        return Err(ExitCode::BadArgs.as_i32());
    }

    let root_dir = repo_root().map_err(|err| {
        eprintln!("error [{}]: {err}", ExitCode::ConfigError);
        ExitCode::ConfigError.as_i32()
    })?;
    let output_dir = output_dir_arg.unwrap_or_else(|| DEFAULT_OUTPUT_DIR.to_owned());
    let output_dir = resolve_path(&root_dir, Path::new(&output_dir));
    fs::create_dir_all(&output_dir).map_err(|err| {
        eprintln!(
            "error [{}]: failed to create membership drill output dir {}: {err}",
            ExitCode::TransientFailure,
            output_dir.display()
        );
        ExitCode::TransientFailure.as_i32()
    })?;

    let snapshot = env::var("RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MEMBERSHIP_SNAPSHOT_PATH.to_owned());
    let log = env::var("RUSTYNET_MEMBERSHIP_LOG_PATH")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MEMBERSHIP_LOG_PATH.to_owned());
    let environment = env::var("RUSTYNET_MEMBERSHIP_EVIDENCE_ENVIRONMENT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_EVIDENCE_ENVIRONMENT.to_owned());

    run_membership_generate_evidence(&root_dir, &snapshot, &log, &output_dir, &environment)?;
    verify_artifacts(&output_dir)?;
    write_summary_log(&root_dir, &output_dir)?;

    println!(
        "membership incident drill complete: {}",
        output_dir.display()
    );
    Ok(())
}

fn run_membership_generate_evidence(
    root_dir: &Path,
    snapshot: &str,
    log: &str,
    output_dir: &Path,
    environment: &str,
) -> Result<(), i32> {
    let status = Command::new("cargo")
        .current_dir(root_dir)
        .args([
            "run",
            "--quiet",
            "-p",
            "rustynet-cli",
            "--",
            "membership",
            "generate-evidence",
            "--snapshot",
            snapshot,
            "--log",
            log,
            "--output-dir",
        ])
        .arg(output_dir)
        .args(["--environment", environment])
        .status()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to run membership generate-evidence: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;
    if status.success() {
        Ok(())
    } else {
        // Pass through: the membership generate-evidence subcommand
        // already classifies its own failures with the X6 taxonomy
        // (signature/integrity failures bubble as PolicyReject inside).
        Err(status_code(status))
    }
}

fn verify_artifacts(output_dir: &Path) -> Result<(), i32> {
    let required = [
        output_dir.join("membership_conformance_report.json"),
        output_dir.join("membership_negative_tests_report.json"),
        output_dir.join("membership_recovery_report.json"),
        output_dir.join("membership_audit_integrity.log"),
    ];
    for artifact in &required {
        if !artifact.is_file() {
            // Missing required membership evidence is a fail-closed
            // verdict: the drill cannot attest to membership integrity
            // without all four artifacts present. Operators must NOT
            // retry; the absence is itself the policy signal.
            eprintln!(
                "error [{}]: missing membership drill artifact: {}",
                ExitCode::PolicyReject,
                artifact.display()
            );
            return Err(ExitCode::PolicyReject.as_i32());
        }
    }

    for artifact in &required[..3] {
        let text = fs::read_to_string(artifact).map_err(|err| {
            eprintln!(
                "error [{}]: failed to read artifact {}: {err}",
                ExitCode::TransientFailure,
                artifact.display()
            );
            ExitCode::TransientFailure.as_i32()
        })?;
        if !text.contains(r#""evidence_mode":"measured""#)
            && !text.contains(r#""evidence_mode": "measured""#)
        {
            // Non-measured evidence means the drill ran in a stub /
            // synthetic mode — accepting that would defeat the
            // membership-integrity claim. Fail-closed.
            eprintln!(
                "error [{}]: artifact is not measured evidence: {}",
                ExitCode::PolicyReject,
                artifact.display()
            );
            return Err(ExitCode::PolicyReject.as_i32());
        }
        if !text.contains("\"captured_at_unix\"") {
            eprintln!(
                "error [{}]: artifact missing captured_at_unix metadata: {}",
                ExitCode::PolicyReject,
                artifact.display()
            );
            return Err(ExitCode::PolicyReject.as_i32());
        }
        if !text.contains("\"environment\"") {
            eprintln!(
                "error [{}]: artifact missing environment metadata: {}",
                ExitCode::PolicyReject,
                artifact.display()
            );
            return Err(ExitCode::PolicyReject.as_i32());
        }
        if !text.contains(r#""status":"pass""#) && !text.contains(r#""status": "pass""#) {
            // The drill explicitly recorded a non-pass status — that
            // is a real fail-closed membership verdict, not a flake.
            eprintln!(
                "error [{}]: membership drill failed: {}",
                ExitCode::PolicyReject,
                artifact.display()
            );
            return Err(ExitCode::PolicyReject.as_i32());
        }
    }

    Ok(())
}

fn write_summary_log(root_dir: &Path, output_dir: &Path) -> Result<(), i32> {
    let timestamp = Command::new("date")
        .current_dir(root_dir)
        .args(["-u", "+%Y%m%dT%H%M%SZ"])
        .output()
        .map_err(|err| {
            eprintln!(
                "error [{}]: failed to run date -u for membership drill summary: {err}",
                ExitCode::TransientFailure
            );
            ExitCode::TransientFailure.as_i32()
        })?;
    if !timestamp.status.success() {
        return Err(status_code(timestamp.status));
    }
    let timestamp_text = String::from_utf8_lossy(&timestamp.stdout).trim().to_owned();
    let summary = format!(
        "timestamp_utc={timestamp}\nscenario=approver_compromise_recovery\nconformance=pass\nnegative=pass\nrecovery=pass\naudit_log={}/membership_audit_integrity.log\n",
        output_dir.display(),
        timestamp = timestamp_text
    );
    fs::write(output_dir.join("drill_summary.log"), summary).map_err(|err| {
        eprintln!(
            "error [{}]: failed to write membership drill summary {}: {err}",
            ExitCode::TransientFailure,
            output_dir.join("drill_summary.log").display()
        );
        ExitCode::TransientFailure.as_i32()
    })
}

fn resolve_path(root_dir: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root_dir.join(path)
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
