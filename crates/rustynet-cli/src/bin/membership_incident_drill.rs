#![forbid(unsafe_code)]

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
        eprintln!("usage: membership_incident_drill [output-dir]");
        return Err(2);
    }

    let root_dir = repo_root().map_err(|err| {
        eprintln!("{err}");
        1
    })?;
    let output_dir = output_dir_arg.unwrap_or_else(|| DEFAULT_OUTPUT_DIR.to_string());
    let output_dir = resolve_path(&root_dir, Path::new(&output_dir));
    fs::create_dir_all(&output_dir).map_err(|err| {
        eprintln!(
            "failed to create membership drill output dir {}: {err}",
            output_dir.display()
        );
        1
    })?;

    let snapshot = env::var("RUSTYNET_MEMBERSHIP_SNAPSHOT_PATH")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MEMBERSHIP_SNAPSHOT_PATH.to_string());
    let log = env::var("RUSTYNET_MEMBERSHIP_LOG_PATH")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_MEMBERSHIP_LOG_PATH.to_string());
    let environment = env::var("RUSTYNET_MEMBERSHIP_EVIDENCE_ENVIRONMENT")
        .ok()
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_EVIDENCE_ENVIRONMENT.to_string());

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
            eprintln!("failed to run membership generate-evidence: {err}");
            1
        })?;
    if status.success() {
        Ok(())
    } else {
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
            eprintln!("missing membership drill artifact: {}", artifact.display());
            return Err(1);
        }
    }

    for artifact in &required[..3] {
        let text = fs::read_to_string(artifact).map_err(|err| {
            eprintln!("failed to read artifact {}: {err}", artifact.display());
            1
        })?;
        if !text.contains(r#""evidence_mode":"measured""#)
            && !text.contains(r#""evidence_mode": "measured""#)
        {
            eprintln!("artifact is not measured evidence: {}", artifact.display());
            return Err(1);
        }
        if !text.contains("\"captured_at_unix\"") {
            eprintln!(
                "artifact missing captured_at_unix metadata: {}",
                artifact.display()
            );
            return Err(1);
        }
        if !text.contains("\"environment\"") {
            eprintln!(
                "artifact missing environment metadata: {}",
                artifact.display()
            );
            return Err(1);
        }
        if !text.contains(r#""status":"pass""#) && !text.contains(r#""status": "pass""#) {
            eprintln!("membership drill failed: {}", artifact.display());
            return Err(1);
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
            eprintln!("failed to run date -u for membership drill summary: {err}");
            1
        })?;
    if !timestamp.status.success() {
        return Err(status_code(timestamp.status));
    }
    let timestamp_text = String::from_utf8_lossy(&timestamp.stdout)
        .trim()
        .to_string();
    let summary = format!(
        "timestamp_utc={timestamp}\nscenario=approver_compromise_recovery\nconformance=pass\nnegative=pass\nrecovery=pass\naudit_log={}/membership_audit_integrity.log\n",
        output_dir.display(),
        timestamp = timestamp_text
    );
    fs::write(output_dir.join("drill_summary.log"), summary).map_err(|err| {
        eprintln!(
            "failed to write membership drill summary {}: {err}",
            output_dir.join("drill_summary.log").display()
        );
        1
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
