#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::json;

#[derive(Clone, Debug)]
pub struct ChaosStage {
    pub name: &'static str,
    pub fault: &'static str,
    pub pass_criterion: &'static str,
    pub recovery_deadline_secs: u64,
}

#[derive(Clone, Debug)]
pub struct ChaosConfig {
    pub category: &'static str,
    pub report_path: PathBuf,
    pub log_path: PathBuf,
    pub dry_run: bool,
    pub git_commit: String,
    pub stages: Vec<ChaosStage>,
}

pub fn repo_root() -> Result<PathBuf, String> {
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

pub fn git_head_commit(root: &Path) -> String {
    std::process::Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .current_dir(root)
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn parse_config(
    category: &'static str,
    stages: Vec<ChaosStage>,
    args: impl IntoIterator<Item = String>,
) -> Result<ChaosConfig, String> {
    let root = repo_root()?;
    let mut report_path = root.join(format!("artifacts/phase10/{category}_report.json"));
    let mut log_path = root.join(format!("artifacts/phase10/source/{category}.log"));
    let mut dry_run = false;
    let mut git_commit = env::var("RUSTYNET_EXPECTED_GIT_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| git_head_commit(&root));

    let args = args.into_iter().collect::<Vec<_>>();
    let mut idx = 0usize;
    while idx < args.len() {
        match args[idx].as_str() {
            "--report-path" => {
                idx += 1;
                report_path = PathBuf::from(required_value(&args, idx, "--report-path")?);
            }
            "--log-path" => {
                idx += 1;
                log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
            }
            "--git-commit" => {
                idx += 1;
                git_commit = required_value(&args, idx, "--git-commit")?;
            }
            "--dry-run" => {
                dry_run = true;
            }
            "-h" | "--help" => {
                print_usage(category);
                std::process::exit(0);
            }
            other => {
                print_usage(category);
                return Err(format!("unknown argument: {other}"));
            }
        }
        idx += 1;
    }

    Ok(ChaosConfig {
        category,
        report_path,
        log_path,
        dry_run,
        git_commit,
        stages,
    })
}

pub fn run_category(config: ChaosConfig) -> Result<(), String> {
    write_parent(&config.log_path)?;
    fs::write(
        &config.log_path,
        format!(
            "category={}\ndry_run={}\ngenerated_at_unix={}\n",
            config.category,
            config.dry_run,
            unix_now()
        ),
    )
    .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))?;

    let status = if config.dry_run { "skipped" } else { "fail" };
    let summary = if config.dry_run {
        "chaos category scaffold validated without mutating live hosts"
    } else {
        "live chaos injection for this category is not enabled by this scaffold slice"
    };
    let stage_reports = config
        .stages
        .iter()
        .map(|stage| {
            json!({
                "name": stage.name,
                "status": status,
                "fault": stage.fault,
                "pass_criterion": stage.pass_criterion,
                "recovery_deadline_secs": stage.recovery_deadline_secs,
                "measured_recovery_secs": null,
                "plaintext_leak_check": "not-run",
            })
        })
        .collect::<Vec<_>>();
    let report = json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": config.category,
        "overall_status": status,
        "summary": summary,
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "stages": stage_reports,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": true,
            "requires_plaintext_leak_capture_for_live_faults": true,
            "production_state_mutation": false
        }
    });
    write_parent(&config.report_path)?;
    fs::write(
        &config.report_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise chaos report failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", config.report_path.display()))?;

    if config.dry_run {
        Ok(())
    } else {
        Err(summary.to_owned())
    }
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage(category: &str) {
    eprintln!(
        "usage: {category} [--dry-run] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

fn write_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    Ok(())
}
