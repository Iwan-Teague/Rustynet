#![forbid(unsafe_code)]

mod live_chaos_support;
mod live_signed_state_chaos;

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use live_chaos_support::{ChaosStage, git_head_commit, repo_root, unix_now};
use live_signed_state_chaos::{
    ValidatedScenario, generate_manifest, validate_manifest, write_manifest,
};
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_signed_state_adversarial";

fn signed_state_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: "chaos_replay_old_membership",
            fault: "inject older validly-signed membership update with stale watermark",
            pass_criterion: "replay rejected and daemon stays on current snapshot",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_future_dated_assignment",
            fault: "inject assignment bundle generated beyond allowed clock skew",
            pass_criterion: "future bundle rejected and existing assignment remains active",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_malformed_bundle_truncation",
            fault: "submit truncated signed-state bundle variants",
            pass_criterion: "all malformed variants fail closed with structured errors and no panic",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_forged_signature_attempt",
            fault: "submit bundle signed by unauthorised key material",
            pass_criterion: "signature verification fails and no state mutation occurs",
            recovery_deadline_secs: 60,
        },
        ChaosStage {
            name: "chaos_quorum_starvation_propose",
            fault: "submit quorum-governed update without enough approvals",
            pass_criterion: "record stays pending and no partial-quorum mutation is accepted",
            recovery_deadline_secs: 60,
        },
    ]
}

#[derive(Clone, Debug)]
struct Config {
    report_path: PathBuf,
    log_path: PathBuf,
    fixture_dir: PathBuf,
    git_commit: String,
    dry_run: bool,
    scenario: String,
}

impl Config {
    fn parse(args: impl IntoIterator<Item = String>) -> Result<Self, String> {
        let root = repo_root()?;
        let mut config = Self {
            report_path: root.join(format!("artifacts/phase10/{CATEGORY}_report.json")),
            log_path: root.join(format!("artifacts/phase10/source/{CATEGORY}.log")),
            fixture_dir: root.join("artifacts/phase10/chaos_signed_state_fixtures"),
            git_commit: env::var("RUSTYNET_EXPECTED_GIT_COMMIT")
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| git_head_commit(&root)),
            dry_run: false,
            scenario: "all".to_owned(),
        };

        let args = args.into_iter().collect::<Vec<_>>();
        let mut idx = 0usize;
        while idx < args.len() {
            match args[idx].as_str() {
                "--dry-run" => config.dry_run = true,
                "--report-path" => {
                    idx += 1;
                    config.report_path =
                        PathBuf::from(required_value(&args, idx, "--report-path")?);
                }
                "--log-path" => {
                    idx += 1;
                    config.log_path = PathBuf::from(required_value(&args, idx, "--log-path")?);
                }
                "--fixture-dir" => {
                    idx += 1;
                    config.fixture_dir =
                        PathBuf::from(required_value(&args, idx, "--fixture-dir")?);
                }
                "--git-commit" => {
                    idx += 1;
                    config.git_commit = required_value(&args, idx, "--git-commit")?;
                }
                "--scenario" => {
                    idx += 1;
                    config.scenario = required_value(&args, idx, "--scenario")?;
                }
                "-h" | "--help" => {
                    print_usage();
                    std::process::exit(0);
                }
                other => {
                    print_usage();
                    return Err(format!("unknown argument: {other}"));
                }
            }
            idx += 1;
        }
        Ok(config)
    }
}

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let config = Config::parse(env::args().skip(1))?;
    write_parent(&config.log_path)?;
    fs::write(
        &config.log_path,
        format!(
            "category={CATEGORY}\ndry_run={}\ngenerated_at_unix={}\nfixture_dir={}\n",
            config.dry_run,
            unix_now(),
            config.fixture_dir.display()
        ),
    )
    .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))?;

    let manifest = generate_manifest(&config.fixture_dir, &config.scenario, unix_now())?;
    let manifest_path = write_manifest(&config.fixture_dir, &manifest)?;
    let validated = validate_manifest(&manifest)?;
    let report = render_report(&config, &manifest_path, &validated);
    write_parent(&config.report_path)?;
    fs::write(
        &config.report_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise signed-state chaos report failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", config.report_path.display()))?;

    if report
        .get("overall_status")
        .and_then(Value::as_str)
        .is_some_and(|status| status == "pass")
    {
        Ok(())
    } else {
        Err("signed-state adversarial fixture validation failed".to_owned())
    }
}

fn render_report(config: &Config, manifest_path: &Path, scenarios: &[ValidatedScenario]) -> Value {
    let grouped = group_by_stage(scenarios);
    let stage_reports = signed_state_stages()
        .iter()
        .map(|stage| render_stage(stage, grouped.get(stage.name)))
        .collect::<Vec<_>>();
    let all_pass = stage_reports
        .iter()
        .all(|stage| stage.get("status").and_then(Value::as_str) == Some("pass"));
    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": if all_pass { "pass" } else { "fail" },
        "summary": "offline signed-state adversarial fixtures generated and pinned to fail-closed expectations",
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "fixture_manifest": manifest_path,
        "fixture_scenario_count": scenarios.len(),
        "stages": stage_reports,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": false,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "offline_only": true,
            "production_accepted": false,
            "expected_result": "reject_fail_closed"
        }
    })
}

fn render_stage(stage: &ChaosStage, scenarios: Option<&Vec<&ValidatedScenario>>) -> Value {
    let scenario_values = scenarios
        .into_iter()
        .flatten()
        .map(|scenario| {
            json!({
                "scenario": scenario.id,
                "bytes": scenario.bytes,
                "expected_rejection": scenario.expected_rejection,
            })
        })
        .collect::<Vec<_>>();
    json!({
        "name": stage.name,
        "status": if scenario_values.is_empty() { "fail" } else { "pass" },
        "fault": stage.fault,
        "pass_criterion": stage.pass_criterion,
        "recovery_deadline_secs": stage.recovery_deadline_secs,
        "measured_recovery_secs": 0,
        "plaintext_leak_check": "not-applicable-offline",
        "production_state_mutation": false,
        "expected_result": "reject_fail_closed",
        "scenarios": scenario_values,
    })
}

fn group_by_stage(scenarios: &[ValidatedScenario]) -> BTreeMap<String, Vec<&ValidatedScenario>> {
    let mut grouped = BTreeMap::new();
    for scenario in scenarios {
        grouped
            .entry(scenario.stage_name.clone())
            .or_insert_with(Vec::new)
            .push(scenario);
    }
    grouped
}

fn required_value(args: &[String], idx: usize, flag: &str) -> Result<String, String> {
    args.get(idx)
        .filter(|value| !value.trim().is_empty())
        .cloned()
        .ok_or_else(|| format!("missing required argument value for {flag}"))
}

fn print_usage() {
    eprintln!(
        "usage: {CATEGORY} [--dry-run] [--scenario all|<scenario>] [--fixture-dir <path>] [--report-path <path>] [--log-path <path>] [--git-commit <sha>]"
    );
}

fn write_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustynet-chaos-signed-state-{label}-{}",
            std::process::id()
        ))
    }

    fn parse(args: &[&str]) -> Result<Config, String> {
        Config::parse(args.iter().map(|value| (*value).to_owned()))
    }

    #[test]
    fn parser_accepts_dry_run_and_fixture_dir() {
        let config = parse(&[
            "--dry-run",
            "--fixture-dir",
            "/tmp/rustynet-signed-state-fixtures",
            "--scenario",
            "all",
        ])
        .expect("config should parse");
        assert!(config.dry_run);
        assert_eq!(config.scenario, "all");
    }

    #[test]
    fn report_marks_all_stages_pass_for_all_scenarios() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let output_dir = test_dir("all-scenarios");
        let manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        let scenarios = validate_manifest(&manifest).expect("validate");
        let report = render_report(&config, Path::new("/tmp/manifest.json"), &scenarios);
        assert_eq!(report["overall_status"], "pass");
        let stages = report["stages"].as_array().expect("stages");
        assert_eq!(stages.len(), 5);
        assert!(stages.iter().all(|stage| stage["status"] == "pass"));
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn report_fails_when_a_stage_has_no_fixture() {
        let config = parse(&["--dry-run"]).expect("config should parse");
        let output_dir = test_dir("single-scenario");
        let manifest =
            generate_manifest(&output_dir, "forged_signature_attempt", 123).expect("manifest");
        let scenarios = validate_manifest(&manifest).expect("validate");
        let report = render_report(&config, Path::new("/tmp/manifest.json"), &scenarios);
        assert_eq!(report["overall_status"], "fail");
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn every_configured_stage_has_an_offline_fixture_in_all_scenarios() {
        let output_dir = test_dir("stage-coverage");
        let manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        let scenarios = validate_manifest(&manifest).expect("validate");
        let present = scenarios
            .iter()
            .map(|scenario| scenario.stage_name.as_str())
            .collect::<BTreeSet<_>>();
        for stage in signed_state_stages() {
            assert!(
                present.contains(stage.name),
                "missing fixture for {}",
                stage.name
            );
        }
        let _ = fs::remove_dir_all(output_dir);
    }
}
