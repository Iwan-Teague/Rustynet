#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::ops_security_audit::{
    EvaluateLiveCoveragePromotionConfig, ValidateLiveLabReportsConfig,
    execute_ops_evaluate_live_coverage_promotion, execute_ops_validate_live_lab_reports,
};
use crate::security_audit_catalog::{
    COMPARATIVE_CATALOG, CheckMetadata, ComparativeCatalogEntry, comparative_command_spec,
    comparative_status_order, sorted_validation_specs, validation_arg_flag,
    validation_check_metadata, validation_spec_by_key, validation_spec_by_mode,
};

const CHECK_PASS: &str = "pass";
const CHECK_SKIP: &str = "skip";
const CHECK_SKIPPED: &str = "skipped";
const STATUS_PASS: &str = "pass";
const EVIDENCE_MODE_MEASURED: &str = "measured";
const DEFAULT_COMPARATIVE_FORMAT: &str = "md";

const SSH_PREFLIGHT_EXPECT_SCRIPT: &str = r#"
if {$argc != 4} {
  puts stderr "usage: ssh-preflight.expect <password-file> <known-hosts-file> <target> <timeout>"
  exit 2
}
set password_file [lindex $argv 0]
set known_hosts [lindex $argv 1]
set target [lindex $argv 2]
set timeout [lindex $argv 3]
set fh [open $password_file r]
gets $fh password
close $fh
log_user 0
match_max 2000000
spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=$timeout -- $target true
expect {
  -re {(?i)password:} { send -- "$password\r"; exp_continue }
  eof {
    catch wait result
    exit [lindex $result 3]
  }
}
"#;

const SSH_CAPTURE_EXPECT_SCRIPT: &str = r#"
if {$argc != 5} {
  puts stderr "usage: ssh-capture.expect <password-file> <known-hosts-file> <target> <timeout> <command>"
  exit 2
}
set password_file [lindex $argv 0]
set known_hosts [lindex $argv 1]
set target [lindex $argv 2]
set timeout [lindex $argv 3]
set remote_command [lindex $argv 4]
set fh [open $password_file r]
gets $fh password
close $fh
log_user 0
match_max 2000000
spawn ssh -o LogLevel=ERROR -o StrictHostKeyChecking=yes -o UserKnownHostsFile=$known_hosts -o ConnectTimeout=$timeout -- $target sh -lc $remote_command
expect {
  -re {(?i)password:} { send -- "$password\r"; exp_continue }
  eof {
    catch wait result
    exit [lindex $result 3]
  }
}
"#;

const REMOTE_RUNTIME_REQUIREMENTS_COMMAND: &str = r#"
missing=""
for cmd in rustynet rustynetd wg systemctl ss python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "missing_binary:$cmd"
    missing=1
  fi
done
if command -v systemctl >/dev/null 2>&1; then
  load_state=$(systemctl show -p LoadState --value rustynetd.service 2>/dev/null || true)
  if [ "$load_state" = "loaded" ]; then
    echo "service_present:rustynetd.service"
  else
    echo "missing_service:rustynetd.service"
    missing=1
  fi
  if systemctl is-active --quiet rustynetd.service; then
    echo "service_active:rustynetd.service"
  else
    echo "inactive_service:rustynetd.service"
    missing=1
  fi
fi
if [ -n "$missing" ]; then
  exit 1
fi
"#;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateLiveLabFindingsConfig {
    pub reports: Vec<PathBuf>,
    pub report_dir: Option<PathBuf>,
    pub output: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateComparativeExploitCoverageConfig {
    pub workspace: PathBuf,
    pub output: PathBuf,
    pub format: String,
    pub projects: String,
    pub attack_families: String,
    pub run_local_tests: bool,
    pub max_output_chars: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunLiveLabValidationsConfig {
    pub repo_root: PathBuf,
    pub ssh_password_file: PathBuf,
    pub sudo_password_file: PathBuf,
    pub ssh_known_hosts_file: Option<PathBuf>,
    pub validations: String,
    pub report_dir: Option<PathBuf>,
    pub findings_output: Option<PathBuf>,
    pub schema_output: Option<PathBuf>,
    pub promotion_output: Option<PathBuf>,
    pub summary_output: Option<PathBuf>,
    pub dry_run: bool,
    pub skip_ssh_reachability_preflight: bool,
    pub exit_host: Option<String>,
    pub client_host: Option<String>,
    pub entry_host: Option<String>,
    pub aux_host: Option<String>,
    pub extra_host: Option<String>,
    pub probe_host: Option<String>,
    pub dns_bind_addr: Option<String>,
    pub ssh_allow_cidrs: Option<String>,
    pub probe_port: Option<String>,
    pub rogue_endpoint_ip: Option<String>,
    pub socket_path: Option<String>,
    pub assignment_path: Option<String>,
    pub connect_timeout_secs: u64,
}

#[derive(Clone)]
struct Finding {
    severity: String,
    title: String,
    exploit_family: String,
    mode_title: String,
    report_path: String,
    check_name: String,
    rationale: String,
    affected_files: Vec<String>,
    evidence_summary: String,
}

#[derive(Clone)]
struct PassingCheck {
    mode_title: String,
    check_name: String,
    report_path: String,
}

#[derive(Clone)]
struct ComparativeCommandResult {
    key: String,
    label: String,
    argv: Vec<String>,
    rc: i32,
    status: String,
    output: String,
}

#[derive(Clone)]
struct ValidationRunResult {
    validation_key: String,
    command: Vec<String>,
    rc: i32,
    stderr: String,
    report_path: PathBuf,
}

pub fn default_comparative_format() -> &'static str {
    DEFAULT_COMPARATIVE_FORMAT
}

pub fn execute_ops_generate_live_lab_findings(
    config: GenerateLiveLabFindingsConfig,
) -> Result<String, String> {
    let report_paths =
        collect_report_paths(config.reports.as_slice(), config.report_dir.as_deref())?;
    let mut findings = Vec::new();
    let mut passes = Vec::new();
    let mut schema_problems = Vec::new();
    for report_path in &report_paths {
        let payload = load_json_object(report_path.as_path())?;
        schema_problems.extend(validate_findings_report_schema(
            report_path.as_path(),
            &payload,
        ));
        let (report_findings, report_passes) = derive_findings(report_path.as_path(), &payload);
        findings.extend(report_findings);
        passes.extend(report_passes);
    }
    let output_path = resolve_path(config.output.as_path())?;
    ensure_parent_dir(output_path.as_path())?;
    fs::write(
        output_path.as_path(),
        render_findings_markdown(
            findings.as_slice(),
            passes.as_slice(),
            schema_problems.as_slice(),
            report_paths.as_slice(),
        ),
    )
    .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
    Ok(format!("wrote live-lab findings {}", output_path.display()))
}

pub fn execute_ops_generate_comparative_exploit_coverage(
    config: GenerateComparativeExploitCoverageConfig,
) -> Result<String, String> {
    let workspace = resolve_path(config.workspace.as_path())?;
    let entries = select_comparative_entries(
        parse_optional_filter(config.projects.as_str())?,
        parse_optional_filter(config.attack_families.as_str())?,
    )?;
    let command_results = if config.run_local_tests {
        Some(run_comparative_commands(
            workspace.as_path(),
            collect_comparative_command_keys(entries.as_slice()),
            config.max_output_chars,
        )?)
    } else {
        None
    };
    let output_path = resolve_path(config.output.as_path())?;
    ensure_parent_dir(output_path.as_path())?;
    let rendered = match config.format.as_str() {
        "md" => render_comparative_markdown(entries.as_slice(), command_results.as_deref()),
        "json" => render_comparative_json(entries.as_slice(), command_results.as_deref())?,
        other => {
            return Err(format!(
                "invalid --format value {other:?}; expected md or json"
            ));
        }
    };
    fs::write(output_path.as_path(), rendered)
        .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
    Ok(format!(
        "wrote comparative exploit coverage {}",
        output_path.display()
    ))
}

pub fn execute_ops_run_live_lab_validations(
    config: RunLiveLabValidationsConfig,
) -> Result<String, String> {
    if config.skip_ssh_reachability_preflight && !config.dry_run {
        return Err("--skip-ssh-reachability-preflight is only allowed with --dry-run".to_string());
    }
    let repo_root = resolve_path(config.repo_root.as_path())?;
    let report_dir = if let Some(path) = config.report_dir.as_ref() {
        resolve_path(path.as_path())?
    } else {
        repo_root
            .join("artifacts")
            .join("phase10")
            .join("live_skill_runs")
            .join(timestamp_for_path())
    };
    fs::create_dir_all(report_dir.as_path())
        .map_err(|err| format!("create {} failed: {err}", report_dir.display()))?;
    let findings_output = config
        .findings_output
        .as_ref()
        .map(|path| resolve_path(path.as_path()))
        .transpose()?
        .unwrap_or_else(|| report_dir.join("live_lab_findings.md"));
    let schema_output = config
        .schema_output
        .as_ref()
        .map(|path| resolve_path(path.as_path()))
        .transpose()?
        .unwrap_or_else(|| report_dir.join("live_lab_schema_validation.md"));
    let promotion_output = config
        .promotion_output
        .as_ref()
        .map(|path| resolve_path(path.as_path()))
        .transpose()?
        .unwrap_or_else(|| report_dir.join("live_lab_coverage_promotion.md"));
    let summary_output = config
        .summary_output
        .as_ref()
        .map(|path| resolve_path(path.as_path()))
        .transpose()?
        .unwrap_or_else(|| report_dir.join("live_lab_validation_summary.md"));

    let specs = selected_validation_specs(config.validations.as_str())?;
    require_validation_args(specs.as_slice(), &config)?;
    let known_hosts_path = run_preflight(&config)?;

    let mut results = Vec::new();
    let mut report_paths = Vec::new();
    for spec in &specs {
        let (command, report_path) =
            build_validation_command(spec, &config, repo_root.as_path(), report_dir.as_path())?;
        let result = if config.dry_run {
            ValidationRunResult {
                validation_key: spec.key.to_string(),
                command,
                rc: 0,
                stderr: String::new(),
                report_path,
            }
        } else {
            run_validation(
                spec.key,
                command,
                report_path,
                repo_root.as_path(),
                known_hosts_path.as_path(),
            )?
        };
        if result.report_path.exists() {
            report_paths.push(result.report_path.clone());
        }
        results.push(result);
    }

    if config.dry_run {
        write_placeholder_file(
            findings_output.as_path(),
            "# Dry Run\n\nNo findings were generated because the runner was executed with `--dry-run`.\n",
        )?;
        write_placeholder_file(
            schema_output.as_path(),
            "# Dry Run\n\nNo schema validation was performed because the runner was executed with `--dry-run`.\n",
        )?;
        write_placeholder_file(
            promotion_output.as_path(),
            "# Dry Run\n\nNo coverage promotion evaluation was performed because the runner was executed with `--dry-run`.\n",
        )?;
        write_summary(
            summary_output.as_path(),
            render_live_validation_summary(
                results.as_slice(),
                known_hosts_path.as_path(),
                0,
                0,
                0,
                findings_output.as_path(),
                schema_output.as_path(),
                promotion_output.as_path(),
            ),
        )?;
        return Ok(format!(
            "completed live-lab validation dry run under {}",
            report_dir.display()
        ));
    }

    if report_paths.is_empty() {
        write_summary(
            summary_output.as_path(),
            render_live_validation_summary(
                results.as_slice(),
                known_hosts_path.as_path(),
                1,
                1,
                1,
                findings_output.as_path(),
                schema_output.as_path(),
                promotion_output.as_path(),
            ),
        )?;
        return Err(format!(
            "live-lab validations produced no reports under {}",
            report_dir.display()
        ));
    }

    let schema_rc = match execute_ops_validate_live_lab_reports(ValidateLiveLabReportsConfig {
        reports: report_paths.clone(),
        report_dir: None,
        output: Some(schema_output.clone()),
    }) {
        Ok(_) => 0,
        Err(_) => 1,
    };
    let findings_rc = match execute_ops_generate_live_lab_findings(GenerateLiveLabFindingsConfig {
        reports: report_paths.clone(),
        report_dir: None,
        output: findings_output.clone(),
    }) {
        Ok(_) => 0,
        Err(_) => 1,
    };
    let promotion_rc =
        match execute_ops_evaluate_live_coverage_promotion(EvaluateLiveCoveragePromotionConfig {
            reports: report_paths.clone(),
            report_dir: None,
            targets: specs
                .iter()
                .map(|spec| spec.key)
                .collect::<Vec<_>>()
                .join(","),
            output: promotion_output.clone(),
        }) {
            Ok(_) => 0,
            Err(_) => 1,
        };
    write_summary(
        summary_output.as_path(),
        render_live_validation_summary(
            results.as_slice(),
            known_hosts_path.as_path(),
            schema_rc,
            findings_rc,
            promotion_rc,
            findings_output.as_path(),
            schema_output.as_path(),
            promotion_output.as_path(),
        ),
    )?;
    if results.iter().any(|result| result.rc != 0)
        || schema_rc != 0
        || findings_rc != 0
        || promotion_rc != 0
    {
        return Err(format!(
            "live-lab validations blocked; see {}",
            summary_output.display()
        ));
    }
    Ok(format!(
        "completed live-lab validations under {}",
        report_dir.display()
    ))
}

fn selected_validation_specs(
    raw: &str,
) -> Result<Vec<&'static crate::security_audit_catalog::ValidationSpec>, String> {
    if raw.trim().eq_ignore_ascii_case("all") {
        return Ok(sorted_validation_specs());
    }
    let keys = split_csv(raw);
    if keys.is_empty() {
        return Err("no validation keys supplied".to_string());
    }
    let mut specs = Vec::new();
    let mut unknown = Vec::new();
    for key in keys {
        if let Some(spec) = validation_spec_by_key(key.as_str()) {
            specs.push(spec);
        } else {
            unknown.push(key);
        }
    }
    if !unknown.is_empty() {
        return Err(format!("unknown validation keys: {}", unknown.join(", ")));
    }
    Ok(specs)
}

fn require_validation_args(
    specs: &[&crate::security_audit_catalog::ValidationSpec],
    config: &RunLiveLabValidationsConfig,
) -> Result<(), String> {
    let mut missing = Vec::new();
    for spec in specs {
        for arg in spec.required_args {
            if validation_arg_value(config, arg).is_none() {
                missing.push(format!("{}:{arg}", spec.key));
            }
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "missing required arguments for live validation run: {}",
            missing.join(", ")
        ))
    }
}

fn validation_arg_value<'a>(
    config: &'a RunLiveLabValidationsConfig,
    arg_name: &str,
) -> Option<&'a str> {
    match arg_name {
        "exit_host" => config.exit_host.as_deref(),
        "client_host" => config.client_host.as_deref(),
        "entry_host" => config.entry_host.as_deref(),
        "aux_host" => config.aux_host.as_deref(),
        "extra_host" => config.extra_host.as_deref(),
        "probe_host" => config.probe_host.as_deref(),
        "dns_bind_addr" => config.dns_bind_addr.as_deref(),
        "ssh_allow_cidrs" => config.ssh_allow_cidrs.as_deref(),
        "probe_port" => config.probe_port.as_deref(),
        "rogue_endpoint_ip" => config.rogue_endpoint_ip.as_deref(),
        "socket_path" => config.socket_path.as_deref(),
        "assignment_path" => config.assignment_path.as_deref(),
        _ => None,
    }
}

fn resolve_known_hosts_path(raw: Option<&Path>) -> Result<PathBuf, String> {
    if let Some(path) = raw {
        return resolve_path(path);
    }
    let default =
        PathBuf::from(env::var("HOME").map_err(|err| format!("resolve HOME failed: {err}"))?)
            .join(".ssh")
            .join("known_hosts");
    if default.is_file() {
        return resolve_path(default.as_path());
    }
    Err("a pinned SSH known_hosts file is required; pass --ssh-known-hosts-file".to_string())
}

fn run_preflight(config: &RunLiveLabValidationsConfig) -> Result<PathBuf, String> {
    for command in ["ssh", "expect", "ssh-keygen"] {
        require_command_available(command)?;
    }
    let known_hosts_path = resolve_known_hosts_path(config.ssh_known_hosts_file.as_deref())?;
    require_known_hosts_file(known_hosts_path.as_path())?;
    let targets = selected_targets(config);
    preflight_pinned_host_entries(targets.as_slice(), known_hosts_path.as_path())?;
    if config.skip_ssh_reachability_preflight {
        return Ok(known_hosts_path);
    }
    for target in &targets {
        ssh_reachability_check(
            target.as_str(),
            config.ssh_password_file.as_path(),
            known_hosts_path.as_path(),
            config.connect_timeout_secs,
        )?;
    }
    for target in &targets {
        remote_runtime_requirements_check(
            target.as_str(),
            config.ssh_password_file.as_path(),
            known_hosts_path.as_path(),
            config.connect_timeout_secs,
        )?;
    }
    Ok(known_hosts_path)
}

fn require_command_available(command: &str) -> Result<(), String> {
    if command_exists(command) {
        Ok(())
    } else {
        Err(format!(
            "missing required command for live-lab preflight: {command}"
        ))
    }
}

fn command_exists(command: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| {
        let candidate = dir.join(command);
        candidate.is_file()
    })
}

fn require_known_hosts_file(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "missing pinned SSH known_hosts file: {} ({err})",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "pinned SSH known_hosts file must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.is_file() {
        return Err(format!(
            "missing pinned SSH known_hosts file: {}",
            path.display()
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode() & 0o777;
        if mode & 0o022 != 0 {
            return Err(format!(
                "pinned SSH known_hosts file must not be group/world writable: {} ({mode:03o})",
                path.display()
            ));
        }
    }
    Ok(())
}

fn selected_targets(config: &RunLiveLabValidationsConfig) -> Vec<String> {
    let ordered = [
        config.exit_host.as_deref(),
        config.client_host.as_deref(),
        config.entry_host.as_deref(),
        config.aux_host.as_deref(),
        config.extra_host.as_deref(),
        config.probe_host.as_deref(),
    ];
    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for target in ordered.into_iter().flatten() {
        if seen.insert(target.to_string()) {
            deduped.push(target.to_string());
        }
    }
    deduped
}

fn preflight_pinned_host_entries(
    targets: &[String],
    known_hosts_path: &Path,
) -> Result<(), String> {
    let mut missing = Vec::new();
    for target in targets {
        let host = target_host(target.as_str());
        let output = Command::new("ssh-keygen")
            .arg("-F")
            .arg(host.as_str())
            .arg("-f")
            .arg(known_hosts_path)
            .output()
            .map_err(|err| format!("ssh-keygen -F {host} failed: {err}"))?;
        if !output.status.success() {
            missing.push(host);
        }
    }
    if missing.is_empty() {
        Ok(())
    } else {
        missing.sort();
        missing.dedup();
        Err(format!(
            "pinned known_hosts file lacks host keys for: {} ({})",
            missing.join(", "),
            known_hosts_path.display()
        ))
    }
}

fn target_host(target: &str) -> String {
    target
        .split_once('@')
        .map(|(_, host)| host)
        .unwrap_or(target)
        .to_string()
}

fn ssh_reachability_check(
    target: &str,
    password_file: &Path,
    known_hosts_path: &Path,
    connect_timeout_secs: u64,
) -> Result<(), String> {
    let output = run_expect_script(
        SSH_PREFLIGHT_EXPECT_SCRIPT,
        &[
            password_file.to_string_lossy().to_string(),
            known_hosts_path.to_string_lossy().to_string(),
            target.to_string(),
            connect_timeout_secs.to_string(),
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = non_empty_output(output.stderr, output.stdout)
            .unwrap_or_else(|| format!("SSH preflight failed for {target}"));
        Err(format!("SSH preflight failed for {target}: {detail}"))
    }
}

fn remote_runtime_requirements_check(
    target: &str,
    password_file: &Path,
    known_hosts_path: &Path,
    connect_timeout_secs: u64,
) -> Result<(), String> {
    let output = run_expect_script(
        SSH_CAPTURE_EXPECT_SCRIPT,
        &[
            password_file.to_string_lossy().to_string(),
            known_hosts_path.to_string_lossy().to_string(),
            target.to_string(),
            connect_timeout_secs.to_string(),
            REMOTE_RUNTIME_REQUIREMENTS_COMMAND.to_string(),
        ],
    )?;
    if output.status.success() {
        Ok(())
    } else {
        let detail = non_empty_output(output.stdout, output.stderr)
            .unwrap_or_else(|| "missing remote prerequisite".to_string());
        Err(format!(
            "remote prerequisite preflight failed for {target}: {detail}"
        ))
    }
}

fn run_expect_script(script: &str, args: &[String]) -> Result<std::process::Output, String> {
    Command::new("expect")
        .arg("-c")
        .arg(script)
        .args(args)
        .output()
        .map_err(|err| format!("expect invocation failed: {err}"))
}

fn build_validation_command(
    spec: &crate::security_audit_catalog::ValidationSpec,
    config: &RunLiveLabValidationsConfig,
    repo_root: &Path,
    report_dir: &Path,
) -> Result<(Vec<String>, PathBuf), String> {
    let script_path = repo_root.join(spec.script_path);
    if !script_path.is_file() {
        return Err(format!(
            "validation script missing: {}",
            script_path.display()
        ));
    }
    let report_path = report_dir.join(spec.default_report_name);
    let log_path = report_dir.join(spec.default_report_name.replace(".json", ".log"));
    let mut command = vec![
        script_path.display().to_string(),
        "--ssh-password-file".to_string(),
        resolve_path(config.ssh_password_file.as_path())?
            .display()
            .to_string(),
        "--sudo-password-file".to_string(),
        resolve_path(config.sudo_password_file.as_path())?
            .display()
            .to_string(),
        "--report-path".to_string(),
        report_path.display().to_string(),
        "--log-path".to_string(),
        log_path.display().to_string(),
    ];
    for arg_name in spec.supported_args {
        if let Some(value) = validation_arg_value(config, arg_name)
            && let Some(flag) = validation_arg_flag(arg_name)
        {
            command.push(flag.to_string());
            command.push(value.to_string());
        }
    }
    Ok((command, report_path))
}

fn run_validation(
    validation_key: &str,
    command: Vec<String>,
    report_path: PathBuf,
    cwd: &Path,
    known_hosts_path: &Path,
) -> Result<ValidationRunResult, String> {
    let mut child_env = env::vars_os().collect::<HashMap<_, _>>();
    child_env.insert(
        "LIVE_LAB_PINNED_KNOWN_HOSTS_FILE".into(),
        known_hosts_path.as_os_str().to_os_string(),
    );
    let output = Command::new(
        command
            .first()
            .ok_or_else(|| "empty validation command".to_string())?,
    )
    .args(&command[1..])
    .current_dir(cwd)
    .envs(child_env)
    .output()
    .map_err(|err| format!("run validation {validation_key} failed: {err}"))?;
    Ok(ValidationRunResult {
        validation_key: validation_key.to_string(),
        command,
        rc: output.status.code().unwrap_or(1),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        report_path,
    })
}

fn render_live_validation_summary(
    results: &[ValidationRunResult],
    known_hosts_path: &Path,
    schema_rc: i32,
    findings_rc: i32,
    promotion_rc: i32,
    findings_output: &Path,
    schema_output: &Path,
    promotion_output: &Path,
) -> String {
    let mut lines = vec![
        "# Rustynet Live-Lab Validation Run".to_string(),
        "".to_string(),
        "## Validator Commands".to_string(),
        "".to_string(),
        "| Validation | Exit Code | Report Path |".to_string(),
        "| --- | --- | --- |".to_string(),
    ];
    for result in results {
        lines.push(format!(
            "| {} | {} | `{}` |",
            result.validation_key,
            result.rc,
            result.report_path.display()
        ));
    }
    lines.extend([
        "".to_string(),
        "## Consolidated Outputs".to_string(),
        "".to_string(),
        format!(
            "- Pinned SSH known_hosts file: `{}`",
            known_hosts_path.display()
        ),
        format!("- Findings report: `{}`", findings_output.display()),
        format!("- Findings generation exit code: `{findings_rc}`"),
        format!("- Schema validation report: `{}`", schema_output.display()),
        format!("- Schema validation exit code: `{schema_rc}`"),
        format!(
            "- Coverage promotion report: `{}`",
            promotion_output.display()
        ),
        format!("- Coverage promotion exit code: `{promotion_rc}`"),
        "".to_string(),
    ]);
    for result in results {
        lines.extend([
            format!("### {}", result.validation_key),
            "".to_string(),
            format!("- Command: `{}`", result.command.join(" ")),
            format!("- Exit code: `{}`", result.rc),
            "- stderr:".to_string(),
            "```text".to_string(),
            if result.stderr.is_empty() {
                "[no stderr]".to_string()
            } else {
                result.stderr.clone()
            },
            "```".to_string(),
            "".to_string(),
        ]);
    }
    lines.join("\n")
}

fn write_placeholder_file(path: &Path, body: &str) -> Result<(), String> {
    ensure_parent_dir(path)?;
    fs::write(path, body).map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn write_summary(path: &Path, body: String) -> Result<(), String> {
    ensure_parent_dir(path)?;
    fs::write(path, body).map_err(|err| format!("write {} failed: {err}", path.display()))
}

fn collect_report_paths(
    reports: &[PathBuf],
    report_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for path in reports {
        paths.push(resolve_path(path.as_path())?);
    }
    if let Some(report_dir) = report_dir {
        collect_json_files(resolve_path(report_dir)?.as_path(), &mut paths)?;
    }
    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    if deduped.is_empty() {
        return Err("no report files supplied".to_string());
    }
    Ok(deduped)
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata =
        fs::metadata(dir).map_err(|err| format!("read {} failed: {err}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut entries = fs::read_dir(dir)
        .map_err(|err| format!("read {} failed: {err}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read {} failed: {err}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("inspect {} failed: {err}", path.display()))?;
        if file_type.is_dir() {
            collect_json_files(path.as_path(), out)?;
        } else if file_type.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn derive_findings(
    report_path: &Path,
    payload: &serde_json::Map<String, Value>,
) -> (Vec<Finding>, Vec<PassingCheck>) {
    let mut findings = Vec::new();
    let mut passes = Vec::new();
    let mode = payload.get("mode").and_then(Value::as_str);
    let status = payload
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let checks = payload.get("checks").and_then(Value::as_object);
    let Some(spec) = mode.and_then(validation_spec_by_mode) else {
        if status != STATUS_PASS {
            findings.push(Finding {
                severity: "high".to_string(),
                title: format!("Unknown report mode failed: {}", mode.unwrap_or("[missing]")),
                exploit_family: "unknown".to_string(),
                mode_title: mode.unwrap_or("[missing]").to_string(),
                report_path: report_path.display().to_string(),
                check_name: "[mode]".to_string(),
                rationale: "The live-lab report failed, but the skill does not yet know how to map this mode into enforcement points.".to_string(),
                affected_files: Vec::new(),
                evidence_summary: summarize_evidence(payload, 600),
            });
        }
        return (findings, passes);
    };

    let Some(checks) = checks else {
        findings.push(Finding {
            severity: "high".to_string(),
            title: format!("{} report schema invalid", spec.title),
            exploit_family: spec.exploit_family.to_string(),
            mode_title: spec.title.to_string(),
            report_path: report_path.display().to_string(),
            check_name: "[schema]".to_string(),
            rationale: "The report did not contain a usable checks object, so the live result cannot be trusted.".to_string(),
            affected_files: spec
                .affected_files
                .iter()
                .map(|path| (*path).to_string())
                .collect(),
            evidence_summary: summarize_evidence(payload, 600),
        });
        return (findings, passes);
    };

    for (check_name, value) in checks {
        match value.as_str() {
            Some(CHECK_PASS) => {
                passes.push(PassingCheck {
                    mode_title: spec.title.to_string(),
                    check_name: check_name.clone(),
                    report_path: report_path.display().to_string(),
                });
            }
            Some(CHECK_SKIP | CHECK_SKIPPED) => {
                findings.push(make_finding(
                    "medium",
                    format!("{} check skipped: {check_name}", spec.title),
                    "A skipped adversarial check leaves the corresponding exploit class unvalidated on the live lab.".to_string(),
                    spec,
                    report_path,
                    payload,
                    check_name,
                ));
            }
            _ => {
                let metadata = validation_check_metadata(spec, check_name)
                    .copied()
                    .unwrap_or(CheckMetadata {
                        severity: "high",
                        title: "",
                        rationale: "",
                    });
                let title = if metadata.title.is_empty() {
                    format!("{}: {check_name}", spec.unknown_failure_title)
                } else {
                    metadata.title.to_string()
                };
                let rationale = if metadata.rationale.is_empty() {
                    "A live-lab check failed and needs manual review because the skill does not yet have a more specific mapping for it.".to_string()
                } else {
                    metadata.rationale.to_string()
                };
                let severity = if metadata.severity.is_empty() {
                    "high"
                } else {
                    metadata.severity
                };
                findings.push(make_finding(
                    severity,
                    title,
                    rationale,
                    spec,
                    report_path,
                    payload,
                    check_name,
                ));
            }
        }
    }

    if status != STATUS_PASS && findings.is_empty() {
        findings.push(make_finding(
            "high",
            spec.unknown_failure_title.to_string(),
            "The report status failed even though no individual failed checks were extracted."
                .to_string(),
            spec,
            report_path,
            payload,
            "[status]",
        ));
    }
    (findings, passes)
}

fn make_finding(
    severity: &str,
    title: String,
    rationale: String,
    spec: &crate::security_audit_catalog::ValidationSpec,
    report_path: &Path,
    payload: &serde_json::Map<String, Value>,
    check_name: &str,
) -> Finding {
    Finding {
        severity: severity.to_string(),
        title,
        exploit_family: spec.exploit_family.to_string(),
        mode_title: spec.title.to_string(),
        report_path: report_path.display().to_string(),
        check_name: check_name.to_string(),
        rationale,
        affected_files: spec
            .affected_files
            .iter()
            .map(|path| (*path).to_string())
            .collect(),
        evidence_summary: summarize_evidence(payload, 600),
    }
}

fn validate_findings_report_schema(
    path: &Path,
    payload: &serde_json::Map<String, Value>,
) -> Vec<String> {
    let mut problems = Vec::new();
    for key in ["mode", "status", "checks", "evidence_mode"] {
        if !payload.contains_key(key) {
            problems.push(format!(
                "{}: missing required field '{}'",
                path.display(),
                key
            ));
        }
    }
    if payload.get("mode").is_some() && payload.get("mode").and_then(Value::as_str).is_none() {
        problems.push(format!("{}: field 'mode' must be a string", path.display()));
    }
    if payload.get("status").is_some() && payload.get("status").and_then(Value::as_str).is_none() {
        problems.push(format!(
            "{}: field 'status' must be a string",
            path.display()
        ));
    }
    if payload.get("checks").is_some() && payload.get("checks").and_then(Value::as_object).is_none()
    {
        problems.push(format!(
            "{}: field 'checks' must be an object",
            path.display()
        ));
    }
    if payload.get("evidence_mode").and_then(Value::as_str) != Some(EVIDENCE_MODE_MEASURED) {
        problems.push(format!(
            "{}: field 'evidence_mode' must be '{}'",
            path.display(),
            EVIDENCE_MODE_MEASURED
        ));
    }
    problems
}

fn render_findings_markdown(
    findings: &[Finding],
    passes: &[PassingCheck],
    schema_problems: &[String],
    analyzed_reports: &[PathBuf],
) -> String {
    let mut ordered_findings = findings.to_vec();
    ordered_findings.sort_by_key(|finding| {
        (
            severity_order(finding.severity.as_str()),
            finding.mode_title.clone(),
            finding.title.clone(),
        )
    });
    let mut lines = vec![
        "# Rustynet Live-Lab Security Findings".to_string(),
        "".to_string(),
        format!("Generated: {}", utc_timestamp()),
        "".to_string(),
        "## Summary".to_string(),
        "".to_string(),
        format!("- Reports analyzed: {}", analyzed_reports.len()),
        format!("- Findings: {}", ordered_findings.len()),
        format!("- Passing checks recorded: {}", passes.len()),
        format!("- Schema problems: {}", schema_problems.len()),
        "".to_string(),
        "## Reports".to_string(),
        "".to_string(),
    ];
    for report in analyzed_reports {
        lines.push(format!("- `{}`", report.display()));
    }
    lines.push(String::new());
    if ordered_findings.is_empty() {
        lines.extend([
            "## Findings".to_string(),
            "".to_string(),
            "No failing or skipped checks were found in the supplied reports.".to_string(),
            "".to_string(),
        ]);
    } else {
        lines.extend(["## Findings".to_string(), "".to_string()]);
        for finding in &ordered_findings {
            lines.extend([
                format!(
                    "### [{}] {}",
                    finding.severity.to_uppercase(),
                    finding.title
                ),
                "".to_string(),
                format!("- Exploit family: `{}`", finding.exploit_family),
                format!("- Validation mode: {}", finding.mode_title),
                format!("- Report: `{}`", finding.report_path),
                format!("- Failing check: `{}`", finding.check_name),
                format!("- Why it matters: {}", finding.rationale),
                format!(
                    "- Likely affected files: {}",
                    if finding.affected_files.is_empty() {
                        "[unknown]".to_string()
                    } else {
                        finding
                            .affected_files
                            .iter()
                            .map(|path| format!("`{path}`"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                ),
                format!("- Evidence summary: {}", finding.evidence_summary),
                "".to_string(),
            ]);
        }
    }
    if !schema_problems.is_empty() {
        lines.extend(["## Schema Problems".to_string(), "".to_string()]);
        for problem in schema_problems {
            lines.push(format!("- {problem}"));
        }
        lines.push(String::new());
    }
    lines.extend(["## Passing Checks".to_string(), "".to_string()]);
    if passes.is_empty() {
        lines.push("No passing checks were recorded.".to_string());
    } else {
        let mut ordered_passes = passes.to_vec();
        ordered_passes.sort_by_key(|passed| (passed.mode_title.clone(), passed.check_name.clone()));
        for passed in ordered_passes {
            lines.push(format!(
                "- {}: `{}` in `{}`",
                passed.mode_title, passed.check_name, passed.report_path
            ));
        }
    }
    lines.extend([
        "".to_string(),
        "## Next Actions".to_string(),
        "".to_string(),
        "1. Fix every `critical` finding before treating the corresponding exploit class as covered.".to_string(),
        "2. Re-run the specific live validation report after each fix; do not rely on adjacent unit tests alone.".to_string(),
        "3. If a report had schema problems, repair the reporting path before trusting any pass/fail outcome from that validator.".to_string(),
        "".to_string(),
    ]);
    lines.join("\n")
}

fn severity_order(severity: &str) -> usize {
    match severity {
        "critical" => 0,
        "high" => 1,
        "medium" => 2,
        "low" => 3,
        _ => usize::MAX,
    }
}

fn summarize_evidence(payload: &serde_json::Map<String, Value>, limit: usize) -> String {
    let Some(evidence) = payload.get("evidence").and_then(Value::as_object) else {
        return "[no structured evidence present]".to_string();
    };
    if evidence.is_empty() {
        return "[no structured evidence present]".to_string();
    }
    let mut keys = evidence.keys().cloned().collect::<Vec<_>>();
    keys.sort();
    let mut parts = Vec::new();
    for key in keys {
        let mut rendered = stringify_json_value(evidence.get(key.as_str()).unwrap_or(&Value::Null));
        if rendered.len() > 160 {
            rendered.truncate(160);
            rendered.push_str("...");
        }
        parts.push(format!("{key}={rendered}"));
    }
    let mut summary = parts.join("; ");
    if summary.len() > limit {
        summary.truncate(limit);
        summary.push_str("...");
    }
    summary
}

fn stringify_json_value(value: &Value) -> String {
    match value {
        Value::String(text) => text.trim().to_string(),
        other => {
            serde_json::to_string(other).unwrap_or_else(|_| "\"[unserializable]\"".to_string())
        }
    }
}

fn parse_optional_filter(raw: &str) -> Result<Option<HashSet<String>>, String> {
    if raw.trim().eq_ignore_ascii_case("all") {
        return Ok(None);
    }
    let values = split_csv(raw)
        .into_iter()
        .map(|item| item.to_lowercase())
        .collect::<HashSet<_>>();
    if values.is_empty() {
        return Err("empty filter supplied".to_string());
    }
    Ok(Some(values))
}

fn select_comparative_entries(
    projects: Option<HashSet<String>>,
    families: Option<HashSet<String>>,
) -> Result<Vec<&'static ComparativeCatalogEntry>, String> {
    let mut entries = Vec::new();
    for entry in COMPARATIVE_CATALOG {
        if let Some(projects) = &projects
            && !projects.contains(&entry.project.to_lowercase())
        {
            continue;
        }
        if let Some(families) = &families
            && !families.contains(&entry.attack_family.to_lowercase())
        {
            continue;
        }
        entries.push(entry);
    }
    if entries.is_empty() {
        Err("no entries matched the selected filters".to_string())
    } else {
        Ok(entries)
    }
}

fn collect_comparative_command_keys(entries: &[&ComparativeCatalogEntry]) -> Vec<&'static str> {
    let mut ordered = Vec::new();
    let mut seen = HashSet::new();
    for entry in entries {
        for key in entry.command_keys {
            if seen.insert(*key) {
                ordered.push(*key);
            }
        }
    }
    ordered
}

fn run_comparative_commands(
    workspace: &Path,
    command_keys: Vec<&'static str>,
    max_output_chars: usize,
) -> Result<Vec<ComparativeCommandResult>, String> {
    let mut results = Vec::new();
    for key in command_keys {
        let spec = comparative_command_spec(key)
            .ok_or_else(|| format!("missing comparative command spec: {key}"))?;
        let output = Command::new(spec.argv[0])
            .args(&spec.argv[1..])
            .current_dir(workspace)
            .output()
            .map_err(|err| format!("run comparative command {key} failed: {err}"))?;
        let mut combined = String::from_utf8_lossy(&output.stdout).to_string();
        if !output.stderr.is_empty() {
            if !combined.is_empty() {
                combined.push('\n');
            }
            combined.push_str(String::from_utf8_lossy(&output.stderr).as_ref());
        }
        let combined = truncate_output(combined.trim().to_string(), max_output_chars);
        let rc = output.status.code().unwrap_or(1);
        results.push(ComparativeCommandResult {
            key: key.to_string(),
            label: spec.label.to_string(),
            argv: spec.argv.iter().map(|value| (*value).to_string()).collect(),
            rc,
            status: if rc == 0 { "pass" } else { "fail" }.to_string(),
            output: combined,
        });
    }
    Ok(results)
}

fn truncate_output(mut text: String, limit: usize) -> String {
    if text.len() > limit {
        text.truncate(limit);
        text.push_str("\n...[truncated]");
    }
    text
}

fn render_comparative_markdown(
    entries: &[&ComparativeCatalogEntry],
    command_results: Option<&[ComparativeCommandResult]>,
) -> String {
    let counts = comparative_status_counts(entries);
    let mut sorted_entries = entries.to_vec();
    sorted_entries.sort_by_key(|entry| {
        (
            comparative_status_order(entry.coverage_status),
            entry.project,
            entry.incident,
        )
    });
    let mut lines = vec![
        "# Rustynet Comparative VPN Exploit Coverage".to_string(),
        "".to_string(),
        "## Summary".to_string(),
        "".to_string(),
        format!("- Covered: {}", counts.get("covered").copied().unwrap_or(0)),
        format!(
            "- Partially covered: {}",
            counts.get("partially_covered").copied().unwrap_or(0)
        ),
        format!(
            "- Architecturally not applicable: {}",
            counts
                .get("architecturally_not_applicable")
                .copied()
                .unwrap_or(0)
        ),
        format!(
            "- Future surface gaps: {}",
            counts.get("future_surface_gap").copied().unwrap_or(0)
        ),
        "".to_string(),
        "## Comparative Incident Matrix".to_string(),
        "".to_string(),
        "| Project | Incident | Exploit Class | Rustynet Analog | Status | Sources |".to_string(),
        "| --- | --- | --- | --- | --- | --- |".to_string(),
    ];
    for entry in &sorted_entries {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            entry.project,
            entry.incident,
            entry.exploit_class,
            entry.rustynet_analog,
            entry.coverage_status,
            entry.sources.join(", ")
        ));
    }
    lines.extend([
        "".to_string(),
        "## Detailed Mapping".to_string(),
        "".to_string(),
    ]);
    for entry in entries {
        lines.extend([
            format!(
                "### {} {}: {}",
                entry.project, entry.incident, entry.exploit_class
            ),
            "".to_string(),
            format!("- Attack family: `{}`", entry.attack_family),
            format!("- Historical issue: {}", entry.summary),
            format!("- Rustynet analog: {}", entry.rustynet_analog),
            format!("- Coverage status: `{}`", entry.coverage_status),
            format!("- Expected secure result: {}", entry.expected_secure_result),
            "- Local verification commands:".to_string(),
        ]);
        for key in entry.command_keys {
            if let Some(spec) = comparative_command_spec(key) {
                lines.push(format!("  - `{}`", spec.argv.join(" ")));
            }
        }
        if !entry.live_validation_scripts.is_empty() {
            lines.push("- Live validation scripts:".to_string());
            for script in entry.live_validation_scripts {
                lines.push(format!("  - `{}`", script));
            }
        }
        lines.push(format!("- Primary sources: {}", entry.sources.join(", ")));
        lines.push(String::new());
    }
    if let Some(command_results) = command_results {
        lines.extend([
            "## Local Verification Results".to_string(),
            "".to_string(),
            "| Command | Result | Exit Code |".to_string(),
            "| --- | --- | --- |".to_string(),
        ]);
        for result in command_results {
            lines.push(format!(
                "| {} | {} | {} |",
                result.argv.join(" "),
                result.status,
                result.rc
            ));
        }
        lines.push(String::new());
        for result in command_results {
            lines.extend([
                format!("### Command Result: {}", result.label),
                "".to_string(),
                format!("- Command: `{}`", result.argv.join(" ")),
                format!("- Result: `{}`", result.status),
                format!("- Exit code: `{}`", result.rc),
                "- Output:".to_string(),
                "```text".to_string(),
                if result.output.is_empty() {
                    "[no output]".to_string()
                } else {
                    result.output.clone()
                },
                "```".to_string(),
                "".to_string(),
            ]);
        }
    }
    lines.extend([
        "## Immediate Priorities".to_string(),
        "".to_string(),
        "1. Keep all `future_surface_gap` items blocked into design before the comparable feature ships.".to_string(),
        "2. Run the listed live validation scripts for every `partially_covered` item on an authorized lab before treating coverage as strong.".to_string(),
        "3. Re-run the mapped local commands whenever the corresponding trust boundary changes.".to_string(),
        "".to_string(),
    ]);
    lines.join("\n")
}

fn render_comparative_json(
    entries: &[&ComparativeCatalogEntry],
    command_results: Option<&[ComparativeCommandResult]>,
) -> Result<String, String> {
    let payload = json!({
        "entries": entries.iter().map(|entry| json!({
            "project": entry.project,
            "incident": entry.incident,
            "date": entry.date,
            "exploit_class": entry.exploit_class,
            "summary": entry.summary,
            "rustynet_analog": entry.rustynet_analog,
            "attack_family": entry.attack_family,
            "coverage_status": entry.coverage_status,
            "command_keys": entry.command_keys,
            "live_validation_scripts": entry.live_validation_scripts,
            "expected_secure_result": entry.expected_secure_result,
            "sources": entry.sources,
        })).collect::<Vec<_>>(),
        "command_results": command_results.map(|results| results.iter().map(|result| json!({
            "key": result.key,
            "label": result.label,
            "argv": result.argv,
            "rc": result.rc,
            "status": result.status,
            "output": result.output,
        })).collect::<Vec<_>>()),
        "status_counts": comparative_status_counts(entries),
    });
    serde_json::to_string_pretty(&payload)
        .map(|text| text + "\n")
        .map_err(|err| format!("encode comparative coverage json failed: {err}"))
}

fn comparative_status_counts(entries: &[&ComparativeCatalogEntry]) -> HashMap<&'static str, usize> {
    let mut counts = HashMap::from([
        ("covered", 0usize),
        ("partially_covered", 0usize),
        ("architecturally_not_applicable", 0usize),
        ("future_surface_gap", 0usize),
    ]);
    for entry in entries {
        *counts.entry(entry.coverage_status).or_insert(0) += 1;
    }
    counts
}

fn split_csv(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
        .map(ToOwned::to_owned)
        .collect()
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|err| format!("create {} failed: {err}", parent.display()))
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        let cwd =
            env::current_dir().map_err(|err| format!("resolve current directory failed: {err}"))?;
        Ok(cwd.join(path))
    }
}

fn load_json_object(path: &Path) -> Result<serde_json::Map<String, Value>, String> {
    let value = load_json_value(path)?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("report must be a JSON object: {}", path.display()))
}

fn load_json_value(path: &Path) -> Result<Value, String> {
    let body =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    serde_json::from_str(&body).map_err(|err| format!("parse {} failed: {err}", path.display()))
}

fn non_empty_output(primary: Vec<u8>, secondary: Vec<u8>) -> Option<String> {
    let primary = String::from_utf8_lossy(&primary).trim().to_string();
    if !primary.is_empty() {
        return Some(primary);
    }
    let secondary = String::from_utf8_lossy(&secondary).trim().to_string();
    if !secondary.is_empty() {
        Some(secondary)
    } else {
        None
    }
}

fn timestamp_for_path() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

fn utc_timestamp() -> String {
    let output = Command::new("date")
        .arg("-u")
        .arg("+%Y-%m-%d %H:%M:%SZ")
        .output();
    match output {
        Ok(output) if output.status.success() => {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() {
                "[unknown]".to_string()
            } else {
                text
            }
        }
        _ => "[unknown]".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(prefix: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let path = env::temp_dir().join(format!(
            "rustynet-security-audit-workflows-{prefix}-{unique}"
        ));
        fs::create_dir_all(path.as_path()).expect("create temp dir");
        path
    }

    fn valid_report_payload() -> Value {
        json!({
            "phase": "phase10",
            "mode": "live_linux_control_surface_exposure",
            "evidence_mode": "measured",
            "captured_at": "2026-04-17 12:00:00Z",
            "captured_at_unix": 1713355200u64,
            "status": "fail",
            "checks": {
                "all_daemon_sockets_secure": "fail",
                "all_helper_sockets_secure": "pass",
                "no_rustynet_tcp_listeners": "pass",
                "rustynet_udp_loopback_only": "pass",
                "remote_underlay_dns_probe_blocked": "pass"
            },
            "hosts": ["client-1"],
            "evidence": {
                "socket_path": "/run/rustynet/daemon.sock"
            },
            "dns_bind_addr": "127.0.0.1:53"
        })
    }

    fn write_json(path: &Path, payload: Value) {
        fs::write(
            path,
            serde_json::to_string_pretty(&payload).expect("encode"),
        )
        .expect("write json");
    }

    #[test]
    fn generate_live_lab_findings_writes_expected_title() {
        let temp = temp_dir("findings");
        let report = temp.join("report.json");
        write_json(report.as_path(), valid_report_payload());
        let output = temp.join("findings.md");
        execute_ops_generate_live_lab_findings(GenerateLiveLabFindingsConfig {
            reports: vec![report],
            report_dir: None,
            output: output.clone(),
        })
        .expect("generate findings");
        let body = fs::read_to_string(output).expect("read findings");
        assert!(body.contains("Daemon socket custody weakened"));
    }

    #[test]
    fn comparative_generation_filters_and_writes_markdown() {
        let temp = temp_dir("comparative");
        let output = temp.join("coverage.md");
        execute_ops_generate_comparative_exploit_coverage(
            GenerateComparativeExploitCoverageConfig {
                workspace: PathBuf::from("."),
                output: output.clone(),
                format: "md".to_string(),
                projects: "tailscale".to_string(),
                attack_families: "local-socket-spoofing".to_string(),
                run_local_tests: false,
                max_output_chars: 1200,
            },
        )
        .expect("generate comparative coverage");
        let body = fs::read_to_string(output).expect("read coverage");
        assert!(body.contains("TS-2022-004"));
        assert!(!body.contains("TunnelCrack"));
    }

    #[test]
    fn build_validation_command_includes_supported_args() {
        let config = RunLiveLabValidationsConfig {
            repo_root: PathBuf::from("."),
            ssh_password_file: PathBuf::from("/tmp/ssh.pass"),
            sudo_password_file: PathBuf::from("/tmp/sudo.pass"),
            ssh_known_hosts_file: Some(PathBuf::from("/tmp/known_hosts")),
            validations: "control_surface_exposure".to_string(),
            report_dir: Some(PathBuf::from("/tmp/reports")),
            findings_output: None,
            schema_output: None,
            promotion_output: None,
            summary_output: None,
            dry_run: true,
            skip_ssh_reachability_preflight: true,
            exit_host: None,
            client_host: Some("debian@192.0.2.10".to_string()),
            entry_host: None,
            aux_host: None,
            extra_host: None,
            probe_host: None,
            dns_bind_addr: Some("127.0.0.1:53".to_string()),
            ssh_allow_cidrs: None,
            probe_port: None,
            rogue_endpoint_ip: None,
            socket_path: None,
            assignment_path: None,
            connect_timeout_secs: 15,
        };
        let spec = validation_spec_by_key("control_surface_exposure").expect("spec");
        let temp = temp_dir("runner");
        let script_dir = temp.join("scripts").join("e2e");
        fs::create_dir_all(script_dir.as_path()).expect("script dir");
        fs::write(
            script_dir.join("live_linux_control_surface_exposure_test.sh"),
            "#!/bin/sh\nexit 0\n",
        )
        .expect("write script");
        let (command, _) =
            build_validation_command(spec, &config, temp.as_path(), temp.join("out").as_path())
                .expect("build command");
        assert!(command.contains(&"--client-host".to_string()));
        assert!(command.contains(&"debian@192.0.2.10".to_string()));
        assert!(command.contains(&"--dns-bind-addr".to_string()));
    }

    #[test]
    fn selected_validation_specs_reject_unknown_keys() {
        let err = selected_validation_specs("not-real").expect_err("must fail");
        assert!(err.contains("unknown validation keys"));
    }

    #[test]
    fn require_validation_args_reports_missing_fields() {
        let config = RunLiveLabValidationsConfig {
            repo_root: PathBuf::from("."),
            ssh_password_file: PathBuf::from("/tmp/ssh.pass"),
            sudo_password_file: PathBuf::from("/tmp/sudo.pass"),
            ssh_known_hosts_file: Some(PathBuf::from("/tmp/known_hosts")),
            validations: "server_ip_bypass".to_string(),
            report_dir: None,
            findings_output: None,
            schema_output: None,
            promotion_output: None,
            summary_output: None,
            dry_run: true,
            skip_ssh_reachability_preflight: true,
            exit_host: None,
            client_host: None,
            entry_host: None,
            aux_host: None,
            extra_host: None,
            probe_host: None,
            dns_bind_addr: None,
            ssh_allow_cidrs: None,
            probe_port: None,
            rogue_endpoint_ip: None,
            socket_path: None,
            assignment_path: None,
            connect_timeout_secs: 15,
        };
        let specs = selected_validation_specs("server_ip_bypass").expect("specs");
        let err = require_validation_args(specs.as_slice(), &config).expect_err("must fail");
        assert!(err.contains("server_ip_bypass:client_host"));
        assert!(err.contains("server_ip_bypass:probe_host"));
    }
}
