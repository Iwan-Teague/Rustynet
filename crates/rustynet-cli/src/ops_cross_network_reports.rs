#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

const CHECK_PASS: &str = "pass";
const CHECK_FAIL: &str = "fail";
const DEFAULT_MAX_EVIDENCE_AGE_SECONDS: u64 = 2_678_400;
const DEFAULT_ARTIFACT_DIR: &str = "artifacts/phase10";
const SCHEMA_VERSION: i64 = 1;
const PHASE_NAME: &str = "phase10";
const EVIDENCE_MODE: &str = "measured";

#[derive(Clone, Copy)]
struct CrossNetworkReportSpec {
    filename: &'static str,
    suite: &'static str,
    title: &'static str,
    required_participants: &'static [&'static str],
    required_network_fields: &'static [&'static str],
    required_checks: &'static [&'static str],
}

const REPORT_SPECS: &[CrossNetworkReportSpec] = &[
    CrossNetworkReportSpec {
        filename: "cross_network_direct_remote_exit_report.json",
        suite: "cross_network_direct_remote_exit",
        title: "Cross-Network Direct Remote Exit",
        required_participants: &["client_host", "exit_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "direct_remote_exit_success",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
        ],
    },
    CrossNetworkReportSpec {
        filename: "cross_network_relay_remote_exit_report.json",
        suite: "cross_network_relay_remote_exit",
        title: "Cross-Network Relay Remote Exit",
        required_participants: &["client_host", "exit_host", "relay_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "relay_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "relay_remote_exit_success",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
        ],
    },
    CrossNetworkReportSpec {
        filename: "cross_network_failback_roaming_report.json",
        suite: "cross_network_failback_roaming",
        title: "Cross-Network Failback and Roaming",
        required_participants: &["client_host", "exit_host", "relay_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "relay_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "relay_to_direct_failback_success",
            "endpoint_roam_recovery_success",
            "remote_exit_no_underlay_leak",
        ],
    },
    CrossNetworkReportSpec {
        filename: "cross_network_traversal_adversarial_report.json",
        suite: "cross_network_traversal_adversarial",
        title: "Cross-Network Traversal Adversarial",
        required_participants: &["client_host", "exit_host", "probe_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "forged_traversal_rejected",
            "stale_traversal_rejected",
            "replayed_traversal_rejected",
            "rogue_endpoint_rejected",
            "control_surface_exposure_blocked",
        ],
    },
    CrossNetworkReportSpec {
        filename: "cross_network_remote_exit_dns_report.json",
        suite: "cross_network_remote_exit_dns",
        title: "Cross-Network Remote Exit DNS",
        required_participants: &["client_host", "exit_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "managed_dns_resolution_success",
            "remote_exit_dns_fail_closed",
            "remote_exit_no_underlay_leak",
        ],
    },
    CrossNetworkReportSpec {
        filename: "cross_network_remote_exit_soak_report.json",
        suite: "cross_network_remote_exit_soak",
        title: "Cross-Network Remote Exit Soak",
        required_participants: &["client_host", "exit_host"],
        required_network_fields: &[
            "client_network_id",
            "exit_network_id",
            "nat_profile",
            "impairment_profile",
        ],
        required_checks: &[
            "long_soak_stable",
            "remote_exit_no_underlay_leak",
            "remote_exit_server_ip_bypass_is_narrow",
            "cross_network_topology_heuristic",
            "direct_remote_exit_ready",
            "post_soak_bypass_ready",
            "no_plaintext_passphrase_files",
        ],
    },
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateCrossNetworkRemoteExitReportConfig {
    pub suite: String,
    pub report_path: PathBuf,
    pub log_path: PathBuf,
    pub status: String,
    pub failure_summary: String,
    pub environment: String,
    pub implementation_state: String,
    pub source_artifacts: Vec<PathBuf>,
    pub log_artifacts: Vec<PathBuf>,
    pub client_host: Option<String>,
    pub exit_host: Option<String>,
    pub relay_host: Option<String>,
    pub probe_host: Option<String>,
    pub client_network_id: Option<String>,
    pub exit_network_id: Option<String>,
    pub relay_network_id: Option<String>,
    pub nat_profile: String,
    pub impairment_profile: String,
    pub check_overrides: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateCrossNetworkRemoteExitReportsConfig {
    pub reports: Vec<PathBuf>,
    pub artifact_dir: Option<PathBuf>,
    pub output: Option<PathBuf>,
    pub max_evidence_age_seconds: u64,
    pub expected_git_commit: Option<String>,
    pub require_pass_status: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateCrossNetworkNatMatrixConfig {
    pub reports: Vec<PathBuf>,
    pub artifact_dir: Option<PathBuf>,
    pub required_nat_profiles: Vec<String>,
    pub max_evidence_age_seconds: u64,
    pub expected_git_commit: Option<String>,
    pub require_pass_status: bool,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadCrossNetworkReportFieldsConfig {
    pub report_path: PathBuf,
    pub include_status: bool,
    pub checks: Vec<String>,
    pub network_fields: Vec<String>,
    pub default_value: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifyCrossNetworkTopologyConfig {
    pub ip_a: String,
    pub ip_b: String,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChooseCrossNetworkRoamAliasConfig {
    pub exit_ip: String,
    pub used_ips: Vec<String>,
    pub ipv4_prefix: u8,
    pub ipv6_prefix: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateIpv4AddressConfig {
    pub ip: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteCrossNetworkSoakMonitorSummaryConfig {
    pub path: PathBuf,
    pub samples: u64,
    pub failing_samples: u64,
    pub max_consecutive_failures_observed: u64,
    pub elapsed_secs: u64,
    pub required_soak_duration_secs: u64,
    pub allowed_failing_samples: u64,
    pub allowed_max_consecutive_failures: u64,
    pub direct_remote_exit_ready: String,
    pub post_soak_bypass_ready: String,
    pub no_plaintext_passphrase_files: String,
    pub first_failure_reason: String,
    pub long_soak_stable: String,
}

struct ReportRecord {
    path: PathBuf,
    suite: String,
    nat_profile: String,
    impairment_profile: String,
    status: String,
}

fn report_spec_by_suite(suite: &str) -> Option<&'static CrossNetworkReportSpec> {
    REPORT_SPECS.iter().find(|spec| spec.suite == suite)
}

fn report_spec_by_filename(filename: &str) -> Option<&'static CrossNetworkReportSpec> {
    REPORT_SPECS.iter().find(|spec| spec.filename == filename)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn canonical_existing_file(path: &Path) -> Option<PathBuf> {
    let resolved = resolve_path(path).ok()?;
    if !resolved.exists() {
        return None;
    }
    fs::canonicalize(resolved).ok()
}

fn non_empty_option(value: Option<String>) -> Option<String> {
    value.and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn collect_existing_artifacts(paths: &[PathBuf]) -> Vec<String> {
    let mut collected = Vec::new();
    for path in paths {
        if let Some(canonical) = canonical_existing_file(path.as_path()) {
            collected.push(canonical.display().to_string());
        }
    }
    collected
}

fn current_git_commit() -> Result<String, String> {
    if let Ok(value) = std::env::var("RUSTYNET_EXPECTED_GIT_COMMIT") {
        let normalized = value.trim().to_ascii_lowercase();
        if !normalized.is_empty() {
            return Ok(normalized);
        }
    }
    let output = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .map_err(|err| format!("resolve git commit failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("resolve git commit failed: {}", stderr.trim()));
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|err| format!("decode git commit failed: {err}"))?
        .trim()
        .to_ascii_lowercase();
    if commit.is_empty() {
        return Err("resolve git commit failed: empty output".to_string());
    }
    Ok(commit)
}

fn parse_check_overrides(items: &[String]) -> Result<HashMap<String, String>, String> {
    let mut overrides = HashMap::new();
    for item in items {
        let Some((raw_key, raw_value)) = item.split_once('=') else {
            return Err(format!(
                "invalid --check value {item:?}; expected key=pass|fail"
            ));
        };
        let key = raw_key.trim();
        let value = raw_value.trim();
        if key.is_empty() {
            return Err(format!(
                "invalid --check value {item:?}; key must be non-empty"
            ));
        }
        if value != CHECK_PASS && value != CHECK_FAIL {
            return Err(format!(
                "invalid --check value {item:?}; expected key=pass|fail"
            ));
        }
        overrides.insert(key.to_string(), value.to_string());
    }
    Ok(overrides)
}

fn is_lower_hex_commit(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn resolve_artifact_path(report_path: &Path, raw: &str) -> PathBuf {
    let candidate = PathBuf::from(raw);
    if candidate.is_absolute() {
        return candidate;
    }
    let base = report_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    base.join(candidate)
}

fn path_is_within(candidate: &Path, root: &Path) -> bool {
    let canonical_candidate = fs::canonicalize(candidate);
    let canonical_root = fs::canonicalize(root);
    match (canonical_candidate, canonical_root) {
        (Ok(candidate), Ok(root)) => candidate.starts_with(root),
        _ => false,
    }
}

fn value_as_non_empty_string(value: Option<&Value>) -> Option<String> {
    value.and_then(Value::as_str).and_then(|entry| {
        let trimmed = entry.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}

fn validate_report_payload(
    report_path: &Path,
    payload: &Value,
    max_evidence_age_seconds: Option<u64>,
    now_unix_override: Option<u64>,
) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(payload_object) = payload.as_object() else {
        return vec![format!(
            "{}: report must be a JSON object",
            report_path.display()
        )];
    };

    let suite = payload_object
        .get("suite")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(spec) = report_spec_by_suite(suite) else {
        let known = REPORT_SPECS
            .iter()
            .map(|entry| entry.suite)
            .collect::<Vec<_>>()
            .join(", ");
        return vec![format!(
            "{}: unknown suite {suite:?}; expected one of {known}",
            report_path.display()
        )];
    };

    if let Some(filename) = report_path.file_name().and_then(|value| value.to_str())
        && let Some(expected) = report_spec_by_filename(filename)
        && expected.suite != spec.suite
    {
        problems.push(format!(
            "filename {filename:?} does not match suite {:?}",
            spec.suite
        ));
    }

    if payload_object.get("schema_version").and_then(Value::as_i64) != Some(SCHEMA_VERSION) {
        problems.push(format!("schema_version must equal {SCHEMA_VERSION}"));
    }
    if payload_object.get("phase").and_then(Value::as_str) != Some(PHASE_NAME) {
        problems.push(format!("phase must equal {PHASE_NAME:?}"));
    }
    if payload_object.get("evidence_mode").and_then(Value::as_str) != Some(EVIDENCE_MODE) {
        problems.push(format!("evidence_mode must equal {EVIDENCE_MODE:?}"));
    }

    if value_as_non_empty_string(payload_object.get("environment")).is_none() {
        problems.push("environment must be a non-empty string".to_string());
    }

    let captured_at_unix = payload_object
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .filter(|value| *value > 0);
    let now_unix = now_unix_override.unwrap_or_else(unix_now);
    match captured_at_unix {
        Some(captured) => {
            if captured > now_unix.saturating_add(300) {
                problems.push("captured_at_unix is too far in the future".to_string());
            }
            if let Some(max_age) = max_evidence_age_seconds
                && now_unix.saturating_sub(captured) > max_age
            {
                problems.push("captured_at_unix is stale".to_string());
            }
        }
        None => problems.push("captured_at_unix must be a positive integer".to_string()),
    }

    let git_commit = payload_object
        .get("git_commit")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !is_lower_hex_commit(git_commit) {
        problems.push("git_commit must be a 40-character lowercase hex commit id".to_string());
    }

    let status = payload_object
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if status != CHECK_PASS && status != CHECK_FAIL {
        problems.push("status must be 'pass' or 'fail'".to_string());
    }

    match payload_object
        .get("participants")
        .and_then(Value::as_object)
    {
        Some(participants) => {
            for field in spec.required_participants {
                if value_as_non_empty_string(participants.get(*field)).is_none() {
                    problems.push(format!("participants.{field} must be a non-empty string"));
                }
            }
        }
        None => problems.push("participants must be an object".to_string()),
    }

    match payload_object
        .get("network_context")
        .and_then(Value::as_object)
    {
        Some(network_context) => {
            for field in spec.required_network_fields {
                if value_as_non_empty_string(network_context.get(*field)).is_none() {
                    problems.push(format!(
                        "network_context.{field} must be a non-empty string"
                    ));
                }
            }
            let client_network_id =
                value_as_non_empty_string(network_context.get("client_network_id"));
            let exit_network_id = value_as_non_empty_string(network_context.get("exit_network_id"));
            if let (Some(client), Some(exit)) = (client_network_id, exit_network_id)
                && client == exit
            {
                problems.push("client_network_id and exit_network_id must differ".to_string());
            }
        }
        None => problems.push("network_context must be an object".to_string()),
    }

    let report_dir = report_path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let repo_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for field_name in ["source_artifacts", "log_artifacts"] {
        match payload_object.get(field_name).and_then(Value::as_array) {
            Some(entries) if !entries.is_empty() => {
                for entry in entries {
                    let Some(raw_path) = entry.as_str() else {
                        problems.push(format!("{field_name} contains an invalid path entry"));
                        continue;
                    };
                    if raw_path.trim().is_empty() {
                        problems.push(format!("{field_name} contains an invalid path entry"));
                        continue;
                    }
                    if raw_path
                        .chars()
                        .any(|value| matches!(value, '\n' | '\r' | '\t'))
                    {
                        problems.push(format!(
                            "{field_name} contains control characters in path entry"
                        ));
                        continue;
                    }
                    let artifact_path = resolve_artifact_path(report_path, raw_path);
                    if !artifact_path.exists() {
                        problems.push(format!("{field_name} path does not exist: {raw_path}"));
                        continue;
                    }
                    match fs::symlink_metadata(&artifact_path) {
                        Ok(metadata) => {
                            if metadata.file_type().is_symlink() {
                                problems.push(format!(
                                    "{field_name} path must not be a symlink: {raw_path}"
                                ));
                                continue;
                            }
                            if !metadata.file_type().is_file() {
                                problems.push(format!(
                                    "{field_name} path must be a regular file: {raw_path}"
                                ));
                                continue;
                            }
                        }
                        Err(err) => {
                            problems.push(format!(
                                "{field_name} path metadata check failed ({raw_path}): {err}"
                            ));
                            continue;
                        }
                    }
                    if !path_is_within(&artifact_path, &report_dir)
                        && !path_is_within(&artifact_path, &repo_root)
                    {
                        problems.push(format!(
                            "{field_name} path must stay within report directory or repository root: {raw_path}"
                        ));
                    }
                }
            }
            _ => problems.push(format!("{field_name} must be a non-empty list")),
        }
    }

    let checks = payload_object.get("checks").and_then(Value::as_object);
    match checks {
        Some(check_map) => {
            for check_name in spec.required_checks {
                let value = check_map
                    .get(*check_name)
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                if value != CHECK_PASS && value != CHECK_FAIL {
                    problems.push(format!(
                        "checks.{check_name} must be one of [\"fail\", \"pass\"], got {value:?}"
                    ));
                }
            }
        }
        None => problems.push("checks must be an object".to_string()),
    }

    let failure_summary = payload_object
        .get("failure_summary")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if status == CHECK_PASS {
        if let Some(check_map) = checks {
            let failing = spec
                .required_checks
                .iter()
                .filter(|name| check_map.get(**name).and_then(Value::as_str) != Some(CHECK_PASS))
                .copied()
                .collect::<Vec<_>>();
            if !failing.is_empty() {
                problems.push(format!(
                    "status=pass requires all required checks to pass; failing checks: {}",
                    failing.join(", ")
                ));
            }
        }
        if !failure_summary.trim().is_empty() {
            problems.push("failure_summary must be absent or empty when status=pass".to_string());
        }
    } else if status == CHECK_FAIL {
        if failure_summary.trim().is_empty() {
            problems.push("failure_summary must be non-empty when status=fail".to_string());
        }
        if let Some(check_map) = checks {
            let all_required_checks_pass = spec
                .required_checks
                .iter()
                .all(|name| check_map.get(*name).and_then(Value::as_str) == Some(CHECK_PASS));
            if all_required_checks_pass {
                problems
                    .push("status=fail requires at least one required check to fail".to_string());
            }
        }
    }

    problems
        .into_iter()
        .map(|problem| format!("{}: {problem}", report_path.display()))
        .collect()
}

fn collect_report_paths(
    reports: &[PathBuf],
    artifact_dir: Option<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    if !reports.is_empty() {
        let mut out = Vec::with_capacity(reports.len());
        for path in reports {
            out.push(resolve_path(path)?);
        }
        return Ok(out);
    }
    let base_dir = match artifact_dir {
        Some(path) => resolve_path(&path)?,
        None => resolve_path(Path::new(DEFAULT_ARTIFACT_DIR))?,
    };
    let mut out = Vec::with_capacity(REPORT_SPECS.len());
    for spec in REPORT_SPECS {
        out.push(base_dir.join(spec.filename));
    }
    Ok(out)
}

fn parse_report_payload(path: &Path) -> Result<Value, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("{}: read report failed: {err}", path.display()))?;
    let payload: Value = serde_json::from_str(&body)
        .map_err(|err| format!("{}: invalid JSON ({err})", path.display()))?;
    if !payload.is_object() {
        return Err(format!("{}: report must be a JSON object", path.display()));
    }
    Ok(payload)
}

fn markdown_for_schema_validation(report_paths: &[PathBuf], errors: &[String]) -> String {
    let mut lines = vec![
        "# Cross-Network Remote Exit Report Validation".to_string(),
        String::new(),
        "## Reports".to_string(),
        String::new(),
    ];
    for path in report_paths {
        lines.push(format!("- `{}`", path.display()));
    }
    lines.push(String::new());
    if errors.is_empty() {
        lines.push("## Result".to_string());
        lines.push(String::new());
        lines.push(
            "All supplied cross-network remote-exit reports matched the required schema."
                .to_string(),
        );
        lines.push(String::new());
    } else {
        lines.push("## Errors".to_string());
        lines.push(String::new());
        for error in errors {
            lines.push(format!("- {error}"));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn parse_csv_unique(raw: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for entry in raw
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        if seen.insert(entry.to_string()) {
            out.push(entry.to_string());
        }
    }
    out
}

fn collect_matrix_paths(
    reports: &[PathBuf],
    artifact_dir: Option<PathBuf>,
) -> Result<Vec<PathBuf>, String> {
    if !reports.is_empty() {
        let mut out = Vec::with_capacity(reports.len());
        for path in reports {
            out.push(resolve_path(path)?);
        }
        return Ok(out);
    }
    let base_dir = match artifact_dir {
        Some(path) => resolve_path(&path)?,
        None => resolve_path(Path::new(DEFAULT_ARTIFACT_DIR))?,
    };
    if !base_dir.is_dir() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let entries = fs::read_dir(&base_dir).map_err(|err| {
        format!(
            "list artifact directory failed ({}): {err}",
            base_dir.display()
        )
    })?;
    for entry in entries {
        let entry = entry.map_err(|err| format!("read directory entry failed: {err}"))?;
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

fn discover_matrix_records(
    report_paths: &[PathBuf],
    max_evidence_age_seconds: u64,
    expected_git_commit: Option<&str>,
    require_pass_status: bool,
) -> (Vec<ReportRecord>, Vec<String>) {
    let known_suites = REPORT_SPECS
        .iter()
        .map(|spec| spec.suite)
        .collect::<HashSet<_>>();
    let mut records = Vec::new();
    let mut errors = Vec::new();

    for path in report_paths {
        if !path.is_file() {
            errors.push(format!("{}: missing report file", path.display()));
            continue;
        }
        let payload = match parse_report_payload(path) {
            Ok(payload) => payload,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        let suite = payload
            .as_object()
            .and_then(|value| value.get("suite"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if !known_suites.contains(suite.as_str()) {
            continue;
        }

        errors.extend(validate_report_payload(
            path,
            &payload,
            Some(max_evidence_age_seconds),
            None,
        ));
        if let Some(expected) = expected_git_commit {
            let got = payload
                .as_object()
                .and_then(|value| value.get("git_commit"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if got != expected {
                errors.push(format!(
                    "{}: git_commit {:?} does not match expected {:?}",
                    path.display(),
                    got,
                    expected
                ));
            }
        }
        let status = payload
            .as_object()
            .and_then(|value| value.get("status"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        if require_pass_status && status != CHECK_PASS {
            errors.push(format!(
                "{}: status must be 'pass' for matrix validation",
                path.display()
            ));
        }

        let Some(network_context) = payload
            .as_object()
            .and_then(|value| value.get("network_context"))
            .and_then(Value::as_object)
        else {
            errors.push(format!(
                "{}: network_context must be an object",
                path.display()
            ));
            continue;
        };
        let nat_profile = value_as_non_empty_string(network_context.get("nat_profile"));
        if nat_profile.is_none() {
            errors.push(format!(
                "{}: network_context.nat_profile must be non-empty",
                path.display()
            ));
            continue;
        }
        let impairment_profile =
            value_as_non_empty_string(network_context.get("impairment_profile"));
        if impairment_profile.is_none() {
            errors.push(format!(
                "{}: network_context.impairment_profile must be non-empty",
                path.display()
            ));
            continue;
        }
        records.push(ReportRecord {
            path: path.clone(),
            suite,
            nat_profile: nat_profile.unwrap_or_default(),
            impairment_profile: impairment_profile.unwrap_or_default(),
            status,
        });
    }

    (records, errors)
}

fn validate_matrix(records: &[ReportRecord], required_nat_profiles: &[String]) -> Vec<String> {
    let mut errors = Vec::new();
    if required_nat_profiles.is_empty() {
        errors.push("required_nat_profiles must not be empty".to_string());
        return errors;
    }

    for spec in REPORT_SPECS {
        for profile in required_nat_profiles {
            let found = records
                .iter()
                .any(|record| record.suite == spec.suite && record.nat_profile == *profile);
            if !found {
                errors.push(format!(
                    "missing matrix evidence: suite={} nat_profile={}",
                    spec.suite, profile
                ));
            }
        }
    }

    errors
}

fn markdown_for_nat_matrix(
    report_paths: &[PathBuf],
    required_nat_profiles: &[String],
    records: &[ReportRecord],
    errors: &[String],
) -> String {
    let mut lines = vec![
        "# Cross-Network NAT Matrix Validation".to_string(),
        String::new(),
        "## Required NAT Profiles".to_string(),
        String::new(),
    ];
    for profile in required_nat_profiles {
        lines.push(format!("- `{profile}`"));
    }
    lines.push(String::new());
    lines.push("## Reports Considered".to_string());
    lines.push(String::new());
    if report_paths.is_empty() {
        lines.push("- none".to_string());
    } else {
        for path in report_paths {
            lines.push(format!("- `{}`", path.display()));
        }
    }
    lines.push(String::new());
    lines.push("## Matrix Records".to_string());
    lines.push(String::new());
    if records.is_empty() {
        lines.push("- none".to_string());
    } else {
        let mut sorted = records.iter().collect::<Vec<_>>();
        sorted.sort_by(|left, right| {
            left.suite
                .cmp(&right.suite)
                .then_with(|| left.nat_profile.cmp(&right.nat_profile))
                .then_with(|| left.path.cmp(&right.path))
        });
        for record in sorted {
            lines.push(format!(
                "- suite=`{}` nat_profile=`{}` impairment_profile=`{}` status=`{}` path=`{}`",
                record.suite,
                record.nat_profile,
                record.impairment_profile,
                record.status,
                record.path.display()
            ));
        }
    }
    lines.push(String::new());
    lines.push("## Result".to_string());
    lines.push(String::new());
    if errors.is_empty() {
        lines.push("Matrix validation passed.".to_string());
    } else {
        for error in errors {
            lines.push(format!("- {error}"));
        }
    }
    lines.push(String::new());
    lines.join("\n")
}

fn write_markdown(path: &Path, body: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output parent directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(path, body).map_err(|err| format!("write output failed ({}): {err}", path.display()))
}

pub fn execute_ops_generate_cross_network_remote_exit_report(
    config: GenerateCrossNetworkRemoteExitReportConfig,
) -> Result<String, String> {
    let spec = report_spec_by_suite(config.suite.as_str()).ok_or_else(|| {
        let known = REPORT_SPECS
            .iter()
            .map(|entry| entry.suite)
            .collect::<Vec<_>>()
            .join(", ");
        format!(
            "unknown suite {:?}; expected one of {known}",
            config.suite.as_str()
        )
    })?;

    let status = config.status.trim().to_string();
    if status != CHECK_PASS && status != CHECK_FAIL {
        return Err("status must be pass or fail".to_string());
    }

    let report_path = resolve_path(&config.report_path)?;
    let log_path = resolve_path(&config.log_path)?;
    if let Some(parent) = report_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create report output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    if let Some(parent) = log_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create log output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    if !log_path.exists() {
        fs::write(&log_path, "").map_err(|err| {
            format!(
                "initialize log artifact failed ({}): {err}",
                log_path.display()
            )
        })?;
    }

    let check_overrides = parse_check_overrides(&config.check_overrides)?;
    let mut checks = Map::new();
    for check in spec.required_checks {
        checks.insert((*check).to_string(), Value::String(CHECK_FAIL.to_string()));
    }
    for (key, value) in check_overrides {
        checks.insert(key, Value::String(value));
    }

    let mut participants = Map::new();
    if let Some(value) = non_empty_option(config.client_host) {
        participants.insert("client_host".to_string(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.exit_host) {
        participants.insert("exit_host".to_string(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.relay_host) {
        participants.insert("relay_host".to_string(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.probe_host) {
        participants.insert("probe_host".to_string(), Value::String(value));
    }

    let mut network_context = Map::new();
    if let Some(value) = non_empty_option(config.client_network_id) {
        network_context.insert("client_network_id".to_string(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.exit_network_id) {
        network_context.insert("exit_network_id".to_string(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.relay_network_id) {
        network_context.insert("relay_network_id".to_string(), Value::String(value));
    }
    if !config.nat_profile.trim().is_empty() {
        network_context.insert(
            "nat_profile".to_string(),
            Value::String(config.nat_profile.trim().to_string()),
        );
    }
    if !config.impairment_profile.trim().is_empty() {
        network_context.insert(
            "impairment_profile".to_string(),
            Value::String(config.impairment_profile.trim().to_string()),
        );
    }

    let mut source_artifact_inputs = Vec::with_capacity(config.source_artifacts.len());
    source_artifact_inputs.extend(config.source_artifacts.iter().cloned());
    let source_artifacts = collect_existing_artifacts(&source_artifact_inputs);

    let mut log_artifact_inputs = Vec::with_capacity(config.log_artifacts.len() + 1);
    log_artifact_inputs.push(log_path.clone());
    log_artifact_inputs.extend(config.log_artifacts.iter().cloned());
    let log_artifacts = collect_existing_artifacts(&log_artifact_inputs);

    let mut payload = json!({
        "schema_version": SCHEMA_VERSION,
        "phase": PHASE_NAME,
        "suite": spec.suite,
        "environment": if config.environment.trim().is_empty() { "live_linux_skeleton".to_string() } else { config.environment.trim().to_string() },
        "evidence_mode": EVIDENCE_MODE,
        "captured_at_unix": unix_now(),
        "git_commit": current_git_commit()?,
        "status": status,
        "participants": Value::Object(participants),
        "network_context": Value::Object(network_context),
        "checks": Value::Object(checks),
        "source_artifacts": source_artifacts,
        "log_artifacts": log_artifacts,
        "implementation_state": if config.implementation_state.trim().is_empty() {
            "not_implemented".to_string()
        } else {
            config.implementation_state.trim().to_string()
        },
    });
    if status == CHECK_FAIL {
        let failure_summary = if config.failure_summary.trim().is_empty() {
            format!("{} is not implemented yet", spec.title)
        } else {
            config.failure_summary.trim().to_string()
        };
        if let Some(object) = payload.as_object_mut() {
            object.insert(
                "failure_summary".to_string(),
                Value::String(failure_summary),
            );
        }
    }

    let problems = validate_report_payload(&report_path, &payload, None, None);
    if !problems.is_empty() {
        return Err(problems.join("\n"));
    }

    let rendered = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("serialize report failed: {err}"))?;
    fs::write(&report_path, format!("{rendered}\n"))
        .map_err(|err| format!("write report failed ({}): {err}", report_path.display()))?;

    Ok(format!(
        "cross-network report generated: suite={} status={} output={}",
        spec.suite,
        status,
        report_path.display()
    ))
}

pub fn execute_ops_validate_cross_network_remote_exit_reports(
    config: ValidateCrossNetworkRemoteExitReportsConfig,
) -> Result<String, String> {
    let report_paths = collect_report_paths(&config.reports, config.artifact_dir)?;
    let expected_git_commit = config
        .expected_git_commit
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let mut errors = Vec::new();

    for path in &report_paths {
        if !path.is_file() {
            errors.push(format!("{}: missing report file", path.display()));
            continue;
        }
        let payload = match parse_report_payload(path) {
            Ok(payload) => payload,
            Err(err) => {
                errors.push(err);
                continue;
            }
        };
        errors.extend(validate_report_payload(
            path,
            &payload,
            Some(config.max_evidence_age_seconds),
            None,
        ));
        if let Some(expected) = expected_git_commit.as_deref() {
            let got = payload
                .as_object()
                .and_then(|value| value.get("git_commit"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if got != expected {
                errors.push(format!(
                    "{}: git_commit {:?} does not match expected {:?}",
                    path.display(),
                    got,
                    expected
                ));
            }
        }
        if config.require_pass_status {
            let status = payload
                .as_object()
                .and_then(|value| value.get("status"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            if status != CHECK_PASS {
                errors.push(format!(
                    "{}: status must be 'pass' for gate usage",
                    path.display()
                ));
            }
        }
    }

    if let Some(output) = config.output {
        let output_path = resolve_path(&output)?;
        write_markdown(
            &output_path,
            markdown_for_schema_validation(&report_paths, &errors).as_str(),
        )?;
    }

    if errors.is_empty() {
        Ok("cross-network report schema validation passed".to_string())
    } else {
        Err(errors.join("\n"))
    }
}

pub fn execute_ops_validate_cross_network_nat_matrix(
    config: ValidateCrossNetworkNatMatrixConfig,
) -> Result<String, String> {
    let report_paths = collect_matrix_paths(&config.reports, config.artifact_dir)?;
    let required_nat_profiles = if config.required_nat_profiles.is_empty() {
        parse_csv_unique("baseline_lan")
    } else {
        let joined = config.required_nat_profiles.join(",");
        parse_csv_unique(&joined)
    };
    let expected_git_commit = config
        .expected_git_commit
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);

    let (records, mut errors) = discover_matrix_records(
        &report_paths,
        config.max_evidence_age_seconds,
        expected_git_commit.as_deref(),
        config.require_pass_status,
    );
    errors.extend(validate_matrix(&records, &required_nat_profiles));

    if let Some(output) = config.output {
        let output_path = resolve_path(&output)?;
        write_markdown(
            &output_path,
            markdown_for_nat_matrix(&report_paths, &required_nat_profiles, &records, &errors)
                .as_str(),
        )?;
    }

    if errors.is_empty() {
        Ok("cross-network NAT matrix validation passed".to_string())
    } else {
        Err(errors.join("\n"))
    }
}

pub fn default_max_evidence_age_seconds() -> u64 {
    DEFAULT_MAX_EVIDENCE_AGE_SECONDS
}

fn parse_ip_addr(label: &str, raw: &str) -> Result<IpAddr, String> {
    raw.trim()
        .parse::<IpAddr>()
        .map_err(|err| format!("invalid {label} {raw:?}: {err}"))
}

fn same_prefix(
    ip_a: IpAddr,
    ip_b: IpAddr,
    ipv4_prefix: u8,
    ipv6_prefix: u8,
) -> Result<bool, String> {
    match (ip_a, ip_b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            if ipv4_prefix > 32 {
                return Err(format!("invalid IPv4 prefix length: {ipv4_prefix}"));
            }
            let mask = if ipv4_prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - ipv4_prefix)
            };
            let a_bits = u32::from(a);
            let b_bits = u32::from(b);
            Ok((a_bits & mask) == (b_bits & mask))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            if ipv6_prefix > 128 {
                return Err(format!("invalid IPv6 prefix length: {ipv6_prefix}"));
            }
            let mask = if ipv6_prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - ipv6_prefix)
            };
            let a_bits = u128::from_be_bytes(a.octets());
            let b_bits = u128::from_be_bytes(b.octets());
            Ok((a_bits & mask) == (b_bits & mask))
        }
        _ => Err("ip-a and ip-b must use the same IP family".to_string()),
    }
}

pub fn execute_ops_classify_cross_network_topology(
    config: ClassifyCrossNetworkTopologyConfig,
) -> Result<String, String> {
    let ip_a = parse_ip_addr("ip-a", &config.ip_a)?;
    let ip_b = parse_ip_addr("ip-b", &config.ip_b)?;
    let same = same_prefix(ip_a, ip_b, config.ipv4_prefix, config.ipv6_prefix)?;
    Ok(if same {
        CHECK_FAIL.to_string()
    } else {
        CHECK_PASS.to_string()
    })
}

pub fn execute_ops_read_cross_network_report_fields(
    config: ReadCrossNetworkReportFieldsConfig,
) -> Result<String, String> {
    if !config.include_status && config.checks.is_empty() && config.network_fields.is_empty() {
        return Err(
            "at least one output selector is required (--include-status, --check, or --network-field)"
                .to_string(),
        );
    }

    let report_path = resolve_path(config.report_path.as_path())?;
    let payload = parse_report_payload(report_path.as_path())?;
    let object = payload
        .as_object()
        .ok_or_else(|| format!("{}: report must be a JSON object", report_path.display()))?;

    let default_value = if config.default_value.is_empty() {
        CHECK_FAIL.to_string()
    } else {
        config.default_value
    };
    let mut values = Vec::new();
    if config.include_status {
        values.push(
            object
                .get("status")
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| default_value.clone()),
        );
    }

    let checks = object.get("checks").and_then(Value::as_object);
    for key in config.checks {
        let name = key.trim();
        if name.is_empty() {
            return Err("check selector must not be empty".to_string());
        }
        values.push(
            checks
                .and_then(|items| items.get(name))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| default_value.clone()),
        );
    }

    let network = object.get("network_context").and_then(Value::as_object);
    for key in config.network_fields {
        let name = key.trim();
        if name.is_empty() {
            return Err("network-field selector must not be empty".to_string());
        }
        values.push(
            network
                .and_then(|items| items.get(name))
                .and_then(Value::as_str)
                .map(str::to_string)
                .unwrap_or_else(|| default_value.clone()),
        );
    }

    Ok(values.join("\n"))
}

pub fn execute_ops_choose_cross_network_roam_alias(
    config: ChooseCrossNetworkRoamAliasConfig,
) -> Result<String, String> {
    let exit_ip = parse_ip_addr("exit-ip", &config.exit_ip)?;
    match exit_ip {
        IpAddr::V4(exit_v4) => {
            if config.ipv4_prefix > 32 {
                return Err(format!(
                    "invalid IPv4 prefix length: {}",
                    config.ipv4_prefix
                ));
            }
            if config.ipv4_prefix == 32 {
                return Err(
                    "cannot choose roam alias in /32; IPv4 prefix must allow host space"
                        .to_string(),
                );
            }
            let mut used = HashSet::new();
            for raw in &config.used_ips {
                let parsed = parse_ip_addr("used-ip", raw)?;
                let IpAddr::V4(value) = parsed else {
                    return Err("all --used-ip values must match exit-ip family".to_string());
                };
                used.insert(u32::from(value));
            }

            let exit_bits = u32::from(exit_v4);
            used.insert(exit_bits);
            let mask = if config.ipv4_prefix == 0 {
                0u32
            } else {
                u32::MAX << (32 - config.ipv4_prefix)
            };
            let network = exit_bits & mask;
            let broadcast = network | !mask;
            for candidate in (network + 1..broadcast).rev() {
                if !used.contains(&candidate) {
                    let ip = std::net::Ipv4Addr::from(candidate);
                    return Ok(format!("{ip}\n{}", config.ipv4_prefix));
                }
            }
            Err("failed to find available IPv4 roam alias in selected prefix".to_string())
        }
        IpAddr::V6(exit_v6) => {
            if config.ipv6_prefix > 128 {
                return Err(format!(
                    "invalid IPv6 prefix length: {}",
                    config.ipv6_prefix
                ));
            }
            if config.ipv6_prefix == 128 {
                return Err(
                    "cannot choose roam alias in /128; IPv6 prefix must allow host space"
                        .to_string(),
                );
            }
            let mut used = HashSet::new();
            for raw in &config.used_ips {
                let parsed = parse_ip_addr("used-ip", raw)?;
                let IpAddr::V6(value) = parsed else {
                    return Err("all --used-ip values must match exit-ip family".to_string());
                };
                used.insert(u128::from_be_bytes(value.octets()));
            }

            let exit_bits = u128::from_be_bytes(exit_v6.octets());
            used.insert(exit_bits);
            let mask = if config.ipv6_prefix == 0 {
                0u128
            } else {
                u128::MAX << (128 - config.ipv6_prefix)
            };
            let network = exit_bits & mask;
            let host_mask = !mask;
            let exit_host = exit_bits & host_mask;

            for offset in 0x100u128..=0x1_0000u128 {
                let host = exit_host.wrapping_add(offset) & host_mask;
                let candidate = network | host;
                if candidate != exit_bits && !used.contains(&candidate) {
                    let ip = std::net::Ipv6Addr::from(candidate.to_be_bytes());
                    return Ok(format!("{ip}\n{}", config.ipv6_prefix));
                }
            }
            Err("failed to find available IPv6 roam alias in selected prefix".to_string())
        }
    }
}

pub fn execute_ops_validate_ipv4_address(
    config: ValidateIpv4AddressConfig,
) -> Result<String, String> {
    let parsed = config
        .ip
        .trim()
        .parse::<std::net::Ipv4Addr>()
        .map_err(|err| format!("invalid IPv4 address {:?}: {err}", config.ip))?;
    Ok(parsed.to_string())
}

pub fn execute_ops_write_cross_network_soak_monitor_summary(
    config: WriteCrossNetworkSoakMonitorSummaryConfig,
) -> Result<String, String> {
    let path = resolve_path(config.path.as_path())?;
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create monitor summary parent directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    let payload = json!({
        "samples": config.samples,
        "failing_samples": config.failing_samples,
        "max_consecutive_failures_observed": config.max_consecutive_failures_observed,
        "elapsed_secs": config.elapsed_secs,
        "required_soak_duration_secs": config.required_soak_duration_secs,
        "allowed_failing_samples": config.allowed_failing_samples,
        "allowed_max_consecutive_failures": config.allowed_max_consecutive_failures,
        "direct_remote_exit_ready": config.direct_remote_exit_ready,
        "post_soak_bypass_ready": config.post_soak_bypass_ready,
        "no_plaintext_passphrase_files": config.no_plaintext_passphrase_files,
        "first_failure_reason": config.first_failure_reason,
        "long_soak_stable": config.long_soak_stable,
    });
    fs::write(
        &path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&payload)
                .map_err(|err| format!("serialize monitor summary failed: {err}"))?
        ),
    )
    .map_err(|err| format!("write monitor summary failed ({}): {err}", path.display()))?;
    Ok(path.display().to_string())
}
