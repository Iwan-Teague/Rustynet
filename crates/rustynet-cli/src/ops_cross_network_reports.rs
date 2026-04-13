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
const DEFAULT_REQUIRED_NAT_PROFILES: &str = "baseline_lan";
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
    required_pass_source_artifacts: &'static [&'static str],
    required_pass_log_artifacts: &'static [&'static str],
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
        required_pass_source_artifacts: &[
            "cross_network_direct_remote_exit_server_ip_bypass_report.json",
            "cross_network_direct_remote_exit_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &["cross_network_direct_remote_exit_server_ip_bypass.log"],
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
        required_pass_source_artifacts: &[
            "cross_network_relay_remote_exit_server_ip_bypass_report.json",
            "cross_network_relay_remote_exit_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &["cross_network_relay_remote_exit_server_ip_bypass.log"],
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
            "failback_reconnect_within_slo",
            "no_underlay_leak_while_reconnecting",
            "signed_state_valid_while_reconnecting",
        ],
        required_pass_source_artifacts: &[
            "cross_network_failback_roaming_relay_stage_report.json",
            "cross_network_failback_roaming_server_ip_bypass_report.json",
            "cross_network_failback_roaming_slo_summary.json",
            "cross_network_failback_roaming_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &[
            "cross_network_failback_roaming_relay_stage.log",
            "cross_network_failback_roaming_server_ip_bypass.log",
            "cross_network_failback_roaming_monitor.log",
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
        required_pass_source_artifacts: &[
            "cross_network_traversal_adversarial_endpoint_hijack_report.json",
            "cross_network_traversal_adversarial_control_surface_report.json",
            "cross_network_traversal_adversarial_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &[
            "cross_network_traversal_adversarial_local_tests.log",
            "cross_network_traversal_adversarial_endpoint_hijack.log",
            "cross_network_traversal_adversarial_control_surface.log",
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
        required_pass_source_artifacts: &[
            "cross_network_remote_exit_dns_direct_remote_exit_report.json",
            "cross_network_remote_exit_dns_managed_dns_report.json",
            "cross_network_remote_exit_dns_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &[
            "cross_network_remote_exit_dns_direct_remote_exit.log",
            "cross_network_remote_exit_dns_managed_dns.log",
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
        required_pass_source_artifacts: &[
            "cross_network_remote_exit_soak_direct_remote_exit_report.json",
            "cross_network_remote_exit_soak_server_ip_bypass_report.json",
            "cross_network_remote_exit_soak_monitor_summary.json",
            "cross_network_remote_exit_soak_ssh_trust_summary.txt",
        ],
        required_pass_log_artifacts: &[
            "cross_network_remote_exit_soak_direct_remote_exit.log",
            "cross_network_remote_exit_soak_server_ip_bypass.log",
            "cross_network_remote_exit_soak_monitor.log",
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
    pub path_status_line: Option<String>,
    pub path_evidence_report: Option<PathBuf>,
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
    pub direct_samples: u64,
    pub relay_samples: u64,
    pub fail_closed_samples: u64,
    pub other_path_samples: u64,
    pub path_transition_count: u64,
    pub status_mismatch_samples: u64,
    pub route_mismatch_samples: u64,
    pub endpoint_mismatch_samples: u64,
    pub dns_alarm_bad_samples: u64,
    pub transport_identity_failures: u64,
    pub endpoint_change_events_start: u64,
    pub endpoint_change_events_end: u64,
    pub endpoint_change_events_delta: u64,
    pub first_non_direct_reason: String,
    pub last_path_mode: String,
    pub last_path_reason: String,
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

fn extract_inline_field(line: &str, key: &str) -> Option<String> {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|token| token.strip_prefix(prefix.as_str()))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn extract_optional_u64_inline_field(line: &str, key: &str) -> Result<Option<u64>, String> {
    match extract_inline_field(line, key) {
        Some(value) if value == "none" => Ok(None),
        Some(value) => value
            .parse::<u64>()
            .map(Some)
            .map_err(|err| format!("status line {key} invalid: {err}")),
        None => Ok(None),
    }
}

fn path_evidence_from_status_line(status_line: &str) -> Result<Value, String> {
    let path_mode = extract_inline_field(status_line, "path_mode")
        .ok_or_else(|| "status line missing path_mode".to_string())?;
    let path_reason = extract_inline_field(status_line, "path_reason")
        .ok_or_else(|| "status line missing path_reason".to_string())?;
    let path_programmed_mode = extract_inline_field(status_line, "path_programmed_mode")
        .ok_or_else(|| "status line missing path_programmed_mode".to_string())?;
    let transport_socket_identity_state =
        extract_inline_field(status_line, "transport_socket_identity_state")
            .ok_or_else(|| "status line missing transport_socket_identity_state".to_string())?;
    let transport_socket_identity_error =
        extract_inline_field(status_line, "transport_socket_identity_error")
            .ok_or_else(|| "status line missing transport_socket_identity_error".to_string())?;
    let path_live_proven = match extract_inline_field(status_line, "path_live_proven")
        .ok_or_else(|| "status line missing path_live_proven".to_string())?
        .as_str()
    {
        "true" => true,
        "false" => false,
        other => {
            return Err(format!(
                "status line path_live_proven must be true|false, got {other}"
            ));
        }
    };
    let path_latest_live_handshake_unix =
        extract_optional_u64_inline_field(status_line, "path_latest_live_handshake_unix")?;
    let relay_session_state = extract_inline_field(status_line, "relay_session_state");
    let traversal_alarm_state = extract_inline_field(status_line, "traversal_alarm_state");
    let traversal_alarm_reason = extract_inline_field(status_line, "traversal_alarm_reason");
    let dns_alarm_state = extract_inline_field(status_line, "dns_alarm_state");
    let dns_alarm_reason = extract_inline_field(status_line, "dns_alarm_reason");
    let traversal_error = extract_inline_field(status_line, "traversal_error");
    let transport_socket_identity_label =
        extract_inline_field(status_line, "transport_socket_identity_label");
    let transport_socket_identity_local_addr =
        extract_inline_field(status_line, "transport_socket_identity_local_addr");
    let traversal_probe_result = extract_inline_field(status_line, "traversal_probe_result");
    let traversal_probe_reason = extract_inline_field(status_line, "traversal_probe_reason");
    let traversal_endpoint_change_events =
        extract_optional_u64_inline_field(status_line, "traversal_endpoint_change_events")?;
    let stun_transport_port_binding =
        extract_inline_field(status_line, "stun_transport_port_binding");

    Ok(json!({
        "path_mode": path_mode,
        "path_reason": path_reason,
        "path_programmed_mode": path_programmed_mode,
        "path_live_proven": path_live_proven,
        "path_latest_live_handshake_unix": path_latest_live_handshake_unix,
        "relay_session_state": relay_session_state,
        "traversal_alarm_state": traversal_alarm_state,
        "traversal_alarm_reason": traversal_alarm_reason,
        "dns_alarm_state": dns_alarm_state,
        "dns_alarm_reason": dns_alarm_reason,
        "traversal_error": traversal_error,
        "transport_socket_identity_state": transport_socket_identity_state,
        "transport_socket_identity_error": transport_socket_identity_error,
        "transport_socket_identity_label": transport_socket_identity_label,
        "transport_socket_identity_local_addr": transport_socket_identity_local_addr,
        "traversal_probe_result": traversal_probe_result,
        "traversal_probe_reason": traversal_probe_reason,
        "traversal_endpoint_change_events": traversal_endpoint_change_events,
        "stun_transport_port_binding": stun_transport_port_binding,
    }))
}

fn artifact_list_has_basename(entries: &[Value], basename: &str) -> bool {
    entries.iter().any(|entry| {
        entry.as_str().is_some_and(|raw_path| {
            Path::new(raw_path)
                .file_name()
                .and_then(|value| value.to_str())
                == Some(basename)
        })
    })
}

fn path_evidence_from_report(path: &Path) -> Result<Value, String> {
    let report_path = resolve_path(path)?;
    let payload = parse_report_payload(report_path.as_path())?;
    payload
        .as_object()
        .and_then(|object| object.get("path_evidence"))
        .cloned()
        .ok_or_else(|| format!("{}: report is missing path_evidence", report_path.display()))
}

fn resolve_optional_path_evidence(
    status: &str,
    path_status_line: Option<String>,
    path_evidence_report: Option<PathBuf>,
) -> Result<Option<Value>, String> {
    let resolved = if let Some(status_line) = non_empty_option(path_status_line) {
        path_evidence_from_status_line(status_line.as_str()).map(Some)
    } else if let Some(path_evidence_report) = path_evidence_report {
        path_evidence_from_report(path_evidence_report.as_path()).map(Some)
    } else {
        Ok(None)
    };

    match resolved {
        Ok(path_evidence) => Ok(path_evidence),
        Err(_err) if status == CHECK_FAIL => Ok(None),
        Err(err) => Err(err),
    }
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

fn resolve_artifact_by_basename(
    report_path: &Path,
    entries: &[Value],
    basename: &str,
) -> Result<Option<PathBuf>, String> {
    let mut matches = entries
        .iter()
        .filter_map(Value::as_str)
        .map(|raw_path| resolve_artifact_path(report_path, raw_path))
        .filter(|artifact_path| {
            artifact_path.file_name().and_then(|value| value.to_str()) == Some(basename)
        })
        .collect::<Vec<_>>();
    if matches.len() > 1 {
        return Err(format!(
            "{}: source_artifacts contains duplicate basename {:?}",
            report_path.display(),
            basename
        ));
    }
    Ok(matches.pop())
}

fn parse_key_value_artifact(path: &Path) -> Result<HashMap<String, String>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("{}: read key/value artifact failed: {err}", path.display()))?;
    let mut out = HashMap::new();
    for (line_index, line) in body.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let Some((raw_key, raw_value)) = trimmed.split_once('=') else {
            return Err(format!(
                "{}: malformed key/value line {}",
                path.display(),
                line_index + 1
            ));
        };
        let key = raw_key.trim();
        if key.is_empty() {
            return Err(format!(
                "{}: empty key on line {}",
                path.display(),
                line_index + 1
            ));
        }
        if out
            .insert(key.to_string(), raw_value.trim().to_string())
            .is_some()
        {
            return Err(format!("{}: duplicate key {:?}", path.display(), key));
        }
    }
    Ok(out)
}

fn validate_ssh_trust_summary_artifact(path: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let summary = match parse_key_value_artifact(path) {
        Ok(summary) => summary,
        Err(err) => return vec![err],
    };

    let expect_non_empty = |key: &str, problems: &mut Vec<String>| -> Option<String> {
        let value = summary.get(key).cloned().unwrap_or_default();
        if value.trim().is_empty() {
            problems.push(format!(
                "{}: {key} must be a non-empty string",
                path.display()
            ));
            None
        } else {
            Some(value)
        }
    };

    if summary.get("schema_version").map(String::as_str) != Some("1") {
        problems.push(format!("{}: schema_version must equal 1", path.display()));
    }
    if expect_non_empty("pinned_known_hosts_file", &mut problems).is_none() {
        // recorded in problems
    }
    let pinned_known_hosts_sha256 = expect_non_empty("pinned_known_hosts_sha256", &mut problems);
    if pinned_known_hosts_sha256.as_deref().is_some_and(|value| {
        value.len() != 64
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) {
        problems.push(format!(
            "{}: pinned_known_hosts_sha256 must be a 64-character lowercase hex digest",
            path.display()
        ));
    }
    if summary.get("all_targets_pinned").map(String::as_str) != Some("true") {
        problems.push(format!(
            "{}: all_targets_pinned must equal true",
            path.display()
        ));
    }
    if summary
        .get("all_targets_passwordless_sudo")
        .map(String::as_str)
        != Some("true")
    {
        problems.push(format!(
            "{}: all_targets_passwordless_sudo must equal true",
            path.display()
        ));
    }

    let target_count = summary
        .get("target_count")
        .and_then(|value| value.parse::<usize>().ok());
    let Some(target_count) = target_count else {
        problems.push(format!(
            "{}: target_count must be a positive integer",
            path.display()
        ));
        return problems;
    };
    if target_count == 0 {
        problems.push(format!(
            "{}: target_count must be a positive integer",
            path.display()
        ));
    }

    for index in 0..target_count {
        let target_key = format!("target[{index}].target");
        let checked_candidates_key = format!("target[{index}].checked_candidates");
        let matched_candidate_key = format!("target[{index}].matched_candidate");
        let host_key_status_key = format!("target[{index}].host_key_status");
        let passwordless_sudo_status_key = format!("target[{index}].passwordless_sudo_status");
        let configured_transport_key = format!("target[{index}].configured_transport");

        let checked_candidates = expect_non_empty(checked_candidates_key.as_str(), &mut problems);
        let matched_candidate = expect_non_empty(matched_candidate_key.as_str(), &mut problems);
        let _target = expect_non_empty(target_key.as_str(), &mut problems);
        let configured_transport =
            expect_non_empty(configured_transport_key.as_str(), &mut problems);
        if configured_transport
            .as_deref()
            .is_some_and(|value| !matches!(value, "ssh" | "utm"))
        {
            problems.push(format!(
                "{}: {configured_transport_key} must equal ssh or utm",
                path.display()
            ));
        }
        if summary
            .get(host_key_status_key.as_str())
            .map(String::as_str)
            != Some(CHECK_PASS)
        {
            problems.push(format!(
                "{}: {host_key_status_key} must equal pass",
                path.display()
            ));
        }
        if summary
            .get(passwordless_sudo_status_key.as_str())
            .map(String::as_str)
            != Some(CHECK_PASS)
        {
            problems.push(format!(
                "{}: {passwordless_sudo_status_key} must equal pass",
                path.display()
            ));
        }
        if let (Some(checked_candidates), Some(matched_candidate)) =
            (checked_candidates.as_deref(), matched_candidate.as_deref())
        {
            let matched = checked_candidates
                .split(',')
                .map(str::trim)
                .any(|candidate| candidate == matched_candidate);
            if !matched {
                problems.push(format!(
                    "{}: {matched_candidate_key} must appear in {checked_candidates_key}",
                    path.display()
                ));
            }
        }
    }

    problems
}

fn parse_json_object_file(path: &Path, label: &str) -> Result<Map<String, Value>, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("{}: read {label} failed: {err}", path.display()))?;
    let payload: Value = serde_json::from_str(&body)
        .map_err(|err| format!("{}: invalid {label} JSON ({err})", path.display()))?;
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{}: {label} must be a JSON object", path.display()))
}

fn validate_soak_monitor_summary_artifact(path: &Path) -> Vec<String> {
    let mut problems = Vec::new();
    let payload = match parse_json_object_file(path, "soak monitor summary") {
        Ok(payload) => payload,
        Err(err) => return vec![err],
    };

    let read_u64 = |field: &str, problems: &mut Vec<String>| -> Option<u64> {
        let value = payload.get(field).and_then(Value::as_u64);
        if value.is_none() {
            problems.push(format!(
                "{}: {field} must be a non-negative integer",
                path.display()
            ));
        }
        value
    };
    let read_status = |field: &str, problems: &mut Vec<String>| -> Option<String> {
        let value = value_as_non_empty_string(payload.get(field));
        if value.is_none() {
            problems.push(format!(
                "{}: {field} must be a non-empty string",
                path.display()
            ));
        }
        value
    };

    let samples = read_u64("samples", &mut problems);
    let failing_samples = read_u64("failing_samples", &mut problems);
    let max_consecutive_failures_observed =
        read_u64("max_consecutive_failures_observed", &mut problems);
    let elapsed_secs = read_u64("elapsed_secs", &mut problems);
    let required_soak_duration_secs = read_u64("required_soak_duration_secs", &mut problems);
    let allowed_failing_samples = read_u64("allowed_failing_samples", &mut problems);
    let allowed_max_consecutive_failures =
        read_u64("allowed_max_consecutive_failures", &mut problems);
    let direct_samples = read_u64("direct_samples", &mut problems);
    let relay_samples = read_u64("relay_samples", &mut problems);
    let fail_closed_samples = read_u64("fail_closed_samples", &mut problems);
    let other_path_samples = read_u64("other_path_samples", &mut problems);
    let path_transition_count = read_u64("path_transition_count", &mut problems);
    let status_mismatch_samples = read_u64("status_mismatch_samples", &mut problems);
    let route_mismatch_samples = read_u64("route_mismatch_samples", &mut problems);
    let endpoint_mismatch_samples = read_u64("endpoint_mismatch_samples", &mut problems);
    let dns_alarm_bad_samples = read_u64("dns_alarm_bad_samples", &mut problems);
    let transport_identity_failures = read_u64("transport_identity_failures", &mut problems);
    let endpoint_change_events_start = read_u64("endpoint_change_events_start", &mut problems);
    let endpoint_change_events_end = read_u64("endpoint_change_events_end", &mut problems);
    let endpoint_change_events_delta = read_u64("endpoint_change_events_delta", &mut problems);

    let direct_remote_exit_ready = read_status("direct_remote_exit_ready", &mut problems);
    let post_soak_bypass_ready = read_status("post_soak_bypass_ready", &mut problems);
    let no_plaintext_passphrase_files = read_status("no_plaintext_passphrase_files", &mut problems);
    let first_non_direct_reason = read_status("first_non_direct_reason", &mut problems);
    let first_failure_reason = read_status("first_failure_reason", &mut problems);
    let last_path_mode = read_status("last_path_mode", &mut problems);
    let last_path_reason = read_status("last_path_reason", &mut problems);
    let long_soak_stable = read_status("long_soak_stable", &mut problems);

    if let (
        Some(samples),
        Some(direct_samples),
        Some(relay_samples),
        Some(fail_closed_samples),
        Some(other_path_samples),
    ) = (
        samples,
        direct_samples,
        relay_samples,
        fail_closed_samples,
        other_path_samples,
    ) && direct_samples + relay_samples + fail_closed_samples + other_path_samples != samples
    {
        problems.push(format!(
            "{}: direct/relay/fail_closed/other sample counts must sum to samples",
            path.display()
        ));
    }
    if let (Some(start), Some(end), Some(delta)) = (
        endpoint_change_events_start,
        endpoint_change_events_end,
        endpoint_change_events_delta,
    ) {
        if end < start {
            problems.push(format!(
                "{}: endpoint_change_events_end must be >= endpoint_change_events_start",
                path.display()
            ));
        }
        if end.saturating_sub(start) != delta {
            problems.push(format!(
                "{}: endpoint_change_events_delta must equal end-start",
                path.display()
            ));
        }
    }

    if elapsed_secs
        .zip(required_soak_duration_secs)
        .is_some_and(|(elapsed, required)| elapsed < required)
    {
        problems.push(format!(
            "{}: elapsed_secs must be >= required_soak_duration_secs",
            path.display()
        ));
    }
    if failing_samples
        .zip(allowed_failing_samples)
        .is_some_and(|(failing, allowed)| failing > allowed)
    {
        problems.push(format!(
            "{}: failing_samples must be <= allowed_failing_samples",
            path.display()
        ));
    }
    if max_consecutive_failures_observed
        .zip(allowed_max_consecutive_failures)
        .is_some_and(|(observed, allowed)| observed > allowed)
    {
        problems.push(format!(
            "{}: max_consecutive_failures_observed must be <= allowed_max_consecutive_failures",
            path.display()
        ));
    }

    if direct_remote_exit_ready.as_deref() != Some(CHECK_PASS) {
        problems.push(format!(
            "{}: direct_remote_exit_ready must equal pass",
            path.display()
        ));
    }
    if post_soak_bypass_ready.as_deref() != Some(CHECK_PASS) {
        problems.push(format!(
            "{}: post_soak_bypass_ready must equal pass",
            path.display()
        ));
    }
    if no_plaintext_passphrase_files.as_deref() != Some(CHECK_PASS) {
        problems.push(format!(
            "{}: no_plaintext_passphrase_files must equal pass",
            path.display()
        ));
    }
    if long_soak_stable.as_deref() != Some(CHECK_PASS) {
        problems.push(format!(
            "{}: long_soak_stable must equal pass",
            path.display()
        ));
    }
    if direct_samples != samples {
        problems.push(format!(
            "{}: direct_samples must equal samples for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    for (field, value) in [
        ("relay_samples", relay_samples),
        ("fail_closed_samples", fail_closed_samples),
        ("other_path_samples", other_path_samples),
        ("path_transition_count", path_transition_count),
        ("status_mismatch_samples", status_mismatch_samples),
        ("route_mismatch_samples", route_mismatch_samples),
        ("endpoint_mismatch_samples", endpoint_mismatch_samples),
        ("dns_alarm_bad_samples", dns_alarm_bad_samples),
        ("transport_identity_failures", transport_identity_failures),
        ("failing_samples", failing_samples),
        (
            "max_consecutive_failures_observed",
            max_consecutive_failures_observed,
        ),
    ] {
        if value.is_some_and(|entry| entry != 0) {
            problems.push(format!(
                "{}: {field} must equal 0 for authoritative direct-path soak evidence",
                path.display()
            ));
        }
    }
    if first_non_direct_reason.as_deref() != Some("none") {
        problems.push(format!(
            "{}: first_non_direct_reason must equal none for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    if first_failure_reason.as_deref() != Some("none") {
        problems.push(format!(
            "{}: first_failure_reason must equal none for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    if last_path_mode.as_deref() != Some("direct_active") {
        problems.push(format!(
            "{}: last_path_mode must equal direct_active",
            path.display()
        ));
    }
    if last_path_reason
        .as_deref()
        .is_none_or(|value| value.trim().is_empty() || value == "none")
    {
        problems.push(format!(
            "{}: last_path_reason must be a non-empty direct-path reason",
            path.display()
        ));
    }

    problems
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

    let path_evidence = payload_object
        .get("path_evidence")
        .and_then(Value::as_object);
    let requires_live_path_evidence =
        status == CHECK_PASS && !matches!(spec.suite, "cross_network_traversal_adversarial");
    if requires_live_path_evidence && path_evidence.is_none() {
        problems.push("path_evidence must be present for pass reports".to_string());
    }
    if let Some(path_evidence) = path_evidence {
        let path_mode = value_as_non_empty_string(path_evidence.get("path_mode"));
        let path_reason = value_as_non_empty_string(path_evidence.get("path_reason"));
        let path_programmed_mode =
            value_as_non_empty_string(path_evidence.get("path_programmed_mode"));
        let path_live_proven = path_evidence
            .get("path_live_proven")
            .and_then(Value::as_bool);
        let path_latest_live_handshake_unix = path_evidence
            .get("path_latest_live_handshake_unix")
            .and_then(Value::as_u64)
            .filter(|value| *value > 0);
        let relay_session_state =
            value_as_non_empty_string(path_evidence.get("relay_session_state"));
        let traversal_alarm_state =
            value_as_non_empty_string(path_evidence.get("traversal_alarm_state"));
        let traversal_alarm_reason =
            value_as_non_empty_string(path_evidence.get("traversal_alarm_reason"));
        let dns_alarm_state = value_as_non_empty_string(path_evidence.get("dns_alarm_state"));
        let dns_alarm_reason = value_as_non_empty_string(path_evidence.get("dns_alarm_reason"));
        let traversal_error = value_as_non_empty_string(path_evidence.get("traversal_error"));
        let transport_socket_identity_state =
            value_as_non_empty_string(path_evidence.get("transport_socket_identity_state"));
        let transport_socket_identity_error =
            value_as_non_empty_string(path_evidence.get("transport_socket_identity_error"));
        let transport_socket_identity_label =
            value_as_non_empty_string(path_evidence.get("transport_socket_identity_label"));
        let transport_socket_identity_local_addr =
            value_as_non_empty_string(path_evidence.get("transport_socket_identity_local_addr"));

        if requires_live_path_evidence {
            if path_mode.is_none() {
                problems.push("path_evidence.path_mode must be a non-empty string".to_string());
            }
            if path_reason.is_none() {
                problems.push("path_evidence.path_reason must be a non-empty string".to_string());
            }
            if path_programmed_mode.is_none() {
                problems.push(
                    "path_evidence.path_programmed_mode must be a non-empty string".to_string(),
                );
            }
            if path_live_proven != Some(true) {
                problems.push("path_evidence.path_live_proven must be true".to_string());
            }
            if path_latest_live_handshake_unix.is_none() {
                problems.push(
                    "path_evidence.path_latest_live_handshake_unix must be a positive integer"
                        .to_string(),
                );
            }
            if transport_socket_identity_state.as_deref()
                != Some("authoritative_backend_shared_transport")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_state must equal authoritative_backend_shared_transport for pass reports"
                        .to_string(),
                );
            }
            if transport_socket_identity_error.as_deref() != Some("none") {
                problems.push(
                    "path_evidence.transport_socket_identity_error must equal none for pass reports"
                        .to_string(),
                );
            }
            if transport_socket_identity_label
                .as_deref()
                .is_none_or(|value| value == "none")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_label must be a non-empty backend identity label"
                        .to_string(),
                );
            }
            if transport_socket_identity_local_addr
                .as_deref()
                .is_none_or(|value| value == "none")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_local_addr must be a non-empty backend local address"
                        .to_string(),
                );
            }
            if traversal_alarm_state
                .as_deref()
                .is_some_and(|value| matches!(value, "critical" | "error" | "missing"))
            {
                problems.push(
                    "path_evidence.traversal_alarm_state must not be critical|error|missing for pass reports"
                        .to_string(),
                );
            }
            if dns_alarm_state
                .as_deref()
                .is_some_and(|value| matches!(value, "critical" | "error" | "missing"))
            {
                problems.push(
                    "path_evidence.dns_alarm_state must not be critical|error|missing for pass reports"
                        .to_string(),
                );
            }
            if traversal_error
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.traversal_error must equal none for pass reports".to_string(),
                );
            }
            if traversal_alarm_reason
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.traversal_alarm_reason must equal none for pass reports"
                        .to_string(),
                );
            }
            if dns_alarm_reason
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.dns_alarm_reason must equal none for pass reports".to_string(),
                );
            }
        }

        if let Some(path_mode) = path_mode.as_deref() {
            if requires_live_path_evidence && path_mode.ends_with("_programmed") {
                problems.push(
                    "path_evidence.path_mode must represent a live path, not a programmed path"
                        .to_string(),
                );
            }
            match spec.suite {
                "cross_network_direct_remote_exit" if status == CHECK_PASS => {
                    if path_mode != "direct_active" {
                        problems.push(
                            "direct remote-exit pass reports require path_evidence.path_mode=direct_active"
                                .to_string(),
                        );
                    }
                }
                "cross_network_relay_remote_exit" if status == CHECK_PASS => {
                    if path_mode != "relay_active" {
                        problems.push(
                            "relay remote-exit pass reports require path_evidence.path_mode=relay_active"
                                .to_string(),
                        );
                    }
                    if relay_session_state.as_deref() != Some("live") {
                        problems.push(
                            "relay remote-exit pass reports require path_evidence.relay_session_state=live"
                                .to_string(),
                        );
                    }
                }
                "cross_network_failback_roaming" if status == CHECK_PASS => {
                    if path_mode != "direct_active" {
                        problems.push(
                            "failback pass reports require path_evidence.path_mode=direct_active"
                                .to_string(),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    if status == CHECK_PASS {
        if let Some(entries) = payload_object
            .get("source_artifacts")
            .and_then(Value::as_array)
        {
            for basename in spec.required_pass_source_artifacts {
                if !artifact_list_has_basename(entries, basename) {
                    problems.push(format!(
                        "source_artifacts must include measured evidence file {basename:?}"
                    ));
                }
            }
            for basename in spec
                .required_pass_source_artifacts
                .iter()
                .copied()
                .filter(|basename| basename.ends_with("_ssh_trust_summary.txt"))
            {
                match resolve_artifact_by_basename(report_path, entries, basename) {
                    Ok(Some(path)) => {
                        problems.extend(validate_ssh_trust_summary_artifact(path.as_path()))
                    }
                    Ok(None) => {}
                    Err(err) => problems.push(err),
                }
            }
            if spec.suite == "cross_network_remote_exit_soak" {
                match resolve_artifact_by_basename(
                    report_path,
                    entries,
                    "cross_network_remote_exit_soak_monitor_summary.json",
                ) {
                    Ok(Some(path)) => {
                        problems.extend(validate_soak_monitor_summary_artifact(path.as_path()))
                    }
                    Ok(None) => {}
                    Err(err) => problems.push(err),
                }
            }
        }
        if let Some(entries) = payload_object
            .get("log_artifacts")
            .and_then(Value::as_array)
        {
            for basename in spec.required_pass_log_artifacts {
                if !artifact_list_has_basename(entries, basename) {
                    problems.push(format!(
                        "log_artifacts must include measured evidence file {basename:?}"
                    ));
                }
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

fn normalize_required_nat_profiles(required_nat_profiles: &[String]) -> Vec<String> {
    if required_nat_profiles.is_empty() {
        return parse_csv_unique(DEFAULT_REQUIRED_NAT_PROFILES);
    }
    let joined = required_nat_profiles.join(",");
    let parsed = parse_csv_unique(&joined);
    if parsed.is_empty() {
        parse_csv_unique(DEFAULT_REQUIRED_NAT_PROFILES)
    } else {
        parsed
    }
}

fn validate_report_paths(
    report_paths: &[PathBuf],
    max_evidence_age_seconds: u64,
    expected_git_commit: Option<&str>,
    require_pass_status: bool,
) -> Vec<String> {
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
        if require_pass_status {
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

    errors
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

pub fn default_required_nat_profiles() -> Vec<String> {
    parse_csv_unique(DEFAULT_REQUIRED_NAT_PROFILES)
}

pub fn validate_cross_network_remote_exit_readiness(
    artifact_dir: &Path,
    max_evidence_age_seconds: u64,
    expected_git_commit: Option<&str>,
    required_nat_profiles: &[String],
) -> Result<(), String> {
    let report_paths = collect_report_paths(&[], Some(artifact_dir.to_path_buf()))?;
    let mut errors = validate_report_paths(
        &report_paths,
        max_evidence_age_seconds,
        expected_git_commit,
        true,
    );

    let matrix_paths = collect_matrix_paths(&[], Some(artifact_dir.to_path_buf()))?;
    let (records, matrix_errors) = discover_matrix_records(
        &matrix_paths,
        max_evidence_age_seconds,
        expected_git_commit,
        true,
    );
    errors.extend(matrix_errors);

    let normalized_profiles = normalize_required_nat_profiles(required_nat_profiles);
    errors.extend(validate_matrix(&records, &normalized_profiles));

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("\n"))
    }
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
    if let Some(path_evidence) = resolve_optional_path_evidence(
        &status,
        config.path_status_line,
        config.path_evidence_report,
    )? {
        payload
            .as_object_mut()
            .expect("payload object")
            .insert("path_evidence".to_string(), path_evidence);
    }
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
    let errors = validate_report_paths(
        &report_paths,
        config.max_evidence_age_seconds,
        expected_git_commit.as_deref(),
        config.require_pass_status,
    );

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
    let required_nat_profiles = normalize_required_nat_profiles(&config.required_nat_profiles);
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
        "direct_samples": config.direct_samples,
        "relay_samples": config.relay_samples,
        "fail_closed_samples": config.fail_closed_samples,
        "other_path_samples": config.other_path_samples,
        "path_transition_count": config.path_transition_count,
        "status_mismatch_samples": config.status_mismatch_samples,
        "route_mismatch_samples": config.route_mismatch_samples,
        "endpoint_mismatch_samples": config.endpoint_mismatch_samples,
        "dns_alarm_bad_samples": config.dns_alarm_bad_samples,
        "transport_identity_failures": config.transport_identity_failures,
        "endpoint_change_events_start": config.endpoint_change_events_start,
        "endpoint_change_events_end": config.endpoint_change_events_end,
        "endpoint_change_events_delta": config.endpoint_change_events_delta,
        "first_non_direct_reason": config.first_non_direct_reason,
        "last_path_mode": config.last_path_mode,
        "last_path_reason": config.last_path_reason,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    const TEST_GIT_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    static TEST_TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn create() -> Result<Self, String> {
            let path = std::env::temp_dir().join(format!(
                "rustynet-cross-network-tests-{}-{}-{}",
                std::process::id(),
                unix_now(),
                TEST_TEMP_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path)
                .map_err(|err| format!("create temp dir failed ({}): {err}", path.display()))?;
            Ok(Self { path })
        }

        fn path(&self) -> &Path {
            self.path.as_path()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    fn report_payload_for_test(
        spec: &CrossNetworkReportSpec,
        artifact_dir: &Path,
        status: &str,
    ) -> Result<Value, String> {
        let source_path = artifact_dir.join(format!("{}_source.txt", spec.suite));
        let log_path = artifact_dir.join(format!("{}_log.txt", spec.suite));
        fs::write(&source_path, "measured source\n")
            .map_err(|err| format!("write source artifact failed: {err}"))?;
        fs::write(&log_path, "measured log\n")
            .map_err(|err| format!("write log artifact failed: {err}"))?;
        let mut source_artifacts = vec![source_path.display().to_string()];
        let mut log_artifacts = vec![log_path.display().to_string()];
        for basename in spec.required_pass_source_artifacts {
            let artifact_path = artifact_dir.join(basename);
            write_test_source_artifact(spec, artifact_path.as_path(), basename)?;
            source_artifacts.push(artifact_path.display().to_string());
        }
        for basename in spec.required_pass_log_artifacts {
            let artifact_path = artifact_dir.join(basename);
            fs::write(&artifact_path, format!("measured {basename}\n")).map_err(|err| {
                format!(
                    "write log artifact failed ({}): {err}",
                    artifact_path.display()
                )
            })?;
            log_artifacts.push(artifact_path.display().to_string());
        }

        let mut participants = Map::new();
        for field in spec.required_participants {
            participants.insert(
                (*field).to_string(),
                Value::String(format!("{field}-value")),
            );
        }

        let mut network_context = Map::new();
        network_context.insert(
            "client_network_id".to_string(),
            Value::String("net-client".to_string()),
        );
        network_context.insert(
            "exit_network_id".to_string(),
            Value::String("net-exit".to_string()),
        );
        network_context.insert(
            "nat_profile".to_string(),
            Value::String("baseline_lan".to_string()),
        );
        network_context.insert(
            "impairment_profile".to_string(),
            Value::String("none".to_string()),
        );
        if spec.required_network_fields.contains(&"relay_network_id") {
            network_context.insert(
                "relay_network_id".to_string(),
                Value::String("net-relay".to_string()),
            );
        }

        let mut checks = Map::new();
        for check in spec.required_checks {
            checks.insert((*check).to_string(), Value::String(CHECK_PASS.to_string()));
        }

        let path_mode = match spec.suite {
            "cross_network_direct_remote_exit" => "direct_active",
            "cross_network_relay_remote_exit" => "relay_active",
            "cross_network_failback_roaming" => "direct_active",
            _ => "direct_active",
        };
        let path_programmed_mode = match spec.suite {
            "cross_network_relay_remote_exit" => "relay_programmed",
            _ => "direct_programmed",
        };
        let relay_session_state = if spec.suite == "cross_network_relay_remote_exit" {
            "live"
        } else {
            "unused"
        };

        let mut payload = json!({
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE_NAME,
            "suite": spec.suite,
            "environment": "unit_test",
            "evidence_mode": EVIDENCE_MODE,
            "captured_at_unix": unix_now(),
            "git_commit": TEST_GIT_COMMIT,
            "status": status,
            "participants": Value::Object(participants),
            "network_context": Value::Object(network_context),
            "checks": Value::Object(checks),
            "source_artifacts": source_artifacts,
            "log_artifacts": log_artifacts,
            "implementation_state": "live_measured_validator",
        });
        if status == CHECK_PASS && spec.suite != "cross_network_traversal_adversarial" {
            payload.as_object_mut().expect("payload object").insert(
                "path_evidence".to_string(),
                json!({
                    "path_mode": path_mode,
                    "path_reason": "fresh_handshake_observed",
                    "path_programmed_mode": path_programmed_mode,
                    "path_live_proven": true,
                    "path_latest_live_handshake_unix": unix_now(),
                    "relay_session_state": relay_session_state,
                    "traversal_alarm_state": "ok",
                    "traversal_alarm_reason": "none",
                    "dns_alarm_state": "ok",
                    "dns_alarm_reason": "none",
                    "traversal_error": "none",
                    "transport_socket_identity_state": "authoritative_backend_shared_transport",
                    "transport_socket_identity_error": "none",
                    "transport_socket_identity_label": "udp4:51820",
                    "transport_socket_identity_local_addr": "192.0.2.10:51820",
                    "traversal_probe_result": "pass",
                    "traversal_probe_reason": "fresh_handshake_observed",
                    "traversal_endpoint_change_events": 0,
                    "stun_transport_port_binding": "192.0.2.10:51820",
                }),
            );
        }
        if status == CHECK_FAIL {
            payload.as_object_mut().expect("payload object").insert(
                "failure_summary".to_string(),
                Value::String("simulated failure".to_string()),
            );
        }
        Ok(payload)
    }

    fn write_test_source_artifact(
        spec: &CrossNetworkReportSpec,
        artifact_path: &Path,
        basename: &str,
    ) -> Result<(), String> {
        let artifact_body = if basename.ends_with("_ssh_trust_summary.txt") {
            let target_count = spec.required_participants.len();
            let mut lines = vec![
                "schema_version=1".to_string(),
                format!("generated_at_unix={}", unix_now()),
                "pinned_known_hosts_file=/tmp/rustynet-known_hosts".to_string(),
                format!("pinned_known_hosts_sha256={}", "b".repeat(64)),
                format!("target_count={target_count}"),
            ];
            for index in 0..target_count {
                lines.push(format!("target[{index}].target=host-{index}"));
                lines.push(format!("target[{index}].configured_transport=utm"));
                lines.push(format!(
                    "target[{index}].checked_candidates=host-{index},192.0.2.{}",
                    index + 10
                ));
                lines.push(format!("target[{index}].matched_candidate=host-{index}"));
                lines.push(format!("target[{index}].host_key_status=pass"));
                lines.push(format!("target[{index}].passwordless_sudo_status=pass"));
            }
            lines.push("all_targets_pinned=true".to_string());
            lines.push("all_targets_passwordless_sudo=true".to_string());
            format!("{}\n", lines.join("\n"))
        } else if basename == "cross_network_remote_exit_soak_monitor_summary.json" {
            serde_json::to_string_pretty(&json!({
                "samples": 24,
                "failing_samples": 0,
                "max_consecutive_failures_observed": 0,
                "elapsed_secs": 120,
                "required_soak_duration_secs": 120,
                "allowed_failing_samples": 2,
                "allowed_max_consecutive_failures": 1,
                "direct_remote_exit_ready": "pass",
                "post_soak_bypass_ready": "pass",
                "no_plaintext_passphrase_files": "pass",
                "direct_samples": 24,
                "relay_samples": 0,
                "fail_closed_samples": 0,
                "other_path_samples": 0,
                "path_transition_count": 0,
                "status_mismatch_samples": 0,
                "route_mismatch_samples": 0,
                "endpoint_mismatch_samples": 0,
                "dns_alarm_bad_samples": 0,
                "transport_identity_failures": 0,
                "endpoint_change_events_start": 1,
                "endpoint_change_events_end": 1,
                "endpoint_change_events_delta": 0,
                "first_non_direct_reason": "none",
                "last_path_mode": "direct_active",
                "last_path_reason": "fresh_handshake_observed",
                "first_failure_reason": "none",
                "long_soak_stable": "pass",
            }))
            .map(|rendered| format!("{rendered}\n"))
            .map_err(|err| format!("serialize soak monitor summary failed: {err}"))?
        } else if basename.ends_with(".json") {
            "{\n  \"status\": \"pass\"\n}\n".to_string()
        } else {
            format!("measured {basename}\n")
        };
        fs::write(artifact_path, artifact_body).map_err(|err| {
            format!(
                "write source artifact failed ({}): {err}",
                artifact_path.display()
            )
        })
    }

    fn write_valid_report(artifact_dir: &Path, suite: &str) -> Result<PathBuf, String> {
        let spec = report_spec_by_suite(suite).ok_or_else(|| format!("unknown suite {suite}"))?;
        let report_path = artifact_dir.join(spec.filename);
        let payload = report_payload_for_test(spec, artifact_dir, CHECK_PASS)?;
        let rendered = serde_json::to_string_pretty(&payload)
            .map_err(|err| format!("serialize test report failed: {err}"))?;
        fs::write(&report_path, format!("{rendered}\n")).map_err(|err| {
            format!(
                "write test report failed ({}): {err}",
                report_path.display()
            )
        })?;
        Ok(report_path)
    }

    #[test]
    fn validate_report_payload_rejects_pass_status_with_failed_required_check() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_direct_remote_exit").expect("direct spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let mut payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        payload["checks"]["direct_remote_exit_success"] = Value::String(CHECK_FAIL.to_string());

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "status=pass requires all required checks to pass; failing checks: direct_remote_exit_success"
            )),
            "expected pass-with-failing-check error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_cross_network_remote_exit_readiness_rejects_missing_canonical_reports() {
        let temp_dir = TempDir::create().expect("temp dir");
        let err = validate_cross_network_remote_exit_readiness(
            temp_dir.path(),
            60,
            Some(TEST_GIT_COMMIT),
            &default_required_nat_profiles(),
        )
        .expect_err("missing canonical reports must fail");

        assert!(
            err.contains("cross_network_direct_remote_exit_report.json: missing report file"),
            "expected missing canonical direct report error, got: {err}"
        );
        assert!(
            err.contains(
                "missing matrix evidence: suite=cross_network_direct_remote_exit nat_profile=baseline_lan"
            ),
            "expected missing matrix coverage error, got: {err}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_pass_status_without_live_path_evidence() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_direct_remote_exit").expect("direct spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let mut payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        payload
            .as_object_mut()
            .expect("payload object")
            .remove("path_evidence");

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors
                .iter()
                .any(|entry| entry.contains("path_evidence must be present")),
            "expected missing path evidence error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_cross_network_remote_exit_readiness_accepts_complete_canonical_reports() {
        let temp_dir = TempDir::create().expect("temp dir");
        for spec in REPORT_SPECS {
            write_valid_report(temp_dir.path(), spec.suite).expect("write valid report");
        }

        validate_cross_network_remote_exit_readiness(
            temp_dir.path(),
            60,
            Some(TEST_GIT_COMMIT),
            &default_required_nat_profiles(),
        )
        .expect("complete canonical reports should validate");
    }

    #[test]
    fn generate_fail_report_ignores_missing_inherited_path_evidence() {
        let temp_dir = TempDir::create().expect("temp dir");
        let child_report_path = temp_dir.path().join("child-fail-report.json");
        let source_path = temp_dir.path().join("source.log");
        let log_path = temp_dir.path().join("parent.log");
        let report_path = temp_dir.path().join("parent-report.json");
        fs::write(&source_path, "source\n").expect("write source artifact");
        fs::write(&child_report_path, "{\n  \"status\": \"fail\"\n}\n")
            .expect("write child fail report");

        let config = GenerateCrossNetworkRemoteExitReportConfig {
            suite: "cross_network_remote_exit_dns".to_string(),
            report_path: report_path.clone(),
            log_path,
            status: CHECK_FAIL.to_string(),
            failure_summary: "direct child failed before live path proof".to_string(),
            environment: "unit_test".to_string(),
            implementation_state: "live_measured_validator".to_string(),
            source_artifacts: vec![source_path],
            log_artifacts: Vec::new(),
            client_host: Some("client-host".to_string()),
            exit_host: Some("exit-host".to_string()),
            relay_host: None,
            probe_host: None,
            client_network_id: Some("client-net".to_string()),
            exit_network_id: Some("exit-net".to_string()),
            relay_network_id: None,
            nat_profile: "baseline_lan".to_string(),
            impairment_profile: "none".to_string(),
            check_overrides: Vec::new(),
            path_status_line: None,
            path_evidence_report: Some(child_report_path),
        };

        execute_ops_generate_cross_network_remote_exit_report(config)
            .expect("fail report should still be written");

        let payload = parse_report_payload(report_path.as_path()).expect("parse generated report");
        assert_eq!(
            payload
                .get("status")
                .and_then(Value::as_str)
                .expect("status should be present"),
            CHECK_FAIL
        );
        assert!(
            payload.get("path_evidence").is_none(),
            "fail report should omit inherited path evidence when child evidence is unavailable"
        );
    }

    #[test]
    fn generate_pass_report_rejects_missing_inherited_path_evidence() {
        let temp_dir = TempDir::create().expect("temp dir");
        let child_report_path = temp_dir.path().join("child-fail-report.json");
        let source_path = temp_dir.path().join("source.log");
        let log_path = temp_dir.path().join("parent.log");
        let report_path = temp_dir.path().join("parent-report.json");
        let direct_report_path = temp_dir
            .path()
            .join("cross_network_remote_exit_dns_direct_remote_exit_report.json");
        let direct_log_path = temp_dir
            .path()
            .join("cross_network_remote_exit_dns_direct_remote_exit.log");
        let managed_dns_report_path = temp_dir
            .path()
            .join("cross_network_remote_exit_dns_managed_dns_report.json");
        let managed_dns_log_path = temp_dir
            .path()
            .join("cross_network_remote_exit_dns_managed_dns.log");
        fs::write(&source_path, "source\n").expect("write source artifact");
        fs::write(&child_report_path, "{\n  \"status\": \"fail\"\n}\n")
            .expect("write child fail report");
        fs::write(&direct_report_path, "child direct report\n").expect("write child direct report");
        fs::write(&direct_log_path, "child direct log\n").expect("write child direct log");
        fs::write(&managed_dns_report_path, "managed dns report\n")
            .expect("write managed dns report");
        fs::write(&managed_dns_log_path, "managed dns log\n").expect("write managed dns log");

        let config = GenerateCrossNetworkRemoteExitReportConfig {
            suite: "cross_network_remote_exit_dns".to_string(),
            report_path,
            log_path,
            status: CHECK_PASS.to_string(),
            failure_summary: String::new(),
            environment: "unit_test".to_string(),
            implementation_state: "live_measured_validator".to_string(),
            source_artifacts: vec![source_path, direct_report_path, managed_dns_report_path],
            log_artifacts: vec![direct_log_path, managed_dns_log_path],
            client_host: Some("client-host".to_string()),
            exit_host: Some("exit-host".to_string()),
            relay_host: None,
            probe_host: None,
            client_network_id: Some("client-net".to_string()),
            exit_network_id: Some("exit-net".to_string()),
            relay_network_id: None,
            nat_profile: "baseline_lan".to_string(),
            impairment_profile: "none".to_string(),
            check_overrides: vec![
                "managed_dns_resolution_success=pass".to_string(),
                "remote_exit_dns_fail_closed=pass".to_string(),
                "remote_exit_no_underlay_leak=pass".to_string(),
            ],
            path_status_line: None,
            path_evidence_report: Some(child_report_path),
        };

        let err = execute_ops_generate_cross_network_remote_exit_report(config)
            .expect_err("pass report must reject missing inherited live path evidence");
        assert!(
            err.contains("report is missing path_evidence"),
            "expected inherited path evidence failure, got: {err}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_failback_pass_without_measured_child_artifacts() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_failback_roaming").expect("failback spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let mut payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        let source_artifacts = payload
            .as_object_mut()
            .expect("payload object")
            .get_mut("source_artifacts")
            .and_then(Value::as_array_mut)
            .expect("source artifacts array");
        source_artifacts.retain(|entry| {
            let Some(raw_path) = entry.as_str() else {
                return true;
            };
            !raw_path.ends_with("cross_network_failback_roaming_relay_stage_report.json")
        });

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "source_artifacts must include measured evidence file \"cross_network_failback_roaming_relay_stage_report.json\""
            )),
            "expected missing failback child artifact error, got: {errors:?}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_pass_status_without_authoritative_transport_identity() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_direct_remote_exit").expect("direct spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let mut payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        payload["path_evidence"]["transport_socket_identity_state"] =
            Value::String("blocked_backend_opaque_socket".to_string());

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "path_evidence.transport_socket_identity_state must equal authoritative_backend_shared_transport"
            )),
            "expected authoritative shared transport rejection, got: {errors:?}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_pass_status_with_failed_ssh_trust_summary() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_direct_remote_exit").expect("direct spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        let trust_summary_path = temp_dir
            .path()
            .join("cross_network_direct_remote_exit_ssh_trust_summary.txt");
        let summary = fs::read_to_string(&trust_summary_path).expect("read trust summary");
        let summary = summary.replace("all_targets_pinned=true", "all_targets_pinned=false");
        fs::write(&trust_summary_path, summary).expect("rewrite trust summary");

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors
                .iter()
                .any(|entry| entry.contains("all_targets_pinned must equal true")),
            "expected failed SSH trust summary rejection, got: {errors:?}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_soak_pass_with_non_direct_samples() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_remote_exit_soak").expect("soak spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        let soak_summary_path = temp_dir
            .path()
            .join("cross_network_remote_exit_soak_monitor_summary.json");
        let mut soak_summary =
            parse_json_object_file(soak_summary_path.as_path(), "soak monitor summary")
                .expect("parse soak summary");
        soak_summary.insert("direct_samples".to_string(), Value::from(23u64));
        soak_summary.insert("relay_samples".to_string(), Value::from(1u64));
        soak_summary.insert(
            "first_non_direct_reason".to_string(),
            Value::String("relay_selected_no_direct_candidate".to_string()),
        );
        fs::write(
            &soak_summary_path,
            format!(
                "{}\n",
                serde_json::to_string_pretty(&Value::Object(soak_summary))
                    .expect("serialize soak summary")
            ),
        )
        .expect("rewrite soak summary");

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "relay_samples must equal 0 for authoritative direct-path soak evidence"
            )),
            "expected soak relay-sample rejection, got: {errors:?}"
        );
    }

    #[test]
    fn validate_report_payload_rejects_pass_status_with_critical_path_alarm() {
        let temp_dir = TempDir::create().expect("temp dir");
        let spec =
            report_spec_by_suite("cross_network_direct_remote_exit").expect("direct spec exists");
        let report_path = temp_dir.path().join(spec.filename);
        let mut payload =
            report_payload_for_test(spec, temp_dir.path(), CHECK_PASS).expect("test payload");
        payload
            .as_object_mut()
            .expect("payload object")
            .get_mut("path_evidence")
            .and_then(Value::as_object_mut)
            .expect("path evidence object")
            .insert(
                "traversal_alarm_state".to_string(),
                Value::String("critical".to_string()),
            );

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "path_evidence.traversal_alarm_state must not be critical|error|missing for pass reports"
            )),
            "expected critical traversal alarm rejection, got: {errors:?}"
        );
    }
}
