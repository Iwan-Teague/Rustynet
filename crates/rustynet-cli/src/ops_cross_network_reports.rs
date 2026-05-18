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
            Some(trimmed.to_owned())
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
        .ok_or_else(|| "status line missing path_mode".to_owned())?;
    let path_reason = extract_inline_field(status_line, "path_reason")
        .ok_or_else(|| "status line missing path_reason".to_owned())?;
    let path_programmed_mode = extract_inline_field(status_line, "path_programmed_mode")
        .ok_or_else(|| "status line missing path_programmed_mode".to_owned())?;
    let transport_socket_identity_state =
        extract_inline_field(status_line, "transport_socket_identity_state")
            .ok_or_else(|| "status line missing transport_socket_identity_state".to_owned())?;
    let transport_socket_identity_error =
        extract_inline_field(status_line, "transport_socket_identity_error")
            .ok_or_else(|| "status line missing transport_socket_identity_error".to_owned())?;
    let path_live_proven = match extract_inline_field(status_line, "path_live_proven")
        .ok_or_else(|| "status line missing path_live_proven".to_owned())?
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
        return Err("resolve git commit failed: empty output".to_owned());
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
        overrides.insert(key.to_owned(), value.to_owned());
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
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
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
            Some(trimmed.to_owned())
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
            .insert(key.to_owned(), raw_value.trim().to_owned())
            .is_some()
        {
            return Err(format!("{}: duplicate key {:?}", path.display(), key));
        }
    }
    Ok(out)
}

/// X2: Phase A typed view for the SSH trust summary artifact. Unlike
/// the soak-monitor and report-payload views (which deserialize JSON),
/// this artifact is the key=value text format produced by
/// `parse_key_value_artifact`. The typed view is therefore populated
/// field-by-field from the parsed `HashMap<String, String>` rather than
/// via `serde_json::from_value`, but the contract goal is identical:
/// pin every required scalar (schema_version, the two pinned-known-
/// hosts fields, the two all-targets flags, target_count) and every
/// per-target scalar (target, configured_transport, checked_candidates,
/// matched_candidate, host_key_status, passwordless_sudo_status) into a
/// typed slot so downstream walkers no longer rely on raw `HashMap`
/// lookups by stringly-typed keys.
///
/// Required string fields are stored as `Option<String>` so the
/// validator can preserve the existing per-field "must be a non-empty
/// string" / "must equal ..." error messages instead of bailing on the
/// first missing key. `target_count` is `Option<usize>` because the
/// validator must distinguish "missing/non-integer" from "zero". Any
/// key not consumed by a typed slot rides through `extra` so callers
/// can still inspect forward-compatible additions.
#[derive(Debug, Clone, Default)]
struct CrossNetworkSshTrustSummaryView {
    schema_version: Option<String>,
    pinned_known_hosts_file: Option<String>,
    pinned_known_hosts_sha256: Option<String>,
    all_targets_pinned: Option<String>,
    all_targets_passwordless_sudo: Option<String>,
    target_count: Option<usize>,
    /// Raw `target_count` value as it appeared in the artifact, kept
    /// so the validator can disambiguate "key missing/invalid" from
    /// "key parsed to zero".
    target_count_raw: Option<String>,
    targets: Vec<CrossNetworkSshTrustTargetView>,
    /// Extra (non-required) keys carried through verbatim. Round-tripped
    /// by `into_key_value_map`.
    #[allow(dead_code)]
    extra: HashMap<String, String>,
}

#[derive(Debug, Clone, Default)]
struct CrossNetworkSshTrustTargetView {
    target: Option<String>,
    configured_transport: Option<String>,
    checked_candidates: Option<String>,
    matched_candidate: Option<String>,
    host_key_status: Option<String>,
    passwordless_sudo_status: Option<String>,
}

impl CrossNetworkSshTrustSummaryView {
    /// Populate the typed view from the raw key=value HashMap. Each
    /// required scalar is moved into its typed slot; per-target fields
    /// are pulled by `target[N].<field>` until `target_count` slots are
    /// filled. Anything left in the HashMap that wasn't consumed flows
    /// into `extra` so downstream walkers see forward-compatible keys.
    ///
    /// Empty strings are treated as `None` so the validator can emit
    /// the existing "must be a non-empty string" message uniformly for
    /// both "key missing" and "key present but blank".
    fn from_key_value(mut summary: HashMap<String, String>) -> Self {
        fn take_non_empty(map: &mut HashMap<String, String>, key: &str) -> Option<String> {
            map.remove(key)
                .and_then(|value| (!value.trim().is_empty()).then_some(value))
        }

        let schema_version = take_non_empty(&mut summary, "schema_version");
        let pinned_known_hosts_file = take_non_empty(&mut summary, "pinned_known_hosts_file");
        let pinned_known_hosts_sha256 = take_non_empty(&mut summary, "pinned_known_hosts_sha256");
        let all_targets_pinned = take_non_empty(&mut summary, "all_targets_pinned");
        let all_targets_passwordless_sudo =
            take_non_empty(&mut summary, "all_targets_passwordless_sudo");
        let target_count_raw = summary.remove("target_count");
        let target_count = target_count_raw
            .as_deref()
            .and_then(|value| value.trim().parse::<usize>().ok());

        let mut targets = Vec::new();
        if let Some(count) = target_count {
            for index in 0..count {
                let target_key = format!("target[{index}].target");
                let configured_transport_key = format!("target[{index}].configured_transport");
                let checked_candidates_key = format!("target[{index}].checked_candidates");
                let matched_candidate_key = format!("target[{index}].matched_candidate");
                let host_key_status_key = format!("target[{index}].host_key_status");
                let passwordless_sudo_status_key =
                    format!("target[{index}].passwordless_sudo_status");
                targets.push(CrossNetworkSshTrustTargetView {
                    target: take_non_empty(&mut summary, target_key.as_str()),
                    configured_transport: take_non_empty(
                        &mut summary,
                        configured_transport_key.as_str(),
                    ),
                    checked_candidates: take_non_empty(
                        &mut summary,
                        checked_candidates_key.as_str(),
                    ),
                    matched_candidate: take_non_empty(&mut summary, matched_candidate_key.as_str()),
                    host_key_status: take_non_empty(&mut summary, host_key_status_key.as_str()),
                    passwordless_sudo_status: take_non_empty(
                        &mut summary,
                        passwordless_sudo_status_key.as_str(),
                    ),
                });
            }
        }

        Self {
            schema_version,
            pinned_known_hosts_file,
            pinned_known_hosts_sha256,
            all_targets_pinned,
            all_targets_passwordless_sudo,
            target_count,
            target_count_raw,
            targets,
            extra: summary,
        }
    }

    /// Bridge the typed view back to a `HashMap<String, String>` for
    /// any downstream helper that still walks the SSH trust summary
    /// generically. Re-injects every typed scalar and every per-target
    /// scalar at its original key, so the round-tripped map is
    /// indistinguishable from the original parse modulo dropped
    /// blank/empty fields (which the typed view treats as `None`).
    /// Exercised by the typed-view round-trip test.
    #[allow(dead_code)]
    fn into_key_value_map(self) -> HashMap<String, String> {
        let mut m = self.extra;
        if let Some(value) = self.schema_version {
            m.insert("schema_version".to_owned(), value);
        }
        if let Some(value) = self.pinned_known_hosts_file {
            m.insert("pinned_known_hosts_file".to_owned(), value);
        }
        if let Some(value) = self.pinned_known_hosts_sha256 {
            m.insert("pinned_known_hosts_sha256".to_owned(), value);
        }
        if let Some(value) = self.all_targets_pinned {
            m.insert("all_targets_pinned".to_owned(), value);
        }
        if let Some(value) = self.all_targets_passwordless_sudo {
            m.insert("all_targets_passwordless_sudo".to_owned(), value);
        }
        if let Some(value) = self.target_count_raw {
            m.insert("target_count".to_owned(), value);
        } else if let Some(count) = self.target_count {
            m.insert("target_count".to_owned(), count.to_string());
        }
        for (index, target) in self.targets.into_iter().enumerate() {
            if let Some(value) = target.target {
                m.insert(format!("target[{index}].target"), value);
            }
            if let Some(value) = target.configured_transport {
                m.insert(format!("target[{index}].configured_transport"), value);
            }
            if let Some(value) = target.checked_candidates {
                m.insert(format!("target[{index}].checked_candidates"), value);
            }
            if let Some(value) = target.matched_candidate {
                m.insert(format!("target[{index}].matched_candidate"), value);
            }
            if let Some(value) = target.host_key_status {
                m.insert(format!("target[{index}].host_key_status"), value);
            }
            if let Some(value) = target.passwordless_sudo_status {
                m.insert(format!("target[{index}].passwordless_sudo_status"), value);
            }
        }
        m
    }
}

fn validate_ssh_trust_summary_artifact(path: &Path) -> Vec<String> {
    // X2: Phase A typed view migration. The SSH trust summary now
    // flows through `CrossNetworkSshTrustSummaryView::from_key_value`,
    // which pins every required scalar (top-level + per-target) into a
    // typed slot. The validator then drives every error message off
    // typed fields rather than raw HashMap key lookups.
    let mut problems = Vec::new();
    let summary = match parse_key_value_artifact(path) {
        Ok(summary) => summary,
        Err(err) => return vec![err],
    };
    let view = CrossNetworkSshTrustSummaryView::from_key_value(summary);

    if view.schema_version.as_deref() != Some("1") {
        problems.push(format!("{}: schema_version must equal 1", path.display()));
    }
    if view.pinned_known_hosts_file.is_none() {
        problems.push(format!(
            "{}: pinned_known_hosts_file must be a non-empty string",
            path.display()
        ));
    }
    if view.pinned_known_hosts_sha256.is_none() {
        problems.push(format!(
            "{}: pinned_known_hosts_sha256 must be a non-empty string",
            path.display()
        ));
    }
    if view
        .pinned_known_hosts_sha256
        .as_deref()
        .is_some_and(|value| {
            value.len() != 64
                || !value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        problems.push(format!(
            "{}: pinned_known_hosts_sha256 must be a 64-character lowercase hex digest",
            path.display()
        ));
    }
    if view.all_targets_pinned.as_deref() != Some("true") {
        problems.push(format!(
            "{}: all_targets_pinned must equal true",
            path.display()
        ));
    }
    if view.all_targets_passwordless_sudo.as_deref() != Some("true") {
        problems.push(format!(
            "{}: all_targets_passwordless_sudo must equal true",
            path.display()
        ));
    }

    let Some(target_count) = view.target_count else {
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

    for (index, target) in view.targets.iter().enumerate() {
        let target_key = format!("target[{index}].target");
        let checked_candidates_key = format!("target[{index}].checked_candidates");
        let matched_candidate_key = format!("target[{index}].matched_candidate");
        let host_key_status_key = format!("target[{index}].host_key_status");
        let passwordless_sudo_status_key = format!("target[{index}].passwordless_sudo_status");
        let configured_transport_key = format!("target[{index}].configured_transport");

        if target.checked_candidates.is_none() {
            problems.push(format!(
                "{}: {checked_candidates_key} must be a non-empty string",
                path.display()
            ));
        }
        if target.matched_candidate.is_none() {
            problems.push(format!(
                "{}: {matched_candidate_key} must be a non-empty string",
                path.display()
            ));
        }
        if target.target.is_none() {
            problems.push(format!(
                "{}: {target_key} must be a non-empty string",
                path.display()
            ));
        }
        if target.configured_transport.is_none() {
            problems.push(format!(
                "{}: {configured_transport_key} must be a non-empty string",
                path.display()
            ));
        }
        if target
            .configured_transport
            .as_deref()
            .is_some_and(|value| !matches!(value, "ssh" | "utm"))
        {
            problems.push(format!(
                "{}: {configured_transport_key} must equal ssh or utm",
                path.display()
            ));
        }
        if target.host_key_status.as_deref() != Some(CHECK_PASS) {
            problems.push(format!(
                "{}: {host_key_status_key} must equal pass",
                path.display()
            ));
        }
        if target.passwordless_sudo_status.as_deref() != Some(CHECK_PASS) {
            problems.push(format!(
                "{}: {passwordless_sudo_status_key} must equal pass",
                path.display()
            ));
        }
        if let (Some(checked_candidates), Some(matched_candidate)) = (
            target.checked_candidates.as_deref(),
            target.matched_candidate.as_deref(),
        ) {
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

#[cfg(test)]
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

/// X2: Phase A typed view for the soak-monitor summary artifact. The
/// reviewed contract pins every required scalar with serde
/// required-field semantics, so missing fields and wrong-type fields
/// (e.g. a stringified counter) fail at deserialize with a precise
/// per-field error rather than silently flowing through
/// `as_u64()`/`as_str()` returning `None`.
///
/// All 19 required counters are typed `u64` and all 8 required status
/// strings are typed `String`. Cross-field invariants (sum of path
/// modes == samples, end >= start, `direct_remote_exit_ready == pass`,
/// etc.) are still enforced by `validate_soak_monitor_summary_artifact`
/// using the typed fields directly.
///
/// Any extra keys in the artifact ride through `#[serde(flatten)]
/// extra` and `into_value_map` re-injects the typed fields so any
/// downstream Map walker keeps working.
#[derive(Debug, Clone, serde::Deserialize)]
struct CrossNetworkSoakMonitorSummaryView {
    samples: u64,
    failing_samples: u64,
    max_consecutive_failures_observed: u64,
    elapsed_secs: u64,
    required_soak_duration_secs: u64,
    allowed_failing_samples: u64,
    allowed_max_consecutive_failures: u64,
    direct_samples: u64,
    relay_samples: u64,
    fail_closed_samples: u64,
    other_path_samples: u64,
    path_transition_count: u64,
    status_mismatch_samples: u64,
    route_mismatch_samples: u64,
    endpoint_mismatch_samples: u64,
    dns_alarm_bad_samples: u64,
    transport_identity_failures: u64,
    endpoint_change_events_start: u64,
    endpoint_change_events_end: u64,
    endpoint_change_events_delta: u64,
    direct_remote_exit_ready: String,
    post_soak_bypass_ready: String,
    no_plaintext_passphrase_files: String,
    first_non_direct_reason: String,
    first_failure_reason: String,
    last_path_mode: String,
    last_path_reason: String,
    long_soak_stable: String,
    // Extra (non-required) keys ride through `#[serde(flatten)]` so the
    // soak summary may evolve forward-compatibly. The current
    // validator drives every assertion from the typed fields above, so
    // `extra` is observed only by tests via `into_value_map`.
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

impl CrossNetworkSoakMonitorSummaryView {
    /// Bridge the typed view back to a `Map<String, Value>` for any
    /// downstream helper that still walks the soak monitor summary
    /// generically. Re-injects every typed field so callers observe the
    /// full artifact shape. Exercised by the typed-view round-trip test.
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert("samples".to_owned(), Value::Number(self.samples.into()));
        m.insert(
            "failing_samples".to_owned(),
            Value::Number(self.failing_samples.into()),
        );
        m.insert(
            "max_consecutive_failures_observed".to_owned(),
            Value::Number(self.max_consecutive_failures_observed.into()),
        );
        m.insert(
            "elapsed_secs".to_owned(),
            Value::Number(self.elapsed_secs.into()),
        );
        m.insert(
            "required_soak_duration_secs".to_owned(),
            Value::Number(self.required_soak_duration_secs.into()),
        );
        m.insert(
            "allowed_failing_samples".to_owned(),
            Value::Number(self.allowed_failing_samples.into()),
        );
        m.insert(
            "allowed_max_consecutive_failures".to_owned(),
            Value::Number(self.allowed_max_consecutive_failures.into()),
        );
        m.insert(
            "direct_samples".to_owned(),
            Value::Number(self.direct_samples.into()),
        );
        m.insert(
            "relay_samples".to_owned(),
            Value::Number(self.relay_samples.into()),
        );
        m.insert(
            "fail_closed_samples".to_owned(),
            Value::Number(self.fail_closed_samples.into()),
        );
        m.insert(
            "other_path_samples".to_owned(),
            Value::Number(self.other_path_samples.into()),
        );
        m.insert(
            "path_transition_count".to_owned(),
            Value::Number(self.path_transition_count.into()),
        );
        m.insert(
            "status_mismatch_samples".to_owned(),
            Value::Number(self.status_mismatch_samples.into()),
        );
        m.insert(
            "route_mismatch_samples".to_owned(),
            Value::Number(self.route_mismatch_samples.into()),
        );
        m.insert(
            "endpoint_mismatch_samples".to_owned(),
            Value::Number(self.endpoint_mismatch_samples.into()),
        );
        m.insert(
            "dns_alarm_bad_samples".to_owned(),
            Value::Number(self.dns_alarm_bad_samples.into()),
        );
        m.insert(
            "transport_identity_failures".to_owned(),
            Value::Number(self.transport_identity_failures.into()),
        );
        m.insert(
            "endpoint_change_events_start".to_owned(),
            Value::Number(self.endpoint_change_events_start.into()),
        );
        m.insert(
            "endpoint_change_events_end".to_owned(),
            Value::Number(self.endpoint_change_events_end.into()),
        );
        m.insert(
            "endpoint_change_events_delta".to_owned(),
            Value::Number(self.endpoint_change_events_delta.into()),
        );
        m.insert(
            "direct_remote_exit_ready".to_owned(),
            Value::String(self.direct_remote_exit_ready),
        );
        m.insert(
            "post_soak_bypass_ready".to_owned(),
            Value::String(self.post_soak_bypass_ready),
        );
        m.insert(
            "no_plaintext_passphrase_files".to_owned(),
            Value::String(self.no_plaintext_passphrase_files),
        );
        m.insert(
            "first_non_direct_reason".to_owned(),
            Value::String(self.first_non_direct_reason),
        );
        m.insert(
            "first_failure_reason".to_owned(),
            Value::String(self.first_failure_reason),
        );
        m.insert(
            "last_path_mode".to_owned(),
            Value::String(self.last_path_mode),
        );
        m.insert(
            "last_path_reason".to_owned(),
            Value::String(self.last_path_reason),
        );
        m.insert(
            "long_soak_stable".to_owned(),
            Value::String(self.long_soak_stable),
        );
        m
    }
}

fn validate_soak_monitor_summary_artifact(path: &Path) -> Vec<String> {
    // X2: Phase A typed view migration. The soak monitor summary now
    // parses through `CrossNetworkSoakMonitorSummaryView`, which pins
    // every required counter and status with serde required-field
    // semantics. A missing or wrong-type required field fails here at
    // deserialize with a precise error rather than falling through to
    // many follow-up "must be ..." problems from `as_u64()`/`as_str()`
    // returning `None`.
    let body = match fs::read_to_string(path) {
        Ok(body) => body,
        Err(err) => {
            return vec![format!(
                "{}: read soak monitor summary failed: {err}",
                path.display()
            )];
        }
    };
    let typed: CrossNetworkSoakMonitorSummaryView = match serde_json::from_str(&body) {
        Ok(view) => view,
        Err(err) => {
            return vec![format!(
                "{}: invalid soak monitor summary ({err})",
                path.display()
            )];
        }
    };

    let mut problems = Vec::new();

    if typed.direct_samples
        + typed.relay_samples
        + typed.fail_closed_samples
        + typed.other_path_samples
        != typed.samples
    {
        problems.push(format!(
            "{}: direct/relay/fail_closed/other sample counts must sum to samples",
            path.display()
        ));
    }
    if typed.endpoint_change_events_end < typed.endpoint_change_events_start {
        problems.push(format!(
            "{}: endpoint_change_events_end must be >= endpoint_change_events_start",
            path.display()
        ));
    }
    if typed
        .endpoint_change_events_end
        .saturating_sub(typed.endpoint_change_events_start)
        != typed.endpoint_change_events_delta
    {
        problems.push(format!(
            "{}: endpoint_change_events_delta must equal end-start",
            path.display()
        ));
    }

    if typed.elapsed_secs < typed.required_soak_duration_secs {
        problems.push(format!(
            "{}: elapsed_secs must be >= required_soak_duration_secs",
            path.display()
        ));
    }
    if typed.failing_samples > typed.allowed_failing_samples {
        problems.push(format!(
            "{}: failing_samples must be <= allowed_failing_samples",
            path.display()
        ));
    }
    if typed.max_consecutive_failures_observed > typed.allowed_max_consecutive_failures {
        problems.push(format!(
            "{}: max_consecutive_failures_observed must be <= allowed_max_consecutive_failures",
            path.display()
        ));
    }

    if typed.direct_remote_exit_ready != CHECK_PASS {
        problems.push(format!(
            "{}: direct_remote_exit_ready must equal pass",
            path.display()
        ));
    }
    if typed.post_soak_bypass_ready != CHECK_PASS {
        problems.push(format!(
            "{}: post_soak_bypass_ready must equal pass",
            path.display()
        ));
    }
    if typed.no_plaintext_passphrase_files != CHECK_PASS {
        problems.push(format!(
            "{}: no_plaintext_passphrase_files must equal pass",
            path.display()
        ));
    }
    if typed.long_soak_stable != CHECK_PASS {
        problems.push(format!(
            "{}: long_soak_stable must equal pass",
            path.display()
        ));
    }
    if typed.direct_samples != typed.samples {
        problems.push(format!(
            "{}: direct_samples must equal samples for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    for (field, value) in [
        ("relay_samples", typed.relay_samples),
        ("fail_closed_samples", typed.fail_closed_samples),
        ("other_path_samples", typed.other_path_samples),
        ("path_transition_count", typed.path_transition_count),
        ("status_mismatch_samples", typed.status_mismatch_samples),
        ("route_mismatch_samples", typed.route_mismatch_samples),
        ("endpoint_mismatch_samples", typed.endpoint_mismatch_samples),
        ("dns_alarm_bad_samples", typed.dns_alarm_bad_samples),
        (
            "transport_identity_failures",
            typed.transport_identity_failures,
        ),
        ("failing_samples", typed.failing_samples),
        (
            "max_consecutive_failures_observed",
            typed.max_consecutive_failures_observed,
        ),
    ] {
        if value != 0 {
            problems.push(format!(
                "{}: {field} must equal 0 for authoritative direct-path soak evidence",
                path.display()
            ));
        }
    }
    if typed.first_non_direct_reason != "none" {
        problems.push(format!(
            "{}: first_non_direct_reason must equal none for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    if typed.first_failure_reason != "none" {
        problems.push(format!(
            "{}: first_failure_reason must equal none for authoritative direct-path soak evidence",
            path.display()
        ));
    }
    if typed.last_path_mode != "direct_active" {
        problems.push(format!(
            "{}: last_path_mode must equal direct_active",
            path.display()
        ));
    }
    let trimmed_reason = typed.last_path_reason.trim();
    if trimmed_reason.is_empty() || trimmed_reason == "none" {
        problems.push(format!(
            "{}: last_path_reason must be a non-empty direct-path reason",
            path.display()
        ));
    }

    problems
}

/// X2: Phase A typed view for the top-level cross-network report
/// payload. Pins the required top-level scalars with serde typed
/// semantics (wrong-type values like a stringified `schema_version`
/// or numeric `git_commit` fail at deserialize with a precise
/// per-field error) while preserving the legacy "missing field
/// produces a domain-specific problem string" behaviour for fields
/// that the existing walker tolerates by `unwrap_or_default()`.
///
/// Nested sections (`participants`, `network_context`, `checks`,
/// `path_evidence`) and artifact lists (`source_artifacts`,
/// `log_artifacts`) keep their `Map<String, Value>` / `Vec<Value>`
/// shapes here. The downstream helpers (`artifact_list_has_basename`,
/// `path_evidence_from_*`, `resolve_artifact_by_basename`,
/// `value_as_non_empty_string`) still walk those sections directly,
/// which keeps this slice behaviour-preserving while pinning the
/// outermost shape.
///
/// Any extra keys ride through `#[serde(flatten)] extra` and
/// `into_value_map` re-injects the typed fields so any downstream
/// Map walker keeps working.
#[derive(Debug, Clone, serde::Deserialize)]
struct CrossNetworkReportPayloadView {
    /// `suite` is the only field that MUST be present at the type
    /// level — every caller pathway through `validate_report_payload`
    /// supplies it, and the function's first action is to dispatch on
    /// it. Missing or wrong-type here fails at deserialize with a
    /// precise serde error rather than the legacy
    /// `unwrap_or_default()` -> `unknown suite ""` shape.
    suite: String,
    /// Remaining top-level scalars stay `Option<T>` so that a missing
    /// key continues to surface the legacy domain-specific problem
    /// string (e.g. `git_commit must be a 40-character lowercase
    /// hex commit id`) rather than a parse error. Wrong-type values
    /// still fail at deserialize because `Option<T>` rejects type
    /// mismatches.
    #[serde(default)]
    schema_version: Option<i64>,
    #[serde(default)]
    phase: Option<String>,
    #[serde(default)]
    evidence_mode: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    captured_at_unix: Option<u64>,
    #[serde(default)]
    git_commit: Option<String>,
    #[serde(default)]
    status: Option<String>,
    #[serde(default)]
    failure_summary: Option<String>,
    /// Nested objects and arrays stay raw so behaviour-preserving
    /// helpers continue to walk them as before. The typed view only
    /// guarantees the SHAPE (object vs not, array vs not) — content
    /// validation still runs in `validate_report_payload`.
    #[serde(default)]
    participants: Option<Map<String, Value>>,
    #[serde(default)]
    network_context: Option<Map<String, Value>>,
    #[serde(default)]
    checks: Option<Map<String, Value>>,
    #[serde(default)]
    path_evidence: Option<Map<String, Value>>,
    #[serde(default)]
    source_artifacts: Option<Vec<Value>>,
    #[serde(default)]
    log_artifacts: Option<Vec<Value>>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over the `path_evidence` block inside a cross-
/// network report payload. The 15 typed slots correspond to every
/// `.get("...")` call the `validate_report_payload` walker makes
/// against `path_evidence`; the `extra` flatten preserves any
/// additional fields a future suite or reporter shape might add
/// (forward-compat).
///
/// Field-shape rules:
/// * String fields use `Option<String>`. A missing field deserialises
///   to `None`; a present-but-empty string deserialises to
///   `Some(String::new())`. The walker's call sites apply the
///   `non_empty_trimmed_string` helper to fold empty/whitespace
///   strings back to `None` (parity with the legacy
///   `value_as_non_empty_string` helper).
/// * Numeric/bool fields use `Option<u64>` / `Option<bool>`. A
///   wrong-type value (e.g. string in a u64 slot) surfaces as a
///   serde deserialisation error and the walker falls back to the
///   legacy untyped walk for that path_evidence block, so a bad
///   incoming report keeps producing the same domain-specific
///   problem strings it always did.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Default)]
#[serde(default)]
struct CrossNetworkPathEvidenceView {
    pub path_mode: Option<String>,
    pub path_reason: Option<String>,
    pub path_programmed_mode: Option<String>,
    pub path_live_proven: Option<bool>,
    pub path_latest_live_handshake_unix: Option<u64>,
    pub relay_session_state: Option<String>,
    pub traversal_alarm_state: Option<String>,
    pub traversal_alarm_reason: Option<String>,
    pub dns_alarm_state: Option<String>,
    pub dns_alarm_reason: Option<String>,
    pub traversal_error: Option<String>,
    pub transport_socket_identity_state: Option<String>,
    pub transport_socket_identity_error: Option<String>,
    pub transport_socket_identity_label: Option<String>,
    pub transport_socket_identity_local_addr: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// Fold an `Option<String>` from a typed-view slot through the same
/// empty/whitespace filter the legacy `value_as_non_empty_string`
/// helper applied. Returns `Some(trimmed)` only when the value is
/// present and contains non-whitespace.
fn non_empty_trimmed_string(opt: &Option<String>) -> Option<String> {
    opt.as_deref().and_then(|s| {
        let t = s.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_owned())
        }
    })
}

impl CrossNetworkReportPayloadView {
    /// Bridge the typed view back to a `Map<String, Value>` for any
    /// downstream helper that still walks the payload generically.
    /// Re-injects every typed field so callers observe the full
    /// payload shape. Exercised by the typed-view round-trip test.
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert("suite".to_owned(), Value::String(self.suite));
        if let Some(v) = self.schema_version {
            m.insert("schema_version".to_owned(), Value::Number(v.into()));
        }
        if let Some(v) = self.phase {
            m.insert("phase".to_owned(), Value::String(v));
        }
        if let Some(v) = self.evidence_mode {
            m.insert("evidence_mode".to_owned(), Value::String(v));
        }
        if let Some(v) = self.environment {
            m.insert("environment".to_owned(), Value::String(v));
        }
        if let Some(v) = self.captured_at_unix {
            m.insert("captured_at_unix".to_owned(), Value::Number(v.into()));
        }
        if let Some(v) = self.git_commit {
            m.insert("git_commit".to_owned(), Value::String(v));
        }
        if let Some(v) = self.status {
            m.insert("status".to_owned(), Value::String(v));
        }
        if let Some(v) = self.failure_summary {
            m.insert("failure_summary".to_owned(), Value::String(v));
        }
        if let Some(v) = self.participants {
            m.insert("participants".to_owned(), Value::Object(v));
        }
        if let Some(v) = self.network_context {
            m.insert("network_context".to_owned(), Value::Object(v));
        }
        if let Some(v) = self.checks {
            m.insert("checks".to_owned(), Value::Object(v));
        }
        if let Some(v) = self.path_evidence {
            m.insert("path_evidence".to_owned(), Value::Object(v));
        }
        if let Some(v) = self.source_artifacts {
            m.insert("source_artifacts".to_owned(), Value::Array(v));
        }
        if let Some(v) = self.log_artifacts {
            m.insert("log_artifacts".to_owned(), Value::Array(v));
        }
        m
    }
}

fn validate_report_payload(
    report_path: &Path,
    payload: &Value,
    max_evidence_age_seconds: Option<u64>,
    now_unix_override: Option<u64>,
) -> Vec<String> {
    // X2: Phase A typed view migration. The report payload now parses
    // through `CrossNetworkReportPayloadView`, which pins the
    // outermost shape (object-ness, scalar types, nested object/array
    // shapes). Wrong-type values fail at deserialize with a precise
    // per-field serde error rather than silently flowing through
    // `as_str()`/`as_u64()` returning `None`. Missing optional
    // top-level scalars keep the legacy domain-specific problem
    // string for parity with the prior `Value`-walk behaviour.
    let mut problems = Vec::new();
    if !payload.is_object() {
        return vec![format!(
            "{}: report must be a JSON object",
            report_path.display()
        )];
    }
    let typed: CrossNetworkReportPayloadView = match serde_json::from_value(payload.clone()) {
        Ok(view) => view,
        Err(err) => {
            return vec![format!(
                "{}: invalid report payload ({err})",
                report_path.display()
            )];
        }
    };

    let suite = typed.suite.as_str();
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

    if typed.schema_version != Some(SCHEMA_VERSION) {
        problems.push(format!("schema_version must equal {SCHEMA_VERSION}"));
    }
    if typed.phase.as_deref() != Some(PHASE_NAME) {
        problems.push(format!("phase must equal {PHASE_NAME:?}"));
    }
    if typed.evidence_mode.as_deref() != Some(EVIDENCE_MODE) {
        problems.push(format!("evidence_mode must equal {EVIDENCE_MODE:?}"));
    }

    if typed
        .environment
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .is_none()
    {
        problems.push("environment must be a non-empty string".to_owned());
    }

    let captured_at_unix = typed.captured_at_unix.filter(|value| *value > 0);
    let now_unix = now_unix_override.unwrap_or_else(unix_now);
    match captured_at_unix {
        Some(captured) => {
            if captured > now_unix.saturating_add(300) {
                problems.push("captured_at_unix is too far in the future".to_owned());
            }
            if let Some(max_age) = max_evidence_age_seconds
                && now_unix.saturating_sub(captured) > max_age
            {
                problems.push("captured_at_unix is stale".to_owned());
            }
        }
        None => problems.push("captured_at_unix must be a positive integer".to_owned()),
    }

    let git_commit = typed.git_commit.as_deref().unwrap_or_default();
    if !is_lower_hex_commit(git_commit) {
        problems.push("git_commit must be a 40-character lowercase hex commit id".to_owned());
    }

    let status = typed.status.as_deref().unwrap_or_default();
    if status != CHECK_PASS && status != CHECK_FAIL {
        problems.push("status must be 'pass' or 'fail'".to_owned());
    }

    match typed.participants.as_ref() {
        Some(participants) => {
            for field in spec.required_participants {
                if value_as_non_empty_string(participants.get(*field)).is_none() {
                    problems.push(format!("participants.{field} must be a non-empty string"));
                }
            }
        }
        None => problems.push("participants must be an object".to_owned()),
    }

    match typed.network_context.as_ref() {
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
                problems.push("client_network_id and exit_network_id must differ".to_owned());
            }
        }
        None => problems.push("network_context must be an object".to_owned()),
    }

    let report_dir = report_path
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let repo_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    for (field_name, entries_opt) in [
        ("source_artifacts", typed.source_artifacts.as_deref()),
        ("log_artifacts", typed.log_artifacts.as_deref()),
    ] {
        match entries_opt {
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

    let checks = typed.checks.as_ref();
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
        None => problems.push("checks must be an object".to_owned()),
    }

    let failure_summary = typed.failure_summary.clone().unwrap_or_default();
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
            problems.push("failure_summary must be absent or empty when status=pass".to_owned());
        }
    } else if status == CHECK_FAIL {
        if failure_summary.trim().is_empty() {
            problems.push("failure_summary must be non-empty when status=fail".to_owned());
        }
        if let Some(check_map) = checks {
            let all_required_checks_pass = spec
                .required_checks
                .iter()
                .all(|name| check_map.get(*name).and_then(Value::as_str) == Some(CHECK_PASS));
            if all_required_checks_pass {
                problems
                    .push("status=fail requires at least one required check to fail".to_owned());
            }
        }
    }

    let path_evidence = typed.path_evidence.as_ref();
    let requires_live_path_evidence =
        status == CHECK_PASS && !matches!(spec.suite, "cross_network_traversal_adversarial");
    if requires_live_path_evidence && path_evidence.is_none() {
        problems.push("path_evidence must be present for pass reports".to_owned());
    }
    if let Some(path_evidence) = path_evidence {
        // X2: deserialise the path_evidence map once into the typed
        // view. If the deserialise fails (a wrong-type field
        // anywhere in the block), fall back to the legacy untyped
        // walk so the validator still surfaces the same per-field
        // problem strings instead of cascading "missing" failures
        // across the whole block.
        let typed_path_evidence: Option<CrossNetworkPathEvidenceView> =
            serde_json::from_value(Value::Object(path_evidence.clone())).ok();
        let (
            path_mode,
            path_reason,
            path_programmed_mode,
            path_live_proven,
            path_latest_live_handshake_unix,
            relay_session_state,
            traversal_alarm_state,
            traversal_alarm_reason,
            dns_alarm_state,
            dns_alarm_reason,
            traversal_error,
            transport_socket_identity_state,
            transport_socket_identity_error,
            transport_socket_identity_label,
            transport_socket_identity_local_addr,
        ) = if let Some(view) = typed_path_evidence.as_ref() {
            (
                non_empty_trimmed_string(&view.path_mode),
                non_empty_trimmed_string(&view.path_reason),
                non_empty_trimmed_string(&view.path_programmed_mode),
                view.path_live_proven,
                view.path_latest_live_handshake_unix
                    .filter(|value| *value > 0),
                non_empty_trimmed_string(&view.relay_session_state),
                non_empty_trimmed_string(&view.traversal_alarm_state),
                non_empty_trimmed_string(&view.traversal_alarm_reason),
                non_empty_trimmed_string(&view.dns_alarm_state),
                non_empty_trimmed_string(&view.dns_alarm_reason),
                non_empty_trimmed_string(&view.traversal_error),
                non_empty_trimmed_string(&view.transport_socket_identity_state),
                non_empty_trimmed_string(&view.transport_socket_identity_error),
                non_empty_trimmed_string(&view.transport_socket_identity_label),
                non_empty_trimmed_string(&view.transport_socket_identity_local_addr),
            )
        } else {
            (
                value_as_non_empty_string(path_evidence.get("path_mode")),
                value_as_non_empty_string(path_evidence.get("path_reason")),
                value_as_non_empty_string(path_evidence.get("path_programmed_mode")),
                path_evidence
                    .get("path_live_proven")
                    .and_then(Value::as_bool),
                path_evidence
                    .get("path_latest_live_handshake_unix")
                    .and_then(Value::as_u64)
                    .filter(|value| *value > 0),
                value_as_non_empty_string(path_evidence.get("relay_session_state")),
                value_as_non_empty_string(path_evidence.get("traversal_alarm_state")),
                value_as_non_empty_string(path_evidence.get("traversal_alarm_reason")),
                value_as_non_empty_string(path_evidence.get("dns_alarm_state")),
                value_as_non_empty_string(path_evidence.get("dns_alarm_reason")),
                value_as_non_empty_string(path_evidence.get("traversal_error")),
                value_as_non_empty_string(path_evidence.get("transport_socket_identity_state")),
                value_as_non_empty_string(path_evidence.get("transport_socket_identity_error")),
                value_as_non_empty_string(path_evidence.get("transport_socket_identity_label")),
                value_as_non_empty_string(
                    path_evidence.get("transport_socket_identity_local_addr"),
                ),
            )
        };

        if requires_live_path_evidence {
            if path_mode.is_none() {
                problems.push("path_evidence.path_mode must be a non-empty string".to_owned());
            }
            if path_reason.is_none() {
                problems.push("path_evidence.path_reason must be a non-empty string".to_owned());
            }
            if path_programmed_mode.is_none() {
                problems.push(
                    "path_evidence.path_programmed_mode must be a non-empty string".to_owned(),
                );
            }
            if path_live_proven != Some(true) {
                problems.push("path_evidence.path_live_proven must be true".to_owned());
            }
            if path_latest_live_handshake_unix.is_none() {
                problems.push(
                    "path_evidence.path_latest_live_handshake_unix must be a positive integer"
                        .to_owned(),
                );
            }
            if transport_socket_identity_state.as_deref()
                != Some("authoritative_backend_shared_transport")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_state must equal authoritative_backend_shared_transport for pass reports".to_owned(),
                );
            }
            if transport_socket_identity_error.as_deref() != Some("none") {
                problems.push(
                    "path_evidence.transport_socket_identity_error must equal none for pass reports".to_owned(),
                );
            }
            if transport_socket_identity_label
                .as_deref()
                .is_none_or(|value| value == "none")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_label must be a non-empty backend identity label".to_owned(),
                );
            }
            if transport_socket_identity_local_addr
                .as_deref()
                .is_none_or(|value| value == "none")
            {
                problems.push(
                    "path_evidence.transport_socket_identity_local_addr must be a non-empty backend local address".to_owned(),
                );
            }
            if traversal_alarm_state
                .as_deref()
                .is_some_and(|value| matches!(value, "critical" | "error" | "missing"))
            {
                problems.push(
                    "path_evidence.traversal_alarm_state must not be critical|error|missing for pass reports".to_owned(),
                );
            }
            if dns_alarm_state
                .as_deref()
                .is_some_and(|value| matches!(value, "critical" | "error" | "missing"))
            {
                problems.push(
                    "path_evidence.dns_alarm_state must not be critical|error|missing for pass reports".to_owned(),
                );
            }
            if traversal_error
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.traversal_error must equal none for pass reports".to_owned(),
                );
            }
            if traversal_alarm_reason
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.traversal_alarm_reason must equal none for pass reports"
                        .to_owned(),
                );
            }
            if dns_alarm_reason
                .as_deref()
                .is_some_and(|value| value != "none")
            {
                problems.push(
                    "path_evidence.dns_alarm_reason must equal none for pass reports".to_owned(),
                );
            }
        }

        if let Some(path_mode) = path_mode.as_deref() {
            if requires_live_path_evidence && path_mode.ends_with("_programmed") {
                problems.push(
                    "path_evidence.path_mode must represent a live path, not a programmed path"
                        .to_owned(),
                );
            }
            match spec.suite {
                "cross_network_direct_remote_exit" if status == CHECK_PASS => {
                    if path_mode != "direct_active" {
                        problems.push(
                            "direct remote-exit pass reports require path_evidence.path_mode=direct_active".to_owned(),
                        );
                    }
                }
                "cross_network_relay_remote_exit" if status == CHECK_PASS => {
                    if path_mode != "relay_active" {
                        problems.push(
                            "relay remote-exit pass reports require path_evidence.path_mode=relay_active".to_owned(),
                        );
                    }
                    if relay_session_state.as_deref() != Some("live") {
                        problems.push(
                            "relay remote-exit pass reports require path_evidence.relay_session_state=live".to_owned(),
                        );
                    }
                }
                "cross_network_failback_roaming" if status == CHECK_PASS => {
                    if path_mode != "direct_active" {
                        problems.push(
                            "failback pass reports require path_evidence.path_mode=direct_active"
                                .to_owned(),
                        );
                    }
                }
                _ => {}
            }
        }
    }

    if status == CHECK_PASS {
        if let Some(entries) = typed.source_artifacts.as_deref() {
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
                        problems.extend(validate_ssh_trust_summary_artifact(path.as_path()));
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
                        problems.extend(validate_soak_monitor_summary_artifact(path.as_path()));
                    }
                    Ok(None) => {}
                    Err(err) => problems.push(err),
                }
            }
        }
        if let Some(entries) = typed.log_artifacts.as_deref() {
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
        "# Cross-Network Remote Exit Report Validation".to_owned(),
        String::new(),
        "## Reports".to_owned(),
        String::new(),
    ];
    for path in report_paths {
        lines.push(format!("- `{}`", path.display()));
    }
    lines.push(String::new());
    if errors.is_empty() {
        lines.push("## Result".to_owned());
        lines.push(String::new());
        lines.push(
            "All supplied cross-network remote-exit reports matched the required schema."
                .to_owned(),
        );
        lines.push(String::new());
    } else {
        lines.push("## Errors".to_owned());
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
        if seen.insert(entry.to_owned()) {
            out.push(entry.to_owned());
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

        // Re-parse the payload through the typed view to read the
        // git_commit + status slots without re-walking the Value
        // graph. The view's `suite` field is required but every
        // caller pathway here has a parsed payload that already
        // dispatched on suite, so the deserialize is expected to
        // succeed. If it doesn't (unusual — payload was already
        // validated as a JSON object upstream), surface the
        // typed-boundary error and continue with the rest of the
        // path list.
        let typed: CrossNetworkReportPayloadView = match serde_json::from_value(payload.clone()) {
            Ok(view) => view,
            Err(err) => {
                errors.push(format!(
                    "{}: typed-view deserialize failed: {err}",
                    path.display()
                ));
                continue;
            }
        };
        if let Some(expected) = expected_git_commit {
            let got = typed.git_commit.as_deref().unwrap_or_default();
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
            let status = typed.status.as_deref().unwrap_or_default();
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
            .to_owned();
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
            .to_owned();
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
        errors.push("required_nat_profiles must not be empty".to_owned());
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
        "# Cross-Network NAT Matrix Validation".to_owned(),
        String::new(),
        "## Required NAT Profiles".to_owned(),
        String::new(),
    ];
    for profile in required_nat_profiles {
        lines.push(format!("- `{profile}`"));
    }
    lines.push(String::new());
    lines.push("## Reports Considered".to_owned());
    lines.push(String::new());
    if report_paths.is_empty() {
        lines.push("- none".to_owned());
    } else {
        for path in report_paths {
            lines.push(format!("- `{}`", path.display()));
        }
    }
    lines.push(String::new());
    lines.push("## Matrix Records".to_owned());
    lines.push(String::new());
    if records.is_empty() {
        lines.push("- none".to_owned());
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
    lines.push("## Result".to_owned());
    lines.push(String::new());
    if errors.is_empty() {
        lines.push("Matrix validation passed.".to_owned());
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

    let status = config.status.trim().to_owned();
    if status != CHECK_PASS && status != CHECK_FAIL {
        return Err("status must be pass or fail".to_owned());
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
        checks.insert((*check).to_owned(), Value::String(CHECK_FAIL.to_owned()));
    }
    for (key, value) in check_overrides {
        checks.insert(key, Value::String(value));
    }

    let mut participants = Map::new();
    if let Some(value) = non_empty_option(config.client_host) {
        participants.insert("client_host".to_owned(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.exit_host) {
        participants.insert("exit_host".to_owned(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.relay_host) {
        participants.insert("relay_host".to_owned(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.probe_host) {
        participants.insert("probe_host".to_owned(), Value::String(value));
    }

    let mut network_context = Map::new();
    if let Some(value) = non_empty_option(config.client_network_id) {
        network_context.insert("client_network_id".to_owned(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.exit_network_id) {
        network_context.insert("exit_network_id".to_owned(), Value::String(value));
    }
    if let Some(value) = non_empty_option(config.relay_network_id) {
        network_context.insert("relay_network_id".to_owned(), Value::String(value));
    }
    if !config.nat_profile.trim().is_empty() {
        network_context.insert(
            "nat_profile".to_owned(),
            Value::String(config.nat_profile.trim().to_owned()),
        );
    }
    if !config.impairment_profile.trim().is_empty() {
        network_context.insert(
            "impairment_profile".to_owned(),
            Value::String(config.impairment_profile.trim().to_owned()),
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
        "environment": if config.environment.trim().is_empty() { "live_linux_skeleton".to_owned() } else { config.environment.trim().to_owned() },
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
            "not_implemented".to_owned()
        } else {
            config.implementation_state.trim().to_owned()
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
            .insert("path_evidence".to_owned(), path_evidence);
    }
    if status == CHECK_FAIL {
        let failure_summary = if config.failure_summary.trim().is_empty() {
            format!("{} is not implemented yet", spec.title)
        } else {
            config.failure_summary.trim().to_owned()
        };
        if let Some(object) = payload.as_object_mut() {
            object.insert("failure_summary".to_owned(), Value::String(failure_summary));
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
        Ok("cross-network report schema validation passed".to_owned())
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
        Ok("cross-network NAT matrix validation passed".to_owned())
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
        _ => Err("ip-a and ip-b must use the same IP family".to_owned()),
    }
}

pub fn execute_ops_classify_cross_network_topology(
    config: ClassifyCrossNetworkTopologyConfig,
) -> Result<String, String> {
    let ip_a = parse_ip_addr("ip-a", &config.ip_a)?;
    let ip_b = parse_ip_addr("ip-b", &config.ip_b)?;
    let same = same_prefix(ip_a, ip_b, config.ipv4_prefix, config.ipv6_prefix)?;
    Ok(if same {
        CHECK_FAIL.to_owned()
    } else {
        CHECK_PASS.to_owned()
    })
}

pub fn execute_ops_read_cross_network_report_fields(
    config: ReadCrossNetworkReportFieldsConfig,
) -> Result<String, String> {
    if !config.include_status && config.checks.is_empty() && config.network_fields.is_empty() {
        return Err(
            "at least one output selector is required (--include-status, --check, or --network-field)".to_owned(),
        );
    }

    let report_path = resolve_path(config.report_path.as_path())?;
    let payload = parse_report_payload(report_path.as_path())?;
    let object = payload
        .as_object()
        .ok_or_else(|| format!("{}: report must be a JSON object", report_path.display()))?;

    let default_value = if config.default_value.is_empty() {
        CHECK_FAIL.to_owned()
    } else {
        config.default_value
    };
    let mut values = Vec::new();
    if config.include_status {
        values.push(
            object
                .get("status")
                .and_then(Value::as_str)
                .map_or_else(|| default_value.clone(), str::to_string),
        );
    }

    let checks = object.get("checks").and_then(Value::as_object);
    for key in config.checks {
        let name = key.trim();
        if name.is_empty() {
            return Err("check selector must not be empty".to_owned());
        }
        values.push(
            checks
                .and_then(|items| items.get(name))
                .and_then(Value::as_str)
                .map_or_else(|| default_value.clone(), str::to_string),
        );
    }

    let network = object.get("network_context").and_then(Value::as_object);
    for key in config.network_fields {
        let name = key.trim();
        if name.is_empty() {
            return Err("network-field selector must not be empty".to_owned());
        }
        values.push(
            network
                .and_then(|items| items.get(name))
                .and_then(Value::as_str)
                .map_or_else(|| default_value.clone(), str::to_string),
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
                    "cannot choose roam alias in /32; IPv4 prefix must allow host space".to_owned(),
                );
            }
            let mut used = HashSet::new();
            for raw in &config.used_ips {
                let parsed = parse_ip_addr("used-ip", raw)?;
                let IpAddr::V4(value) = parsed else {
                    return Err("all --used-ip values must match exit-ip family".to_owned());
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
            Err("failed to find available IPv4 roam alias in selected prefix".to_owned())
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
                        .to_owned(),
                );
            }
            let mut used = HashSet::new();
            for raw in &config.used_ips {
                let parsed = parse_ip_addr("used-ip", raw)?;
                let IpAddr::V6(value) = parsed else {
                    return Err("all --used-ip values must match exit-ip family".to_owned());
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
            Err("failed to find available IPv6 roam alias in selected prefix".to_owned())
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
            participants.insert((*field).to_owned(), Value::String(format!("{field}-value")));
        }

        let mut network_context = Map::new();
        network_context.insert(
            "client_network_id".to_owned(),
            Value::String("net-client".to_owned()),
        );
        network_context.insert(
            "exit_network_id".to_owned(),
            Value::String("net-exit".to_owned()),
        );
        network_context.insert(
            "nat_profile".to_owned(),
            Value::String("baseline_lan".to_owned()),
        );
        network_context.insert(
            "impairment_profile".to_owned(),
            Value::String("none".to_owned()),
        );
        if spec.required_network_fields.contains(&"relay_network_id") {
            network_context.insert(
                "relay_network_id".to_owned(),
                Value::String("net-relay".to_owned()),
            );
        }

        let mut checks = Map::new();
        for check in spec.required_checks {
            checks.insert((*check).to_owned(), Value::String(CHECK_PASS.to_owned()));
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
                "path_evidence".to_owned(),
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
                "failure_summary".to_owned(),
                Value::String("simulated failure".to_owned()),
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
                "schema_version=1".to_owned(),
                format!("generated_at_unix={}", unix_now()),
                "pinned_known_hosts_file=/tmp/rustynet-known_hosts".to_owned(),
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
            lines.push("all_targets_pinned=true".to_owned());
            lines.push("all_targets_passwordless_sudo=true".to_owned());
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
            "{\n  \"status\": \"pass\"\n}\n".to_owned()
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
        payload["checks"]["direct_remote_exit_success"] = Value::String(CHECK_FAIL.to_owned());

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
            suite: "cross_network_remote_exit_dns".to_owned(),
            report_path: report_path.clone(),
            log_path,
            status: CHECK_FAIL.to_owned(),
            failure_summary: "direct child failed before live path proof".to_owned(),
            environment: "unit_test".to_owned(),
            implementation_state: "live_measured_validator".to_owned(),
            source_artifacts: vec![source_path],
            log_artifacts: Vec::new(),
            client_host: Some("client-host".to_owned()),
            exit_host: Some("exit-host".to_owned()),
            relay_host: None,
            probe_host: None,
            client_network_id: Some("client-net".to_owned()),
            exit_network_id: Some("exit-net".to_owned()),
            relay_network_id: None,
            nat_profile: "baseline_lan".to_owned(),
            impairment_profile: "none".to_owned(),
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
            suite: "cross_network_remote_exit_dns".to_owned(),
            report_path,
            log_path,
            status: CHECK_PASS.to_owned(),
            failure_summary: String::new(),
            environment: "unit_test".to_owned(),
            implementation_state: "live_measured_validator".to_owned(),
            source_artifacts: vec![source_path, direct_report_path, managed_dns_report_path],
            log_artifacts: vec![direct_log_path, managed_dns_log_path],
            client_host: Some("client-host".to_owned()),
            exit_host: Some("exit-host".to_owned()),
            relay_host: None,
            probe_host: None,
            client_network_id: Some("client-net".to_owned()),
            exit_network_id: Some("exit-net".to_owned()),
            relay_network_id: None,
            nat_profile: "baseline_lan".to_owned(),
            impairment_profile: "none".to_owned(),
            check_overrides: vec![
                "managed_dns_resolution_success=pass".to_owned(),
                "remote_exit_dns_fail_closed=pass".to_owned(),
                "remote_exit_no_underlay_leak=pass".to_owned(),
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
            Value::String("blocked_backend_opaque_socket".to_owned());

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
        soak_summary.insert("direct_samples".to_owned(), Value::from(23u64));
        soak_summary.insert("relay_samples".to_owned(), Value::from(1u64));
        soak_summary.insert(
            "first_non_direct_reason".to_owned(),
            Value::String("relay_selected_no_direct_candidate".to_owned()),
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
                "traversal_alarm_state".to_owned(),
                Value::String("critical".to_owned()),
            );

        let errors = validate_report_payload(&report_path, &payload, Some(60), Some(unix_now()));

        assert!(
            errors.iter().any(|entry| entry.contains(
                "path_evidence.traversal_alarm_state must not be critical|error|missing for pass reports"
            )),
            "expected critical traversal alarm rejection, got: {errors:?}"
        );
    }

    /// Helper: build a clean soak-monitor-summary JSON `Value` whose
    /// shape matches the reviewed contract pinned by
    /// `CrossNetworkSoakMonitorSummaryView` (all 19 required counters,
    /// all 8 required status strings, plus an extra ride-through key
    /// to exercise `#[serde(flatten)] extra`).
    fn clean_soak_summary_value() -> Value {
        json!({
            "samples": 24u64,
            "failing_samples": 0u64,
            "max_consecutive_failures_observed": 0u64,
            "elapsed_secs": 120u64,
            "required_soak_duration_secs": 120u64,
            "allowed_failing_samples": 2u64,
            "allowed_max_consecutive_failures": 1u64,
            "direct_samples": 24u64,
            "relay_samples": 0u64,
            "fail_closed_samples": 0u64,
            "other_path_samples": 0u64,
            "path_transition_count": 0u64,
            "status_mismatch_samples": 0u64,
            "route_mismatch_samples": 0u64,
            "endpoint_mismatch_samples": 0u64,
            "dns_alarm_bad_samples": 0u64,
            "transport_identity_failures": 0u64,
            "endpoint_change_events_start": 1u64,
            "endpoint_change_events_end": 1u64,
            "endpoint_change_events_delta": 0u64,
            "direct_remote_exit_ready": "pass",
            "post_soak_bypass_ready": "pass",
            "no_plaintext_passphrase_files": "pass",
            "first_non_direct_reason": "none",
            "first_failure_reason": "none",
            "last_path_mode": "direct_active",
            "last_path_reason": "fresh_handshake_observed",
            "long_soak_stable": "pass",
            "extra_field": "ride-through",
        })
    }

    /// Clean fixture: a well-formed soak-monitor-summary deserializes
    /// into the typed view, every typed field lands in its slot, and
    /// the extra ride-through key flows into `#[serde(flatten)] extra`.
    #[test]
    fn cross_network_soak_monitor_summary_view_accepts_clean_artifact() {
        let payload = clean_soak_summary_value();
        let view: CrossNetworkSoakMonitorSummaryView = serde_json::from_value(payload)
            .expect("typed view accepts the clean soak monitor summary fixture");
        assert_eq!(view.samples, 24);
        assert_eq!(view.direct_samples, 24);
        assert_eq!(view.relay_samples, 0);
        assert_eq!(view.direct_remote_exit_ready, "pass");
        assert_eq!(view.last_path_mode, "direct_active");
        assert_eq!(view.last_path_reason, "fresh_handshake_observed");
        assert_eq!(
            view.extra.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "non-required keys must ride through #[serde(flatten)] extra"
        );
    }

    /// Missing required field rejected with a precise error that names
    /// the missing field. The serde error must mention `direct_samples`
    /// so the failure points to the source field — not a downstream
    /// "must be a non-negative integer" line.
    #[test]
    fn cross_network_soak_monitor_summary_view_rejects_missing_required_field() {
        let mut payload = clean_soak_summary_value();
        payload
            .as_object_mut()
            .expect("payload is an object")
            .remove("direct_samples");
        let err = serde_json::from_value::<CrossNetworkSoakMonitorSummaryView>(payload)
            .expect_err("missing direct_samples must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("direct_samples"),
            "error must name the missing required field: {message}"
        );
    }

    /// Wrong-type required field rejected at deserialize. `samples` is
    /// typed `u64`; supplying a string must fail at parse, not later
    /// via `as_u64()` returning `None` and downstream cross-field logic
    /// silently skipping.
    #[test]
    fn cross_network_soak_monitor_summary_view_rejects_wrong_type_required_field() {
        let mut payload = clean_soak_summary_value();
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("samples".to_owned(), Value::String("twenty-four".into()));
        let err = serde_json::from_value::<CrossNetworkSoakMonitorSummaryView>(payload)
            .expect_err("string samples must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("samples") || message.contains("u64"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// `into_value_map` round-trips: every typed field is re-injected
    /// at its original key and any flattened extras are preserved
    /// verbatim. This is the bridge downstream Map-walking helpers
    /// would rely on.
    #[test]
    fn cross_network_soak_monitor_summary_view_into_value_map_round_trips() {
        let payload = clean_soak_summary_value();
        let view: CrossNetworkSoakMonitorSummaryView =
            serde_json::from_value(payload).expect("typed view parses the clean fixture");
        let map = view.into_value_map();
        assert_eq!(
            map.get("samples").and_then(Value::as_u64),
            Some(24),
            "samples must round-trip"
        );
        assert_eq!(
            map.get("direct_samples").and_then(Value::as_u64),
            Some(24),
            "direct_samples must round-trip"
        );
        assert_eq!(
            map.get("endpoint_change_events_delta")
                .and_then(Value::as_u64),
            Some(0),
            "endpoint_change_events_delta must round-trip"
        );
        assert_eq!(
            map.get("direct_remote_exit_ready").and_then(Value::as_str),
            Some("pass"),
            "direct_remote_exit_ready must round-trip"
        );
        assert_eq!(
            map.get("last_path_reason").and_then(Value::as_str),
            Some("fresh_handshake_observed"),
            "last_path_reason must round-trip"
        );
        assert_eq!(
            map.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "scalar extras must be preserved verbatim"
        );
    }

    /// Helper: build a clean cross-network report payload value whose
    /// outermost shape matches the contract pinned by
    /// `CrossNetworkReportPayloadView` (typed required `suite`, all
    /// optional top-level scalars present, nested object/array
    /// sections present, plus an extra ride-through key to exercise
    /// `#[serde(flatten)] extra`).
    fn clean_report_payload_value() -> Value {
        json!({
            "schema_version": SCHEMA_VERSION,
            "phase": PHASE_NAME,
            "suite": "cross_network_direct_remote_exit",
            "environment": "unit_test",
            "evidence_mode": EVIDENCE_MODE,
            "captured_at_unix": 1_700_000_000u64,
            "git_commit": "a".repeat(40),
            "status": "pass",
            "failure_summary": "",
            "participants": {
                "client_host": "client",
                "exit_host": "exit",
            },
            "network_context": {
                "client_network_id": "net-client",
                "exit_network_id": "net-exit",
                "nat_profile": "baseline_lan",
                "impairment_profile": "none",
            },
            "checks": {
                "direct_remote_exit_success": "pass",
            },
            "path_evidence": {
                "path_mode": "direct_active",
            },
            "source_artifacts": ["source.txt"],
            "log_artifacts": ["log.txt"],
            "extra_field": "ride-through",
        })
    }

    /// Clean fixture: a well-formed report payload deserializes into
    /// the typed view, every typed field lands in its slot, and the
    /// extra ride-through key flows into `#[serde(flatten)] extra`.
    #[test]
    fn cross_network_report_payload_view_accepts_clean_payload() {
        let payload = clean_report_payload_value();
        let view: CrossNetworkReportPayloadView = serde_json::from_value(payload)
            .expect("typed view accepts the clean cross-network report payload fixture");
        assert_eq!(view.suite, "cross_network_direct_remote_exit");
        assert_eq!(view.schema_version, Some(SCHEMA_VERSION));
        assert_eq!(view.phase.as_deref(), Some(PHASE_NAME));
        assert_eq!(view.evidence_mode.as_deref(), Some(EVIDENCE_MODE));
        assert_eq!(view.environment.as_deref(), Some("unit_test"));
        assert_eq!(view.captured_at_unix, Some(1_700_000_000));
        assert_eq!(view.git_commit.as_deref(), Some("a".repeat(40).as_str()));
        assert_eq!(view.status.as_deref(), Some("pass"));
        assert_eq!(view.failure_summary.as_deref(), Some(""));
        assert!(
            view.participants
                .as_ref()
                .and_then(|m| m.get("client_host"))
                .and_then(Value::as_str)
                == Some("client"),
            "participants object must be retained"
        );
        assert!(
            view.network_context
                .as_ref()
                .and_then(|m| m.get("nat_profile"))
                .and_then(Value::as_str)
                == Some("baseline_lan"),
            "network_context object must be retained"
        );
        assert!(
            view.checks
                .as_ref()
                .and_then(|m| m.get("direct_remote_exit_success"))
                .and_then(Value::as_str)
                == Some("pass"),
            "checks object must be retained"
        );
        assert!(
            view.path_evidence
                .as_ref()
                .and_then(|m| m.get("path_mode"))
                .and_then(Value::as_str)
                == Some("direct_active"),
            "path_evidence object must be retained"
        );
        assert_eq!(
            view.source_artifacts.as_deref().map(<[Value]>::len),
            Some(1),
            "source_artifacts must be retained"
        );
        assert_eq!(
            view.log_artifacts.as_deref().map(<[Value]>::len),
            Some(1),
            "log_artifacts must be retained"
        );
        assert_eq!(
            view.extra.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "non-required keys must ride through #[serde(flatten)] extra"
        );
    }

    /// Missing required field rejected with a precise serde error
    /// that names the missing field. `suite` is the only field pinned
    /// as required-`String` (every caller pathway supplies it), so
    /// removing it must fail at deserialize.
    #[test]
    fn cross_network_report_payload_view_rejects_missing_required_field() {
        let mut payload = clean_report_payload_value();
        payload
            .as_object_mut()
            .expect("payload is an object")
            .remove("suite");
        let err = serde_json::from_value::<CrossNetworkReportPayloadView>(payload)
            .expect_err("missing suite must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("suite"),
            "error must name the missing required field: {message}"
        );
    }

    /// Wrong-type required field rejected at deserialize. `suite` is
    /// typed `String`; supplying a number must fail at parse, not
    /// later via `as_str()` returning `None` and the downstream
    /// `unknown suite` path silently catching it.
    #[test]
    fn cross_network_report_payload_view_rejects_wrong_type_required_field() {
        let mut payload = clean_report_payload_value();
        payload
            .as_object_mut()
            .expect("payload is an object")
            .insert("schema_version".to_owned(), Value::String("one".to_owned()));
        let err = serde_json::from_value::<CrossNetworkReportPayloadView>(payload)
            .expect_err("string schema_version must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("schema_version") || message.contains("i64"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// `into_value_map` round-trips: every typed field is re-injected
    /// at its original key and any flattened extras are preserved
    /// verbatim. This is the bridge downstream Map-walking helpers
    /// would rely on.
    #[test]
    fn cross_network_report_payload_view_into_value_map_round_trips() {
        let payload = clean_report_payload_value();
        let view: CrossNetworkReportPayloadView =
            serde_json::from_value(payload).expect("typed view parses the clean fixture");
        let map = view.into_value_map();
        assert_eq!(
            map.get("suite").and_then(Value::as_str),
            Some("cross_network_direct_remote_exit"),
            "suite must round-trip"
        );
        assert_eq!(
            map.get("schema_version").and_then(Value::as_i64),
            Some(SCHEMA_VERSION),
            "schema_version must round-trip"
        );
        assert_eq!(
            map.get("captured_at_unix").and_then(Value::as_u64),
            Some(1_700_000_000),
            "captured_at_unix must round-trip"
        );
        assert_eq!(
            map.get("status").and_then(Value::as_str),
            Some("pass"),
            "status must round-trip"
        );
        assert!(
            map.get("participants")
                .and_then(Value::as_object)
                .and_then(|m| m.get("client_host"))
                .and_then(Value::as_str)
                == Some("client"),
            "participants object must round-trip"
        );
        assert!(
            map.get("source_artifacts")
                .and_then(Value::as_array)
                .is_some_and(|entries| entries.len() == 1),
            "source_artifacts array must round-trip"
        );
        assert_eq!(
            map.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "scalar extras must be preserved verbatim"
        );
    }

    /// Helper: build a clean `path_evidence` map populated for a live
    /// direct remote-exit pass report. Every typed slot is filled and
    /// an extra ride-through key exercises `#[serde(flatten)] extra`.
    fn clean_path_evidence_value() -> Value {
        json!({
            "path_mode": "direct_active",
            "path_reason": "live_handshake_observed",
            "path_programmed_mode": "direct",
            "path_live_proven": true,
            "path_latest_live_handshake_unix": 1_700_000_000u64,
            "relay_session_state": "live",
            "traversal_alarm_state": "ok",
            "traversal_alarm_reason": "none",
            "dns_alarm_state": "ok",
            "dns_alarm_reason": "none",
            "traversal_error": "none",
            "transport_socket_identity_state": "authoritative_backend_shared_transport",
            "transport_socket_identity_error": "none",
            "transport_socket_identity_label": "wireguard_backend",
            "transport_socket_identity_local_addr": "10.10.10.1:51820",
            "extra_field": "ride-through",
        })
    }

    /// Clean fixture: a well-formed `path_evidence` block deserializes
    /// into `CrossNetworkPathEvidenceView`, every typed slot is filled,
    /// and the ride-through key flows into `extra`.
    #[test]
    fn cross_network_path_evidence_view_accepts_clean_block() {
        let block = clean_path_evidence_value();
        let view: CrossNetworkPathEvidenceView = serde_json::from_value(block)
            .expect("typed view accepts the clean path_evidence fixture");
        assert_eq!(view.path_mode.as_deref(), Some("direct_active"));
        assert_eq!(view.path_reason.as_deref(), Some("live_handshake_observed"));
        assert_eq!(view.path_programmed_mode.as_deref(), Some("direct"));
        assert_eq!(view.path_live_proven, Some(true));
        assert_eq!(view.path_latest_live_handshake_unix, Some(1_700_000_000));
        assert_eq!(view.relay_session_state.as_deref(), Some("live"));
        assert_eq!(view.traversal_alarm_state.as_deref(), Some("ok"));
        assert_eq!(view.traversal_alarm_reason.as_deref(), Some("none"));
        assert_eq!(view.dns_alarm_state.as_deref(), Some("ok"));
        assert_eq!(view.dns_alarm_reason.as_deref(), Some("none"));
        assert_eq!(view.traversal_error.as_deref(), Some("none"));
        assert_eq!(
            view.transport_socket_identity_state.as_deref(),
            Some("authoritative_backend_shared_transport")
        );
        assert_eq!(
            view.transport_socket_identity_error.as_deref(),
            Some("none")
        );
        assert_eq!(
            view.transport_socket_identity_label.as_deref(),
            Some("wireguard_backend")
        );
        assert_eq!(
            view.transport_socket_identity_local_addr.as_deref(),
            Some("10.10.10.1:51820")
        );
        assert_eq!(
            view.extra.get("extra_field").and_then(Value::as_str),
            Some("ride-through"),
            "non-required keys must ride through #[serde(flatten)] extra"
        );
    }

    /// Missing required typed slots deserialize to `None` because every
    /// slot is `Option<...>` with `#[serde(default)]`. The walker's
    /// `requires_live_path_evidence` branch surfaces the per-field
    /// problem strings — verified at the validator level by the
    /// existing `validate_report_payload_*` tests; this test pins the
    /// typed-view contract that missing slots are `None`, not errors.
    #[test]
    fn cross_network_path_evidence_view_accepts_missing_optional_slots() {
        let block = json!({
            "path_mode": "direct_active",
        });
        let view: CrossNetworkPathEvidenceView =
            serde_json::from_value(block).expect("typed view tolerates missing optional slots");
        assert_eq!(view.path_mode.as_deref(), Some("direct_active"));
        assert!(view.path_reason.is_none(), "missing slots must be None");
        assert!(
            view.path_live_proven.is_none(),
            "missing bool slot must be None"
        );
        assert!(
            view.path_latest_live_handshake_unix.is_none(),
            "missing u64 slot must be None"
        );
    }

    /// Wrong-type slot fails deserialize at the typed layer. The walker
    /// catches the `Err(_)` and falls back to the legacy untyped walk
    /// so a single bad field does not cascade "missing" failures across
    /// every other slot in the block.
    #[test]
    fn cross_network_path_evidence_view_rejects_wrong_type_slot() {
        let mut block = clean_path_evidence_value();
        block
            .as_object_mut()
            .expect("path_evidence fixture is an object")
            .insert(
                "path_live_proven".to_owned(),
                Value::String("true".to_owned()),
            );
        let err = serde_json::from_value::<CrossNetworkPathEvidenceView>(block)
            .expect_err("string path_live_proven must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("path_live_proven") || message.contains("bool"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// `non_empty_trimmed_string` pins parity with the legacy
    /// `value_as_non_empty_string` helper: `None`, empty, and
    /// whitespace-only inputs all fold to `None`; non-whitespace
    /// content is returned trimmed.
    #[test]
    fn non_empty_trimmed_string_folds_empty_and_whitespace_to_none() {
        assert!(non_empty_trimmed_string(&None).is_none());
        assert!(non_empty_trimmed_string(&Some(String::new())).is_none());
        assert!(non_empty_trimmed_string(&Some("   ".to_owned())).is_none());
        assert!(non_empty_trimmed_string(&Some("\t\n  ".to_owned())).is_none());
        assert_eq!(
            non_empty_trimmed_string(&Some("  direct_active  ".to_owned())).as_deref(),
            Some("direct_active"),
            "non-whitespace content must be returned trimmed"
        );
    }

    /// Walker integration: a wrong-type `path_live_proven` slot causes
    /// the typed deserialize to fail; the walker's legacy-fallback walk
    /// reads the remaining fields successfully so the validator emits
    /// the specific "path_live_proven must be true" problem string
    /// instead of cascading "missing" failures across every slot.
    #[test]
    fn validate_report_payload_falls_back_to_untyped_walk_on_wrong_type_slot() {
        let mut payload = clean_report_payload_value();
        let payload_map = payload.as_object_mut().expect("payload is an object");
        payload_map.insert("path_evidence".to_owned(), clean_path_evidence_value());
        let path_evidence_map = payload_map
            .get_mut("path_evidence")
            .and_then(Value::as_object_mut)
            .expect("path_evidence is an object");
        path_evidence_map.insert(
            "path_live_proven".to_owned(),
            Value::String("not_a_bool".to_owned()),
        );
        let problems =
            validate_report_payload(Path::new("/tmp/fake_report.json"), &payload, None, None);
        assert!(
            problems
                .iter()
                .any(|entry| entry.contains("path_live_proven must be true")),
            "fallback walk must still emit the per-field problem string: {problems:?}"
        );
        assert!(
            !problems
                .iter()
                .any(|entry| entry.contains("path_mode must be a non-empty string")),
            "wrong-type slot must not cascade into other slot failures: {problems:?}"
        );
    }

    /// Helper: build a clean key=value-text SSH trust summary as a
    /// `HashMap<String, String>` matching the contract pinned by
    /// `CrossNetworkSshTrustSummaryView`. The fixture covers the five
    /// top-level required scalars, two targets (each with all six
    /// per-target required scalars), and an extra ride-through key to
    /// exercise the `extra` map.
    fn clean_ssh_trust_summary_map() -> HashMap<String, String> {
        let mut m = HashMap::new();
        m.insert("schema_version".to_owned(), "1".to_owned());
        m.insert(
            "pinned_known_hosts_file".to_owned(),
            "/tmp/rustynet-known_hosts".to_owned(),
        );
        m.insert("pinned_known_hosts_sha256".to_owned(), "b".repeat(64));
        m.insert("all_targets_pinned".to_owned(), "true".to_owned());
        m.insert(
            "all_targets_passwordless_sudo".to_owned(),
            "true".to_owned(),
        );
        m.insert("target_count".to_owned(), "2".to_owned());
        for index in 0..2usize {
            m.insert(format!("target[{index}].target"), format!("host-{index}"));
            m.insert(
                format!("target[{index}].configured_transport"),
                "utm".to_owned(),
            );
            m.insert(
                format!("target[{index}].checked_candidates"),
                format!("host-{index},192.0.2.{}", index + 10),
            );
            m.insert(
                format!("target[{index}].matched_candidate"),
                format!("host-{index}"),
            );
            m.insert(
                format!("target[{index}].host_key_status"),
                "pass".to_owned(),
            );
            m.insert(
                format!("target[{index}].passwordless_sudo_status"),
                "pass".to_owned(),
            );
        }
        m.insert("extra_field".to_owned(), "ride-through".to_owned());
        m
    }

    /// Clean fixture: a well-formed SSH trust summary populates every
    /// typed slot, all per-target slots are filled for `target_count`
    /// entries, and the extra ride-through key flows into `extra`.
    #[test]
    fn cross_network_ssh_trust_summary_view_accepts_clean_artifact() {
        let map = clean_ssh_trust_summary_map();
        let view = CrossNetworkSshTrustSummaryView::from_key_value(map);
        assert_eq!(view.schema_version.as_deref(), Some("1"));
        assert_eq!(
            view.pinned_known_hosts_file.as_deref(),
            Some("/tmp/rustynet-known_hosts")
        );
        assert_eq!(
            view.pinned_known_hosts_sha256.as_deref(),
            Some("b".repeat(64).as_str())
        );
        assert_eq!(view.all_targets_pinned.as_deref(), Some("true"));
        assert_eq!(view.all_targets_passwordless_sudo.as_deref(), Some("true"));
        assert_eq!(view.target_count, Some(2));
        assert_eq!(view.targets.len(), 2);
        assert_eq!(view.targets[0].target.as_deref(), Some("host-0"));
        assert_eq!(view.targets[0].configured_transport.as_deref(), Some("utm"));
        assert_eq!(
            view.targets[0].checked_candidates.as_deref(),
            Some("host-0,192.0.2.10")
        );
        assert_eq!(view.targets[0].matched_candidate.as_deref(), Some("host-0"));
        assert_eq!(view.targets[0].host_key_status.as_deref(), Some("pass"));
        assert_eq!(
            view.targets[0].passwordless_sudo_status.as_deref(),
            Some("pass")
        );
        assert_eq!(view.targets[1].target.as_deref(), Some("host-1"));
        assert_eq!(
            view.extra.get("extra_field").map(String::as_str),
            Some("ride-through"),
            "non-required keys must ride through extra"
        );
    }

    /// Missing required top-level field: when `pinned_known_hosts_file`
    /// is absent from the parsed key=value map, the typed view loads
    /// `None` into the typed slot and the validator surfaces the
    /// existing "must be a non-empty string" message — verifying that
    /// missing scalars are caught at the typed layer rather than via a
    /// raw HashMap lookup deep in the validator.
    #[test]
    fn cross_network_ssh_trust_summary_view_rejects_missing_required_field() {
        let mut map = clean_ssh_trust_summary_map();
        map.remove("pinned_known_hosts_file");
        let view = CrossNetworkSshTrustSummaryView::from_key_value(map);
        assert!(
            view.pinned_known_hosts_file.is_none(),
            "missing required key must land as None in the typed slot"
        );
        // Still populated (the missing field is independent).
        assert_eq!(view.schema_version.as_deref(), Some("1"));
        assert_eq!(view.target_count, Some(2));
    }

    /// Wrong-type / non-parseable scalar: when `target_count` is not a
    /// non-negative integer, the typed view's `target_count` slot lands
    /// as `None` (and the `target_count_raw` slot preserves the
    /// original string so the round-trip helper does not lose it).
    /// This pins the typed-layer rejection that previously lived in
    /// the validator's ad-hoc `parse::<usize>()` walk.
    #[test]
    fn cross_network_ssh_trust_summary_view_rejects_wrong_type_required_field() {
        let mut map = clean_ssh_trust_summary_map();
        map.insert("target_count".to_owned(), "not-a-number".to_owned());
        let view = CrossNetworkSshTrustSummaryView::from_key_value(map);
        assert!(
            view.target_count.is_none(),
            "non-integer target_count must reject at the typed layer"
        );
        assert_eq!(
            view.target_count_raw.as_deref(),
            Some("not-a-number"),
            "raw target_count value must be retained so the round-trip helper does not silently drop it"
        );
        // Because target_count is None, the typed loader emits no
        // per-target slots — preventing follow-on panics or N silent
        // per-target validator errors.
        assert!(
            view.targets.is_empty(),
            "no per-target slots are populated when target_count fails to parse"
        );
    }

    /// `into_key_value_map` round-trips: every typed scalar (top-level
    /// and per-target) is re-injected at its original key and any
    /// non-consumed keys ride through `extra` verbatim. This is the
    /// bridge downstream key=value walkers would rely on.
    #[test]
    fn cross_network_ssh_trust_summary_view_into_key_value_map_round_trips() {
        let map = clean_ssh_trust_summary_map();
        let view = CrossNetworkSshTrustSummaryView::from_key_value(map);
        let round_tripped = view.into_key_value_map();
        assert_eq!(
            round_tripped.get("schema_version").map(String::as_str),
            Some("1"),
            "schema_version must round-trip"
        );
        assert_eq!(
            round_tripped
                .get("pinned_known_hosts_file")
                .map(String::as_str),
            Some("/tmp/rustynet-known_hosts"),
            "pinned_known_hosts_file must round-trip"
        );
        assert_eq!(
            round_tripped
                .get("pinned_known_hosts_sha256")
                .map(String::as_str),
            Some("b".repeat(64).as_str()),
            "pinned_known_hosts_sha256 must round-trip"
        );
        assert_eq!(
            round_tripped.get("all_targets_pinned").map(String::as_str),
            Some("true"),
            "all_targets_pinned must round-trip"
        );
        assert_eq!(
            round_tripped
                .get("all_targets_passwordless_sudo")
                .map(String::as_str),
            Some("true"),
            "all_targets_passwordless_sudo must round-trip"
        );
        assert_eq!(
            round_tripped.get("target_count").map(String::as_str),
            Some("2"),
            "target_count must round-trip"
        );
        assert_eq!(
            round_tripped.get("target[0].target").map(String::as_str),
            Some("host-0"),
            "per-target target slot must round-trip"
        );
        assert_eq!(
            round_tripped
                .get("target[1].configured_transport")
                .map(String::as_str),
            Some("utm"),
            "per-target configured_transport must round-trip"
        );
        assert_eq!(
            round_tripped
                .get("target[1].host_key_status")
                .map(String::as_str),
            Some("pass"),
            "per-target host_key_status must round-trip"
        );
        assert_eq!(
            round_tripped.get("extra_field").map(String::as_str),
            Some("ride-through"),
            "scalar extras must be preserved verbatim"
        );
    }
}
