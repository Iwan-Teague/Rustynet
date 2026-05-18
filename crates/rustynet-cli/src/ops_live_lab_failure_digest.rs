#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::live_lab_results::{LiveLabWorkerResult, read_parallel_stage_results};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

/// Typed view of the relevant subset of
/// `live_linux_reboot_recovery_report.json` used by the failure-digest
/// extractor. The schema covers exactly the fields the extractor reads;
/// unknown fields are ignored (default serde behaviour), but the fields
/// declared here must hold the documented shape or the parse fails — no
/// `serde_json::Value` walks remain on this trust-adjacent path.
#[derive(Debug, Clone, Default, Deserialize)]
struct RebootRecoveryReportView {
    #[serde(default)]
    failure_reasons: Vec<String>,
    #[serde(default)]
    checks: BTreeMap<String, String>,
    #[serde(default)]
    observations: String,
}

/// X2: Phase A typed view for one entry in the digest `nodes` array.
/// Required fields are the four columns of the nodes TSV (`label`,
/// `target`, `node_id`, `bootstrap_role`). Any extra keys ride through
/// `extra`; `into_value_map` re-injects the typed fields so Map-walking
/// callers see the full shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DigestNodeView {
    label: String,
    target: String,
    node_id: String,
    bootstrap_role: String,
    #[serde(flatten, default)]
    extra: Map<String, Value>,
}

impl DigestNodeView {
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert("label".to_string(), Value::String(self.label));
        m.insert("target".to_string(), Value::String(self.target));
        m.insert("node_id".to_string(), Value::String(self.node_id));
        m.insert(
            "bootstrap_role".to_string(),
            Value::String(self.bootstrap_role),
        );
        m
    }
}

/// X2: Phase A typed view for one entry in `failed_workers`. Required
/// fields mirror the columns of the worker-result TSV consumed by
/// `read_parallel_stage_results`. `rc` is `i64` to match the worker
/// schema; the remaining fields are strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DigestFailedWorkerView {
    label: String,
    target: String,
    node_id: String,
    role: String,
    rc: i64,
    started_at: String,
    finished_at: String,
    log_path: String,
    snapshot_path: String,
    route_policy_path: String,
    dns_state_path: String,
    primary_failure_reason: String,
    likely_reason: String,
    #[serde(flatten, default)]
    extra: Map<String, Value>,
}

impl DigestFailedWorkerView {
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert("label".to_string(), Value::String(self.label));
        m.insert("target".to_string(), Value::String(self.target));
        m.insert("node_id".to_string(), Value::String(self.node_id));
        m.insert("role".to_string(), Value::String(self.role));
        m.insert("rc".to_string(), Value::Number(self.rc.into()));
        m.insert("started_at".to_string(), Value::String(self.started_at));
        m.insert("finished_at".to_string(), Value::String(self.finished_at));
        m.insert("log_path".to_string(), Value::String(self.log_path));
        m.insert(
            "snapshot_path".to_string(),
            Value::String(self.snapshot_path),
        );
        m.insert(
            "route_policy_path".to_string(),
            Value::String(self.route_policy_path),
        );
        m.insert(
            "dns_state_path".to_string(),
            Value::String(self.dns_state_path),
        );
        m.insert(
            "primary_failure_reason".to_string(),
            Value::String(self.primary_failure_reason),
        );
        m.insert(
            "likely_reason".to_string(),
            Value::String(self.likely_reason),
        );
        m
    }
}

/// X2: Phase A typed view for one entry in `stages`. Captures the full
/// reviewed shape emitted by the live-lab failure-digest generator: a
/// stage name and severity classifier, a pass/fail/skipped status, an
/// `i64` return code, a free-form description, two RFC-3339 timestamps,
/// the originating log path, two condensed human-readable summaries
/// (`condensed_result` + `likely_reason`/`primary_failure_reason`), and
/// the nested `failed_workers` typed view list. Any extra keys ride
/// through `extra`; `into_value_map` re-injects every typed field
/// (including the nested workers) so Map-walking consumers see the
/// complete shape.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DigestStageEntryView {
    stage: String,
    severity: String,
    status: String,
    rc: i64,
    description: String,
    started_at: String,
    finished_at: String,
    log_path: String,
    condensed_result: String,
    primary_failure_reason: String,
    likely_reason: String,
    failed_workers: Vec<DigestFailedWorkerView>,
    #[serde(flatten, default)]
    extra: Map<String, Value>,
}

impl DigestStageEntryView {
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert("stage".to_string(), Value::String(self.stage));
        m.insert("severity".to_string(), Value::String(self.severity));
        m.insert("status".to_string(), Value::String(self.status));
        m.insert("rc".to_string(), Value::Number(self.rc.into()));
        m.insert("description".to_string(), Value::String(self.description));
        m.insert("started_at".to_string(), Value::String(self.started_at));
        m.insert("finished_at".to_string(), Value::String(self.finished_at));
        m.insert("log_path".to_string(), Value::String(self.log_path));
        m.insert(
            "condensed_result".to_string(),
            Value::String(self.condensed_result),
        );
        m.insert(
            "primary_failure_reason".to_string(),
            Value::String(self.primary_failure_reason),
        );
        m.insert(
            "likely_reason".to_string(),
            Value::String(self.likely_reason),
        );
        m.insert(
            "failed_workers".to_string(),
            Value::Array(
                self.failed_workers
                    .into_iter()
                    .map(|w| Value::Object(w.into_value_map()))
                    .collect(),
            ),
        );
        m
    }
}

/// X2: Phase A typed view for the live-lab failure-digest top-level
/// JSON. Captures the full reviewed envelope:
///   - `schema_version` (`u64`) pins the contract version
///   - `run_id`, `network_id`, `report_dir`, `overall_status` (`String`)
///     identify the run
///   - `node_count`, `failed_stage_count` (`u64`) are counters derived
///     from the nested arrays
///   - `nodes` and `stages` are typed view lists
///   - `first_failure` is `Option<DigestStageEntryView>` so the
///     "no failed stage recorded" case serialises back to JSON `null`
///     exactly as the legacy `json!`-built shape did
///
/// `into_value_map` re-injects every typed field (including the nested
/// arrays and the optional first failure) so any downstream Map walker
/// keeps working.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LiveLabFailureDigestView {
    schema_version: u64,
    run_id: String,
    network_id: String,
    report_dir: String,
    overall_status: String,
    node_count: u64,
    nodes: Vec<DigestNodeView>,
    stages: Vec<DigestStageEntryView>,
    failed_stage_count: u64,
    first_failure: Option<DigestStageEntryView>,
    #[serde(flatten, default)]
    extra: Map<String, Value>,
}

impl LiveLabFailureDigestView {
    #[allow(dead_code)]
    fn into_value_map(self) -> Map<String, Value> {
        let mut m = self.extra;
        m.insert(
            "schema_version".to_string(),
            Value::Number(self.schema_version.into()),
        );
        m.insert("run_id".to_string(), Value::String(self.run_id));
        m.insert("network_id".to_string(), Value::String(self.network_id));
        m.insert("report_dir".to_string(), Value::String(self.report_dir));
        m.insert(
            "overall_status".to_string(),
            Value::String(self.overall_status),
        );
        m.insert(
            "node_count".to_string(),
            Value::Number(self.node_count.into()),
        );
        m.insert(
            "nodes".to_string(),
            Value::Array(
                self.nodes
                    .into_iter()
                    .map(|n| Value::Object(n.into_value_map()))
                    .collect(),
            ),
        );
        m.insert(
            "stages".to_string(),
            Value::Array(
                self.stages
                    .into_iter()
                    .map(|s| Value::Object(s.into_value_map()))
                    .collect(),
            ),
        );
        m.insert(
            "failed_stage_count".to_string(),
            Value::Number(self.failed_stage_count.into()),
        );
        m.insert(
            "first_failure".to_string(),
            match self.first_failure {
                Some(stage) => Value::Object(stage.into_value_map()),
                None => Value::Null,
            },
        );
        m
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateLiveLinuxLabFailureDigestConfig {
    pub nodes_tsv: PathBuf,
    pub stages_tsv: PathBuf,
    pub report_dir: PathBuf,
    pub run_id: String,
    pub network_id: String,
    pub overall_status: String,
    pub output_json: PathBuf,
    pub output_md: PathBuf,
}

fn stage_text(stage_name: &str, status: &str) -> Option<&'static str> {
    match (stage_name, status) {
        ("preflight", "pass") => Some("local prerequisites are ready"),
        ("preflight", "fail") => Some("local prerequisite validation failed"),
        ("prepare_source_archive", "pass") => Some("deploy source archive prepared successfully"),
        ("prepare_source_archive", "fail") => Some("deploy source archive preparation failed"),
        ("prime_remote_access", "pass") => {
            Some("all targeted nodes accepted remote SSH and sudo priming")
        }
        ("prime_remote_access", "fail") => {
            Some("remote SSH or sudo priming failed on one or more targeted nodes")
        }
        ("cleanup_hosts", "pass") => {
            Some("all targeted nodes cleaned prior RustyNet state successfully")
        }
        ("cleanup_hosts", "fail") => {
            Some("prior RustyNet state cleanup failed on one or more targeted nodes")
        }
        ("bootstrap_hosts", "pass") => {
            Some("all targeted nodes bootstrapped and compiled RustyNet successfully")
        }
        ("bootstrap_hosts", "fail") => {
            Some("bootstrap or compile failed on one or more targeted nodes")
        }
        ("collect_pubkeys", "pass") => {
            Some("all targeted nodes exported WireGuard public keys successfully")
        }
        ("collect_pubkeys", "fail") => {
            Some("WireGuard public key collection failed on one or more targeted nodes")
        }
        ("membership_setup", "pass") => {
            Some("primary exit applied signed membership updates successfully")
        }
        ("membership_setup", "fail") => Some("signed membership setup failed on the primary exit"),
        ("distribute_membership_state", "pass") => {
            Some("membership state distributed to all targeted peer nodes successfully")
        }
        ("distribute_membership_state", "fail") => {
            Some("membership state distribution failed on one or more targeted peer nodes")
        }
        ("issue_and_distribute_assignments", "pass") => Some(
            "signed assignments were issued and distributed to all targeted nodes successfully",
        ),
        ("issue_and_distribute_assignments", "fail") => {
            Some("assignment issuance or distribution failed on one or more targeted nodes")
        }
        ("enforce_baseline_runtime", "pass") => {
            Some("all targeted nodes enforced baseline runtime successfully")
        }
        ("enforce_baseline_runtime", "fail") => {
            Some("baseline runtime enforcement failed on one or more targeted nodes")
        }
        ("validate_baseline_runtime", "pass") => {
            Some("all targeted nodes connected to the network correctly under baseline validation")
        }
        ("validate_baseline_runtime", "fail") => {
            Some("baseline network validation failed on one or more targeted nodes")
        }
        ("live_role_switch_matrix", "pass") => Some("controlled role-switch validation passed"),
        ("live_role_switch_matrix", "fail") => Some("controlled role-switch validation failed"),
        ("live_exit_handoff", "pass") => Some("live exit handoff validation passed"),
        ("live_exit_handoff", "fail") => Some("live exit handoff validation failed"),
        ("live_two_hop", "pass") => Some("live two-hop validation passed"),
        ("live_two_hop", "fail") => Some("live two-hop validation failed"),
        ("live_lan_toggle", "pass") => Some("LAN toggle and blind-exit validation passed"),
        ("live_lan_toggle", "fail") => Some("LAN toggle or blind-exit validation failed"),
        ("fresh_install_os_matrix_report", "pass") => {
            Some("commit-bound fresh install OS matrix evidence was generated successfully")
        }
        ("fresh_install_os_matrix_report", "fail") => {
            Some("fresh install OS matrix evidence generation failed")
        }
        ("local_full_gate_suite", "pass") => Some("local full gate suite passed"),
        ("local_full_gate_suite", "fail") => Some("local full gate suite failed"),
        ("extended_soak", "pass") => Some("extended soak and reboot recovery validation passed"),
        ("extended_soak", "fail") => Some("extended soak or reboot recovery validation failed"),
        _ => None,
    }
}

fn reboot_check_reason_text(check: &str) -> Option<&'static str> {
    match check {
        "exit_reboot_returns" => Some("exit did not return on SSH after reboot"),
        "exit_boot_id_changes" => Some("exit reboot was not proven by a new boot_id"),
        "post_exit_reboot_twohop" => Some("two-hop validation failed after exit reboot"),
        "client_reboot_returns" => Some("client did not return on SSH after reboot"),
        "client_boot_id_changes" => Some("client reboot was not proven by a new boot_id"),
        "post_client_reboot_twohop" => Some("two-hop validation failed after client reboot"),
        "client_failure_salvage_twohop" => {
            Some("salvage two-hop validation failed after the client reboot outage")
        }
        _ => None,
    }
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn read_tsv(path: &Path) -> Vec<Vec<String>> {
    if !path.exists() {
        return Vec::new();
    }
    let Ok(body) = fs::read_to_string(path) else {
        return Vec::new();
    };
    body.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            line.split('\t')
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .filter(|row| !row.is_empty())
        .collect()
}

fn strip_ansi_escape(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' {
            if matches!(chars.peek(), Some('[')) {
                let _ = chars.next();
                for next in chars.by_ref() {
                    if next.is_ascii_alphabetic() {
                        break;
                    }
                }
                continue;
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn sanitize_line(line: &str) -> String {
    strip_ansi_escape(line).trim().to_string()
}

fn is_ignored_line(line: &str) -> bool {
    if line.starts_with("[stage:")
        && (line.contains("] START") || line.contains("] PASS") || line.contains("] FAIL"))
    {
        return true;
    }
    line.starts_with("[parallel:") || line.starts_with("----- ")
}

fn shorten(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    format!("{}...", text[..max_len.saturating_sub(3)].trim_end())
}

fn matches_preferred_reason(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    lowered.contains("error:")
        || lowered.contains("fail")
        || lowered.contains("timed out")
        || lowered.contains("timeout")
        || lowered.contains("permission denied")
        || (lowered.contains("auth") && lowered.contains("fail"))
        || lowered.contains("missing")
        || lowered.contains("invalid")
        || lowered.contains("mismatch")
        || lowered.contains("does not exist")
        || lowered.contains("no such")
        || lowered.contains("unreachable")
}

fn extract_likely_reason(log_path: &Path) -> String {
    if !log_path.exists() {
        return "log file missing".to_string();
    }
    let lines = match fs::read_to_string(log_path) {
        Ok(body) => body.lines().map(ToString::to_string).collect::<Vec<_>>(),
        Err(_) => return "log file unreadable".to_string(),
    };
    let mut candidates = Vec::new();
    for raw_line in lines {
        let line = sanitize_line(raw_line.as_str());
        if line.is_empty() || is_ignored_line(line.as_str()) {
            continue;
        }
        candidates.push(line);
    }
    if candidates.is_empty() {
        return "see full log".to_string();
    }
    for line in candidates.iter().rev() {
        if matches_preferred_reason(line.as_str()) {
            return shorten(line.as_str(), 220);
        }
    }
    shorten(
        candidates
            .last()
            .map(String::as_str)
            .unwrap_or("see full log"),
        220,
    )
}

fn extract_extended_soak_reason(report_dir: &Path) -> Option<String> {
    let report_path = report_dir.join("live_linux_reboot_recovery_report.json");
    if !report_path.exists() {
        return None;
    }
    let body = fs::read_to_string(&report_path).ok()?;
    let payload: RebootRecoveryReportView = serde_json::from_str(body.as_str()).ok()?;

    let cleaned: Vec<String> = payload
        .failure_reasons
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .map(ToString::to_string)
        .collect();
    if !cleaned.is_empty() {
        return Some(shorten(cleaned.join("; ").as_str(), 220));
    }

    let mut reasons = Vec::new();
    for (name, value) in &payload.checks {
        if value == "fail"
            && let Some(reason) = reboot_check_reason_text(name.as_str())
        {
            reasons.push(reason.to_string());
        }
    }

    for line in payload
        .observations
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        match line {
            "client_reboot_wait=fail" => reasons.push("client reboot wait timed out".to_string()),
            "exit_reboot_wait=fail" => reasons.push("exit reboot wait timed out".to_string()),
            "exit_post=" => reasons.push("exit post-reboot boot_id capture was empty".to_string()),
            "client_post=" => {
                reasons.push("client post-reboot boot_id capture was empty".to_string())
            }
            _ if line.starts_with("ssh_port22_hosts=") => reasons.push(line.to_string()),
            _ => {}
        }
    }

    if reasons.is_empty() {
        return None;
    }
    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for reason in reasons {
        if seen.insert(reason.clone()) {
            deduped.push(reason);
        }
    }
    Some(shorten(deduped.join("; ").as_str(), 220))
}

fn extract_stage_reason(stage_name: &str, report_dir: &Path, log_path: &Path) -> String {
    if stage_name == "extended_soak"
        && let Some(reason) = extract_extended_soak_reason(report_dir)
    {
        return reason;
    }
    extract_likely_reason(log_path)
}

fn worker_likely_reason(worker: &LiveLabWorkerResult) -> String {
    if !worker.primary_failure_reason.trim().is_empty() {
        return worker.primary_failure_reason.clone();
    }
    extract_likely_reason(Path::new(worker.log_path.as_str()))
}

fn stage_sentence(
    stage_name: &str,
    status: &str,
    worker_results: &[LiveLabWorkerResult],
) -> String {
    if status == "pass" {
        return stage_text(stage_name, "pass")
            .unwrap_or("stage passed")
            .to_string();
    }
    if status == "skipped" {
        return "stage skipped".to_string();
    }
    if !worker_results.is_empty() {
        let total = worker_results.len();
        let failed = worker_results.iter().filter(|item| item.rc != 0).count();
        let base = stage_text(stage_name, "fail").unwrap_or("stage failed");
        return format!("{base} ({failed}/{total} targeted nodes failed)");
    }
    stage_text(stage_name, "fail")
        .unwrap_or("stage failed")
        .to_string()
}

pub fn execute_ops_generate_live_linux_lab_failure_digest(
    config: GenerateLiveLinuxLabFailureDigestConfig,
) -> Result<String, String> {
    let report_dir = resolve_path(config.report_dir.as_path())?;
    let nodes_tsv = resolve_path(config.nodes_tsv.as_path())?;
    let stages_tsv = resolve_path(config.stages_tsv.as_path())?;
    let output_json = resolve_path(config.output_json.as_path())?;
    let output_md = resolve_path(config.output_md.as_path())?;

    let nodes: Vec<DigestNodeView> = read_tsv(nodes_tsv.as_path())
        .into_iter()
        .filter(|row| row.len() == 4)
        .map(|row| DigestNodeView {
            label: row[0].clone(),
            target: row[1].clone(),
            node_id: row[2].clone(),
            bootstrap_role: row[3].clone(),
            extra: Map::new(),
        })
        .collect();

    let mut stages: Vec<DigestStageEntryView> = Vec::new();
    let mut failed_stages: Vec<DigestStageEntryView> = Vec::new();
    for row in read_tsv(stages_tsv.as_path()) {
        if row.len() != 8 {
            continue;
        }
        let stage_name = row[0].clone();
        let severity = row[1].clone();
        let status = row[2].clone();
        let rc = row[3].parse::<i64>().unwrap_or(1);
        let log_path = row[4].clone();
        let message = row[5].clone();
        let started_at = row[6].clone();
        let finished_at = row[7].clone();
        let worker_results = read_parallel_stage_results(report_dir.as_path(), stage_name.as_str());
        let failed_workers: Vec<DigestFailedWorkerView> = worker_results
            .iter()
            .filter(|item| item.rc != 0)
            .map(|item| DigestFailedWorkerView {
                label: item.label.clone(),
                target: item.target.clone(),
                node_id: item.node_id.clone(),
                role: item.role.clone(),
                rc: item.rc,
                started_at: item.started_at.clone(),
                finished_at: item.finished_at.clone(),
                log_path: item.log_path.clone(),
                snapshot_path: item.snapshot_path.clone(),
                route_policy_path: item.route_policy_path.clone(),
                dns_state_path: item.dns_state_path.clone(),
                primary_failure_reason: item.primary_failure_reason.clone(),
                likely_reason: worker_likely_reason(item),
                extra: Map::new(),
            })
            .collect();
        let mut likely_reason = extract_stage_reason(
            stage_name.as_str(),
            report_dir.as_path(),
            Path::new(log_path.as_str()),
        );
        if let Some(first_failed) = worker_results.iter().find(|item| item.rc != 0) {
            likely_reason = worker_likely_reason(first_failed);
        }
        let condensed_result =
            stage_sentence(stage_name.as_str(), status.as_str(), &worker_results);
        let stage_entry = DigestStageEntryView {
            stage: stage_name,
            severity,
            status: status.clone(),
            rc,
            description: message,
            started_at,
            finished_at,
            log_path,
            condensed_result,
            primary_failure_reason: likely_reason.clone(),
            likely_reason,
            failed_workers,
            extra: Map::new(),
        };
        if stage_entry.status == "fail" {
            failed_stages.push(stage_entry.clone());
        }
        stages.push(stage_entry);
    }

    let first_failure: Option<DigestStageEntryView> = failed_stages.first().cloned();
    let node_count = nodes.len() as u64;
    let failed_stage_count = failed_stages.len() as u64;
    let digest = LiveLabFailureDigestView {
        schema_version: 1,
        run_id: config.run_id,
        network_id: config.network_id,
        report_dir: report_dir.display().to_string(),
        overall_status: config.overall_status,
        node_count,
        nodes,
        stages,
        failed_stage_count,
        first_failure: first_failure.clone(),
        extra: Map::new(),
    };

    let mut lines = vec![
        format!("# Live Linux Lab Failure Digest ({})", digest.run_id),
        String::new(),
        format!("- overall_status: `{}`", digest.overall_status),
        format!("- report_dir: `{}`", digest.report_dir),
        format!("- node_count: `{}`", digest.node_count),
        String::new(),
        "## Condensed Checks".to_string(),
        String::new(),
    ];

    if digest.stages.is_empty() {
        lines.push("- no stage results recorded yet".to_string());
    } else {
        for stage in &digest.stages {
            lines.push(format!(
                "- `{}` `{}`: {}",
                stage.status.to_ascii_uppercase(),
                stage.stage,
                stage.condensed_result,
            ));
        }
    }

    lines.extend([
        "".to_string(),
        "## Failure Focus".to_string(),
        "".to_string(),
    ]);
    match first_failure {
        None => lines.push("- no failed stage recorded".to_string()),
        Some(first) => {
            lines.push(format!("- first_failed_stage: `{}`", first.stage));
            lines.push(format!("- severity: `{}`", first.severity));
            lines.push(format!("- rc: `{}`", first.rc));
            lines.push(format!("- likely_reason: {}", first.likely_reason));
            lines.push(format!("- full_log: `{}`", first.log_path));
            if !first.failed_workers.is_empty() {
                lines.extend([String::new(), "### Failed Nodes".to_string(), String::new()]);
                for worker in &first.failed_workers {
                    let snapshot = if worker.snapshot_path.is_empty() {
                        "n/a"
                    } else {
                        worker.snapshot_path.as_str()
                    };
                    lines.push(format!(
                        "- `{}` `{}` (`{}`): rc={} reason={} log=`{}` snapshot=`{}`",
                        worker.label,
                        worker.target,
                        worker.node_id,
                        worker.rc,
                        worker.likely_reason,
                        worker.log_path,
                        snapshot,
                    ));
                }
            }
        }
    }

    if let Some(parent) = output_json.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    if let Some(parent) = output_md.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::write(
        &output_json,
        serde_json::to_string_pretty(&digest)
            .map_err(|err| format!("serialize digest failed: {err}"))?
            + "\n",
    )
    .map_err(|err| {
        format!(
            "write digest json failed ({}): {err}",
            output_json.display()
        )
    })?;
    fs::write(&output_md, lines.join("\n") + "\n").map_err(|err| {
        format!(
            "write digest markdown failed ({}): {err}",
            output_md.display()
        )
    })?;

    Ok(format!(
        "live lab failure digest generated: json={} md={}",
        output_json.display(),
        output_md.display()
    ))
}

#[cfg(test)]
mod typed_parser_tests {
    use super::*;
    use serde_json::json;

    fn write_report(dir: &Path, body: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join("live_linux_reboot_recovery_report.json"), body).unwrap();
    }

    fn tmp_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-cli-failure-digest-{}-{}",
            std::process::id(),
            suffix
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn extract_returns_none_when_report_file_is_absent() {
        let dir = tmp_dir("absent");
        fs::create_dir_all(&dir).unwrap();
        assert!(extract_extended_soak_reason(&dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_returns_none_when_payload_is_not_valid_json() {
        let dir = tmp_dir("invalid");
        write_report(&dir, "not json");
        // Typed parse fails closed; the extractor returns None.
        assert!(extract_extended_soak_reason(&dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_uses_failure_reasons_array_when_present() {
        let dir = tmp_dir("reasons");
        write_report(
            &dir,
            r#"{"schema_version":1,"failure_reasons":["alpha","  beta  ","",  "gamma"]}"#,
        );
        let out =
            extract_extended_soak_reason(&dir).expect("non-empty failure_reasons must surface");
        // Empty-after-trim entries are dropped; whitespace is trimmed; order preserved.
        assert_eq!(out, "alpha; beta; gamma");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_falls_back_to_checks_when_failure_reasons_is_absent() {
        let dir = tmp_dir("checks");
        write_report(
            &dir,
            r#"{"schema_version":1,"checks":{"exit_reboot_returns":"fail","client_reboot_returns":"pass"}}"#,
        );
        let out = extract_extended_soak_reason(&dir)
            .expect("failed check must yield a reboot_check_reason_text mapping");
        assert!(!out.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_consumes_observations_when_no_failure_reasons_or_failed_checks() {
        let dir = tmp_dir("obs");
        write_report(
            &dir,
            r#"{"schema_version":1,"observations":"client_reboot_wait=fail\nexit_post=\nunrelated_line"}"#,
        );
        let out = extract_extended_soak_reason(&dir)
            .expect("matching observation lines must surface a reason");
        assert!(out.contains("client reboot wait timed out"));
        assert!(out.contains("exit post-reboot boot_id capture was empty"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_dedupes_repeated_reasons() {
        let dir = tmp_dir("dedup");
        write_report(
            &dir,
            r#"{"schema_version":1,"observations":"client_reboot_wait=fail\nclient_reboot_wait=fail\nexit_reboot_wait=fail"}"#,
        );
        let out = extract_extended_soak_reason(&dir).unwrap();
        let cnt = out.matches("client reboot wait timed out").count();
        assert_eq!(
            cnt, 1,
            "repeated observation lines must dedupe in output: {out}"
        );
    }

    #[test]
    fn extract_returns_none_when_payload_has_no_signals_at_all() {
        let dir = tmp_dir("empty-signals");
        write_report(
            &dir,
            r#"{"schema_version":1,"mode":"live_linux_reboot_recovery","status":"pass"}"#,
        );
        // No failure_reasons, no failed checks, no matching observations: nothing to report.
        assert!(extract_extended_soak_reason(&dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_ignores_unknown_fields_under_typed_parse() {
        let dir = tmp_dir("unknown-fields");
        // Unknown top-level fields (boot_ids, etc.) must not break parsing —
        // RebootRecoveryReportView intentionally accepts the documented
        // subset and ignores everything else.
        write_report(
            &dir,
            r#"{
              "schema_version": 1,
              "mode": "live_linux_reboot_recovery",
              "status": "fail",
              "boot_ids": {"exit_pre":"a","exit_post":"b","client_pre":"c","client_post":"d"},
              "failure_reasons": ["fault-from-typed-view"],
              "checks": {"exit_reboot_returns":"fail"},
              "observations": "exit_post="
            }"#,
        );
        let out = extract_extended_soak_reason(&dir).unwrap();
        assert!(out.contains("fault-from-typed-view"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn extract_treats_failure_reasons_with_only_whitespace_entries_as_empty() {
        let dir = tmp_dir("whitespace-only");
        write_report(
            &dir,
            r#"{"failure_reasons":["", "  ", "\t"], "observations":"exit_post="}"#,
        );
        // failure_reasons effectively empty -> falls through to observations.
        let out = extract_extended_soak_reason(&dir).unwrap();
        assert!(out.contains("exit post-reboot boot_id capture was empty"));
        let _ = fs::remove_dir_all(&dir);
    }

    // ---------- typed-view round-trip + shape pinning tests ----------

    fn clean_node_value() -> Value {
        json!({
            "label": "exit-a",
            "target": "10.0.0.1",
            "node_id": "node-001",
            "bootstrap_role": "primary_exit",
        })
    }

    fn clean_failed_worker_value() -> Value {
        json!({
            "label": "exit-a",
            "target": "10.0.0.1",
            "node_id": "node-001",
            "role": "primary_exit",
            "rc": 2_i64,
            "started_at": "2026-05-16T12:00:00Z",
            "finished_at": "2026-05-16T12:01:00Z",
            "log_path": "/tmp/log.txt",
            "snapshot_path": "/tmp/snap.tar",
            "route_policy_path": "/tmp/route.json",
            "dns_state_path": "/tmp/dns.json",
            "primary_failure_reason": "tunnel down",
            "likely_reason": "wg handshake timed out",
        })
    }

    fn clean_stage_entry_value() -> Value {
        json!({
            "stage": "validate_baseline_runtime",
            "severity": "critical",
            "status": "fail",
            "rc": 1_i64,
            "description": "validation step failed",
            "started_at": "2026-05-16T12:00:00Z",
            "finished_at": "2026-05-16T12:05:00Z",
            "log_path": "/tmp/stage.log",
            "condensed_result": "baseline network validation failed",
            "primary_failure_reason": "wg handshake timed out",
            "likely_reason": "wg handshake timed out",
            "failed_workers": [clean_failed_worker_value()],
        })
    }

    fn clean_digest_value() -> Value {
        json!({
            "schema_version": 1_u64,
            "run_id": "run-123",
            "network_id": "net-7",
            "report_dir": "/tmp/report",
            "overall_status": "fail",
            "node_count": 1_u64,
            "nodes": [clean_node_value()],
            "stages": [clean_stage_entry_value()],
            "failed_stage_count": 1_u64,
            "first_failure": clean_stage_entry_value(),
        })
    }

    #[test]
    fn digest_node_view_parses_clean_fixture() {
        let view: DigestNodeView = serde_json::from_value(clean_node_value()).expect("clean parse");
        assert_eq!(view.label, "exit-a");
        assert_eq!(view.target, "10.0.0.1");
        assert_eq!(view.node_id, "node-001");
        assert_eq!(view.bootstrap_role, "primary_exit");
    }

    #[test]
    fn digest_node_view_rejects_missing_required_field() {
        let mut payload = clean_node_value();
        payload.as_object_mut().unwrap().remove("bootstrap_role");
        let err = serde_json::from_value::<DigestNodeView>(payload).unwrap_err();
        assert!(
            err.to_string().contains("bootstrap_role"),
            "missing field message must name `bootstrap_role`: {err}"
        );
    }

    #[test]
    fn digest_node_view_rejects_wrong_type_required_field() {
        let mut payload = clean_node_value();
        payload.as_object_mut().unwrap()["target"] = json!(42_i64);
        let err = serde_json::from_value::<DigestNodeView>(payload).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("string"),
            "wrong-type message must mention `string`: {err}"
        );
    }

    #[test]
    fn digest_node_view_into_value_map_round_trips() {
        let view: DigestNodeView = serde_json::from_value(clean_node_value()).unwrap();
        let map = view.into_value_map();
        assert_eq!(map.get("label").and_then(|v| v.as_str()), Some("exit-a"));
        assert_eq!(map.get("target").and_then(|v| v.as_str()), Some("10.0.0.1"));
        assert_eq!(
            map.get("node_id").and_then(|v| v.as_str()),
            Some("node-001")
        );
        assert_eq!(
            map.get("bootstrap_role").and_then(|v| v.as_str()),
            Some("primary_exit")
        );
    }

    #[test]
    fn digest_failed_worker_view_parses_clean_fixture() {
        let view: DigestFailedWorkerView =
            serde_json::from_value(clean_failed_worker_value()).expect("clean parse");
        assert_eq!(view.label, "exit-a");
        assert_eq!(view.rc, 2);
        assert_eq!(view.primary_failure_reason, "tunnel down");
        assert_eq!(view.likely_reason, "wg handshake timed out");
    }

    #[test]
    fn digest_failed_worker_view_rejects_missing_required_field() {
        let mut payload = clean_failed_worker_value();
        payload.as_object_mut().unwrap().remove("log_path");
        let err = serde_json::from_value::<DigestFailedWorkerView>(payload).unwrap_err();
        assert!(
            err.to_string().contains("log_path"),
            "missing field message must name `log_path`: {err}"
        );
    }

    #[test]
    fn digest_failed_worker_view_rejects_wrong_type_required_field() {
        let mut payload = clean_failed_worker_value();
        payload.as_object_mut().unwrap()["rc"] = json!("not-a-number");
        let err = serde_json::from_value::<DigestFailedWorkerView>(payload).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("integer")
                || err.to_string().to_ascii_lowercase().contains("number")
                || err.to_string().to_ascii_lowercase().contains("i64"),
            "wrong-type message must mention numeric expectation: {err}"
        );
    }

    #[test]
    fn digest_failed_worker_view_into_value_map_round_trips() {
        let view: DigestFailedWorkerView =
            serde_json::from_value(clean_failed_worker_value()).unwrap();
        let map = view.into_value_map();
        assert_eq!(map.get("rc").and_then(serde_json::Value::as_i64), Some(2));
        assert_eq!(
            map.get("snapshot_path").and_then(|v| v.as_str()),
            Some("/tmp/snap.tar")
        );
        assert_eq!(
            map.get("likely_reason").and_then(|v| v.as_str()),
            Some("wg handshake timed out")
        );
    }

    #[test]
    fn digest_stage_entry_view_parses_clean_fixture() {
        let view: DigestStageEntryView =
            serde_json::from_value(clean_stage_entry_value()).expect("clean parse");
        assert_eq!(view.stage, "validate_baseline_runtime");
        assert_eq!(view.status, "fail");
        assert_eq!(view.rc, 1);
        assert_eq!(view.failed_workers.len(), 1);
        assert_eq!(view.failed_workers[0].label, "exit-a");
    }

    #[test]
    fn digest_stage_entry_view_rejects_missing_required_field() {
        let mut payload = clean_stage_entry_value();
        payload.as_object_mut().unwrap().remove("condensed_result");
        let err = serde_json::from_value::<DigestStageEntryView>(payload).unwrap_err();
        assert!(
            err.to_string().contains("condensed_result"),
            "missing field message must name `condensed_result`: {err}"
        );
    }

    #[test]
    fn digest_stage_entry_view_rejects_wrong_type_required_field() {
        let mut payload = clean_stage_entry_value();
        payload.as_object_mut().unwrap()["status"] = json!(0_i64);
        let err = serde_json::from_value::<DigestStageEntryView>(payload).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("string"),
            "wrong-type message must mention `string`: {err}"
        );
    }

    #[test]
    fn digest_stage_entry_view_into_value_map_round_trips() {
        let view: DigestStageEntryView = serde_json::from_value(clean_stage_entry_value()).unwrap();
        let map = view.into_value_map();
        assert_eq!(
            map.get("stage").and_then(|v| v.as_str()),
            Some("validate_baseline_runtime")
        );
        assert_eq!(map.get("status").and_then(|v| v.as_str()), Some("fail"));
        assert_eq!(map.get("rc").and_then(serde_json::Value::as_i64), Some(1));
        let workers = map
            .get("failed_workers")
            .and_then(|v| v.as_array())
            .expect("failed_workers re-injected as array");
        assert_eq!(workers.len(), 1);
        assert_eq!(
            workers[0].get("label").and_then(|v| v.as_str()),
            Some("exit-a")
        );
    }

    #[test]
    fn live_lab_failure_digest_view_parses_clean_fixture() {
        let view: LiveLabFailureDigestView =
            serde_json::from_value(clean_digest_value()).expect("clean parse");
        assert_eq!(view.schema_version, 1);
        assert_eq!(view.run_id, "run-123");
        assert_eq!(view.network_id, "net-7");
        assert_eq!(view.node_count, 1);
        assert_eq!(view.nodes.len(), 1);
        assert_eq!(view.stages.len(), 1);
        assert_eq!(view.failed_stage_count, 1);
        assert!(view.first_failure.is_some());
    }

    #[test]
    fn live_lab_failure_digest_view_rejects_missing_required_field() {
        let mut payload = clean_digest_value();
        payload.as_object_mut().unwrap().remove("schema_version");
        let err = serde_json::from_value::<LiveLabFailureDigestView>(payload).unwrap_err();
        assert!(
            err.to_string().contains("schema_version"),
            "missing field message must name `schema_version`: {err}"
        );
    }

    #[test]
    fn live_lab_failure_digest_view_rejects_wrong_type_required_field() {
        let mut payload = clean_digest_value();
        payload.as_object_mut().unwrap()["node_count"] = json!("one");
        let err = serde_json::from_value::<LiveLabFailureDigestView>(payload).unwrap_err();
        assert!(
            err.to_string().to_ascii_lowercase().contains("integer")
                || err.to_string().to_ascii_lowercase().contains("number")
                || err.to_string().to_ascii_lowercase().contains("u64"),
            "wrong-type message must mention numeric expectation: {err}"
        );
    }

    #[test]
    fn live_lab_failure_digest_view_first_failure_accepts_null() {
        let mut payload = clean_digest_value();
        payload.as_object_mut().unwrap()["first_failure"] = Value::Null;
        payload.as_object_mut().unwrap()["failed_stage_count"] = json!(0_u64);
        let view: LiveLabFailureDigestView =
            serde_json::from_value(payload).expect("null first_failure must parse");
        assert!(view.first_failure.is_none());
    }

    #[test]
    fn live_lab_failure_digest_view_into_value_map_round_trips() {
        let view: LiveLabFailureDigestView = serde_json::from_value(clean_digest_value()).unwrap();
        let map = view.into_value_map();
        assert_eq!(
            map.get("schema_version")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(map.get("run_id").and_then(|v| v.as_str()), Some("run-123"));
        assert_eq!(
            map.get("node_count").and_then(serde_json::Value::as_u64),
            Some(1)
        );
        assert_eq!(
            map.get("failed_stage_count")
                .and_then(serde_json::Value::as_u64),
            Some(1)
        );
        let nodes = map.get("nodes").and_then(|v| v.as_array()).unwrap();
        assert_eq!(nodes.len(), 1);
        let stages = map.get("stages").and_then(|v| v.as_array()).unwrap();
        assert_eq!(stages.len(), 1);
        let first = map.get("first_failure").unwrap();
        assert!(first.is_object());
    }

    #[test]
    fn live_lab_failure_digest_view_into_value_map_emits_null_first_failure() {
        let view = LiveLabFailureDigestView {
            schema_version: 1,
            run_id: "run-x".to_string(),
            network_id: "net-x".to_string(),
            report_dir: "/tmp".to_string(),
            overall_status: "pass".to_string(),
            node_count: 0,
            nodes: Vec::new(),
            stages: Vec::new(),
            failed_stage_count: 0,
            first_failure: None,
            extra: Map::new(),
        };
        let map = view.into_value_map();
        assert!(matches!(map.get("first_failure"), Some(Value::Null)));
    }
}
