#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::live_lab_results::{LiveLabWorkerResult, read_parallel_stage_results};
use serde_json::json;

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
    let payload: serde_json::Value = serde_json::from_str(
        fs::read_to_string(&report_path)
            .ok()
            .as_deref()
            .unwrap_or_default(),
    )
    .ok()?;

    if let Some(failure_reasons) = payload.get("failure_reasons").and_then(|v| v.as_array()) {
        let cleaned = failure_reasons
            .iter()
            .filter_map(|item| item.as_str().map(str::trim))
            .filter(|item| !item.is_empty())
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        if !cleaned.is_empty() {
            return Some(shorten(cleaned.join("; ").as_str(), 220));
        }
    }

    let mut reasons = Vec::new();
    if let Some(checks) = payload.get("checks").and_then(|v| v.as_object()) {
        for (name, value) in checks {
            if value.as_str() == Some("fail")
                && let Some(reason) = reboot_check_reason_text(name.as_str())
            {
                reasons.push(reason.to_string());
            }
        }
    }

    if let Some(observations) = payload.get("observations").and_then(|v| v.as_str()) {
        for line in observations
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
        {
            match line {
                "client_reboot_wait=fail" => {
                    reasons.push("client reboot wait timed out".to_string())
                }
                "exit_reboot_wait=fail" => reasons.push("exit reboot wait timed out".to_string()),
                "exit_post=" => {
                    reasons.push("exit post-reboot boot_id capture was empty".to_string())
                }
                "client_post=" => {
                    reasons.push("client post-reboot boot_id capture was empty".to_string())
                }
                _ if line.starts_with("ssh_port22_hosts=") => reasons.push(line.to_string()),
                _ => {}
            }
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

    let nodes = read_tsv(nodes_tsv.as_path())
        .into_iter()
        .filter(|row| row.len() == 4)
        .map(|row| {
            json!({
                "label": row[0],
                "target": row[1],
                "node_id": row[2],
                "bootstrap_role": row[3],
            })
        })
        .collect::<Vec<_>>();

    let mut stages = Vec::new();
    let mut failed_stages = Vec::new();
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
        let failed_workers = worker_results
            .iter()
            .filter(|item| item.rc != 0)
            .map(|item| {
                json!({
                    "label": item.label,
                    "target": item.target,
                    "node_id": item.node_id,
                    "role": item.role,
                    "rc": item.rc,
                    "started_at": item.started_at,
                    "finished_at": item.finished_at,
                    "log_path": item.log_path,
                    "snapshot_path": item.snapshot_path,
                    "route_policy_path": item.route_policy_path,
                    "dns_state_path": item.dns_state_path,
                    "primary_failure_reason": item.primary_failure_reason,
                    "likely_reason": worker_likely_reason(item),
                })
            })
            .collect::<Vec<_>>();
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
        let stage_entry = json!({
            "stage": stage_name,
            "severity": severity,
            "status": status,
            "rc": rc,
            "description": message,
            "started_at": started_at,
            "finished_at": finished_at,
            "log_path": log_path,
            "condensed_result": condensed_result,
            "primary_failure_reason": likely_reason,
            "likely_reason": likely_reason,
            "failed_workers": failed_workers,
        });
        if stage_entry.get("status").and_then(|v| v.as_str()) == Some("fail") {
            failed_stages.push(stage_entry.clone());
        }
        stages.push(stage_entry);
    }

    let first_failure = failed_stages
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let digest = json!({
        "schema_version": 1,
        "run_id": config.run_id,
        "network_id": config.network_id,
        "report_dir": report_dir.display().to_string(),
        "overall_status": config.overall_status,
        "node_count": nodes.len(),
        "nodes": nodes,
        "stages": stages,
        "failed_stage_count": failed_stages.len(),
        "first_failure": first_failure,
    });

    let mut lines = vec![
        format!(
            "# Live Linux Lab Failure Digest ({})",
            digest
                .get("run_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ),
        String::new(),
        format!(
            "- overall_status: `{}`",
            digest
                .get("overall_status")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ),
        format!(
            "- report_dir: `{}`",
            digest
                .get("report_dir")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ),
        format!("- node_count: `{}`", nodes.len()),
        String::new(),
        "## Condensed Checks".to_string(),
        String::new(),
    ];

    if digest
        .get("stages")
        .and_then(|v| v.as_array())
        .is_none_or(|stages| stages.is_empty())
    {
        lines.push("- no stage results recorded yet".to_string());
    } else if let Some(stages_array) = digest.get("stages").and_then(|v| v.as_array()) {
        for stage in stages_array {
            lines.push(format!(
                "- `{}` `{}`: {}",
                stage
                    .get("status")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_ascii_uppercase(),
                stage
                    .get("stage")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown"),
                stage
                    .get("condensed_result")
                    .and_then(|v| v.as_str())
                    .unwrap_or("stage result unavailable"),
            ));
        }
    }

    lines.extend([
        "".to_string(),
        "## Failure Focus".to_string(),
        "".to_string(),
    ]);
    if first_failure.is_null() {
        lines.push("- no failed stage recorded".to_string());
    } else {
        lines.push(format!(
            "- first_failed_stage: `{}`",
            first_failure
                .get("stage")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ));
        lines.push(format!(
            "- severity: `{}`",
            first_failure
                .get("severity")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ));
        lines.push(format!(
            "- rc: `{}`",
            first_failure
                .get("rc")
                .and_then(|v| v.as_i64())
                .unwrap_or(1)
        ));
        lines.push(format!(
            "- likely_reason: {}",
            first_failure
                .get("likely_reason")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ));
        lines.push(format!(
            "- full_log: `{}`",
            first_failure
                .get("log_path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
        ));
        if let Some(failed_workers) = first_failure
            .get("failed_workers")
            .and_then(|v| v.as_array())
            .filter(|items| !items.is_empty())
        {
            lines.extend([String::new(), "### Failed Nodes".to_string(), String::new()]);
            for worker in failed_workers {
                lines.push(format!(
                    "- `{}` `{}` (`{}`): rc={} reason={} log=`{}` snapshot=`{}`",
                    worker
                        .get("label")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    worker
                        .get("target")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    worker
                        .get("node_id")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    worker.get("rc").and_then(|v| v.as_i64()).unwrap_or(1),
                    worker
                        .get("likely_reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    worker
                        .get("log_path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown"),
                    worker
                        .get("snapshot_path")
                        .and_then(|v| v.as_str())
                        .filter(|value| !value.is_empty())
                        .unwrap_or("n/a"),
                ));
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
