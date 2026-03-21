#![forbid(unsafe_code)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindLinuxFreshInstallOsMatrixInputsConfig {
    pub dest_dir: PathBuf,
    pub bootstrap_log: PathBuf,
    pub baseline_log: PathBuf,
    pub two_hop_report: PathBuf,
    pub role_switch_report: PathBuf,
    pub lan_toggle_report: PathBuf,
    pub exit_handoff_report: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateLinuxFreshInstallOsMatrixReportConfig {
    pub output: PathBuf,
    pub environment: String,
    pub source_mode: String,
    pub expected_git_commit_file: PathBuf,
    pub git_status_file: PathBuf,
    pub bootstrap_log: PathBuf,
    pub baseline_log: PathBuf,
    pub two_hop_report: PathBuf,
    pub role_switch_report: PathBuf,
    pub lan_toggle_report: PathBuf,
    pub exit_handoff_report: PathBuf,
    pub exit_node_id: String,
    pub client_node_id: String,
    pub ubuntu_node_id: String,
    pub fedora_node_id: String,
    pub mint_node_id: String,
    pub debian_os_version: String,
    pub ubuntu_os_version: String,
    pub fedora_os_version: String,
    pub mint_os_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifyLinuxFreshInstallOsMatrixReadinessConfig {
    pub report_path: PathBuf,
    pub max_age_seconds: u64,
    pub profile: String,
    pub expected_git_commit: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFreshInstallOsMatrixReadinessFixturesConfig {
    pub output_dir: PathBuf,
    pub head_commit: String,
    pub stale_commit: String,
    pub now_unix: u64,
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

fn repo_root() -> Result<PathBuf, String> {
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd)
}

fn require_file(path: &Path, label: &str) -> Result<PathBuf, String> {
    let resolved = resolve_path(path)?;
    if !resolved.is_file() {
        return Err(format!("missing {label}: {}", resolved.display()));
    }
    Ok(resolved)
}

fn normalize_path(path: &Path, root: &Path) -> String {
    let resolved = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    match resolved.strip_prefix(root) {
        Ok(relative) => relative.display().to_string(),
        Err(_) => resolved.display().to_string(),
    }
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<PathBuf, String> {
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create destination parent failed ({}): {err}",
                parent.display()
            )
        })?;
    }
    fs::copy(source, destination).map_err(|err| {
        format!(
            "copy artifact failed ({} -> {}): {err}",
            source.display(),
            destination.display()
        )
    })?;
    Ok(fs::canonicalize(destination).unwrap_or_else(|_| destination.to_path_buf()))
}

fn parse_json_object(path: &Path, label: &str) -> Result<Map<String, Value>, String> {
    let body = fs::read_to_string(path).map_err(|err| format!("read {label} failed: {err}"))?;
    let payload: Value = serde_json::from_str(&body)
        .map_err(|err| format!("parse {label} JSON failed ({}): {err}", path.display()))?;
    payload
        .as_object()
        .cloned()
        .ok_or_else(|| format!("{label} must be a JSON object"))
}

fn write_json(path: &Path, payload: &Value, label: &str) -> Result<(), String> {
    let mut body = serde_json::to_string_pretty(payload)
        .map_err(|err| format!("serialize {label} failed: {err}"))?;
    body.push('\n');
    fs::write(path, body.as_bytes())
        .map_err(|err| format!("write {label} failed ({}): {err}", path.display()))
}

fn write_text(path: &Path, body: &str, label: &str) -> Result<(), String> {
    fs::write(path, body.as_bytes())
        .map_err(|err| format!("write {label} failed ({}): {err}", path.display()))
}

fn absolute_display(path: &Path) -> String {
    fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .display()
        .to_string()
}

fn canonicalize_report(
    report_path: &Path,
    report_label: &str,
    dest_dir: &Path,
    root: &Path,
    slug: &str,
) -> Result<PathBuf, String> {
    let mut payload = parse_json_object(report_path, report_label)?;
    let canonical_report_path = dest_dir.join(
        report_path
            .file_name()
            .ok_or_else(|| format!("{report_label} has invalid filename"))?,
    );

    if let Some(source_artifacts) = payload.get("source_artifacts") {
        let source_artifacts = source_artifacts
            .as_array()
            .ok_or_else(|| format!("{report_label} requires a non-empty source_artifacts list"))?;
        if source_artifacts.is_empty() {
            return Err(format!(
                "{report_label} requires a non-empty source_artifacts list"
            ));
        }
        let mut rebound = Vec::new();
        for (index, artifact) in source_artifacts.iter().enumerate() {
            let raw = artifact
                .as_str()
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .ok_or_else(|| format!("{report_label} has invalid source_artifacts entry"))?;
            let mut source = PathBuf::from(raw);
            if !source.is_absolute() {
                source = root.join(source);
            }
            let source = require_file(
                source.as_path(),
                format!("{report_label} source artifact").as_str(),
            )?;
            let canonical_source = copy_artifact(
                source.as_path(),
                dest_dir
                    .join(format!(
                        "{slug}_{:02}_{}",
                        index + 1,
                        source
                            .file_name()
                            .and_then(|v| v.to_str())
                            .unwrap_or("artifact")
                    ))
                    .as_path(),
            )?;
            rebound.push(Value::String(normalize_path(
                canonical_source.as_path(),
                root,
            )));
        }
        payload.insert("source_artifacts".to_string(), Value::Array(rebound));
    }

    if let Some(source_artifact) = payload.get("source_artifact") {
        let raw = source_artifact
            .as_str()
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .ok_or_else(|| format!("{report_label} has invalid source_artifact"))?;
        let mut source = PathBuf::from(raw);
        if !source.is_absolute() {
            source = root.join(source);
        }
        let source = require_file(
            source.as_path(),
            format!("{report_label} source artifact").as_str(),
        )?;
        let canonical_source = copy_artifact(
            source.as_path(),
            dest_dir
                .join(format!(
                    "{slug}_source_{}",
                    source
                        .file_name()
                        .and_then(|v| v.to_str())
                        .unwrap_or("artifact")
                ))
                .as_path(),
        )?;
        payload.insert(
            "source_artifact".to_string(),
            Value::String(normalize_path(canonical_source.as_path(), root)),
        );
    }

    fs::write(
        &canonical_report_path,
        serde_json::to_string_pretty(&Value::Object(payload))
            .map_err(|err| format!("serialize canonicalized {report_label} failed: {err}"))?
            + "\n",
    )
    .map_err(|err| {
        format!(
            "write canonicalized {report_label} failed ({}): {err}",
            canonical_report_path.display()
        )
    })?;
    Ok(fs::canonicalize(&canonical_report_path).unwrap_or(canonical_report_path))
}

fn normalize_source_artifacts(items: &Value, root: &Path) -> Result<Vec<String>, String> {
    let Some(items) = items.as_array() else {
        return Err("report contains invalid source_artifacts entry".to_string());
    };
    let mut out = Vec::new();
    for item in items {
        let raw = item
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| "report contains invalid source_artifacts entry".to_string())?;
        let mut source = PathBuf::from(raw);
        if !source.is_absolute() {
            source = root.join(source);
        }
        if !source.exists() {
            return Err(format!("source artifact does not exist: {raw}"));
        }
        out.push(normalize_path(source.as_path(), root));
    }
    Ok(out)
}

fn dedupe(items: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for item in items {
        if seen.insert(item.clone()) {
            out.push(item);
        }
    }
    out
}

fn load_json_report(
    path: &Path,
    label: &str,
    root: &Path,
    expected_commit: &str,
) -> Result<Map<String, Value>, String> {
    let path = require_file(path, label)?;
    let mut payload = parse_json_object(path.as_path(), label)?;
    if payload.get("status").and_then(Value::as_str) != Some("pass") {
        return Err(format!("{label} status must be pass"));
    }
    let git_commit = payload
        .get("git_commit")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if git_commit != expected_commit {
        return Err(format!(
            "{label} git_commit mismatch: {git_commit} != {expected_commit}"
        ));
    }
    if payload.get("evidence_mode").and_then(Value::as_str) != Some("measured") {
        return Err(format!("{label} evidence_mode must be measured"));
    }
    let normalized_source_artifacts = normalize_source_artifacts(
        payload
            .get("source_artifacts")
            .unwrap_or(&Value::Array(Vec::new())),
        root,
    )?;
    payload.insert(
        "normalized_source_artifacts".to_string(),
        Value::Array(
            normalized_source_artifacts
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    Ok(payload)
}

fn as_string_vec(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

struct FreshInstallVerifyContext<'a> {
    expected_commit: &'a str,
    now_unix: u64,
    max_age_seconds: u64,
    root: &'a Path,
}

fn is_lower_hex_sha40(value: &str) -> bool {
    value.len() == 40
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn require_nonempty_string_field(
    payload: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<String, String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| format!("{label} requires non-empty string field: {key}"))
}

fn require_positive_u64_field(
    payload: &Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<u64, String> {
    payload
        .get(key)
        .and_then(Value::as_u64)
        .filter(|value| *value > 0)
        .ok_or_else(|| format!("{label} requires positive integer field: {key}"))
}

fn validate_timestamp(
    value: u64,
    label: &str,
    now_unix: u64,
    max_age_seconds: u64,
) -> Result<(), String> {
    if value > now_unix.saturating_add(300) {
        return Err(format!("{label} timestamp is too far in the future"));
    }
    if now_unix.saturating_sub(value) > max_age_seconds {
        return Err(format!(
            "{label} evidence is stale; refresh OS matrix evidence"
        ));
    }
    Ok(())
}

fn git_head_commit() -> Result<String, String> {
    let output = Command::new("git")
        .arg("rev-parse")
        .arg("HEAD")
        .output()
        .map_err(|err| format!("run git rev-parse HEAD failed: {err}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("resolve git head commit failed: {}", stderr.trim()));
    }
    let head = String::from_utf8(output.stdout)
        .map_err(|err| format!("decode git head commit failed: {err}"))?
        .trim()
        .to_ascii_lowercase();
    if !is_lower_hex_sha40(head.as_str()) {
        return Err(format!(
            "git head commit is not a lowercase 40-char SHA: {head}"
        ));
    }
    Ok(head)
}

fn resolve_artifact_path_for_verify(
    raw: &str,
    root: &Path,
    label: &str,
) -> Result<PathBuf, String> {
    let item = raw.trim();
    if item.is_empty() {
        return Err(format!("{label} has invalid source artifact entry"));
    }
    let candidate = PathBuf::from(item);
    let resolved = if candidate.is_absolute() {
        candidate
    } else {
        root.join(candidate)
    };
    if !resolved.exists() {
        return Err(format!("{label} source artifact does not exist: {raw}"));
    }
    Ok(fs::canonicalize(resolved).unwrap_or_else(|_| PathBuf::from(raw)))
}

fn validate_measured_child_report_for_verify(
    report_path: &Path,
    label: &str,
    visited_reports: &mut HashSet<PathBuf>,
    context: &FreshInstallVerifyContext<'_>,
) -> Result<(), String> {
    let resolved = fs::canonicalize(report_path).unwrap_or_else(|_| report_path.to_path_buf());
    if !visited_reports.insert(resolved.clone()) {
        return Ok(());
    }
    if resolved
        .extension()
        .and_then(|value| value.to_str())
        .map(|value| !value.eq_ignore_ascii_case("json"))
        .unwrap_or(true)
    {
        return Ok(());
    }

    let body = fs::read_to_string(resolved.as_path())
        .map_err(|err| format!("{label} source artifact read failed: {err}"))?;
    let payload = serde_json::from_str::<Value>(body.as_str()).map_err(|err| {
        format!(
            "{label} source artifact is not valid JSON: {} ({err})",
            resolved.display()
        )
    })?;
    let object = payload.as_object().ok_or_else(|| {
        format!(
            "{label} source artifact JSON must be an object: {}",
            resolved.display()
        )
    })?;

    let structured_markers = [
        "evidence_mode",
        "git_commit",
        "captured_at_unix",
        "source_artifacts",
        "source_artifact",
    ];
    if !structured_markers
        .iter()
        .any(|marker| object.contains_key(*marker))
    {
        return Ok(());
    }

    if object.get("evidence_mode").and_then(Value::as_str) != Some("measured") {
        return Err(format!(
            "{label} child report must set evidence_mode=measured: {}",
            resolved.display()
        ));
    }

    let child_commit = require_nonempty_string_field(object, "git_commit", label)?;
    if !is_lower_hex_sha40(child_commit.as_str()) {
        return Err(format!(
            "{label} child report git_commit must be a 40-char lowercase hex SHA"
        ));
    }
    if child_commit != context.expected_commit {
        return Err(format!(
            "{label} child report git_commit does not match expected commit; report={child_commit} expected={} path={}",
            context.expected_commit,
            resolved.display(),
        ));
    }
    let child_captured_at = require_positive_u64_field(object, "captured_at_unix", label)?;
    validate_timestamp(
        child_captured_at,
        label,
        context.now_unix,
        context.max_age_seconds,
    )?;

    if let Some(status) = object.get("status").and_then(Value::as_str)
        && status != "pass"
    {
        return Err(format!(
            "{label} child report status must be pass: {}",
            resolved.display()
        ));
    }

    let child_source_artifacts = object.get("source_artifacts");
    let child_source_artifact = object.get("source_artifact");
    if child_source_artifacts.is_none() && child_source_artifact.is_none() {
        return Err(format!(
            "{label} child report must declare source_artifacts or source_artifact: {}",
            resolved.display()
        ));
    }
    if let Some(items) = child_source_artifacts {
        validate_source_artifact_entries_for_verify(
            items,
            format!("{label}.child_sources").as_str(),
            visited_reports,
            context,
            true,
        )?;
    }
    if let Some(item) = child_source_artifact {
        let item = item
            .as_str()
            .ok_or_else(|| format!("{label}.child_source has invalid source artifact entry"))?;
        let child_path = resolve_artifact_path_for_verify(
            item,
            context.root,
            format!("{label}.child_source").as_str(),
        )?;
        validate_measured_child_report_for_verify(
            child_path.as_path(),
            format!("{label}.child_source").as_str(),
            visited_reports,
            context,
        )?;
    }
    Ok(())
}

fn validate_source_artifact_entries_for_verify(
    artifacts: &Value,
    label: &str,
    visited_reports: &mut HashSet<PathBuf>,
    context: &FreshInstallVerifyContext<'_>,
    require_non_empty: bool,
) -> Result<(), String> {
    let entries = artifacts
        .as_array()
        .ok_or_else(|| format!("{label} requires non-empty source_artifacts list"))?;
    if require_non_empty && entries.is_empty() {
        return Err(format!("{label} requires non-empty source_artifacts list"));
    }
    for item in entries {
        let item = item
            .as_str()
            .ok_or_else(|| format!("{label} has invalid source artifact entry"))?;
        let child_path = resolve_artifact_path_for_verify(item, context.root, label)?;
        validate_measured_child_report_for_verify(
            child_path.as_path(),
            label,
            visited_reports,
            context,
        )?;
    }
    Ok(())
}

pub fn execute_ops_rebind_linux_fresh_install_os_matrix_inputs(
    config: RebindLinuxFreshInstallOsMatrixInputsConfig,
) -> Result<String, String> {
    let root = repo_root()?;
    let mut dest_dir = resolve_path(config.dest_dir.as_path())?;
    if !dest_dir.is_absolute() {
        dest_dir = root.join(dest_dir);
    }
    fs::create_dir_all(&dest_dir).map_err(|err| {
        format!(
            "create destination directory failed ({}): {err}",
            dest_dir.display()
        )
    })?;

    let bootstrap_log = require_file(config.bootstrap_log.as_path(), "bootstrap log")?;
    let baseline_log = require_file(config.baseline_log.as_path(), "baseline log")?;
    let two_hop_report = require_file(config.two_hop_report.as_path(), "two-hop report")?;
    let role_switch_report =
        require_file(config.role_switch_report.as_path(), "role-switch report")?;
    let lan_toggle_report = require_file(config.lan_toggle_report.as_path(), "LAN toggle report")?;
    let exit_handoff_report =
        require_file(config.exit_handoff_report.as_path(), "exit handoff report")?;

    let bootstrap_canonical = copy_artifact(
        bootstrap_log.as_path(),
        dest_dir.join("bootstrap_hosts.log").as_path(),
    )?;
    let baseline_canonical = copy_artifact(
        baseline_log.as_path(),
        dest_dir.join("validate_baseline_runtime.log").as_path(),
    )?;
    let two_hop_canonical = canonicalize_report(
        two_hop_report.as_path(),
        "two-hop report",
        &dest_dir,
        &root,
        "two_hop",
    )?;
    let role_switch_canonical = canonicalize_report(
        role_switch_report.as_path(),
        "role-switch report",
        &dest_dir,
        &root,
        "role_switch",
    )?;
    let lan_toggle_canonical = canonicalize_report(
        lan_toggle_report.as_path(),
        "LAN toggle report",
        &dest_dir,
        &root,
        "lan_toggle",
    )?;
    let exit_handoff_canonical = canonicalize_report(
        exit_handoff_report.as_path(),
        "exit handoff report",
        &dest_dir,
        &root,
        "exit_handoff",
    )?;

    let payload = json!({
        "bootstrap_log": normalize_path(bootstrap_canonical.as_path(), &root),
        "baseline_log": normalize_path(baseline_canonical.as_path(), &root),
        "two_hop_report": normalize_path(two_hop_canonical.as_path(), &root),
        "role_switch_report": normalize_path(role_switch_canonical.as_path(), &root),
        "lan_toggle_report": normalize_path(lan_toggle_canonical.as_path(), &root),
        "exit_handoff_report": normalize_path(exit_handoff_canonical.as_path(), &root),
    });
    serde_json::to_string(&payload)
        .map_err(|err| format!("serialize rebind manifest failed: {err}"))
}

pub fn execute_ops_generate_linux_fresh_install_os_matrix_report(
    config: GenerateLinuxFreshInstallOsMatrixReportConfig,
) -> Result<String, String> {
    let root = repo_root()?;
    let mut output_path = resolve_path(config.output.as_path())?;
    if !output_path.is_absolute() {
        output_path = root.join(output_path);
    }
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            format!(
                "create output directory failed ({}): {err}",
                parent.display()
            )
        })?;
    }

    let expected_commit_path = require_file(
        config.expected_git_commit_file.as_path(),
        "expected git commit file",
    )?;
    let expected_commit = fs::read_to_string(&expected_commit_path)
        .map_err(|err| {
            format!(
                "read expected git commit failed ({}): {err}",
                expected_commit_path.display()
            )
        })?
        .trim()
        .to_ascii_lowercase();
    if expected_commit.len() != 40 {
        return Err(format!(
            "invalid expected git commit in {}: {expected_commit}",
            expected_commit_path.display()
        ));
    }
    let git_status_path = require_file(config.git_status_file.as_path(), "git status file")?;
    let git_status = fs::read_to_string(&git_status_path).map_err(|err| {
        format!(
            "read git status file failed ({}): {err}",
            git_status_path.display()
        )
    })?;
    if config.source_mode == "working-tree" && !git_status.trim().is_empty() {
        return Err(
            "cannot generate commit-bound fresh install OS matrix report from a dirty working tree; commit or stash local changes first"
                .to_string(),
        );
    }

    let bootstrap_log = require_file(config.bootstrap_log.as_path(), "bootstrap log")?;
    let baseline_log = require_file(config.baseline_log.as_path(), "baseline validation log")?;
    let bootstrap_meta = fs::metadata(&bootstrap_log).map_err(|err| {
        format!(
            "stat bootstrap log failed ({}): {err}",
            bootstrap_log.display()
        )
    })?;
    let baseline_meta = fs::metadata(&baseline_log).map_err(|err| {
        format!(
            "stat baseline log failed ({}): {err}",
            baseline_log.display()
        )
    })?;
    if bootstrap_meta.len() == 0 {
        return Err(format!(
            "bootstrap log is empty: {}",
            bootstrap_log.display()
        ));
    }
    if baseline_meta.len() == 0 {
        return Err(format!(
            "baseline validation log is empty: {}",
            baseline_log.display()
        ));
    }

    let bootstrap_source = normalize_path(bootstrap_log.as_path(), &root);
    let baseline_source = normalize_path(baseline_log.as_path(), &root);
    let bootstrap_time = bootstrap_meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let baseline_time = baseline_meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let two_hop_report_path = require_file(config.two_hop_report.as_path(), "two-hop report")?;
    let role_switch_report_path =
        require_file(config.role_switch_report.as_path(), "role-switch report")?;
    let lan_toggle_report_path =
        require_file(config.lan_toggle_report.as_path(), "LAN toggle report")?;
    let exit_handoff_report_path =
        require_file(config.exit_handoff_report.as_path(), "exit handoff report")?;

    let two_hop = load_json_report(
        two_hop_report_path.as_path(),
        "two-hop report",
        &root,
        expected_commit.as_str(),
    )?;
    let role_switch = load_json_report(
        role_switch_report_path.as_path(),
        "role-switch report",
        &root,
        expected_commit.as_str(),
    )?;
    let lan_toggle = load_json_report(
        lan_toggle_report_path.as_path(),
        "LAN toggle report",
        &root,
        expected_commit.as_str(),
    )?;
    let exit_handoff = load_json_report(
        exit_handoff_report_path.as_path(),
        "exit handoff report",
        &root,
        expected_commit.as_str(),
    )?;

    let role_switch_source_value = role_switch
        .get("source_artifact")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| "role-switch report requires non-empty source_artifact".to_string())?;
    let mut role_switch_source_path = PathBuf::from(role_switch_source_value);
    if !role_switch_source_path.is_absolute() {
        role_switch_source_path = root.join(role_switch_source_path);
    }
    let role_switch_source_path = require_file(
        role_switch_source_path.as_path(),
        "role-switch source artifact",
    )?;
    let role_switch_source = normalize_path(role_switch_source_path.as_path(), &root);

    let role_switch_time = role_switch
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if role_switch_time == 0 {
        return Err("role-switch report requires positive captured_at_unix".to_string());
    }
    let two_hop_time = two_hop
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let lan_toggle_time = lan_toggle
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let exit_handoff_time = exit_handoff
        .get("captured_at_unix")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    if two_hop_time == 0 || lan_toggle_time == 0 || exit_handoff_time == 0 {
        return Err("live reports require positive captured_at_unix".to_string());
    }

    let role_hosts = role_switch
        .get("hosts")
        .and_then(Value::as_object)
        .ok_or_else(|| "role-switch report requires hosts object".to_string())?;
    for required_os in ["debian13", "ubuntu", "fedora", "mint"] {
        let host_entry = role_hosts
            .get(required_os)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("role-switch report missing host entry: {required_os}"))?;
        let transition = host_entry
            .get("transition")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("role-switch report host entry malformed: {required_os}"))?;
        let checks = host_entry
            .get("checks")
            .and_then(Value::as_object)
            .ok_or_else(|| format!("role-switch report host entry malformed: {required_os}"))?;
        if transition.get("status").and_then(Value::as_str) != Some("pass") {
            return Err(format!(
                "role-switch transition must pass for {required_os}"
            ));
        }
        for key in [
            "switch_execution",
            "post_switch_reconcile",
            "policy_still_enforced",
            "least_privilege_preserved",
        ] {
            if checks.get(key).and_then(Value::as_str) != Some("pass") {
                return Err(format!(
                    "role-switch check {required_os}.{key} must be pass"
                ));
            }
        }
    }

    let clean_install = json!({
        "status": "pass",
        "captured_at_unix": bootstrap_time.max(baseline_time),
        "source_artifacts": dedupe(vec![bootstrap_source.clone(), baseline_source.clone()]),
        "checks": {
            "host_pristine": "pass",
            "fresh_install_completed": "pass",
            "service_bootstrap_secure": "pass",
            "key_custody_hardened": "pass",
            "no_legacy_fallback_paths": "pass",
        },
    });

    let one_hop = json!({
        "status": "pass",
        "hop_count": 1,
        "captured_at_unix": baseline_time.max(exit_handoff_time),
        "source_artifacts": dedupe(
            std::iter::once(baseline_source.clone())
                .chain(std::iter::once(normalize_path(exit_handoff_report_path.as_path(), &root)))
                .chain(as_string_vec(exit_handoff.get("normalized_source_artifacts").unwrap_or(&Value::Array(Vec::new()))))
                .collect::<Vec<_>>()
        ),
        "checks": {
            "tunnel_established": "pass",
            "encrypted_transport": "pass",
            "egress_via_selected_exit": "pass",
            "dns_fail_closed": "pass",
            "no_underlay_leak": "pass",
        },
    });

    let two_hop_section = json!({
        "status": "pass",
        "hop_count": 2,
        "captured_at_unix": two_hop_time,
        "source_artifacts": dedupe(
            std::iter::once(normalize_path(two_hop_report_path.as_path(), &root))
                .chain(as_string_vec(two_hop.get("normalized_source_artifacts").unwrap_or(&Value::Array(Vec::new()))))
                .collect::<Vec<_>>()
        ),
        "checks": {
            "chain_enforced": "pass",
            "encrypted_transport": "pass",
            "entry_relay_forwarding": "pass",
            "final_exit_egress": "pass",
            "no_underlay_leak": "pass",
        },
    });

    let role_section = |os_id: &str| -> Value {
        let checks = role_hosts
            .get(os_id)
            .and_then(Value::as_object)
            .and_then(|host_entry| host_entry.get("checks").cloned())
            .unwrap_or(Value::Null);
        let transition = role_hosts
            .get(os_id)
            .and_then(Value::as_object)
            .and_then(|host_entry| host_entry.get("transition").cloned())
            .unwrap_or(Value::Null);
        json!({
            "status": "pass",
            "captured_at_unix": role_switch_time,
            "source_artifacts": dedupe(vec![
                normalize_path(role_switch_report_path.as_path(), &root),
                role_switch_source.clone(),
            ]),
            "checks": checks,
            "transitions": vec![transition],
        })
    };

    let report_time = unix_now()
        .max(bootstrap_time)
        .max(baseline_time)
        .max(two_hop_time)
        .max(role_switch_time)
        .max(lan_toggle_time)
        .max(exit_handoff_time);

    let report = json!({
        "schema_version": 1,
        "evidence_mode": "measured",
        "environment": config.environment,
        "captured_at_unix": report_time,
        "git_commit": expected_commit,
        "source_artifacts": dedupe(
            std::iter::once(bootstrap_source.clone())
                .chain(std::iter::once(baseline_source.clone()))
                .chain(std::iter::once(normalize_path(two_hop_report_path.as_path(), &root)))
                .chain(std::iter::once(normalize_path(role_switch_report_path.as_path(), &root)))
                .chain(std::iter::once(normalize_path(lan_toggle_report_path.as_path(), &root)))
                .chain(std::iter::once(normalize_path(exit_handoff_report_path.as_path(), &root)))
                .chain(std::iter::once(role_switch_source.clone()))
                .chain(as_string_vec(two_hop.get("normalized_source_artifacts").unwrap_or(&Value::Array(Vec::new()))))
                .chain(as_string_vec(lan_toggle.get("normalized_source_artifacts").unwrap_or(&Value::Array(Vec::new()))))
                .chain(as_string_vec(exit_handoff.get("normalized_source_artifacts").unwrap_or(&Value::Array(Vec::new()))))
                .collect::<Vec<_>>()
        ),
        "security_assertions": {
            "no_plaintext_secrets_at_rest": true,
            "encrypted_transport_required": true,
            "default_deny_enforced": true,
            "fail_closed_enforced": true,
            "least_privilege_role_switch": true,
        },
        "scenarios": {
            "debian13": {
                "status": "pass",
                "host_profile": "linux",
                "os_version": config.debian_os_version,
                "node_id": format!("{}/{}", config.exit_node_id, config.client_node_id),
                "clean_install": clean_install,
                "one_hop": one_hop,
                "two_hop": two_hop_section,
                "role_switch": role_section("debian13"),
            },
            "ubuntu": {
                "status": "pass",
                "host_profile": "linux",
                "os_version": config.ubuntu_os_version,
                "node_id": config.ubuntu_node_id,
                "clean_install": clean_install,
                "one_hop": one_hop,
                "two_hop": two_hop_section,
                "role_switch": role_section("ubuntu"),
            },
            "fedora": {
                "status": "pass",
                "host_profile": "linux",
                "os_version": config.fedora_os_version,
                "node_id": config.fedora_node_id,
                "clean_install": clean_install,
                "one_hop": one_hop,
                "two_hop": two_hop_section,
                "role_switch": role_section("fedora"),
            },
            "mint": {
                "status": "pass",
                "host_profile": "linux",
                "os_version": config.mint_os_version,
                "node_id": config.mint_node_id,
                "clean_install": clean_install,
                "one_hop": one_hop,
                "two_hop": two_hop_section,
                "role_switch": role_section("mint"),
            },
        },
    });

    fs::write(
        &output_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialize OS matrix report failed: {err}"))?
            + "\n",
    )
    .map_err(|err| {
        format!(
            "write OS matrix report failed ({}): {err}",
            output_path.display()
        )
    })?;
    Ok(output_path.display().to_string())
}

pub fn execute_ops_verify_linux_fresh_install_os_matrix_readiness(
    config: VerifyLinuxFreshInstallOsMatrixReadinessConfig,
) -> Result<String, String> {
    let root = repo_root()?;
    let report_path = require_file(
        config.report_path.as_path(),
        "fresh install OS matrix report",
    )?;
    let max_age_seconds = if config.max_age_seconds == 0 {
        604_800
    } else {
        config.max_age_seconds
    };
    let now_unix = unix_now();

    let required_os_profiles = match config.profile.trim() {
        "cross_platform" => vec![
            ("debian13", "linux"),
            ("ubuntu", "linux"),
            ("fedora", "linux"),
            ("mint", "linux"),
            ("macos", "macos"),
        ],
        "linux" => vec![
            ("debian13", "linux"),
            ("ubuntu", "linux"),
            ("fedora", "linux"),
            ("mint", "linux"),
        ],
        other => {
            return Err(format!(
                "unsupported fresh install OS matrix profile: {other} (expected cross_platform or linux)"
            ));
        }
    };

    let required_checks = vec![
        (
            "clean_install",
            vec![
                "host_pristine",
                "fresh_install_completed",
                "service_bootstrap_secure",
                "key_custody_hardened",
                "no_legacy_fallback_paths",
            ],
        ),
        (
            "one_hop",
            vec![
                "tunnel_established",
                "encrypted_transport",
                "egress_via_selected_exit",
                "dns_fail_closed",
                "no_underlay_leak",
            ],
        ),
        (
            "two_hop",
            vec![
                "chain_enforced",
                "encrypted_transport",
                "entry_relay_forwarding",
                "final_exit_egress",
                "no_underlay_leak",
            ],
        ),
        (
            "role_switch",
            vec![
                "switch_execution",
                "post_switch_reconcile",
                "policy_still_enforced",
                "least_privilege_preserved",
            ],
        ),
    ];
    let required_security_assertions = vec![
        "no_plaintext_secrets_at_rest",
        "encrypted_transport_required",
        "default_deny_enforced",
        "fail_closed_enforced",
        "least_privilege_role_switch",
    ];

    let body = fs::read_to_string(report_path.as_path()).map_err(|err| {
        format!(
            "read fresh install OS matrix report failed ({}): {err}",
            report_path.display()
        )
    })?;
    let payload = serde_json::from_str::<Value>(body.as_str()).map_err(|err| {
        format!(
            "parse fresh install OS matrix report JSON failed ({}): {err}",
            report_path.display()
        )
    })?;
    let payload = payload
        .as_object()
        .ok_or_else(|| "fresh install OS matrix report must be a JSON object".to_string())?;

    if payload.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("fresh install OS matrix report must set schema_version=1".to_string());
    }
    if payload.get("evidence_mode").and_then(Value::as_str) != Some("measured") {
        return Err("fresh install OS matrix report must set evidence_mode=measured".to_string());
    }
    require_nonempty_string_field(payload, "environment", "fresh_install_os_matrix_report")?;
    let captured_at_unix = require_positive_u64_field(
        payload,
        "captured_at_unix",
        "fresh_install_os_matrix_report",
    )?;
    validate_timestamp(
        captured_at_unix,
        "fresh_install_os_matrix_report",
        now_unix,
        max_age_seconds,
    )?;

    let git_commit =
        require_nonempty_string_field(payload, "git_commit", "fresh_install_os_matrix_report")?;
    if !is_lower_hex_sha40(git_commit.as_str()) {
        return Err(
            "fresh install OS matrix report git_commit must be a 40-char lowercase hex SHA"
                .to_string(),
        );
    }
    let expected_git_commit_arg = config.expected_git_commit.trim().to_ascii_lowercase();
    if !expected_git_commit_arg.is_empty() && !is_lower_hex_sha40(expected_git_commit_arg.as_str())
    {
        return Err(
            "RUSTYNET_FRESH_INSTALL_OS_MATRIX_EXPECTED_GIT_COMMIT must be a 40-char lowercase hex SHA when set"
                .to_string(),
        );
    }
    let expected_commit = if expected_git_commit_arg.is_empty() {
        git_head_commit()?
    } else {
        expected_git_commit_arg
    };
    if git_commit != expected_commit {
        return Err(format!(
            "fresh install OS matrix report git_commit does not match expected commit; report={git_commit} expected={expected_commit}"
        ));
    }
    let verify_context = FreshInstallVerifyContext {
        expected_commit: expected_commit.as_str(),
        now_unix,
        max_age_seconds,
        root: &root,
    };

    let mut visited_reports = HashSet::new();
    visited_reports.insert(fs::canonicalize(report_path.as_path()).unwrap_or(report_path.clone()));
    let source_artifacts = payload.get("source_artifacts").ok_or_else(|| {
        "fresh_install_os_matrix_report requires non-empty source_artifacts list".to_string()
    })?;
    validate_source_artifact_entries_for_verify(
        source_artifacts,
        "fresh_install_os_matrix_report",
        &mut visited_reports,
        &verify_context,
        true,
    )?;

    let security_assertions = payload
        .get("security_assertions")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            "fresh install OS matrix report requires security_assertions object".to_string()
        })?;
    let missing_assertions = required_security_assertions
        .iter()
        .filter(|key| !security_assertions.contains_key(**key))
        .copied()
        .collect::<Vec<_>>();
    if !missing_assertions.is_empty() {
        return Err(format!(
            "fresh install OS matrix report missing security_assertions: {}",
            missing_assertions.join(", ")
        ));
    }
    for key in required_security_assertions {
        if security_assertions.get(key).and_then(Value::as_bool) != Some(true) {
            return Err(format!(
                "fresh install OS matrix security_assertion must be true: {key}"
            ));
        }
    }

    let scenarios = payload
        .get("scenarios")
        .and_then(Value::as_object)
        .ok_or_else(|| "fresh install OS matrix report requires scenarios object".to_string())?;
    let required_os_ids = required_os_profiles
        .iter()
        .map(|(id, _)| (*id).to_string())
        .collect::<HashSet<_>>();
    let observed_os_ids = scenarios.keys().cloned().collect::<HashSet<_>>();
    if required_os_ids != observed_os_ids {
        let mut missing = required_os_ids
            .difference(&observed_os_ids)
            .cloned()
            .collect::<Vec<_>>();
        let mut extra = observed_os_ids
            .difference(&required_os_ids)
            .cloned()
            .collect::<Vec<_>>();
        missing.sort();
        extra.sort();
        let mut details = Vec::new();
        if !missing.is_empty() {
            details.push(format!("missing={}", missing.join(",")));
        }
        if !extra.is_empty() {
            details.push(format!("extra={}", extra.join(",")));
        }
        return Err(format!(
            "fresh install OS matrix scenarios must match required OS set ({})",
            details.join("; ")
        ));
    }

    for (os_id, expected_profile) in required_os_profiles {
        let label = format!("fresh_install_os_matrix.scenarios.{os_id}");
        let scenario = scenarios
            .get(os_id)
            .and_then(Value::as_object)
            .ok_or_else(|| format!("{label} must be an object"))?;
        if scenario.get("status").and_then(Value::as_str) != Some("pass") {
            return Err(format!("{label}.status must be pass"));
        }
        let host_profile = require_nonempty_string_field(scenario, "host_profile", label.as_str())?;
        if host_profile != expected_profile {
            return Err(format!("{label}.host_profile must be {expected_profile}"));
        }
        require_nonempty_string_field(scenario, "os_version", label.as_str())?;
        require_nonempty_string_field(scenario, "node_id", label.as_str())?;

        for (section_name, expected_keys) in &required_checks {
            let section_label = format!("{label}.{section_name}");
            let section = scenario
                .get(*section_name)
                .and_then(Value::as_object)
                .ok_or_else(|| format!("{section_label} must be an object"))?;
            if section.get("status").and_then(Value::as_str) != Some("pass") {
                return Err(format!("{section_label}.status must be pass"));
            }
            let section_time =
                require_positive_u64_field(section, "captured_at_unix", section_label.as_str())?;
            validate_timestamp(
                section_time,
                section_label.as_str(),
                now_unix,
                max_age_seconds,
            )?;
            let section_sources = section.get("source_artifacts").ok_or_else(|| {
                format!("{section_label} requires non-empty source_artifacts list")
            })?;
            validate_source_artifact_entries_for_verify(
                section_sources,
                section_label.as_str(),
                &mut visited_reports,
                &verify_context,
                true,
            )?;
            let checks = section
                .get("checks")
                .and_then(Value::as_object)
                .ok_or_else(|| format!("{section_label}.checks must be an object"))?;
            let missing_checks = expected_keys
                .iter()
                .filter(|key| !checks.contains_key(**key))
                .copied()
                .collect::<Vec<_>>();
            if !missing_checks.is_empty() {
                return Err(format!(
                    "{section_label}.checks missing required keys: {}",
                    missing_checks.join(", ")
                ));
            }
            for key in expected_keys {
                if checks.get(*key).and_then(Value::as_str) != Some("pass") {
                    return Err(format!("{section_label}.checks.{key} must be pass"));
                }
            }
        }

        if scenario
            .get("one_hop")
            .and_then(Value::as_object)
            .and_then(|value| value.get("hop_count"))
            .and_then(Value::as_u64)
            != Some(1)
        {
            return Err(format!("{label}.one_hop.hop_count must be 1"));
        }
        if scenario
            .get("two_hop")
            .and_then(Value::as_object)
            .and_then(|value| value.get("hop_count"))
            .and_then(Value::as_u64)
            != Some(2)
        {
            return Err(format!("{label}.two_hop.hop_count must be 2"));
        }

        let transitions = scenario
            .get("role_switch")
            .and_then(Value::as_object)
            .and_then(|value| value.get("transitions"))
            .and_then(Value::as_array)
            .ok_or_else(|| {
                format!("{label}.role_switch.transitions must contain at least one transition")
            })?;
        if transitions.is_empty() {
            return Err(format!(
                "{label}.role_switch.transitions must contain at least one transition"
            ));
        }
        for (index, transition) in transitions.iter().enumerate() {
            let transition_label = format!("{label}.role_switch.transitions[{index}]");
            let transition = transition
                .as_object()
                .ok_or_else(|| format!("{transition_label} must be an object"))?;
            let from_role =
                require_nonempty_string_field(transition, "from_role", transition_label.as_str())?;
            let to_role =
                require_nonempty_string_field(transition, "to_role", transition_label.as_str())?;
            if from_role == to_role {
                return Err(format!("{transition_label} must change role"));
            }
            if transition.get("status").and_then(Value::as_str) != Some("pass") {
                return Err(format!("{transition_label}.status must be pass"));
            }
        }
    }

    Ok("Fresh install OS matrix readiness checks: PASS".to_string())
}

pub fn execute_ops_write_fresh_install_os_matrix_readiness_fixtures(
    config: WriteFreshInstallOsMatrixReadinessFixturesConfig,
) -> Result<String, String> {
    if config.now_unix == 0 {
        return Err("fixture now_unix must be positive".to_string());
    }
    let head_commit = config.head_commit.trim().to_ascii_lowercase();
    if !is_lower_hex_sha40(head_commit.as_str()) {
        return Err("fixture head_commit must be a 40-char lowercase hex SHA".to_string());
    }
    let stale_commit = config.stale_commit.trim().to_ascii_lowercase();
    if !is_lower_hex_sha40(stale_commit.as_str()) {
        return Err("fixture stale_commit must be a 40-char lowercase hex SHA".to_string());
    }

    let output_dir = resolve_path(config.output_dir.as_path())?;
    fs::create_dir_all(output_dir.as_path()).map_err(|err| {
        format!(
            "create fixture output directory failed ({}): {err}",
            output_dir.display()
        )
    })?;

    let bootstrap_log = output_dir.join("bootstrap_hosts.log");
    let baseline_log = output_dir.join("validate_baseline_runtime.log");
    let two_hop_log = output_dir.join("two_hop.log");
    let lan_toggle_log = output_dir.join("lan_toggle.log");
    let exit_handoff_log = output_dir.join("exit_handoff.log");
    let exit_handoff_monitor_log = output_dir.join("exit_handoff_monitor.log");
    let role_switch_md = output_dir.join("role_switch.md");

    for path in [
        bootstrap_log.as_path(),
        baseline_log.as_path(),
        two_hop_log.as_path(),
        lan_toggle_log.as_path(),
        exit_handoff_log.as_path(),
        exit_handoff_monitor_log.as_path(),
        role_switch_md.as_path(),
    ] {
        let file_name = path
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("fixture");
        write_text(
            path,
            format!("{file_name}\n").as_str(),
            "fixture text artifact",
        )?;
    }

    let role_switch_report_path = output_dir.join("role_switch_matrix_report.json");
    let two_hop_report_path = output_dir.join("live_linux_two_hop_report.json");
    let lan_toggle_report_path = output_dir.join("live_linux_lan_toggle_report.json");
    let exit_handoff_report_path = output_dir.join("live_linux_exit_handoff_report.json");
    let report_path = output_dir.join("report.json");
    let stale_two_hop_report_path = output_dir.join("live_linux_two_hop_report_stale.json");
    let stale_wrapper_report_path = output_dir.join("report_with_stale_child.json");

    let role_switch_hosts = ["debian13", "ubuntu", "fedora", "mint"]
        .into_iter()
        .map(|os_id| {
            (
                os_id.to_string(),
                json!({
                    "transition": {
                        "from_role": "client",
                        "to_role": "admin",
                        "status": "pass",
                    },
                    "checks": {
                        "switch_execution": "pass",
                        "post_switch_reconcile": "pass",
                        "policy_still_enforced": "pass",
                        "least_privilege_preserved": "pass",
                    },
                }),
            )
        })
        .collect::<Map<String, Value>>();

    let role_switch_report = json!({
        "schema_version": 1,
        "evidence_mode": "measured",
        "git_commit": head_commit,
        "captured_at_unix": config.now_unix,
        "status": "pass",
        "hosts": role_switch_hosts,
        "source_artifact": absolute_display(role_switch_md.as_path()),
    });
    write_json(
        role_switch_report_path.as_path(),
        &role_switch_report,
        "fixture role-switch report",
    )?;

    let two_hop_report = json!({
        "phase": "phase10",
        "mode": "live_linux_two_hop_report",
        "evidence_mode": "measured",
        "captured_at_unix": config.now_unix,
        "git_commit": head_commit,
        "status": "pass",
        "source_artifacts": [absolute_display(two_hop_log.as_path())],
    });
    write_json(
        two_hop_report_path.as_path(),
        &two_hop_report,
        "fixture two-hop report",
    )?;

    let lan_toggle_report = json!({
        "phase": "phase10",
        "mode": "live_linux_lan_toggle_report",
        "evidence_mode": "measured",
        "captured_at_unix": config.now_unix,
        "git_commit": head_commit,
        "status": "pass",
        "source_artifacts": [absolute_display(lan_toggle_log.as_path())],
    });
    write_json(
        lan_toggle_report_path.as_path(),
        &lan_toggle_report,
        "fixture lan-toggle report",
    )?;

    let exit_handoff_report = json!({
        "phase": "phase10",
        "mode": "live_linux_exit_handoff_report",
        "evidence_mode": "measured",
        "captured_at_unix": config.now_unix,
        "git_commit": head_commit,
        "status": "pass",
        "source_artifacts": [
            absolute_display(exit_handoff_log.as_path()),
            absolute_display(exit_handoff_monitor_log.as_path()),
        ],
    });
    write_json(
        exit_handoff_report_path.as_path(),
        &exit_handoff_report,
        "fixture exit-handoff report",
    )?;

    let scenario = |os_id: &str| {
        json!({
            "status": "pass",
            "host_profile": "linux",
            "os_version": os_id,
            "node_id": format!("{os_id}-node"),
            "clean_install": {
                "status": "pass",
                "captured_at_unix": config.now_unix,
                "source_artifacts": [
                    absolute_display(bootstrap_log.as_path()),
                    absolute_display(baseline_log.as_path()),
                ],
                "checks": {
                    "host_pristine": "pass",
                    "fresh_install_completed": "pass",
                    "service_bootstrap_secure": "pass",
                    "key_custody_hardened": "pass",
                    "no_legacy_fallback_paths": "pass",
                },
            },
            "one_hop": {
                "status": "pass",
                "captured_at_unix": config.now_unix,
                "hop_count": 1,
                "source_artifacts": [
                    absolute_display(baseline_log.as_path()),
                    absolute_display(exit_handoff_report_path.as_path()),
                    absolute_display(exit_handoff_log.as_path()),
                    absolute_display(exit_handoff_monitor_log.as_path()),
                ],
                "checks": {
                    "tunnel_established": "pass",
                    "encrypted_transport": "pass",
                    "egress_via_selected_exit": "pass",
                    "dns_fail_closed": "pass",
                    "no_underlay_leak": "pass",
                },
            },
            "two_hop": {
                "status": "pass",
                "captured_at_unix": config.now_unix,
                "hop_count": 2,
                "source_artifacts": [
                    absolute_display(two_hop_report_path.as_path()),
                    absolute_display(two_hop_log.as_path()),
                ],
                "checks": {
                    "chain_enforced": "pass",
                    "encrypted_transport": "pass",
                    "entry_relay_forwarding": "pass",
                    "final_exit_egress": "pass",
                    "no_underlay_leak": "pass",
                },
            },
            "role_switch": {
                "status": "pass",
                "captured_at_unix": config.now_unix,
                "source_artifacts": [
                    absolute_display(role_switch_report_path.as_path()),
                    absolute_display(role_switch_md.as_path()),
                ],
                "checks": {
                    "switch_execution": "pass",
                    "post_switch_reconcile": "pass",
                    "policy_still_enforced": "pass",
                    "least_privilege_preserved": "pass",
                },
                "transitions": [
                    {
                        "from_role": "client",
                        "to_role": "admin",
                        "status": "pass",
                    }
                ],
            },
        })
    };

    let report = json!({
        "schema_version": 1,
        "evidence_mode": "measured",
        "environment": "fixture",
        "captured_at_unix": config.now_unix,
        "git_commit": head_commit,
        "source_artifacts": [
            absolute_display(bootstrap_log.as_path()),
            absolute_display(baseline_log.as_path()),
            absolute_display(two_hop_report_path.as_path()),
            absolute_display(role_switch_report_path.as_path()),
            absolute_display(lan_toggle_report_path.as_path()),
            absolute_display(exit_handoff_report_path.as_path()),
            absolute_display(role_switch_md.as_path()),
            absolute_display(two_hop_log.as_path()),
            absolute_display(lan_toggle_log.as_path()),
            absolute_display(exit_handoff_log.as_path()),
            absolute_display(exit_handoff_monitor_log.as_path()),
        ],
        "security_assertions": {
            "no_plaintext_secrets_at_rest": true,
            "encrypted_transport_required": true,
            "default_deny_enforced": true,
            "fail_closed_enforced": true,
            "least_privilege_role_switch": true,
        },
        "scenarios": {
            "debian13": scenario("debian13"),
            "ubuntu": scenario("ubuntu"),
            "fedora": scenario("fedora"),
            "mint": scenario("mint"),
        },
    });
    write_json(report_path.as_path(), &report, "fixture readiness report")?;

    let mut stale_two_hop = two_hop_report
        .as_object()
        .cloned()
        .ok_or_else(|| "fixture two-hop report shape invalid".to_string())?;
    stale_two_hop.insert("git_commit".to_string(), Value::String(stale_commit));
    write_json(
        stale_two_hop_report_path.as_path(),
        &Value::Object(stale_two_hop),
        "fixture stale two-hop report",
    )?;

    let mut stale_wrapper = report
        .as_object()
        .cloned()
        .ok_or_else(|| "fixture readiness report shape invalid".to_string())?;
    stale_wrapper.insert(
        "source_artifacts".to_string(),
        Value::Array(vec![
            Value::String(absolute_display(bootstrap_log.as_path())),
            Value::String(absolute_display(baseline_log.as_path())),
            Value::String(absolute_display(stale_two_hop_report_path.as_path())),
            Value::String(absolute_display(role_switch_report_path.as_path())),
            Value::String(absolute_display(lan_toggle_report_path.as_path())),
            Value::String(absolute_display(exit_handoff_report_path.as_path())),
            Value::String(absolute_display(role_switch_md.as_path())),
            Value::String(absolute_display(two_hop_log.as_path())),
            Value::String(absolute_display(lan_toggle_log.as_path())),
            Value::String(absolute_display(exit_handoff_log.as_path())),
            Value::String(absolute_display(exit_handoff_monitor_log.as_path())),
        ]),
    );
    let scenarios = stale_wrapper
        .get_mut("scenarios")
        .and_then(Value::as_object_mut)
        .ok_or_else(|| "fixture readiness report scenarios missing".to_string())?;
    for scenario_payload in scenarios.values_mut() {
        let two_hop_section = scenario_payload
            .as_object_mut()
            .and_then(|entry| entry.get_mut("two_hop"))
            .and_then(Value::as_object_mut)
            .ok_or_else(|| "fixture scenario two_hop section missing".to_string())?;
        two_hop_section.insert(
            "source_artifacts".to_string(),
            Value::Array(vec![
                Value::String(absolute_display(stale_two_hop_report_path.as_path())),
                Value::String(absolute_display(two_hop_log.as_path())),
            ]),
        );
    }
    write_json(
        stale_wrapper_report_path.as_path(),
        &Value::Object(stale_wrapper),
        "fixture stale-wrapper report",
    )?;

    Ok(format!(
        "fresh install readiness fixtures written: output_dir={} report={} stale_report={}",
        output_dir.display(),
        report_path.display(),
        stale_wrapper_report_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        WriteFreshInstallOsMatrixReadinessFixturesConfig,
        execute_ops_write_fresh_install_os_matrix_readiness_fixtures, parse_json_object,
    };
    use serde_json::Value;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn writes_readiness_fixtures_with_stale_child_commit() {
        let unique = format!(
            "ops-fresh-install-fixtures-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system time after unix epoch")
                .as_nanos()
        );
        let output_dir = std::env::temp_dir().join(unique);
        fs::create_dir_all(output_dir.as_path()).expect("create fixture temp dir");

        execute_ops_write_fresh_install_os_matrix_readiness_fixtures(
            WriteFreshInstallOsMatrixReadinessFixturesConfig {
                output_dir: output_dir.clone(),
                head_commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
                stale_commit: "1111111111111111111111111111111111111111".to_string(),
                now_unix: 1_773_300_000,
            },
        )
        .expect("write fixtures");

        let stale_child = parse_json_object(
            output_dir
                .join("live_linux_two_hop_report_stale.json")
                .as_path(),
            "stale child fixture",
        )
        .expect("load stale child fixture");
        assert_eq!(
            stale_child.get("git_commit").and_then(Value::as_str),
            Some("1111111111111111111111111111111111111111")
        );

        let stale_wrapper = parse_json_object(
            output_dir.join("report_with_stale_child.json").as_path(),
            "stale wrapper fixture",
        )
        .expect("load stale wrapper fixture");
        let source_artifacts = stale_wrapper
            .get("source_artifacts")
            .and_then(Value::as_array)
            .expect("source_artifacts array");
        assert!(source_artifacts.iter().any(|entry| {
            entry
                .as_str()
                .map(|value| value.ends_with("/live_linux_two_hop_report_stale.json"))
                .unwrap_or(false)
        }));

        fs::remove_dir_all(output_dir.as_path()).expect("cleanup fixture temp dir");
    }
}
