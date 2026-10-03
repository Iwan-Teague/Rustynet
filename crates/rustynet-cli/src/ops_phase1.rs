#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing
    )
)]

use std::collections::{BTreeSet, HashMap};
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use nix::unistd::Uid;
use serde_json::{Map, Value, json};

const DEFAULT_PHASE1_MEASURED_INPUT_PATH: &str = "artifacts/perf/phase1/measured_input.json";
const DEFAULT_PHASE1_RUNTIME_REPORT_PATH: &str = "artifacts/perf/phase1/baseline.json";
const DEFAULT_PHASE1_BACKEND_REPORT_PATH: &str = "artifacts/perf/phase1/backend_contract_perf.json";
pub const DEFAULT_PHASE1_PERF_REGRESSION_PHASE1_REPORT_PATH: &str =
    "artifacts/perf/phase1/baseline.json";
pub const DEFAULT_PHASE1_PERF_REGRESSION_PHASE3_REPORT_PATH: &str =
    "artifacts/perf/phase3/mesh_baseline.json";
pub const DEFAULT_DEPENDENCY_EXCEPTIONS_PATH: &str =
    "documents/operations/dependency_exceptions.json";
pub const DEFAULT_UNSAFE_SCAN_ROOT_PATH: &str = "crates";
pub const DEFAULT_SECRETS_HYGIENE_SCAN_ROOT_PATH: &str = ".";

const PHASE1_IDLE_CPU_ALIASES: &[&str] = &["idle_cpu_percent"];
const PHASE1_IDLE_MEMORY_ALIASES: &[&str] = &["idle_memory_mb", "idle_rss_mb"];
const PHASE1_RECONNECT_ALIASES: &[&str] = &["reconnect_seconds", "reconnect_p95_seconds"];
const PHASE1_ROUTE_APPLY_ALIASES: &[&str] = &["route_apply_p95_seconds", "route_apply_seconds_p95"];
const PHASE1_THROUGHPUT_ALIASES: &[&str] = &[
    "throughput_overhead_percent",
    "throughput_overhead_vs_wireguard_percent",
];
const PHASE1_BACKEND_THROUGHPUT_ALIASES: &[&str] = &[
    "backend_throughput_overhead_percent",
    "backend_overhead_percent",
    "throughput_overhead_percent",
    "throughput_overhead_vs_wireguard_percent",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckNoUnsafeRustSourcesConfig {
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckDependencyExceptionsConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckPerfRegressionConfig {
    pub phase1_report_path: PathBuf,
    pub phase3_report_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSecretsHygieneConfig {
    pub root: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
struct Phase1MeasuredInput {
    source_path: PathBuf,
    sample_count: usize,
    idle_cpu_percent: f64,
    idle_memory_mb: f64,
    reconnect_seconds: f64,
    route_policy_apply_p95_seconds: f64,
    throughput_overhead_percent: f64,
    backend_throughput_overhead_percent: f64,
}

#[derive(Debug, Default, Clone, PartialEq)]
struct Phase1MetricAccumulator {
    sample_count: usize,
    idle_cpu_percent: Option<f64>,
    idle_memory_mb: Option<f64>,
    reconnect_seconds: Option<f64>,
    route_policy_apply_p95_seconds: Option<f64>,
    throughput_overhead_percent: Option<f64>,
    backend_throughput_overhead_percent: Option<f64>,
}

impl Phase1MetricAccumulator {
    fn consume_object(&mut self, entry: &Map<String, Value>, label: &str) -> Result<(), String> {
        let idle_cpu_percent = phase1_require_metric(entry, PHASE1_IDLE_CPU_ALIASES, label)?;
        let idle_memory_mb = phase1_require_metric(entry, PHASE1_IDLE_MEMORY_ALIASES, label)?;
        let reconnect_seconds = phase1_require_metric(entry, PHASE1_RECONNECT_ALIASES, label)?;
        let route_policy_apply_p95_seconds =
            phase1_require_metric(entry, PHASE1_ROUTE_APPLY_ALIASES, label)?;
        let throughput_overhead_percent =
            phase1_require_metric(entry, PHASE1_THROUGHPUT_ALIASES, label)?;
        let backend_throughput_overhead_percent =
            phase1_require_metric(entry, PHASE1_BACKEND_THROUGHPUT_ALIASES, label)?;

        self.sample_count += 1;
        phase1_update_max(&mut self.idle_cpu_percent, idle_cpu_percent);
        phase1_update_max(&mut self.idle_memory_mb, idle_memory_mb);
        phase1_update_max(&mut self.reconnect_seconds, reconnect_seconds);
        phase1_update_max(
            &mut self.route_policy_apply_p95_seconds,
            route_policy_apply_p95_seconds,
        );
        phase1_update_max(
            &mut self.throughput_overhead_percent,
            throughput_overhead_percent,
        );
        phase1_update_max(
            &mut self.backend_throughput_overhead_percent,
            backend_throughput_overhead_percent,
        );
        Ok(())
    }

    fn into_measured_input(self, source_path: PathBuf) -> Result<Phase1MeasuredInput, String> {
        if self.sample_count == 0 {
            return Err(format!(
                "no measured entries found in {}",
                source_path.display()
            ));
        }
        Ok(Phase1MeasuredInput {
            source_path,
            sample_count: self.sample_count,
            idle_cpu_percent: self
                .idle_cpu_percent
                .ok_or_else(|| "missing idle_cpu_percent metric".to_owned())?,
            idle_memory_mb: self
                .idle_memory_mb
                .ok_or_else(|| "missing idle_memory_mb metric".to_owned())?,
            reconnect_seconds: self
                .reconnect_seconds
                .ok_or_else(|| "missing reconnect_seconds metric".to_owned())?,
            route_policy_apply_p95_seconds: self
                .route_policy_apply_p95_seconds
                .ok_or_else(|| "missing route_policy_apply_p95_seconds metric".to_owned())?,
            throughput_overhead_percent: self
                .throughput_overhead_percent
                .ok_or_else(|| "missing throughput_overhead_percent metric".to_owned())?,
            backend_throughput_overhead_percent: self
                .backend_throughput_overhead_percent
                .ok_or_else(|| "missing backend_throughput_overhead_percent metric".to_owned())?,
        })
    }
}

fn phase1_update_max(current: &mut Option<f64>, value: f64) {
    let next = match current {
        Some(existing) => (*existing).max(value),
        None => value,
    };
    *current = Some(next);
}

/// X2: typed view over a single entry in a Phase 1 report's
/// `metrics` array, walked by `phase1_validate_report`.
///
/// Field-shape rules:
/// * `name: String` and `status: String` are required. Missing or
///   wrong-type fields fail at deserialize with a precise serde
///   error; the validator wraps that error with the report label
///   and path so reviewers see which file is at fault.
/// * `value: Value` is left as `Value` on purpose. The downstream
///   `phase1_value_as_number` helper performs a custom multi-shape
///   coercion (rejects bools; accepts f64/i64/u64; requires
///   finite + non-negative). Forcing a typed numeric here would
///   change the contract — e.g. an integer-shaped `value: 5` would
///   fail an `f64` typed slot. Keep the helper as the single source
///   of truth and route the typed slot through it.
/// * `reason: Option<String>` lets the validator distinguish
///   absent-reason from present-string; a wrong-type slot fails at
///   deserialize.
/// * `#[serde(flatten)] extra` preserves any other metric fields
///   the report shape may carry (forward-compat).
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct Phase1MetricEntryView {
    pub name: Option<String>,
    pub value: Option<Value>,
    pub status: Option<String>,
    pub reason: Option<String>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

/// X2: typed view over the top-level shape walked by
/// `phase1_validate_report`. The validator only reads `metrics`,
/// so the typed view exposes that one required-shape slot and rides
/// every other field through `#[serde(flatten)] extra`.
///
/// `metrics: Option<Vec<Phase1MetricEntryView>>` is `Option<_>` so
/// the validator can emit the legacy "missing metrics array" error
/// message instead of bubbling a serde error. A present-but-wrong-
/// type `metrics` field (e.g. `metrics: {}`) still fails at
/// deserialize, with the precise serde error wrapped at the
/// validator boundary.
#[derive(Debug, Clone, PartialEq, serde::Deserialize, Default)]
#[serde(default)]
struct Phase1ValidateReportView {
    pub metrics: Option<Vec<Phase1MetricEntryView>>,
    #[allow(dead_code)]
    #[serde(flatten)]
    extra: Map<String, Value>,
}

fn phase1_value_as_number(value: &Value) -> Option<f64> {
    if value.is_boolean() {
        return None;
    }
    let numeric = value.as_f64()?;
    if !numeric.is_finite() || numeric < 0.0 {
        return None;
    }
    Some(numeric)
}

fn phase1_require_metric(
    entry: &Map<String, Value>,
    aliases: &[&str],
    label: &str,
) -> Result<f64, String> {
    for alias in aliases {
        if let Some(value) = entry.get(*alias).and_then(phase1_value_as_number) {
            return Ok(value);
        }
    }
    Err(format!(
        "missing required metric in {label}; expected one of: {}",
        aliases.join(", ")
    ))
}

fn phase1_resolve_path(raw_path: &str) -> Result<PathBuf, String> {
    let trimmed = raw_path.trim();
    if trimmed.is_empty() {
        return Err("path must not be empty".to_owned());
    }
    let path = PathBuf::from(trimmed);
    if path.is_absolute() {
        return Ok(path);
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn env_optional_string(key: &str) -> Result<Option<String>, String> {
    match std::env::var(key) {
        Ok(value) => {
            if value.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(value))
            }
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => {
            Err(format!("environment variable {key} contains non-utf8 data"))
        }
    }
}

fn phase1_path_from_env_or_default(key: &str, default: &str) -> Result<PathBuf, String> {
    let raw = env_optional_string(key)?.unwrap_or_else(|| default.to_owned());
    phase1_resolve_path(raw.as_str())
}

fn parse_bool_value(key: &str, value: &str) -> Result<bool, String> {
    match value {
        "true" | "TRUE" | "yes" | "YES" | "1" | "on" | "ON" => Ok(true),
        "false" | "FALSE" | "no" | "NO" | "0" | "off" | "OFF" | "" => Ok(false),
        _ => Err(format!("invalid boolean value for {key}: {value}")),
    }
}

fn parse_env_bool_with_default(key: &str, default: &str) -> Result<bool, String> {
    let value = env_optional_string(key)?.unwrap_or_else(|| default.to_owned());
    parse_bool_value(key, value.as_str())
}

fn phase1_validate_non_writable_by_group_or_world(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<(), String> {
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        return Err(format!(
            "{label} must not be group/world writable ({} mode {:o})",
            path.display(),
            mode & 0o777
        ));
    }
    Ok(())
}

fn phase1_validate_trusted_owner(
    path: &Path,
    metadata: &fs::Metadata,
    label: &str,
) -> Result<(), String> {
    let owner_uid = metadata.uid();
    let expected_uid = Uid::effective().as_raw();
    if owner_uid != expected_uid {
        return Err(format!(
            "{label} owner is not trusted ({} uid={owner_uid} expected_uid={expected_uid})",
            path.display()
        ));
    }
    Ok(())
}

fn phase1_harden_file_write_bits_if_needed(
    path: &Path,
    metadata: fs::Metadata,
    label: &str,
) -> Result<fs::Metadata, String> {
    phase1_validate_trusted_owner(path, &metadata, label)?;
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        let hardened_mode = mode & !0o022;
        fs::set_permissions(path, fs::Permissions::from_mode(hardened_mode)).map_err(|err| {
            format!(
                "failed to harden {label} write bits ({} mode {:o} -> {:o}): {err}",
                path.display(),
                mode & 0o777,
                hardened_mode & 0o777
            )
        })?;
    }
    let refreshed_metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "inspect {label} failed after hardening ({}): {err}",
            path.display()
        )
    })?;
    phase1_validate_non_writable_by_group_or_world(path, &refreshed_metadata, label)?;
    Ok(refreshed_metadata)
}

fn phase1_harden_directory_write_bits_if_needed(
    path: &Path,
    metadata: fs::Metadata,
    label: &str,
) -> Result<fs::Metadata, String> {
    phase1_validate_trusted_owner(path, &metadata, label)?;
    let mode = metadata.permissions().mode();
    if mode & 0o022 != 0 {
        let hardened_mode = mode & !0o022;
        fs::set_permissions(path, fs::Permissions::from_mode(hardened_mode)).map_err(|err| {
            format!(
                "failed to harden {label} write bits ({} mode {:o} -> {:o}): {err}",
                path.display(),
                mode & 0o777,
                hardened_mode & 0o777
            )
        })?;
    }
    let refreshed_metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "inspect {label} failed after hardening ({}): {err}",
            path.display()
        )
    })?;
    if refreshed_metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !refreshed_metadata.file_type().is_dir() {
        return Err(format!("{label} must be a directory: {}", path.display()));
    }
    phase1_validate_non_writable_by_group_or_world(path, &refreshed_metadata, label)?;
    Ok(refreshed_metadata)
}

fn phase1_validate_secure_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!("{label} must be a directory: {}", path.display()));
    }
    let _ = phase1_harden_directory_write_bits_if_needed(path, metadata, label)?;
    Ok(())
}

fn phase1_validate_source_path(path: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path).map_err(|err| {
        format!(
            "phase1 metrics source path does not exist: {} ({err})",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err(format!(
            "phase1 metrics source path must not be a symlink: {}",
            path.display()
        ));
    }
    if !metadata.file_type().is_file() {
        return Err(format!(
            "phase1 metrics source path must be a regular file: {}",
            path.display()
        ));
    }
    if metadata.len() == 0 {
        return Err(format!(
            "phase1 metrics source file is empty: {}",
            path.display()
        ));
    }
    let _ = phase1_harden_file_write_bits_if_needed(path, metadata, "phase1 metrics source file")?;
    Ok(())
}

fn resolve_phase1_measured_source_path() -> Result<PathBuf, String> {
    let configured_path = env_optional_string("RUSTYNET_PHASE1_PERF_SAMPLES_PATH")?.ok_or_else(
        || {
            "missing required measured source path: RUSTYNET_PHASE1_PERF_SAMPLES_PATH\n\
             fallback source discovery is disabled for phase1 security gating.\n\
             expected canonical source (default): artifacts/perf/phase1/source/performance_samples.ndjson".to_owned()
        },
    )?;
    let resolved = phase1_resolve_path(configured_path.as_str())?;
    phase1_validate_source_path(resolved.as_path())?;
    Ok(resolved)
}

fn read_json_value(path: &Path, label: &str) -> Result<Value, String> {
    let body = fs::read_to_string(path)
        .map_err(|err| format!("read {label} failed ({}): {err}", path.display()))?;
    serde_json::from_str(body.as_str())
        .map_err(|err| format!("parse {label} failed ({}): {err}", path.display()))
}

fn phase1_collect_measured_input_from_source(
    source_path: &Path,
) -> Result<Phase1MeasuredInput, String> {
    phase1_validate_source_path(source_path)?;
    let mut accumulator = Phase1MetricAccumulator::default();
    let extension = source_path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    if extension == "ndjson" {
        let file = fs::File::open(source_path).map_err(|err| {
            format!(
                "open measured phase1 source failed ({}): {err}",
                source_path.display()
            )
        })?;
        let reader = BufReader::new(file);
        for (line_index, line_result) in reader.lines().enumerate() {
            let line_number = line_index + 1;
            let line = line_result.map_err(|err| {
                format!(
                    "read measured source line failed ({}:{}): {err}",
                    source_path.display(),
                    line_number
                )
            })?;
            let stripped = line.trim();
            if stripped.is_empty() {
                continue;
            }
            let value: Value = serde_json::from_str(stripped).map_err(|err| {
                format!(
                    "invalid ndjson at {}:{}: {err}",
                    source_path.display(),
                    line_number
                )
            })?;
            let object = value.as_object().ok_or_else(|| {
                format!(
                    "invalid ndjson object at {}:{}",
                    source_path.display(),
                    line_number
                )
            })?;
            if let Some(mode) = object.get("evidence_mode").and_then(Value::as_str)
                && mode != "measured"
            {
                return Err(format!(
                    "ndjson source is not measured evidence at {}:{}: evidence_mode={mode}",
                    source_path.display(),
                    line_number
                ));
            }
            accumulator.consume_object(
                object,
                format!("{}:{}", source_path.display(), line_number).as_str(),
            )?;
        }
        return accumulator.into_measured_input(source_path.to_path_buf());
    }

    let payload = read_json_value(source_path, "phase1 measured source payload")?;
    let payload_object = payload
        .as_object()
        .ok_or_else(|| format!("json source must be object: {}", source_path.display()))?;
    if let Some(mode) = payload_object.get("evidence_mode").and_then(Value::as_str)
        && mode != "measured"
    {
        return Err(format!(
            "json source is not measured evidence ({}): evidence_mode={mode}",
            source_path.display()
        ));
    }

    if let Some(metrics) = payload_object.get("metrics").and_then(Value::as_array) {
        let mut flattened = Map::new();
        for (index, metric) in metrics.iter().enumerate() {
            let metric_object = metric.as_object().ok_or_else(|| {
                format!(
                    "invalid metrics entry at index {index} in {}: expected object",
                    source_path.display()
                )
            })?;
            let Some(name) = metric_object.get("name").and_then(Value::as_str) else {
                continue;
            };
            let Some(value) = metric_object.get("value").and_then(phase1_value_as_number) else {
                continue;
            };
            flattened.insert(name.to_owned(), json!(value));
        }
        for key in [
            "idle_cpu_percent",
            "idle_memory_mb",
            "idle_rss_mb",
            "reconnect_seconds",
            "reconnect_p95_seconds",
            "route_apply_p95_seconds",
            "route_apply_seconds_p95",
            "throughput_overhead_percent",
            "throughput_overhead_vs_wireguard_percent",
            "backend_throughput_overhead_percent",
            "backend_overhead_percent",
        ] {
            if !flattened.contains_key(key)
                && let Some(value) = payload_object.get(key).and_then(phase1_value_as_number)
            {
                flattened.insert(key.to_owned(), json!(value));
            }
        }
        accumulator.consume_object(&flattened, source_path.display().to_string().as_str())?;
        return accumulator.into_measured_input(source_path.to_path_buf());
    }

    accumulator.consume_object(payload_object, source_path.display().to_string().as_str())?;
    accumulator.into_measured_input(source_path.to_path_buf())
}

fn create_secure_temp_file(dir: &Path, prefix: &str) -> Result<PathBuf, String> {
    fs::create_dir_all(dir)
        .map_err(|err| format!("create temp directory {} failed: {err}", dir.display()))?;
    phase1_validate_secure_directory(dir, "phase1 temp directory")?;
    let pid = std::process::id();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| format!("system time before unix epoch: {err}"))?
        .as_nanos();
    for counter in 0..32u32 {
        let candidate = dir.join(format!("{prefix}{pid}-{nonce}-{counter}"));
        let file_open = OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(&candidate);
        match file_open {
            Ok(_) => return Ok(candidate),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(format!(
                    "create secure temp file {} failed: {err}",
                    candidate.display()
                ));
            }
        }
    }
    Err(format!(
        "unable to allocate secure temporary file in {}",
        dir.display()
    ))
}

fn phase1_write_measured_input_artifact(
    output_path: &Path,
    measured_input: &Phase1MeasuredInput,
) -> Result<(), String> {
    if output_path.exists() {
        let metadata = fs::symlink_metadata(output_path).map_err(|err| {
            format!(
                "inspect phase1 measured output path failed ({}): {err}",
                output_path.display()
            )
        })?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "phase1 measured output path must not be a symlink: {}",
                output_path.display()
            ));
        }
        if !metadata.file_type().is_file() {
            return Err(format!(
                "phase1 measured output path must be a file: {}",
                output_path.display()
            ));
        }
        let _ = phase1_harden_file_write_bits_if_needed(
            output_path,
            metadata,
            "phase1 measured output file",
        )?;
    }

    let parent = output_path.parent().ok_or_else(|| {
        format!(
            "phase1 measured output path has no parent: {}",
            output_path.display()
        )
    })?;
    fs::create_dir_all(parent).map_err(|err| {
        format!(
            "create phase1 measured output directory failed ({}): {err}",
            parent.display()
        )
    })?;
    phase1_validate_secure_directory(parent, "phase1 measured output directory")?;

    let temp_output = create_secure_temp_file(parent, "phase1-measured-input.")?;
    let payload = json!({
        "phase": "phase1",
        "suite": "measured_input_collector",
        "evidence_mode": "measured",
        "captured_at_unix": unix_now(),
        "sample_count": measured_input.sample_count,
        "source_path": measured_input.source_path.display().to_string(),
        "metrics": {
            "idle_cpu_percent": measured_input.idle_cpu_percent,
            "idle_memory_mb": measured_input.idle_memory_mb,
            "reconnect_seconds": measured_input.reconnect_seconds,
            "route_policy_apply_p95_seconds": measured_input.route_policy_apply_p95_seconds,
            "throughput_overhead_percent": measured_input.throughput_overhead_percent,
            "backend_throughput_overhead_percent": measured_input.backend_throughput_overhead_percent,
        },
    });
    let mut body = serde_json::to_string_pretty(&payload)
        .map_err(|err| format!("serialize phase1 measured output failed: {err}"))?;
    body.push('\n');

    {
        let mut file = OpenOptions::new()
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(&temp_output)
            .map_err(|err| {
                format!(
                    "open phase1 temp output failed ({}): {err}",
                    temp_output.display()
                )
            })?;
        file.write_all(body.as_bytes()).map_err(|err| {
            format!(
                "write phase1 measured output failed ({}): {err}",
                temp_output.display()
            )
        })?;
        file.sync_all().map_err(|err| {
            format!(
                "sync phase1 measured output failed ({}): {err}",
                temp_output.display()
            )
        })?;
    }

    fs::set_permissions(&temp_output, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "set phase1 measured output mode failed ({}): {err}",
            temp_output.display()
        )
    })?;
    fs::rename(&temp_output, output_path).map_err(|err| {
        format!(
            "publish phase1 measured output failed ({}): {err}",
            output_path.display()
        )
    })?;
    fs::set_permissions(output_path, fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "set phase1 measured output mode failed ({}): {err}",
            output_path.display()
        )
    })?;

    Ok(())
}

fn collect_phase1_measured_input_artifact() -> Result<(Phase1MeasuredInput, PathBuf), String> {
    let source_path = resolve_phase1_measured_source_path()?;
    let measured_input = phase1_collect_measured_input_from_source(source_path.as_path())?;
    let output_path = phase1_path_from_env_or_default(
        "RUSTYNET_PHASE1_MEASURED_INPUT_OUT",
        DEFAULT_PHASE1_MEASURED_INPUT_PATH,
    )?;
    phase1_write_measured_input_artifact(output_path.as_path(), &measured_input)?;
    Ok((measured_input, output_path))
}

pub fn execute_ops_collect_phase1_measured_input() -> Result<String, String> {
    let (measured_input, output_path) = collect_phase1_measured_input_artifact()?;
    Ok(format!(
        "phase1 measured input generated: path={} samples={} source={}",
        output_path.display(),
        measured_input.sample_count,
        measured_input.source_path.display()
    ))
}

fn phase1_parse_metric_env(
    key: &str,
    missing_env: &mut Vec<String>,
) -> Result<Option<f64>, String> {
    let Some(raw) = env_optional_string(key)? else {
        missing_env.push(key.to_owned());
        return Ok(None);
    };
    let value = raw
        .parse::<f64>()
        .map_err(|err| format!("invalid numeric value for {key}: {err}"))?;
    if !value.is_finite() || value < 0.0 {
        return Err(format!(
            "invalid numeric value for {key}: must be finite and >= 0"
        ));
    }
    Ok(Some(value))
}

fn phase1_metrics_from_env(
    missing_env: &mut Vec<String>,
) -> Result<Option<Phase1MeasuredInput>, String> {
    let idle_cpu_percent =
        phase1_parse_metric_env("RUSTYNET_PHASE1_IDLE_CPU_PERCENT", missing_env)?;
    let idle_memory_mb = phase1_parse_metric_env("RUSTYNET_PHASE1_IDLE_MEMORY_MB", missing_env)?;
    let reconnect_seconds =
        phase1_parse_metric_env("RUSTYNET_PHASE1_RECONNECT_SECONDS", missing_env)?;
    let route_policy_apply_p95_seconds = phase1_parse_metric_env(
        "RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS",
        missing_env,
    )?;
    let throughput_overhead_percent =
        phase1_parse_metric_env("RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT", missing_env)?;
    let backend_throughput_overhead_percent = phase1_parse_metric_env(
        "RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT",
        missing_env,
    )?;

    if !missing_env.is_empty() {
        return Ok(None);
    }

    let source_path = match env_optional_string("RUSTYNET_PHASE1_METRICS_SOURCE")? {
        Some(value) => {
            let resolved = phase1_resolve_path(value.as_str())?;
            phase1_validate_source_path(resolved.as_path())?;
            resolved
        }
        None => PathBuf::from("env"),
    };

    Ok(Some(Phase1MeasuredInput {
        source_path,
        sample_count: 1,
        idle_cpu_percent: idle_cpu_percent
            .ok_or_else(|| "missing RUSTYNET_PHASE1_IDLE_CPU_PERCENT".to_owned())?,
        idle_memory_mb: idle_memory_mb
            .ok_or_else(|| "missing RUSTYNET_PHASE1_IDLE_MEMORY_MB".to_owned())?,
        reconnect_seconds: reconnect_seconds
            .ok_or_else(|| "missing RUSTYNET_PHASE1_RECONNECT_SECONDS".to_owned())?,
        route_policy_apply_p95_seconds: route_policy_apply_p95_seconds
            .ok_or_else(|| "missing RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS".to_owned())?,
        throughput_overhead_percent: throughput_overhead_percent
            .ok_or_else(|| "missing RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT".to_owned())?,
        backend_throughput_overhead_percent: backend_throughput_overhead_percent.ok_or_else(
            || "missing RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT".to_owned(),
        )?,
    }))
}

fn phase1_apply_metrics_to_command(command: &mut Command, metrics: &Phase1MeasuredInput) {
    if metrics.source_path != Path::new("env") {
        command.env(
            "RUSTYNET_PHASE1_METRICS_SOURCE",
            metrics.source_path.as_os_str(),
        );
    }
    command
        .env(
            "RUSTYNET_PHASE1_IDLE_CPU_PERCENT",
            format!("{:.6}", metrics.idle_cpu_percent),
        )
        .env(
            "RUSTYNET_PHASE1_IDLE_MEMORY_MB",
            format!("{:.6}", metrics.idle_memory_mb),
        )
        .env(
            "RUSTYNET_PHASE1_RECONNECT_SECONDS",
            format!("{:.6}", metrics.reconnect_seconds),
        )
        .env(
            "RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS",
            format!("{:.6}", metrics.route_policy_apply_p95_seconds),
        )
        .env(
            "RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT",
            format!("{:.6}", metrics.throughput_overhead_percent),
        )
        .env(
            "RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT",
            format!("{:.6}", metrics.backend_throughput_overhead_percent),
        );
}

fn phase1_run_runtime_baseline(
    runtime_report: &Path,
    metrics: &Phase1MeasuredInput,
) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command
        .arg("run")
        .arg("--locked")
        .arg("-p")
        .arg("rustynetd")
        .arg("--")
        .arg("--emit-phase1-baseline")
        .arg(runtime_report.as_os_str());
    phase1_apply_metrics_to_command(&mut command, metrics);

    let status = command
        .status()
        .map_err(|err| format!("invoke phase1 runtime baseline command failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "phase1 runtime baseline command failed with status {status}"
        ));
    }
    Ok(())
}

fn phase1_run_backend_contract_perf(
    backend_report: &Path,
    metrics: &Phase1MeasuredInput,
) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command
        .arg("test")
        .arg("--locked")
        .arg("-p")
        .arg("rustynet-backend-api")
        .arg("--test")
        .arg("backend_contract_perf")
        .env(
            "RUSTYNET_PHASE1_BACKEND_PERF_REPORT",
            backend_report.as_os_str(),
        );
    phase1_apply_metrics_to_command(&mut command, metrics);

    let status = command
        .status()
        .map_err(|err| format!("invoke phase1 backend perf test failed: {err}"))?;
    if !status.success() {
        return Err(format!(
            "phase1 backend perf test command failed with status {status}"
        ));
    }
    Ok(())
}

fn phase1_validate_report(
    report_path: &Path,
    report_label: &str,
    required_metric_names: &[&str],
) -> Result<(), String> {
    let payload = read_json_value(report_path, report_label)?;
    if !payload.is_object() {
        return Err(format!(
            "{report_label} must be a JSON object: {}",
            report_path.display()
        ));
    }
    // X2: deserialise the report payload once into the typed view.
    // A present-but-wrong-type `metrics` field (e.g. `metrics: {}`)
    // fails here with a precise serde error; a wrong-type slot
    // inside a metric entry (e.g. `status: 42`) likewise fails here
    // instead of slipping past the legacy
    // `.and_then(Value::as_str)` walk. The legacy "missing metrics
    // array" / "missing name" / "missing status" / "missing numeric
    // value" messages are preserved at the validator boundary so the
    // existing failing-report tests do not regress.
    let typed: Phase1ValidateReportView = serde_json::from_value(payload).map_err(|err| {
        format!(
            "{report_label} has invalid field shape: {} ({err})",
            report_path.display()
        )
    })?;
    let metrics = typed.metrics.as_ref().ok_or_else(|| {
        format!(
            "{report_label} missing metrics array: {}",
            report_path.display()
        )
    })?;
    if metrics.is_empty() {
        return Err(format!(
            "{report_label} metrics array is empty: {}",
            report_path.display()
        ));
    }

    let mut present_metrics = HashMap::new();
    for metric in metrics {
        let name = metric.name.as_deref().ok_or_else(|| {
            format!(
                "{report_label} metric entry missing name: {}",
                report_path.display()
            )
        })?;
        let metric_value = metric
            .value
            .as_ref()
            .and_then(phase1_value_as_number)
            .ok_or_else(|| {
                format!(
                    "{report_label} metric '{name}' missing numeric value: {}",
                    report_path.display()
                )
            })?;
        if !metric_value.is_finite() || metric_value < 0.0 {
            return Err(format!(
                "{report_label} metric '{name}' has invalid value {metric_value}: {}",
                report_path.display()
            ));
        }
        let status = metric.status.as_deref().ok_or_else(|| {
            format!(
                "{report_label} metric '{name}' missing status: {}",
                report_path.display()
            )
        })?;
        if status == "fail" {
            return Err(format!(
                "{report_label} contains failing metric '{name}': {}",
                report_path.display()
            ));
        }
        if status == "not_measurable" {
            return Err(format!(
                "{report_label} contains non-measured metric '{name}': {}",
                report_path.display()
            ));
        }
        if metric.reason.as_deref().is_some_and(|reason| {
            reason == "measurement_unavailable" || reason == "measurement_invalid"
        }) {
            return Err(format!(
                "{report_label} contains unavailable/invalid measurement for metric '{name}': {}",
                report_path.display()
            ));
        }
        present_metrics.insert(name.to_owned(), true);
    }

    for required_metric_name in required_metric_names {
        if !present_metrics.contains_key(*required_metric_name) {
            return Err(format!(
                "{report_label} missing required metric '{}': {}",
                required_metric_name,
                report_path.display()
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UnsafeScannerState {
    Normal,
    LineComment,
    BlockComment,
    String,
    Char,
    RawString,
}

fn unsafe_scanner_is_ident_start(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphabetic()
}

fn unsafe_scanner_is_ident_continue(byte: u8) -> bool {
    unsafe_scanner_is_ident_start(byte) || byte.is_ascii_digit()
}

fn unsafe_scanner_advance(
    bytes: &[u8],
    index: usize,
    line: &mut usize,
    column: &mut usize,
) -> usize {
    if bytes.get(index).copied() == Some(b'\n') {
        *line += 1;
        *column = 1;
    } else {
        *column += 1;
    }
    index + 1
}

fn scan_rust_source_text_for_unsafe(source: &str) -> Vec<(usize, usize)> {
    let bytes = source.as_bytes();
    let mut findings = Vec::new();

    let mut index = 0usize;
    let mut line = 1usize;
    let mut column = 1usize;
    let mut state = UnsafeScannerState::Normal;
    let mut block_depth = 0usize;
    let mut raw_hashes = 0usize;

    while let Some(&byte) = bytes.get(index) {
        match state {
            UnsafeScannerState::Normal => {
                if byte == b'/' && bytes.get(index + 1) == Some(&b'/') {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::LineComment;
                    continue;
                }

                if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::BlockComment;
                    block_depth = 1;
                    continue;
                }

                if byte == b'"' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::String;
                    continue;
                }

                if byte == b'\'' {
                    if bytes
                        .get(index + 1)
                        .is_some_and(|&next| unsafe_scanner_is_ident_start(next))
                    {
                        let is_char_literal = bytes.get(index + 2) == Some(&b'\'');
                        if !is_char_literal {
                            index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                            while bytes
                                .get(index)
                                .is_some_and(|&next| unsafe_scanner_is_ident_continue(next))
                            {
                                index =
                                    unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                            }
                            continue;
                        }
                    }
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::Char;
                    continue;
                }

                if byte == b'r' {
                    let mut candidate = index + 1;
                    let mut hashes = 0usize;
                    while bytes.get(candidate) == Some(&b'#') {
                        candidate += 1;
                        hashes += 1;
                    }
                    if bytes.get(candidate) == Some(&b'"') {
                        while index <= candidate {
                            index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        }
                        state = UnsafeScannerState::RawString;
                        raw_hashes = hashes;
                        continue;
                    }
                }

                if unsafe_scanner_is_ident_start(byte) {
                    let token_line = line;
                    let token_column = column;
                    let token_start = index;
                    while bytes
                        .get(index)
                        .is_some_and(|&next| unsafe_scanner_is_ident_continue(next))
                    {
                        index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    }
                    if bytes
                        .get(token_start..index)
                        .is_some_and(|token| token == b"unsafe")
                    {
                        findings.push((token_line, token_column));
                    }
                    continue;
                }

                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
            UnsafeScannerState::LineComment => {
                if byte == b'\n' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::Normal;
                    continue;
                }
                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
            UnsafeScannerState::BlockComment => {
                if byte == b'/' && bytes.get(index + 1) == Some(&b'*') {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    block_depth += 1;
                    continue;
                }
                if byte == b'*' && bytes.get(index + 1) == Some(&b'/') {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    block_depth = block_depth.saturating_sub(1);
                    if block_depth == 0 {
                        state = UnsafeScannerState::Normal;
                    }
                    continue;
                }
                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
            UnsafeScannerState::String => {
                if byte == b'\\' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    if index < bytes.len() {
                        index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    }
                    continue;
                }
                if byte == b'"' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::Normal;
                    continue;
                }
                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
            UnsafeScannerState::Char => {
                if byte == b'\\' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    if index < bytes.len() {
                        index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    }
                    continue;
                }
                if byte == b'\'' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::Normal;
                    continue;
                }
                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
            UnsafeScannerState::RawString => {
                if byte == b'"' {
                    let suffix_start = index + 1;
                    let suffix_end = suffix_start + raw_hashes;
                    if suffix_end <= bytes.len()
                        && bytes
                            .get(suffix_start..suffix_end)
                            .is_some_and(|suffix| suffix.iter().all(|candidate| *candidate == b'#'))
                    {
                        index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        for _ in 0..raw_hashes {
                            index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        }
                        state = UnsafeScannerState::Normal;
                        continue;
                    }
                }
                index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
            }
        }
    }

    findings
}

fn run_unsafe_scanner_self_tests() -> Result<(), String> {
    let cases = [
        (
            "lifetime_only",
            "fn keep<'a>(value: &'a str) -> &'a str { value }\n",
            0usize,
        ),
        (
            "lifetime_plus_unsafe_block",
            "fn keep<'a>(value: &'a str) -> &'a str { value }\nfn bad() { unsafe { let _x = 1; } }\n",
            1usize,
        ),
        (
            "comments_and_strings",
            "// unsafe should not match here\nconst NOTE: &str = \"unsafe in string\";\n",
            0usize,
        ),
    ];

    for (name, source, expected_count) in cases {
        let findings = scan_rust_source_text_for_unsafe(source);
        if findings.len() != expected_count {
            return Err(format!(
                "unsafe scanner self-test failed for {name}: expected {expected_count} findings, got {}",
                findings.len()
            ));
        }
    }

    Ok(())
}

fn collect_rust_source_paths(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.exists() {
        return Err(format!("source root does not exist: {}", root.display()));
    }
    if !root.is_dir() {
        return Err(format!(
            "source root is not a directory: {}",
            root.display()
        ));
    }

    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(dir) = pending.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|err| format!("read directory failed ({}): {err}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read directory entry failed ({}): {err}", dir.display()))?;
        entries.sort_by_key(std::fs::DirEntry::path);

        for entry in entries {
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("inspect path type failed ({}): {err}", path.display()))?;

            if file_type.is_symlink() {
                return Err(format!(
                    "unsafe source scan refuses symlink path; remove symlink or scan concrete paths only: {}",
                    path.display()
                ));
            }

            if file_type.is_dir() {
                if path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value == "target")
                {
                    continue;
                }
                pending.push(path);
                continue;
            }

            if file_type.is_file() && path.extension().is_some_and(|value| value == "rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    Ok(files)
}

/// Unsafe-code scopes permitted under OI-20 (decision log "Owner
/// decisions — round 2"; T2 security-bar §B1): the workspace pins
/// `unsafe_code = "deny"`, `forbid` applies only where a crate holds
/// zero unsafe, every unsafe site carries an adjacent `// SAFETY:`
/// comment, and `unsafe` is legal ONLY inside the explicitly scoped
/// `#[allow(unsafe_code)]` regions inventoried here. Anything else
/// fails this gate — the check stays fail-closed.
///
/// Each entry is (path prefix relative to `--root`, rationale). The
/// textual scan is file-granular; the compile-level pins are the
/// exact-scope backstop: each member crate carries its own
/// `[lints.rust]` pin (forbid where the crate holds zero unsafe, deny
/// where it holds the audited FFI unsafe), so `unsafe` planted outside
/// the source-level `#[allow(unsafe_code)]` region fails `cargo
/// check`/`clippy` even when this textual gate sees the file.
///
/// To extend this list:
/// 1. The unsafe must live inside one narrowly scoped
///    `#[allow(unsafe_code)]` region (one module, one FFI concern).
/// 2. Every unsafe site must carry an adjacent `// SAFETY:` comment
///    stating the invariant that makes it sound.
/// 3. The crate must pin `unsafe_code = "deny"` in its own
///    `[lints.rust]` so the allow cannot spread silently.
/// 4. Document the rationale here, in the same commit.
const UNSAFE_SCAN_ALLOWED_SCOPES: &[(&str, &str)] = &[
    // macOS utun FFI isolation module: SCM_RIGHTS fd passing for the
    // privileged-helper path (AQ-72). Scoped `#[allow(unsafe_code)]` on
    // the `mod macos_utun_helper_unsafe` declaration
    // (`cfg(target_os = "macos")`) in crates/rustynetd/src/lib.rs; the
    // crate pins deny via its own `[lints.rust]`. Every site carries
    // `// SAFETY:`.
    (
        "rustynetd/src/macos_utun_helper_unsafe.rs",
        "macOS utun FFI isolation module (SCM_RIGHTS fd passing); scoped #[allow(unsafe_code)] on the module decl in crates/rustynetd/src/lib.rs (cfg target_os = macos); AQ-72",
    ),
    // cfg(windows) `mod imp`, inline at the tail of src/lib.rs: the
    // Win32 FFI half of the crate (DPAPI, WFP, IpHelper, RPC,
    // registry). Scoped `#[allow(unsafe_code)]` on `mod imp`; the crate
    // pins deny via its own `[lints.rust]`. Every site carries
    // `// SAFETY:`. The textual scope is the whole file (the module is
    // an inline tail); the crate-level deny is the exact backstop for
    // unsafe planted outside `mod imp`.
    (
        "rustynet-windows-native/src/lib.rs",
        "cfg(windows) `mod imp` Win32 FFI (DPAPI, WFP, IpHelper, RPC, registry); scoped #[allow(unsafe_code)] on `mod imp` in this file; crate [lints.rust] pins deny outside the module",
    ),
];

fn unsafe_scan_path_is_allowlisted(repo_relative: &str) -> bool {
    UNSAFE_SCAN_ALLOWED_SCOPES
        .iter()
        .any(|(prefix, _)| repo_relative.starts_with(prefix))
}

/// OI-20 §B1: every unsafe site needs an adjacent `// SAFETY:` comment —
/// on the same line as the unsafe token, or inside the contiguous `//`
/// comment block ending on the line directly above it (multi-line
/// SAFETY justifications are the tree's real style; all 123 audited
/// sites satisfy this). Any non-comment line — blank line or code —
/// between the block and the site breaks adjacency (fail closed).
/// Adjacency is judged on the line text with string and char literal
/// contents stripped (AQ-248/D1): a `// SAFETY:` inside a literal is
/// data, not a comment, and never counts.
/// True when `line` at `r` opens a raw string literal (`r"`, `r#"`,
/// `r##"`...). The `r` must start a token: not preceded by an
/// identifier character, except the byte/C-string prefixes `br` and
/// `cr` whose own preceding character must also be a token boundary.
fn is_raw_string_open(chars: &[char], r: usize) -> bool {
    if r > 0
        && let Some(&prev) = chars.get(r - 1)
    {
        let in_identifier = prev.is_ascii_alphanumeric() || prev == '_';
        let prefix = (prev == 'b' || prev == 'c')
            && (r < 2
                || !chars
                    .get(r - 2)
                    .is_some_and(|&earlier| earlier.is_ascii_alphanumeric() || earlier == '_'));
        if in_identifier && !prefix {
            return false;
        }
    }
    match chars.get(r + 1) {
        Some('"') => true,
        Some('#') => {
            let mut probe = r + 1;
            while chars.get(probe) == Some(&'#') {
                probe += 1;
            }
            probe > r + 1 && chars.get(probe) == Some(&'"')
        }
        _ => false,
    }
}

/// True when the `'` at `quote` opens a char literal: either the escape
/// form `'\n'`, `'\u{...}'` (a closing quote exists before end of
/// line, backslash pairs skipped) or the plain one-char form `'x'`.
/// Lifetime apostrophes (`'a`, `'static`) have no same-line closing
/// quote after one character and are not char literals.
fn is_char_literal_open(chars: &[char], quote: usize) -> bool {
    match chars.get(quote + 1) {
        Some('\\') => {
            let mut probe = quote + 2;
            while probe < chars.len() {
                match chars.get(probe) {
                    Some('\\') => {
                        probe += 2;
                        continue;
                    }
                    Some('\'') => return true,
                    Some(_) => probe += 1,
                    None => return false,
                }
            }
            false
        }
        Some(_) => chars.get(quote + 2) == Some(&'\''),
        None => false,
    }
}

/// Blank out the contents of string and char literals so a `// SAFETY:`
/// forged inside a literal cannot satisfy the adjacency check
/// (AQ-248/D1): literal contents are data, not comments. Literal state
/// carries across lines — normal `"..."` strings and `'...'` char
/// literals honor `\` escapes, raw strings `r".."` / `r#".."#` (any
/// hash count, including the `br`/`cr` prefixed forms) honor none and
/// may span lines. Quotes delimiting a literal are kept and `//` line
/// comments are copied verbatim from the `//` on, so comment prose can
/// neither open nor close literal state. Block comments are not
/// tracked: `/* // SAFETY: */` is a real comment, so leaving it intact
/// cannot forge acceptance. A line that cannot be fully scanned (one
/// ending mid-escape) degrades to more blanking, never to less.
fn strip_string_and_char_literal_contents(lines: &[&str]) -> Vec<String> {
    let mut stripped_lines = Vec::with_capacity(lines.len());
    let mut in_string = false;
    let mut in_raw_string: Option<usize> = None;
    for line in lines {
        let chars: Vec<char> = line.chars().collect();
        let mut stripped = String::with_capacity(line.len());
        let mut in_char = false;
        let mut index = 0;
        while let Some(&ch) = chars.get(index) {
            if in_string {
                match ch {
                    '"' => {
                        in_string = false;
                        stripped.push('"');
                    }
                    '\\' => {
                        stripped.push(' ');
                        if index + 1 < chars.len() {
                            stripped.push(' ');
                            index += 1;
                        }
                    }
                    _ => stripped.push(' '),
                }
                index += 1;
                continue;
            }
            if let Some(hashes) = in_raw_string {
                if ch == '"' {
                    let mut seen = 0;
                    while seen < hashes && chars.get(index + 1 + seen) == Some(&'#') {
                        seen += 1;
                    }
                    if seen == hashes {
                        in_raw_string = None;
                        stripped.push('"');
                        for _ in 0..hashes {
                            stripped.push('#');
                        }
                        index += 1 + hashes;
                    } else {
                        stripped.push(' ');
                        index += 1;
                    }
                } else {
                    stripped.push(' ');
                    index += 1;
                }
                continue;
            }
            if in_char {
                match ch {
                    '\'' => {
                        in_char = false;
                        stripped.push('\'');
                    }
                    '\\' => {
                        stripped.push(' ');
                        if index + 1 < chars.len() {
                            stripped.push(' ');
                            index += 1;
                        }
                    }
                    _ => stripped.push(' '),
                }
                index += 1;
                continue;
            }
            if ch == '/' && chars.get(index + 1) == Some(&'/') {
                stripped.extend(chars.get(index..).into_iter().flatten().copied());
                break;
            }
            match ch {
                '"' => {
                    in_string = true;
                    stripped.push('"');
                }
                '\'' if is_char_literal_open(&chars, index) => {
                    in_char = true;
                    stripped.push('\'');
                }
                'r' if is_raw_string_open(&chars, index) => {
                    let mut hashes = 0;
                    let mut probe = index + 1;
                    while chars.get(probe) == Some(&'#') {
                        hashes += 1;
                        probe += 1;
                    }
                    in_raw_string = Some(hashes);
                    stripped.push('r');
                    for _ in 0..hashes {
                        stripped.push('#');
                    }
                    stripped.push('"');
                    index = probe + 1;
                    continue;
                }
                other => stripped.push(other),
            }
            index += 1;
        }
        stripped_lines.push(stripped);
    }
    stripped_lines
}

fn unsafe_site_has_adjacent_safety_comment(lines: &[&str], site_index: usize) -> bool {
    let stripped = strip_string_and_char_literal_contents(lines);
    let Some(site_line) = stripped.get(site_index) else {
        return false;
    };
    if site_line.contains("// SAFETY:") {
        return true;
    }
    let mut index = site_index;
    while index > 0 {
        index -= 1;
        let Some(stripped_line) = stripped.get(index) else {
            return false;
        };
        match stripped_line.trim_start().strip_prefix("//") {
            Some(comment) => {
                if comment.contains("SAFETY:") {
                    return true;
                }
            }
            None => return false,
        }
    }
    false
}

/// Extract the body of one top-level TOML table (`header` without
/// brackets) as the lines from its header to the next `[` header at
/// line start (or end of file). Deliberately textual: the pin this
/// guards is one static line, not a general TOML parser.
fn toml_table_section<'a>(manifest: &'a str, header: &str) -> Option<&'a str> {
    let header_line = format!("[{header}]");
    let mut start: Option<usize> = None;
    let mut end = manifest.len();
    let mut offset = 0usize;
    for line in manifest.lines() {
        let trimmed = line.trim_start();
        if start.is_none() {
            if trimmed == header_line {
                start = Some(offset);
            }
        } else if trimmed.starts_with('[') {
            end = offset;
            break;
        }
        offset += line.len() + 1;
    }
    let start = start?;
    manifest.get(start..end)
}

/// OI-20 §B1 structural half: the workspace manifest must pin the exact
/// line `unsafe_code = "forbid"` under `[workspace.lints.rust]`. OI-20
/// reads "deny + mandatory SAFETY comment as the bar; forbid only where
/// a project has zero unsafe" — at rustynet this is satisfied by the
/// STRICTER root: `forbid` at the workspace root, and every member that
/// actually holds an unsafe site must declare its own `[lints.rust]
/// unsafe_code = "deny"` (checked by [`verify_member_unsafe_lints`]),
/// because inherited workspace lints cannot be overridden per crate and
/// forbid admits no `#[allow(unsafe_code)]`. The only members holding
/// unsafe (rustynetd, rustynet-windows-native) carry exactly that own
/// deny table and do not inherit the workspace lints, so the root
/// `forbid` means "forbid wherever a crate holds zero unsafe". Fails
/// closed on a missing manifest — a scan root outside a rustynet
/// workspace is a configuration error, not a pass.
fn verify_workspace_unsafe_pin(workspace_manifest: &Path) -> Result<(), String> {
    let manifest = fs::read_to_string(workspace_manifest).map_err(|err| {
        format!(
            "OI-20 unsafe policy: cannot read workspace manifest {}: {err}",
            workspace_manifest.display()
        )
    })?;
    let section = toml_table_section(&manifest, "workspace.lints.rust").ok_or_else(|| {
        format!(
            "OI-20 unsafe policy: workspace manifest {} has no [workspace.lints.rust] table (T2 security-bar B1 requires unsafe_code = \"forbid\")",
            workspace_manifest.display()
        )
    })?;
    let pinned = section
        .lines()
        .any(|line| line.trim() == "unsafe_code = \"forbid\"");
    if !pinned {
        return Err(format!(
            "OI-20 unsafe policy: [workspace.lints.rust] in {} must pin the exact line unsafe_code = \"forbid\" (OI-20: deny is carried per crate — every member holding an unsafe site must declare its own [lints.rust] unsafe_code = \"deny\", so the root stays forbid wherever a crate holds zero unsafe)",
            workspace_manifest.display()
        ));
    }
    Ok(())
}

/// Extract the quoted entries of the `members = [ ... ]` array inside
/// the `[workspace]` table. Deliberately textual and fail-closed: a
/// glob entry (or a members array outside `[workspace]`) is a
/// configuration error, not an empty member list.
fn workspace_member_paths(workspace_manifest_text: &str) -> Result<Vec<String>, String> {
    let section = toml_table_section(workspace_manifest_text, "workspace")
        .ok_or_else(|| "OI-20 unsafe policy: manifest has no [workspace] table".to_string())?;
    let mut members: Vec<String> = Vec::new();
    let mut in_array = false;
    let mut array_closed = false;
    for line in section.lines() {
        let trimmed = line.trim();
        if !in_array {
            let Some(rest) = trimmed.strip_prefix("members") else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('=') else {
                continue;
            };
            let Some(rest) = rest.trim_start().strip_prefix('[') else {
                return Err("OI-20 unsafe policy: [workspace] members must be an array".to_string());
            };
            in_array = true;
            array_closed = push_member_entries(rest, &mut members)?;
            if array_closed {
                return Ok(members);
            }
            continue;
        }
        array_closed = push_member_entries(trimmed, &mut members)?;
        if array_closed {
            return Ok(members);
        }
    }
    if in_array && array_closed {
        Ok(members)
    } else if in_array {
        Err(
            "OI-20 unsafe policy: [workspace] members array is unterminated (fail closed)"
                .to_string(),
        )
    } else {
        Err("OI-20 unsafe policy: manifest has no [workspace] members array".to_string())
    }
}

/// Consume comma-separated member entries from one line of the members
/// array. Returns `true` when the line closed the array with `]`. A
/// glob entry fails closed with a named error.
fn push_member_entries(line: &str, members: &mut Vec<String>) -> Result<bool, String> {
    for segment in line.split(',') {
        let segment = segment.trim();
        let (entry_text, closed) = match segment.split_once(']') {
            Some((before, _)) => (before.trim(), true),
            None => (segment, false),
        };
        let entry = entry_text.trim_matches(|c| c == '"' || c == '\'');
        if !entry.is_empty() {
            if entry.contains('*') || entry.contains('?') {
                return Err(format!(
                    "OI-20 unsafe policy: workspace member glob {entry:?} cannot be resolved fail-closed; list members explicitly"
                ));
            }
            members.push(entry.to_string());
        }
        if closed {
            return Ok(true);
        }
    }
    Ok(false)
}

/// OI-20 §B1 per-crate half: every workspace member whose sources hold
/// an `unsafe` site must declare its OWN `[lints.rust]` table with the
/// exact line `unsafe_code = "deny"` (never `[lints] workspace = true`
/// inheritance: inherited workspace lints cannot be overridden per
/// crate, so an inheriting member under the root `forbid` pin cannot
/// host a scoped `#[allow(unsafe_code)]` at all). Fail-closed with a
/// named error naming the member.
fn verify_member_unsafe_lints(workspace_root: &Path) -> Result<(), String> {
    let workspace_manifest = workspace_root.join("Cargo.toml");
    let manifest_text = fs::read_to_string(&workspace_manifest).map_err(|err| {
        format!(
            "OI-20 unsafe policy: cannot read workspace manifest {}: {err}",
            workspace_manifest.display()
        )
    })?;
    for member in workspace_member_paths(&manifest_text)? {
        let member_dir = workspace_root.join(&member);
        let sources = collect_rust_source_paths(member_dir.as_path())?;
        let holds_unsafe = sources.iter().any(|source_path| {
            fs::read_to_string(source_path)
                .map(|source| !scan_rust_source_text_for_unsafe(source.as_str()).is_empty())
                .unwrap_or(false)
        });
        if !holds_unsafe {
            continue;
        }
        let member_manifest = member_dir.join("Cargo.toml");
        let member_text = fs::read_to_string(&member_manifest).map_err(|err| {
            format!(
                "OI-20 unsafe policy: member {member} holds unsafe sites but its manifest {} cannot be read: {err}",
                member_manifest.display()
            )
        })?;
        let owns_deny = toml_table_section(&member_text, "lints.rust")
            .map(|section| {
                section
                    .lines()
                    .any(|line| line.trim() == "unsafe_code = \"deny\"")
            })
            .unwrap_or(false);
        if !owns_deny {
            return Err(format!(
                "OI-20 unsafe policy: workspace member {member} holds unsafe sites but does not declare its own [lints.rust] unsafe_code = \"deny\" (OI-20: the workspace root pins forbid, forbid admits no #[allow(unsafe_code)], and [lints] workspace = true inheritance cannot be overridden per crate — a member holding unsafe must pin deny in its own manifest)"
            ));
        }
    }
    Ok(())
}

pub fn execute_ops_check_no_unsafe_rust_sources(
    config: CheckNoUnsafeRustSourcesConfig,
) -> Result<String, String> {
    run_unsafe_scanner_self_tests()?;

    let root = phase1_resolve_path(config.root.to_string_lossy().as_ref())?;
    let workspace_manifest = root
        .parent()
        .map(|parent| parent.join("Cargo.toml"))
        .ok_or_else(|| {
            format!(
                "OI-20 unsafe policy: scan root {} has no parent workspace",
                root.display()
            )
        })?;
    verify_workspace_unsafe_pin(&workspace_manifest)?;
    let workspace_root = workspace_manifest.parent().ok_or_else(|| {
        format!(
            "OI-20 unsafe policy: workspace manifest {} has no parent directory",
            workspace_manifest.display()
        )
    })?;
    verify_member_unsafe_lints(workspace_root)?;

    let rust_sources = collect_rust_source_paths(root.as_path())?;
    let mut findings = Vec::new();

    for source_path in rust_sources {
        let repo_relative = source_path.strip_prefix(root.as_path()).map_or_else(
            |_| source_path.to_string_lossy().to_string(),
            |relative| relative.to_string_lossy().replace('\\', "/"),
        );
        let allowlisted = unsafe_scan_path_is_allowlisted(repo_relative.as_str());
        let source = fs::read_to_string(&source_path)
            .map_err(|err| format!("read Rust source failed ({}): {err}", source_path.display()))?;
        let lines: Vec<&str> = source.lines().collect();
        for (line, column) in scan_rust_source_text_for_unsafe(source.as_str()) {
            // The SAFETY half of OI-20 applies to every site, including
            // the permitted scopes — check it first so an allowlisted
            // site without a justification still fails the gate.
            if !unsafe_site_has_adjacent_safety_comment(&lines, line.saturating_sub(1)) {
                findings.push(format!(
                    "{}:{line}:{column}: unsafe site has no adjacent // SAFETY: comment (OI-20/T2 security-bar B1)",
                    source_path.display()
                ));
                continue;
            }
            if !allowlisted {
                findings.push(format!(
                    "{}:{line}:{column}: unsafe outside a permitted OI-20 scope (see UNSAFE_SCAN_ALLOWED_SCOPES: scoped #[allow(unsafe_code)] + // SAFETY: required)",
                    source_path.display()
                ));
            }
        }
    }

    if !findings.is_empty() {
        return Err(format!(
            "unsafe policy violation (OI-20/T2 security-bar B1): unsafe is permitted only inside explicitly scoped #[allow(unsafe_code)] regions (rustynetd macos_utun_helper_unsafe module, rustynet-windows-native cfg(windows) mod imp) and every site needs an adjacent // SAFETY: comment:\n{}",
            findings.join("\n")
        ));
    }

    Ok("Unsafe code checks: PASS".to_owned())
}

fn parse_two_digits(value: &str, field: &str) -> Result<u32, String> {
    if value.len() != 2 || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid numeric field for {field}: {value}"));
    }
    value
        .parse::<u32>()
        .map_err(|err| format!("invalid numeric field for {field}: {err}"))
}

fn parse_four_digits(value: &str, field: &str) -> Result<i32, String> {
    if value.len() != 4 || !value.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(format!("invalid numeric field for {field}: {value}"));
    }
    value
        .parse::<i32>()
        .map_err(|err| format!("invalid numeric field for {field}: {err}"))
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

fn days_in_month(year: i32, month: u32) -> Option<u32> {
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => return None,
    };
    Some(days)
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn parse_utc_to_unix(value: &str, field: &str) -> Result<i64, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(format!("missing or invalid UTC field: {field}"));
    }

    let (datetime_part, offset_seconds) = if let Some(stripped) = trimmed.strip_suffix('Z') {
        (stripped, 0i64)
    } else {
        let tz_start = trimmed
            .char_indices()
            .rev()
            .find_map(|(index, ch)| (index > 10 && (ch == '+' || ch == '-')).then_some(index))
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        let (base, zone) = trimmed.split_at(tz_start);
        if zone.len() != 6 || !zone.is_ascii() {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let [zone_sign, _, _, zone_colon, _, _] = zone.as_bytes() else {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        };
        if *zone_colon != b':' {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let sign = if *zone_sign == b'+' { 1i64 } else { -1i64 };
        let offset_hour = parse_two_digits(zone.get(1..3).unwrap_or(""), field)?;
        let offset_minute = parse_two_digits(zone.get(4..6).unwrap_or(""), field)?;
        if offset_hour > 23 || offset_minute > 59 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let total = i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60;
        (base, sign * total)
    };

    let (date_part, time_part) = datetime_part
        .split_once('T')
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    let date_fields = date_part.split('-').collect::<Vec<_>>();
    let [year_field, month_field, day_field] = date_fields.as_slice() else {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    };
    let year = parse_four_digits(year_field, field)?;
    let month = parse_two_digits(month_field, field)?;
    let day = parse_two_digits(day_field, field)?;
    let max_day = days_in_month(year, month)
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    if day == 0 || day > max_day {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }

    let (time_core, fraction) = match time_part.split_once('.') {
        Some((core, frac)) => (core, Some(frac)),
        None => (time_part, None),
    };
    if let Some(frac) = fraction
        && (frac.is_empty() || !frac.chars().all(|ch| ch.is_ascii_digit()))
    {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }
    let time_fields = time_core.split(':').collect::<Vec<_>>();
    let [hour_field, minute_field, second_field] = time_fields.as_slice() else {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    };
    let hour = parse_two_digits(hour_field, field)?;
    let minute = parse_two_digits(minute_field, field)?;
    let second = parse_two_digits(second_field, field)?;
    if hour > 23 || minute > 59 || second > 59 {
        return Err(format!("invalid UTC timestamp for {field}: {value}"));
    }

    let date_seconds = days_from_civil(year, month, day)
        .checked_mul(86_400)
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
    let time_seconds = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
    date_seconds
        .checked_add(time_seconds)
        .and_then(|result| result.checked_sub(offset_seconds))
        .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))
}

fn require_non_empty_string_field<'a>(
    payload: &'a Map<String, Value>,
    key: &str,
    label: &str,
) -> Result<&'a str, String> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{label} missing non-empty string field: {key}"))
}

pub fn execute_ops_check_dependency_exceptions(
    config: CheckDependencyExceptionsConfig,
) -> Result<String, String> {
    let path = phase1_resolve_path(config.path.to_string_lossy().as_ref())?;
    if !path.exists() {
        return Err(format!(
            "missing dependency exception file: {}",
            path.display()
        ));
    }
    let payload = read_json_value(path.as_path(), "dependency exception file")?;
    let payload_object = payload.as_object().ok_or_else(|| {
        format!(
            "dependency exception file must be a JSON object: {}",
            path.display()
        )
    })?;
    let exceptions = payload_object
        .get("exceptions")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let required_fields = BTreeSet::from([
        "id",
        "crate",
        "reason",
        "owner",
        "approved_by",
        "expires_utc",
    ]);
    let now_unix = unix_now() as i64;

    for entry in exceptions {
        let exception = entry
            .as_object()
            .ok_or_else(|| "dependency exception entry must be a JSON object".to_owned())?;
        let present = exception
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        let missing = required_fields
            .difference(&present)
            .copied()
            .collect::<Vec<_>>();
        if !missing.is_empty() {
            return Err(format!(
                "dependency exception missing fields: [{}]",
                missing.join(", ")
            ));
        }

        let exception_id = require_non_empty_string_field(exception, "id", "dependency exception")?;
        let expires_utc =
            require_non_empty_string_field(exception, "expires_utc", "dependency exception")?;
        let expires_unix = parse_utc_to_unix(expires_utc, "dependency exception expires_utc")?;
        if expires_unix <= now_unix {
            return Err(format!("dependency exception expired: {exception_id}"));
        }
    }

    Ok("Dependency exception policy check: PASS".to_owned())
}

fn load_perf_metrics(path: &Path, label: &str) -> Result<HashMap<String, f64>, String> {
    let payload = read_json_value(path, label)?;
    if !payload.is_object() {
        return Err(format!("{label} must be a JSON object: {}", path.display()));
    }
    // X2: reuse the `Phase1ValidateReportView` + `Phase1MetricEntryView`
    // typed contract introduced in cycle 65 — both perf-metrics loaders
    // walk the same `{ metrics: [{ name, value, status, reason }] }`
    // shape, and routing them through the same view ensures the
    // contract is pinned in one place. Wrong-type slots (e.g.
    // `status: 42`) fail at deserialise here instead of slipping
    // past the legacy `.and_then(Value::as_str)` walks.
    let typed: Phase1ValidateReportView = serde_json::from_value(payload).map_err(|err| {
        format!(
            "{label} has invalid field shape: {} ({err})",
            path.display()
        )
    })?;
    let metrics = typed.metrics.as_ref().ok_or_else(|| {
        format!(
            "{label} metrics must be a non-empty array: {}",
            path.display()
        )
    })?;
    if metrics.is_empty() {
        return Err(format!(
            "{label} metrics must be a non-empty array: {}",
            path.display()
        ));
    }

    let mut values = HashMap::new();
    for metric in metrics {
        let metric_name = metric
            .name
            .as_deref()
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("{label} metric missing non-empty name: {}", path.display()))?;
        let metric_value = metric
            .value
            .as_ref()
            .and_then(phase1_value_as_number)
            .ok_or_else(|| {
                format!(
                    "{label} metric '{metric_name}' missing numeric value: {}",
                    path.display()
                )
            })?;
        if !metric_value.is_finite() || metric_value < 0.0 {
            return Err(format!(
                "{label} metric '{metric_name}' has invalid numeric value: {}",
                metric.value.clone().unwrap_or(Value::Null)
            ));
        }
        if metric
            .status
            .as_deref()
            .is_some_and(|status| status == "fail" || status == "not_measurable")
        {
            let status = metric.status.as_deref().unwrap_or("unknown");
            return Err(format!(
                "{label} metric '{metric_name}' has failing status: {status}"
            ));
        }
        values.insert(metric_name.to_owned(), metric_value);
    }

    Ok(values)
}

fn require_perf_metric(
    metrics: &HashMap<String, f64>,
    name: &str,
    label: &str,
) -> Result<f64, String> {
    metrics
        .get(name)
        .copied()
        .ok_or_else(|| format!("{label} missing required metric: {name}"))
}

pub fn execute_ops_check_perf_regression(
    config: CheckPerfRegressionConfig,
) -> Result<String, String> {
    let phase1_report_path =
        phase1_resolve_path(config.phase1_report_path.to_string_lossy().as_ref())?;
    let phase3_report_path =
        phase1_resolve_path(config.phase3_report_path.to_string_lossy().as_ref())?;

    if !phase1_report_path.is_file() {
        return Err(format!(
            "missing phase1 report: {}",
            phase1_report_path.display()
        ));
    }
    if !phase3_report_path.is_file() {
        return Err(format!(
            "missing phase3 report: {}",
            phase3_report_path.display()
        ));
    }

    let phase1_metrics = load_perf_metrics(phase1_report_path.as_path(), "phase1 report")?;
    let phase3_metrics = load_perf_metrics(phase3_report_path.as_path(), "phase3 report")?;
    let idle_cpu = require_perf_metric(&phase1_metrics, "idle_cpu_percent", "phase1 report")?;
    let idle_memory = require_perf_metric(&phase1_metrics, "idle_memory_mb", "phase1 report")?;
    let route_apply = require_perf_metric(
        &phase1_metrics,
        "route_policy_apply_p95_seconds",
        "phase1 report",
    )?;
    let peer_sessions = require_perf_metric(&phase3_metrics, "peer_sessions", "phase3 report")?;

    if idle_cpu > 2.0 {
        return Err(format!("idle cpu regression detected: {idle_cpu}"));
    }
    if idle_memory > 120.0 {
        return Err(format!("idle memory regression detected: {idle_memory}"));
    }
    if route_apply > 2.0 {
        return Err(format!(
            "route apply latency regression detected: {route_apply}"
        ));
    }
    if peer_sessions < 6.0 {
        return Err(format!(
            "phase3 mesh benchmark too small: peer_sessions={peer_sessions}"
        ));
    }

    Ok("Performance regression gate: PASS".to_owned())
}

fn secrets_hygiene_error(summary: &str, details: &[String]) -> String {
    let mut lines = Vec::new();
    lines.push(format!("[secrets-hygiene] {summary}"));
    for detail in details.iter().take(20) {
        lines.push(format!("  - {detail}"));
    }
    if details.len() > 20 {
        lines.push(format!(
            "  - ... {} additional violation(s)",
            details.len() - 20
        ));
    }
    lines.join("\n")
}

fn parse_git_tracked_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(root)
        .arg("ls-files")
        .arg("-z")
        .output()
        .map_err(|err| format!("invoke git ls-files failed ({}): {err}", root.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed for secrets hygiene scan root {} with status {}",
            root.display(),
            output.status
        ));
    }

    let mut files = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let path_text = std::str::from_utf8(entry)
            .map_err(|_| "git ls-files emitted non-utf8 path".to_owned())?;
        let relative = PathBuf::from(path_text);
        if relative.is_absolute() {
            return Err(format!(
                "git ls-files returned absolute path, refusing scan: {}",
                relative.display()
            ));
        }
        if relative
            .components()
            .any(|component| matches!(component, Component::ParentDir))
        {
            return Err(format!(
                "git ls-files returned parent-traversal path, refusing scan: {}",
                relative.display()
            ));
        }
        files.push(relative);
    }
    files.sort();
    Ok(files)
}

fn collect_workspace_files(
    root: &Path,
    excluded_roots: &BTreeSet<&str>,
) -> Result<Vec<PathBuf>, String> {
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();

    while let Some(dir) = pending.pop() {
        let mut entries = fs::read_dir(&dir)
            .map_err(|err| format!("read directory failed ({}): {err}", dir.display()))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| format!("read directory entry failed ({}): {err}", dir.display()))?;
        entries.sort_by_key(std::fs::DirEntry::path);

        for entry in entries {
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|err| {
                format!(
                    "resolve relative workspace path failed ({}): {err}",
                    path.display()
                )
            })?;
            if relative.components().any(|component| {
                excluded_roots.contains(component.as_os_str().to_string_lossy().as_ref())
            }) {
                continue;
            }
            let file_type = entry
                .file_type()
                .map_err(|err| format!("inspect path type failed ({}): {err}", path.display()))?;
            if file_type.is_symlink() {
                continue;
            }
            if file_type.is_dir() {
                pending.push(path);
                continue;
            }
            if file_type.is_file() {
                files.push(path);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn read_text_lossy(path: &Path) -> Result<String, String> {
    let bytes =
        fs::read(path).map_err(|err| format!("read file failed ({}): {err}", path.display()))?;
    Ok(String::from_utf8_lossy(bytes.as_slice()).to_string())
}

fn is_secret_value_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '+' | '/' | '=' | '_' | '-')
}

fn is_word_char_byte(byte: u8) -> bool {
    byte == b'_' || byte.is_ascii_alphanumeric()
}

fn keyword_has_word_boundaries(text: &str, start: usize, length: usize) -> bool {
    let bytes = text.as_bytes();
    let end = start + length;
    let starts_at_boundary = start == 0
        || !bytes
            .get(start - 1)
            .is_some_and(|&byte| is_word_char_byte(byte));
    let ends_at_boundary =
        end >= bytes.len() || !bytes.get(end).is_some_and(|&byte| is_word_char_byte(byte));
    starts_at_boundary && ends_at_boundary
}

fn is_bearer_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '~' | '-')
}

fn extract_secret_assignment_excerpt(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let keywords = [
        "passphrase",
        "password",
        "api_key",
        "api-key",
        "secret",
        "token",
    ];
    for keyword in keywords {
        let mut search_start = 0usize;
        while let Some(index) = lower[search_start..].find(keyword) {
            let keyword_index = search_start + index;
            if !keyword_has_word_boundaries(lower.as_str(), keyword_index, keyword.len()) {
                search_start = keyword_index + keyword.len();
                if search_start >= lower.len() {
                    break;
                }
                continue;
            }
            let delimiter_window_end = (keyword_index + keyword.len() + 24).min(line.len());
            for delimiter in [':', '='] {
                if let Some(offset) = line[keyword_index..delimiter_window_end].find(delimiter) {
                    let delimiter_index = keyword_index + offset;
                    // Reject matches where word characters appear between the keyword and the
                    // delimiter: that means this is a natural-language sentence
                    // (e.g. "passphrase hygiene result:") not a key-value assignment
                    // (e.g. "passphrase: abc" or "\"passphrase\": \"abc\"").
                    let gap = &line[keyword_index + keyword.len()..delimiter_index];
                    if gap.chars().any(|c| c.is_ascii_alphanumeric() || c == '_') {
                        continue;
                    }
                    let mut value = line[delimiter_index + 1..].trim_start();
                    if value.starts_with('"') || value.starts_with('\'') {
                        value = &value[1..];
                    }
                    let token = value
                        .chars()
                        .take_while(|candidate| is_secret_value_char(*candidate))
                        .collect::<String>();
                    let remainder = value[token.len()..].trim_start();
                    if remainder.starts_with("::") || remainder.starts_with('(') {
                        continue;
                    }
                    if token.len() >= 16 {
                        return Some(line.trim().chars().take(80).collect::<String>());
                    }
                }
            }
            search_start = keyword_index + keyword.len();
            if search_start >= lower.len() {
                break;
            }
        }
    }
    None
}

fn extract_bearer_excerpt(line: &str) -> Option<String> {
    let lower = line.to_ascii_lowercase();
    let mut search_start = 0usize;
    while let Some(index) = lower[search_start..].find("bearer ") {
        let token_start = search_start + index + "bearer ".len();
        let token = line[token_start..]
            .chars()
            .take_while(|candidate| is_bearer_char(*candidate))
            .collect::<String>();
        if token.len() >= 20 {
            return Some(line.trim().chars().take(80).collect::<String>());
        }
        search_start = token_start;
        if search_start >= lower.len() {
            break;
        }
    }
    None
}

fn line_contains_forbidden_inline_passphrase_flag(line: &str) -> bool {
    let passphrase_flag = concat!("--pass", "phrase");
    let mut search_start = 0usize;
    while let Some(index) = line[search_start..].find(passphrase_flag) {
        let flag_start = search_start + index;
        let suffix = &line[flag_start + passphrase_flag.len()..];
        if !suffix.starts_with("-file") {
            return true;
        }
        search_start = flag_start + passphrase_flag.len();
        if search_start >= line.len() {
            break;
        }
    }
    false
}

/// True when a shell line unlinks key/passphrase material with plain `rm`.
///
/// Matching only literal filenames (the original rule) is trivially defeated by
/// the ordinary way shell scripts are written — putting the path in a variable.
/// The macOS bootstrap had four such deletions and the literal-only rule caught
/// exactly one, the single line that spelled `wireguard.passphrase` out. The three
/// it missed included `rm -f "${runtime_key}"`, which unlinks the plaintext
/// WireGuard private key. A check that a normal refactor silently disarms is worse
/// than no check, because it reads as coverage.
///
/// So a line trips this if it runs `rm` with `-f` AND mentions a secret-ish token
/// either literally or through a variable name. Comments are skipped — prose about
/// `rm -f` is not a deletion, and flagging it would train people to phrase comments
/// around the linter.
fn line_removes_secret_artifact(line: &str, sensitive_names: &[&str]) -> bool {
    let trimmed = line.trim();
    if trimmed.starts_with('#') {
        return false;
    }
    if !line_runs_forced_rm(trimmed) {
        return false;
    }
    if sensitive_names.iter().any(|name| trimmed.contains(name)) {
        return true;
    }
    // Variable-name tokens. Deliberately narrow: `_key`/`.key` rather than bare
    // "key", so `keyboard.conf` or `keychain-account` do not trip it.
    const SECRET_TOKENS: &[&str] = &[
        "passphrase",
        "secret",
        "private_key",
        "privatekey",
        "signing_key",
        "runtime_key",
        "owner_key",
        "keys_dir",
        "_key}",
        "_key\"",
        ".key}",
        ".key\"",
    ];
    let lower = trimmed.to_ascii_lowercase();
    SECRET_TOKENS.iter().any(|token| lower.contains(token))
}

/// True when the line invokes `rm` with a force flag, in any of the spellings a
/// shell script actually uses (`rm -f`, `rm -rf`, `rm -fr`, `rm --force`).
fn line_runs_forced_rm(line: &str) -> bool {
    for (index, _) in line.match_indices("rm ") {
        // Require `rm` to start a word: not `confirm `, `perform `, `$FIRM `.
        let preceded_by_word_char = line[..index]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
        if preceded_by_word_char {
            continue;
        }
        // Scan the flags that follow, stopping at the first operand.
        for word in line[index + 3..].split_whitespace() {
            if word == "--" {
                break;
            }
            if !word.starts_with('-') {
                break;
            }
            if word == "--force" || (!word.starts_with("--") && word.contains('f')) {
                return true;
            }
        }
    }
    false
}

fn parse_mktemp_secret_variable(line: &str) -> Option<String> {
    let trimmed = line.trim();
    let assignment = trimmed.strip_prefix("local ").unwrap_or(trimmed);
    let (variable, value) = assignment.split_once('=')?;
    let variable = variable.trim();
    if variable.is_empty() {
        return None;
    }
    let mut characters = variable.chars();
    let first = characters.next()?;
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return None;
    }
    if !characters.all(|character| character == '_' || character.is_ascii_alphanumeric()) {
        return None;
    }
    if value.trim() != "$(mktemp)" {
        return None;
    }
    let lowered = variable.to_ascii_lowercase();
    if !(lowered.contains("passphrase")
        || lowered.contains("secret")
        || lowered.contains("private")
        || lowered.contains("signing"))
    {
        return None;
    }
    Some(variable.to_owned())
}

pub fn execute_ops_check_secrets_hygiene(
    config: CheckSecretsHygieneConfig,
) -> Result<String, String> {
    let root = phase1_resolve_path(config.root.to_string_lossy().as_ref())?;
    if !root.is_dir() {
        return Err(format!(
            "secrets hygiene scan root must be a directory: {}",
            root.display()
        ));
    }

    let tracked_files = parse_git_tracked_files(root.as_path())?;
    let runtime_secret_basenames = BTreeSet::from([
        "membership.owner.key",
        "trust-evidence.key",
        "assignment.signing.secret",
        "wireguard.passphrase",
        "wireguard.key",
    ]);

    let tracked_secret_artifacts = tracked_files
        .iter()
        .filter_map(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .filter(|name| runtime_secret_basenames.contains(*name))
                .map(|_| path.display().to_string())
        })
        .collect::<Vec<_>>();
    if !tracked_secret_artifacts.is_empty() {
        return Err(secrets_hygiene_error(
            "tracked plaintext runtime secret artifacts are forbidden",
            tracked_secret_artifacts.as_slice(),
        ));
    }

    let excluded_roots = BTreeSet::from([".git", "target", ".cargo-home", ".ci-home"]);
    let workspace_files = collect_workspace_files(root.as_path(), &excluded_roots)?;
    let mut workspace_secret_artifacts = Vec::new();
    for file in &workspace_files {
        let relative = file.strip_prefix(root.as_path()).map_err(|err| {
            format!(
                "resolve relative workspace path failed ({}): {err}",
                file.display()
            )
        })?;
        if relative
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| runtime_secret_basenames.contains(name))
        {
            workspace_secret_artifacts.push(relative.display().to_string());
        }
    }
    if !workspace_secret_artifacts.is_empty() {
        workspace_secret_artifacts.sort();
        return Err(secrets_hygiene_error(
            "workspace contains runtime plaintext secret artifacts (must be encrypted-at-rest or removed)",
            workspace_secret_artifacts.as_slice(),
        ));
    }

    let artifact_suffixes = BTreeSet::from([".json", ".log", ".ndjson", ".txt", ".env"]);
    let artifact_roots = ["artifacts", "tmp", "tmpcfg"]
        .into_iter()
        .map(|suffix| root.join(suffix))
        .collect::<Vec<_>>();
    let mut artifact_leaks = Vec::new();
    for artifact_root in artifact_roots {
        if !artifact_root.exists() {
            continue;
        }
        if !artifact_root.is_dir() {
            continue;
        }
        let artifact_files = collect_workspace_files(artifact_root.as_path(), &BTreeSet::new())?;
        for file in artifact_files {
            if file
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name == ".gitkeep")
            {
                continue;
            }
            let extension = file
                .extension()
                .and_then(|value| value.to_str())
                .map(|value| format!(".{}", value.to_ascii_lowercase()));
            if extension
                .as_deref()
                .is_none_or(|value| !artifact_suffixes.contains(value))
            {
                continue;
            }

            let text = read_text_lossy(file.as_path())?;
            let relative = file
                .strip_prefix(root.as_path())
                .map_err(|err| {
                    format!(
                        "resolve artifact relative path failed ({}): {err}",
                        file.display()
                    )
                })?
                .display()
                .to_string();
            for line in text.lines() {
                let upper = line.to_ascii_uppercase();
                if upper.contains("-----BEGIN ") && upper.contains("PRIVATE KEY-----") {
                    artifact_leaks.push(format!(
                        "{relative} [private-key-block] -> {}",
                        line.trim().chars().take(80).collect::<String>()
                    ));
                    break;
                }
                if let Some(excerpt) = extract_secret_assignment_excerpt(line) {
                    artifact_leaks.push(format!("{relative} [secret-assignment] -> {excerpt}"));
                    break;
                }
                if let Some(excerpt) = extract_bearer_excerpt(line) {
                    artifact_leaks.push(format!("{relative} [bearer-token] -> {excerpt}"));
                    break;
                }
            }
        }
    }
    if !artifact_leaks.is_empty() {
        artifact_leaks.sort();
        return Err(secrets_hygiene_error(
            "artifact/log leak scan detected possible secrets",
            artifact_leaks.as_slice(),
        ));
    }

    let mut argv_violations = Vec::new();
    for relative in &tracked_files {
        let extension = relative.extension().and_then(|value| value.to_str());
        if !matches!(extension, Some("rs" | "sh" | "service" | "timer")) {
            continue;
        }
        if relative == Path::new("scripts/ci/secrets_hygiene_gates.sh") {
            continue;
        }
        let absolute = root.join(relative);
        if !absolute.is_file() {
            continue;
        }
        let text = read_text_lossy(absolute.as_path())?;
        for (line_index, line) in text.lines().enumerate() {
            let line_number = line_index + 1;
            if line_contains_forbidden_inline_passphrase_flag(line) {
                argv_violations.push(format!(
                    "{}:{line_number} contains forbidden inline secret argv flag ({}{}{}) -> {}",
                    relative.display(),
                    concat!("--pass", "phrase"),
                    "(?!-",
                    "file)",
                    line.trim()
                ));
            }
            for flag in [
                concat!("--pass", "word"),
                concat!("--secret", "-value"),
                concat!("--token", "-value"),
            ] {
                if line.contains(flag) {
                    argv_violations.push(format!(
                        "{}:{line_number} contains forbidden inline secret argv flag ({flag}) -> {}",
                        relative.display(),
                        line.trim()
                    ));
                }
            }
        }
    }
    if !argv_violations.is_empty() {
        argv_violations.sort();
        return Err(secrets_hygiene_error(
            "inline secret argv flags detected",
            argv_violations.as_slice(),
        ));
    }

    let mut rm_violations = Vec::new();
    let sensitive_names = [
        "membership.owner.key",
        "trust-evidence.key",
        "assignment.signing.secret",
        "wireguard.passphrase",
        "wireguard.key",
    ];
    let mut mktemp_violations = Vec::new();
    for relative in &tracked_files {
        if relative.extension().and_then(|value| value.to_str()) != Some("sh") {
            continue;
        }
        let absolute = root.join(relative);
        if !absolute.is_file() {
            continue;
        }
        let text = read_text_lossy(absolute.as_path())?;
        for (line_index, line) in text.lines().enumerate() {
            let line_number = line_index + 1;
            if line_removes_secret_artifact(line, sensitive_names.as_slice()) {
                rm_violations.push(format!(
                    "{}:{line_number} -> {}",
                    relative.display(),
                    line.trim()
                ));
            }
            if let Some(variable) = parse_mktemp_secret_variable(line) {
                let braced = format!("${{{variable}}}");
                let chmod_plain = format!("chmod 600 \"{braced}\"");
                let chmod_run_root = format!("run_root chmod 600 \"{braced}\"");
                let cleanup_plain = format!("secure_remove_file \"{braced}\"");
                let cleanup_scope = format!("secure_remove_file_with_scope \"{braced}\"");

                if !text.contains(chmod_plain.as_str()) && !text.contains(chmod_run_root.as_str()) {
                    mktemp_violations.push(format!(
                        "{}:{line_number} missing chmod 600 for mktemp secret variable {}",
                        relative.display(),
                        variable
                    ));
                }
                if !text.contains(cleanup_plain.as_str()) && !text.contains(cleanup_scope.as_str())
                {
                    mktemp_violations.push(format!(
                        "{}:{line_number} missing secure-remove cleanup for mktemp secret variable {}",
                        relative.display(),
                        variable
                    ));
                }
            }
        }
    }

    if !rm_violations.is_empty() {
        rm_violations.sort();
        return Err(secrets_hygiene_error(
            "shell scripts use rm -f on sensitive key/passphrase artifacts",
            rm_violations.as_slice(),
        ));
    }

    if !mktemp_violations.is_empty() {
        mktemp_violations.sort();
        return Err(secrets_hygiene_error(
            "mktemp secret handling is missing strict tmp-mode or secure cleanup",
            mktemp_violations.as_slice(),
        ));
    }

    Ok("Secrets hygiene gate: PASS".to_owned())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub fn execute_ops_run_phase1_baseline() -> Result<String, String> {
    let runtime_report = phase1_path_from_env_or_default(
        "RUSTYNET_PHASE1_RUNTIME_REPORT",
        DEFAULT_PHASE1_RUNTIME_REPORT_PATH,
    )?;
    let backend_report = phase1_path_from_env_or_default(
        "RUSTYNET_PHASE1_BACKEND_REPORT",
        DEFAULT_PHASE1_BACKEND_REPORT_PATH,
    )?;
    let auto_collect = parse_env_bool_with_default("RUSTYNET_PHASE1_AUTO_COLLECT", "1")?;

    let mut missing_env = Vec::new();
    let parsed_env_metrics = phase1_metrics_from_env(&mut missing_env)?;
    let (metrics, collected_output_path) = if missing_env.is_empty() {
        (
            parsed_env_metrics
                .ok_or_else(|| "phase1 metrics env parse produced no values".to_owned())?,
            None,
        )
    } else if auto_collect {
        let (collected_metrics, output_path) = collect_phase1_measured_input_artifact()?;
        (collected_metrics, Some(output_path))
    } else {
        return Err(format!(
            "missing required measured input environment variable(s): {}",
            missing_env.join(" ")
        ));
    };

    phase1_run_runtime_baseline(runtime_report.as_path(), &metrics)?;
    phase1_run_backend_contract_perf(backend_report.as_path(), &metrics)?;

    phase1_validate_report(
        runtime_report.as_path(),
        "phase1 runtime report",
        &[
            "idle_cpu_percent",
            "idle_memory_mb",
            "reconnect_seconds",
            "route_policy_apply_p95_seconds",
            "throughput_overhead_vs_wireguard_percent",
        ],
    )?;
    phase1_validate_report(
        backend_report.as_path(),
        "phase1 backend report",
        &[
            "configure_peer_avg_us",
            "apply_routes_avg_us",
            "stats_avg_us",
            "throughput_overhead_vs_wireguard_percent",
        ],
    )?;

    let collected_note = collected_output_path
        .map(|path| format!(" collected_input={}", path.display()))
        .unwrap_or_default();
    Ok(format!(
        "phase1 baseline artifacts generated: runtime_report={} backend_report={} source={}{}",
        runtime_report.display(),
        backend_report.display(),
        metrics.source_path.display(),
        collected_note
    ))
}

#[cfg(test)]
mod secret_removal_rule_tests {
    use super::{line_removes_secret_artifact, line_runs_forced_rm};

    const SENSITIVE: &[&str] = &[
        "membership.owner.key",
        "trust-evidence.key",
        "assignment.signing.secret",
        "wireguard.passphrase",
        "wireguard.key",
    ];

    fn flags(line: &str) -> bool {
        line_removes_secret_artifact(line, SENSITIVE)
    }

    #[test]
    fn catches_every_deletion_the_macos_bootstrap_actually_had() {
        // These are the four real lines. The old literal-only rule caught only the
        // first; the other three hid behind variables, including the one that
        // unlinks the plaintext WireGuard private key.
        assert!(flags(r#"    rm -f "${KEYS_DIR}/wireguard.passphrase""#));
        assert!(flags(r#"  trap 'rm -f "${passphrase_tmp}"' EXIT"#));
        assert!(flags(r#"    rm -f "${runtime_key}""#));
        assert!(flags(r#"    rm -f "${passphrase_file}""#));
    }

    #[test]
    fn the_secure_helper_is_not_flagged_as_its_own_violation() {
        // secure_remove_file ends in `rm -f -- "${target}"`. That is the approved
        // path and names no secret, so the rule must leave it alone or the fix
        // could never pass its own gate.
        assert!(!flags(r#"  rm -f -- "${target}""#));
        assert!(!flags(r#"  secure_remove_file "${passphrase_file}""#));
        assert!(!flags(
            r#"  trap 'secure_remove_file "${passphrase_tmp}"' EXIT"#
        ));
    }

    #[test]
    fn prose_about_rm_f_is_not_a_deletion() {
        // Flagging comments would only teach people to reword comments.
        assert!(!flags(
            "# same reason: `rm -f` on a secret is two separate hazards."
        ));
        assert!(!flags(
            "  # rm -f \"${passphrase_file}\" would be unsafe here"
        ));
    }

    #[test]
    fn near_miss_names_do_not_trip_the_rule() {
        // Narrow tokens (_key/.key, not bare "key") keep these clean.
        assert!(!flags(r#"  rm -f "${tmp}/keyboard.conf""#));
        assert!(!flags(r#"  rm -f "${BUILD_DIR}/monkey.txt""#));
        assert!(!flags(r#"  rm -f "${cache}/donkey""#));
    }

    #[test]
    fn other_force_spellings_are_caught_too() {
        // A rule that only knows `rm -f` is one refactor from silence.
        assert!(flags(r#"  rm -rf "${passphrase_dir}""#));
        assert!(flags(r#"  rm -fr "${passphrase_dir}""#));
        assert!(flags(r#"  rm --force "${passphrase_file}""#));
    }

    #[test]
    fn non_forced_rm_is_out_of_scope_for_this_rule() {
        assert!(!line_runs_forced_rm(r#"rm "${passphrase_file}""#));
        assert!(!line_runs_forced_rm(r#"rm -i "${passphrase_file}""#));
    }

    #[test]
    fn rm_must_be_a_word_not_a_suffix() {
        assert!(!line_runs_forced_rm("confirm -f something"));
        assert!(!line_runs_forced_rm("perform -f action"));
        assert!(line_runs_forced_rm("rm -f x"));
        assert!(line_runs_forced_rm("sudo rm -f x"));
    }

    #[test]
    fn flags_stop_at_the_first_operand() {
        // `rm -- -f` deletes a file literally named "-f"; that is not a force flag.
        assert!(!line_runs_forced_rm("rm -- -f"));
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CheckDependencyExceptionsConfig, CheckNoUnsafeRustSourcesConfig, CheckPerfRegressionConfig,
        Phase1MetricEntryView, Phase1ValidateReportView, execute_ops_check_dependency_exceptions,
        execute_ops_check_no_unsafe_rust_sources, execute_ops_check_perf_regression,
        extract_bearer_excerpt, extract_secret_assignment_excerpt,
        line_contains_forbidden_inline_passphrase_flag, parse_bool_value,
        parse_mktemp_secret_variable, parse_utc_to_unix, phase1_collect_measured_input_from_source,
        phase1_validate_report, phase1_validate_secure_directory, scan_rust_source_text_for_unsafe,
        unsafe_scan_path_is_allowlisted, unsafe_site_has_adjacent_safety_comment,
        verify_member_unsafe_lints, verify_workspace_unsafe_pin, workspace_member_paths,
    };
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{SystemTime, UNIX_EPOCH};

    static TEST_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn unique_temp_path(prefix: &str, suffix: &str) -> PathBuf {
        let counter = TEST_ID_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        // The process id is required, not decorative: cargo-nextest runs every
        // test in its own process, so `TEST_ID_COUNTER` is always 0 and the
        // timestamp alone can collide between two concurrently starting test
        // processes, letting one test clobber another's temporary files.
        let pid = std::process::id();
        std::env::temp_dir().join(format!("{prefix}-{pid}-{now_nanos}-{counter}{suffix}"))
    }

    #[test]
    fn parse_bool_value_matches_systemd_script_contract() {
        assert!(parse_bool_value("TEST_BOOL", "true").expect("true should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "off").expect("off should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "").expect("empty should parse"));
        assert!(parse_bool_value("TEST_BOOL", "bogus").is_err());
    }

    #[test]
    fn phase1_collector_derives_max_metrics_from_ndjson() {
        let source_path = unique_temp_path("rustynet-phase1-collector", ".ndjson");
        let body = concat!(
            "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n",
            "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.6,\"idle_memory_mb\":96,\"reconnect_seconds\":2.1,\"route_apply_p95_seconds\":1.4,\"throughput_overhead_percent\":12.3}\n"
        );
        std::fs::write(&source_path, body).expect("write ndjson source");
        let mut perms = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&source_path, perms).expect("set secure mode");

        let measured = phase1_collect_measured_input_from_source(&source_path)
            .expect("collector should parse ndjson");
        assert_eq!(measured.sample_count, 2);
        assert!((measured.idle_cpu_percent - 1.6).abs() < f64::EPSILON);
        assert!((measured.idle_memory_mb - 96.0).abs() < f64::EPSILON);
        assert!((measured.reconnect_seconds - 2.1).abs() < f64::EPSILON);
        assert!((measured.route_policy_apply_p95_seconds - 1.4).abs() < f64::EPSILON);
        assert!((measured.throughput_overhead_percent - 12.3).abs() < f64::EPSILON);
        assert!((measured.backend_throughput_overhead_percent - 12.3).abs() < f64::EPSILON);

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_collector_rejects_non_measured_json_source() {
        let source_path = unique_temp_path("rustynet-phase1-unmeasured", ".json");
        let body = concat!(
            "{",
            "\"evidence_mode\":\"synthetic\",",
            "\"idle_cpu_percent\":1.0,",
            "\"idle_memory_mb\":64,",
            "\"reconnect_seconds\":1.0,",
            "\"route_apply_p95_seconds\":0.5,",
            "\"throughput_overhead_percent\":8.0",
            "}\n"
        );
        std::fs::write(&source_path, body).expect("write json source");
        let mut perms = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&source_path, perms).expect("set secure mode");

        let err = phase1_collect_measured_input_from_source(&source_path)
            .expect_err("collector should reject non-measured evidence");
        assert!(err.contains("not measured evidence"));

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_collector_rejects_non_measured_ndjson_entry() {
        let source_path = unique_temp_path("rustynet-phase1-ndjson-unmeasured", ".ndjson");
        let body = "{\"evidence_mode\":\"synthetic\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n";
        std::fs::write(&source_path, body).expect("write ndjson source");
        let mut perms = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(&source_path, perms).expect("set secure mode");

        let err = phase1_collect_measured_input_from_source(&source_path)
            .expect_err("collector should reject non-measured ndjson evidence");
        assert!(err.contains("not measured evidence"));

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_collector_hardens_group_writable_source_file() {
        let source_path = unique_temp_path("rustynet-phase1-insecure-perms", ".ndjson");
        let body = "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n";
        std::fs::write(&source_path, body).expect("write ndjson source");
        let mut perms = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o664);
        std::fs::set_permissions(&source_path, perms).expect("set insecure mode");

        let measured = phase1_collect_measured_input_from_source(&source_path)
            .expect("collector should harden trusted group-writable source");
        assert_eq!(measured.sample_count, 1);
        let hardened_mode = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(hardened_mode & 0o022, 0);

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_secure_directory_hardens_group_writable_directory() {
        let dir_path = unique_temp_path("rustynet-phase1-dir-perms", "");
        std::fs::create_dir_all(&dir_path).expect("create temp directory");
        let mut perms = std::fs::metadata(&dir_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&dir_path, perms).expect("set insecure mode");

        phase1_validate_secure_directory(&dir_path, "test phase1 output directory")
            .expect("directory should be hardened when owner is trusted");
        let hardened_mode = std::fs::metadata(&dir_path)
            .expect("metadata after harden")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(hardened_mode & 0o022, 0);

        let _ = std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700));
        let _ = std::fs::remove_dir_all(dir_path);
    }

    #[test]
    fn phase1_report_validator_rejects_not_measurable_metric() {
        let report_path =
            std::env::temp_dir().join(format!("rustynet-phase1-report-{}", std::process::id()));
        let body = concat!(
            "{",
            "\"phase\":\"phase1\",",
            "\"suite\":\"runtime_baseline\",",
            "\"metrics\":[",
            "{\"name\":\"idle_cpu_percent\",\"value\":1.0,\"status\":\"not_measurable\",\"reason\":\"measurement_unavailable\"}",
            "]",
            "}\n"
        );
        std::fs::write(&report_path, body).expect("write report");

        let err =
            phase1_validate_report(&report_path, "phase1 runtime report", &["idle_cpu_percent"])
                .expect_err("report validation should fail");
        assert!(err.contains("non-measured metric"));
        let _ = std::fs::remove_file(report_path);
    }

    // ---- X2: Phase1ValidateReportView typed-view migration --------

    /// Clean fixture: a well-formed report payload (single metric)
    /// deserialises into the typed view; the metric entry's typed
    /// slots populate; non-required keys ride through
    /// `#[serde(flatten)] extra`.
    #[test]
    fn phase1_validate_report_view_accepts_clean_payload() {
        let payload = serde_json::json!({
            "phase": "phase1",
            "suite": "runtime_baseline",
            "metrics": [
                {
                    "name": "idle_cpu_percent",
                    "value": 1.5,
                    "status": "pass",
                    "reason": "ok",
                    "extra_field": "ride-through",
                }
            ],
        });
        let view: Phase1ValidateReportView =
            serde_json::from_value(payload).expect("typed view accepts the clean phase1 fixture");
        let metrics = view.metrics.expect("metrics array present");
        assert_eq!(metrics.len(), 1);
        let entry = &metrics[0];
        assert_eq!(entry.name.as_deref(), Some("idle_cpu_percent"));
        assert_eq!(entry.status.as_deref(), Some("pass"));
        assert_eq!(entry.reason.as_deref(), Some("ok"));
        assert!(entry.value.is_some(), "value slot must carry the Value");
        assert_eq!(
            entry
                .extra
                .get("extra_field")
                .and_then(serde_json::Value::as_str),
            Some("ride-through")
        );
    }

    /// Wrong-type `metrics` slot rejected at the typed layer. The
    /// legacy code path used `.and_then(Value::as_array)` which
    /// silently returned `None` and surfaced as "missing metrics
    /// array"; the typed deserialise instead produces a precise
    /// "invalid field shape" error that names `metrics`.
    #[test]
    fn phase1_validate_report_view_rejects_wrong_type_metrics_slot() {
        let payload = serde_json::json!({ "metrics": {} });
        let err = serde_json::from_value::<Phase1ValidateReportView>(payload)
            .expect_err("object metrics must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("metrics") || message.contains("sequence"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Wrong-type `status` slot inside a metric entry rejected. Was
    /// previously silent: `.and_then(Value::as_str)` returning `None`
    /// caused the legacy validator to bubble "missing status",
    /// hiding the actual shape problem. Now the typed deserialize
    /// surfaces the precise field-type error.
    #[test]
    fn phase1_metric_entry_view_rejects_wrong_type_status_slot() {
        let payload = serde_json::json!({
            "name": "idle_cpu_percent",
            "value": 1.0,
            "status": 42,
        });
        let err = serde_json::from_value::<Phase1MetricEntryView>(payload)
            .expect_err("integer status must be rejected at deserialize");
        let message = err.to_string();
        assert!(
            message.contains("status") || message.contains("string"),
            "error must point to the offending field or type: {message}"
        );
    }

    /// Validator integration: a present-but-wrong-type `metrics`
    /// field surfaces the new "invalid field shape" error wrapping
    /// the precise serde message — confirming the typed layer
    /// triggers before the legacy "missing metrics array" branch.
    #[test]
    fn phase1_validate_report_surfaces_typed_shape_error() {
        let path = unique_temp_path("rustynet-phase1-shape-error", ".json");
        std::fs::write(&path, br#"{"metrics": {}}"#).expect("write report");
        let err = phase1_validate_report(&path, "phase1 runtime report", &["idle_cpu_percent"])
            .expect_err("validator must surface the typed shape error");
        assert!(
            err.contains("invalid field shape"),
            "validator must wrap the typed deserialise error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    /// Cycle 72: `load_perf_metrics` reuses the cycle-65 typed views
    /// (`Phase1ValidateReportView` + `Phase1MetricEntryView`). A
    /// wrong-type `metrics` slot surfaces the same "invalid field
    /// shape" wrap as `phase1_validate_report` — the two loaders now
    /// share one canonical X2 contract.
    #[test]
    fn load_perf_metrics_surfaces_typed_shape_error_for_wrong_type_metrics() {
        let path = unique_temp_path("rustynet-phase1-perf-shape-error", ".json");
        std::fs::write(&path, br#"{"metrics": "not-an-array"}"#).expect("write report");
        let err = super::load_perf_metrics(&path, "perf shape error report")
            .expect_err("perf loader must surface the typed shape error");
        assert!(
            err.contains("invalid field shape"),
            "perf loader must wrap the typed deserialise error: {err}"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn unsafe_scanner_ignores_lifetimes_comments_and_strings() {
        let source = concat!(
            "fn keep<'a>(value: &'a str) -> &'a str { value }\n",
            "// unsafe should not match here\n",
            "const NOTE: &str = \"unsafe in string\";\n"
        );
        let findings = scan_rust_source_text_for_unsafe(source);
        assert!(findings.is_empty());
    }

    #[test]
    fn unsafe_scanner_detects_keyword_in_code() {
        let source = "fn bad() {\n  unsafe { let _x = 1; }\n}\n";
        let findings = scan_rust_source_text_for_unsafe(source);
        assert_eq!(findings, vec![(2, 3)]);
    }

    #[test]
    fn parse_utc_to_unix_accepts_zulu_and_offset_forms() {
        let zulu = parse_utc_to_unix("1970-01-01T00:00:00Z", "timestamp").expect("parse zulu");
        let offset =
            parse_utc_to_unix("1970-01-01T01:00:00+01:00", "timestamp").expect("parse offset");
        assert_eq!(zulu, 0);
        assert_eq!(offset, 0);
    }

    #[test]
    fn parse_utc_to_unix_refuses_multibyte_offset_without_panicking() {
        let err = parse_utc_to_unix("2026-01-01T00:00:00+\u{c911}:1", "timestamp")
            .expect_err("must fail");
        assert!(err.contains("invalid UTC timestamp"));
    }

    #[test]
    fn parse_utc_to_unix_rejects_invalid_timestamp() {
        let err = parse_utc_to_unix("not-a-timestamp", "timestamp").expect_err("must fail");
        assert!(err.contains("invalid UTC timestamp"));
    }

    #[test]
    fn dependency_exception_checker_rejects_expired_entries() {
        let path = unique_temp_path("rustynet-dependency-exceptions", ".json");
        let payload = concat!(
            "{",
            "\"exceptions\":[",
            "{",
            "\"id\":\"expired-1\",",
            "\"crate\":\"openssl-sys\",",
            "\"reason\":\"temporary\",",
            "\"owner\":\"security\",",
            "\"approved_by\":\"eng\",",
            "\"expires_utc\":\"1970-01-01T00:00:00Z\"",
            "}",
            "]",
            "}\n"
        );
        std::fs::write(&path, payload).expect("write exceptions file");
        let result = execute_ops_check_dependency_exceptions(CheckDependencyExceptionsConfig {
            path: path.clone(),
        });
        let err = result.expect_err("expired entry must fail");
        assert!(err.contains("dependency exception expired"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn perf_regression_checker_passes_for_valid_metrics() {
        let phase1 = unique_temp_path("rustynet-perf-phase1", ".json");
        let phase3 = unique_temp_path("rustynet-perf-phase3", ".json");
        let phase1_payload = concat!(
            "{",
            "\"metrics\":[",
            "{\"name\":\"idle_cpu_percent\",\"value\":1.0,\"status\":\"pass\"},",
            "{\"name\":\"idle_memory_mb\",\"value\":64.0,\"status\":\"pass\"},",
            "{\"name\":\"route_policy_apply_p95_seconds\",\"value\":1.5,\"status\":\"pass\"}",
            "]",
            "}\n"
        );
        let phase3_payload = concat!(
            "{",
            "\"metrics\":[",
            "{\"name\":\"peer_sessions\",\"value\":6.0,\"status\":\"pass\"}",
            "]",
            "}\n"
        );
        std::fs::write(&phase1, phase1_payload).expect("write phase1 report");
        std::fs::write(&phase3, phase3_payload).expect("write phase3 report");

        let result = execute_ops_check_perf_regression(CheckPerfRegressionConfig {
            phase1_report_path: phase1.clone(),
            phase3_report_path: phase3.clone(),
        })
        .expect("perf regression should pass");
        assert!(result.contains("PASS"));

        let _ = std::fs::remove_file(phase1);
        let _ = std::fs::remove_file(phase3);
    }

    #[test]
    fn secrets_assignment_excerpt_detects_secret_value_shape() {
        let line = "token = \"AbCdEfGhIjKlMnOpQrSt\"";
        let excerpt = extract_secret_assignment_excerpt(line);
        assert!(excerpt.is_some());
    }

    #[test]
    fn secrets_assignment_excerpt_requires_word_boundaries() {
        let line = "RUSTYNET_ASSIGNMENT_SIGNING_SECRET=\"/etc/rustynet/assignment.signing.secret\"";
        let excerpt = extract_secret_assignment_excerpt(line);
        assert!(excerpt.is_none());
    }

    #[test]
    fn secrets_assignment_excerpt_ignores_code_expression_rhs() {
        let line =
            "1118 |         let mut token = RelaySessionToken::sign(&sk, \"node-a\", \"node-b\",";
        let excerpt = extract_secret_assignment_excerpt(line);
        assert!(excerpt.is_none());
    }

    #[test]
    fn secrets_assignment_excerpt_ignores_natural_language_sentence() {
        // "passphrase" appears in a human-readable diagnostic sentence, not as a key.
        // Word characters exist between the keyword and the colon, so this must not fire.
        let line = "  \"summary\": \"Expected plaintext-passphrase hygiene result: no-plaintext-passphrase-files.\",";
        let excerpt = extract_secret_assignment_excerpt(line);
        assert!(
            excerpt.is_none(),
            "diagnostic sentence must not be flagged as a secret assignment; got: {excerpt:?}"
        );
    }

    #[test]
    fn secrets_assignment_excerpt_still_detects_passphrase_key_value() {
        // Genuine YAML/JSON passphrase assignment must still be caught.
        let line = "  \"passphrase\": \"hunter2supersecretlongvalue\"";
        let excerpt = extract_secret_assignment_excerpt(line);
        assert!(
            excerpt.is_some(),
            "passphrase key-value assignment must be detected"
        );
    }

    #[test]
    fn bearer_excerpt_detects_bearer_token_shape() {
        let line = "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345";
        let excerpt = extract_bearer_excerpt(line);
        assert!(excerpt.is_some());
    }

    #[test]
    fn inline_passphrase_flag_detection_allows_file_variant_only() {
        assert!(line_contains_forbidden_inline_passphrase_flag(
            format!("rustynet trust keygen {} foo", concat!("--pass", "phrase")).as_str()
        ));
        assert!(!line_contains_forbidden_inline_passphrase_flag(
            format!(
                "rustynet trust keygen {} /tmp/cred",
                concat!("--pass", "phrase-file")
            )
            .as_str()
        ));
    }

    #[test]
    fn mktemp_secret_variable_parser_matches_expected_form() {
        assert_eq!(
            parse_mktemp_secret_variable("local signing_secret_tmp=$(mktemp)"),
            Some("signing_secret_tmp".to_owned())
        );
        assert_eq!(parse_mktemp_secret_variable("tmp=$(mktemp)"), None);
    }

    #[test]
    fn unsafe_allowlist_matches_exactly_the_two_oi20_scopes() {
        assert!(unsafe_scan_path_is_allowlisted(
            "rustynetd/src/macos_utun_helper_unsafe.rs"
        ));
        assert!(unsafe_scan_path_is_allowlisted(
            "rustynet-windows-native/src/lib.rs"
        ));
        assert!(!unsafe_scan_path_is_allowlisted("rustynetd/src/daemon.rs"));
        assert!(!unsafe_scan_path_is_allowlisted(
            "rustynet-windows-native/src/imp.rs"
        ));
        assert!(!unsafe_scan_path_is_allowlisted(
            "rustynet-relay/src/lib.rs"
        ));
        assert!(!unsafe_scan_path_is_allowlisted(
            "third_party/rustynet-tun/src/lib.rs"
        ));
    }

    #[test]
    fn safety_comment_adjacency_same_line_counts() {
        let lines = vec![
            "fn f() {",
            "    let p = std::ptr::null_mut::<u8>(); // SAFETY: never dereferenced",
            "}",
        ];
        assert!(unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_multiline_block_counts() {
        // Mirrors the real tree style (e.g. rustynet-windows-native
        // read_token_user_sid): SAFETY opens a contiguous block whose
        // last line sits directly above the site.
        let lines = vec![
            "fn f() {",
            "    // SAFETY: `bytes` was sized + filled by GetTokenInformation for",
            "    // the TokenUser class, so `*token_user` is a valid TOKEN_USER",
            "    let sid = std::ptr::null_mut::<u8>();",
            "}",
        ];
        assert!(unsafe_site_has_adjacent_safety_comment(&lines, 3));
    }

    #[test]
    fn safety_comment_adjacency_no_comment_fails_closed() {
        let lines = vec!["fn f() {", "    let p = std::ptr::null_mut::<u8>();", "}"];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_blank_line_breaks_block() {
        let lines = vec![
            "fn f() {",
            "    // SAFETY: orphaned by the blank line below.",
            "",
            "    let p = std::ptr::null_mut::<u8>();",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 3));
    }

    #[test]
    fn safety_comment_adjacency_code_between_safety_and_site_fails_closed() {
        let lines = vec![
            "fn f() {",
            "    // SAFETY: separated from the site by a code line.",
            "    setup();",
            "    let p = std::ptr::null_mut::<u8>();",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 3));
    }

    #[test]
    fn safety_comment_adjacency_forged_in_same_line_string_literal_fails() {
        // AQ-248/D1 witness M1: a string literal on the unsafe line
        // containing "// SAFETY:" is data, not a comment, and must not
        // satisfy the adjacency check.
        let lines = vec![
            "fn f() {",
            "    let _p = unsafe { std::ptr::null_mut::<u8>() }; let _fake = \"// SAFETY: forged inside a string literal\";",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_forged_in_raw_string_fails() {
        let lines = vec![
            "fn f() {",
            "    let _fake = r\"// SAFETY: forged in a raw string\"; let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_forged_in_raw_hash_string_fails() {
        let lines = vec![
            "fn f() {",
            "    let _fake = r#\"// SAFETY: forged, with \"quotes\" inside\"#; let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_forged_behind_escaped_quote_fails() {
        let lines = vec![
            "fn f() {",
            "    let _fake = \"escaped \\\"// SAFETY:\\\" quote\"; let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_forged_inside_multiline_string_fails() {
        // The literal spans lines: the forged text sits on its own line
        // ABOVE the site, so the preceding-line branch must not read it
        // as a comment either.
        let lines = vec![
            "fn f() {",
            "    let _fake = \"first line",
            "// SAFETY: forged inside a multi-line string literal",
            "\"; let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 3));
    }

    #[test]
    fn safety_comment_adjacency_real_same_line_comment_after_string_still_counts() {
        let lines = vec![
            "fn f() {",
            "    let _msg = \"not a safety comment\"; let _p = unsafe { std::ptr::null_mut::<u8>() }; // SAFETY: witness pointer is never dereferenced",
            "}",
        ];
        assert!(unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    #[test]
    fn safety_comment_adjacency_apostrophes_do_not_disguise_comment_state() {
        // Lifetime apostrophes in code and apostrophes inside comments
        // must not put the scanner into char-literal state and blank
        // out a genuine SAFETY comment.
        let lines = vec![
            "fn f<'a, T: 'static>(x: &'a T) -> &'a T where T: Copy { x }",
            "    // don't drop this; it's the invariant.",
            "    // SAFETY: witness pointer is never dereferenced",
            "    let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(unsafe_site_has_adjacent_safety_comment(&lines, 3));
    }

    #[test]
    fn safety_comment_adjacency_raw_byte_string_forge_fails() {
        // br#".."# must be seen as a raw string, not b + a normal
        // string, or the desync leaves forged text scanned as code.
        let lines = vec![
            "fn f() {",
            "    let _fake = br#\"a\"// SAFETY: forged\"#; let _p = unsafe { std::ptr::null_mut::<u8>() };",
            "}",
        ];
        assert!(!unsafe_site_has_adjacent_safety_comment(&lines, 1));
    }

    fn write_synthetic_workspace_manifest(manifest: &str) -> PathBuf {
        let workspace_dir = unique_temp_path("rustynet-oi20-ws", "");
        std::fs::create_dir_all(&workspace_dir).expect("create workspace dir");
        std::fs::write(workspace_dir.join("Cargo.toml"), manifest).expect("write manifest");
        std::fs::create_dir_all(workspace_dir.join("crates/probe/src")).expect("create probe src");
        workspace_dir
    }

    #[test]
    fn workspace_unsafe_pin_accepts_forbid() {
        let dir = write_synthetic_workspace_manifest(
            "[workspace]\nmembers = []\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
        );
        verify_workspace_unsafe_pin(&dir.join("Cargo.toml")).expect("forbid pin must verify");
    }

    #[test]
    fn workspace_unsafe_pin_rejects_deny() {
        let dir = write_synthetic_workspace_manifest(
            "[workspace]\n\n[workspace.lints.rust]\nunsafe_code = \"deny\"\n",
        );
        let err = verify_workspace_unsafe_pin(&dir.join("Cargo.toml"))
            .expect_err("deny pin must fail: the root stays forbid under OI-20");
        assert!(err.contains("unsafe_code = \"forbid\""), "err: {err}");
    }

    #[test]
    fn workspace_unsafe_pin_rejects_missing_table() {
        let dir = write_synthetic_workspace_manifest("[workspace]\nmembers = []\n");
        let err = verify_workspace_unsafe_pin(&dir.join("Cargo.toml"))
            .expect_err("missing table must fail closed");
        assert!(err.contains("[workspace.lints.rust]"), "err: {err}");
    }

    #[test]
    fn workspace_unsafe_pin_rejects_missing_manifest() {
        let missing = unique_temp_path("rustynet-oi20-missing", ".toml");
        let err =
            verify_workspace_unsafe_pin(&missing).expect_err("missing manifest must fail closed");
        assert!(err.contains("cannot read workspace manifest"), "err: {err}");
    }

    #[test]
    fn workspace_member_paths_parse_explicit_lists_and_fail_closed_on_globs() {
        let multi_line = "[workspace]\nmembers = [\n  \"crates/a\",\n  \"crates/b\",\n]\n";
        assert_eq!(
            workspace_member_paths(multi_line).expect("multi-line members parse"),
            vec!["crates/a".to_string(), "crates/b".to_string()]
        );
        let single_line = "[workspace]\nmembers = [\"crates/a\", \"crates/b\"]\n";
        assert_eq!(
            workspace_member_paths(single_line).expect("single-line members parse"),
            vec!["crates/a".to_string(), "crates/b".to_string()]
        );
        let glob = "[workspace]\nmembers = [\"crates/*\"]\n";
        let err = workspace_member_paths(glob).expect_err("glob member must fail closed");
        assert!(err.contains("glob"), "err: {err}");
        let no_members = "[workspace]\nresolver = \"2\"\n";
        let err = workspace_member_paths(no_members).expect_err("missing members must fail closed");
        assert!(err.contains("members"), "err: {err}");
    }

    #[test]
    fn member_with_unsafe_site_requires_own_deny_lints_table() {
        // A member holding an unsafe site without its own
        // [lints.rust] unsafe_code = "deny" fails with a named error.
        let dir = write_synthetic_workspace_manifest(
            "[workspace]\nmembers = [\"crates/probe\"]\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
        );
        let lib = dir.join("crates/probe/src/lib.rs");
        std::fs::write(
            &lib,
            "pub fn f() {\n    // SAFETY: witness pointer is never dereferenced.\n    let p = unsafe { 0 as *const u8 };\n}\n",
        )
        .expect("write lib.rs");
        std::fs::write(
            dir.join("crates/probe/Cargo.toml"),
            "[package]\nname = \"probe\"\n",
        )
        .expect("write manifest without lints table");
        let err = verify_member_unsafe_lints(&dir).expect_err("missing own deny must fail");
        assert!(err.contains("crates/probe"), "err: {err}");
        assert!(err.contains("unsafe_code = \"deny\""), "err: {err}");

        // Inheriting the workspace lints instead ([lints] workspace =
        // true) is exactly the failure the check exists to name.
        std::fs::write(
            dir.join("crates/probe/Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lints]\nworkspace = true\n",
        )
        .expect("write inheriting manifest");
        let err = verify_member_unsafe_lints(&dir).expect_err("inheriting member must still fail");
        assert!(err.contains("crates/probe"), "err: {err}");

        // With its own deny table the member verifies.
        std::fs::write(
            dir.join("crates/probe/Cargo.toml"),
            "[package]\nname = \"probe\"\n\n[lints.rust]\nunsafe_code = \"deny\"\n",
        )
        .expect("write own-deny manifest");
        verify_member_unsafe_lints(&dir).expect("own deny table must verify");

        // A member with zero unsafe needs no own table at all.
        std::fs::write(&lib, "pub fn f() -> usize { 3 }\n").expect("clean lib.rs");
        std::fs::remove_file(dir.join("crates/probe/Cargo.toml")).expect("remove manifest");
        verify_member_unsafe_lints(&dir).expect("zero-unsafe member without own table must verify");
    }

    #[test]
    fn no_unsafe_check_enforces_safety_comment_scope_and_pass_on_clean_tree() {
        // Planted unsafe without a SAFETY comment: the SAFETY half fires
        // before the scope half.
        let dir = write_synthetic_workspace_manifest(
            "[workspace]\nmembers = []\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
        );
        let lib = dir.join("crates/probe/src/lib.rs");
        std::fs::write(&lib, "pub fn f() { let p = unsafe { 0 as *const u8 }; }\n")
            .expect("write lib.rs");
        let err = execute_ops_check_no_unsafe_rust_sources(CheckNoUnsafeRustSourcesConfig {
            root: dir.join("crates"),
        })
        .expect_err("unsafe without SAFETY must fail");
        assert!(err.contains("no adjacent // SAFETY:"), "err: {err}");

        // With a SAFETY comment the site is sound per B1 but outside the
        // permitted scopes, so the scope half fires.
        std::fs::write(
            &lib,
            "pub fn f() {\n    // SAFETY: witness pointer is never dereferenced.\n    let p = unsafe { 0 as *const u8 };\n}\n",
        )
        .expect("rewrite lib.rs");
        let err = execute_ops_check_no_unsafe_rust_sources(CheckNoUnsafeRustSourcesConfig {
            root: dir.join("crates"),
        })
        .expect_err("unsafe with SAFETY outside scopes must still fail");
        assert!(
            err.contains("outside a permitted OI-20 scope"),
            "err: {err}"
        );

        // Clean tree passes.
        std::fs::write(&lib, "pub fn f() -> usize { 3 }\n").expect("clean lib.rs");
        let ok = execute_ops_check_no_unsafe_rust_sources(CheckNoUnsafeRustSourcesConfig {
            root: dir.join("crates"),
        })
        .expect("clean tree must pass");
        assert!(ok.contains("Unsafe code checks: PASS"), "ok: {ok}");
    }
}
#[cfg(test)]
mod aq08_6b_differential {
    //! AQ-08 bucket 6b part 1 (rustynet-cli/ops_phase1.rs): seeded-mutation
    //! differential harness. Every `old_*` function is a verbatim copy of the
    //! corresponding pre-patch function body from the pre-patch tree (HEAD
    //! 53ba50956), renamed only; verbatim identity is checked by the lane's
    //! harness (brace-span extract + rename-normalized compare against
    //! `git show HEAD`). For a golden fixture plus 2000 deterministic
    //! mutations per parser (truncation, char delete/duplicate/swap, junk and
    //! multibyte injection, oversize padding, empty input), the old and new
    //! implementations must produce identical results. Any divergence fails
    //! the test and names the parser and the offending input. Three of the
    //! old copies can panic on inputs their callers never produce
    //! (`old_unsafe_site_has_adjacent_safety_comment` with an out-of-range
    //! site index, `old_keyword_has_word_boundaries` with a start past the
    //! end, `old_is_raw_string_open` with an index past the end); they are
    //! exercised only over their documented domains, and the new code's
    //! fail-closed behaviour for the first one is pinned by a dedicated unit
    //! assertion.

    use super::*;

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
    }

    const ALPHABET: &[char] = &[
        'a', 'Z', '_', '"', '\'', 'r', '#', '/', '\\', '*', '+', '-', ':', '.', '0', '1', '9', ' ',
        '\t', '\n', 'т', 'é',
    ];

    fn mutate_string(input: &str, rng: &mut Rng) -> String {
        let mut chars: Vec<char> = input.chars().collect();
        match rng.below(8) {
            0 => {
                let keep = rng.below(chars.len() + 2);
                chars.truncate(keep);
            }
            1 => {
                if !chars.is_empty() {
                    let at = rng.below(chars.len());
                    chars.remove(at);
                }
            }
            2 => {
                if !chars.is_empty() {
                    let at = rng.below(chars.len());
                    let taken = chars[at];
                    chars.insert(at, taken);
                }
            }
            3 => {
                if chars.len() >= 2 {
                    let at = rng.below(chars.len() - 1);
                    chars.swap(at, at + 1);
                }
            }
            4 => {
                let at = rng.below(chars.len() + 1);
                let letter = ALPHABET[rng.below(ALPHABET.len())];
                chars.insert(at, letter);
            }
            5 => {
                for _ in 0..(1 + rng.below(8)) {
                    let at = rng.below(chars.len() + 1);
                    let letter = ALPHABET[rng.below(ALPHABET.len())];
                    chars.insert(at, letter);
                }
            }
            6 => {
                if !chars.is_empty() {
                    let at = rng.below(chars.len());
                    let letter = ALPHABET[rng.below(ALPHABET.len())];
                    chars[at] = letter;
                }
            }
            _ => {
                let letter = ALPHABET[rng.below(ALPHABET.len())];
                chars.push(letter);
            }
        }
        chars.into_iter().collect()
    }

    fn check(
        parser: &str,
        old: impl std::fmt::Debug,
        new: impl std::fmt::Debug,
        input: &str,
    ) -> bool {
        let old_repr = format!("{old:?}");
        let new_repr = format!("{new:?}");
        if old_repr == new_repr {
            true
        } else {
            panic!("DIVERGENCE in {parser} on input {input:?}: old {old_repr} new {new_repr}");
        }
    }

    const MUTATIONS: usize = 2000;

    fn old_unsafe_scanner_advance(
        bytes: &[u8],
        index: usize,
        line: &mut usize,
        column: &mut usize,
    ) -> usize {
        if bytes[index] == b'\n' {
            *line += 1;
            *column = 1;
        } else {
            *column += 1;
        }
        index + 1
    }

    fn old_scan_rust_source_text_for_unsafe(source: &str) -> Vec<(usize, usize)> {
        let bytes = source.as_bytes();
        let mut findings = Vec::new();

        let mut index = 0usize;
        let mut line = 1usize;
        let mut column = 1usize;
        let mut state = UnsafeScannerState::Normal;
        let mut block_depth = 0usize;
        let mut raw_hashes = 0usize;

        while index < bytes.len() {
            let byte = bytes[index];

            match state {
                UnsafeScannerState::Normal => {
                    if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::LineComment;
                        continue;
                    }

                    if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::BlockComment;
                        block_depth = 1;
                        continue;
                    }

                    if byte == b'"' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::String;
                        continue;
                    }

                    if byte == b'\'' {
                        if index + 1 < bytes.len()
                            && unsafe_scanner_is_ident_start(bytes[index + 1])
                        {
                            let is_char_literal =
                                index + 2 < bytes.len() && bytes[index + 2] == b'\'';
                            if !is_char_literal {
                                index = old_unsafe_scanner_advance(
                                    bytes,
                                    index,
                                    &mut line,
                                    &mut column,
                                );
                                while index < bytes.len()
                                    && unsafe_scanner_is_ident_continue(bytes[index])
                                {
                                    index = old_unsafe_scanner_advance(
                                        bytes,
                                        index,
                                        &mut line,
                                        &mut column,
                                    );
                                }
                                continue;
                            }
                        }
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::Char;
                        continue;
                    }

                    if byte == b'r' {
                        let mut candidate = index + 1;
                        let mut hashes = 0usize;
                        while candidate < bytes.len() && bytes[candidate] == b'#' {
                            candidate += 1;
                            hashes += 1;
                        }
                        if candidate < bytes.len() && bytes[candidate] == b'"' {
                            while index <= candidate {
                                index = old_unsafe_scanner_advance(
                                    bytes,
                                    index,
                                    &mut line,
                                    &mut column,
                                );
                            }
                            state = UnsafeScannerState::RawString;
                            raw_hashes = hashes;
                            continue;
                        }
                    }

                    if unsafe_scanner_is_ident_start(byte) {
                        let token_line = line;
                        let token_column = column;
                        let token_start = index;
                        while index < bytes.len() && unsafe_scanner_is_ident_continue(bytes[index])
                        {
                            index =
                                old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        }
                        if &bytes[token_start..index] == b"unsafe" {
                            findings.push((token_line, token_column));
                        }
                        continue;
                    }

                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
                UnsafeScannerState::LineComment => {
                    if byte == b'\n' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::Normal;
                        continue;
                    }
                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
                UnsafeScannerState::BlockComment => {
                    if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        block_depth += 1;
                        continue;
                    }
                    if byte == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        block_depth = block_depth.saturating_sub(1);
                        if block_depth == 0 {
                            state = UnsafeScannerState::Normal;
                        }
                        continue;
                    }
                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
                UnsafeScannerState::String => {
                    if byte == b'\\' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        if index < bytes.len() {
                            index =
                                old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        }
                        continue;
                    }
                    if byte == b'"' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::Normal;
                        continue;
                    }
                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
                UnsafeScannerState::Char => {
                    if byte == b'\\' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        if index < bytes.len() {
                            index =
                                old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        }
                        continue;
                    }
                    if byte == b'\'' {
                        index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                        state = UnsafeScannerState::Normal;
                        continue;
                    }
                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
                UnsafeScannerState::RawString => {
                    if byte == b'"' {
                        let suffix_start = index + 1;
                        let suffix_end = suffix_start + raw_hashes;
                        if suffix_end <= bytes.len()
                            && bytes[suffix_start..suffix_end]
                                .iter()
                                .all(|candidate| *candidate == b'#')
                        {
                            index =
                                old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                            for _ in 0..raw_hashes {
                                index = old_unsafe_scanner_advance(
                                    bytes,
                                    index,
                                    &mut line,
                                    &mut column,
                                );
                            }
                            state = UnsafeScannerState::Normal;
                            continue;
                        }
                    }
                    index = old_unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                }
            }
        }

        findings
    }

    fn old_is_raw_string_open(chars: &[char], r: usize) -> bool {
        if r > 0 {
            let prev = chars[r - 1];
            let in_identifier = prev.is_ascii_alphanumeric() || prev == '_';
            let prefix = (prev == 'b' || prev == 'c')
                && (r < 2 || !(chars[r - 2].is_ascii_alphanumeric() || chars[r - 2] == '_'));
            if in_identifier && !prefix {
                return false;
            }
        }
        match chars.get(r + 1) {
            Some('"') => true,
            Some('#') => {
                let mut probe = r + 1;
                while chars.get(probe) == Some(&'#') {
                    probe += 1;
                }
                probe > r + 1 && chars.get(probe) == Some(&'"')
            }
            _ => false,
        }
    }

    fn old_is_char_literal_open(chars: &[char], quote: usize) -> bool {
        match chars.get(quote + 1) {
            Some('\\') => {
                let mut probe = quote + 2;
                while probe < chars.len() {
                    if chars[probe] == '\\' {
                        probe += 2;
                        continue;
                    }
                    if chars[probe] == '\'' {
                        return true;
                    }
                    probe += 1;
                }
                false
            }
            Some(_) => chars.get(quote + 2) == Some(&'\''),
            None => false,
        }
    }

    fn old_strip_string_and_char_literal_contents(lines: &[&str]) -> Vec<String> {
        let mut stripped_lines = Vec::with_capacity(lines.len());
        let mut in_string = false;
        let mut in_raw_string: Option<usize> = None;
        for line in lines {
            let chars: Vec<char> = line.chars().collect();
            let mut stripped = String::with_capacity(line.len());
            let mut in_char = false;
            let mut index = 0;
            while index < chars.len() {
                if in_string {
                    match chars[index] {
                        '"' => {
                            in_string = false;
                            stripped.push('"');
                        }
                        '\\' => {
                            stripped.push(' ');
                            if index + 1 < chars.len() {
                                stripped.push(' ');
                                index += 1;
                            }
                        }
                        _ => stripped.push(' '),
                    }
                    index += 1;
                    continue;
                }
                if let Some(hashes) = in_raw_string {
                    if chars[index] == '"' {
                        let mut seen = 0;
                        while seen < hashes && chars.get(index + 1 + seen) == Some(&'#') {
                            seen += 1;
                        }
                        if seen == hashes {
                            in_raw_string = None;
                            stripped.push('"');
                            for _ in 0..hashes {
                                stripped.push('#');
                            }
                            index += 1 + hashes;
                        } else {
                            stripped.push(' ');
                            index += 1;
                        }
                    } else {
                        stripped.push(' ');
                        index += 1;
                    }
                    continue;
                }
                if in_char {
                    match chars[index] {
                        '\'' => {
                            in_char = false;
                            stripped.push('\'');
                        }
                        '\\' => {
                            stripped.push(' ');
                            if index + 1 < chars.len() {
                                stripped.push(' ');
                                index += 1;
                            }
                        }
                        _ => stripped.push(' '),
                    }
                    index += 1;
                    continue;
                }
                if chars[index] == '/' && chars.get(index + 1) == Some(&'/') {
                    stripped.extend(chars[index..].iter());
                    break;
                }
                match chars[index] {
                    '"' => {
                        in_string = true;
                        stripped.push('"');
                    }
                    '\'' if old_is_char_literal_open(&chars, index) => {
                        in_char = true;
                        stripped.push('\'');
                    }
                    'r' if old_is_raw_string_open(&chars, index) => {
                        let mut hashes = 0;
                        let mut probe = index + 1;
                        while chars.get(probe) == Some(&'#') {
                            hashes += 1;
                            probe += 1;
                        }
                        in_raw_string = Some(hashes);
                        stripped.push('r');
                        for _ in 0..hashes {
                            stripped.push('#');
                        }
                        stripped.push('"');
                        index = probe + 1;
                        continue;
                    }
                    other => stripped.push(other),
                }
                index += 1;
            }
            stripped_lines.push(stripped);
        }
        stripped_lines
    }

    fn old_unsafe_site_has_adjacent_safety_comment(lines: &[&str], site_index: usize) -> bool {
        let stripped = old_strip_string_and_char_literal_contents(lines);
        if stripped[site_index].contains("// SAFETY:") {
            return true;
        }
        let mut index = site_index;
        while index > 0 {
            index -= 1;
            match stripped[index].trim_start().strip_prefix("//") {
                Some(comment) => {
                    if comment.contains("SAFETY:") {
                        return true;
                    }
                }
                None => return false,
            }
        }
        false
    }

    fn old_toml_table_section<'a>(manifest: &'a str, header: &str) -> Option<&'a str> {
        let header_line = format!("[{header}]");
        let mut start: Option<usize> = None;
        let mut end = manifest.len();
        let mut offset = 0usize;
        for line in manifest.lines() {
            let trimmed = line.trim_start();
            if start.is_none() {
                if trimmed == header_line {
                    start = Some(offset);
                }
            } else if trimmed.starts_with('[') {
                end = offset;
                break;
            }
            offset += line.len() + 1;
        }
        let start = start?;
        Some(&manifest[start..end])
    }

    fn old_parse_utc_to_unix(value: &str, field: &str) -> Result<i64, String> {
        let trimmed = value.trim();
        if trimmed.is_empty() {
            return Err(format!("missing or invalid UTC field: {field}"));
        }

        let (datetime_part, offset_seconds) = if let Some(stripped) = trimmed.strip_suffix('Z') {
            (stripped, 0i64)
        } else {
            let tz_start = trimmed
                .char_indices()
                .rev()
                .find_map(|(index, ch)| (index > 10 && (ch == '+' || ch == '-')).then_some(index))
                .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
            let (base, zone) = trimmed.split_at(tz_start);
            if zone.len() != 6 || !zone.is_ascii() || &zone[3..4] != ":" {
                return Err(format!("invalid UTC timestamp for {field}: {value}"));
            }
            let sign = if &zone[0..1] == "+" { 1i64 } else { -1i64 };
            let offset_hour = parse_two_digits(&zone[1..3], field)?;
            let offset_minute = parse_two_digits(&zone[4..6], field)?;
            if offset_hour > 23 || offset_minute > 59 {
                return Err(format!("invalid UTC timestamp for {field}: {value}"));
            }
            let total = i64::from(offset_hour) * 3600 + i64::from(offset_minute) * 60;
            (base, sign * total)
        };

        let (date_part, time_part) = datetime_part
            .split_once('T')
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        let date_fields = date_part.split('-').collect::<Vec<_>>();
        if date_fields.len() != 3 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let year = parse_four_digits(date_fields[0], field)?;
        let month = parse_two_digits(date_fields[1], field)?;
        let day = parse_two_digits(date_fields[2], field)?;
        let max_day = days_in_month(year, month)
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        if day == 0 || day > max_day {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }

        let (time_core, fraction) = match time_part.split_once('.') {
            Some((core, frac)) => (core, Some(frac)),
            None => (time_part, None),
        };
        if let Some(frac) = fraction
            && (frac.is_empty() || !frac.chars().all(|ch| ch.is_ascii_digit()))
        {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let time_fields = time_core.split(':').collect::<Vec<_>>();
        if time_fields.len() != 3 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }
        let hour = parse_two_digits(time_fields[0], field)?;
        let minute = parse_two_digits(time_fields[1], field)?;
        let second = parse_two_digits(time_fields[2], field)?;
        if hour > 23 || minute > 59 || second > 59 {
            return Err(format!("invalid UTC timestamp for {field}: {value}"));
        }

        let date_seconds = days_from_civil(year, month, day)
            .checked_mul(86_400)
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        let time_seconds = i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second);
        date_seconds
            .checked_add(time_seconds)
            .and_then(|result| result.checked_sub(offset_seconds))
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))
    }

    fn old_keyword_has_word_boundaries(text: &str, start: usize, length: usize) -> bool {
        let bytes = text.as_bytes();
        let end = start + length;
        let starts_at_boundary = start == 0 || !is_word_char_byte(bytes[start - 1]);
        let ends_at_boundary = end >= bytes.len() || !is_word_char_byte(bytes[end]);
        starts_at_boundary && ends_at_boundary
    }

    fn scan_golden_sources() -> Vec<&'static str> {
        vec![
            "",
            "fn main() { unsafe { } }\n",
            "// unsafe in a comment\nlet a = \"unsafe in a string\";\n",
            "let s = r#\"unsafe inside raw\"#;\nlet t = r\"unsafe\";\n",
            "static X: &'static str = \"unsafe\";\n",
            "/* unsafe /* nested unsafe */ still */ unsafe fn f() {}\n",
            "fn c() { let ch = '\\''; let ch2 = '\\n'; }\nlet lifetime: &'a str = \"x\";\n",
            "br#\"unsafe byte raw\"# cr#\"c raw\"# r##\"deep\"## unsafe {}\n",
            "'r' 'unsafe_char' not_a_keyword unsafe\n",
            "let bytes = b\"unsafe\";\n",
        ]
    }

    #[test]
    fn scanner_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B01_0000_0000_0002);
        let mut checked = 0usize;
        for base in scan_golden_sources() {
            check(
                "scan_rust_source_text_for_unsafe GOLDEN",
                old_scan_rust_source_text_for_unsafe(base),
                scan_rust_source_text_for_unsafe(base),
                base,
            );
            checked += 1;
            for _ in 0..MUTATIONS {
                let candidate = mutate_string(base, &mut rng);
                let old = old_scan_rust_source_text_for_unsafe(candidate.as_str());
                let new = scan_rust_source_text_for_unsafe(candidate.as_str());
                check(
                    "scan_rust_source_text_for_unsafe",
                    old,
                    new,
                    candidate.as_str(),
                );
                checked += 1;
            }
        }
        assert!(checked >= 15_000, "mutation floor: only {checked}");
    }

    fn strip_golden_line_sets() -> Vec<Vec<&'static str>> {
        vec![
            vec!["// SAFETY: clean"],
            vec!["let s = \"// SAFETY:\";"],
            vec!["let s = \"unclosed", "next line // SAFETY:"],
            vec!["let ch = '//'; // SAFETY: real"],
            vec!["r#\"// SAFETY:\"#;"],
            vec!["let s = \"a\\\"b // SAFETY:\";"],
            vec!["normal line", "// SAFETY: above unsafe", "unsafe {}"],
            vec!["x", "", "   // SAFETY: indented"],
            vec!["let raw = r\"// SAFETY:\";"],
            vec!["let mut s = \"\\", "// SAFETY:"],
        ]
    }

    #[test]
    fn strip_and_literal_open_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B02_0000_0000_0003);
        let mut checked = 0usize;
        for base in strip_golden_line_sets() {
            check(
                "strip GOLDEN",
                old_strip_string_and_char_literal_contents(base.as_slice()),
                strip_string_and_char_literal_contents(base.as_slice()),
                base.join("\n").as_str(),
            );
            checked += 1;
            for _ in 0..MUTATIONS {
                let candidate: Vec<String> = base
                    .iter()
                    .map(|line| mutate_string(line, &mut rng))
                    .collect();
                let refs: Vec<&str> = candidate.iter().map(String::as_str).collect();
                let old = old_strip_string_and_char_literal_contents(refs.as_slice());
                let new = strip_string_and_char_literal_contents(refs.as_slice());
                assert_eq!(old, new, "DIVERGENCE in strip on input {candidate:?}");
                checked += 1;
            }
        }

        // literal-open predicates over mutated char vectors
        let opens_bases: Vec<Vec<char>> = scan_golden_sources()
            .iter()
            .map(|source| source.chars().collect())
            .collect();
        for base in opens_bases {
            for _ in 0..MUTATIONS / 4 {
                let joined: String = base.iter().collect();
                let candidate = mutate_string(joined.as_str(), &mut rng);
                let chars: Vec<char> = candidate.chars().collect();
                if chars.is_empty() {
                    continue;
                }
                for pos in [0usize, 1, chars.len() / 2, chars.len() - 1, chars.len()] {
                    let old = old_is_raw_string_open(chars.as_slice(), pos);
                    let new = is_raw_string_open(chars.as_slice(), pos);
                    assert_eq!(
                        old, new,
                        "DIVERGENCE in is_raw_string_open at {pos} on {candidate:?}"
                    );
                    let old = old_is_char_literal_open(chars.as_slice(), pos);
                    let new = is_char_literal_open(chars.as_slice(), pos);
                    assert_eq!(
                        old, new,
                        "DIVERGENCE in is_char_literal_open at {pos} on {candidate:?}"
                    );
                    checked += 6;
                }
            }
        }
        assert!(checked >= 15_000, "mutation floor: only {checked}");
    }

    #[test]
    fn adjacent_safety_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B03_0000_0000_0004);
        let mut checked = 0usize;
        for base in strip_golden_line_sets() {
            let max_index = base.len() - 1;
            check(
                "adjacent_safety GOLDEN",
                old_unsafe_site_has_adjacent_safety_comment(base.as_slice(), max_index),
                unsafe_site_has_adjacent_safety_comment(base.as_slice(), max_index),
                base.join("\n").as_str(),
            );
            checked += 1;
            for _ in 0..MUTATIONS {
                let candidate: Vec<String> = base
                    .iter()
                    .map(|line| mutate_string(line, &mut rng))
                    .collect();
                if candidate.is_empty() {
                    continue;
                }
                let refs: Vec<&str> = candidate.iter().map(String::as_str).collect();
                // old panics on out-of-range site indices; stay inside its domain
                let site = rng.below(refs.len());
                let old = old_unsafe_site_has_adjacent_safety_comment(refs.as_slice(), site);
                let new = unsafe_site_has_adjacent_safety_comment(refs.as_slice(), site);
                assert_eq!(
                    old, new,
                    "DIVERGENCE in adjacent_safety at site {site} on {candidate:?}"
                );
                checked += 1;
            }
        }
        // fail-closed witness: out-of-range site index no longer panics
        let lines = ["let x = 1;", "// SAFETY:"];
        assert!(!unsafe_site_has_adjacent_safety_comment(
            lines.as_slice(),
            2
        ));
        assert!(!unsafe_site_has_adjacent_safety_comment(
            lines.as_slice(),
            500
        ));
        assert!(checked >= 15_000, "mutation floor: only {checked}");
    }

    fn toml_golden_manifests() -> Vec<&'static str> {
        vec![
            "[workspace]\nmembers = [\n  \"crates/a\",\n  \"crates/b\",\n]\n\n[workspace.lints.rust]\nunsafe_code = \"forbid\"\n",
            "[workspace]\r\nmembers = [\"a\"]\r\n[workspace.lints.rust]\r\nunsafe_code = \"forbid\"\r\n",
            "[workspace.lints.rust]\nunsafe_code = \"deny\"\n",
            "no tables here",
            "[workspace]",
            "[workspace]\nmembers = []\n[workspace]\nmembers = [\"second\"]\n",
            "\n\n[workspace.lints.rust]\n",
        ]
    }

    #[test]
    fn toml_table_section_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B04_0000_0000_0005);
        let headers = ["workspace", "workspace.lints.rust", "missing"];
        let mut checked = 0usize;
        for base in toml_golden_manifests() {
            for header in headers {
                check(
                    "toml_table_section GOLDEN",
                    old_toml_table_section(base, header).map(str::to_owned),
                    toml_table_section(base, header).map(str::to_owned),
                    &format!("{header} in {base:?}"),
                );
                checked += 1;
            }
            for _ in 0..MUTATIONS {
                let candidate = mutate_string(base, &mut rng);
                for header in headers {
                    let old = old_toml_table_section(candidate.as_str(), header).map(str::to_owned);
                    let new = toml_table_section(candidate.as_str(), header).map(str::to_owned);
                    assert_eq!(
                        old, new,
                        "DIVERGENCE in toml_table_section header {header} on {candidate:?}"
                    );
                    checked += 1;
                }
            }
        }
        assert!(checked >= 15_000, "mutation floor: only {checked}");
    }

    fn utc_golden_stamps() -> Vec<&'static str> {
        vec![
            "2026-04-08T10:00:00Z",
            "2026-04-08T10:00:00+05:30",
            "2026-04-08T10:00:00-08:00",
            "2026-02-29T23:59:59Z",
            "2026-04-08T10:00:00.123456Z",
            "2026-04-08T10:00:00.5-00:00",
            "  2026-04-08T10:00:00Z  ",
            "",
            "garbage",
            "2026-13-45T99:99:99Z",
            "2026-04-08T10:00:00+99:99",
            "значение-2026-04-08T10:00:00+05:30",
        ]
    }

    #[test]
    fn parse_utc_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B05_0000_0000_0006);
        let mut checked = 0usize;
        for base in utc_golden_stamps() {
            check(
                "parse_utc_to_unix GOLDEN",
                old_parse_utc_to_unix(base, "clock"),
                parse_utc_to_unix(base, "clock"),
                base,
            );
            checked += 1;
            for _ in 0..MUTATIONS {
                let candidate = mutate_string(base, &mut rng);
                let old = old_parse_utc_to_unix(candidate.as_str(), "clock");
                let new = parse_utc_to_unix(candidate.as_str(), "clock");
                check("parse_utc_to_unix", old, new, candidate.as_str());
                checked += 1;
            }
        }
        assert!(checked >= 20_000, "mutation floor: only {checked}");
    }

    #[test]
    fn keyword_boundaries_old_equals_new_over_mutations() {
        let mut rng = Rng(0x6B06_0000_0000_0007);
        let bases = [
            "password = hunter2",
            "api_key=\"abc\" api-key: xyz",
            "токен passphrase here",
            "",
            "a",
            "__password__",
        ];
        let mut checked = 0usize;
        for base in bases {
            let len = base.len();
            for start in 0..=len {
                for length in [0usize, 1, 8, 20] {
                    let old = old_keyword_has_word_boundaries(base, start, length);
                    let new = keyword_has_word_boundaries(base, start, length);
                    check(
                        "keyword_has_word_boundaries GOLDEN",
                        old,
                        new,
                        &format!("{base} @{start}+{length}"),
                    );
                    checked += 1;
                }
            }
            for _ in 0..MUTATIONS / 8 {
                let candidate = mutate_string(base, &mut rng);
                let clen = candidate.len();
                let start = rng.below(clen + 1);
                let length = rng.below(clen + 3);
                let old = old_keyword_has_word_boundaries(candidate.as_str(), start, length);
                let new = keyword_has_word_boundaries(candidate.as_str(), start, length);
                check("keyword_has_word_boundaries", old, new, candidate.as_str());
                checked += 1;
            }
        }
        assert!(checked >= 1600, "mutation floor: only {checked}");
    }
}
