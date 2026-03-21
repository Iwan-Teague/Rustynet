#![forbid(unsafe_code)]

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
                .ok_or_else(|| "missing idle_cpu_percent metric".to_string())?,
            idle_memory_mb: self
                .idle_memory_mb
                .ok_or_else(|| "missing idle_memory_mb metric".to_string())?,
            reconnect_seconds: self
                .reconnect_seconds
                .ok_or_else(|| "missing reconnect_seconds metric".to_string())?,
            route_policy_apply_p95_seconds: self
                .route_policy_apply_p95_seconds
                .ok_or_else(|| "missing route_policy_apply_p95_seconds metric".to_string())?,
            throughput_overhead_percent: self
                .throughput_overhead_percent
                .ok_or_else(|| "missing throughput_overhead_percent metric".to_string())?,
            backend_throughput_overhead_percent: self
                .backend_throughput_overhead_percent
                .ok_or_else(|| "missing backend_throughput_overhead_percent metric".to_string())?,
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
        return Err("path must not be empty".to_string());
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
    let raw = env_optional_string(key)?.unwrap_or_else(|| default.to_string());
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
    let value = env_optional_string(key)?.unwrap_or_else(|| default.to_string());
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
             expected canonical source (default): artifacts/perf/phase1/source/performance_samples.ndjson"
                .to_string()
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
            flattened.insert(name.to_string(), json!(value));
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
                flattened.insert(key.to_string(), json!(value));
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
        missing_env.push(key.to_string());
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
            .ok_or_else(|| "missing RUSTYNET_PHASE1_IDLE_CPU_PERCENT".to_string())?,
        idle_memory_mb: idle_memory_mb
            .ok_or_else(|| "missing RUSTYNET_PHASE1_IDLE_MEMORY_MB".to_string())?,
        reconnect_seconds: reconnect_seconds
            .ok_or_else(|| "missing RUSTYNET_PHASE1_RECONNECT_SECONDS".to_string())?,
        route_policy_apply_p95_seconds: route_policy_apply_p95_seconds
            .ok_or_else(|| "missing RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS".to_string())?,
        throughput_overhead_percent: throughput_overhead_percent
            .ok_or_else(|| "missing RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT".to_string())?,
        backend_throughput_overhead_percent: backend_throughput_overhead_percent.ok_or_else(
            || "missing RUSTYNET_PHASE1_BACKEND_THROUGHPUT_OVERHEAD_PERCENT".to_string(),
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
    let payload_object = payload.as_object().ok_or_else(|| {
        format!(
            "{report_label} must be a JSON object: {}",
            report_path.display()
        )
    })?;
    let metrics = payload_object
        .get("metrics")
        .and_then(Value::as_array)
        .ok_or_else(|| {
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
        let metric_object = metric.as_object().ok_or_else(|| {
            format!(
                "{report_label} metric entry is not an object: {}",
                report_path.display()
            )
        })?;
        let name = metric_object
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                format!(
                    "{report_label} metric entry missing name: {}",
                    report_path.display()
                )
            })?;
        let metric_value = metric_object
            .get("value")
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
        let status = metric_object
            .get("status")
            .and_then(Value::as_str)
            .ok_or_else(|| {
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
        if metric_object
            .get("reason")
            .and_then(Value::as_str)
            .is_some_and(|reason| {
                reason == "measurement_unavailable" || reason == "measurement_invalid"
            })
        {
            return Err(format!(
                "{report_label} contains unavailable/invalid measurement for metric '{name}': {}",
                report_path.display()
            ));
        }
        present_metrics.insert(name.to_string(), true);
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
    if bytes[index] == b'\n' {
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

    while index < bytes.len() {
        let byte = bytes[index];

        match state {
            UnsafeScannerState::Normal => {
                if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    state = UnsafeScannerState::LineComment;
                    continue;
                }

                if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
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
                    if index + 1 < bytes.len() && unsafe_scanner_is_ident_start(bytes[index + 1]) {
                        let is_char_literal = index + 2 < bytes.len() && bytes[index + 2] == b'\'';
                        if !is_char_literal {
                            index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                            while index < bytes.len()
                                && unsafe_scanner_is_ident_continue(bytes[index])
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
                    while candidate < bytes.len() && bytes[candidate] == b'#' {
                        candidate += 1;
                        hashes += 1;
                    }
                    if candidate < bytes.len() && bytes[candidate] == b'"' {
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
                    while index < bytes.len() && unsafe_scanner_is_ident_continue(bytes[index]) {
                        index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    }
                    if &bytes[token_start..index] == b"unsafe" {
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
                if byte == b'/' && index + 1 < bytes.len() && bytes[index + 1] == b'*' {
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    index = unsafe_scanner_advance(bytes, index, &mut line, &mut column);
                    block_depth += 1;
                    continue;
                }
                if byte == b'*' && index + 1 < bytes.len() && bytes[index + 1] == b'/' {
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
                        && bytes[suffix_start..suffix_end]
                            .iter()
                            .all(|candidate| *candidate == b'#')
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
        entries.sort_by_key(|entry| entry.path());

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

pub fn execute_ops_check_no_unsafe_rust_sources(
    config: CheckNoUnsafeRustSourcesConfig,
) -> Result<String, String> {
    run_unsafe_scanner_self_tests()?;

    let root = phase1_resolve_path(config.root.to_string_lossy().as_ref())?;
    let rust_sources = collect_rust_source_paths(root.as_path())?;
    let mut findings = Vec::new();

    for source_path in rust_sources {
        let source = fs::read_to_string(&source_path)
            .map_err(|err| format!("read Rust source failed ({}): {err}", source_path.display()))?;
        for (line, column) in scan_rust_source_text_for_unsafe(source.as_str()) {
            findings.push(format!(
                "{}:{line}:{column}: unsafe keyword detected",
                source_path.display()
            ));
        }
    }

    if !findings.is_empty() {
        return Err(format!(
            "unsafe keyword usage is forbidden in repository Rust sources:\n{}",
            findings.join("\n")
        ));
    }

    Ok("Unsafe code checks: PASS".to_string())
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
            .find_map(|(index, ch)| {
                if index > 10 && (ch == '+' || ch == '-') {
                    Some(index)
                } else {
                    None
                }
            })
            .ok_or_else(|| format!("invalid UTC timestamp for {field}: {value}"))?;
        let (base, zone) = trimmed.split_at(tz_start);
        if zone.len() != 6 || &zone[3..4] != ":" {
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
            .ok_or_else(|| "dependency exception entry must be a JSON object".to_string())?;
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

    Ok("Dependency exception policy check: PASS".to_string())
}

fn load_perf_metrics(path: &Path, label: &str) -> Result<HashMap<String, f64>, String> {
    let payload = read_json_value(path, label)?;
    let payload_object = payload
        .as_object()
        .ok_or_else(|| format!("{label} must be a JSON object: {}", path.display()))?;
    let metrics = payload_object
        .get("metrics")
        .and_then(Value::as_array)
        .ok_or_else(|| {
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
        let metric_object = metric
            .as_object()
            .ok_or_else(|| format!("{label} metric entry must be object: {}", path.display()))?;
        let metric_name = metric_object
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .ok_or_else(|| format!("{label} metric missing non-empty name: {}", path.display()))?;
        let metric_value = metric_object
            .get("value")
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
                metric_object.get("value").cloned().unwrap_or(Value::Null)
            ));
        }
        if metric_object
            .get("status")
            .and_then(Value::as_str)
            .is_some_and(|status| status == "fail" || status == "not_measurable")
        {
            let status = metric_object
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("unknown");
            return Err(format!(
                "{label} metric '{metric_name}' has failing status: {status}"
            ));
        }
        values.insert(metric_name.to_string(), metric_value);
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

    Ok("Performance regression gate: PASS".to_string())
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
            .map_err(|_| "git ls-files emitted non-utf8 path".to_string())?;
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
        entries.sort_by_key(|entry| entry.path());

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
    let starts_at_boundary = start == 0 || !is_word_char_byte(bytes[start - 1]);
    let ends_at_boundary = end >= bytes.len() || !is_word_char_byte(bytes[end]);
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
                    let mut value = line[delimiter_index + 1..].trim_start();
                    if value.starts_with('"') || value.starts_with('\'') {
                        value = &value[1..];
                    }
                    let token = value
                        .chars()
                        .take_while(|candidate| is_secret_value_char(*candidate))
                        .collect::<String>();
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
    Some(variable.to_string())
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
            if line.contains("rm -f") && sensitive_names.iter().any(|name| line.contains(name)) {
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

    Ok("Secrets hygiene gate: PASS".to_string())
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
                .ok_or_else(|| "phase1 metrics env parse produced no values".to_string())?,
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
mod tests {
    use super::{
        CheckDependencyExceptionsConfig, CheckPerfRegressionConfig,
        execute_ops_check_dependency_exceptions, execute_ops_check_perf_regression,
        extract_bearer_excerpt, extract_secret_assignment_excerpt,
        line_contains_forbidden_inline_passphrase_flag, parse_bool_value,
        parse_mktemp_secret_variable, parse_utc_to_unix, phase1_collect_measured_input_from_source,
        phase1_validate_report, phase1_validate_secure_directory, scan_rust_source_text_for_unsafe,
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
        std::env::temp_dir().join(format!("{prefix}-{now_nanos}-{counter}{suffix}"))
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
            Some("signing_secret_tmp".to_string())
        );
        assert_eq!(parse_mktemp_secret_variable("tmp=$(mktemp)"), None);
    }
}
