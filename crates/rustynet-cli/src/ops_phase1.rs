#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

const DEFAULT_PHASE1_SOURCE_NDJSON_PATH: &str =
    "artifacts/perf/phase1/source/performance_samples.ndjson";
const DEFAULT_PHASE1_FALLBACK_SOURCE_NDJSON_PATH: &str =
    "artifacts/operations/source/performance_samples.ndjson";
const DEFAULT_PHASE1_OPERATIONS_PERF_REPORT_PATH: &str =
    "artifacts/operations/performance_budget_report.json";
const DEFAULT_PHASE1_PHASE10_PERF_REPORT_PATH: &str = "artifacts/phase10/perf_budget_report.json";
const DEFAULT_PHASE1_OPERATIONS_RAW_PERF_REPORT_PATH: &str =
    "artifacts/operations/raw/performance_budget_report.json";
const DEFAULT_PHASE1_MEASURED_INPUT_PATH: &str = "artifacts/perf/phase1/measured_input.json";
const DEFAULT_PHASE1_RUNTIME_REPORT_PATH: &str = "artifacts/perf/phase1/baseline.json";
const DEFAULT_PHASE1_BACKEND_REPORT_PATH: &str = "artifacts/perf/phase1/backend_contract_perf.json";

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

fn phase1_validate_secure_directory(path: &Path, label: &str) -> Result<(), String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|err| format!("inspect {label} failed ({}): {err}", path.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink: {}", path.display()));
    }
    if !metadata.file_type().is_dir() {
        return Err(format!("{label} must be a directory: {}", path.display()));
    }
    phase1_validate_non_writable_by_group_or_world(path, &metadata, label)?;
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
    phase1_validate_non_writable_by_group_or_world(path, &metadata, "phase1 metrics source file")?;
    Ok(())
}

fn resolve_phase1_measured_source_path() -> Result<PathBuf, String> {
    if let Some(configured_path) = env_optional_string("RUSTYNET_PHASE1_PERF_SAMPLES_PATH")? {
        let resolved = phase1_resolve_path(configured_path.as_str())?;
        phase1_validate_source_path(resolved.as_path())?;
        return Ok(resolved);
    }

    for candidate in [
        DEFAULT_PHASE1_SOURCE_NDJSON_PATH,
        DEFAULT_PHASE1_FALLBACK_SOURCE_NDJSON_PATH,
        DEFAULT_PHASE1_OPERATIONS_PERF_REPORT_PATH,
        DEFAULT_PHASE1_PHASE10_PERF_REPORT_PATH,
        DEFAULT_PHASE1_OPERATIONS_RAW_PERF_REPORT_PATH,
    ] {
        let resolved = phase1_resolve_path(candidate)?;
        if phase1_validate_source_path(resolved.as_path()).is_ok() {
            return Ok(resolved);
        }
    }

    Err(format!(
        "missing measured source file for phase1 metrics collector\nset RUSTYNET_PHASE1_PERF_SAMPLES_PATH or provide one of:\n  - {DEFAULT_PHASE1_SOURCE_NDJSON_PATH}\n  - {DEFAULT_PHASE1_FALLBACK_SOURCE_NDJSON_PATH}\n  - {DEFAULT_PHASE1_OPERATIONS_PERF_REPORT_PATH}\n  - {DEFAULT_PHASE1_PHASE10_PERF_REPORT_PATH}\n  - {DEFAULT_PHASE1_OPERATIONS_RAW_PERF_REPORT_PATH}"
    ))
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
        phase1_validate_non_writable_by_group_or_world(
            output_path,
            &metadata,
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
        parse_bool_value, phase1_collect_measured_input_from_source, phase1_validate_report,
        phase1_validate_secure_directory,
    };
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn parse_bool_value_matches_systemd_script_contract() {
        assert!(parse_bool_value("TEST_BOOL", "true").expect("true should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "off").expect("off should parse"));
        assert!(!parse_bool_value("TEST_BOOL", "").expect("empty should parse"));
        assert!(parse_bool_value("TEST_BOOL", "bogus").is_err());
    }

    #[test]
    fn phase1_collector_derives_max_metrics_from_ndjson() {
        let source_path = std::env::temp_dir().join(format!(
            "rustynet-phase1-collector-{}.ndjson",
            std::process::id()
        ));
        let body = concat!(
            "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n",
            "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.6,\"idle_memory_mb\":96,\"reconnect_seconds\":2.1,\"route_apply_p95_seconds\":1.4,\"throughput_overhead_percent\":12.3}\n"
        );
        std::fs::write(&source_path, body).expect("write ndjson source");

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
        let source_path =
            std::env::temp_dir().join(format!("rustynet-phase1-unmeasured-{}", std::process::id()));
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

        let err = phase1_collect_measured_input_from_source(&source_path)
            .expect_err("collector should reject non-measured evidence");
        assert!(err.contains("not measured evidence"));

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_collector_rejects_non_measured_ndjson_entry() {
        let source_path = std::env::temp_dir().join(format!(
            "rustynet-phase1-ndjson-unmeasured-{}.ndjson",
            std::process::id()
        ));
        let body = "{\"evidence_mode\":\"synthetic\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n";
        std::fs::write(&source_path, body).expect("write ndjson source");

        let err = phase1_collect_measured_input_from_source(&source_path)
            .expect_err("collector should reject non-measured ndjson evidence");
        assert!(err.contains("not measured evidence"));

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_collector_rejects_group_writable_source_file() {
        let source_path = std::env::temp_dir().join(format!(
            "rustynet-phase1-insecure-perms-{}.ndjson",
            std::process::id()
        ));
        let body = "{\"evidence_mode\":\"measured\",\"idle_cpu_percent\":1.2,\"idle_memory_mb\":80,\"reconnect_seconds\":1.5,\"route_apply_p95_seconds\":0.8,\"throughput_overhead_percent\":10.0}\n";
        std::fs::write(&source_path, body).expect("write ndjson source");
        let mut perms = std::fs::metadata(&source_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o664);
        std::fs::set_permissions(&source_path, perms).expect("set insecure mode");

        let err = phase1_collect_measured_input_from_source(&source_path)
            .expect_err("collector should reject group writable source");
        assert!(err.contains("must not be group/world writable"));

        let _ = std::fs::remove_file(source_path);
    }

    #[test]
    fn phase1_secure_directory_rejects_group_writable_directory() {
        let dir_path =
            std::env::temp_dir().join(format!("rustynet-phase1-dir-perms-{}", std::process::id()));
        std::fs::create_dir_all(&dir_path).expect("create temp directory");
        let mut perms = std::fs::metadata(&dir_path)
            .expect("metadata")
            .permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&dir_path, perms).expect("set insecure mode");

        let err = phase1_validate_secure_directory(&dir_path, "test phase1 output directory")
            .expect_err("directory with open write bits must be rejected");
        assert!(err.contains("must not be group/world writable"));

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
}
