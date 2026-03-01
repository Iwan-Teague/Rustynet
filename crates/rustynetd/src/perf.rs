#![forbid(unsafe_code)]

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct MetricRow {
    pub name: &'static str,
    pub value: f64,
    pub unit: &'static str,
    pub threshold: &'static str,
    pub status: &'static str,
    pub reason: &'static str,
}

fn metric_from_env(
    name: &'static str,
    env_key: &'static str,
    unit: &'static str,
    threshold: &'static str,
    threshold_max: f64,
) -> MetricRow {
    match std::env::var(env_key) {
        Ok(raw) => match raw.parse::<f64>() {
            Ok(value) if value.is_finite() && value >= 0.0 => MetricRow {
                name,
                value,
                unit,
                threshold,
                status: if value <= threshold_max {
                    "pass"
                } else {
                    "fail"
                },
                reason: "measured",
            },
            _ => MetricRow {
                name,
                value: 0.0,
                unit,
                threshold,
                status: "fail",
                reason: "measurement_invalid",
            },
        },
        Err(_) => MetricRow {
            name,
            value: 0.0,
            unit,
            threshold,
            status: "fail",
            reason: "measurement_unavailable",
        },
    }
}

pub fn phase1_baseline_metrics() -> [MetricRow; 5] {
    [
        metric_from_env(
            "idle_cpu_percent",
            "RUSTYNET_PHASE1_IDLE_CPU_PERCENT",
            "percent_of_one_core",
            "<=2",
            2.0,
        ),
        metric_from_env(
            "idle_memory_mb",
            "RUSTYNET_PHASE1_IDLE_MEMORY_MB",
            "mb_rss",
            "<=120",
            120.0,
        ),
        metric_from_env(
            "reconnect_seconds",
            "RUSTYNET_PHASE1_RECONNECT_SECONDS",
            "seconds",
            "<=5",
            5.0,
        ),
        metric_from_env(
            "route_policy_apply_p95_seconds",
            "RUSTYNET_PHASE1_ROUTE_POLICY_APPLY_P95_SECONDS",
            "seconds",
            "<=2",
            2.0,
        ),
        metric_from_env(
            "throughput_overhead_vs_wireguard_percent",
            "RUSTYNET_PHASE1_THROUGHPUT_OVERHEAD_PERCENT",
            "percent",
            "<=15",
            15.0,
        ),
    ]
}

fn metrics_to_json(metrics: &[MetricRow]) -> String {
    let mut out = String::from(
        "{\n  \"phase\": \"phase1\",\n  \"suite\": \"runtime_baseline\",\n  \"metrics\": [\n",
    );

    for (index, metric) in metrics.iter().enumerate() {
        let comma = if index + 1 == metrics.len() { "" } else { "," };
        out.push_str(&format!(
            "    {{\"name\":\"{}\",\"value\":{},\"unit\":\"{}\",\"threshold\":\"{}\",\"status\":\"{}\",\"reason\":\"{}\"}}{}\n",
            metric.name, metric.value, metric.unit, metric.threshold, metric.status, metric.reason, comma
        ));
    }

    out.push_str("  ]\n}\n");
    out
}

pub fn write_phase1_baseline_report(path: impl AsRef<Path>) -> Result<(), String> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| format!("create_dir_all failed: {err}"))?;
    }

    let metrics = phase1_baseline_metrics();
    let json = metrics_to_json(&metrics);
    fs::write(path, json).map_err(|err| format!("write baseline report failed: {err}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{phase1_baseline_metrics, write_phase1_baseline_report};

    #[test]
    fn metrics_include_required_phase1_names() {
        let metrics = phase1_baseline_metrics();
        let names: Vec<&str> = metrics.iter().map(|metric| metric.name).collect();

        assert!(names.contains(&"idle_cpu_percent"));
        assert!(names.contains(&"idle_memory_mb"));
        assert!(names.contains(&"reconnect_seconds"));
        assert!(names.contains(&"route_policy_apply_p95_seconds"));
        assert!(names.contains(&"throughput_overhead_vs_wireguard_percent"));
    }

    #[test]
    fn baseline_report_is_writable() {
        let temp_dir = std::env::temp_dir();
        let report_path = temp_dir.join("rustynet-phase1-runtime-baseline.json");
        write_phase1_baseline_report(&report_path).expect("report should be written");
        let content =
            std::fs::read_to_string(&report_path).expect("report content should be readable");
        assert!(content.contains("\"metrics\""));
    }
}
