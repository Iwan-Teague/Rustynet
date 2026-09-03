#![allow(dead_code)]
use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Machine-readable JSON output produced at the end of a live-lab run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveLabRunReport {
    pub run_id: String,
    pub timestamp_utc: String,
    pub overall_status: RunStatus,
    pub stages: Vec<StageReport>,
    pub node_statuses: HashMap<String, NodeStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Passed,
    Failed,
    Partial,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StageReport {
    pub stage_id: String,
    pub stage_name: String,
    pub outcome: StageOutcomeRecord,
    pub duration_ms: u64,
    pub error_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcomeRecord {
    Passed,
    Failed,
    Skipped,
    /// A required observation was missing or unattributable — a blocking
    /// non-pass, kept distinct from `Skipped` so an evidence gap can never be
    /// read as a legitimate profile omission. Serializes as `not_proven`.
    NotProven,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStatus {
    pub alias: String,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub node_id: String,
    pub platform: String,
    pub role: String,
    pub validator_results: Vec<ValidatorResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorResult {
    pub op: String,
    pub passed: bool,
    pub summary: String,
    /// The daemon's validator report, embedded VERBATIM (no re-shaping) —
    /// design §5.2 Item 2. `None` when the op errored before a report could
    /// be parsed (connection failure, cancelled, no adapter).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<serde_json::Value>,
}
