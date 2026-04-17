#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::security_audit_catalog::{
    ValidationSpec as LiveValidationSpec,
    sorted_validation_specs as catalog_sorted_validation_specs,
    validation_spec_by_key as catalog_validation_spec_by_key,
    validation_spec_by_mode as catalog_validation_spec_by_mode,
};

const CHECK_PASS: &str = "pass";
const CHECK_FAIL: &str = "fail";
const CHECK_SKIP: &str = "skip";
const CHECK_SKIPPED: &str = "skipped";
const EVIDENCE_MODE_MEASURED: &str = "measured";
const STATUS_PASS: &str = "pass";
const STATUS_FAIL: &str = "fail";
const DEFAULT_ATTACK_MATRIX_FORMAT: &str = "md";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAttackMatrixConfig {
    pub attacks: String,
    pub nodes: String,
    pub output: PathBuf,
    pub format: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerateAssessmentFromMatrixConfig {
    pub project: String,
    pub matrix_json: PathBuf,
    pub output: PathBuf,
    pub topology: Option<String>,
    pub authorization: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidateLiveLabReportsConfig {
    pub reports: Vec<PathBuf>,
    pub report_dir: Option<PathBuf>,
    pub output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvaluateLiveCoveragePromotionConfig {
    pub reports: Vec<PathBuf>,
    pub report_dir: Option<PathBuf>,
    pub targets: String,
    pub output: PathBuf,
}

#[derive(Clone, Copy)]
struct AttackSpec {
    key: &'static str,
    title: &'static str,
    hypothesis: &'static str,
    expected: &'static str,
}

const ATTACK_SPECS: &[AttackSpec] = &[
    AttackSpec {
        key: "control-plane-replay",
        title: "Control-Plane Replay And Rollback",
        hypothesis: "Stale or tampered signed artifacts must be rejected without widening runtime state.",
        expected: "Reject artifact and preserve secure state or fail closed.",
    },
    AttackSpec {
        key: "local-socket-spoofing",
        title: "Local Control Surface Spoofing",
        hypothesis: "Clients must reject insecure or attacker-owned local control surfaces before connecting.",
        expected: "Reject path based on ownership, symlink, or mode checks.",
    },
    AttackSpec {
        key: "host-trust-downgrade",
        title: "Host Trust Downgrade",
        hypothesis: "Automation must not silently trust changed host identity.",
        expected: "Host-key verification fails closed.",
    },
    AttackSpec {
        key: "route-hijack",
        title: "Route Or Exit Hijack",
        hypothesis: "Unauthorized route or exit state must not widen the data path.",
        expected: "Reject unauthorized path change and keep routing constrained.",
    },
    AttackSpec {
        key: "dns-integrity",
        title: "DNS Integrity And Namespace Abuse",
        hypothesis: "Managed DNS must reject stale, mismatched, or unauthorized name-to-node mappings.",
        expected: "Managed names fail closed and non-managed names are refused.",
    },
    AttackSpec {
        key: "traversal-abuse",
        title: "Traversal Hint Or Relay Abuse",
        hypothesis: "Direct or relay path decisions must require current verified evidence.",
        expected: "Reject stale hints and promote only with fresh evidence.",
    },
    AttackSpec {
        key: "secret-custody",
        title: "Secret Custody And Log Leakage",
        hypothesis: "Secrets must not leak through files, temp paths, argv, or logs.",
        expected: "No plaintext leakage; secure custody and cleanup only.",
    },
    AttackSpec {
        key: "missing-state-fail-closed",
        title: "Missing-State Fail-Closed Validation",
        hypothesis: "Removing required trust inputs must make the system restrictive, not permissive.",
        expected: "Operation fails closed with explicit error.",
    },
    AttackSpec {
        key: "helper-input-abuse",
        title: "Privileged Helper Input Abuse",
        hypothesis: "Malformed helper requests must be rejected before privileged execution.",
        expected: "Deterministic parser rejection without shell execution.",
    },
    AttackSpec {
        key: "release-evidence-integrity",
        title: "Release Evidence Integrity",
        hypothesis: "Release evidence must bind to the exact source state and portable artifact paths.",
        expected: "Mismatched or stale evidence is rejected.",
    },
];

#[derive(Clone)]
struct LoadedReportRecord {
    path: PathBuf,
    payload: Value,
}

#[derive(Clone)]
struct AttackRow {
    attack_key: String,
    attack_family: String,
    primary_nodes: String,
    hypothesis: String,
    expected_secure_behavior: String,
    result: String,
    evidence: String,
}

#[derive(Debug, Clone)]
struct NodeSpec {
    label: String,
    role: String,
}

pub fn default_attack_matrix_format() -> &'static str {
    DEFAULT_ATTACK_MATRIX_FORMAT
}

pub fn execute_ops_generate_attack_matrix(
    config: GenerateAttackMatrixConfig,
) -> Result<String, String> {
    let attacks = parse_attacks(config.attacks.as_str())?;
    let nodes = parse_nodes(config.nodes.as_str())?;
    let rows = build_attack_rows(&attacks, &nodes)?;
    let output_path = resolve_path(config.output.as_path())?;
    ensure_parent_dir(output_path.as_path())?;
    match config.format.as_str() {
        "json" => {
            let payload = json!({
                "nodes": nodes.iter().map(|node| json!({
                    "label": node.label,
                    "role": node.role,
                })).collect::<Vec<_>>(),
                "attacks": rows.iter().map(|row| json!({
                    "attack_key": row.attack_key,
                    "attack_family": row.attack_family,
                    "primary_nodes": row.primary_nodes,
                    "hypothesis": row.hypothesis,
                    "expected_secure_behavior": row.expected_secure_behavior,
                    "result": row.result,
                    "evidence": row.evidence,
                })).collect::<Vec<_>>(),
            });
            fs::write(
                output_path.as_path(),
                serde_json::to_string_pretty(&payload)
                    .map_err(|err| format!("encode attack matrix json failed: {err}"))?
                    + "\n",
            )
            .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
        }
        "md" => {
            fs::write(
                output_path.as_path(),
                render_attack_matrix_markdown(&rows, &nodes),
            )
            .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
        }
        other => {
            return Err(format!(
                "invalid --format value {other:?}; expected md or json"
            ));
        }
    }
    Ok(format!("wrote attack matrix {}", output_path.display()))
}

pub fn execute_ops_generate_assessment_from_matrix(
    config: GenerateAssessmentFromMatrixConfig,
) -> Result<String, String> {
    let matrix_path = resolve_path(config.matrix_json.as_path())?;
    let matrix = load_matrix_payload(matrix_path.as_path())?;
    let output_path = resolve_path(config.output.as_path())?;
    ensure_parent_dir(output_path.as_path())?;
    let topology = config.topology.unwrap_or_else(|| {
        matrix
            .nodes
            .iter()
            .map(|node| format!("{} ({})", node.label, node.role))
            .collect::<Vec<_>>()
            .join(", ")
    });
    let rendered = render_assessment_markdown(
        config.project.as_str(),
        matrix.attacks.as_slice(),
        topology.as_str(),
        config.authorization.as_str(),
    );
    fs::write(output_path.as_path(), rendered)
        .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
    Ok(format!(
        "wrote assessment scaffold {}",
        output_path.display()
    ))
}

pub fn execute_ops_validate_live_lab_reports(
    config: ValidateLiveLabReportsConfig,
) -> Result<String, String> {
    let report_paths =
        collect_report_paths(config.reports.as_slice(), config.report_dir.as_deref())?;
    let errors = validate_report_paths(report_paths.as_slice())?;
    if let Some(output) = config.output {
        let output_path = resolve_path(output.as_path())?;
        ensure_parent_dir(output_path.as_path())?;
        fs::write(
            output_path.as_path(),
            render_validation_markdown(report_paths.as_slice(), errors.as_slice()),
        )
        .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
    }
    if errors.is_empty() {
        Ok(format!(
            "validated {} live-lab report(s)",
            report_paths.len()
        ))
    } else {
        Err(errors.join("\n"))
    }
}

pub fn execute_ops_evaluate_live_coverage_promotion(
    config: EvaluateLiveCoveragePromotionConfig,
) -> Result<String, String> {
    let report_paths =
        collect_report_paths(config.reports.as_slice(), config.report_dir.as_deref())?;
    let specs = selected_validation_specs(config.targets.as_str())?;
    let loaded = load_reports_by_mode(report_paths.as_slice())?;
    let mut rows = Vec::new();
    let mut failed = false;
    for spec in specs {
        let evaluation = evaluate_spec(spec, &loaded)?;
        if !evaluation.eligible {
            failed = true;
        }
        rows.push(evaluation);
    }
    let output_path = resolve_path(config.output.as_path())?;
    ensure_parent_dir(output_path.as_path())?;
    fs::write(
        output_path.as_path(),
        render_promotion_markdown(rows.as_slice()),
    )
    .map_err(|err| format!("write {} failed: {err}", output_path.display()))?;
    if failed {
        Err(format!(
            "live coverage promotion blocked; see {}",
            output_path.display()
        ))
    } else {
        Ok(format!(
            "live coverage promotion eligible; wrote {}",
            output_path.display()
        ))
    }
}

fn parse_attacks(raw: &str) -> Result<Vec<String>, String> {
    let attacks = split_csv_string(raw);
    if attacks.is_empty() {
        return Err("no attack keys supplied".to_string());
    }
    for attack in &attacks {
        if attack_spec(attack.as_str()).is_none() {
            return Err(format!("unknown attack keys: {attack}"));
        }
    }
    Ok(attacks)
}

fn attack_spec(key: &str) -> Option<&'static AttackSpec> {
    ATTACK_SPECS.iter().find(|spec| spec.key == key)
}

fn parse_nodes(raw: &str) -> Result<Vec<NodeSpec>, String> {
    let mut nodes = Vec::new();
    for item in split_csv_string(raw) {
        let Some((label, role)) = item.split_once(':') else {
            return Err(format!("invalid node spec: {item}"));
        };
        let label = label.trim();
        let role = role.trim();
        if label.is_empty() || role.is_empty() {
            return Err(format!("invalid node spec: {item}"));
        }
        nodes.push(NodeSpec {
            label: label.to_string(),
            role: role.to_string(),
        });
    }
    if nodes.is_empty() {
        return Err("no nodes supplied".to_string());
    }
    Ok(nodes)
}

fn build_attack_rows(attacks: &[String], nodes: &[NodeSpec]) -> Result<Vec<AttackRow>, String> {
    let mut rows = Vec::new();
    for attack in attacks {
        let spec =
            attack_spec(attack.as_str()).ok_or_else(|| format!("unknown attack keys: {attack}"))?;
        rows.push(AttackRow {
            attack_key: spec.key.to_string(),
            attack_family: spec.title.to_string(),
            primary_nodes: suggested_targets(spec.key, nodes),
            hypothesis: spec.hypothesis.to_string(),
            expected_secure_behavior: spec.expected.to_string(),
            result: "[pass/fail/blocked/skipped]".to_string(),
            evidence: "[fill in logs, tests, reports]".to_string(),
        });
    }
    Ok(rows)
}

fn suggested_targets(attack_key: &str, nodes: &[NodeSpec]) -> String {
    let roles: HashSet<&str> = nodes.iter().map(|node| node.role.as_str()).collect();
    if matches!(
        attack_key,
        "route-hijack" | "dns-integrity" | "control-plane-replay"
    ) && roles.contains("admin")
    {
        return nodes
            .iter()
            .filter(|node| node.role == "admin")
            .map(|node| node.label.clone())
            .collect::<Vec<_>>()
            .join(", ");
    }
    if matches!(
        attack_key,
        "local-socket-spoofing" | "secret-custody" | "missing-state-fail-closed"
    ) {
        return nodes
            .iter()
            .map(|node| node.label.clone())
            .collect::<Vec<_>>()
            .join(", ");
    }
    if attack_key == "host-trust-downgrade" {
        return format!(
            "operator -> {}",
            nodes
                .iter()
                .map(|node| node.label.clone())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }
    if attack_key == "traversal-abuse" {
        let preferred = nodes
            .iter()
            .filter(|node| matches!(node.role.as_str(), "client" | "admin" | "relay" | "entry"))
            .map(|node| node.label.clone())
            .collect::<Vec<_>>();
        if !preferred.is_empty() {
            return preferred.join(", ");
        }
    }
    if attack_key == "helper-input-abuse" {
        let preferred = nodes
            .iter()
            .filter(|node| matches!(node.role.as_str(), "client" | "admin"))
            .map(|node| node.label.clone())
            .collect::<Vec<_>>();
        if !preferred.is_empty() {
            return preferred.join(", ");
        }
    }
    nodes
        .iter()
        .map(|node| node.label.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

fn render_attack_matrix_markdown(rows: &[AttackRow], nodes: &[NodeSpec]) -> String {
    let node_summary = nodes
        .iter()
        .map(|node| format!("{} ({})", node.label, node.role))
        .collect::<Vec<_>>()
        .join(", ");
    let mut lines = vec![
        "# Attack Matrix".to_string(),
        "".to_string(),
        "## Lab Nodes".to_string(),
        "".to_string(),
        format!("- {node_summary}"),
        "".to_string(),
        "## Planned Attacks".to_string(),
        "".to_string(),
        "| Attack Family | Primary Nodes | Hypothesis | Expected Secure Behavior | Result | Evidence |".to_string(),
        "| --- | --- | --- | --- | --- | --- |".to_string(),
    ];
    for row in rows {
        lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            row.attack_family,
            row.primary_nodes,
            row.hypothesis,
            row.expected_secure_behavior,
            row.result,
            row.evidence
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

struct AssessmentMatrix {
    nodes: Vec<NodeSpec>,
    attacks: Vec<AttackRow>,
}

fn load_matrix_payload(path: &Path) -> Result<AssessmentMatrix, String> {
    let payload = load_json_object(path)?;
    let nodes_value = payload
        .get("nodes")
        .ok_or_else(|| "matrix payload must contain 'nodes' and 'attacks' arrays".to_string())?;
    let attacks_value = payload
        .get("attacks")
        .ok_or_else(|| "matrix payload must contain 'nodes' and 'attacks' arrays".to_string())?;
    let nodes_array = nodes_value
        .as_array()
        .ok_or_else(|| "matrix payload must contain 'nodes' and 'attacks' arrays".to_string())?;
    let attacks_array = attacks_value
        .as_array()
        .ok_or_else(|| "matrix payload must contain 'nodes' and 'attacks' arrays".to_string())?;

    let mut nodes = Vec::new();
    for node in nodes_array {
        let object = node
            .as_object()
            .ok_or_else(|| "invalid node entry in matrix payload".to_string())?;
        let label = require_non_empty_string_field(
            object,
            "label",
            "invalid node entry in matrix payload",
        )?;
        let role =
            require_non_empty_string_field(object, "role", "invalid node entry in matrix payload")?;
        nodes.push(NodeSpec { label, role });
    }

    let required_attack_fields = [
        "attack_key",
        "attack_family",
        "primary_nodes",
        "hypothesis",
        "expected_secure_behavior",
        "result",
        "evidence",
    ];
    let mut attacks = Vec::new();
    for attack in attacks_array {
        let object = attack
            .as_object()
            .ok_or_else(|| "invalid attack entry in matrix payload".to_string())?;
        let mut missing = Vec::new();
        for field in required_attack_fields {
            if object.get(field).and_then(Value::as_str).is_none() {
                missing.push(field);
            }
        }
        if !missing.is_empty() {
            return Err(format!(
                "invalid attack entry in matrix payload; missing fields: {}",
                missing.join(", ")
            ));
        }
        attacks.push(AttackRow {
            attack_key: object["attack_key"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            attack_family: object["attack_family"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            primary_nodes: object["primary_nodes"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            hypothesis: object["hypothesis"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            expected_secure_behavior: object["expected_secure_behavior"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            result: object["result"].as_str().unwrap_or_default().to_string(),
            evidence: object["evidence"].as_str().unwrap_or_default().to_string(),
        });
    }

    Ok(AssessmentMatrix { nodes, attacks })
}

fn render_assessment_markdown(
    project: &str,
    attacks: &[AttackRow],
    topology: &str,
    authorization: &str,
) -> String {
    let generated_at = utc_timestamp();
    let attack_lines = if attacks.is_empty() {
        "- [fill in attack families]".to_string()
    } else {
        attacks
            .iter()
            .map(|attack| format!("- {}", attack.attack_family))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let mut matrix_lines = vec![
        "| Attack Family | Primary Nodes | Hypothesis | Expected Secure Behavior | Result | Evidence |"
            .to_string(),
        "| --- | --- | --- | --- | --- | --- |".to_string(),
    ];
    for attack in attacks {
        matrix_lines.push(format!(
            "| {} | {} | {} | {} | {} | {} |",
            attack.attack_family,
            attack.primary_nodes,
            attack.hypothesis,
            attack.expected_secure_behavior,
            attack.result,
            attack.evidence
        ));
    }
    format!(
        "# {project} Adversarial Hardening Assessment\n\nGenerated: {generated_at}\n\n## Scope And Authorization\n\n- Lab-only authorization confirmed: {authorization}\n- In-scope systems:\n- Out-of-scope systems:\n- Success criteria:\n\n## Topology\n\n{topology}\n\n## Attack Plan\n\n{attack_lines}\n\n## Attack Matrix\n\n{}\n\n## Findings\n\n### [Severity] [Title]\n\n- Attack family:\n- Evidence:\n- Affected files/subsystems:\n- Expected secure behavior:\n- Actual behavior:\n- Remediation:\n- Required regression test or gate:\n\n## Code Audit Notes\n\n- Trust boundaries reviewed:\n- Privileged boundaries reviewed:\n- Fallback or legacy paths found:\n- Tests and gates reviewed:\n\n## Recommended Hardening Work\n\n1. [Highest-priority change]\n2. [Next change]\n3. [Next change]\n\n## Verification Plan\n\n1. [Unit or integration test]\n2. [Gate or live lab validation]\n3. [Evidence artifact to regenerate]\n",
        matrix_lines.join("\n")
    )
}

fn collect_report_paths(
    reports: &[PathBuf],
    report_dir: Option<&Path>,
) -> Result<Vec<PathBuf>, String> {
    let mut paths = Vec::new();
    for path in reports {
        paths.push(resolve_path(path.as_path())?);
    }
    if let Some(report_dir) = report_dir {
        collect_json_files(resolve_path(report_dir)?.as_path(), &mut paths)?;
    }
    let mut deduped = Vec::new();
    let mut seen = HashSet::new();
    for path in paths {
        if seen.insert(path.clone()) {
            deduped.push(path);
        }
    }
    if deduped.is_empty() {
        return Err("no report files supplied".to_string());
    }
    Ok(deduped)
}

fn collect_json_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    let metadata =
        fs::metadata(dir).map_err(|err| format!("read {} failed: {err}", dir.display()))?;
    if !metadata.is_dir() {
        return Err(format!("{} is not a directory", dir.display()));
    }
    let mut entries = fs::read_dir(dir)
        .map_err(|err| format!("read {} failed: {err}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| format!("read {} failed: {err}", dir.display()))?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|err| format!("inspect {} failed: {err}", path.display()))?;
        if file_type.is_dir() {
            collect_json_files(path.as_path(), out)?;
        } else if file_type.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("json")
        {
            out.push(path);
        }
    }
    Ok(())
}

fn validate_report_paths(report_paths: &[PathBuf]) -> Result<Vec<String>, String> {
    let mut errors = Vec::new();
    for path in report_paths {
        let payload = load_json_object(path.as_path())?;
        errors.extend(validate_report_payload(path.as_path(), &payload));
    }
    Ok(errors)
}

fn validate_report_payload(path: &Path, payload: &serde_json::Map<String, Value>) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(mode) = payload.get("mode").and_then(Value::as_str) else {
        return vec![format!(
            "{}: missing or invalid 'mode' field",
            path.display()
        )];
    };
    let Some(spec) = validation_spec_by_mode(mode) else {
        return vec![format!("{}: unknown report mode '{mode}'", path.display())];
    };
    for field in spec.required_report_fields {
        if !payload.contains_key(*field) {
            problems.push(format!(
                "{}: missing required field '{}'",
                path.display(),
                field
            ));
        }
    }
    if payload.get("evidence_mode").and_then(Value::as_str) != Some(EVIDENCE_MODE_MEASURED) {
        problems.push(format!(
            "{}: field 'evidence_mode' must equal '{}'",
            path.display(),
            EVIDENCE_MODE_MEASURED
        ));
    }
    let Some(checks) = payload.get("checks").and_then(Value::as_object) else {
        problems.push(format!(
            "{}: field 'checks' must be an object",
            path.display()
        ));
        return problems;
    };
    for check_name in spec.required_check_keys {
        match checks.get(*check_name).and_then(Value::as_str) {
            None => problems.push(format!(
                "{}: missing required check '{}'",
                path.display(),
                check_name
            )),
            Some(value)
                if !matches!(value, CHECK_PASS | CHECK_FAIL | CHECK_SKIP | CHECK_SKIPPED) =>
            {
                problems.push(format!(
                    "{}: check '{}' must be one of pass/fail/skip/skipped, got {:?}",
                    path.display(),
                    check_name,
                    value
                ));
            }
            Some(_) => {}
        }
    }
    match payload.get("captured_at_unix").and_then(Value::as_u64) {
        Some(value) if value > 0 => {}
        _ => problems.push(format!(
            "{}: field 'captured_at_unix' must be a positive integer",
            path.display()
        )),
    }
    if !matches!(
        payload.get("status").and_then(Value::as_str),
        Some(STATUS_PASS | STATUS_FAIL)
    ) {
        problems.push(format!(
            "{}: field 'status' must be 'pass' or 'fail'",
            path.display()
        ));
    }
    problems
}

fn render_validation_markdown(report_paths: &[PathBuf], errors: &[String]) -> String {
    let mut lines = vec![
        "# Rustynet Live-Lab Report Validation".to_string(),
        "".to_string(),
        "## Reports".to_string(),
        "".to_string(),
    ];
    for path in report_paths {
        lines.push(format!("- `{}`", path.display()));
    }
    lines.push(String::new());
    if errors.is_empty() {
        lines.extend([
            "## Result".to_string(),
            "".to_string(),
            "All supplied reports matched the expected shared schema.".to_string(),
            "".to_string(),
        ]);
    } else {
        lines.extend(["## Errors".to_string(), "".to_string()]);
        for error in errors {
            lines.push(format!("- {error}"));
        }
        lines.push(String::new());
    }
    lines.join("\n")
}

fn validation_spec_by_mode(mode: &str) -> Option<&'static LiveValidationSpec> {
    catalog_validation_spec_by_mode(mode)
}

fn validation_spec_by_key(key: &str) -> Option<&'static LiveValidationSpec> {
    catalog_validation_spec_by_key(key)
}

fn selected_validation_specs(raw: &str) -> Result<Vec<&'static LiveValidationSpec>, String> {
    if raw.trim().eq_ignore_ascii_case("all") {
        return Ok(catalog_sorted_validation_specs());
    }
    let keys = split_csv_string(raw);
    if keys.is_empty() {
        return Err("no targets supplied".to_string());
    }
    let mut specs = Vec::new();
    let mut unknown = Vec::new();
    for key in keys {
        if let Some(spec) = validation_spec_by_key(key.as_str()) {
            specs.push(spec);
        } else {
            unknown.push(key);
        }
    }
    if !unknown.is_empty() {
        return Err(format!("unknown targets: {}", unknown.join(", ")));
    }
    Ok(specs)
}

fn load_reports_by_mode(
    report_paths: &[PathBuf],
) -> Result<HashMap<String, LoadedReportRecord>, String> {
    let mut loaded = HashMap::new();
    for path in report_paths {
        let payload = load_json_value(path.as_path())?;
        if let Some(mode) = payload.get("mode").and_then(Value::as_str) {
            loaded.insert(
                mode.to_string(),
                LoadedReportRecord {
                    path: path.clone(),
                    payload,
                },
            );
        }
    }
    Ok(loaded)
}

struct PromotionRow {
    validation: String,
    targets: String,
    eligible: bool,
    reason: String,
    report_path: String,
}

fn evaluate_spec(
    spec: &LiveValidationSpec,
    loaded: &HashMap<String, LoadedReportRecord>,
) -> Result<PromotionRow, String> {
    let Some(record) = loaded.get(spec.mode) else {
        return Ok(PromotionRow {
            validation: spec.key.to_string(),
            targets: spec.coverage_targets.join(", "),
            eligible: false,
            reason: "required live report missing".to_string(),
            report_path: "[missing]".to_string(),
        });
    };
    let payload_object = record
        .payload
        .as_object()
        .ok_or_else(|| format!("report must be a JSON object: {}", record.path.display()))?;
    let schema_errors = validate_report_payload(record.path.as_path(), payload_object);
    if !schema_errors.is_empty() {
        return Ok(PromotionRow {
            validation: spec.key.to_string(),
            targets: spec.coverage_targets.join(", "),
            eligible: false,
            reason: "report schema validation failed".to_string(),
            report_path: record.path.display().to_string(),
        });
    }
    if payload_object.get("status").and_then(Value::as_str) != Some(STATUS_PASS) {
        return Ok(PromotionRow {
            validation: spec.key.to_string(),
            targets: spec.coverage_targets.join(", "),
            eligible: false,
            reason: "report status is not pass".to_string(),
            report_path: record.path.display().to_string(),
        });
    }
    let Some(checks) = payload_object.get("checks").and_then(Value::as_object) else {
        return Ok(PromotionRow {
            validation: spec.key.to_string(),
            targets: spec.coverage_targets.join(", "),
            eligible: false,
            reason: "report checks object is missing or invalid".to_string(),
            report_path: record.path.display().to_string(),
        });
    };
    let failing = spec
        .required_check_keys
        .iter()
        .filter(|name| checks.get(**name).and_then(Value::as_str) != Some(CHECK_PASS))
        .copied()
        .collect::<Vec<_>>();
    if !failing.is_empty() {
        return Ok(PromotionRow {
            validation: spec.key.to_string(),
            targets: spec.coverage_targets.join(", "),
            eligible: false,
            reason: format!("required checks did not all pass: {}", failing.join(", ")),
            report_path: record.path.display().to_string(),
        });
    }
    Ok(PromotionRow {
        validation: spec.key.to_string(),
        targets: spec.coverage_targets.join(", "),
        eligible: true,
        reason: "all required checks passed".to_string(),
        report_path: record.path.display().to_string(),
    })
}

fn render_promotion_markdown(rows: &[PromotionRow]) -> String {
    let mut lines = vec![
        "# Rustynet Live Coverage Promotion Gate".to_string(),
        "".to_string(),
        "| Validation | Comparative Targets | Eligible | Reason | Report |".to_string(),
        "| --- | --- | --- | --- | --- |".to_string(),
    ];
    for row in rows {
        lines.push(format!(
            "| {} | {} | {} | {} | `{}` |",
            row.validation, row.targets, row.eligible, row.reason, row.report_path
        ));
    }
    lines.push(String::new());
    lines.join("\n")
}

fn load_json_value(path: &Path) -> Result<Value, String> {
    let body =
        fs::read_to_string(path).map_err(|err| format!("read {} failed: {err}", path.display()))?;
    serde_json::from_str(&body).map_err(|err| format!("parse {} failed: {err}", path.display()))
}

fn load_json_object(path: &Path) -> Result<serde_json::Map<String, Value>, String> {
    let value = load_json_value(path)?;
    value
        .as_object()
        .cloned()
        .ok_or_else(|| format!("report must be a JSON object: {}", path.display()))
}

fn ensure_parent_dir(path: &Path) -> Result<(), String> {
    let Some(parent) = path.parent() else {
        return Ok(());
    };
    fs::create_dir_all(parent).map_err(|err| format!("create {} failed: {err}", parent.display()))
}

fn resolve_path(path: &Path) -> Result<PathBuf, String> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    let cwd = std::env::current_dir()
        .map_err(|err| format!("resolve current directory failed: {err}"))?;
    Ok(cwd.join(path))
}

fn require_non_empty_string_field(
    object: &serde_json::Map<String, Value>,
    field: &str,
    error: &str,
) -> Result<String, String> {
    object
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| error.to_string())
}

fn split_csv_string(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn utc_timestamp() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output();
    match output {
        Ok(output) if output.status.success() => String::from_utf8(output.stdout)
            .unwrap_or_else(|_| "1970-01-01T00:00:00Z\n".to_string())
            .trim()
            .to_string(),
        _ => format!("{}", unix_now()),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvaluateLiveCoveragePromotionConfig, GenerateAssessmentFromMatrixConfig,
        GenerateAttackMatrixConfig, ValidateLiveLabReportsConfig, build_attack_rows,
        execute_ops_evaluate_live_coverage_promotion, execute_ops_generate_assessment_from_matrix,
        execute_ops_generate_attack_matrix, execute_ops_validate_live_lab_reports, parse_attacks,
        parse_nodes, render_promotion_markdown, validate_report_payload,
    };
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    use serde_json::json;

    fn temp_dir(label: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rustynet-cli-{label}-{unique}"));
        fs::create_dir_all(path.as_path()).expect("create temp dir");
        path
    }

    fn write_json(path: &Path, payload: serde_json::Value) {
        fs::write(
            path,
            serde_json::to_string_pretty(&payload).expect("encode json") + "\n",
        )
        .expect("write json");
    }

    fn valid_report_payload() -> serde_json::Value {
        json!({
            "phase": "phase10",
            "mode": "live_linux_control_surface_exposure",
            "evidence_mode": "measured",
            "captured_at": "2026-04-17T10:00:00Z",
            "captured_at_unix": 1_777_420_800u64,
            "status": "pass",
            "checks": {
                "all_daemon_sockets_secure": "pass",
                "all_helper_sockets_secure": "pass",
                "no_rustynet_tcp_listeners": "pass",
                "rustynet_udp_loopback_only": "pass",
                "remote_underlay_dns_probe_blocked": "pass"
            },
            "hosts": ["client-host"],
            "evidence": {"sample":"value"},
            "dns_bind_addr": "127.0.0.1:53"
        })
    }

    #[test]
    fn parse_attacks_rejects_unknown_attack() {
        let err = parse_attacks("not-real").expect_err("must fail");
        assert!(err.contains("unknown attack keys"));
    }

    #[test]
    fn parse_nodes_rejects_invalid_node_spec() {
        let err = parse_nodes("client").expect_err("must fail");
        assert!(err.contains("invalid node spec"));
    }

    #[test]
    fn generate_attack_matrix_writes_json_payload() {
        let temp = temp_dir("attack-matrix");
        let output = temp.join("matrix.json");
        execute_ops_generate_attack_matrix(GenerateAttackMatrixConfig {
            attacks: "control-plane-replay,route-hijack".to_string(),
            nodes: "exit:admin,client:client".to_string(),
            output: output.clone(),
            format: "json".to_string(),
        })
        .expect("generate matrix");
        let body = fs::read_to_string(output).expect("read matrix");
        assert!(body.contains("\"attack_key\": \"control-plane-replay\""));
        assert!(body.contains("\"label\": \"exit\""));
    }

    #[test]
    fn build_attack_rows_prefers_admin_for_route_hijack() {
        let nodes = parse_nodes("exit:admin,client:client").expect("nodes");
        let attacks = vec!["route-hijack".to_string()];
        let rows = build_attack_rows(&attacks, &nodes).expect("rows");
        assert_eq!(rows[0].primary_nodes, "exit");
    }

    #[test]
    fn generate_assessment_from_matrix_rejects_invalid_matrix() {
        let temp = temp_dir("assessment-invalid");
        let matrix = temp.join("matrix.json");
        fs::write(matrix.as_path(), "{\"nodes\":[],\"attacks\":[{}]}")
            .expect("write invalid matrix");
        let err = execute_ops_generate_assessment_from_matrix(GenerateAssessmentFromMatrixConfig {
            project: "Rustynet".to_string(),
            matrix_json: matrix,
            output: temp.join("report.md"),
            topology: None,
            authorization: "[yes/no]".to_string(),
        })
        .expect_err("must fail");
        assert!(err.contains("invalid attack entry in matrix payload"));
    }

    #[test]
    fn validate_report_payload_accepts_valid_report() {
        let path = PathBuf::from("/tmp/report.json");
        let payload = valid_report_payload();
        let errors = validate_report_payload(path.as_path(), payload.as_object().expect("object"));
        assert!(errors.is_empty(), "{errors:?}");
    }

    #[test]
    fn validate_report_payload_rejects_invalid_status() {
        let path = PathBuf::from("/tmp/report.json");
        let mut payload = valid_report_payload();
        payload["status"] = json!("blocked");
        let errors = validate_report_payload(path.as_path(), payload.as_object().expect("object"));
        assert!(errors.iter().any(|error| error.contains("field 'status'")));
    }

    #[test]
    fn evaluate_live_coverage_promotion_marks_valid_report_eligible() {
        let temp = temp_dir("promotion-pass");
        let report = temp.join("report.json");
        write_json(report.as_path(), valid_report_payload());
        let output = temp.join("promotion.md");
        let result =
            execute_ops_evaluate_live_coverage_promotion(EvaluateLiveCoveragePromotionConfig {
                reports: vec![report],
                report_dir: None,
                targets: "control_surface_exposure".to_string(),
                output: output.clone(),
            })
            .expect("promotion should pass");
        assert!(result.contains("eligible"));
        let body = fs::read_to_string(output).expect("read promotion");
        assert!(body.contains("| control_surface_exposure |"));
        assert!(body.contains("| true |"));
    }

    #[test]
    fn evaluate_live_coverage_promotion_blocks_missing_report() {
        let temp = temp_dir("promotion-missing");
        let output = temp.join("promotion.md");
        let err =
            execute_ops_evaluate_live_coverage_promotion(EvaluateLiveCoveragePromotionConfig {
                reports: Vec::new(),
                report_dir: Some(temp),
                targets: "control_surface_exposure".to_string(),
                output,
            })
            .expect_err("missing reports should fail");
        assert!(err.contains("no report files supplied"));
    }

    #[test]
    fn validate_live_lab_reports_writes_markdown_summary() {
        let temp = temp_dir("validate");
        let report = temp.join("report.json");
        write_json(report.as_path(), valid_report_payload());
        let output = temp.join("summary.md");
        execute_ops_validate_live_lab_reports(ValidateLiveLabReportsConfig {
            reports: vec![report],
            report_dir: None,
            output: Some(output.clone()),
        })
        .expect("validation should pass");
        let body = fs::read_to_string(output).expect("read summary");
        assert!(body.contains("All supplied reports matched the expected shared schema."));
    }

    #[test]
    fn render_promotion_markdown_includes_reason_and_report() {
        let markdown = render_promotion_markdown(&[super::PromotionRow {
            validation: "control_surface_exposure".to_string(),
            targets: "Tailscale TS-2022-005".to_string(),
            eligible: false,
            reason: "required live report missing".to_string(),
            report_path: "[missing]".to_string(),
        }]);
        assert!(markdown.contains("required live report missing"));
        assert!(markdown.contains("`[missing]`"));
    }
}
