#![forbid(unsafe_code)]
#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};

use serde_json::{Value, json};

pub const ALL_SCENARIOS: &[Scenario] = &[
    Scenario {
        id: "truncated_one_byte",
        stage_name: "chaos_malformed_bundle_truncation",
        expected_rejection: "malformed_truncated_one_byte",
    },
    Scenario {
        id: "truncated_half_length",
        stage_name: "chaos_malformed_bundle_truncation",
        expected_rejection: "malformed_truncated_half_length",
    },
    Scenario {
        id: "future_dated_assignment",
        stage_name: "chaos_future_dated_assignment",
        expected_rejection: "future_dated_signed_state",
    },
    Scenario {
        id: "forged_signature_attempt",
        stage_name: "chaos_forged_signature_attempt",
        expected_rejection: "unauthorised_signature",
    },
    Scenario {
        id: "replay_watermarked_membership",
        stage_name: "chaos_replay_old_membership",
        expected_rejection: "replay_watermark_regression",
    },
    Scenario {
        id: "quorum_starved_update",
        stage_name: "chaos_quorum_starvation_propose",
        expected_rejection: "partial_quorum_not_accepted",
    },
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scenario {
    pub id: &'static str,
    pub stage_name: &'static str,
    pub expected_rejection: &'static str,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedScenario {
    pub id: String,
    pub stage_name: String,
    pub bytes: u64,
    pub expected_rejection: String,
}

pub fn scenario_names() -> Vec<&'static str> {
    ALL_SCENARIOS.iter().map(|scenario| scenario.id).collect()
}

pub fn selected_scenarios(name: &str) -> Result<Vec<Scenario>, String> {
    if name == "all" {
        return Ok(ALL_SCENARIOS.to_vec());
    }
    ALL_SCENARIOS
        .iter()
        .copied()
        .find(|candidate| candidate.id == name)
        .map(|scenario| vec![scenario])
        .ok_or_else(|| format!("unsupported scenario: {name}"))
}

pub fn generate_manifest(
    output_dir: &Path,
    scenario: &str,
    generated_at_unix: u64,
) -> Result<Value, String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create {} failed: {err}", output_dir.display()))?;
    let mut artifacts = Vec::new();
    for selected in selected_scenarios(scenario)? {
        let bytes = fixture_bytes(selected.id, generated_at_unix);
        if bytes.is_empty() {
            return Err(format!("empty fixture generated for {}", selected.id));
        }
        let path = output_dir.join(format!("{}.fixture", selected.id));
        fs::write(&path, &bytes)
            .map_err(|err| format!("write {} failed: {err}", path.display()))?;
        artifacts.push(json!({
            "scenario": selected.id,
            "stage_name": selected.stage_name,
            "path": path,
            "bytes": bytes.len(),
            "expected_result": "reject_fail_closed",
            "expected_rejection": selected.expected_rejection,
        }));
    }
    Ok(json!({
        "schema_version": 1,
        "tool": "live_signed_bundle_forger",
        "production_accepted": false,
        "generated_at_unix": generated_at_unix,
        "scenarios": artifacts,
    }))
}

pub fn write_manifest(output_dir: &Path, manifest: &Value) -> Result<PathBuf, String> {
    fs::create_dir_all(output_dir)
        .map_err(|err| format!("create {} failed: {err}", output_dir.display()))?;
    let manifest_path = output_dir.join("manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(manifest)
            .map_err(|err| format!("serialise manifest failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", manifest_path.display()))?;
    Ok(manifest_path)
}

pub fn validate_manifest(manifest: &Value) -> Result<Vec<ValidatedScenario>, String> {
    if manifest.get("schema_version").and_then(Value::as_u64) != Some(1) {
        return Err("signed-state forger manifest schema_version must be 1".to_owned());
    }
    if manifest.get("production_accepted").and_then(Value::as_bool) != Some(false) {
        return Err(
            "signed-state forger manifest must declare production_accepted=false".to_owned(),
        );
    }
    let scenarios = manifest
        .get("scenarios")
        .and_then(Value::as_array)
        .ok_or_else(|| "signed-state forger manifest missing scenarios array".to_owned())?;
    let mut validated = Vec::new();
    for scenario in scenarios {
        let id = required_str(scenario, "scenario")?;
        let stage_name = required_str(scenario, "stage_name")?;
        let expected_result = required_str(scenario, "expected_result")?;
        if expected_result != "reject_fail_closed" {
            return Err(format!(
                "scenario {id} expected_result must be reject_fail_closed"
            ));
        }
        let expected_rejection = required_str(scenario, "expected_rejection")?;
        let bytes = scenario
            .get("bytes")
            .and_then(Value::as_u64)
            .ok_or_else(|| format!("scenario {id} missing bytes"))?;
        if bytes == 0 {
            return Err(format!("scenario {id} fixture must not be empty"));
        }
        let known = ALL_SCENARIOS
            .iter()
            .find(|known| known.id == id)
            .ok_or_else(|| format!("unknown signed-state scenario: {id}"))?;
        if known.stage_name != stage_name {
            return Err(format!(
                "scenario {id} stage mismatch: expected {}, got {stage_name}",
                known.stage_name
            ));
        }
        if known.expected_rejection != expected_rejection {
            return Err(format!(
                "scenario {id} rejection mismatch: expected {}, got {expected_rejection}",
                known.expected_rejection
            ));
        }
        validated.push(ValidatedScenario {
            id: id.to_owned(),
            stage_name: stage_name.to_owned(),
            bytes,
            expected_rejection: expected_rejection.to_owned(),
        });
    }
    Ok(validated)
}

pub fn fixture_bytes(name: &str, generated_at: u64) -> Vec<u8> {
    match name {
        "truncated_one_byte" => vec![b'{'],
        "truncated_half_length" => br#"{"schema_version":1,"payload":"half"#.to_vec(),
        "future_dated_assignment" => json!({
            "schema_version": 1,
            "bundle_type": "assignment",
            "generated_at_unix": generated_at + 86_400,
            "signature": "invalid-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "forged_signature_attempt" => json!({
            "schema_version": 1,
            "bundle_type": "membership",
            "signer": "unauthorised-test-key",
            "signature": "forged-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "replay_watermarked_membership" => json!({
            "schema_version": 1,
            "bundle_type": "membership",
            "watermark": 1,
            "epoch": 1,
            "signature": "stale-test-fixture",
        })
        .to_string()
        .into_bytes(),
        "quorum_starved_update" => json!({
            "schema_version": 1,
            "bundle_type": "membership_update_proposal",
            "required_quorum": 3,
            "present_signatures": 1,
            "signature": "partial-quorum-test-fixture",
        })
        .to_string()
        .into_bytes(),
        _ => Vec::new(),
    }
}

fn required_str<'a>(value: &'a Value, field: &str) -> Result<&'a str, String> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("scenario missing {field}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustynet-signed-state-chaos-{label}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn selected_scenarios_accepts_all_and_single() {
        assert_eq!(selected_scenarios("all").expect("all").len(), 6);
        let selected = selected_scenarios("forged_signature_attempt").expect("single");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].stage_name, "chaos_forged_signature_attempt");
    }

    #[test]
    fn selected_scenarios_rejects_unknown() {
        let err = selected_scenarios("not-real").expect_err("unknown must reject");
        assert!(err.contains("unsupported scenario"));
    }

    #[test]
    fn generated_manifest_validates_fail_closed_contract() {
        let output_dir = test_dir("manifest-validates");
        let manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        let validated = validate_manifest(&manifest).expect("manifest validates");
        assert_eq!(validated.len(), 6);
        assert!(
            validated
                .iter()
                .any(|scenario| scenario.id == "truncated_one_byte")
        );
        assert_eq!(manifest["production_accepted"], false);
        let _ = fs::remove_dir_all(output_dir);
    }

    #[test]
    fn validation_rejects_production_accepted_manifest() {
        let output_dir = test_dir("manifest-rejects-production");
        let mut manifest = generate_manifest(&output_dir, "all", 123).expect("manifest");
        manifest["production_accepted"] = json!(true);
        let err = validate_manifest(&manifest).expect_err("production accepted must reject");
        assert!(err.contains("production_accepted=false"));
        let _ = fs::remove_dir_all(output_dir);
    }
}
