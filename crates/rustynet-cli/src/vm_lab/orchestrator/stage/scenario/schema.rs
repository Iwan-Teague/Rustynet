//! The `scenario.v1` evidence schema (L0.5,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §3.3).
//!
//! One document per scenario, the single interchange format a scenario WRITES
//! and the verifier READS. It carries no secret material and references every
//! raw artifact by report-root-relative path plus SHA-256.
//!
//! IMPORTANT — the `result` fields here are the scenario's SELF-REPORT and are
//! NOT trusted for the pass decision. The verifier recomputes each required
//! assertion from the raw witnesses named in `evidence` (§2.4); this schema only
//! carries the structure, the contract binding, and the artifact references the
//! verifier independently re-checks. Parsing therefore validates shape and
//! version only — never "the scenario said it passed".

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::AssertionClass;

/// The only accepted schema version. The parser rejects anything else rather
/// than guessing (§3.3).
pub const SCENARIO_SCHEMA_VERSION: u64 = 1;

/// The fixed file name a scenario writes and the verifier reads.
pub const SCENARIO_V1_FILE_NAME: &str = "scenario.v1.json";

/// A participant the scenario exercised. Identity is asserted, not just logged:
/// the verifier binds these to an expected-node-id challenge (§4.8/S2).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SelectedTarget {
    pub alias: String,
    pub node_id: String,
    pub role: String,
    pub platform: String,
    #[serde(default)]
    pub os_version: String,
}

/// A reference to a raw artifact: report-root-relative path plus the SHA-256 the
/// scenario recorded. The verifier validates the path for containment
/// (`artifact::validate_artifact`) and recomputes the digest before trusting it;
/// a mismatch is a rejection, never a pass.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArtifactRef {
    pub reference: String,
    pub sha256: String,
}

/// A self-reported per-item result. Present for human/debugging readability; the
/// verifier recomputes and does not trust it.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ItemResult {
    Pass,
    Fail,
    NotProven,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdmissionRecord {
    pub requirement: String,
    pub result: ItemResult,
    #[serde(default)]
    pub evidence: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BaselineRecord {
    pub assertion: String,
    pub result: ItemResult,
    #[serde(default)]
    pub evidence: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct FaultRecord {
    pub kind: String,
    pub scope: String,
    /// Whether the fault was applied, and whether its application was
    /// INDEPENDENTLY verified. An unverified fault is NotProven (§2.5); the
    /// verifier re-derives this from `evidence`, not from these booleans.
    pub applied: bool,
    pub verified: bool,
    #[serde(default)]
    pub evidence: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AssertionRecord {
    pub id: String,
    pub class: AssertionClass,
    /// Whether the contract marks this assertion required. The verifier cross-
    /// checks this against the independent contract registry — a scenario
    /// cannot demote a required assertion to optional here.
    pub required: bool,
    pub result: ItemResult,
    #[serde(default)]
    pub evidence: Vec<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CleanupRecord {
    pub action: String,
    pub result: ItemResult,
    pub residual_check: ItemResult,
    #[serde(default)]
    pub evidence: Vec<ArtifactRef>,
}

/// The `scenario.v1` document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScenarioV1 {
    pub schema_version: u64,
    pub scenario_id: String,
    pub stage_id: String,
    /// The digest of the [`super::StageContract`] this scenario claims to
    /// satisfy; the verifier binds it to its independent contract registry.
    pub contract_digest: String,
    /// The `run_instance_id` this scenario belongs to — the generation binding.
    pub run_identity: String,
    pub selected_targets: Vec<SelectedTarget>,
    #[serde(default)]
    pub admission: Vec<AdmissionRecord>,
    #[serde(default)]
    pub baseline: Vec<BaselineRecord>,
    #[serde(default)]
    pub fault: Option<FaultRecord>,
    pub assertions: Vec<AssertionRecord>,
    #[serde(default)]
    pub cleanup: Vec<CleanupRecord>,
    #[serde(default)]
    pub limitations: Vec<String>,
    pub terminal_outcome: String,
}

impl ScenarioV1 {
    /// Serialize to pretty JSON for `scenario.v1.json`.
    pub fn to_json_pretty(&self) -> Result<String, String> {
        serde_json::to_string_pretty(self).map_err(|e| format!("serialize scenario.v1: {e}"))
    }

    /// Parse and shape-validate a `scenario.v1` document. Rejects an unknown
    /// schema version rather than guessing. Does NOT judge pass/fail — that is
    /// the verifier's job against the raw artifacts (§2.4).
    pub fn parse(body: &str) -> Result<ScenarioV1, String> {
        let doc: ScenarioV1 =
            serde_json::from_str(body).map_err(|e| format!("parse scenario.v1: {e}"))?;
        if doc.schema_version != SCENARIO_SCHEMA_VERSION {
            return Err(format!(
                "scenario.v1 has unsupported schema_version {} (expected {SCENARIO_SCHEMA_VERSION})",
                doc.schema_version
            ));
        }
        Ok(doc)
    }
}

/// Canonical on-disk location of a stage's `scenario.v1.json`, keyed by
/// `stage_id` under the run's report root. Both the emitting control and the
/// finalizer's verifier derive the path through this one function, so they can
/// never disagree about where a scenario's evidence lives.
pub fn scenario_v1_path(report_root: &Path, stage_id: &str) -> PathBuf {
    report_root
        .join("scenarios")
        .join(stage_id)
        .join(SCENARIO_V1_FILE_NAME)
}

/// Durably write a `scenario.v1` document to its canonical path under
/// `report_root` (atomic tmp → fsync → rename → dir-fsync via the shared
/// [`crate::vm_lab::orchestrator::context::atomic_write_fsync`], so a reader
/// never observes a torn file). Returns the path written.
///
/// Fails CLOSED before writing anything if the document could not bind or be
/// located: an unsupported `schema_version`, an empty `run_identity` (the
/// generation binding the verifier checks — an unbound one would neuter its
/// identity gate, §10.1), or an empty `stage_id` (no canonical path) is
/// rejected. `scenario.v1` carries no secret material (§3.3), so the file keeps
/// the process default mode.
pub fn write_scenario_v1(report_root: &Path, scenario: &ScenarioV1) -> Result<PathBuf, String> {
    if scenario.schema_version != SCENARIO_SCHEMA_VERSION {
        return Err(format!(
            "refusing to write scenario.v1 with unsupported schema_version {} (expected {SCENARIO_SCHEMA_VERSION})",
            scenario.schema_version
        ));
    }
    if scenario.run_identity.trim().is_empty() {
        return Err(
            "refusing to write scenario.v1 with an empty run_identity; an unbound generation \
             would neuter the verifier's identity gate"
                .to_owned(),
        );
    }
    if scenario.stage_id.trim().is_empty() {
        return Err(
            "refusing to write scenario.v1 with an empty stage_id; no canonical path can be derived"
                .to_owned(),
        );
    }
    let body = scenario.to_json_pretty()?;
    let path = scenario_v1_path(report_root, &scenario.stage_id);
    crate::vm_lab::orchestrator::context::atomic_write_fsync(&path, body.as_bytes(), None)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn sample() -> ScenarioV1 {
        ScenarioV1 {
            schema_version: SCENARIO_SCHEMA_VERSION,
            scenario_id: "relay_frame_forward".to_owned(),
            stage_id: "relay_frame_forward_validation".to_owned(),
            contract_digest: "abc123".to_owned(),
            run_identity: "0123456789abcdef0123456789abcdef".to_owned(),
            selected_targets: vec![SelectedTarget {
                alias: "debian-1".to_owned(),
                node_id: "node-a".to_owned(),
                role: "relay".to_owned(),
                platform: "linux".to_owned(),
                os_version: "debian-13".to_owned(),
            }],
            admission: vec![AdmissionRecord {
                requirement: "relay + two peers".to_owned(),
                result: ItemResult::Pass,
                evidence: vec![],
            }],
            baseline: vec![],
            fault: Some(FaultRecord {
                kind: "direct_udp_block".to_owned(),
                scope: "peer_pair".to_owned(),
                applied: true,
                verified: true,
                evidence: vec![ArtifactRef {
                    reference: "state/scenarios/relay/nft.txt".to_owned(),
                    sha256: "deadbeef".to_owned(),
                }],
            }),
            assertions: vec![AssertionRecord {
                id: "relay_counter_delta".to_owned(),
                class: AssertionClass::Functional,
                required: true,
                result: ItemResult::Pass,
                evidence: vec![ArtifactRef {
                    reference: "state/scenarios/relay/counters.json".to_owned(),
                    sha256: "cafebabe".to_owned(),
                }],
            }],
            cleanup: vec![CleanupRecord {
                action: "remove_direct_udp_block".to_owned(),
                result: ItemResult::Pass,
                residual_check: ItemResult::Pass,
                evidence: vec![],
            }],
            limitations: vec!["linux only".to_owned()],
            terminal_outcome: "passed".to_owned(),
        }
    }

    #[test]
    fn scenario_v1_round_trips_through_json() {
        let doc = sample();
        let json = doc.to_json_pretty().unwrap();
        let back = ScenarioV1::parse(&json).unwrap();
        assert_eq!(doc, back);
    }

    #[test]
    fn assertion_class_serializes_as_its_snake_case_token() {
        let json = sample().to_json_pretty().unwrap();
        assert!(
            json.contains("\"class\": \"functional\""),
            "class must serialize as the same snake_case token as as_str"
        );
        // And a round-trip preserves the exact class.
        let back = ScenarioV1::parse(&json).unwrap();
        assert_eq!(back.assertions[0].class, AssertionClass::Functional);
    }

    #[test]
    fn parse_rejects_an_unknown_schema_version() {
        let mut doc = sample();
        doc.schema_version = 999;
        let json = doc.to_json_pretty().unwrap();
        let err = ScenarioV1::parse(&json).unwrap_err();
        assert!(
            err.contains("schema_version"),
            "must reject unknown version: {err}"
        );
    }

    #[test]
    fn parse_does_not_judge_the_self_reported_results() {
        // A document that self-reports everything as passed still parses — the
        // parser validates shape/version only; the verifier (L0.5) recomputes
        // from artifacts and is where a false self-report is caught.
        let doc = sample();
        let json = doc.to_json_pretty().unwrap();
        let back = ScenarioV1::parse(&json).expect("shape-valid doc parses");
        // The parser surfaces the self-report verbatim; it draws no pass/fail
        // conclusion from it.
        assert_eq!(back.assertions[0].result, ItemResult::Pass);
    }

    #[test]
    fn write_scenario_v1_round_trips_from_its_canonical_path() {
        let tmp = tempdir().unwrap();
        let doc = sample();
        let path = write_scenario_v1(tmp.path(), &doc).expect("write");
        // The writer and the path helper agree on the location.
        assert_eq!(path, scenario_v1_path(tmp.path(), &doc.stage_id));
        assert!(path.ends_with("scenario.v1.json"));
        // What was written parses back identical.
        let body = std::fs::read_to_string(&path).expect("read back");
        let back = ScenarioV1::parse(&body).expect("parse");
        assert_eq!(doc, back);
    }

    #[test]
    fn write_scenario_v1_refuses_empty_run_identity_and_writes_nothing() {
        let tmp = tempdir().unwrap();
        let mut doc = sample();
        doc.run_identity = "   ".to_owned();
        let err = write_scenario_v1(tmp.path(), &doc).expect_err("must refuse");
        assert!(err.contains("run_identity"), "{err}");
        // Fail-closed: nothing is written on refusal.
        assert!(!scenario_v1_path(tmp.path(), &doc.stage_id).exists());
    }

    #[test]
    fn write_scenario_v1_refuses_empty_stage_id_and_bad_version() {
        let tmp = tempdir().unwrap();
        let mut doc = sample();
        doc.stage_id = String::new();
        assert!(
            write_scenario_v1(tmp.path(), &doc)
                .unwrap_err()
                .contains("stage_id")
        );
        let mut doc2 = sample();
        doc2.schema_version = 2;
        assert!(
            write_scenario_v1(tmp.path(), &doc2)
                .unwrap_err()
                .contains("schema_version")
        );
    }

    #[test]
    fn missing_optional_sections_default_empty() {
        // A minimal document with only required fields parses, with the
        // #[serde(default)] sections empty.
        let json = r#"{
            "schema_version": 1,
            "scenario_id": "s",
            "stage_id": "st",
            "contract_digest": "d",
            "run_identity": "r",
            "selected_targets": [],
            "assertions": [],
            "terminal_outcome": "not_proven"
        }"#;
        let doc = ScenarioV1::parse(json).expect("minimal doc parses");
        assert!(doc.admission.is_empty());
        assert!(doc.baseline.is_empty());
        assert!(doc.fault.is_none());
        assert!(doc.cleanup.is_empty());
        assert!(doc.limitations.is_empty());
    }
}
