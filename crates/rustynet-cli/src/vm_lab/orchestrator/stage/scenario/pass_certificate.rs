//! The PassCertificate and its private evaluator (L0.5,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §2.1 / §2.4).
//!
//! A [`PassCertificate`] is the ONLY thing that turns into a `Passed` outcome,
//! and it has no public constructor — [`evaluate`] is the sole gate. A scenario
//! body therefore cannot fabricate a pass: it can write `result: pass` all it
//! likes in `scenario.v1`, but `evaluate` ignores those self-reports and instead
//! re-checks, for every REQUIRED assertion named by the independent contract:
//!
//!   * the scenario binds to the expected contract digest and run instance
//!     (generation) — stale or foreign evidence is never current;
//!   * the assertion is present and carries at least one artifact;
//!   * every artifact reference is containment-safe (no absolute/`..`/symlink
//!     escape) and its recorded SHA-256 matches the file on disk — a swapped or
//!     mutated artifact is rejected;
//!   * an INDEPENDENT recomputer for that assertion re-derives the claim from
//!     the raw witnesses and agrees. No recomputer registered ⇒ NotProven (the
//!     claim cannot be proven), never a pass.
//!
//! and that the scenario named the intended node identities and recorded a
//! cleanup whose residual check holds (a failed cleanup TAINTS the run, §2.5).
//! Any gap is a typed non-pass carrying WHY; only when all gates hold is a
//! certificate minted.
//!
//! The per-assertion recomputers are supplied by the scenario/verifier layer in
//! L1 (they parse the raw capture/transcript for the marker, the counter delta,
//! the absence of cleartext, …). This module is the gate they plug into; with
//! no recomputer every required assertion is NotProven, so the framework cannot
//! emit a false pass before the real checks exist.

use std::collections::HashMap;
use std::path::Path;

use crate::vm_lab::orchestrator::error::ReasonCode;

use super::ScenarioEvidenceContract;
use super::artifact::{self, ValidatedArtifact};
use super::schema::{AssertionRecord, ItemResult, ScenarioV1};

/// Independently re-derive one assertion's claim from its validated artifacts.
/// `Ok(())` means the raw witnesses prove it; `Err(reason)` means they do not.
/// Never consult the scenario's self-reported `result`.
pub type Recomputer<'a> = dyn Fn(&AssertionRecord, &[ValidatedArtifact]) -> Result<(), String> + 'a;

/// Proof that a scenario's exact claim was independently verified. No public
/// constructor — only [`evaluate`] mints one, so a `Passed` outcome cannot be
/// forged by a scenario body.
#[derive(Debug, Clone)]
pub struct PassCertificate {
    scenario_id: String,
    stage_id: String,
    run_identity: String,
    contract_digest: String,
    verified_assertions: Vec<String>,
    /// Private, unit-typed seal: makes the struct impossible to construct with a
    /// literal outside this module even though the other fields are readable.
    _seal: (),
}

impl PassCertificate {
    pub fn scenario_id(&self) -> &str {
        &self.scenario_id
    }
    pub fn stage_id(&self) -> &str {
        &self.stage_id
    }
    pub fn run_identity(&self) -> &str {
        &self.run_identity
    }
    pub fn contract_digest(&self) -> &str {
        &self.contract_digest
    }
    /// The required assertion ids that recomputed true, in the contract's order.
    pub fn verified_assertions(&self) -> &[String] {
        &self.verified_assertions
    }
}

/// The verdict of [`evaluate`].
#[derive(Debug)]
pub enum Assessment {
    /// Every required proof item validated — the certificate.
    Passed(PassCertificate),
    /// A required observation is missing or unattributable; blocking non-pass.
    NotProven(ReasonCode, String),
    /// A product/test invariant was disproved, or cleanup failed — a hard
    /// failure (§2.5: a failed cleanup taints the run).
    Failed(String),
}

impl Assessment {
    pub fn is_pass(&self) -> bool {
        matches!(self, Assessment::Passed(_))
    }
}

/// The sole gate that mints a [`PassCertificate`]. `expected_contract_digest`
/// and `expected_run_identity` come from the INDEPENDENT plan/run state (not the
/// scenario file); `contract` is the independent evidence contract; `recomputers`
/// re-derive each required assertion. Self-reported results in `scenario` are
/// never consulted.
pub fn evaluate(
    report_root: &Path,
    scenario: &ScenarioV1,
    contract: &ScenarioEvidenceContract,
    expected_contract_digest: &str,
    expected_run_identity: &str,
    max_artifact_bytes: u64,
    recomputers: &HashMap<&str, &Recomputer<'_>>,
) -> Assessment {
    // Contract binding: the scenario must claim the exact contract we verify
    // against, or its evidence is unattributable to this claim.
    if scenario.contract_digest != expected_contract_digest {
        return Assessment::NotProven(
            ReasonCode::Unattributable,
            format!(
                "scenario contract_digest `{}` != expected `{expected_contract_digest}`",
                scenario.contract_digest
            ),
        );
    }
    // Generation binding: the scenario must belong to this run instance.
    if scenario.run_identity != expected_run_identity {
        return Assessment::NotProven(
            ReasonCode::StaleEvidence,
            format!(
                "scenario run_identity `{}` != current `{expected_run_identity}`",
                scenario.run_identity
            ),
        );
    }
    // Node identity must be asserted, not merely absent.
    if scenario.selected_targets.is_empty() {
        return Assessment::NotProven(
            ReasonCode::MissingWitness,
            "scenario named no selected targets (node identity unasserted)".to_owned(),
        );
    }

    // Every REQUIRED assertion (per the independent contract, not the scenario's
    // own list) must be present, artifact-bound, and recompute true.
    let mut verified = Vec::new();
    for req in contract.required_assertions.iter().filter(|a| a.required) {
        let Some(record) = scenario.assertions.iter().find(|a| a.id == req.id) else {
            return Assessment::NotProven(
                ReasonCode::MissingWitness,
                format!("required assertion `{}` is absent from scenario.v1", req.id),
            );
        };

        // Validate + digest-bind each artifact. A swapped or mutated artifact
        // (recorded digest != actual) is unattributable.
        let mut validated: Vec<ValidatedArtifact> = Vec::new();
        for aref in &record.evidence {
            match artifact::validate_artifact(report_root, &aref.reference, max_artifact_bytes) {
                Ok(v) => {
                    if v.sha256 != aref.sha256 {
                        return Assessment::NotProven(
                            ReasonCode::Unattributable,
                            format!(
                                "artifact `{}` digest {} != recorded {}",
                                aref.reference, v.sha256, aref.sha256
                            ),
                        );
                    }
                    validated.push(v);
                }
                Err(e) => {
                    return Assessment::NotProven(ReasonCode::UnreadableEvidence, e.to_string());
                }
            }
        }
        if validated.is_empty() {
            return Assessment::NotProven(
                ReasonCode::MissingWitness,
                format!(
                    "required assertion `{}` carries no artifact evidence",
                    req.id
                ),
            );
        }

        // Recompute from the raw witnesses — never from the self-report.
        let Some(recompute) = recomputers.get(req.id) else {
            return Assessment::NotProven(
                ReasonCode::MissingWitness,
                format!(
                    "no independent recomputer registered for required assertion `{}`; \
                     cannot prove it",
                    req.id
                ),
            );
        };
        if let Err(reason) = recompute(record, &validated) {
            return Assessment::NotProven(
                ReasonCode::ContradictoryEvidence,
                format!(
                    "required assertion `{}` did not recompute: {reason}",
                    req.id
                ),
            );
        }
        verified.push(req.id.to_owned());
    }

    // A pass without cleanup is rejected; a failed residual check is a hard
    // taint, not a NotProven.
    if scenario.cleanup.is_empty() {
        return Assessment::NotProven(
            ReasonCode::MissingWitness,
            "scenario recorded no cleanup (a pass without cleanup is refused)".to_owned(),
        );
    }
    for c in &scenario.cleanup {
        if c.residual_check == ItemResult::Fail {
            return Assessment::Failed(format!(
                "cleanup `{}` left residue (residual check failed) — run tainted",
                c.action
            ));
        }
    }

    Assessment::Passed(PassCertificate {
        scenario_id: scenario.scenario_id.clone(),
        stage_id: scenario.stage_id.clone(),
        run_identity: scenario.run_identity.clone(),
        contract_digest: scenario.contract_digest.clone(),
        verified_assertions: verified,
        _seal: (),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::scenario::schema::{
        ArtifactRef, CleanupRecord, SelectedTarget,
    };
    use crate::vm_lab::orchestrator::stage::scenario::{AssertionClass, RequiredAssertion};
    use std::path::PathBuf;

    const RUN: &str = "run-abc";
    const CONTRACT_DIGEST: &str = "contract-xyz";

    fn temp_root(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "rustynet-passcert-test-{}-{tag}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn contract() -> ScenarioEvidenceContract {
        ScenarioEvidenceContract {
            contract_version: 1,
            required_assertions: vec![RequiredAssertion {
                id: "marked_payload",
                class: AssertionClass::Functional,
                required: true,
            }],
        }
    }

    /// A scenario that writes one artifact and references it by its real digest.
    fn scenario_with_artifact(root: &Path, contents: &[u8]) -> ScenarioV1 {
        std::fs::create_dir_all(root.join("state")).unwrap();
        std::fs::write(root.join("state/payload.txt"), contents).unwrap();
        let sha = crate::vm_lab::sha256_hex_bytes(contents);
        ScenarioV1 {
            schema_version: super::super::schema::SCENARIO_SCHEMA_VERSION,
            scenario_id: "s".to_owned(),
            stage_id: "st".to_owned(),
            contract_digest: CONTRACT_DIGEST.to_owned(),
            run_identity: RUN.to_owned(),
            selected_targets: vec![SelectedTarget {
                alias: "a".to_owned(),
                node_id: "n".to_owned(),
                role: "client".to_owned(),
                platform: "linux".to_owned(),
                os_version: String::new(),
            }],
            admission: vec![],
            baseline: vec![],
            fault: None,
            assertions: vec![AssertionRecord {
                id: "marked_payload".to_owned(),
                class: AssertionClass::Functional,
                required: true,
                result: ItemResult::Pass,
                evidence: vec![ArtifactRef {
                    reference: "state/payload.txt".to_owned(),
                    sha256: sha,
                }],
            }],
            cleanup: vec![CleanupRecord {
                action: "teardown".to_owned(),
                result: ItemResult::Pass,
                residual_check: ItemResult::Pass,
                evidence: vec![],
            }],
            limitations: vec![],
            terminal_outcome: "passed".to_owned(),
        }
    }

    fn passing_recomputers<'a>() -> HashMap<&'a str, &'a Recomputer<'a>> {
        // A recomputer that agrees the claim holds.
        static OK: fn(&AssertionRecord, &[ValidatedArtifact]) -> Result<(), String> = |_, _| Ok(());
        let mut m: HashMap<&str, &Recomputer> = HashMap::new();
        m.insert("marked_payload", &OK);
        m
    }

    #[test]
    fn all_gates_pass_mints_a_certificate() {
        let root = temp_root("pass");
        let s = scenario_with_artifact(&root, b"marker-42");
        let a = evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            RUN,
            1024,
            &passing_recomputers(),
        );
        match a {
            Assessment::Passed(cert) => {
                assert_eq!(cert.verified_assertions(), &["marked_payload".to_owned()]);
                assert_eq!(cert.run_identity(), RUN);
            }
            other => panic!("expected Passed, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_recomputer_is_not_proven_never_a_pass() {
        let root = temp_root("norecomp");
        let s = scenario_with_artifact(&root, b"x");
        let empty: HashMap<&str, &Recomputer> = HashMap::new();
        match evaluate(&root, &s, &contract(), CONTRACT_DIGEST, RUN, 1024, &empty) {
            Assessment::NotProven(ReasonCode::MissingWitness, d) => {
                assert!(d.contains("recomputer"), "{d}")
            }
            other => panic!("expected NotProven(MissingWitness), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_mutated_artifact_digest_is_rejected() {
        let root = temp_root("digest");
        let mut s = scenario_with_artifact(&root, b"real");
        // The scenario claims a different digest than the file actually has.
        s.assertions[0].evidence[0].sha256 = "0".repeat(64);
        match evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            RUN,
            1024,
            &passing_recomputers(),
        ) {
            Assessment::NotProven(ReasonCode::Unattributable, d) => {
                assert!(d.contains("digest"), "{d}")
            }
            other => panic!("expected NotProven(Unattributable), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_wrong_run_identity_is_stale() {
        let root = temp_root("gen");
        let s = scenario_with_artifact(&root, b"x");
        match evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            "a-different-run",
            1024,
            &passing_recomputers(),
        ) {
            Assessment::NotProven(ReasonCode::StaleEvidence, _) => {}
            other => panic!("expected NotProven(StaleEvidence), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_missing_required_assertion_is_not_proven() {
        let root = temp_root("missing");
        let mut s = scenario_with_artifact(&root, b"x");
        s.assertions.clear(); // drop the required assertion
        match evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            RUN,
            1024,
            &passing_recomputers(),
        ) {
            Assessment::NotProven(ReasonCode::MissingWitness, d) => {
                assert!(d.contains("marked_payload"), "{d}")
            }
            other => panic!("expected NotProven(MissingWitness), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_recomputer_that_refutes_yields_contradictory_not_proven() {
        let root = temp_root("refute");
        let s = scenario_with_artifact(&root, b"x");
        static NO: fn(&AssertionRecord, &[ValidatedArtifact]) -> Result<(), String> =
            |_, _| Err("marker not found in capture".to_owned());
        let mut m: HashMap<&str, &Recomputer> = HashMap::new();
        m.insert("marked_payload", &NO);
        match evaluate(&root, &s, &contract(), CONTRACT_DIGEST, RUN, 1024, &m) {
            Assessment::NotProven(ReasonCode::ContradictoryEvidence, d) => {
                assert!(d.contains("did not recompute"), "{d}")
            }
            other => panic!("expected NotProven(ContradictoryEvidence), got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pass_without_cleanup_is_refused() {
        let root = temp_root("nocleanup");
        let mut s = scenario_with_artifact(&root, b"x");
        s.cleanup.clear();
        match evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            RUN,
            1024,
            &passing_recomputers(),
        ) {
            Assessment::NotProven(ReasonCode::MissingWitness, d) => {
                assert!(d.contains("cleanup"), "{d}")
            }
            other => {
                panic!("expected NotProven(MissingWitness) for missing cleanup, got {other:?}")
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_failed_cleanup_residual_check_is_a_hard_failure() {
        let root = temp_root("residue");
        let mut s = scenario_with_artifact(&root, b"x");
        s.cleanup[0].residual_check = ItemResult::Fail;
        match evaluate(
            &root,
            &s,
            &contract(),
            CONTRACT_DIGEST,
            RUN,
            1024,
            &passing_recomputers(),
        ) {
            Assessment::Failed(d) => assert!(d.contains("residue"), "{d}"),
            other => panic!("expected Failed for residue, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&root);
    }
}
