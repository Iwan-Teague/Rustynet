//! The independent scenario-contract registry (L1,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §2.4).
//!
//! The evidence verifier does NOT trust the assertion list or any boolean inside
//! a `scenario.v1`. Instead it looks the scenario's `stage_id` up here, gets the
//! INDEPENDENTLY-DEFINED [`StageContract`] (source-defined in [`canonical`], never
//! read from a run artifact), and recomputes exactly the required assertions that
//! contract names. A scenario whose `stage_id` is unknown, or whose
//! `contract_digest` does not equal the registered contract's digest, is bound to
//! a different (or no) contract and is rejected — it can never certify a pass.
//!
//! The digest is stable over the contract's identity — the stage id, the contract
//! version, and its required-assertion set — so a contract change bumps the digest
//! and a scenario recorded against the old contract no longer resolves. The scenario
//! schema carries `contract_digest` but no separate version field, so the digest
//! is the single binding: matching it proves the scenario was produced against
//! this exact contract version.

use std::collections::BTreeMap;

use super::schema::ScenarioV1;
use super::{
    AdmissionContract, AssertionClass, RequiredAssertion, ScenarioEvidenceContract, StageContract,
};

/// One stage's independently-defined contract, with its identity digest computed
/// at registration.
#[derive(Debug, Clone)]
pub struct RegisteredContract {
    stage_id: &'static str,
    contract: StageContract,
    digest: String,
}

impl RegisteredContract {
    fn new(stage_id: &'static str, contract: StageContract) -> Self {
        let digest = compute_contract_digest(stage_id, &contract);
        RegisteredContract {
            stage_id,
            contract,
            digest,
        }
    }

    pub fn stage_id(&self) -> &str {
        self.stage_id
    }

    pub fn contract(&self) -> &StageContract {
        &self.contract
    }

    /// The digest a faithful `scenario.v1.contract_digest` must equal.
    pub fn contract_digest(&self) -> &str {
        &self.digest
    }

    pub fn contract_version(&self) -> u32 {
        self.contract.evidence.contract_version
    }
}

/// Why a scenario could not be bound to a registered contract. Each is a typed
/// non-pass reason for the verifier — never softened to a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContractLookupError {
    /// The scenario's `stage_id` is not a registered scenario stage.
    UnknownStage(String),
    /// The scenario's `contract_digest` does not match the registered contract —
    /// it was produced against a different contract (or version).
    ContractDigestMismatch {
        stage_id: String,
        expected: String,
        got: String,
    },
}

impl std::fmt::Display for ContractLookupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractLookupError::UnknownStage(stage) => {
                write!(f, "no registered scenario contract for stage `{stage}`")
            }
            ContractLookupError::ContractDigestMismatch {
                stage_id,
                expected,
                got,
            } => write!(
                f,
                "scenario for stage `{stage_id}` carries contract_digest {got}, \
                 but the registered contract's digest is {expected}"
            ),
        }
    }
}

/// The registry the verifier consults. Constructed independently of any run
/// artifact (source of truth is [`ScenarioContractRegistry::canonical`]).
#[derive(Debug, Clone)]
pub struct ScenarioContractRegistry {
    by_stage: BTreeMap<&'static str, RegisteredContract>,
}

impl ScenarioContractRegistry {
    fn from_contracts(contracts: Vec<RegisteredContract>) -> Self {
        let mut by_stage = BTreeMap::new();
        for contract in contracts {
            by_stage.insert(contract.stage_id, contract);
        }
        ScenarioContractRegistry { by_stage }
    }

    /// The canonical registry: every scenario stage's independently-defined
    /// contract. This is the verifier's source of truth. New scenario stages add
    /// their contract here as they are wired to emit `scenario.v1`.
    pub fn canonical() -> Self {
        Self::from_contracts(vec![
            RegisteredContract::new(
                "negative_control_signed_bundle_rejection",
                signed_bundle_rejection_contract(),
            ),
            RegisteredContract::new(
                "negative_control_wrong_node_substitution",
                wrong_node_substitution_contract(),
            ),
        ])
    }

    pub fn lookup(&self, stage_id: &str) -> Option<&RegisteredContract> {
        self.by_stage.get(stage_id)
    }

    /// Resolve a `scenario.v1` to its registered contract, enforcing that the
    /// stage is known and the scenario is bound to this exact contract (digest
    /// match). The returned contract is what the verifier recomputes against —
    /// never the scenario's own assertion list.
    pub fn resolve_for(
        &self,
        scenario: &ScenarioV1,
    ) -> Result<&RegisteredContract, ContractLookupError> {
        let registered = self
            .lookup(&scenario.stage_id)
            .ok_or_else(|| ContractLookupError::UnknownStage(scenario.stage_id.clone()))?;
        if scenario.contract_digest != registered.digest {
            return Err(ContractLookupError::ContractDigestMismatch {
                stage_id: scenario.stage_id.clone(),
                expected: registered.digest.clone(),
                got: scenario.contract_digest.clone(),
            });
        }
        Ok(registered)
    }
}

/// Stable SHA-256 over the contract's identity: `stage_id`, contract version, and
/// each required-assertion `(id, class, required)` in a canonical sorted order.
/// Independent of admission (admission gates whether the scenario runs, not what
/// it must prove) and of field ordering.
fn compute_contract_digest(stage_id: &str, contract: &StageContract) -> String {
    let mut lines: Vec<String> = contract
        .evidence
        .required_assertions
        .iter()
        .map(|a| format!("{}|{}|{}", a.id, a.class.as_str(), a.required))
        .collect();
    lines.sort();
    let canonical = format!(
        "scenario-contract\nstage={stage_id}\nversion={}\n{}",
        contract.evidence.contract_version,
        lines.join("\n")
    );
    crate::vm_lab::sha256_hex_bytes(canonical.as_bytes())
}

// ── The initial registered contracts (the two local, in-proc T5 controls) ──
// The live-guest controls (planted_residue, daemon_kill) register their contracts
// when their live scenario.v1 emission is wired.

fn signed_bundle_rejection_contract() -> StageContract {
    StageContract {
        // In-process crypto against a forged-bundle corpus — no live participant.
        admission: AdmissionContract::default(),
        evidence: ScenarioEvidenceContract {
            contract_version: 1,
            required_assertions: vec![RequiredAssertion {
                id: "signed_bundle_forgery_rejected",
                class: AssertionClass::Security,
                required: true,
            }],
        },
    }
}

fn wrong_node_substitution_contract() -> StageContract {
    StageContract {
        admission: AdmissionContract::default(),
        evidence: ScenarioEvidenceContract {
            contract_version: 1,
            required_assertions: vec![RequiredAssertion {
                id: "wrong_node_substitution_rejected",
                class: AssertionClass::Identity,
                required: true,
            }],
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::scenario::schema::SCENARIO_SCHEMA_VERSION;

    fn scenario_for(stage_id: &str, contract_digest: &str) -> ScenarioV1 {
        ScenarioV1 {
            schema_version: SCENARIO_SCHEMA_VERSION,
            scenario_id: "s".to_owned(),
            stage_id: stage_id.to_owned(),
            contract_digest: contract_digest.to_owned(),
            run_identity: "run-1".to_owned(),
            selected_targets: vec![],
            admission: vec![],
            baseline: vec![],
            fault: None,
            assertions: vec![],
            cleanup: vec![],
            limitations: vec![],
            terminal_outcome: "passed".to_owned(),
        }
    }

    #[test]
    fn a_faithful_scenario_resolves_to_its_registered_contract() {
        let registry = ScenarioContractRegistry::canonical();
        let registered = registry
            .lookup("negative_control_signed_bundle_rejection")
            .expect("registered");
        let scenario = scenario_for(
            "negative_control_signed_bundle_rejection",
            registered.contract_digest(),
        );
        let resolved = registry.resolve_for(&scenario).expect("resolves");
        assert_eq!(
            resolved.stage_id(),
            "negative_control_signed_bundle_rejection"
        );
        assert_eq!(resolved.contract_version(), 1);
    }

    #[test]
    fn an_unknown_stage_id_is_rejected() {
        let registry = ScenarioContractRegistry::canonical();
        let scenario = scenario_for("some_unregistered_stage", "whatever");
        assert_eq!(
            registry.resolve_for(&scenario).unwrap_err(),
            ContractLookupError::UnknownStage("some_unregistered_stage".to_owned())
        );
    }

    #[test]
    fn a_wrong_contract_digest_is_rejected() {
        let registry = ScenarioContractRegistry::canonical();
        // Correct stage, but a digest that does not match the registered contract
        // — the scenario was produced against a different contract/version.
        let scenario = scenario_for("negative_control_wrong_node_substitution", &"0".repeat(64));
        match registry.resolve_for(&scenario).unwrap_err() {
            ContractLookupError::ContractDigestMismatch { stage_id, got, .. } => {
                assert_eq!(stage_id, "negative_control_wrong_node_substitution");
                assert_eq!(got, "0".repeat(64));
            }
            other => panic!("expected ContractDigestMismatch, got {other:?}"),
        }
    }

    #[test]
    fn contract_digests_are_stable_and_distinct_per_stage() {
        // Stable across calls (deterministic), and distinct between two contracts
        // with different required-assertion sets.
        let a = ScenarioContractRegistry::canonical();
        let b = ScenarioContractRegistry::canonical();
        let signed_a = a
            .lookup("negative_control_signed_bundle_rejection")
            .unwrap();
        let signed_b = b
            .lookup("negative_control_signed_bundle_rejection")
            .unwrap();
        assert_eq!(signed_a.contract_digest(), signed_b.contract_digest());
        let wrong = a
            .lookup("negative_control_wrong_node_substitution")
            .unwrap();
        assert_ne!(
            signed_a.contract_digest(),
            wrong.contract_digest(),
            "distinct contracts must have distinct digests"
        );
        assert_eq!(signed_a.contract_digest().len(), 64, "sha-256 hex");
    }

    #[test]
    fn a_contract_version_bump_changes_the_digest() {
        // The digest binds the version, so an old scenario cannot resolve against
        // a bumped contract.
        let v1 = compute_contract_digest("s", &signed_bundle_rejection_contract());
        let mut bumped = signed_bundle_rejection_contract();
        bumped.evidence.contract_version = 2;
        let v2 = compute_contract_digest("s", &bumped);
        assert_ne!(v1, v2);
    }
}
