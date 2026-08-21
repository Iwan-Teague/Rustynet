//! Scenario contracts — the typed admission + evidence requirements a live-lab
//! scenario declares (L0.3 of the truth-preserving framework,
//! `LiveLabTestCoverageImplementationDesign_2026-08-19` §2.4 / §3.1 / §3.3).
//!
//! This is the FRAMEWORK layer, not per-stage content. It provides:
//!   * [`AdmissionContract`] + [`AdmissionContract::evaluate`] — the typed,
//!     pre-mutation verdict that decides whether a scenario's required
//!     participants are present, and classifies an absence as a legitimate
//!     profile omission (`Skipped`) or a missing required capability in a cell
//!     that claims it (`NotProven`) — never a silent pass (§3.1 / §2.2);
//!   * [`AssertionClass`] — the fixed vocabulary of what KIND of proof each
//!     scenario assertion carries, so the verifier recomputes it from the right
//!     raw witnesses (§3.3);
//!   * [`ScenarioEvidenceContract`] + [`StageContract`] — the shape a scenario
//!     stage attaches (which the verifier consults independently of anything the
//!     scenario self-reports). The recomputation itself, and the `scenario.v1`
//!     parser it consumes, land in L0.5 — this slice fixes the contract types.
//!
//! Deliberately does NOT enumerate a contract for every existing `StageId`: old
//! stages are migrated only when their own contract is reviewed (§2.1). The set
//! of contracted scenarios starts empty and grows as scenarios adopt it.
#![allow(dead_code)] // consumed by the scenario evaluator + verifier in L0.4/L0.5

pub mod artifact;
pub mod finalize;
pub mod pass_certificate;
pub mod registry;
pub mod schema;
pub mod verdict;

use crate::vm_lab::VmGuestPlatform;
use crate::vm_lab::orchestrator::error::ReasonCode;
use crate::vm_lab::orchestrator::role::NodeRole;

/// The class of a scenario assertion — fixes what KIND of proof it carries so
/// the verifier recomputes it from the right raw witnesses (§3.3). A scenario
/// cannot self-report an assertion true; the class routes it to a recomputation.
///
/// The serde tokens are snake_case and match [`AssertionClass::as_str`] exactly,
/// so the `scenario.v1` on-disk form and the in-code token never drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertionClass {
    /// Proves the intended node identity was exercised (expected-node-id
    /// challenge), not merely that a name was logged.
    Identity,
    /// Proves a trust/leak/firewall/ACL control held (never from daemon
    /// self-report alone).
    Security,
    /// Proves the functional claim (marked payload received, counter delta, …).
    Functional,
    /// Proves a component was alive/reachable at the moment of the claim.
    Liveness,
    /// A recorded measurement (throughput, latency); never on its own a pass.
    PerformanceMeasurement,
    /// Proves teardown removed residue (residual-state check).
    Cleanup,
}

impl AssertionClass {
    /// Stable snake_case token recorded in `scenario.v1` and parsed by the
    /// verifier. Never localize.
    pub fn as_str(self) -> &'static str {
        match self {
            AssertionClass::Identity => "identity",
            AssertionClass::Security => "security",
            AssertionClass::Functional => "functional",
            AssertionClass::Liveness => "liveness",
            AssertionClass::PerformanceMeasurement => "performance_measurement",
            AssertionClass::Cleanup => "cleanup",
        }
    }

    /// Every class, for totality checks.
    pub const ALL: [AssertionClass; 6] = [
        AssertionClass::Identity,
        AssertionClass::Security,
        AssertionClass::Functional,
        AssertionClass::Liveness,
        AssertionClass::PerformanceMeasurement,
        AssertionClass::Cleanup,
    ];
}

/// One participant available to a run: a node with a role and a platform. The
/// caller (the plan/admission step, L0.4) adapts the run's real node assignments
/// into these before evaluating a contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdmissionParticipant {
    pub node_id: String,
    pub role: NodeRole,
    pub platform: VmGuestPlatform,
}

/// The typed admission requirement a scenario declares, evaluated BEFORE any
/// mutation (§3.1). A stage's `applies_to_roles()` says which roles it acts on;
/// this says how many of which roles/platforms must actually be PRESENT, so an
/// empty or under-provisioned topology can never reach the scenario body and
/// pass by vacuity.
#[derive(Debug, Clone, Default)]
pub struct AdmissionContract {
    /// Roles that must each be present at least once. Empty = no role gate.
    pub required_roles: Vec<NodeRole>,
    /// Platforms that must each be present at least once. Empty = no platform gate.
    pub required_platforms: Vec<VmGuestPlatform>,
    /// Minimum number of distinct participants the scenario exercises. A
    /// participant-exercising scenario sets this `>= 1` so an empty set can
    /// never be admitted (§3.1: "Empty participant sets never pass a stage
    /// intended to exercise participants").
    pub min_participants: usize,
}

/// The pre-mutation admission verdict. Only [`AdmissionVerdict::Admitted`] runs
/// the scenario body; the others are terminal non-pass outcomes carrying WHY.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionVerdict {
    /// Required participants present — run the scenario.
    Admitted,
    /// The selected profile legitimately does not claim this scenario (e.g. a
    /// Linux-only `tc`/`netem` fault while the selected cell is a macOS
    /// lifecycle cell). Visible non-green, never a pass, never counts toward a
    /// release cell — but not a defect.
    Skipped(String),
    /// A required participant/capability is ABSENT in a cell that CLAIMS this
    /// scenario — the exact claim cannot be proven. A blocking non-pass, never
    /// softened to `Skipped` (§2.2).
    NotProven(ReasonCode, String),
}

impl AdmissionContract {
    /// Evaluate admission against the run's actual participants.
    ///
    /// `cell_claims_scenario` distinguishes the two absence meanings (§2.2):
    /// when a release-selected cell claims this scenario, a missing required
    /// participant is `NotProven` (the claim is unproven); when the selected
    /// profile does not claim it, the same absence is a legitimate `Skipped`.
    /// Presence of all requirements is always `Admitted`, regardless of the
    /// flag.
    pub fn evaluate(
        &self,
        participants: &[AdmissionParticipant],
        cell_claims_scenario: bool,
    ) -> AdmissionVerdict {
        let mut missing: Vec<String> = Vec::new();

        if participants.len() < self.min_participants {
            missing.push(format!(
                "needs >= {} participant(s), have {}",
                self.min_participants,
                participants.len()
            ));
        }
        for role in &self.required_roles {
            if !participants.iter().any(|p| &p.role == role) {
                missing.push(format!("no participant with role `{}`", role.as_str()));
            }
        }
        for platform in &self.required_platforms {
            if !participants.iter().any(|p| &p.platform == platform) {
                missing.push(format!("no participant on platform {platform:?}"));
            }
        }

        if missing.is_empty() {
            return AdmissionVerdict::Admitted;
        }

        let detail = missing.join("; ");
        if cell_claims_scenario {
            AdmissionVerdict::NotProven(ReasonCode::RequiredCapabilityAbsent, detail)
        } else {
            AdmissionVerdict::Skipped(detail)
        }
    }
}

/// One assertion a scenario's evidence contract requires. The verifier
/// recomputes each `required` assertion from raw witnesses (L0.5); a scenario
/// cannot self-report it true.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredAssertion {
    /// Stable id, matched against the `scenario.v1` assertion list.
    pub id: &'static str,
    pub class: AssertionClass,
    /// True if this assertion MUST be present and independently verified for a
    /// `PassCertificate`. A `false` assertion is optional supporting evidence.
    pub required: bool,
}

/// The evidence a scenario must produce for its exact claim (§2.4 / §3.3). Fixes
/// the required assertion ids and their classes, plus a contract version, so the
/// verifier knows exactly what to recompute — it never trusts an assertion list
/// inside `scenario.v1`.
#[derive(Debug, Clone)]
pub struct ScenarioEvidenceContract {
    /// Bumped when the required-assertion set changes; the verifier rejects an
    /// unknown contract version rather than guessing (§3.3).
    pub contract_version: u32,
    pub required_assertions: Vec<RequiredAssertion>,
}

impl ScenarioEvidenceContract {
    /// The ids that MUST be present and verified for a pass — the verifier's
    /// cardinality check derives from this, not from the scenario file.
    pub fn required_ids(&self) -> Vec<&'static str> {
        self.required_assertions
            .iter()
            .filter(|a| a.required)
            .map(|a| a.id)
            .collect()
    }
}

/// A scenario stage's full contract: what must be present to run it (admission)
/// and what it must prove (evidence). Attached by the scenario stage; consulted
/// independently by the verifier.
#[derive(Debug, Clone)]
pub struct StageContract {
    pub admission: AdmissionContract,
    pub evidence: ScenarioEvidenceContract,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn participant(
        node_id: &str,
        role: NodeRole,
        platform: VmGuestPlatform,
    ) -> AdmissionParticipant {
        AdmissionParticipant {
            node_id: node_id.to_owned(),
            role,
            platform,
        }
    }

    #[test]
    fn assertion_class_tokens_are_stable_distinct_and_total() {
        let mut seen = std::collections::HashSet::new();
        for class in AssertionClass::ALL {
            assert!(
                seen.insert(class.as_str()),
                "duplicate assertion-class token"
            );
        }
        assert_eq!(seen.len(), 6, "ALL must cover every class exactly once");
        assert_eq!(AssertionClass::Identity.as_str(), "identity");
        assert_eq!(
            AssertionClass::PerformanceMeasurement.as_str(),
            "performance_measurement"
        );
        // The serde token must equal `as_str` for EVERY variant, so the
        // scenario.v1 on-disk form and the in-code token can never drift (the
        // multi-word variant is the real risk).
        for class in AssertionClass::ALL {
            let serde_token = serde_json::to_value(class)
                .unwrap()
                .as_str()
                .unwrap()
                .to_owned();
            assert_eq!(
                serde_token,
                class.as_str(),
                "serde token must match as_str for {class:?}"
            );
        }
    }

    #[test]
    fn empty_participant_set_is_never_admitted() {
        let contract = AdmissionContract {
            required_roles: vec![NodeRole::Relay],
            required_platforms: vec![],
            min_participants: 2,
        };
        // A cell that claims the scenario but has no participants: NotProven,
        // never Admitted, never Skipped.
        match contract.evaluate(&[], true) {
            AdmissionVerdict::NotProven(ReasonCode::RequiredCapabilityAbsent, _) => {}
            other => panic!("empty claimed cell must be NotProven, got {other:?}"),
        }
        // The same emptiness under a profile that does not claim it: Skipped.
        assert!(matches!(
            contract.evaluate(&[], false),
            AdmissionVerdict::Skipped(_)
        ));
    }

    #[test]
    fn all_requirements_present_admits_regardless_of_claim_flag() {
        let contract = AdmissionContract {
            required_roles: vec![NodeRole::Relay, NodeRole::Client],
            required_platforms: vec![VmGuestPlatform::Linux],
            min_participants: 2,
        };
        let participants = vec![
            participant("n1", NodeRole::Relay, VmGuestPlatform::Linux),
            participant("n2", NodeRole::Client, VmGuestPlatform::Linux),
        ];
        assert_eq!(
            contract.evaluate(&participants, true),
            AdmissionVerdict::Admitted
        );
        assert_eq!(
            contract.evaluate(&participants, false),
            AdmissionVerdict::Admitted
        );
    }

    #[test]
    fn missing_required_role_in_a_claimed_cell_is_not_proven_not_skipped() {
        let contract = AdmissionContract {
            required_roles: vec![NodeRole::Exit],
            required_platforms: vec![],
            min_participants: 1,
        };
        // Have a participant, but not the required Exit role.
        let participants = vec![participant("n1", NodeRole::Client, VmGuestPlatform::Linux)];
        match contract.evaluate(&participants, true) {
            AdmissionVerdict::NotProven(ReasonCode::RequiredCapabilityAbsent, detail) => {
                assert!(
                    detail.contains("exit"),
                    "detail names the missing role: {detail}"
                );
            }
            other => {
                panic!("missing required role in a claimed cell must be NotProven, got {other:?}")
            }
        }
    }

    #[test]
    fn platform_absent_under_unclaimed_profile_is_skipped() {
        // A macOS-only requirement while the selected profile does not claim it
        // (a Linux-only cell): a legitimate Skipped, not a defect.
        let contract = AdmissionContract {
            required_roles: vec![],
            required_platforms: vec![VmGuestPlatform::Macos],
            min_participants: 1,
        };
        let participants = vec![participant("n1", NodeRole::Client, VmGuestPlatform::Linux)];
        assert!(matches!(
            contract.evaluate(&participants, false),
            AdmissionVerdict::Skipped(_)
        ));
    }

    #[test]
    fn required_ids_returns_only_required_assertions() {
        let contract = ScenarioEvidenceContract {
            contract_version: 1,
            required_assertions: vec![
                RequiredAssertion {
                    id: "identity_challenge",
                    class: AssertionClass::Identity,
                    required: true,
                },
                RequiredAssertion {
                    id: "throughput_sample",
                    class: AssertionClass::PerformanceMeasurement,
                    required: false,
                },
                RequiredAssertion {
                    id: "marked_payload",
                    class: AssertionClass::Functional,
                    required: true,
                },
            ],
        };
        assert_eq!(
            contract.required_ids(),
            vec!["identity_challenge", "marked_payload"]
        );
    }
}
