#![allow(clippy::result_large_err)]

//! Adversarial self-audit proving RT-2's fix actually works: once a node is
//! `blind_exit`, EVERY other role transition attempt must be rejected at the
//! signed-membership-state layer, not merely refused by the CLI-facing
//! `transition_plan()` advisory planner.
//!
//! Companion of the orchestrator-side `evaluate_blind_exit_reversal_audit_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd blind-exit-reversal-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §6.D.2 — blind_exit is irreversible; the only way
//! out is factory reset plus fresh enrollment under a new identity.
//! `rustynet_control::role_presets::transition_plan` already refuses to
//! *construct* a `blind_exit -> X` transition, but that is a CLI-facing
//! advisory helper — nothing previously stopped a validly-signed
//! `SetNodeCapabilities` update from reversing blind_exit directly at the
//! membership-state layer (the same class of gap as RSA-0009/DD-03:
//! enforcement lived in a helper, not the trust boundary). The fix adds a
//! check inside `reduce_membership_state`'s `SetNodeCapabilities` arm.
//!
//! This audit drives the REAL shipped `preview_next_state` (which calls the
//! fixed reducer) in-process, synthetic state only:
//!   - 7 reversal cases (attempting to change a blind_exit node's
//!     capabilities to every other role's typical set) MUST be rejected;
//!   - 1 baseline case (a normal, non-blind_exit node's capability change)
//!     MUST still be accepted — proving this audit isn't vacuously
//!     "always reject" and that the fix didn't break ordinary role changes.
//!
//! It FAILs LOUD (non-zero exit) if any reversal case is accepted (the
//! regression this exists to catch) or the baseline case is wrongly denied.

use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipState, preview_next_state,
};
use rustynet_control::roles::RoleCapability;
use serde::{Deserialize, Serialize};

const BLIND_EXIT_REVERSAL_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_NETWORK_ID: &str = "blind-exit-reversal-audit-net";
const AUDIT_CREATED_AT_UNIX: u64 = 1_700_000_000;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindExitReversalAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the 7 reversal cases that were correctly REJECTED.
    pub reversal_denied: u32,
    /// Count of the 1 baseline case that was correctly ACCEPTED.
    pub baseline_accepted: u32,
    pub violations: Vec<BlindExitReversalCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlindExitReversalCaseResult {
    pub id: String,
    pub expectation: String,
    pub outcome: String,
    pub reason: String,
    pub passed: bool,
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn node(node_id: &str, pubkey_byte: u8, capabilities: Vec<RoleCapability>) -> MembershipNode {
    MembershipNode {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_lower(&[pubkey_byte; 32]),
        owner: "blind-exit-audit-owner@example.local".to_owned(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:servers".to_owned()],
        capabilities,
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

fn approver(id: &str, seed: u8, role: MembershipApproverRole) -> MembershipApprover {
    MembershipApprover {
        approver_id: id.to_owned(),
        approver_pubkey_hex: hex_lower(&[seed; 32]),
        role,
        status: MembershipApproverStatus::Active,
        created_at_unix: 100,
    }
}

/// A state with two nodes: `blind-exit-node` (already blind_exit) and
/// `regular-node` (an ordinary Anchor-capable node), so the baseline
/// (accept) case exercises a genuinely different, non-blind_exit target.
fn synthetic_state() -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: AUDIT_NETWORK_ID.to_owned(),
        epoch: 1,
        nodes: vec![
            node(
                "blind-exit-node",
                9,
                vec![RoleCapability::BlindExit, RoleCapability::ExitServer],
            ),
            node("regular-node", 10, vec![RoleCapability::Anchor]),
        ],
        approver_set: vec![
            approver("owner-1", 1, MembershipApproverRole::Owner),
            approver("guardian-1", 2, MembershipApproverRole::Guardian),
            approver("guardian-2", 3, MembershipApproverRole::Guardian),
        ],
        quorum_threshold: 2,
        metadata_hash: None,
    }
}

fn reversal_case(
    id: &str,
    target_capabilities: Vec<RoleCapability>,
) -> BlindExitReversalCaseResult {
    let state = synthetic_state();
    let operation = MembershipOperation::SetNodeCapabilities {
        node_id: "blind-exit-node".to_owned(),
        capabilities: target_capabilities,
    };
    match preview_next_state(&state, &operation, AUDIT_CREATED_AT_UNIX) {
        Ok(_) => BlindExitReversalCaseResult {
            id: id.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "ACCEPTED: blind_exit capabilities were reversed".to_owned(),
            passed: false,
        },
        Err(err) => {
            let reason = err.to_string();
            let matches = reason.to_lowercase().contains("blind_exit is immutable");
            BlindExitReversalCaseResult {
                id: id.to_owned(),
                expectation: "reject".to_owned(),
                outcome: "rejected".to_owned(),
                reason,
                passed: matches,
            }
        }
    }
}

fn baseline_case() -> BlindExitReversalCaseResult {
    let id = "non_blind_exit_capability_change_accepted";
    let state = synthetic_state();
    let operation = MembershipOperation::SetNodeCapabilities {
        node_id: "regular-node".to_owned(),
        capabilities: vec![RoleCapability::Client],
    };
    match preview_next_state(&state, &operation, AUDIT_CREATED_AT_UNIX) {
        Ok(next) => {
            let node = next.nodes.iter().find(|n| n.node_id == "regular-node");
            let applied = node.is_some_and(|n| n.capabilities == vec![RoleCapability::Client]);
            BlindExitReversalCaseResult {
                id: id.to_owned(),
                expectation: "accept".to_owned(),
                outcome: if applied {
                    "accepted".to_owned()
                } else {
                    "accepted_wrong_result".to_owned()
                },
                reason: "ACCEPTED: capability change applied".to_owned(),
                passed: applied,
            }
        }
        Err(err) => BlindExitReversalCaseResult {
            id: id.to_owned(),
            expectation: "accept".to_owned(),
            outcome: "rejected".to_owned(),
            reason: err.to_string(),
            passed: false,
        },
    }
}

pub fn run_blind_exit_reversal_audit() -> Result<BlindExitReversalAuditReport, String> {
    let results = [
        reversal_case("blind_exit_to_client_denied", vec![RoleCapability::Client]),
        reversal_case("blind_exit_to_admin_denied", vec![]),
        reversal_case(
            "blind_exit_to_regular_exit_denied",
            vec![RoleCapability::ExitServer],
        ),
        reversal_case(
            "blind_exit_to_relay_denied",
            vec![RoleCapability::RelayHost],
        ),
        reversal_case("blind_exit_to_anchor_denied", vec![RoleCapability::Anchor]),
        reversal_case("blind_exit_to_nas_denied", vec![RoleCapability::ServesNas]),
        reversal_case("blind_exit_to_llm_denied", vec![RoleCapability::ServesLlm]),
        baseline_case(),
    ];

    let reversal_denied = results
        .iter()
        .filter(|r| r.expectation == "reject" && r.passed)
        .count() as u32;
    let baseline_accepted = results
        .iter()
        .filter(|r| r.expectation == "accept" && r.passed)
        .count() as u32;
    let violations: Vec<BlindExitReversalCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(BlindExitReversalAuditReport {
        schema_version: BLIND_EXIT_REVERSAL_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        reversal_denied,
        baseline_accepted,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_fixed_reducer() {
        let report = run_blind_exit_reversal_audit().expect("audit runs");
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 8);
        assert_eq!(report.reversal_denied, 7);
        assert_eq!(report.baseline_accepted, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn every_reversal_case_is_individually_denied() {
        for target in [
            vec![RoleCapability::Client],
            vec![],
            vec![RoleCapability::ExitServer],
            vec![RoleCapability::RelayHost],
            vec![RoleCapability::Anchor],
            vec![RoleCapability::ServesNas],
            vec![RoleCapability::ServesLlm],
        ] {
            let result = reversal_case("case", target.clone());
            assert!(
                result.passed,
                "reversal to {target:?} must be denied: {result:?}"
            );
            assert_eq!(result.outcome, "rejected");
        }
    }

    #[test]
    fn baseline_case_is_accepted_not_vacuously_denied() {
        let result = baseline_case();
        assert!(
            result.passed,
            "a non-blind_exit capability change must still be accepted: {result:?}"
        );
        assert_eq!(result.outcome, "accepted");
    }
}
