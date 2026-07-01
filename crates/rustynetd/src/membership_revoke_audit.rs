#![allow(clippy::result_large_err)]

//! Adversarial self-audit proving RSA-0009's fix actually works: signed
//! Revoke/RotateKey/Restore/SetCapabilities updates must APPLY even when the
//! apply happens strictly later than the record's signed `created_at_unix`
//! (the realistic propose→sign→transport→apply gap that broke every one of
//! these four ops before the fix).
//!
//! Companion of the orchestrator-side `evaluate_membership_revoke_audit_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd membership-revoke-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.3 (signed control/trust-state mutation) — the
//! reducer [`rustynet_control::membership::reduce_membership_state`] used to
//! stamp `unix_now()` (apply time) into `updated_at_unix` for these four ops,
//! feeding a nondeterministic value into the state-root hash. The proposer
//! computes `new_state_root` at propose time (T); the applier recomputed it at
//! apply time (T+n); any T != T+n produced `NewStateRootMismatch` and the op
//! was rejected — revocation and key-rotation were non-functional in practice
//! (RSA-0009). The fix threads the signed record's own `created_at_unix`
//! through instead (see `apply_signed_update`).
//!
//! This audit drives the REAL shipped funnel, in-process, with synthetic keys
//! (touches no production key, file, or state):
//!   - four delayed-apply cases (Revoke/Restore/RotateKey/SetCapabilities),
//!     each signed at T and applied at T+5, MUST be accepted;
//!   - two negative cases (a tampered `new_state_root`, and a record replayed
//!     against a state it was not signed against) MUST be rejected — proving
//!     this audit isn't vacuously "always accept" and that state-root
//!     integrity still holds alongside the timing fix.
//!
//! It FAILs LOUD (non-zero exit) if any delayed-apply case is rejected (the
//! regression this exists to catch) or either negative case is wrongly
//! accepted (a broken/over-permissive fix).

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipSignature, MembershipState, MembershipUpdateRecord,
    SignedMembershipUpdate, apply_signed_update, preview_next_state, sign_update_record,
};
use rustynet_control::roles::RoleCapability;

const MEMBERSHIP_REVOKE_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_NETWORK_ID: &str = "revoke-audit-net";
/// Fixed "signed at" instant for every case — deterministic, not wall-clock.
const AUDIT_CREATED_AT_UNIX: u64 = 1_700_000_000;
/// Apply time strictly after `AUDIT_CREATED_AT_UNIX`. This gap is exactly what
/// broke the four ops pre-fix: propose→sign→transport→apply always takes >0s.
const AUDIT_APPLY_AT_UNIX: u64 = AUDIT_CREATED_AT_UNIX + 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRevokeAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the 4 delayed-apply cases (Revoke/Restore/RotateKey/
    /// SetCapabilities) that were correctly ACCEPTED.
    pub delayed_apply_accepted: u32,
    /// Count of the 2 negative cases that were correctly REJECTED.
    pub reject_cases_passed: u32,
    /// Cases whose outcome did not match expectation. Empty when overall_ok.
    pub violations: Vec<RevokeAuditCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeAuditCaseResult {
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

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pubkey_hex(seed: u8) -> String {
    hex_lower(key(seed).verifying_key().as_bytes())
}

fn approver(id: &str, seed: u8, role: MembershipApproverRole) -> MembershipApprover {
    MembershipApprover {
        approver_id: id.to_owned(),
        approver_pubkey_hex: pubkey_hex(seed),
        role,
        status: MembershipApproverStatus::Active,
        created_at_unix: 100,
    }
}

fn node(node_id: &str, pubkey_byte: u8, status: MembershipNodeStatus) -> MembershipNode {
    MembershipNode {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_lower(&[pubkey_byte; 32]),
        owner: "revoke-audit-owner@example.local".to_owned(),
        status,
        roles: vec!["tag:servers".to_owned()],
        capabilities: vec![RoleCapability::Anchor],
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

fn synthetic_state(node_status: MembershipNodeStatus) -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: AUDIT_NETWORK_ID.to_owned(),
        epoch: 1,
        nodes: vec![node("node-a", 9, node_status)],
        approver_set: vec![
            approver("owner-1", 1, MembershipApproverRole::Owner),
            approver("guardian-1", 2, MembershipApproverRole::Guardian),
            approver("guardian-2", 3, MembershipApproverRole::Guardian),
        ],
        quorum_threshold: 2,
        metadata_hash: None,
    }
}

fn quorum_signatures(record: &MembershipUpdateRecord) -> Result<Vec<MembershipSignature>, String> {
    Ok(vec![
        sign_update_record(record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?,
        sign_update_record(record, "guardian-1", &key(2))
            .map_err(|err| format!("guardian sign failed: {err}"))?,
    ])
}

/// Builds and signs a well-formed update: created at `AUDIT_CREATED_AT_UNIX`
/// against `state`, with a correctly-computed `new_state_root`.
fn build_signed_update(
    state: &MembershipState,
    operation: MembershipOperation,
    update_id: &str,
) -> Result<SignedMembershipUpdate, String> {
    let candidate = preview_next_state(state, &operation, AUDIT_CREATED_AT_UNIX)
        .map_err(|err| format!("preview_next_state failed for {update_id}: {err}"))?;
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: update_id.to_owned(),
        operation,
        target: "node-a".to_owned(),
        prev_state_root: state
            .state_root_hex()
            .map_err(|err| format!("prev state root failed: {err}"))?,
        new_state_root: candidate
            .state_root_hex()
            .map_err(|err| format!("new state root failed: {err}"))?,
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix: AUDIT_CREATED_AT_UNIX,
        expires_at_unix: AUDIT_CREATED_AT_UNIX + 600,
        reason_code: "revokeaudit".to_owned(),
        policy_context: None,
    };
    let approver_signatures = quorum_signatures(&record)?;
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures,
    })
}

fn build_failed_result(id: &str, reason: String) -> RevokeAuditCaseResult {
    RevokeAuditCaseResult {
        id: id.to_owned(),
        expectation: "reject".to_owned(),
        outcome: "build_failed".to_owned(),
        reason,
        passed: false,
    }
}

/// A delayed-apply case: sign at `AUDIT_CREATED_AT_UNIX`, apply at
/// `AUDIT_APPLY_AT_UNIX` (strictly later) against the SAME state it was
/// signed against. Must be ACCEPTED — this is the RSA-0009 regression proof.
fn delayed_apply_case(
    id: &str,
    state: &MembershipState,
    operation: MembershipOperation,
) -> RevokeAuditCaseResult {
    let signed = match build_signed_update(state, operation, id) {
        Ok(signed) => signed,
        Err(err) => {
            return RevokeAuditCaseResult {
                id: id.to_owned(),
                expectation: "accept".to_owned(),
                outcome: "build_failed".to_owned(),
                reason: err,
                passed: false,
            };
        }
    };
    let mut cache = MembershipReplayCache::default();
    match apply_signed_update(state, &signed, AUDIT_APPLY_AT_UNIX, &mut cache) {
        Ok(_) => RevokeAuditCaseResult {
            id: id.to_owned(),
            expectation: "accept".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "ACCEPTED: delayed apply succeeded".to_owned(),
            passed: true,
        },
        Err(err) => RevokeAuditCaseResult {
            id: id.to_owned(),
            expectation: "accept".to_owned(),
            outcome: "rejected".to_owned(),
            reason: err.to_string(),
            passed: false,
        },
    }
}

/// Negative case: a signed record whose `new_state_root` does NOT match what
/// re-deriving the operation actually produces (proposer lied, or a broader
/// regression that stopped checking state roots at all). Must still be
/// rejected with a state-root mismatch regardless of the RSA-0009 timing fix
/// — the fix must not have loosened this check.
fn tampered_new_state_root_case(state: &MembershipState) -> RevokeAuditCaseResult {
    let id = "tampered_new_state_root_rejected";
    let prev_root = match state.state_root_hex() {
        Ok(root) => root,
        Err(err) => return build_failed_result(id, format!("prev state root failed: {err}")),
    };
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: id.to_owned(),
        operation: MembershipOperation::RevokeNode {
            node_id: "node-a".to_owned(),
        },
        target: "node-a".to_owned(),
        // Deliberately wrong: claims the revoke left the state root
        // unchanged, which cannot be correct for a RevokeNode operation.
        new_state_root: prev_root.clone(),
        prev_state_root: prev_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix: AUDIT_CREATED_AT_UNIX,
        expires_at_unix: AUDIT_CREATED_AT_UNIX + 600,
        reason_code: "revokeaudit".to_owned(),
        policy_context: None,
    };
    let approver_signatures = match quorum_signatures(&record) {
        Ok(sigs) => sigs,
        Err(err) => return build_failed_result(id, err),
    };
    let signed = SignedMembershipUpdate {
        record,
        approver_signatures,
    };
    let mut cache = MembershipReplayCache::default();
    match apply_signed_update(state, &signed, AUDIT_APPLY_AT_UNIX, &mut cache) {
        Ok(_) => RevokeAuditCaseResult {
            id: id.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "ACCEPTED: verifier applied an update with a wrong new_state_root".to_owned(),
            passed: false,
        },
        Err(err) => {
            let reason = err.to_string();
            let matches = reason.to_lowercase().contains("state root");
            RevokeAuditCaseResult {
                id: id.to_owned(),
                expectation: "reject".to_owned(),
                outcome: "rejected".to_owned(),
                reason,
                passed: matches,
            }
        }
    }
}

/// Negative case: a validly-signed record built against `sign_against_state`
/// is replayed against a DIFFERENT current state (`apply_against_state`). Its
/// `prev_state_root` no longer matches the state it's being applied to, so it
/// must be rejected. Proves this audit harness can actually detect and
/// report a rejection — a harness bug that always reports "accepted"
/// regardless of the real outcome would fail this case (anti-vacuous).
fn stale_prev_state_root_case(
    sign_against_state: &MembershipState,
    apply_against_state: &MembershipState,
) -> RevokeAuditCaseResult {
    let id = "stale_prev_state_root_rejected";
    let operation = MembershipOperation::RestoreNode {
        node_id: "node-a".to_owned(),
    };
    let signed = match build_signed_update(sign_against_state, operation, id) {
        Ok(signed) => signed,
        Err(err) => return build_failed_result(id, err),
    };
    let mut cache = MembershipReplayCache::default();
    match apply_signed_update(
        apply_against_state,
        &signed,
        AUDIT_APPLY_AT_UNIX,
        &mut cache,
    ) {
        Ok(_) => RevokeAuditCaseResult {
            id: id.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "ACCEPTED: verifier applied a record signed against a stale state".to_owned(),
            passed: false,
        },
        Err(err) => {
            let reason = err.to_string();
            let matches = reason.to_lowercase().contains("state root");
            RevokeAuditCaseResult {
                id: id.to_owned(),
                expectation: "reject".to_owned(),
                outcome: "rejected".to_owned(),
                reason,
                passed: matches,
            }
        }
    }
}

pub fn run_membership_revoke_audit() -> Result<MembershipRevokeAuditReport, String> {
    let active_state = synthetic_state(MembershipNodeStatus::Active);
    let revoked_state = synthetic_state(MembershipNodeStatus::Revoked);

    let results = [
        delayed_apply_case(
            "revoke_delayed_apply",
            &active_state,
            MembershipOperation::RevokeNode {
                node_id: "node-a".to_owned(),
            },
        ),
        delayed_apply_case(
            "restore_delayed_apply",
            &revoked_state,
            MembershipOperation::RestoreNode {
                node_id: "node-a".to_owned(),
            },
        ),
        delayed_apply_case(
            "rotate_key_delayed_apply",
            &active_state,
            MembershipOperation::RotateNodeKey {
                node_id: "node-a".to_owned(),
                new_pubkey_hex: hex_lower(&[0xAB; 32]),
            },
        ),
        delayed_apply_case(
            "set_capabilities_delayed_apply",
            &active_state,
            MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: vec![RoleCapability::AnchorBundlePull],
            },
        ),
        tampered_new_state_root_case(&active_state),
        // Sign against revoked_state (where RestoreNode is valid), apply
        // against active_state (a different root) — proves stale-prev-root
        // rejection independent of the RSA-0009 timing fix.
        stale_prev_state_root_case(&revoked_state, &active_state),
    ];

    let delayed_apply_accepted = results
        .iter()
        .filter(|r| r.expectation == "accept" && r.passed)
        .count() as u32;
    let reject_cases_passed = results
        .iter()
        .filter(|r| r.expectation == "reject" && r.passed)
        .count() as u32;
    let violations: Vec<RevokeAuditCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(MembershipRevokeAuditReport {
        schema_version: MEMBERSHIP_REVOKE_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        delayed_apply_accepted,
        reject_cases_passed,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_shipped_reducer() {
        let report = run_membership_revoke_audit().expect("audit runs");
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 6);
        assert_eq!(report.delayed_apply_accepted, 4);
        assert_eq!(report.reject_cases_passed, 2);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn all_four_delayed_apply_ops_are_present_and_accepted() {
        let report = run_membership_revoke_audit().expect("audit runs");
        let accepted_ids: Vec<&str> = report.violations.iter().map(|v| v.id.as_str()).collect();
        assert!(
            accepted_ids.is_empty(),
            "expected zero violations among the delayed-apply ops, got: {accepted_ids:?}"
        );
    }

    #[test]
    fn tampered_new_state_root_is_rejected_not_silently_accepted() {
        let active_state = synthetic_state(MembershipNodeStatus::Active);
        let result = tampered_new_state_root_case(&active_state);
        assert!(
            result.passed,
            "a wrong new_state_root must be rejected: {result:?}"
        );
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn stale_prev_state_root_is_rejected_not_silently_accepted() {
        let active_state = synthetic_state(MembershipNodeStatus::Active);
        let revoked_state = synthetic_state(MembershipNodeStatus::Revoked);
        let result = stale_prev_state_root_case(&revoked_state, &active_state);
        assert!(
            result.passed,
            "a record replayed against a drifted state must be rejected: {result:?}"
        );
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn delayed_apply_case_reports_a_violation_when_the_op_is_rejected() {
        // Regression-detector sanity: if apply_signed_update ever goes back
        // to rejecting a delayed apply, this harness must report it as a
        // failure, not silently mark it accepted.
        let active_state = synthetic_state(MembershipNodeStatus::Active);
        // RestoreNode against an already-Active node is invalid at build
        // time (preview_next_state fails) — this exercises the
        // build_failed path and proves it's reported as a failure, not a
        // false pass.
        let result = delayed_apply_case(
            "restore_on_active_should_fail_to_build",
            &active_state,
            MembershipOperation::RestoreNode {
                node_id: "node-a".to_owned(),
            },
        );
        assert!(!result.passed, "an invalid op must not report passed=true");
        assert_eq!(result.outcome, "build_failed");
    }
}
