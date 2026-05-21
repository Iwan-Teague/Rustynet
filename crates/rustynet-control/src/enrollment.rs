#![forbid(unsafe_code)]

//! D2.7 — Enrollment-to-membership bridge.
//!
//! After the operator on an existing peer consumes a fresh
//! enrollment token presented by a new device, the new device must
//! be folded into the signed membership snapshot so the rest of the
//! mesh learns about its identity. Without that step the new device
//! is reachable from the existing peer (via the gossip-routing
//! registration in `enrollment_consume`) but invisible to every
//! other peer, which is the trust-propagation gap the user wants
//! closed.
//!
//! This module is the bridge: given the current snapshot and the
//! enrollee's identity, [`build_add_node_record_for_enrollee`]
//! produces an unsigned [`MembershipUpdateRecord`] for an `AddNode`
//! operation. The operator then runs the existing
//! `sign-update` → `apply-update` membership flow (or the new
//! one-shot `rustynet enrollment admit` CLI verb which does both at
//! once when quorum is achievable in a single signature).
//!
//! Security framing:
//!
//! * The membership update produced here carries no signatures.
//!   It MUST be signed by enough approvers to meet
//!   `state.quorum_threshold` before it can be applied. The existing
//!   apply-update path enforces this; we do not relax it.
//! * The enrollee's verifying key is taken at face value — that is
//!   the same trust model as every other AddNode update, which is
//!   sanctioned by the approvers signing the membership update.
//!   We do NOT pretend the token consumes provides additional
//!   approver-grade trust; the approver(s) doing the signing are
//!   the trust authority.
//! * The reducer-preview is the existing public `preview_next_state`
//!   helper — we never bypass the reducer or shortcut the state-
//!   root computation. A misconfigured reason code or owner would
//!   still produce a record that round-trips through
//!   `apply_signed_update`.

use crate::membership::{
    MembershipError, MembershipNode, MembershipNodeStatus, MembershipOperation, MembershipState,
    MembershipUpdateRecord, preview_next_state,
};

/// Default time-to-live for a freshly-built AddNode update. Mirrors
/// the membership Propose CLI's default TTL — long enough to walk
/// an operator through co-signing if quorum > 1, short enough that
/// a stale update doesn't sit around indefinitely.
pub const DEFAULT_ADMIT_UPDATE_TTL_SECS: u64 = 60 * 60;

/// Construction-time inputs for [`build_add_node_record_for_enrollee`].
/// Distinct struct (rather than a long argument list) so the call
/// site is readable and a future field addition stays additive at
/// the call site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrolleeAdmitContext {
    /// Logical node id the enrollee will carry in the membership
    /// snapshot (e.g. "minipc-2"). Must not collide with an existing
    /// node id; the reducer rejects duplicates with
    /// `InvalidTransition`.
    pub node_id: String,
    /// Enrollee's 32-byte Ed25519 verifying key, hex-encoded
    /// lowercase. The reducer rejects non-32-byte values.
    pub node_pubkey_hex: String,
    /// Free-form owner identifier — typically the operator's
    /// principal name, but the membership schema doesn't constrain
    /// it. Surfaced in the canonical update payload.
    pub owner: String,
    /// Roles the enrollee will carry. Empty vec is a legitimate
    /// "client peer with no special privileges" entry.
    pub roles: Vec<String>,
    /// Unique update id (e.g. UUID-style). The replay cache refuses
    /// a second update with the same id under the same epoch.
    pub update_id: String,
    /// Reason code for the audit log (e.g.
    /// `enrollment.token_consume.v1`). Free-form but stable so
    /// downstream audit tooling can group identical-shape updates.
    pub reason_code: String,
    /// Optional policy context — currently passed through verbatim
    /// into the canonical payload.
    pub policy_context: Option<String>,
    /// Wall-clock now in unix seconds, used for `created_at_unix`
    /// and to compute `expires_at_unix`.
    pub now_unix: u64,
    /// TTL window for the produced update. The membership Propose
    /// default is one hour; admit defaults to the same.
    pub ttl_secs: u64,
}

/// Errors specific to the enrollment-to-membership bridge. Most
/// failures funnel into the underlying `MembershipError` variants;
/// this enum adds a single new variant for the "ttl_secs is zero"
/// case so the call site can produce a typed reject without
/// reaching for `InvalidFormat`.
#[derive(Debug)]
pub enum EnrollmentMembershipError {
    /// Caller passed `ttl_secs = 0` — the resulting update would
    /// have `expires_at_unix <= created_at_unix` which the
    /// canonical-payload validator already rejects, but failing
    /// earlier with a clearer diagnostic is friendlier.
    TtlMustBePositive,
    /// Underlying membership reducer / validation error.
    Membership(MembershipError),
}

impl std::fmt::Display for EnrollmentMembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnrollmentMembershipError::TtlMustBePositive => {
                write!(f, "admit update ttl_secs must be > 0")
            }
            EnrollmentMembershipError::Membership(err) => {
                write!(f, "membership bridge failed: {err}")
            }
        }
    }
}

impl std::error::Error for EnrollmentMembershipError {}

impl From<MembershipError> for EnrollmentMembershipError {
    fn from(err: MembershipError) -> Self {
        EnrollmentMembershipError::Membership(err)
    }
}

/// Build an unsigned `AddNode` [`MembershipUpdateRecord`] that adds
/// `ctx.node_id` (with `ctx.node_pubkey_hex` and `ctx.owner`) to the
/// snapshot. The record's `prev_state_root` and `new_state_root` are
/// computed from `state` using the same reducer the apply path uses,
/// so a signature gathered against this record will validate when
/// `apply_signed_update` runs.
///
/// The caller's responsibility:
///
/// 1. Sign the returned record with one or more approver keys (the
///    existing `sign_update_record` helper).
/// 2. Verify quorum: count signatures against `state.quorum_threshold`.
/// 3. Run the existing `apply_signed_update` → `append_membership_log_entry`
///    → `persist_membership_snapshot` flow when quorum is met.
pub fn build_add_node_record_for_enrollee(
    state: &MembershipState,
    ctx: EnrolleeAdmitContext,
) -> Result<MembershipUpdateRecord, EnrollmentMembershipError> {
    if ctx.ttl_secs == 0 {
        return Err(EnrollmentMembershipError::TtlMustBePositive);
    }
    let now_unix = ctx.now_unix;
    let expires_at_unix = now_unix.saturating_add(ctx.ttl_secs);
    let candidate_node = MembershipNode {
        node_id: ctx.node_id.clone(),
        node_pubkey_hex: ctx.node_pubkey_hex.clone(),
        owner: ctx.owner.clone(),
        status: MembershipNodeStatus::Active,
        roles: ctx.roles,
        joined_at_unix: now_unix,
        updated_at_unix: now_unix,
    };
    let operation = MembershipOperation::AddNode(candidate_node);
    let prev_state_root = state
        .state_root_hex()
        .map_err(EnrollmentMembershipError::from)?;
    let next = preview_next_state(state, &operation).map_err(EnrollmentMembershipError::from)?;
    let new_state_root = next
        .state_root_hex()
        .map_err(EnrollmentMembershipError::from)?;
    Ok(MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: ctx.update_id,
        operation,
        target: ctx.node_id,
        prev_state_root,
        new_state_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch.saturating_add(1),
        created_at_unix: now_unix,
        expires_at_unix,
        reason_code: ctx.reason_code,
        policy_context: ctx.policy_context,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::membership::{
        MembershipApprover, MembershipApproverRole, MembershipApproverStatus,
        MembershipReplayCache, MembershipSignature, SignedMembershipUpdate, apply_signed_update,
    };
    use ed25519_dalek::{Signer, SigningKey};

    fn approver_signing_key(byte: u8) -> SigningKey {
        SigningKey::from_bytes(&[byte; 32])
    }

    fn hex_lower(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    fn base_state() -> MembershipState {
        let owner_key = approver_signing_key(0x40);
        let owner_pubkey = owner_key.verifying_key().to_bytes();
        // Need at least one existing node so the state is realistic;
        // the enrollee will be the second.
        let founder_key = approver_signing_key(0x41);
        let founder_pubkey = founder_key.verifying_key().to_bytes();
        let state = MembershipState {
            schema_version: 1,
            network_id: "test-net".to_owned(),
            epoch: 1,
            nodes: vec![MembershipNode {
                node_id: "founder".to_owned(),
                node_pubkey_hex: hex_lower(&founder_pubkey),
                owner: "alice".to_owned(),
                status: MembershipNodeStatus::Active,
                roles: vec!["admin".to_owned()],
                joined_at_unix: 1_700_000_000,
                updated_at_unix: 1_700_000_000,
            }],
            approver_set: vec![MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex_lower(&owner_pubkey),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            }],
            quorum_threshold: 1,
            metadata_hash: None,
        };
        state.validate().expect("base state is valid");
        state
    }

    #[test]
    fn build_add_node_record_round_trips_through_apply_signed_update() {
        // Pin the full bridge: build the record under the current
        // snapshot, sign it with a quorum of approver keys, then
        // hand the signed update to the existing apply_signed_update
        // path. The resulting state MUST contain the enrollee as an
        // Active node.
        let state = base_state();
        let enrollee_key = approver_signing_key(0xc3);
        let enrollee_pubkey = enrollee_key.verifying_key().to_bytes();
        let now_unix = 1_700_000_500u64;
        let ctx = EnrolleeAdmitContext {
            node_id: "minipc-2".to_owned(),
            node_pubkey_hex: hex_lower(&enrollee_pubkey),
            owner: "alice".to_owned(),
            roles: vec!["client".to_owned()],
            update_id: "test-update-0001".to_owned(),
            reason_code: "enrollment.token_consume.v1".to_owned(),
            policy_context: None,
            now_unix,
            ttl_secs: 3600,
        };
        let record = build_add_node_record_for_enrollee(&state, ctx)
            .expect("build_add_node_record succeeds");
        assert_eq!(record.epoch_prev, 1);
        assert_eq!(record.epoch_new, 2);
        assert_eq!(record.target, "minipc-2");

        // Sign the record with the owner's approver key.
        let owner_key = approver_signing_key(0x40);
        let payload = record.canonical_payload().expect("payload");
        let signature = owner_key.sign(payload.as_bytes());
        let signed = SignedMembershipUpdate {
            record,
            approver_signatures: vec![MembershipSignature {
                approver_id: "owner-1".to_owned(),
                signature_hex: hex_lower(&signature.to_bytes()),
            }],
        };

        let mut replay = MembershipReplayCache::default();
        let next =
            apply_signed_update(&state, &signed, now_unix, &mut replay).expect("apply succeeds");
        assert_eq!(next.epoch, 2);
        assert!(
            next.nodes.iter().any(|n| n.node_id == "minipc-2"),
            "post-apply state must contain the enrollee"
        );
        let added = next.nodes.iter().find(|n| n.node_id == "minipc-2").unwrap();
        assert_eq!(added.status, MembershipNodeStatus::Active);
        assert_eq!(added.owner, "alice");
        assert_eq!(added.node_pubkey_hex, hex_lower(&enrollee_pubkey));
    }

    #[test]
    fn build_add_node_record_rejects_zero_ttl() {
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "x".to_owned(),
            node_pubkey_hex: hex_lower(&[1u8; 32]),
            owner: "bob".to_owned(),
            roles: vec![],
            update_id: "u".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 0,
        };
        let err =
            build_add_node_record_for_enrollee(&state, ctx).expect_err("zero ttl must reject");
        assert!(matches!(err, EnrollmentMembershipError::TtlMustBePositive));
    }

    #[test]
    fn build_add_node_record_propagates_reducer_reject_for_duplicate_node_id() {
        // The reducer rejects an AddNode whose node_id already
        // exists. The bridge must surface that reject — no silent
        // overwrite, no shortcut.
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "founder".to_owned(), // collision with base_state
            node_pubkey_hex: hex_lower(&[2u8; 32]),
            owner: "carol".to_owned(),
            roles: vec![],
            update_id: "u-2".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 600,
        };
        let err = build_add_node_record_for_enrollee(&state, ctx)
            .expect_err("duplicate node id must reject");
        assert!(matches!(
            err,
            EnrollmentMembershipError::Membership(MembershipError::InvalidTransition(_))
        ));
    }

    #[test]
    fn build_add_node_record_rejects_invalid_pubkey_hex() {
        // The reducer's hex decoder rejects non-32-byte values.
        let state = base_state();
        let ctx = EnrolleeAdmitContext {
            node_id: "minipc-3".to_owned(),
            node_pubkey_hex: "deadbeef".to_owned(),
            owner: "carol".to_owned(),
            roles: vec![],
            update_id: "u-3".to_owned(),
            reason_code: "r".to_owned(),
            policy_context: None,
            now_unix: 1_700_000_500,
            ttl_secs: 600,
        };
        let err =
            build_add_node_record_for_enrollee(&state, ctx).expect_err("short pubkey must reject");
        assert!(matches!(err, EnrollmentMembershipError::Membership(_)));
    }
}
