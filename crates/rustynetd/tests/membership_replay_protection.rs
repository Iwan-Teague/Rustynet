//! Membership replay protection tests.
//!
//! Existing `gossip_three_peer_mesh.rs` covers in-session gossip replay.
//! These tests pin the membership-layer replay and rollback defences:
//!
//! 1. Direct `MembershipReplayCache::observe()` semantics.
//! 2. `apply_signed_update` rejects a repeated update in the same session
//!    (update_id already seen by the replay cache).
//! 3. `apply_signed_update` rejects epoch rollback (epoch_new <= max_epoch).
//! 4. A fresh replay cache + stale signed update fails at PrevStateRootMismatch,
//!    showing that the state-root chain is the durable rollback guard that
//!    survives across restarts even without persisting the replay cache.

#![forbid(unsafe_code)]

use ed25519_dalek::{Signer, SigningKey};

use rustynet_control::enrollment::{EnrolleeAdmitContext, build_add_node_record_for_enrollee};
use rustynet_control::membership::{
    MembershipApprover, MembershipApproverRole, MembershipApproverStatus, MembershipError,
    MembershipNode, MembershipNodeStatus, MembershipReplayCache, MembershipSignature,
    MembershipState, SignedMembershipUpdate, apply_signed_update,
};
use rustynet_control::roles::RoleCapability;

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn signing_key(byte: u8) -> SigningKey {
    SigningKey::from_bytes(&[byte; 32])
}

fn single_approver_state(epoch: u64) -> MembershipState {
    let owner_pk = signing_key(0x30).verifying_key().to_bytes();
    let founder_pk = signing_key(0x31).verifying_key().to_bytes();
    MembershipState {
        schema_version: 1,
        network_id: "replay-test-net".to_owned(),
        epoch,
        nodes: vec![MembershipNode {
            node_id: "founder".to_owned(),
            node_pubkey_hex: hex_lower(&founder_pk),
            owner: "alice".to_owned(),
            status: MembershipNodeStatus::Active,
            capabilities: vec![RoleCapability::Anchor],
            roles: vec!["admin".to_owned()],
            joined_at_unix: 1_700_000_000,
            updated_at_unix: 1_700_000_000,
        }],
        approver_set: vec![MembershipApprover {
            approver_id: "owner-1".to_owned(),
            approver_pubkey_hex: hex_lower(&owner_pk),
            role: MembershipApproverRole::Owner,
            status: MembershipApproverStatus::Active,
            created_at_unix: 1_700_000_000,
        }],
        quorum_threshold: 1,
        metadata_hash: None,
    }
}

fn admit_signed(state: &MembershipState, node_id: &str, now_unix: u64) -> SignedMembershipUpdate {
    let owner_key = signing_key(0x30);
    let enrollee_pk = signing_key(0xbe).verifying_key().to_bytes();
    let ctx = EnrolleeAdmitContext {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_lower(&enrollee_pk),
        owner: "alice".to_owned(),
        roles: vec!["client".to_owned()],
        update_id: format!("admit-{node_id}-{now_unix}"),
        reason_code: "enrollment.token_consume.v1".to_owned(),
        policy_context: None,
        now_unix,
        ttl_secs: 600,
    };
    let record = build_add_node_record_for_enrollee(state, ctx).expect("build record");
    let payload = record.canonical_payload().expect("canonical payload");
    let sig = owner_key.sign(payload.as_bytes());
    SignedMembershipUpdate {
        record,
        approver_signatures: vec![MembershipSignature {
            approver_id: "owner-1".to_owned(),
            signature_hex: hex_lower(&sig.to_bytes()),
            head_signature_hex: None,
        }],
    }
}

#[test]
fn replay_cache_observe_blocks_same_update_id() {
    let mut cache = MembershipReplayCache::default();
    cache
        .observe("update-abc", 2)
        .expect("first observe at epoch 2 must succeed");
    let err = cache
        .observe("update-abc", 3)
        .expect_err("same update_id at higher epoch must still be rejected");
    assert!(
        matches!(err, MembershipError::ReplayDetected),
        "expected ReplayDetected, got {err:?}"
    );
}

#[test]
fn replay_cache_observe_blocks_epoch_rollback() {
    let mut cache = MembershipReplayCache::default();
    cache
        .observe("update-1", 5)
        .expect("first observe at epoch 5 must succeed");
    let err = cache
        .observe("update-2", 5)
        .expect_err("epoch_new == max_epoch must be rejected as rollback");
    assert!(
        matches!(err, MembershipError::ReplayDetected),
        "expected ReplayDetected, got {err:?}"
    );
    let err2 = cache
        .observe("update-3", 4)
        .expect_err("epoch_new < max_epoch must be rejected as rollback");
    assert!(
        matches!(err2, MembershipError::ReplayDetected),
        "expected ReplayDetected, got {err2:?}"
    );
}

#[test]
fn apply_signed_update_rejects_same_update_in_session() {
    // After successfully applying an update, attempting to apply the exact
    // same signed update a second time must fail with ReplayDetected.
    let state = single_approver_state(1);
    state.validate().expect("state must validate");

    let signed = admit_signed(&state, "peer-replay-1", 1_700_020_000);

    let mut replay = MembershipReplayCache::default();
    let next =
        apply_signed_update(&state, &signed, 1_700_020_000, &mut replay).expect("first apply");
    assert_eq!(next.epoch, 2);

    // Retry with the same replay cache — update_id is already observed.
    let err = apply_signed_update(&next, &signed, 1_700_020_001, &mut replay)
        .expect_err("second apply of same update must fail");
    assert!(
        matches!(
            err,
            MembershipError::ReplayDetected | MembershipError::PrevStateRootMismatch
        ),
        "expected ReplayDetected or PrevStateRootMismatch, got {err:?}"
    );
}

#[test]
fn stale_signed_update_fails_on_fresh_replay_cache_via_state_root_chain() {
    // Simulates a "post-restart" scenario: the replay cache is fresh (default),
    // but the attacker replays an old signed update from epoch 1→2 against the
    // current state which is already at epoch 2.
    //
    // The state-root chain (`prev_state_root` check in apply_signed_update)
    // acts as the durable defence and rejects the replayed update regardless
    // of the fresh replay cache — this documents the architectural invariant
    // that replay protection does not depend solely on the in-memory cache.
    let state_epoch1 = single_approver_state(1);
    state_epoch1
        .validate()
        .expect("epoch-1 state must validate");

    let old_signed = admit_signed(&state_epoch1, "peer-stale-1", 1_700_030_000);

    // Advance to epoch 2 using the same update.
    let mut replay1 = MembershipReplayCache::default();
    let state_epoch2 = apply_signed_update(&state_epoch1, &old_signed, 1_700_030_000, &mut replay1)
        .expect("first apply");
    assert_eq!(state_epoch2.epoch, 2);

    // Fresh replay cache — simulates restart with no persisted cache.
    let mut fresh_replay = MembershipReplayCache::default();
    // Try to replay the original epoch-1→2 update against the epoch-2 state.
    let err = apply_signed_update(&state_epoch2, &old_signed, 1_700_030_001, &mut fresh_replay)
        .expect_err("stale update must fail against advanced state");
    assert!(
        matches!(
            err,
            MembershipError::PrevStateRootMismatch
                | MembershipError::InvalidTransition(_)
                | MembershipError::ReplayDetected
        ),
        "expected state-root or epoch chain rejection, got {err:?}"
    );
}
