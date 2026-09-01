//! GAP-5 offline half: signed-state epoch rollback pinned at the membership
//! APPLY layer, through the PUBLIC API only.
//!
//! Pins design `LiveLabSignedStateRollbackApplyLayerStageDesign_2026-09-01.md`
//! §2.5 (the offline validator tests) against the ordered guard set of §1.2:
//! `apply_signed_update` (`crates/rustynet-control/src/membership.rs:1032-1076`)
//! validates prev-state-root (`:1052-1054`) BEFORE the epoch chain
//! (`:1055-1059`), so a genuine old-epoch bundle is rejected at
//! `PrevStateRootMismatch`, and the epoch-chain guard is reachable only by a
//! root-forged shape (adversarial review §4/§8 amendment 1). `EpochRegression`
//! is constructed only in `verify_attested_snapshot` (`:1513`) — never on the
//! apply path — and the final test pins that source-level fact so the live
//! stage's expected-rejection set (§2.3 step 4) stays correct.
//!
//! No guard is modified here: `membership.rs` is the system under test
//! (design §4 non-goal).

use ed25519_dalek::SigningKey;
use rustynet_control::membership::{
    apply_signed_update, preview_next_state, sign_update_record, MembershipApprover,
    MembershipApproverRole, MembershipApproverStatus, MembershipError, MembershipNode,
    MembershipNodeStatus, MembershipOperation, MembershipReplayCache, MembershipState,
    MembershipUpdateRecord, MembershipWatermark, SignedMembershipUpdate, MEMBERSHIP_SCHEMA_VERSION,
};
use rustynet_control::roles::RoleCapability;

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn approver(id: &str, key_byte: u8, role: MembershipApproverRole) -> MembershipApprover {
    let signing = SigningKey::from_bytes(&[key_byte; 32]);
    MembershipApprover {
        approver_id: id.to_owned(),
        approver_pubkey_hex: hex_encode(signing.verifying_key().as_bytes()),
        role,
        status: MembershipApproverStatus::Active,
        created_at_unix: 100,
    }
}

fn active_node(node_id: &str, pubkey_byte: u8) -> MembershipNode {
    MembershipNode {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_encode(&[pubkey_byte; 32]),
        owner: "owner@example.local".to_owned(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:servers".to_owned()],
        capabilities: vec![RoleCapability::Anchor],
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

/// Fresh membership state at epoch 1 (the E-2 era for these tests).
fn base_state() -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: "net-1".to_owned(),
        epoch: 1,
        nodes: vec![active_node("node-a", 9)],
        approver_set: vec![
            approver("owner-1", 1, MembershipApproverRole::Owner),
            approver("guardian-1", 2, MembershipApproverRole::Guardian),
            approver("guardian-2", 3, MembershipApproverRole::Guardian),
        ],
        quorum_threshold: 2,
        metadata_hash: None,
    }
}

/// Honest producer, mirrored from the public-API conformance test: preview at
/// `created_at_unix` (the RSA-0009-correct stamp), build the chained record,
/// quorum-sign with owner-1 + guardian-1.
fn mint_update(
    state: &MembershipState,
    operation: MembershipOperation,
    target: &str,
    update_id: &str,
    created_at_unix: u64,
) -> SignedMembershipUpdate {
    let candidate =
        preview_next_state(state, &operation, created_at_unix).expect("honest mint previews");
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: update_id.to_owned(),
        operation,
        target: target.to_owned(),
        prev_state_root: state.state_root_hex().expect("state root computes"),
        new_state_root: candidate.state_root_hex().expect("candidate root computes"),
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix,
        expires_at_unix: created_at_unix + 300,
        reason_code: "rollback-offline-test".to_owned(),
        policy_context: None,
    };
    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let guardian_key = SigningKey::from_bytes(&[2; 32]);
    SignedMembershipUpdate {
        record: record.clone(),
        approver_signatures: vec![
            sign_update_record(&record, "owner-1", &owner_key).expect("owner signs"),
            sign_update_record(&record, "guardian-1", &guardian_key).expect("guardian signs"),
        ],
    }
}

/// Drive a genuine two-epoch history 1 -> 2 -> 3 (E-2 -> E-1 -> E) with
/// honestly minted, quorum-signed updates, returning the final epoch-E state
/// plus the RETAINED epoch E-1 envelope: the byte-identical update that was
/// minted at epoch E-1 and drove the E-1 -> E transition (design §2.2 capture
/// model — captured at the mint point, never re-forged).
fn driven_to_epoch_e() -> (MembershipState, SignedMembershipUpdate) {
    let mut state = base_state();
    let mut cache = MembershipReplayCache::default();

    let epoch_e2_to_e1 = mint_update(
        &state,
        MembershipOperation::AddNode(active_node("node-b", 12)),
        "node-b",
        "rollback-epoch2",
        200,
    );
    state = apply_signed_update(&state, &epoch_e2_to_e1, 200, &mut cache)
        .expect("genuine epoch 1 -> 2 update applies");

    let epoch_e1_to_e = mint_update(
        &state,
        MembershipOperation::RevokeNode {
            node_id: "node-b".to_owned(),
        },
        "node-b",
        "rollback-epoch3",
        210,
    );
    state = apply_signed_update(&state, &epoch_e1_to_e, 210, &mut cache)
        .expect("genuine epoch 2 -> 3 update applies");

    assert_eq!(state.epoch, 3, "mesh driven to epoch E=3");
    (state, epoch_e1_to_e)
}

/// Design §2.5 test 1 / adversarial review §4: the genuine old-epoch bundle
/// carries its E-1-era `prev_state_root`, which no longer matches the current
/// state, so the prev-root guard (`membership.rs:1052-1054`) fires BEFORE the
/// epoch-chain guard — `PrevStateRootMismatch`, not `InvalidTransition`.
#[test]
fn genuine_old_epoch_update_is_rejected_at_prev_state_root_guard() {
    let (state_at_e, retained_e1_update) = driven_to_epoch_e();

    let mut cache = MembershipReplayCache::default();
    let replayed = apply_signed_update(&state_at_e, &retained_e1_update, 250, &mut cache);

    match replayed {
        Err(MembershipError::PrevStateRootMismatch) => {}
        other => panic!(
            "genuine old-epoch bundle must reject at the prev-state-root guard \
             (fires before the epoch-chain guard), got {other:?}"
        ),
    }
}

/// Design §2.5 test 2 / adversarial review §8: the ONLY shape that reaches the
/// epoch-chain guard (`membership.rs:1055-1059`) is one whose
/// `prev_state_root` already carries the CURRENT state root. Forge exactly
/// that shape from the retained E-1 record (re-signed so the record shape is
/// internally consistent) and assert the epoch-chain rejection.
#[test]
fn root_forged_old_epoch_update_is_rejected_at_epoch_chain_guard() {
    let (state_at_e, retained_e1_update) = driven_to_epoch_e();

    let mut forged_record = retained_e1_update.record.clone();
    forged_record.prev_state_root = state_at_e.state_root_hex().expect("state root computes");
    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let guardian_key = SigningKey::from_bytes(&[2; 32]);
    let forged = SignedMembershipUpdate {
        approver_signatures: vec![
            sign_update_record(&forged_record, "owner-1", &owner_key).expect("owner signs"),
            sign_update_record(&forged_record, "guardian-1", &guardian_key)
                .expect("guardian signs"),
        ],
        record: forged_record,
    };

    let mut cache = MembershipReplayCache::default();
    let replayed = apply_signed_update(&state_at_e, &forged, 250, &mut cache);

    match replayed {
        Err(MembershipError::InvalidTransition(message)) => assert!(
            message.contains("epoch chain mismatch for membership update"),
            "epoch-chain guard message pinned, got: {message}"
        ),
        other => panic!(
            "root-forged old-epoch shape must reject at the epoch-chain guard, got {other:?}"
        ),
    }
}

/// Design §2.5 test 3: the id-dedup layer — a duplicate `update_id` observed
/// by the replay cache rejects with `ReplayDetected`
/// (`membership.rs:737-742`).
#[test]
fn duplicate_update_id_is_rejected_by_replay_cache() {
    let mut cache = MembershipReplayCache::default();
    cache
        .observe("rollback-duplicate-id", 3)
        .expect("first observation of a fresh id is accepted");
    let second = cache.observe("rollback-duplicate-id", 3);
    assert!(
        matches!(second, Err(MembershipError::ReplayDetected)),
        "duplicate id must reject with ReplayDetected, got {second:?}"
    );
}

/// Design §2.5 test 4 / adversarial review §5: a rejected replay perturbs
/// nothing. Capture the state's canonical serialization, its root, its epoch,
/// and the derived `MembershipWatermark` before and after each rejected
/// apply; assert byte-identical state, equal roots, equal epoch, and equal
/// watermark (the persisted `(epoch, state_root)` field names per
/// `membership.rs:1546-1549`).
#[test]
fn rejected_replay_leaves_state_and_watermark_byte_identical() {
    let (state, retained_e1_update) = driven_to_epoch_e();

    fn capture(state: &MembershipState) -> (String, String, u64, MembershipWatermark) {
        let canonical = state
            .canonical_payload()
            .expect("canonical payload serializes");
        let root = state.state_root_hex().expect("state root computes");
        let watermark = MembershipWatermark {
            epoch: state.epoch,
            state_root: root.clone(),
        };
        (canonical, root, state.epoch, watermark)
    }

    let mut cache = MembershipReplayCache::default();
    for label in ["genuine-replay", "root-forged-replay"] {
        let before = capture(&state);
        let attempt = if label == "genuine-replay" {
            apply_signed_update(&state, &retained_e1_update, 250, &mut cache)
        } else {
            let mut forged_record = retained_e1_update.record.clone();
            forged_record.prev_state_root = state.state_root_hex().expect("state root computes");
            let owner_key = SigningKey::from_bytes(&[1; 32]);
            let guardian_key = SigningKey::from_bytes(&[2; 32]);
            let forged = SignedMembershipUpdate {
                approver_signatures: vec![
                    sign_update_record(&forged_record, "owner-1", &owner_key).expect("owner signs"),
                    sign_update_record(&forged_record, "guardian-1", &guardian_key)
                        .expect("guardian signs"),
                ],
                record: forged_record,
            };
            apply_signed_update(&state, &forged, 250, &mut cache)
        };
        assert!(attempt.is_err(), "{label}: the replay must reject");

        let after = capture(&state);
        assert_eq!(
            before.0, after.0,
            "{label}: canonical state bytes unchanged"
        );
        assert_eq!(before.1, after.1, "{label}: state root unchanged");
        assert_eq!(before.2, after.2, "{label}: epoch unchanged");
        assert_eq!(
            before.3, after.3,
            "{label}: watermark (epoch, state_root) unchanged"
        );
    }
}

/// Design §2.5 test 5 (negative-as-positive): a properly chained epoch
/// E -> E+1 update still applies — the rejection is epoch-selective, not a
/// blanket refusal of the apply surface.
#[test]
fn correct_epoch_update_still_applies() {
    let (state_at_e, _retained) = driven_to_epoch_e();

    // node-b was revoked by the retained E-1 -> E update; restoring it is a
    // semantically valid next step.
    let forward = mint_update(
        &state_at_e,
        MembershipOperation::RestoreNode {
            node_id: "node-b".to_owned(),
        },
        "node-b",
        "rollback-forward-epoch4",
        260,
    );
    let mut cache = MembershipReplayCache::default();
    let next = apply_signed_update(&state_at_e, &forward, 260, &mut cache)
        .expect("a correctly chained E -> E+1 update must apply");
    assert_eq!(
        next.epoch,
        state_at_e.epoch + 1,
        "epoch chains by exactly 1"
    );
}

/// Design §2.3 step 4 / §2.5 (amendment 1): `EpochRegression` is constructed
/// only in `verify_attested_snapshot` (`membership.rs:1513`), never on the
/// apply path — so the live stage's expected-rejection set must never assert
/// it. Pin the source directly: within the `apply_signed_update` body the
/// token `EpochRegression` does not occur.
#[test]
fn epoch_regression_is_not_an_apply_path_outcome() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let source_path = format!("{manifest_dir}/src/membership.rs");
    let source = std::fs::read_to_string(&source_path)
        .unwrap_or_else(|err| panic!("read {source_path} at test time: {err}"));

    let start = source
        .find("pub fn apply_signed_update(")
        .unwrap_or_else(|| panic!("apply_signed_update signature not found in {source_path}"));
    let rest = &source[start..];
    let end_pub_fn = rest.find("\npub fn ").map_or(rest.len(), |index| index + 1);
    let end_priv_fn = rest.find("\nfn ").map_or(rest.len(), |index| index + 1);
    let body = &rest[..end_pub_fn.min(end_priv_fn)];

    assert!(
        body.contains("PrevStateRootMismatch"),
        "slice sanity: the extracted body must be the real apply body carrying \
         the prev-root guard"
    );
    assert!(
        !body.contains("EpochRegression"),
        "apply_signed_update must never construct EpochRegression: it lives only \
         on the verify_attested_snapshot surface (membership.rs:1513), so the \
         live stage's expected-rejection set stays correct (design §2.3)"
    );
}
