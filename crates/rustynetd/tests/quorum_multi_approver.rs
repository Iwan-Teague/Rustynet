//! Multi-approver quorum admission tests (quorum_threshold > 1).
//!
//! The code path exists in `rustynet_control::membership` (`ThresholdNotMet`
//! at the signature-count check) but was only exercised inside private module
//! tests in daemon.rs. These external integration tests pin the behaviour
//! through the public API used by all production callers.
//!
//! All tests use a 3-approver set (1 Owner + 2 Guardians) with
//! `quorum_threshold = 2`, which is the smallest non-trivial quorum.

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

/// 3-approver state: owner-1 (Owner), guardian-1 (Guardian), guardian-2
/// (Guardian). quorum_threshold = 2 so any two of the three must sign.
fn three_approver_state() -> MembershipState {
    let owner_pk = signing_key(0x10).verifying_key().to_bytes();
    let guardian1_pk = signing_key(0x11).verifying_key().to_bytes();
    let guardian2_pk = signing_key(0x12).verifying_key().to_bytes();
    let founder_pk = signing_key(0x13).verifying_key().to_bytes();
    let state = MembershipState {
        schema_version: 1,
        network_id: "quorum-test-net".to_owned(),
        epoch: 1,
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
        approver_set: vec![
            MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex_lower(&owner_pk),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
            MembershipApprover {
                approver_id: "guardian-1".to_owned(),
                approver_pubkey_hex: hex_lower(&guardian1_pk),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
            MembershipApprover {
                approver_id: "guardian-2".to_owned(),
                approver_pubkey_hex: hex_lower(&guardian2_pk),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
        ],
        quorum_threshold: 2,
        metadata_hash: None,
    };
    state
        .validate()
        .expect("three-approver state must validate");
    state
}

/// Build a `SignedMembershipUpdate` for `enrollee_node_id` signed by the
/// provided list of `(approver_id, signing_key)` pairs.
fn build_signed_update(
    state: &MembershipState,
    signers: &[(&str, &SigningKey)],
    enrollee_pk: &[u8; 32],
    enrollee_node_id: &str,
    now_unix: u64,
) -> Result<SignedMembershipUpdate, String> {
    let ctx = EnrolleeAdmitContext {
        node_id: enrollee_node_id.to_owned(),
        node_pubkey_hex: hex_lower(enrollee_pk),
        owner: "alice".to_owned(),
        roles: vec!["client".to_owned()],
        update_id: format!("admit-{enrollee_node_id}-{now_unix}"),
        reason_code: "enrollment.token_consume.v1".to_owned(),
        policy_context: None,
        now_unix,
        ttl_secs: 600,
    };
    let record = build_add_node_record_for_enrollee(state, ctx).map_err(|e| e.to_string())?;
    let payload = record.canonical_payload().map_err(|e| e.to_string())?;
    let signatures: Vec<MembershipSignature> = signers
        .iter()
        .map(|(id, key)| {
            let sig = key.sign(payload.as_bytes());
            MembershipSignature {
                approver_id: (*id).to_owned(),
                signature_hex: hex_lower(&sig.to_bytes()),
                head_signature_hex: None,
            }
        })
        .collect();
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures: signatures,
    })
}

#[test]
fn quorum_2_of_3_admits_with_two_valid_signatures() {
    let state = three_approver_state();
    let owner_key = signing_key(0x10);
    let guardian1_key = signing_key(0x11);
    let enrollee_pk = signing_key(0xaa).verifying_key().to_bytes();

    let signed = build_signed_update(
        &state,
        &[("owner-1", &owner_key), ("guardian-1", &guardian1_key)],
        &enrollee_pk,
        "new-peer-1",
        1_700_010_000,
    )
    .expect("build signed update");

    let mut replay = MembershipReplayCache::default();
    let next = apply_signed_update(&state, &signed, 1_700_010_000, &mut replay)
        .expect("2-of-3 admit must succeed");
    assert_eq!(next.epoch, 2);
    assert!(
        next.nodes.iter().any(|n| n.node_id == "new-peer-1"),
        "admitted peer must appear in post-apply state"
    );
}

#[test]
fn quorum_2_of_3_rejects_with_one_signature() {
    let state = three_approver_state();
    let owner_key = signing_key(0x10);
    let enrollee_pk = signing_key(0xab).verifying_key().to_bytes();

    let signed = build_signed_update(
        &state,
        &[("owner-1", &owner_key)],
        &enrollee_pk,
        "new-peer-2",
        1_700_011_000,
    )
    .expect("build signed update");

    let mut replay = MembershipReplayCache::default();
    let err = apply_signed_update(&state, &signed, 1_700_011_000, &mut replay)
        .expect_err("single signature must not satisfy quorum=2");
    assert!(
        matches!(err, MembershipError::ThresholdNotMet),
        "expected ThresholdNotMet, got {err:?}"
    );
}

#[test]
fn quorum_threshold_exceeds_active_approvers_fails_validate() {
    // quorum_threshold=3 with only 2 active approvers must be rejected by
    // validate() — an operator misconfiguration is caught at write time.
    let owner_pk = signing_key(0x20).verifying_key().to_bytes();
    let guardian_pk = signing_key(0x21).verifying_key().to_bytes();
    let founder_pk = signing_key(0x22).verifying_key().to_bytes();
    let state = MembershipState {
        schema_version: 1,
        network_id: "quorum-validate-net".to_owned(),
        epoch: 1,
        nodes: vec![MembershipNode {
            node_id: "founder".to_owned(),
            node_pubkey_hex: hex_lower(&founder_pk),
            owner: "bob".to_owned(),
            status: MembershipNodeStatus::Active,
            capabilities: vec![RoleCapability::Anchor],
            roles: vec!["admin".to_owned()],
            joined_at_unix: 1_700_000_000,
            updated_at_unix: 1_700_000_000,
        }],
        approver_set: vec![
            MembershipApprover {
                approver_id: "owner-a".to_owned(),
                approver_pubkey_hex: hex_lower(&owner_pk),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
            MembershipApprover {
                approver_id: "guardian-a".to_owned(),
                approver_pubkey_hex: hex_lower(&guardian_pk),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
        ],
        quorum_threshold: 3, // exceeds active approver count of 2
        metadata_hash: None,
    };
    let err = state
        .validate()
        .expect_err("threshold > active approvers must fail validate");
    match &err {
        MembershipError::InvalidFormat(msg) => {
            assert!(
                msg.contains("quorum threshold"),
                "error must mention quorum threshold: {msg}"
            );
        }
        other => panic!("expected InvalidFormat, got {other:?}"),
    }
}

#[test]
fn revoked_approver_does_not_count_toward_quorum() {
    // guardian-2 is revoked. With quorum=2, owner-1 + guardian-1 is the
    // only valid signing combination. A signature from revoked guardian-2
    // must not count.
    let owner_pk = signing_key(0x10).verifying_key().to_bytes();
    let guardian1_pk = signing_key(0x11).verifying_key().to_bytes();
    let guardian2_pk = signing_key(0x12).verifying_key().to_bytes();
    let founder_pk = signing_key(0x13).verifying_key().to_bytes();
    let state_with_revoked = MembershipState {
        schema_version: 1,
        network_id: "revoked-guardian-net".to_owned(),
        epoch: 1,
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
        approver_set: vec![
            MembershipApprover {
                approver_id: "owner-1".to_owned(),
                approver_pubkey_hex: hex_lower(&owner_pk),
                role: MembershipApproverRole::Owner,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
            MembershipApprover {
                approver_id: "guardian-1".to_owned(),
                approver_pubkey_hex: hex_lower(&guardian1_pk),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Active,
                created_at_unix: 1_700_000_000,
            },
            MembershipApprover {
                approver_id: "guardian-2".to_owned(),
                approver_pubkey_hex: hex_lower(&guardian2_pk),
                role: MembershipApproverRole::Guardian,
                status: MembershipApproverStatus::Revoked, // revoked
                created_at_unix: 1_700_000_000,
            },
        ],
        quorum_threshold: 2, // still requires 2 active signatures
        metadata_hash: None,
    };
    state_with_revoked
        .validate()
        .expect("state with revoked approver is valid (quorum <= 2 active)");

    // Signing with owner + revoked guardian-2 must not satisfy quorum.
    let owner_key = signing_key(0x10);
    let guardian2_key = signing_key(0x12);
    let enrollee_pk = signing_key(0xac).verifying_key().to_bytes();
    let signed = build_signed_update(
        &state_with_revoked,
        &[("owner-1", &owner_key), ("guardian-2", &guardian2_key)],
        &enrollee_pk,
        "new-peer-3",
        1_700_012_000,
    )
    .expect("build signed update");

    let mut replay = MembershipReplayCache::default();
    let err = apply_signed_update(&state_with_revoked, &signed, 1_700_012_000, &mut replay)
        .expect_err("signature from revoked approver must not satisfy quorum");
    assert!(
        matches!(
            err,
            MembershipError::ThresholdNotMet | MembershipError::SignerNotAuthorized(_)
        ),
        "expected ThresholdNotMet or SignerNotAuthorized, got {err:?}"
    );
}

#[test]
fn owner_plus_guardian_satisfies_quorum() {
    // Explicit proof that the quorum counter does not restrict which
    // *role* signs — any two active approvers, regardless of their role
    // (Owner or Guardian), satisfy quorum=2.
    let state = three_approver_state();
    let guardian1_key = signing_key(0x11);
    let guardian2_key = signing_key(0x12);
    let enrollee_pk = signing_key(0xad).verifying_key().to_bytes();

    // Two guardians, no owner — still 2 active approvers, quorum=2 met.
    let signed = build_signed_update(
        &state,
        &[
            ("guardian-1", &guardian1_key),
            ("guardian-2", &guardian2_key),
        ],
        &enrollee_pk,
        "new-peer-4",
        1_700_013_000,
    )
    .expect("build signed update");

    let mut replay = MembershipReplayCache::default();
    apply_signed_update(&state, &signed, 1_700_013_000, &mut replay)
        .expect("two guardians must satisfy quorum=2 without owner");
}
