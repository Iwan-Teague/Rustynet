//! FIS-0019: bounded-exhaustive conformance tests binding the real
//! `apply_signed_update` to the TLA+ model at
//! `documents/formal/MembershipTrustState.tla`.
//!
//! Discipline rule (recorded in the model too): the `.tla`, the `.cfg`, the
//! Python explorer, and THIS test share their constants and must move
//! together — this test is the CI-enforced layer. It drives the REAL
//! functions with real Ed25519 test keys over the same small domains the
//! model explores, asserting the model's invariants after every step:
//! epoch chaining, no-double-accept, honest-never-root-mismatch (the
//! RSA-0009 catcher), no-fork-per-root, and reject-leaves-cache-intact.
//!
//! Deliberately dependency-free (no proptest): hand-rolled bounded
//! exhaustion matches the crate's existing convention and the recorded
//! new-dependency posture.

use ed25519_dalek::SigningKey;
use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipState, MembershipUpdateRecord, SignedMembershipUpdate,
    apply_signed_update, preview_next_state, sign_update_record,
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

/// Honest producer: preview at `created_at_unix` (the RSA-0009-correct
/// stamp), build the chained record, quorum-sign with owner-1 + guardian-1.
/// Returns None when the operation is semantically inapplicable to the
/// state (a valid producer would not mint it).
fn mint_signed(
    state: &MembershipState,
    operation: MembershipOperation,
    target: &str,
    update_id: &str,
    created_at_unix: u64,
) -> Option<SignedMembershipUpdate> {
    let candidate = preview_next_state(state, &operation, created_at_unix).ok()?;
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: update_id.to_owned(),
        operation,
        target: target.to_owned(),
        prev_state_root: state.state_root_hex().ok()?,
        new_state_root: candidate.state_root_hex().ok()?,
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix,
        expires_at_unix: created_at_unix + 300,
        reason_code: "conformance".to_owned(),
        policy_context: None,
    };
    let owner_key = SigningKey::from_bytes(&[1; 32]);
    let guardian_key = SigningKey::from_bytes(&[2; 32]);
    Some(SignedMembershipUpdate {
        record: record.clone(),
        approver_signatures: vec![
            sign_update_record(&record, "owner-1", &owner_key).ok()?,
            sign_update_record(&record, "guardian-1", &guardian_key).ok()?,
        ],
    })
}

/// The single most valuable pin the suite lacked: RSA-0009's exact shape.
/// The reducer previously stamped `unix_now()` instead of the signed
/// record's `created_at_unix`, so any stamping operation applied at a later
/// wall-clock second recomputed a DIFFERENT root and was rejected —
/// RevokeNode/RestoreNode/RotateNodeKey/SetNodeCapabilities could never
/// apply while AddNode kept working, which is why the mesh looked healthy
/// with revocation silently dead. Mint at T, apply at T+Δ, assert success.
#[test]
fn membership_stamping_ops_apply_at_later_wall_clock() {
    let minted_at = 200u64;
    // Δ well past any one-second boundary, inside the 300s expiry window.
    let applied_at = 200u64 + 250;

    let mut two_node_state = base_state();
    two_node_state.nodes.push(active_node("node-b", 12));

    let mut revoked_state = two_node_state.clone();
    revoked_state.nodes[1].status = MembershipNodeStatus::Revoked;

    let cases: Vec<(&str, MembershipState, MembershipOperation, &str)> = vec![
        (
            "revoke_node",
            two_node_state.clone(),
            MembershipOperation::RevokeNode {
                node_id: "node-b".to_owned(),
            },
            "node-b",
        ),
        (
            "restore_node",
            revoked_state,
            MembershipOperation::RestoreNode {
                node_id: "node-b".to_owned(),
            },
            "node-b",
        ),
        (
            "set_node_capabilities",
            two_node_state.clone(),
            MembershipOperation::SetNodeCapabilities {
                node_id: "node-a".to_owned(),
                capabilities: vec![RoleCapability::Client],
            },
            "node-a",
        ),
        (
            "rotate_node_key",
            two_node_state,
            MembershipOperation::RotateNodeKey {
                node_id: "node-a".to_owned(),
                new_pubkey_hex: hex_encode(&[42; 32]),
            },
            "node-a",
        ),
    ];

    for (label, state, operation, target) in cases {
        let signed = mint_signed(
            &state,
            operation,
            target,
            &format!("update-{label}"),
            minted_at,
        )
        .unwrap_or_else(|| panic!("{label}: honest mint must succeed"));
        let mut cache = MembershipReplayCache::default();
        let applied = apply_signed_update(&state, &signed, applied_at, &mut cache);
        assert!(
            applied.is_ok(),
            "{label}: honest stamping op minted at T={minted_at} must apply at \
             T+250 (RSA-0009 regression: reducer must stamp the SIGNED \
             created_at_unix, never the applier's wall clock): {:?}",
            applied.err()
        );
        let next = applied.expect("checked ok");
        assert_eq!(next.epoch, state.epoch + 1, "{label}: epoch chains by 1");
    }
}

/// Bounded-exhaustive mini-model-check of the real code: every sequence of
/// three operations from the model's alphabet, driven through the real
/// `apply_signed_update` with real signatures, asserting the model's
/// invariants after every step.
#[test]
fn membership_bounded_exhaustive_invariants_hold() {
    #[derive(Debug, Clone, Copy, PartialEq)]
    enum Op {
        AddB,
        RevokeB,
        RestoreB,
        RemoveB,
        SetCapsA,
        RotateKeyA,
    }
    let alphabet = [
        Op::AddB,
        Op::RevokeB,
        Op::RestoreB,
        Op::RemoveB,
        Op::SetCapsA,
        Op::RotateKeyA,
    ];

    let build = |op: Op, sequence_tag: &str, step: usize| -> (MembershipOperation, &'static str) {
        let _ = (sequence_tag, step);
        match op {
            Op::AddB => (
                MembershipOperation::AddNode(active_node("node-b", 12)),
                "node-b",
            ),
            Op::RevokeB => (
                MembershipOperation::RevokeNode {
                    node_id: "node-b".to_owned(),
                },
                "node-b",
            ),
            Op::RestoreB => (
                MembershipOperation::RestoreNode {
                    node_id: "node-b".to_owned(),
                },
                "node-b",
            ),
            Op::RemoveB => (
                MembershipOperation::RemoveNode {
                    node_id: "node-b".to_owned(),
                },
                "node-b",
            ),
            Op::SetCapsA => (
                MembershipOperation::SetNodeCapabilities {
                    node_id: "node-a".to_owned(),
                    capabilities: vec![RoleCapability::Client, RoleCapability::Anchor],
                },
                "node-a",
            ),
            Op::RotateKeyA => (
                MembershipOperation::RotateNodeKey {
                    node_id: "node-a".to_owned(),
                    new_pubkey_hex: hex_encode(&[77; 32]),
                },
                "node-a",
            ),
        }
    };

    let mut sequences_run = 0u32;
    let mut accepted_total = 0u32;
    for first in alphabet {
        for second in alphabet {
            for third in alphabet {
                let tag = format!("{first:?}-{second:?}-{third:?}");
                let mut state = base_state();
                let mut cache = MembershipReplayCache::default();
                let mut now = 200u64;
                let mut last_accepted: Option<(MembershipState, SignedMembershipUpdate)> = None;

                for (step, op) in [first, second, third].into_iter().enumerate() {
                    now += 10;
                    let (operation, target) = build(op, &tag, step);
                    let update_id = format!("update-{tag}-{step}");
                    // Honest mint at an EARLIER wall-clock than apply (Δ=5)
                    // so every accepted step re-proves the RSA-0009 shape.
                    let Some(signed) = mint_signed(&state, operation, target, &update_id, now - 5)
                    else {
                        // Semantically inapplicable (e.g. revoke a missing
                        // node): a valid producer would not mint it.
                        continue;
                    };

                    // InvHonestNeverRootMismatch: an honest, fresh, chained,
                    // quorum-signed record must apply.
                    let before_epoch = state.epoch;
                    let before_state = state.clone();
                    let next = apply_signed_update(&state, &signed, now, &mut cache)
                        .unwrap_or_else(|err| {
                            panic!("{tag} step {step}: honest record rejected: {err:?}")
                        });
                    accepted_total += 1;

                    // InvLogEpochsChain: exactly +1 per acceptance.
                    assert_eq!(next.epoch, before_epoch + 1, "{tag} step {step}");

                    // InvNoDoubleAccept + RejectLeavesCacheIntact: an exact
                    // byte-replay must reject without disturbing the cache.
                    assert!(
                        apply_signed_update(&next, &signed, now + 1, &mut cache).is_err(),
                        "{tag} step {step}: byte-replay must reject"
                    );

                    // InvNoForkPerRoot: a SECOND honest record built on the
                    // now-stale parent root must reject (the epoch/root
                    // guards force linear history).
                    if let Some(fork) = mint_signed(
                        &state,
                        MembershipOperation::SetNodeCapabilities {
                            node_id: "node-a".to_owned(),
                            capabilities: vec![RoleCapability::Anchor],
                        },
                        "node-a",
                        &format!("fork-{tag}-{step}"),
                        now,
                    ) {
                        assert!(
                            apply_signed_update(&next, &fork, now + 1, &mut cache).is_err(),
                            "{tag} step {step}: stale-parent fork must reject"
                        );
                    }

                    // Replay of the PREVIOUS accepted record (rollback) must
                    // also reject against the advanced state.
                    if let Some((_, earlier_signed)) = &last_accepted {
                        assert!(
                            apply_signed_update(&next, earlier_signed, now + 1, &mut cache)
                                .is_err(),
                            "{tag} step {step}: rollback replay must reject"
                        );
                    }

                    last_accepted = Some((before_state, signed));
                    state = next;
                }
                sequences_run += 1;
            }
        }
    }
    assert_eq!(sequences_run, 216, "full 6^3 alphabet exhausted");
    assert!(
        accepted_total > 300,
        "the bounded space must exercise a substantial accepting set, got {accepted_total}"
    );
}

/// RejectLeavesCacheIntact, pinned directly: a rejected apply (corrupted
/// root) must leave the replay cache able to accept the honest record with
/// the SAME update id — the cache-poisoning ordering bug this guards.
#[test]
fn membership_rejected_apply_never_poisons_replay_cache() {
    let state = base_state();
    let signed = mint_signed(
        &state,
        MembershipOperation::AddNode(active_node("node-b", 12)),
        "node-b",
        "update-poison",
        200,
    )
    .expect("honest mint");

    let mut corrupted = signed.clone();
    corrupted.record.new_state_root = "00".repeat(32);

    let mut cache = MembershipReplayCache::default();
    assert!(
        apply_signed_update(&state, &corrupted, 210, &mut cache).is_err(),
        "corrupted root must reject"
    );
    // The honest record with the same update id still applies: the failed
    // attempt left the cache byte-intact.
    let applied = apply_signed_update(&state, &signed, 211, &mut cache);
    assert!(
        applied.is_ok(),
        "rejection must not consume the update id: {:?}",
        applied.err()
    );
}
