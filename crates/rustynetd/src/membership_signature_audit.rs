#![allow(clippy::result_large_err)]

//! Adversarial self-audit of the signed-membership verify funnel.
//!
//! Companion of the orchestrator-side `evaluate_membership_signature_audit_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd membership-signature-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.2 (signed control/trust data validated before
//! application) + §6.B (the trust anchor verifies membership snapshots). The
//! enforcement funnel is [`rustynet_control::membership::apply_signed_update`]
//! (signature → quorum → freshness → replay → state-root → apply) and
//! [`rustynet_control::membership::decode_signed_update`] (default-deny on
//! malformed input). Signatures are checked with `verify_strict` (RN-22), so a
//! non-canonical / malleable signature is rejected — the exact failure mode
//! behind the real-world Nebula ECDSA-malleability CRL bypass.
//!
//! This audit drives that REAL shipped funnel, in-process, with synthetic keys
//! (it touches no production key, file, or state) against an adversarial corpus
//! and asserts:
//!   - a fully-valid signed update is ACCEPTED (anti-vacuous baseline — not the
//!     trivial "reject everything" pass), and
//!   - every forgery (tampered signature, malleable non-canonical S,
//!     unauthorized signer, sub-quorum, future-dated, expired, replayed,
//!     network-id mismatch, prev-state-root mismatch, truncated/empty envelope)
//!     is REJECTED, fail-closed.
//!
//! It FAILs LOUD (non-zero exit) the moment the verify funnel accepts a forgery
//! or rejects the valid baseline — so a `verify_strict`→`verify` regression, a
//! dropped quorum/freshness/replay check, or a decoder that stops failing
//! closed is caught on the DEPLOYED binary, per OS.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipSignature, MembershipState, MembershipUpdateRecord,
    SignedMembershipUpdate, apply_signed_update, decode_signed_update, encode_signed_update,
    preview_next_state, sign_update_record,
};
use rustynet_control::roles::RoleCapability;

pub const MEMBERSHIP_SIGNATURE_AUDIT_SCHEMA_VERSION: u32 = 1;

/// Synthetic network id — never collides with any real deployment.
const AUDIT_NETWORK_ID: &str = "rustynet-sigaudit-net";
/// Fixed evaluation clock so freshness checks are deterministic.
const AUDIT_NOW_UNIX: u64 = 1_000_000;

/// The ed25519 group order ℓ (= 2^252 + 27742317777372353535851937790883648493)
/// in little-endian byte order. Adding ℓ to a canonical signature scalar `S`
/// yields a non-canonical `S' = S + ℓ` that is congruent mod ℓ (so non-strict
/// `verify` still accepts) but `>= ℓ` (so `verify_strict` rejects) — the
/// malleability the RN-22 standard forbids.
const ED25519_GROUP_ORDER_LE: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CasePath {
    Apply,
    Decode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expect {
    /// A fully-valid update the funnel MUST accept (anti-vacuous baseline).
    Accept,
    /// A forgery the funnel MUST reject.
    Reject,
}

struct SignatureAuditCase {
    id: &'static str,
    path: CasePath,
    expect: Expect,
    /// Substring the rejection reason must contain (Reject cases only).
    expect_reason_contains: &'static str,
    signed_update: Option<SignedMembershipUpdate>,
    preseed_replay: Option<(String, u64)>,
    raw_payload: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureAuditCaseResult {
    pub id: String,
    pub expectation: String,
    pub rejected: bool,
    pub reason: String,
    pub reason_matches: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipSignatureAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    pub forgeries_rejected: u32,
    pub baseline_accepted: u32,
    /// Cases whose outcome did not match expectation. Empty when overall_ok.
    pub violations: Vec<SignatureAuditCaseResult>,
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

fn active_node(node_id: &str, pubkey_byte: u8) -> MembershipNode {
    MembershipNode {
        node_id: node_id.to_owned(),
        node_pubkey_hex: hex_lower(&[pubkey_byte; 32]),
        owner: "sigaudit-owner@example.local".to_owned(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:servers".to_owned()],
        capabilities: vec![RoleCapability::Anchor],
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

fn synthetic_state() -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: AUDIT_NETWORK_ID.to_owned(),
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

fn valid_operation() -> MembershipOperation {
    MembershipOperation::SetNodeCapabilities {
        node_id: "node-a".to_owned(),
        capabilities: vec![RoleCapability::Anchor, RoleCapability::Client],
    }
}

fn valid_record(update_id: &str) -> Result<(MembershipState, MembershipUpdateRecord), String> {
    let state = synthetic_state();
    let operation = valid_operation();
    // RSA-0009: match the record's created_at_unix below so the previewed root
    // reproduces at apply.
    let next = preview_next_state(&state, &operation, AUDIT_NOW_UNIX - 10)
        .map_err(|err| format!("preview_next_state failed: {err}"))?;
    let prev_root = state
        .state_root_hex()
        .map_err(|err| format!("prev state root failed: {err}"))?;
    let new_root = next
        .state_root_hex()
        .map_err(|err| format!("new state root failed: {err}"))?;
    let record = MembershipUpdateRecord {
        network_id: state.network_id.clone(),
        update_id: update_id.to_owned(),
        operation,
        target: "node-a".to_owned(),
        prev_state_root: prev_root,
        new_state_root: new_root,
        epoch_prev: state.epoch,
        epoch_new: state.epoch + 1,
        created_at_unix: AUDIT_NOW_UNIX - 10,
        expires_at_unix: AUDIT_NOW_UNIX + 600,
        reason_code: "sigaudit".to_owned(),
        policy_context: None,
    };
    Ok((state, record))
}

fn quorum_signatures(record: &MembershipUpdateRecord) -> Result<Vec<MembershipSignature>, String> {
    Ok(vec![
        sign_update_record(record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?,
        sign_update_record(record, "guardian-1", &key(2))
            .map_err(|err| format!("guardian sign failed: {err}"))?,
    ])
}

fn valid_signed_update(update_id: &str) -> Result<SignedMembershipUpdate, String> {
    let (_state, record) = valid_record(update_id)?;
    let signatures = quorum_signatures(&record)?;
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures: signatures,
    })
}

/// Mutate a 64-byte ed25519 signature hex (`R || S`, LE) into a non-canonical
/// but congruent malleable form `S' = S + ℓ`. Returns the new hex.
fn malleate_signature_hex(signature_hex: &str) -> Result<String, String> {
    let mut bytes = decode_hex_64(signature_hex)?;
    // S occupies bytes 32..64 (little-endian). Add the group order with carry.
    let mut carry = 0u16;
    for i in 0..32 {
        let sum = bytes[32 + i] as u16 + ED25519_GROUP_ORDER_LE[i] as u16 + carry;
        bytes[32 + i] = (sum & 0xff) as u8;
        carry = sum >> 8;
    }
    Ok(hex_lower(&bytes))
}

fn decode_hex_64(value: &str) -> Result<[u8; 64], String> {
    if value.len() != 128 {
        return Err(format!(
            "expected 64-byte signature hex, got {} chars",
            value.len()
        ));
    }
    let mut out = [0u8; 64];
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = value.as_bytes()[i * 2];
        let lo = value.as_bytes()[i * 2 + 1];
        *slot = (hex_nibble(hi)? << 4) | hex_nibble(lo)?;
    }
    Ok(out)
}

fn hex_nibble(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        other => Err(format!("non-hex byte: {other}")),
    }
}

fn adversarial_corpus() -> Result<Vec<SignatureAuditCase>, String> {
    let mut cases = Vec::new();

    // 0. valid_baseline (MUST be accepted) — anti-vacuous guard.
    cases.push(SignatureAuditCase {
        id: "valid_baseline_accepted",
        path: CasePath::Apply,
        expect: Expect::Accept,
        expect_reason_contains: "",
        signed_update: Some(valid_signed_update("update-valid-baseline")?),
        preseed_replay: None,
        raw_payload: None,
    });

    // 1. forged_owner_signature: flip a hex nibble of the owner signature.
    {
        let (_state, record) = valid_record("update-forged-sig")?;
        let mut signatures = quorum_signatures(&record)?;
        let sig = &mut signatures[0].signature_hex;
        let flipped = if sig.starts_with('f') { "0" } else { "f" };
        sig.replace_range(0..1, flipped);
        cases.push(SignatureAuditCase {
            id: "forged_owner_signature",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "signature verification failed",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 2. malleable_s_signature (RN-22 / Nebula-malleability): valid signature
    //    with S' = S + ℓ. Non-strict verify would accept; verify_strict rejects.
    {
        let (_state, record) = valid_record("update-malleable-s")?;
        let mut signatures = quorum_signatures(&record)?;
        signatures[0].signature_hex = malleate_signature_hex(&signatures[0].signature_hex)?;
        cases.push(SignatureAuditCase {
            id: "malleable_s_signature",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "signature verification failed",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 3. unauthorized_signer_key: owner signs to clear threshold; the second
    //    signer is an attacker id signed with an off-roster key.
    {
        let (_state, record) = valid_record("update-unauthorized-signer")?;
        let owner_sig = sign_update_record(&record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?;
        let rogue_sig = sign_update_record(&record, "attacker-1", &key(99))
            .map_err(|err| format!("rogue sign failed: {err}"))?;
        cases.push(SignatureAuditCase {
            id: "unauthorized_signer_key",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "signer is not authorized",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: vec![owner_sig, rogue_sig],
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 4. quorum_below_threshold: one signature when threshold is two.
    {
        let (_state, record) = valid_record("update-below-threshold")?;
        let owner_sig = sign_update_record(&record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?;
        cases.push(SignatureAuditCase {
            id: "quorum_below_threshold",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "threshold signature requirements not met",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: vec![owner_sig],
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 5. future_dated_update: created beyond now + clock skew.
    {
        let (_state, mut record) = valid_record("update-future-dated")?;
        record.created_at_unix = AUDIT_NOW_UNIX + 3600;
        record.expires_at_unix = record.created_at_unix + 600;
        let signatures = quorum_signatures(&record)?;
        cases.push(SignatureAuditCase {
            id: "future_dated_update",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "future dated",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 6. expired_update: expiry before now.
    {
        let (_state, mut record) = valid_record("update-expired")?;
        record.created_at_unix = AUDIT_NOW_UNIX - 1000;
        record.expires_at_unix = AUDIT_NOW_UNIX - 500;
        let signatures = quorum_signatures(&record)?;
        cases.push(SignatureAuditCase {
            id: "expired_update",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "expired",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 7. replayed_update: a valid update whose id+epoch are pre-seeded into the
    //    replay cache so the apply reaches observe() and is rejected.
    {
        let signed = valid_signed_update("update-replayed")?;
        let update_id = signed.record.update_id.clone();
        let epoch_new = signed.record.epoch_new;
        cases.push(SignatureAuditCase {
            id: "replayed_update",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "membership replay detected",
            signed_update: Some(signed),
            preseed_replay: Some((update_id, epoch_new)),
            raw_payload: None,
        });
    }

    // 8. network_id_mismatch.
    {
        let (_state, mut record) = valid_record("update-network-mismatch")?;
        record.network_id = "wrong-net".to_owned();
        let signatures = quorum_signatures(&record)?;
        cases.push(SignatureAuditCase {
            id: "network_id_mismatch",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "network id mismatch",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 9. prev_state_root_mismatch.
    {
        let (_state, mut record) = valid_record("update-prev-root")?;
        record.prev_state_root =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let signatures = quorum_signatures(&record)?;
        cases.push(SignatureAuditCase {
            id: "prev_state_root_mismatch",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "previous state root mismatch",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 10. truncated_envelope (decode path).
    {
        let signed = valid_signed_update("update-truncated")?;
        let envelope = encode_signed_update(&signed)
            .map_err(|err| format!("encode envelope failed: {err}"))?;
        let truncated = envelope[..envelope.len() / 2].to_owned();
        cases.push(SignatureAuditCase {
            id: "truncated_envelope",
            path: CasePath::Decode,
            expect: Expect::Reject,
            expect_reason_contains: "invalid membership format",
            signed_update: None,
            preseed_replay: None,
            raw_payload: Some(truncated),
        });
    }

    // 11. empty_payload_default_deny (decode path).
    cases.push(SignatureAuditCase {
        id: "empty_payload_default_deny",
        path: CasePath::Decode,
        expect: Expect::Reject,
        expect_reason_contains: "invalid membership format",
        signed_update: None,
        preseed_replay: None,
        raw_payload: Some(String::new()),
    });

    Ok(cases)
}

fn evaluate_case(case: &SignatureAuditCase) -> SignatureAuditCaseResult {
    let (rejected, reason) = match case.path {
        CasePath::Apply => {
            let signed = case
                .signed_update
                .as_ref()
                .expect("apply-path case carries a signed update");
            let state = synthetic_state();
            let mut cache = MembershipReplayCache::default();
            if let Some((update_id, epoch_new)) = &case.preseed_replay {
                let _ = cache.observe(update_id, *epoch_new);
            }
            match apply_signed_update(&state, signed, AUDIT_NOW_UNIX, &mut cache) {
                Ok(_) => (false, "ACCEPTED: verifier applied the update".to_owned()),
                Err(err) => (true, err.to_string()),
            }
        }
        CasePath::Decode => {
            let raw = case
                .raw_payload
                .as_ref()
                .expect("decode-path case carries a raw payload");
            match decode_signed_update(raw) {
                Ok(_) => (false, "ACCEPTED: decoder accepted the envelope".to_owned()),
                Err(err) => (true, err.to_string()),
            }
        }
    };
    let reason_matches = case.expect_reason_contains.is_empty()
        || reason
            .to_lowercase()
            .contains(&case.expect_reason_contains.to_lowercase());
    let passed = match case.expect {
        Expect::Accept => !rejected,
        Expect::Reject => rejected && reason_matches,
    };
    SignatureAuditCaseResult {
        id: case.id.to_owned(),
        expectation: match case.expect {
            Expect::Accept => "accept".to_owned(),
            Expect::Reject => "reject".to_owned(),
        },
        rejected,
        reason,
        reason_matches,
        passed,
    }
}

pub fn run_membership_signature_audit() -> Result<MembershipSignatureAuditReport, String> {
    let corpus = adversarial_corpus()?;
    Ok(build_membership_signature_audit_report(&corpus))
}

fn build_membership_signature_audit_report(
    corpus: &[SignatureAuditCase],
) -> MembershipSignatureAuditReport {
    let results: Vec<SignatureAuditCaseResult> = corpus.iter().map(evaluate_case).collect();
    let forgeries_rejected = corpus
        .iter()
        .zip(results.iter())
        .filter(|(case, res)| case.expect == Expect::Reject && res.passed)
        .count() as u32;
    let baseline_accepted = corpus
        .iter()
        .zip(results.iter())
        .filter(|(case, res)| case.expect == Expect::Accept && res.passed)
        .count() as u32;
    let violations: Vec<SignatureAuditCaseResult> =
        results.iter().filter(|res| !res.passed).cloned().collect();
    MembershipSignatureAuditReport {
        schema_version: MEMBERSHIP_SIGNATURE_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: corpus.len() as u32,
        forgeries_rejected,
        baseline_accepted,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};

    #[test]
    fn corpus_has_baseline_and_broad_forgery_battery() {
        let corpus = adversarial_corpus().expect("corpus builds");
        let accepts = corpus.iter().filter(|c| c.expect == Expect::Accept).count();
        let rejects = corpus.iter().filter(|c| c.expect == Expect::Reject).count();
        assert!(accepts >= 1, "must carry a valid baseline (anti-vacuous)");
        assert!(
            rejects >= 10,
            "expected a broad forgery battery, got {rejects}"
        );
    }

    #[test]
    fn audit_passes_against_the_real_verify_funnel() {
        // Load-bearing: every forgery is rejected by the REAL apply/decode
        // funnel and the valid baseline is accepted. A verify_strict->verify
        // regression or a dropped check makes this fail.
        let report = run_membership_signature_audit().expect("audit runs");
        assert!(
            report.overall_ok,
            "membership signature audit found violations: {:?}",
            report.violations
        );
        assert!(report.baseline_accepted >= 1);
        assert_eq!(
            report.total_cases,
            report.forgeries_rejected + report.baseline_accepted
        );
    }

    #[test]
    fn malleable_s_is_rejected_by_verify_strict_and_is_congruent() {
        // Proves the malleability construction is correct AND meaningful:
        //   (a) `verify_strict` accepts the original canonical signature;
        //   (b) `verify_strict` REJECTS the mutated S' = S + ℓ (RN-22) — the
        //       property the production apply funnel relies on; and
        //   (c) S' is genuinely *congruent* (S' - ℓ == S), i.e. a true
        //       malleable variant, not random garbage that would be trivially
        //       rejected. The arithmetic check is version-independent (it does
        //       not depend on whether this dalek's non-strict verify also
        //       rejects non-canonical S — modern dalek does, which is stricter).
        let _ = Signature::from_bytes; // keep the import meaningful across versions
        let signing = key(1);
        let verifying: VerifyingKey = signing.verifying_key();
        let message = b"rn22-malleability-probe";
        let original = ed25519_dalek::Signer::sign(&signing, message);
        assert!(
            verifying.verify_strict(message, &original).is_ok(),
            "the original canonical signature must verify_strict"
        );
        let original_bytes = original.to_bytes();
        let malleated_hex = malleate_signature_hex(&hex_lower(&original_bytes)).expect("malleate");
        let malleated_bytes = decode_hex_64(&malleated_hex).expect("decode");
        let malleated = Signature::from_bytes(&malleated_bytes);
        assert!(
            verifying.verify_strict(message, &malleated).is_err(),
            "verify_strict must reject S + group_order (RN-22)"
        );

        // (c) Congruence: subtract ℓ from S' with borrow; must equal original S.
        let mut s_prime = [0u8; 32];
        s_prime.copy_from_slice(&malleated_bytes[32..64]);
        let mut borrow = 0i16;
        let mut recovered = [0u8; 32];
        for i in 0..32 {
            let diff = s_prime[i] as i16 - ED25519_GROUP_ORDER_LE[i] as i16 - borrow;
            if diff < 0 {
                recovered[i] = (diff + 256) as u8;
                borrow = 1;
            } else {
                recovered[i] = diff as u8;
                borrow = 0;
            }
        }
        assert_eq!(borrow, 0, "S' - ℓ must not underflow");
        assert_eq!(
            recovered,
            original_bytes[32..64],
            "S' must equal S + ℓ (a congruent malleable variant)"
        );
    }

    #[test]
    fn audit_bites_when_a_forgery_is_accepted() {
        // Relabel the valid baseline as a forgery (Reject): the funnel accepts
        // it, so evaluate_case must flag a violation — the regression signal.
        let valid = valid_signed_update("update-bite").expect("valid update");
        let mislabeled = SignatureAuditCase {
            id: "bite_probe",
            path: CasePath::Apply,
            expect: Expect::Reject,
            expect_reason_contains: "signature verification failed",
            signed_update: Some(valid),
            preseed_replay: None,
            raw_payload: None,
        };
        let result = evaluate_case(&mislabeled);
        assert!(!result.rejected, "a valid update is accepted by the funnel");
        assert!(!result.passed, "an accepted Reject-case must be flagged");
        let report = build_membership_signature_audit_report(&[mislabeled]);
        assert!(!report.overall_ok);
        assert_eq!(report.violations.len(), 1);
    }
}
