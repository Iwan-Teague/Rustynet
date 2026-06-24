#![forbid(unsafe_code)]

//! Live-lab chaos stage: membership-verifier adversarial sweep.
//!
//! Converts the former `chaos_membership_adversarial` scaffold into a real proof
//! of SecurityMinimumBar §4 ("Enforce signed control/trust state validation
//! before mutation" / "Enforce anti-replay and rollback protection where state
//! freshness matters").
//!
//! It drives the *real* membership verifier
//! ([`rustynet_control::membership::apply_signed_update`] — the exact signed-state
//! application funnel the daemon runs in production before any membership state is
//! mutated — and its decode sibling
//! [`rustynet_control::membership::decode_signed_update`]) with a battery of
//! forged signed updates and asserts every one is rejected fail-closed. The whole
//! sweep is built from throwaway in-process Ed25519 keys against a synthetic
//! membership network; it touches no production key, file, or state and never
//! accepts a forged bundle, so it is rejection-only by construction.
//!
//! Scope honesty: this slice fully exercises the offline forged-bundle portion of
//! each category. The live-injection remainder of each named stage (concurrent
//! mutation races, owner-key rotation against a running daemon, mesh-rejoin
//! traversal-drop, on-disk log bit-flip on a guest) requires a live coordinated
//! lab and is recorded transparently as `skipped` (future increments) — never
//! claimed as passed.

mod live_chaos_support;

use std::fs;
use std::path::Path;

use ed25519_dalek::SigningKey;
use live_chaos_support::{ChaosConfig, ChaosStage, parse_config, unix_now};
use rustynet_control::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipApprover, MembershipApproverRole,
    MembershipApproverStatus, MembershipNode, MembershipNodeStatus, MembershipOperation,
    MembershipReplayCache, MembershipSignature, MembershipState, MembershipUpdateRecord,
    SignedMembershipUpdate, apply_signed_update, decode_signed_update, encode_signed_update,
    preview_next_state, sign_update_record,
};
use rustynet_control::roles::RoleCapability;
use serde_json::{Value, json};

const CATEGORY: &str = "chaos_membership_adversarial";

/// Synthetic network id — never collides with any real deployment.
const CHAOS_NETWORK_ID: &str = "chaos-net";
/// Fixed evaluation clock so freshness checks are deterministic.
const CHAOS_NOW_UNIX: u64 = 1_000_000;

/// Each adversarial case is mapped to exactly one of the four category stages so
/// the report can honestly report per-stage pass/skip status.
#[derive(Clone, Copy, PartialEq, Eq)]
enum CaseStage {
    ConcurrentRoleTransitions,
    OwnerKeyCompromise,
    RevokedNodePersistence,
    LogTamper,
}

const STAGE_CONCURRENT: &str = "chaos_concurrent_role_transitions";
const STAGE_OWNER_KEY: &str = "chaos_owner_key_compromise_simulation";
const STAGE_REVOKED: &str = "chaos_revoked_node_persistence";
const STAGE_LOG_TAMPER: &str = "chaos_membership_log_tamper";

impl CaseStage {
    fn stage_name(self) -> &'static str {
        match self {
            CaseStage::ConcurrentRoleTransitions => STAGE_CONCURRENT,
            CaseStage::OwnerKeyCompromise => STAGE_OWNER_KEY,
            CaseStage::RevokedNodePersistence => STAGE_REVOKED,
            CaseStage::LogTamper => STAGE_LOG_TAMPER,
        }
    }
}

/// Which production entry point a case drives.
#[derive(Clone, Copy)]
enum VerifyPath {
    /// Forge a fully-formed `SignedMembershipUpdate` and run it through
    /// `apply_signed_update`.
    Apply,
    /// Hand a raw (malformed/truncated/empty) envelope string to
    /// `decode_signed_update`.
    Decode,
}

/// A single forged membership update (or raw envelope) that MUST be rejected.
struct AdversarialCase {
    id: &'static str,
    stage: CaseStage,
    path: VerifyPath,
    /// Lowercased substring that must appear in the rejection reason, so we
    /// assert the *right* control rejected (not an unrelated error).
    expect_reason_contains: &'static str,
    rationale: &'static str,
    /// For `VerifyPath::Apply`: the forged signed update applied against
    /// `synthetic_state()`. `None` for decode-path cases.
    signed_update: Option<SignedMembershipUpdate>,
    /// For `VerifyPath::Apply` replay cases: pre-seed the replay cache so the
    /// case reaches `replay_cache.observe`. `None` means a fresh cache.
    preseed_replay: Option<(String, u64)>,
    /// For `VerifyPath::Decode`: the raw envelope string handed to the decoder.
    raw_payload: Option<String>,
}

/// Lowercase hex encode (no external `hex` dep in this bin).
fn hex_lower(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(LUT[(byte >> 4) as usize] as char);
        out.push(LUT[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Deterministic in-process signing key from a single seed byte.
fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

/// Public-key hex for an in-process key (32-byte verifying key).
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
        owner: "chaos-owner@example.local".to_owned(),
        status: MembershipNodeStatus::Active,
        roles: vec!["tag:servers".to_owned()],
        capabilities: vec![RoleCapability::Anchor],
        joined_at_unix: 100,
        updated_at_unix: 100,
    }
}

/// The self-contained synthetic network the whole sweep runs against: one node,
/// an owner approver (key seed 1) plus two guardian approvers (seeds 2/3), quorum
/// threshold 2. Mirrors the production crate's own `base_state()` test fixture
/// using only public types.
fn synthetic_state() -> MembershipState {
    MembershipState {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        network_id: CHAOS_NETWORK_ID.to_owned(),
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

/// A legitimate `SetNodeCapabilities` operation on the synthetic network.
fn valid_operation() -> MembershipOperation {
    MembershipOperation::SetNodeCapabilities {
        node_id: "node-a".to_owned(),
        capabilities: vec![RoleCapability::Anchor, RoleCapability::Client],
    }
}

/// Build the canonical, *correct* update record for `valid_operation()` against
/// `synthetic_state()`: correct prev/new state roots, epoch chain, and freshness.
/// This is the honest baseline every forged case is derived from, so a forged
/// case reaches its intended rejection rather than tripping an earlier check.
fn valid_record(update_id: &str) -> Result<(MembershipState, MembershipUpdateRecord), String> {
    let state = synthetic_state();
    let operation = valid_operation();
    // RSA-0009: match the record's created_at_unix below.
    let next = preview_next_state(&state, &operation, CHAOS_NOW_UNIX - 10)
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
        created_at_unix: CHAOS_NOW_UNIX - 10,
        expires_at_unix: CHAOS_NOW_UNIX + 600,
        reason_code: "chaos".to_owned(),
        policy_context: None,
    };
    Ok((state, record))
}

/// Sign `record` with the in-process owner and guardian-1 keys (quorum 2, owner
/// present) — the canonical valid signature set.
fn quorum_signatures(record: &MembershipUpdateRecord) -> Result<Vec<MembershipSignature>, String> {
    Ok(vec![
        sign_update_record(record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?,
        sign_update_record(record, "guardian-1", &key(2))
            .map_err(|err| format!("guardian sign failed: {err}"))?,
    ])
}

/// Build a fully valid signed update (used by the load-bearing accept test and as
/// the basis for replay forgery).
fn valid_signed_update(update_id: &str) -> Result<SignedMembershipUpdate, String> {
    let (_state, record) = valid_record(update_id)?;
    let signatures = quorum_signatures(&record)?;
    Ok(SignedMembershipUpdate {
        record,
        approver_signatures: signatures,
    })
}

/// Assemble the forged adversarial battery. Every case is engineered so the
/// earlier checks in `apply_signed_update` pass and execution reaches the one
/// control under test (see the check order documented on the function).
fn adversarial_cases() -> Result<Vec<AdversarialCase>, String> {
    let mut cases = Vec::new();

    // 1. forged_owner_signature: valid record, flip one hex char of a signature
    //    → reaches verify_membership_signatures → SignatureInvalid.
    {
        let (_state, record) = valid_record("update-forged-sig")?;
        let mut signatures = quorum_signatures(&record)?;
        // Flip the leading hex nibble of the owner signature.
        let sig = &mut signatures[0].signature_hex;
        let flipped = if sig.starts_with('f') { "0" } else { "f" };
        sig.replace_range(0..1, flipped);
        cases.push(AdversarialCase {
            id: "forged_owner_signature",
            stage: CaseStage::OwnerKeyCompromise,
            path: VerifyPath::Apply,
            expect_reason_contains: "signature verification failed",
            rationale: "a tampered signature must fail strict Ed25519 verification",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 2. unauthorized_signer_key: sign with an off-roster key claiming an
    //    approver_id that is not in the active set → SignerNotAuthorized.
    {
        let (_state, record) = valid_record("update-unauthorized-signer")?;
        // owner-1 signs legitimately to clear the threshold; the second signer
        // is an attacker id signed with off-roster key seed 99.
        let owner_sig = sign_update_record(&record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?;
        let rogue_sig = sign_update_record(&record, "attacker-1", &key(99))
            .map_err(|err| format!("rogue sign failed: {err}"))?;
        cases.push(AdversarialCase {
            id: "unauthorized_signer_key",
            stage: CaseStage::OwnerKeyCompromise,
            path: VerifyPath::Apply,
            expect_reason_contains: "signer is not authorized",
            rationale: "a signer id absent from the active approver set is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: vec![owner_sig, rogue_sig],
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 3. quorum_below_threshold: only 1 signature when threshold=2 →
    //    ThresholdNotMet.
    {
        let (_state, record) = valid_record("update-below-threshold")?;
        let owner_sig = sign_update_record(&record, "owner-1", &key(1))
            .map_err(|err| format!("owner sign failed: {err}"))?;
        cases.push(AdversarialCase {
            id: "quorum_below_threshold",
            stage: CaseStage::ConcurrentRoleTransitions,
            path: VerifyPath::Apply,
            expect_reason_contains: "threshold signature requirements not met",
            rationale: "fewer signatures than the quorum threshold is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: vec![owner_sig],
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 4. future_dated_update: created_at_unix beyond now + clock skew → FutureDated.
    {
        let (_state, mut record) = valid_record("update-future-dated")?;
        record.created_at_unix = CHAOS_NOW_UNIX + 3600;
        // Keep expires_at_unix strictly greater than created_at_unix so the
        // canonical-payload invariant holds and the freshness check is reached.
        record.expires_at_unix = record.created_at_unix + 600;
        let signatures = quorum_signatures(&record)?;
        cases.push(AdversarialCase {
            id: "future_dated_update",
            stage: CaseStage::ConcurrentRoleTransitions,
            path: VerifyPath::Apply,
            expect_reason_contains: "future dated",
            rationale: "an update created beyond the clock-skew window is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 5. expired_update: expires_at_unix before now → Expired.
    {
        let (_state, mut record) = valid_record("update-expired")?;
        record.created_at_unix = CHAOS_NOW_UNIX - 1000;
        record.expires_at_unix = CHAOS_NOW_UNIX - 500;
        let signatures = quorum_signatures(&record)?;
        cases.push(AdversarialCase {
            id: "expired_update",
            stage: CaseStage::RevokedNodePersistence,
            path: VerifyPath::Apply,
            expect_reason_contains: "expired",
            rationale: "an update past its expiry is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 6. replayed_update: a fully valid update whose id+epoch are pre-seeded
    //    into the replay cache, so the evaluated apply reaches
    //    replay_cache.observe → ReplayDetected. Applied against the same
    //    original state so all earlier checks pass.
    {
        let signed = valid_signed_update("update-replayed")?;
        let update_id = signed.record.update_id.clone();
        let epoch_new = signed.record.epoch_new;
        cases.push(AdversarialCase {
            id: "replayed_update",
            stage: CaseStage::RevokedNodePersistence,
            path: VerifyPath::Apply,
            expect_reason_contains: "membership replay detected",
            rationale: "a previously-observed update id (or non-advancing epoch) is rejected",
            signed_update: Some(signed),
            preseed_replay: Some((update_id, epoch_new)),
            raw_payload: None,
        });
    }

    // 7. network_id_mismatch: record.network_id != state.network_id →
    //    InvalidTransition("network id mismatch"). Checked before freshness, so
    //    a valid-everywhere-else record still reaches it.
    {
        let (_state, mut record) = valid_record("update-network-mismatch")?;
        record.network_id = "wrong-net".to_owned();
        let signatures = quorum_signatures(&record)?;
        cases.push(AdversarialCase {
            id: "network_id_mismatch",
            stage: CaseStage::ConcurrentRoleTransitions,
            path: VerifyPath::Apply,
            expect_reason_contains: "network id mismatch",
            rationale: "an update targeting a different network id is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 8. prev_state_root_mismatch: tamper prev_state_root → PrevStateRootMismatch.
    {
        let (_state, mut record) = valid_record("update-prev-root")?;
        record.prev_state_root =
            "0000000000000000000000000000000000000000000000000000000000000000".to_owned();
        let signatures = quorum_signatures(&record)?;
        cases.push(AdversarialCase {
            id: "prev_state_root_mismatch",
            stage: CaseStage::RevokedNodePersistence,
            path: VerifyPath::Apply,
            expect_reason_contains: "previous state root mismatch",
            rationale: "an update not chained to the current state root is rejected",
            signed_update: Some(SignedMembershipUpdate {
                record,
                approver_signatures: signatures,
            }),
            preseed_replay: None,
            raw_payload: None,
        });
    }

    // 9. truncated_envelope (decode path): half-truncate a valid envelope string
    //    → invalid membership format (or unsupported version).
    {
        let signed = valid_signed_update("update-truncated")?;
        let envelope = encode_signed_update(&signed)
            .map_err(|err| format!("encode envelope failed: {err}"))?;
        let truncated = envelope[..envelope.len() / 2].to_owned();
        cases.push(AdversarialCase {
            id: "truncated_envelope",
            stage: CaseStage::LogTamper,
            path: VerifyPath::Decode,
            expect_reason_contains: "invalid membership format",
            rationale: "a half-truncated envelope cannot be decoded into a signed update",
            signed_update: None,
            preseed_replay: None,
            raw_payload: Some(truncated),
        });
    }

    // 10. empty_payload_default_deny (decode path): decode_signed_update("") →
    //     invalid membership format (default-deny on empty input).
    cases.push(AdversarialCase {
        id: "empty_payload_default_deny",
        stage: CaseStage::LogTamper,
        path: VerifyPath::Decode,
        expect_reason_contains: "invalid membership format",
        rationale: "an empty raw payload is rejected (default-deny)",
        signed_update: None,
        preseed_replay: None,
        raw_payload: Some(String::new()),
    });

    Ok(cases)
}

/// Outcome of evaluating one adversarial case against the real verifier.
struct CaseOutcome {
    id: &'static str,
    stage: CaseStage,
    rejected: bool,
    reason: String,
    expected_reason_contains: &'static str,
    reason_matches: bool,
    rationale: &'static str,
    passed: bool,
}

/// Evaluate a case through the production rejection path. For `Apply` cases the
/// forged update runs through `apply_signed_update` against the synthetic state;
/// for `Decode` cases the raw payload runs through `decode_signed_update`. Either
/// way an (unexpected) accept performs no production mutation — the state is
/// fully synthetic and in-memory.
fn evaluate(case: &AdversarialCase) -> CaseOutcome {
    let (rejected, reason) = match case.path {
        VerifyPath::Apply => {
            let signed = case
                .signed_update
                .as_ref()
                .expect("apply-path case carries a signed update");
            let state = synthetic_state();
            let mut cache = MembershipReplayCache::default();
            if let Some((update_id, epoch_new)) = &case.preseed_replay {
                // Pre-seed the cache so the evaluated apply reaches observe().
                let _ = cache.observe(update_id, *epoch_new);
            }
            match apply_signed_update(&state, signed, CHAOS_NOW_UNIX, &mut cache) {
                Ok(_) => (
                    false,
                    "ACCEPTED: verifier applied an adversarial update".to_owned(),
                ),
                Err(err) => (true, err.to_string()),
            }
        }
        VerifyPath::Decode => {
            let raw = case
                .raw_payload
                .as_ref()
                .expect("decode-path case carries a raw payload");
            match decode_signed_update(raw) {
                Ok(_) => (
                    false,
                    "ACCEPTED: decoder accepted a malformed envelope".to_owned(),
                ),
                Err(err) => (true, err.to_string()),
            }
        }
    };
    let reason_matches = reason
        .to_lowercase()
        .contains(&case.expect_reason_contains.to_lowercase());
    let passed = rejected && reason_matches;
    CaseOutcome {
        id: case.id,
        stage: case.stage,
        rejected,
        reason,
        expected_reason_contains: case.expect_reason_contains,
        reason_matches,
        rationale: case.rationale,
        passed,
    }
}

fn main() {
    let stages = category_stages();
    let parsed = parse_config(CATEGORY, stages, std::env::args().skip(1)).and_then(run);
    if let Err(err) = parsed {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

/// The four named slices of this category. The offline forged-bundle portion of
/// each is exercised here; the live-injection remainder is recorded `skipped`.
fn category_stages() -> Vec<ChaosStage> {
    vec![
        ChaosStage {
            name: STAGE_CONCURRENT,
            fault: "request mutually conflicting role transitions concurrently",
            pass_criterion: "only one role outcome wins, conflicts fail closed, audit log records resolution",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: STAGE_OWNER_KEY,
            fault: "rotate owner key while submitting updates from old key",
            pass_criterion: "post-rotation old-key updates are rejected while valid in-flight updates complete",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: STAGE_REVOKED,
            fault: "attempt mesh rejoin with stale assignment after revocation",
            pass_criterion: "revoked node fails closed and peers drop traversal targets",
            recovery_deadline_secs: 120,
        },
        ChaosStage {
            name: STAGE_LOG_TAMPER,
            fault: "bit-flip membership log after write",
            pass_criterion: "digest mismatch is detected and derived state is refused",
            recovery_deadline_secs: 120,
        },
    ]
}

fn run(config: ChaosConfig) -> Result<(), String> {
    let cases = adversarial_cases()?;
    let outcomes: Vec<CaseOutcome> = cases.iter().map(evaluate).collect();
    let all_passed = outcomes.iter().all(|outcome| outcome.passed);
    let accepted_count = outcomes.iter().filter(|outcome| !outcome.rejected).count();

    write_log(&config, &outcomes)?;

    let report = render_report(&config, &outcomes, all_passed, accepted_count);
    write_parent(&config.report_path)?;
    fs::write(
        &config.report_path,
        serde_json::to_string_pretty(&report)
            .map_err(|err| format!("serialise membership chaos report failed: {err}"))?,
    )
    .map_err(|err| format!("write {} failed: {err}", config.report_path.display()))?;

    if all_passed {
        Ok(())
    } else {
        Err(format!(
            "membership adversarial sweep failed: {} of {} cases not rejected as expected ({} accepted)",
            outcomes.iter().filter(|outcome| !outcome.passed).count(),
            outcomes.len(),
            accepted_count,
        ))
    }
}

fn write_log(config: &ChaosConfig, outcomes: &[CaseOutcome]) -> Result<(), String> {
    write_parent(&config.log_path)?;
    let mut body = format!(
        "category={CATEGORY}\ndry_run={}\ngenerated_at_unix={}\ncase_count={}\n",
        config.dry_run,
        unix_now(),
        outcomes.len(),
    );
    for outcome in outcomes {
        body.push_str(&format!(
            "case={} stage={} rejected={} reason_matches={} passed={} reason={}\n",
            outcome.id,
            outcome.stage.stage_name(),
            outcome.rejected,
            outcome.reason_matches,
            outcome.passed,
            outcome.reason,
        ));
    }
    fs::write(&config.log_path, body)
        .map_err(|err| format!("write {} failed: {err}", config.log_path.display()))
}

fn render_report(
    config: &ChaosConfig,
    outcomes: &[CaseOutcome],
    all_passed: bool,
    accepted_count: usize,
) -> Value {
    let stage_values: Vec<Value> = config
        .stages
        .iter()
        .map(|stage| {
            let stage_cases: Vec<&CaseOutcome> = outcomes
                .iter()
                .filter(|outcome| outcome.stage.stage_name() == stage.name)
                .collect();
            let stage_passed =
                !stage_cases.is_empty() && stage_cases.iter().all(|outcome| outcome.passed);
            let case_values: Vec<Value> = stage_cases
                .iter()
                .map(|outcome| {
                    json!({
                        "case": outcome.id,
                        "rejected": outcome.rejected,
                        "expected_reason_contains": outcome.expected_reason_contains,
                        "reason_matches": outcome.reason_matches,
                        "reason": outcome.reason,
                        "rationale": outcome.rationale,
                        "status": if outcome.passed { "pass" } else { "fail" },
                    })
                })
                .collect();
            json!({
                "name": stage.name,
                "status": if stage_passed { "pass" } else { "fail" },
                "fault": stage.fault,
                "pass_criterion": stage.pass_criterion,
                "recovery_deadline_secs": stage.recovery_deadline_secs,
                "measured_recovery_secs": 0,
                "plaintext_leak_check": "not-applicable-offline",
                "production_state_mutation": false,
                "expected_result": "reject_fail_closed",
                "offline_case_count": stage_cases.len(),
                "offline_cases": case_values,
                "live_injection_remainder": "skipped",
                "skip_reason": "the live-injection portion of this stage (coordinated daemon/lab fault) is not exercised by the offline forged-bundle slice",
            })
        })
        .collect();

    json!({
        "schema_version": 1,
        "suite": "rustynet-live-lab-chaos",
        "category": CATEGORY,
        "overall_status": if all_passed { "pass" } else { "fail" },
        "summary": "offline forged membership updates are rejected fail-closed by the production verifier; the live coordinated-fault remainder of each stage is not yet exercised",
        "dry_run": config.dry_run,
        "generated_at_unix": unix_now(),
        "git_commit": config.git_commit,
        "offline_case_count": outcomes.len(),
        "stages": stage_values,
        "security_invariants": {
            "requires_explicit_enable_chaos_suite": true,
            "requires_teardown_registration_before_injection": false,
            "requires_plaintext_leak_capture_for_live_faults": false,
            "production_state_mutation": false,
            "offline_only": true,
            "production_accepted": false,
            "expected_result": "reject_fail_closed",
            "verifier_rejects_all_forged_updates": all_passed,
            "no_forged_update_accepted": accepted_count == 0
        }
    })
}

fn write_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| format!("create {} failed: {err}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_adversarial_case_is_rejected_with_expected_reason() {
        let cases = adversarial_cases().expect("adversarial battery should build");
        for case in &cases {
            let outcome = evaluate(case);
            assert!(
                outcome.rejected,
                "case `{}` was ACCEPTED by the membership verifier (reason={})",
                case.id, outcome.reason
            );
            assert!(
                outcome.reason_matches,
                "case `{}` rejected but reason did not contain `{}` (reason={})",
                case.id, case.expect_reason_contains, outcome.reason
            );
            assert!(outcome.passed, "case `{}` did not pass", case.id);
        }
    }

    #[test]
    fn no_adversarial_bundle_is_accepted() {
        let cases = adversarial_cases().expect("adversarial battery should build");
        let accepted: Vec<&'static str> = cases
            .iter()
            .filter(|case| !evaluate(case).rejected)
            .map(|case| case.id)
            .collect();
        assert!(
            accepted.is_empty(),
            "adversarial bundles unexpectedly accepted: {accepted:?}"
        );
    }

    #[test]
    fn verifier_accepts_a_valid_bundle_so_rejections_are_meaningful() {
        // Load-bearing: prove the verifier is not rejecting everything. A fully
        // valid update (owner + guardian signatures, correct roots/epoch) must
        // apply cleanly and advance the epoch by exactly one.
        let signed =
            valid_signed_update("update-valid-control").expect("valid signed update should build");
        let state = synthetic_state();
        let mut cache = MembershipReplayCache::default();
        let applied = apply_signed_update(&state, &signed, CHAOS_NOW_UNIX, &mut cache)
            .expect("a fully valid membership update must be accepted");
        assert_eq!(
            applied.epoch,
            state.epoch + 1,
            "a valid update must advance the epoch by exactly one"
        );
    }

    #[test]
    fn sweep_covers_signature_freshness_replay_and_malformed_paths() {
        let cases = adversarial_cases().expect("adversarial battery should build");
        let ids: Vec<&'static str> = cases.iter().map(|case| case.id).collect();
        // signature class
        assert!(ids.contains(&"forged_owner_signature"));
        assert!(ids.contains(&"unauthorized_signer_key"));
        assert!(ids.contains(&"quorum_below_threshold"));
        // freshness class
        assert!(ids.contains(&"future_dated_update"));
        assert!(ids.contains(&"expired_update"));
        // replay class
        assert!(ids.contains(&"replayed_update"));
        // malformed / decode class
        assert!(ids.contains(&"truncated_envelope"));
        assert!(ids.contains(&"empty_payload_default_deny"));
    }
}
