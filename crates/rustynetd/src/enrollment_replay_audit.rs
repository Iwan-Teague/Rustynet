//! Adversarial self-audit proving ENR-1 (single-use enrollment token replay
//! is denied) and TOCTOU-1 (concurrent redemption of the same token cannot
//! double-spend it) actually hold against the REAL shipped enrollment-token
//! code path — not just in the crate's own `#[cfg(test)]` unit tests.
//!
//! Companion of the orchestrator-side `evaluate_enrollment_replay_report` in
//! `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynetd enrollment-replay-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.3 (CWE-362, TOCTOU) requires a single-use
//! credential to be redeemable exactly once even under concurrent redemption
//! attempts. `enrollment_token::acquire_ledger_lock` (RSA-0023) already
//! serializes the daemon's real `handle_enrollment_consume` IPC handler
//! around the locked `load_ledger -> verify_and_consume_token_with_now ->
//! write_ledger` sequence. This audit does not change that code; it proves
//! the fix by driving it, in-process, against a throwaway on-disk ledger
//! (touches no production spool path):
//!
//!   - ENR-1: redeeming the same token twice, sequentially, MUST succeed
//!     once and then fail with `AlreadyConsumed`;
//!   - TOCTOU-1: 8 threads racing to redeem the SAME token, each performing
//!     the real locked read-modify-write sequence, MUST yield exactly ONE
//!     success;
//!   - a baseline case redeems two DIFFERENT tokens sequentially and
//!     requires BOTH to succeed, so the audit cannot pass by vacuously
//!     denying everything.
//!
//! It FAILs LOUD (non-zero exit) if a token is ever redeemed more than once,
//! if concurrent racers double-spend, or if the vacuous-deny-all baseline
//! is wrongly rejected.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use tempfile::TempDir;

use crate::enrollment_token::{
    ConsumedTokenLedger, ENROLLMENT_SECRET_LEN, EnrollmentTokenError, acquire_ledger_lock,
    load_ledger, mint_token_with_clock, verify_and_consume_token_with_now, write_ledger,
};

const ENROLLMENT_REPLAY_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_TOKEN_TTL_SECS: u64 = 600;
const AUDIT_ISSUED_AT_UNIX: u64 = 1_700_000_000;
const AUDIT_REDEEM_AT_UNIX: u64 = 1_700_000_300;
const TOCTOU_RACER_COUNT: usize = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentReplayAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the "must reject" replay/race cases correctly REJECTED
    /// (sequential-replay-denied + toctou-race-single-winner).
    pub replay_denied: u32,
    /// Count of the "must accept" baseline case correctly ACCEPTED
    /// (two distinct tokens both redeemed).
    pub baseline_accepted: u32,
    pub violations: Vec<EnrollmentReplayCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentReplayCaseResult {
    pub id: String,
    pub expectation: String,
    pub outcome: String,
    pub reason: String,
    pub passed: bool,
}

fn failed(id: &str, expectation: &str, reason: String) -> EnrollmentReplayCaseResult {
    EnrollmentReplayCaseResult {
        id: id.to_owned(),
        expectation: expectation.to_owned(),
        outcome: "build_failed".to_owned(),
        reason,
        passed: false,
    }
}

/// ENR-1: sequential replay of the SAME token must succeed exactly once,
/// then be denied with `AlreadyConsumed` on the second attempt — driven
/// against a real on-disk ledger via the locked read-modify-write sequence
/// (same shape as the daemon's `handle_enrollment_consume`).
fn run_sequential_replay_case() -> EnrollmentReplayCaseResult {
    const ID: &str = "sequential_replay_denied";
    let dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(err) => return failed(ID, "reject", format!("tempdir: {err}")),
    };
    let path = dir.path().join("enrollment.ledger");
    let secret = [0x11u8; ENROLLMENT_SECRET_LEN];
    let (_, encoded) =
        match mint_token_with_clock(&secret, AUDIT_TOKEN_TTL_SECS, AUDIT_ISSUED_AT_UNIX) {
            Ok(pair) => pair,
            Err(err) => return failed(ID, "reject", format!("mint failed: {err:?}")),
        };
    if let Err(err) = write_ledger(&path, &ConsumedTokenLedger::new()) {
        return failed(ID, "reject", format!("seed ledger failed: {err}"));
    }

    let redeem = |now_unix: u64| -> Result<(), EnrollmentTokenError> {
        let _lock = acquire_ledger_lock(&path).map_err(|err| {
            EnrollmentTokenError::Malformed(format!("acquire lock failed: {err}"))
        })?;
        let mut ledger = load_ledger(&path)
            .map_err(|err| EnrollmentTokenError::Malformed(format!("load ledger: {err}")))?;
        let result = verify_and_consume_token_with_now(&encoded, &secret, &mut ledger, now_unix);
        if result.is_ok() {
            write_ledger(&path, &ledger)
                .map_err(|err| EnrollmentTokenError::Malformed(format!("write ledger: {err}")))?;
        }
        result.map(|_| ())
    };

    if let Err(err) = redeem(AUDIT_REDEEM_AT_UNIX) {
        return failed(
            ID,
            "reject",
            format!("first redemption must succeed: {err:?}"),
        );
    }
    match redeem(AUDIT_REDEEM_AT_UNIX + 100) {
        Err(EnrollmentTokenError::AlreadyConsumed) => EnrollmentReplayCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "rejected".to_owned(),
            reason: "AlreadyConsumed on second redemption, as required".to_owned(),
            passed: true,
        },
        Err(other) => EnrollmentReplayCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "rejected_other".to_owned(),
            reason: format!("wrong rejection reason: {other:?}"),
            passed: false,
        },
        Ok(()) => EnrollmentReplayCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "VIOLATION: single-use token redeemed twice".to_owned(),
            passed: false,
        },
    }
}

/// TOCTOU-1: N threads race to redeem the SAME token, each performing the
/// real locked `acquire_ledger_lock -> load_ledger -> verify_and_consume ->
/// write_ledger` sequence. Exactly one may win.
fn run_concurrent_race_case() -> EnrollmentReplayCaseResult {
    const ID: &str = "toctou_race_single_winner";
    let dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(err) => return failed(ID, "reject", format!("tempdir: {err}")),
    };
    let path = Arc::new(dir.path().join("enrollment.ledger"));
    let secret = [0x22u8; ENROLLMENT_SECRET_LEN];
    let (_, encoded) =
        match mint_token_with_clock(&secret, AUDIT_TOKEN_TTL_SECS, AUDIT_ISSUED_AT_UNIX) {
            Ok(pair) => pair,
            Err(err) => return failed(ID, "reject", format!("mint failed: {err:?}")),
        };
    let encoded = Arc::new(encoded);
    if let Err(err) = write_ledger(&path, &ConsumedTokenLedger::new()) {
        return failed(ID, "reject", format!("seed ledger failed: {err}"));
    }

    let successes = Arc::new(AtomicUsize::new(0));
    let threads: Vec<_> = (0..TOCTOU_RACER_COUNT)
        .map(|_| {
            let path = Arc::clone(&path);
            let encoded = Arc::clone(&encoded);
            let successes = Arc::clone(&successes);
            std::thread::spawn(move || -> Result<(), String> {
                let _lock =
                    acquire_ledger_lock(&path).map_err(|err| format!("acquire lock: {err}"))?;
                let mut ledger = load_ledger(&path).map_err(|err| format!("load ledger: {err}"))?;
                if verify_and_consume_token_with_now(
                    &encoded,
                    &secret,
                    &mut ledger,
                    AUDIT_REDEEM_AT_UNIX,
                )
                .is_ok()
                {
                    write_ledger(&path, &ledger).map_err(|err| format!("write ledger: {err}"))?;
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                Ok(())
            })
        })
        .collect();

    for handle in threads {
        match handle.join() {
            Ok(Ok(())) => {}
            Ok(Err(err)) => return failed(ID, "reject", format!("racer failed: {err}")),
            Err(_) => return failed(ID, "reject", "racer thread panicked".to_owned()),
        }
    }

    let won = successes.load(Ordering::SeqCst);
    let final_count = match load_ledger(&path) {
        Ok(ledger) => ledger.consumed_count(),
        Err(err) => return failed(ID, "reject", format!("final load failed: {err}")),
    };
    if won == 1 && final_count == 1 {
        EnrollmentReplayCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "rejected".to_owned(),
            reason: format!(
                "{TOCTOU_RACER_COUNT} concurrent racers, exactly 1 redeemed the single-use token"
            ),
            passed: true,
        }
    } else {
        EnrollmentReplayCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: format!(
                "VIOLATION: {won} of {TOCTOU_RACER_COUNT} racers redeemed (ledger holds {final_count} entries); single-use token must be redeemable exactly once"
            ),
            passed: false,
        }
    }
}

/// Baseline: two DISTINCT tokens, each redeemed once, must BOTH succeed —
/// proves the audit's denial cases aren't just a lock that rejects
/// everything.
fn run_baseline_distinct_tokens_case() -> EnrollmentReplayCaseResult {
    const ID: &str = "distinct_tokens_both_accepted";
    let dir = match TempDir::new() {
        Ok(dir) => dir,
        Err(err) => return failed(ID, "accept", format!("tempdir: {err}")),
    };
    let path = dir.path().join("enrollment.ledger");
    let secret = [0x33u8; ENROLLMENT_SECRET_LEN];
    let (_, encoded_a) =
        match mint_token_with_clock(&secret, AUDIT_TOKEN_TTL_SECS, AUDIT_ISSUED_AT_UNIX) {
            Ok(pair) => pair,
            Err(err) => return failed(ID, "accept", format!("mint a failed: {err:?}")),
        };
    let (_, encoded_b) =
        match mint_token_with_clock(&secret, AUDIT_TOKEN_TTL_SECS, AUDIT_ISSUED_AT_UNIX) {
            Ok(pair) => pair,
            Err(err) => return failed(ID, "accept", format!("mint b failed: {err:?}")),
        };
    if encoded_a == encoded_b {
        return failed(
            ID,
            "accept",
            "minted tokens collided; cannot exercise distinct-token baseline".to_owned(),
        );
    }
    if let Err(err) = write_ledger(&path, &ConsumedTokenLedger::new()) {
        return failed(ID, "accept", format!("seed ledger failed: {err}"));
    }

    for encoded in [&encoded_a, &encoded_b] {
        let _lock = match acquire_ledger_lock(&path) {
            Ok(lock) => lock,
            Err(err) => return failed(ID, "accept", format!("acquire lock: {err}")),
        };
        let mut ledger = match load_ledger(&path) {
            Ok(ledger) => ledger,
            Err(err) => return failed(ID, "accept", format!("load ledger: {err}")),
        };
        if let Err(err) =
            verify_and_consume_token_with_now(encoded, &secret, &mut ledger, AUDIT_REDEEM_AT_UNIX)
        {
            return EnrollmentReplayCaseResult {
                id: ID.to_owned(),
                expectation: "accept".to_owned(),
                outcome: "rejected".to_owned(),
                reason: format!(
                    "VIOLATION: distinct never-before-seen token wrongly denied: {err:?}"
                ),
                passed: false,
            };
        }
        if let Err(err) = write_ledger(&path, &ledger) {
            return failed(ID, "accept", format!("write ledger: {err}"));
        }
    }

    EnrollmentReplayCaseResult {
        id: ID.to_owned(),
        expectation: "accept".to_owned(),
        outcome: "accepted".to_owned(),
        reason: "both distinct tokens redeemed exactly once, as required".to_owned(),
        passed: true,
    }
}

pub fn run_enrollment_replay_audit() -> Result<EnrollmentReplayAuditReport, String> {
    let results = [
        run_sequential_replay_case(),
        run_concurrent_race_case(),
        run_baseline_distinct_tokens_case(),
    ];

    let replay_denied = results
        .iter()
        .filter(|r| r.expectation == "reject" && r.passed)
        .count() as u32;
    let baseline_accepted = results
        .iter()
        .filter(|r| r.expectation == "accept" && r.passed)
        .count() as u32;
    let violations: Vec<EnrollmentReplayCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    Ok(EnrollmentReplayAuditReport {
        schema_version: ENROLLMENT_REPLAY_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        replay_denied,
        baseline_accepted,
        violations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_enrollment_token_code_path() {
        let report = run_enrollment_replay_audit().expect("audit runs");
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 3);
        assert_eq!(report.replay_denied, 2);
        assert_eq!(report.baseline_accepted, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn sequential_replay_case_is_individually_denied() {
        let result = run_sequential_replay_case();
        assert!(result.passed, "replay must be denied: {result:?}");
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn concurrent_race_case_yields_single_winner() {
        let result = run_concurrent_race_case();
        assert!(
            result.passed,
            "race must yield exactly one winner: {result:?}"
        );
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn baseline_case_is_accepted_not_vacuously_denied() {
        let result = run_baseline_distinct_tokens_case();
        assert!(
            result.passed,
            "distinct tokens must both succeed: {result:?}"
        );
        assert_eq!(result.outcome, "accepted");
    }
}
