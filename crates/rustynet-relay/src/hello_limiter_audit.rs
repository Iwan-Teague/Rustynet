//! Adversarial self-audit proving DOS-1's fix actually works: a pre-auth
//! flood of distinct `node_id` strings against `HelloLimiter::check` must
//! not grow the limiter's map without bound.
//!
//! Companion of the orchestrator-side `evaluate_hello_limiter_flood_report`
//! in `crates/rustynet-cli/src/vm_lab/mod.rs`, wired as
//! `rustynet-relay hello-limiter-audit`.
//!
//! ## What this proves
//!
//! `SecurityMinimumBar.md` §3.3 (CWE-770, resource exhaustion) requires a
//! pre-auth-reachable counter to be bounded. `HelloLimiter::check` is
//! consulted from `handle_hello` BEFORE the ed25519 signature check, keyed
//! on the attacker-controlled `node_id` string — without a cap, a flood of
//! distinct `node_id`s could grow the map without limit (RSA-0037). The fix
//! (`MAX_HELLO_LIMITER_ENTRIES`) hard-caps the map and rejects a brand-new
//! `node_id` once at capacity, pruning elapsed windows first.
//!
//! This audit drives the REAL shipped `HelloLimiter`, in-process, with the
//! REAL production cap value (not a test-only override):
//!   - flooding `MAX_HELLO_LIMITER_ENTRIES` distinct `node_id`s must all be
//!     allowed, and the map must never exceed the cap;
//!   - one more distinct `node_id` beyond the cap MUST be denied;
//!   - a baseline case on a FRESH limiter proves a single legitimate
//!     `node_id`'s first hello is still allowed (the guard isn't vacuously
//!     "always deny").
//!
//! It FAILs LOUD (non-zero exit) if the map ever grows past the cap or the
//! baseline case is wrongly denied.

use serde::{Deserialize, Serialize};

use crate::transport::{HelloLimiter, MAX_HELLO_LIMITER_ENTRIES};

const HELLO_LIMITER_AUDIT_SCHEMA_VERSION: u32 = 1;
const AUDIT_MAX_PER_SEC: u32 = 5;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloLimiterAuditReport {
    pub schema_version: u32,
    pub overall_ok: bool,
    pub total_cases: u32,
    /// Count of the 1 "must reject" case that was correctly REJECTED
    /// (a node_id beyond the cap).
    pub flood_denied: u32,
    /// Count of the 1 "must accept" baseline case that was correctly
    /// ACCEPTED.
    pub baseline_accepted: u32,
    pub violations: Vec<HelloLimiterCaseResult>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloLimiterCaseResult {
    pub id: String,
    pub expectation: String,
    pub outcome: String,
    pub reason: String,
    pub passed: bool,
}

fn run_flood_case() -> HelloLimiterCaseResult {
    const ID: &str = "distinct_node_id_flood_denied_beyond_cap";
    let mut limiter = HelloLimiter::new(AUDIT_MAX_PER_SEC);
    for index in 0..MAX_HELLO_LIMITER_ENTRIES {
        let node_id = format!("dos1-flood-node-{index}");
        if !limiter.check(&node_id) {
            return HelloLimiterCaseResult {
                id: ID.to_owned(),
                expectation: "reject".to_owned(),
                outcome: "false_reject".to_owned(),
                reason: format!(
                    "in-cap node_id #{index} was denied before reaching the {MAX_HELLO_LIMITER_ENTRIES}-entry cap"
                ),
                passed: false,
            };
        }
    }
    if limiter.entry_count() != MAX_HELLO_LIMITER_ENTRIES {
        return HelloLimiterCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "wrong_entry_count".to_owned(),
            reason: format!(
                "expected exactly {MAX_HELLO_LIMITER_ENTRIES} tracked entries after the flood, found {}",
                limiter.entry_count()
            ),
            passed: false,
        };
    }
    let overflow_allowed = limiter.check("dos1-overflow-node");
    let final_count = limiter.entry_count();
    if overflow_allowed || final_count > MAX_HELLO_LIMITER_ENTRIES {
        HelloLimiterCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "accepted".to_owned(),
            reason: format!(
                "VIOLATION: node_id beyond the cap was admitted (allowed={overflow_allowed}, map now holds {final_count} entries) — RSA-0037 regression"
            ),
            passed: false,
        }
    } else {
        HelloLimiterCaseResult {
            id: ID.to_owned(),
            expectation: "reject".to_owned(),
            outcome: "rejected".to_owned(),
            reason: format!(
                "{MAX_HELLO_LIMITER_ENTRIES} distinct node_ids admitted, the next one denied, map bounded at {final_count} entries"
            ),
            passed: true,
        }
    }
}

fn run_baseline_case() -> HelloLimiterCaseResult {
    const ID: &str = "single_node_hello_allowed";
    let mut limiter = HelloLimiter::new(AUDIT_MAX_PER_SEC);
    let allowed = limiter.check("dos1-baseline-node");
    if allowed {
        HelloLimiterCaseResult {
            id: ID.to_owned(),
            expectation: "accept".to_owned(),
            outcome: "accepted".to_owned(),
            reason: "first hello from a fresh node_id was allowed, as required".to_owned(),
            passed: true,
        }
    } else {
        HelloLimiterCaseResult {
            id: ID.to_owned(),
            expectation: "accept".to_owned(),
            outcome: "rejected".to_owned(),
            reason: "VIOLATION: a fresh node_id's first hello was denied; the guard is vacuous (would deny everything)".to_owned(),
            passed: false,
        }
    }
}

pub fn run_hello_limiter_flood_audit() -> HelloLimiterAuditReport {
    let results = [run_flood_case(), run_baseline_case()];

    let flood_denied = results
        .iter()
        .filter(|r| r.expectation == "reject" && r.passed)
        .count() as u32;
    let baseline_accepted = results
        .iter()
        .filter(|r| r.expectation == "accept" && r.passed)
        .count() as u32;
    let violations: Vec<HelloLimiterCaseResult> =
        results.iter().filter(|r| !r.passed).cloned().collect();

    HelloLimiterAuditReport {
        schema_version: HELLO_LIMITER_AUDIT_SCHEMA_VERSION,
        overall_ok: violations.is_empty(),
        total_cases: results.len() as u32,
        flood_denied,
        baseline_accepted,
        violations,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_passes_against_the_real_fixed_hello_limiter() {
        let report = run_hello_limiter_flood_audit();
        assert!(report.overall_ok, "reviewed funnel must pass: {report:?}");
        assert_eq!(report.total_cases, 2);
        assert_eq!(report.flood_denied, 1);
        assert_eq!(report.baseline_accepted, 1);
        assert!(report.violations.is_empty());
    }

    #[test]
    fn flood_case_is_individually_denied() {
        let result = run_flood_case();
        assert!(result.passed, "flood beyond cap must be denied: {result:?}");
        assert_eq!(result.outcome, "rejected");
    }

    #[test]
    fn baseline_case_is_accepted_not_vacuously_denied() {
        let result = run_baseline_case();
        assert!(result.passed, "fresh node_id must be accepted: {result:?}");
        assert_eq!(result.outcome, "accepted");
    }
}
