//! Tests for the shared scenario contract: the fail-closed `Checks` ledger and
//! the `ScenarioOutcome` a scenario hands back to the stage.
//!
//! The remote-command helpers and `netcheck` predicates land with the first
//! scenario that drives a lab guest; they are deliberately absent here rather
//! than carried unused.

use super::*;

// ───────────────────────────── Checks ledger ─────────────────────────────

#[test]
fn an_unrecorded_check_reads_as_fail() {
    let checks = Checks::new();
    assert_eq!(checks.verdict("never_recorded"), Verdict::Fail);
    assert!(!checks.passed("never_recorded"));
}

#[test]
fn declare_seeds_the_fail_closed_default_and_fixes_report_order() {
    let mut checks = Checks::new();
    checks.declare(&["alpha", "beta", "gamma"]);
    assert_eq!(
        checks.as_report_args(),
        vec!["alpha=fail", "beta=fail", "gamma=fail"]
    );
}

#[test]
fn recording_upgrades_a_declared_check_in_place_without_reordering() {
    let mut checks = Checks::new();
    checks.declare(&["alpha", "beta", "gamma"]);
    checks.record("beta", Verdict::Pass);
    assert_eq!(
        checks.as_report_args(),
        vec!["alpha=fail", "beta=pass", "gamma=fail"]
    );
    assert_eq!(checks.len(), 3, "re-recording must not append a duplicate");
}

#[test]
fn recording_can_downgrade_a_check_back_to_fail() {
    let mut checks = Checks::new();
    checks.record("alpha", Verdict::Pass);
    checks.record("alpha", Verdict::Fail);
    assert!(!checks.passed("alpha"));
}

#[test]
fn all_passed_is_false_when_any_named_check_is_absent() {
    let mut checks = Checks::new();
    checks.record("alpha", Verdict::Pass);
    assert!(checks.all_passed(&["alpha"]));
    assert!(
        !checks.all_passed(&["alpha", "missing"]),
        "an absent check must not read as passing"
    );
}

#[test]
fn record_bool_maps_false_to_fail() {
    let mut checks = Checks::new();
    checks.record_bool("alpha", false);
    checks.record_bool("beta", true);
    assert_eq!(checks.as_report_args(), vec!["alpha=fail", "beta=pass"]);
}

// ───────────────────────────── outcomes ─────────────────────────────

#[test]
fn a_failed_outcome_carries_the_summary_and_is_not_a_pass() {
    let mut checks = Checks::new();
    checks.declare(&["alpha"]);
    let outcome = ScenarioOutcome::failed(checks, "something did not pass");
    assert!(!outcome.is_pass());
    assert_eq!(outcome.failure_summary, "something did not pass");
}

#[test]
fn a_passing_outcome_has_an_empty_summary() {
    let outcome = ScenarioOutcome::passed(Checks::new());
    assert!(outcome.is_pass());
    assert_eq!(outcome.failure_summary, "");
}
