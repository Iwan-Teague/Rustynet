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

// ─────────────────────── netcheck health predicates ───────────────────────

#[test]
fn signed_state_is_unhealthy_when_the_positive_clause_is_absent() {
    // The trap this predicate exists to avoid: a netcheck line that simply
    // omits `traversal_error` satisfies every NEGATIVE clause (no alarm state
    // is critical/error/missing) while proving nothing at all. Absence must not
    // read as health.
    assert!(!signed_state_healthy("path_mode=direct_active"));
    assert!(!signed_state_healthy(
        "traversal_alarm_state=ok dns_alarm_state=ok"
    ));
    assert!(signed_state_healthy(
        "traversal_alarm_state=ok dns_alarm_state=ok traversal_error=none"
    ));
}

#[test]
fn signed_state_is_unhealthy_for_every_bad_alarm_state() {
    for state in ["critical", "error", "missing"] {
        for field in ["traversal_alarm_state", "dns_alarm_state"] {
            let line = format!("{field}={state} traversal_error=none");
            assert!(
                !signed_state_healthy(&line),
                "{field}={state} must not read as healthy"
            );
        }
    }
}

#[test]
fn a_proven_path_needs_both_the_mode_and_the_liveness_proof() {
    // `path_mode` alone is the daemon's INTENT; only `path_live_proven=true`
    // says traffic actually crossed. Accepting the first without the second is
    // the whole failure this suite exists to catch.
    assert!(!path_proven_direct("path_mode=direct_active"));
    assert!(!path_proven_direct("path_live_proven=true"));
    assert!(path_proven_direct(
        "path_mode=direct_active path_live_proven=true"
    ));
    assert!(!path_proven_relay(
        "path_mode=direct_active path_live_proven=true"
    ));
}

#[test]
fn a_relay_path_needs_a_live_session_on_top_of_a_proven_relay_path() {
    // The relay scenario requires three independent clauses. `relay_active` is
    // the daemon's choice, `path_live_proven` says a path was proven, and only
    // `relay_session_state=live` says the relay session itself is carrying
    // traffic. A session that is merely negotiating satisfies the first two.
    let negotiating = "path_mode=relay_active path_live_proven=true relay_session_state=pending";
    assert!(path_proven_relay(negotiating));
    assert!(
        !relay_session_live(negotiating),
        "a pending relay session must not read as live"
    );

    let live = "path_mode=relay_active path_live_proven=true relay_session_state=live";
    assert!(path_proven_relay(live) && relay_session_live(live));

    // An omitted field is not a live session.
    assert!(!relay_session_live(
        "path_mode=relay_active path_live_proven=true"
    ));
}

#[test]
fn the_two_remote_exit_scenarios_agree_on_their_shared_check_names() {
    // Both reports carry the same two bypass conclusions and the same topology
    // heuristic. If one scenario renamed its check, the cross-network report
    // validator would start reading a field the other never writes.
    for shared in [
        "remote_exit_no_underlay_leak",
        "remote_exit_server_ip_bypass_is_narrow",
        "cross_network_topology_heuristic",
        "no_plaintext_passphrase_files",
        "client_route_via_rustynet0",
    ] {
        assert!(
            direct_remote_exit::CHECKS.contains(&shared),
            "direct remote exit must emit {shared}"
        );
        assert!(
            relay_remote_exit::CHECKS.contains(&shared),
            "relay remote exit must emit {shared}"
        );
    }
}

#[test]
fn each_remote_exit_scenario_leads_its_report_with_its_own_aggregate() {
    // The report spec's `required_checks` reads the aggregate first, so the
    // emission order is load-bearing rather than cosmetic.
    assert_eq!(
        direct_remote_exit::CHECKS.first(),
        Some(&"direct_remote_exit_success")
    );
    assert_eq!(
        relay_remote_exit::CHECKS.first(),
        Some(&"relay_remote_exit_success")
    );
}

// ─────────────────────── provisioning helpers ───────────────────────

#[test]
fn remote_src_dir_matches_the_shell_for_root_and_for_a_normal_user() {
    assert_eq!(
        provisioning::remote_src_dir("root").expect("root is a valid user"),
        "/root/Rustynet"
    );
    assert_eq!(
        provisioning::remote_src_dir("debian").expect("debian is a valid user"),
        "/home/debian/Rustynet"
    );
}

#[test]
fn remote_src_dir_refuses_a_user_that_would_escape_the_path() {
    // The value becomes a `--src-dir` argument; a separator or an
    // option-looking value would change which directory is enforced.
    for bad in ["../root", "a/b", "-oProxyCommand=x", ""] {
        assert!(
            provisioning::remote_src_dir(bad).is_err(),
            "{bad:?} must be rejected before it reaches argv"
        );
    }
}

// ───────────────── direct remote-exit bypass aggregation ─────────────────

fn bypass(values: &[&str]) -> remote_exit_common::BypassVerdicts {
    let owned: Vec<String> = values.iter().map(|value| (*value).to_owned()).collect();
    remote_exit_common::bypass_verdicts(&owned)
}

#[test]
fn both_bypass_conclusions_hold_when_every_check_passed() {
    let verdicts = bypass(&["pass", "pass", "pass", "pass"]);
    assert!(verdicts.no_underlay_leak);
    assert!(verdicts.bypass_is_narrow);
}

#[test]
fn the_shared_service_block_check_gates_both_conclusions() {
    // Index 1 (`probe_service_blocked_from_client`) appears in both
    // conjunctions, so losing it must lose both — that is what distinguishes
    // "traffic uses the tunnel" from "traffic can ONLY use the tunnel".
    let verdicts = bypass(&["pass", "fail", "pass", "pass"]);
    assert!(!verdicts.no_underlay_leak);
    assert!(!verdicts.bypass_is_narrow);
}

#[test]
fn the_two_bypass_conclusions_are_independent_where_they_do_not_overlap() {
    // A leaking route (index 0) is not the same finding as a broad bypass.
    let leaking = bypass(&["fail", "pass", "pass", "pass"]);
    assert!(!leaking.no_underlay_leak);
    assert!(leaking.bypass_is_narrow);

    // ...and a broad bypass (index 3) is not the same finding as a leak.
    let broad = bypass(&["pass", "pass", "pass", "fail"]);
    assert!(broad.no_underlay_leak);
    assert!(!broad.bypass_is_narrow);
}

#[test]
fn a_truncated_bypass_report_cannot_produce_a_pass() {
    // A report carrying fewer checks than were asked for must read every
    // missing index as fail, never as absent-and-therefore-fine.
    for truncated in [
        vec!["pass"],
        vec!["pass", "pass"],
        vec!["pass", "pass", "pass"],
    ] {
        let verdicts = bypass(&truncated);
        assert!(
            !verdicts.bypass_is_narrow,
            "{truncated:?} must not prove a narrow bypass"
        );
    }
    assert!(!bypass(&[]).no_underlay_leak);
}
