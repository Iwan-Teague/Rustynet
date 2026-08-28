//! `cross_network_traversal_adversarial` — ported from
//! `scripts/e2e/live_linux_cross_network_traversal_adversarial_test.sh` (268 ln).
//!
//! # What this scenario proves
//!
//! That a cross-network topology rejects *forged* traversal state and refuses
//! to widen its control surface, across three independent evidence sources:
//!
//! 1. **Signed-traversal tamper/replay rejection** — three `rustynetd` gates
//!    run as required tests: a forged/stale/wrong-signer/nonce-replay gate, a
//!    tampered-signature-and-replay bundle-load gate, and a fail-closed
//!    `netcheck` gate against a forged traversal hint. All three must pass for
//!    the forged/stale/replayed trio of checks to pass — the shell set all
//!    three from a single combined status, and that coupling is preserved
//!    exactly rather than split into three independent verdicts.
//! 2. **Rogue-endpoint hijack denial** — the `endpoint_hijack` sibling
//!    validator must show the hijack drove the daemon fail-closed, the rogue
//!    endpoint was never adopted, and recovery kept rejecting it.
//! 3. **Control-surface exposure** — the `control_surface_exposure` sibling
//!    validator must show daemon and helper sockets secure, no RustyNet TCP
//!    listeners, UDP loopback-only, and the remote underlay DNS probe blocked.
//!
//! # Checks dropped as structurally guaranteed
//!
//! Beyond the four common to every scenario (see the module docs), this port
//! drops one more:
//!
//! * **`live_lab_push_sudo_password` on all three hosts.** Its job was to prove
//!   passwordless sudo before the first privileged command. Every remote call
//!   here goes through `SudoRunner`'s `sudo -n`, which fails closed on exactly
//!   the condition the pre-check existed to detect, and reports the guest's own
//!   stderr rather than a generic pre-flight message. Keeping it would be a
//!   second, weaker copy of a check the transport already makes.
//!
//! Note the SSH trust summary artifact is likewise not re-derived here: the
//! orchestrator pins host keys for the whole run before any stage executes, so
//! a per-scenario summary of that pinning would restate run-level state.

use std::path::{Path, PathBuf};

use super::host::{ScenarioHost, all_pass};
use super::{Checks, ScenarioOutcome, Verdict};

/// The three `rustynetd` required tests that together prove signed-traversal
/// forgery, staleness and replay are rejected.
pub const TRAVERSAL_GATE_TESTS: &[&str] = &[
    "daemon::tests::traversal_adversarial_gate_rejects_forged_stale_wrong_signer_and_nonce_replay",
    "daemon::tests::load_traversal_bundle_rejects_tampered_signature_and_replay",
    "daemon::tests::daemon_runtime_netcheck_rejects_forged_traversal_hint_fail_closed",
];

/// The crate those gates live in.
pub const TRAVERSAL_GATE_CRATE: &str = "rustynetd";

/// Sibling validator proving a rogue endpoint cannot be adopted.
pub const ENDPOINT_HIJACK_BIN: &str = "live_linux_endpoint_hijack_test";
/// Sibling validator proving the control surface stays closed.
pub const CONTROL_SURFACE_BIN: &str = "live_linux_control_surface_exposure_test";

/// Checks read out of the endpoint-hijack report, in the shell's order.
pub const ENDPOINT_HIJACK_CHECKS: &[&str] = &[
    "hijack_drives_fail_closed",
    "rogue_endpoint_not_adopted",
    "recovery_keeps_rogue_endpoint_rejected",
];

/// Checks read out of the control-surface report, in the shell's order.
pub const CONTROL_SURFACE_CHECKS: &[&str] = &[
    "all_daemon_sockets_secure",
    "all_helper_sockets_secure",
    "no_rustynet_tcp_listeners",
    "rustynet_udp_loopback_only",
    "remote_underlay_dns_probe_blocked",
];

/// The documentation-range address the shell defaulted `--rogue-endpoint-ip`
/// to. RFC 5737 TEST-NET-3, so a misconfigured run cannot hijack toward a real
/// host.
pub const DEFAULT_ROGUE_ENDPOINT_IP: std::net::Ipv4Addr = std::net::Ipv4Addr::new(203, 0, 113, 44);

/// Check names, declared in the order the report lists them.
const CHECK_FORGED: &str = "forged_traversal_rejected";
const CHECK_STALE: &str = "stale_traversal_rejected";
const CHECK_REPLAYED: &str = "replayed_traversal_rejected";
const CHECK_ROGUE: &str = "rogue_endpoint_rejected";
const CHECK_CONTROL_SURFACE: &str = "control_surface_exposure_blocked";

const ALL_CHECKS: &[&str] = &[
    CHECK_FORGED,
    CHECK_STALE,
    CHECK_REPLAYED,
    CHECK_ROGUE,
    CHECK_CONTROL_SURFACE,
];

/// Paths this scenario asks its siblings to write, derived from the stage's
/// artifact directory exactly as the shell derived them from `dirname
/// "$REPORT_PATH"`.
pub struct TraversalAdversarialPaths {
    pub endpoint_report: PathBuf,
    pub endpoint_log: PathBuf,
    pub control_report: PathBuf,
    pub control_log: PathBuf,
}

impl TraversalAdversarialPaths {
    pub fn in_dir(artifact_dir: &Path) -> Self {
        Self {
            endpoint_report: artifact_dir
                .join("cross_network_traversal_adversarial_endpoint_hijack_report.json"),
            endpoint_log: artifact_dir
                .join("cross_network_traversal_adversarial_endpoint_hijack.log"),
            control_report: artifact_dir
                .join("cross_network_traversal_adversarial_control_surface_report.json"),
            control_log: artifact_dir
                .join("cross_network_traversal_adversarial_control_surface.log"),
        }
    }
}

/// Everything this scenario needs that is not a remote runner. The hosts are
/// SSH targets because the two sibling validators take `--*-host` arguments and
/// drive their own transport; this scenario runs no remote commands itself.
pub struct TraversalAdversarialInputs<'a> {
    pub ssh_identity_file: &'a Path,
    pub client_host: &'a str,
    pub exit_host: &'a str,
    pub probe_host: &'a str,
    pub rogue_endpoint_ip: std::net::Ipv4Addr,
    pub artifact_dir: &'a Path,
}

/// Run the scenario.
///
/// Returns a [`ScenarioOutcome`] on every path — including the two
/// "sibling failed before emitting evidence" paths, which the shell reached via
/// `return 1` and which are fail-closed here for the same reason: with no
/// report there is nothing to assert on, and an unassertable run must not read
/// as a pass.
pub fn run(host: &dyn ScenarioHost, inputs: &TraversalAdversarialInputs<'_>) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(ALL_CHECKS);

    let paths = TraversalAdversarialPaths::in_dir(inputs.artifact_dir);

    // ── 1. signed traversal tamper and replay regression tests ──────────────
    //
    // The shell ran all three unconditionally (via `&&`, so it short-circuited
    // on the first failure) and set the forged/stale/replayed trio only if the
    // combined status was zero. Short-circuiting is preserved: a later gate
    // adds no information once an earlier one has failed the trio.
    let mut gates_passed = true;
    for test_name in TRAVERSAL_GATE_TESTS {
        match host.run_required_test(TRAVERSAL_GATE_CRATE, test_name) {
            Ok(true) => {}
            Ok(false) => {
                gates_passed = false;
                break;
            }
            Err(err) => {
                return ScenarioOutcome::failed(
                    checks,
                    format!("running signed traversal tamper and replay regression tests: {err}"),
                );
            }
        }
    }
    if gates_passed {
        checks.record(CHECK_FORGED, Verdict::Pass);
        checks.record(CHECK_STALE, Verdict::Pass);
        checks.record(CHECK_REPLAYED, Verdict::Pass);
    }

    // ── 2. live rogue-endpoint hijack denial ────────────────────────────────
    let rogue_ip = inputs.rogue_endpoint_ip.to_string();
    let identity = path_arg(inputs.ssh_identity_file);
    let endpoint_report_arg = path_arg(&paths.endpoint_report);
    let endpoint_log_arg = path_arg(&paths.endpoint_log);
    let endpoint_args = [
        "--ssh-identity-file",
        identity.as_str(),
        "--client-host",
        inputs.client_host,
        "--rogue-endpoint-ip",
        rogue_ip.as_str(),
        "--report-path",
        endpoint_report_arg.as_str(),
        "--log-path",
        endpoint_log_arg.as_str(),
    ];
    let endpoint_ran = match host.run_validator_bin(ENDPOINT_HIJACK_BIN, &endpoint_args) {
        Ok(succeeded) => succeeded,
        Err(err) => {
            return ScenarioOutcome::failed(
                checks,
                format!("running live rogue-endpoint hijack denial test: {err}"),
            );
        }
    };
    if !endpoint_ran && !host.report_exists(&paths.endpoint_report) {
        return ScenarioOutcome::failed(
            checks,
            "endpoint hijack validator failed before emitting evidence",
        );
    }
    match host.read_report_checks(&paths.endpoint_report, ENDPOINT_HIJACK_CHECKS) {
        Ok(values) => checks.record_bool(CHECK_ROGUE, all_pass(&values)),
        Err(err) => {
            return ScenarioOutcome::failed(
                checks,
                format!("reading endpoint hijack evidence failed: {err}"),
            );
        }
    }

    // ── 3. live control-surface exposure validation ─────────────────────────
    let control_report_arg = path_arg(&paths.control_report);
    let control_log_arg = path_arg(&paths.control_log);
    let control_args = [
        "--ssh-identity-file",
        identity.as_str(),
        "--exit-host",
        inputs.exit_host,
        "--client-host",
        inputs.client_host,
        "--probe-host",
        inputs.probe_host,
        "--report-path",
        control_report_arg.as_str(),
        "--log-path",
        control_log_arg.as_str(),
    ];
    let control_ran = match host.run_validator_bin(CONTROL_SURFACE_BIN, &control_args) {
        Ok(succeeded) => succeeded,
        Err(err) => {
            return ScenarioOutcome::failed(
                checks,
                format!("running live control-surface exposure validation: {err}"),
            );
        }
    };
    if !control_ran && !host.report_exists(&paths.control_report) {
        return ScenarioOutcome::failed(
            checks,
            "control-surface exposure validator failed before emitting evidence",
        );
    }
    match host.read_report_checks(&paths.control_report, CONTROL_SURFACE_CHECKS) {
        Ok(values) => checks.record_bool(CHECK_CONTROL_SURFACE, all_pass(&values)),
        Err(err) => {
            return ScenarioOutcome::failed(
                checks,
                format!("reading control-surface evidence failed: {err}"),
            );
        }
    }

    // ── final gates, in the shell's order ───────────────────────────────────
    if !checks.passed(CHECK_FORGED) {
        return ScenarioOutcome::failed(
            checks,
            "forged/stale/replayed traversal rejection evidence did not pass",
        );
    }
    if !checks.passed(CHECK_ROGUE) {
        return ScenarioOutcome::failed(
            checks,
            "rogue endpoint hijack denial evidence did not pass",
        );
    }
    if !checks.passed(CHECK_CONTROL_SURFACE) {
        return ScenarioOutcome::failed(checks, "control-surface exposure evidence did not pass");
    }

    let source_artifacts = vec![
        path_arg(&paths.endpoint_report),
        path_arg(&paths.control_report),
    ];
    let log_artifacts = vec![path_arg(&paths.endpoint_log), path_arg(&paths.control_log)];
    let mut outcome = ScenarioOutcome::passed(checks);
    outcome.source_artifacts = source_artifacts;
    outcome.log_artifacts = log_artifacts;
    outcome
}

/// Render a path for argv. Lossy conversion is acceptable here and nowhere
/// else: these paths are orchestrator-derived (a report dir joined with a fixed
/// literal), never guest-supplied, so there is no untrusted content to mangle.
fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

/// True when `values` are all `"pass"` — re-exported spelling used by the
/// tests to build fixtures without importing the host module.
#[cfg(test)]
fn pass_values(count: usize) -> Vec<String> {
    vec![super::host::CHECK_PASS.to_owned(); count]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::scenario::host::recording::{
        HostCall, RecordingHost,
    };
    use std::collections::BTreeMap;

    fn artifact_dir() -> PathBuf {
        PathBuf::from("/tmp/rustynet-cn3-tests")
    }

    fn paths() -> TraversalAdversarialPaths {
        TraversalAdversarialPaths::in_dir(&artifact_dir())
    }

    fn inputs<'a>(identity: &'a Path, dir: &'a Path) -> TraversalAdversarialInputs<'a> {
        TraversalAdversarialInputs {
            ssh_identity_file: identity,
            client_host: "debian@client-host",
            exit_host: "debian@exit-host",
            probe_host: "debian@probe-host",
            rogue_endpoint_ip: DEFAULT_ROGUE_ENDPOINT_IP,
            artifact_dir: dir,
        }
    }

    /// A host where every gate and both siblings pass with full evidence.
    fn healthy_host() -> RecordingHost {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(p.endpoint_report.clone(), pass_values(3));
        report_checks.insert(p.control_report.clone(), pass_values(5));
        RecordingHost {
            existing_reports: vec![p.endpoint_report, p.control_report],
            report_checks,
            ..RecordingHost::default()
        }
    }

    #[test]
    fn passes_when_gates_and_both_siblings_report_full_evidence() {
        let host = healthy_host();
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(outcome.is_pass(), "summary: {}", outcome.failure_summary);
        assert_eq!(outcome.failure_summary, "");
        for name in ALL_CHECKS {
            assert!(outcome.checks.passed(name), "{name} should pass");
        }
        // Report order is the shell's emission order and report consumers read
        // it positionally, so it is part of the contract.
        assert_eq!(
            outcome.checks.as_report_args(),
            vec![
                "forged_traversal_rejected=pass",
                "stale_traversal_rejected=pass",
                "replayed_traversal_rejected=pass",
                "rogue_endpoint_rejected=pass",
                "control_surface_exposure_blocked=pass",
            ]
        );
    }

    #[test]
    fn runs_all_three_traversal_gates_against_the_daemon_crate() {
        let host = healthy_host();
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let _ = run(&host, &inputs(&identity, &dir));

        let gate_calls: Vec<String> = host
            .recorded()
            .into_iter()
            .filter_map(|call| match call {
                HostCall::RequiredTest {
                    crate_name,
                    test_name,
                } => {
                    assert_eq!(crate_name, TRAVERSAL_GATE_CRATE);
                    Some(test_name)
                }
                _ => None,
            })
            .collect();
        assert_eq!(gate_calls, TRAVERSAL_GATE_TESTS.to_vec());
    }

    #[test]
    fn a_failing_traversal_gate_fails_the_whole_forged_stale_replayed_trio() {
        let mut host = healthy_host();
        host.required_test_results
            .insert(TRAVERSAL_GATE_TESTS[1].to_owned(), false);
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "forged/stale/replayed traversal rejection evidence did not pass"
        );
        // All three fail together: the shell coupled them to one combined status.
        assert!(!outcome.checks.passed(CHECK_FORGED));
        assert!(!outcome.checks.passed(CHECK_STALE));
        assert!(!outcome.checks.passed(CHECK_REPLAYED));
    }

    #[test]
    fn a_failing_gate_short_circuits_the_remaining_gates() {
        let mut host = healthy_host();
        host.required_test_results
            .insert(TRAVERSAL_GATE_TESTS[0].to_owned(), false);
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let _ = run(&host, &inputs(&identity, &dir));

        let gate_count = host
            .recorded()
            .iter()
            .filter(|call| matches!(call, HostCall::RequiredTest { .. }))
            .count();
        assert_eq!(
            gate_count, 1,
            "later gates add nothing once the trio failed"
        );
    }

    #[test]
    fn a_gate_that_cannot_run_fails_closed_rather_than_reading_as_a_pass() {
        let mut host = healthy_host();
        host.required_test_errors
            .push(TRAVERSAL_GATE_TESTS[0].to_owned());
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert!(
            outcome
                .failure_summary
                .starts_with("running signed traversal tamper and replay regression tests:"),
            "got: {}",
            outcome.failure_summary
        );
        assert!(!outcome.checks.passed(CHECK_FORGED));
    }

    #[test]
    fn endpoint_hijack_failing_without_evidence_fails_closed() {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(p.control_report.clone(), pass_values(5));
        let mut validator_results = BTreeMap::new();
        validator_results.insert(ENDPOINT_HIJACK_BIN.to_owned(), false);
        let host = RecordingHost {
            // endpoint report deliberately absent
            existing_reports: vec![p.control_report],
            report_checks,
            validator_results,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "endpoint hijack validator failed before emitting evidence"
        );
    }

    #[test]
    fn endpoint_hijack_failing_with_evidence_still_reads_its_checks() {
        // The shell deliberately continued when the sibling exited non-zero but
        // left a report: the report is the evidence, not the exit status.
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(p.endpoint_report.clone(), pass_values(3));
        report_checks.insert(p.control_report.clone(), pass_values(5));
        let mut validator_results = BTreeMap::new();
        validator_results.insert(ENDPOINT_HIJACK_BIN.to_owned(), false);
        let host = RecordingHost {
            existing_reports: vec![p.endpoint_report, p.control_report],
            report_checks,
            validator_results,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(outcome.is_pass(), "summary: {}", outcome.failure_summary);
        assert!(outcome.checks.passed(CHECK_ROGUE));
    }

    #[test]
    fn a_partially_passing_endpoint_report_does_not_pass_the_rogue_check() {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(
            p.endpoint_report.clone(),
            vec!["pass".to_owned(), "fail".to_owned(), "pass".to_owned()],
        );
        report_checks.insert(p.control_report.clone(), pass_values(5));
        let host = RecordingHost {
            existing_reports: vec![p.endpoint_report, p.control_report],
            report_checks,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "rogue endpoint hijack denial evidence did not pass"
        );
    }

    #[test]
    fn a_report_missing_a_check_reads_as_fail_not_as_absent() {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        // Only two of the three endpoint checks are present.
        report_checks.insert(
            p.endpoint_report.clone(),
            vec!["pass".to_owned(), "pass".to_owned()],
        );
        report_checks.insert(p.control_report.clone(), pass_values(5));
        let host = RecordingHost {
            existing_reports: vec![p.endpoint_report, p.control_report],
            report_checks,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "rogue endpoint hijack denial evidence did not pass"
        );
    }

    #[test]
    fn control_surface_failing_without_evidence_fails_closed() {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(p.endpoint_report.clone(), pass_values(3));
        let mut validator_results = BTreeMap::new();
        validator_results.insert(CONTROL_SURFACE_BIN.to_owned(), false);
        let host = RecordingHost {
            existing_reports: vec![p.endpoint_report],
            report_checks,
            validator_results,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "control-surface exposure validator failed before emitting evidence"
        );
    }

    #[test]
    fn a_partially_passing_control_surface_report_fails_that_check() {
        let p = paths();
        let mut report_checks = BTreeMap::new();
        report_checks.insert(p.endpoint_report.clone(), pass_values(3));
        report_checks.insert(
            p.control_report.clone(),
            vec![
                "pass".to_owned(),
                "pass".to_owned(),
                "pass".to_owned(),
                "pass".to_owned(),
                "fail".to_owned(),
            ],
        );
        let host = RecordingHost {
            existing_reports: vec![p.endpoint_report, p.control_report],
            report_checks,
            ..RecordingHost::default()
        };
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert_eq!(
            outcome.failure_summary,
            "control-surface exposure evidence did not pass"
        );
    }

    #[test]
    fn siblings_are_invoked_argv_only_with_the_shell_s_flag_set() {
        let host = healthy_host();
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let _ = run(&host, &inputs(&identity, &dir));

        let p = paths();
        let bins: Vec<(String, Vec<String>)> = host
            .recorded()
            .into_iter()
            .filter_map(|call| match call {
                HostCall::ValidatorBin { bin, args } => Some((bin, args)),
                _ => None,
            })
            .collect();
        assert_eq!(bins.len(), 2);

        assert_eq!(bins[0].0, ENDPOINT_HIJACK_BIN);
        assert_eq!(
            bins[0].1,
            vec![
                "--ssh-identity-file",
                "/home/op/.ssh/id",
                "--client-host",
                "debian@client-host",
                "--rogue-endpoint-ip",
                "203.0.113.44",
                "--report-path",
                p.endpoint_report.to_str().expect("utf8 path"),
                "--log-path",
                p.endpoint_log.to_str().expect("utf8 path"),
            ]
        );

        assert_eq!(bins[1].0, CONTROL_SURFACE_BIN);
        assert_eq!(
            bins[1].1,
            vec![
                "--ssh-identity-file",
                "/home/op/.ssh/id",
                "--exit-host",
                "debian@exit-host",
                "--client-host",
                "debian@client-host",
                "--probe-host",
                "debian@probe-host",
                "--report-path",
                p.control_report.to_str().expect("utf8 path"),
                "--log-path",
                p.control_log.to_str().expect("utf8 path"),
            ]
        );
    }

    #[test]
    fn a_sibling_that_cannot_be_launched_fails_closed() {
        let mut host = healthy_host();
        host.validator_errors.push(ENDPOINT_HIJACK_BIN.to_owned());
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert!(
            outcome
                .failure_summary
                .starts_with("running live rogue-endpoint hijack denial test:"),
            "got: {}",
            outcome.failure_summary
        );
    }

    #[test]
    fn an_unreadable_report_fails_closed_rather_than_defaulting_to_pass() {
        let p = paths();
        let mut host = healthy_host();
        host.report_read_errors.push(p.endpoint_report);
        let dir = artifact_dir();
        let identity = PathBuf::from("/home/op/.ssh/id");
        let outcome = run(&host, &inputs(&identity, &dir));

        assert!(!outcome.is_pass());
        assert!(
            outcome
                .failure_summary
                .starts_with("reading endpoint hijack evidence failed:"),
            "got: {}",
            outcome.failure_summary
        );
    }

    #[test]
    fn every_check_defaults_to_fail_before_any_evidence_is_gathered() {
        let mut checks = Checks::new();
        checks.declare(ALL_CHECKS);
        for name in ALL_CHECKS {
            assert!(!checks.passed(name), "{name} must default to fail");
        }
        assert_eq!(checks.len(), 5);
    }

    #[test]
    fn artifact_paths_match_the_shell_s_derived_names() {
        let p = TraversalAdversarialPaths::in_dir(Path::new("/reports/stage"));
        assert_eq!(
            p.endpoint_report,
            PathBuf::from(
                "/reports/stage/cross_network_traversal_adversarial_endpoint_hijack_report.json"
            )
        );
        assert_eq!(
            p.control_report,
            PathBuf::from(
                "/reports/stage/cross_network_traversal_adversarial_control_surface_report.json"
            )
        );
    }
}
