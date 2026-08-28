//! `cross_network_remote_exit_dns`, ported from
//! `scripts/e2e/live_linux_cross_network_remote_exit_dns_test.sh` (329 ln).
//!
//! # What this proves
//!
//! That managed DNS keeps working — and keeps failing closed — for a client
//! whose traffic leaves through an exit on a *different underlay prefix*.
//!
//! The two halves are separate checks because they are separate properties.
//! `managed_dns_resolution_success` says the split-DNS runtime is up and
//! answering the names it should; `remote_exit_dns_fail_closed` says it refuses
//! the ones it should — an unauthorised query, a stale signed bundle — and then
//! recovers when a valid bundle is restored. A resolver that answers everything
//! satisfies the first and fails the second, which is exactly the failure this
//! scenario exists to catch.
//!
//! # Composition
//!
//! Two children, in order: [`direct_remote_exit`](super::direct_remote_exit)
//! establishes the cross-network exit path, and the `live_linux_managed_dns_test`
//! sibling binary then validates DNS *on that path*. The first is a Rust call
//! now; the second is still a process, for the reason recorded on
//! [`ScenarioHost`](super::host::ScenarioHost) — it is one of four validators
//! ported ahead of CN-3 whose logic lives in `main()`, and lifting those is a
//! separate change.
//!
//! # An index shift the port removes
//!
//! The shell read each child's evidence with `--include-status`, which prepends
//! the report's status to the results and shifts every check index by one. Both
//! reads here are indexed from zero and the status is fetched separately, so a
//! check can no longer be read as the status or vice versa.
//!
//! # Checks the shell performed that are now structural
//!
//! The ones common to every scenario (see the module docs), plus `live_lab_init`
//! / `live_lab_push_sudo_password` on both hosts. Note this scenario runs **no
//! remote commands of its own** — both children drive their own transport — so
//! it is the one ported scenario that never builds a `NetLeafRunner`.

use std::path::{Path, PathBuf};

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::host::{CHECK_PASS, ScenarioHost, all_pass};
use super::provisioning::{self, LabContext, during};
use super::remote_exit_common::write_trust_summary;
use super::{Checks, ScenarioInputs, ScenarioOutcome};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_remote_exit_dns";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "managed_dns_resolution_success",
    "remote_exit_dns_fail_closed",
    "remote_exit_no_underlay_leak",
    "cross_network_topology_heuristic",
    "direct_remote_exit_ready",
    "managed_dns_child_ready",
];

/// The checks read out of the managed-DNS child's report, in the shell's order.
///
/// The split below indexes into this list, so the two cannot drift.
pub const MANAGED_DNS_CHECKS: &[&str] = &[
    // 0..=5 — the resolution half.
    "dns_inspect_valid",
    "managed_dns_service_active",
    "resolvectl_split_dns_configured",
    "loopback_resolver_answers_managed_name",
    "systemd_resolved_answers_managed_name",
    "alias_resolves_to_expected_ip",
    // 6..=8 — the fail-closed half.
    "non_managed_query_refused",
    "stale_bundle_fail_closed",
    "valid_bundle_restored",
];

/// How many of [`MANAGED_DNS_CHECKS`] belong to the resolution half. The
/// remainder are the fail-closed half.
const RESOLUTION_CHECK_COUNT: usize = 6;

/// The shell's `--zone-name` default.
pub const DEFAULT_ZONE_NAME: &str = "rustynet";
/// The shell's `--dns-interface` default.
pub const DEFAULT_DNS_INTERFACE: &str = super::TUNNEL_INTERFACE;
/// The shell's `--dns-bind-addr` default: loopback only, so the managed
/// resolver is never reachable off-box.
pub const DEFAULT_DNS_BIND_ADDR: &str = "127.0.0.1:53535";

/// Artifact basename of the composed direct baseline's report.
const BASELINE_REPORT_FILE: &str = "cross_network_remote_exit_dns_direct_remote_exit_report.json";
/// Artifact basename of the composed direct baseline's log.
const BASELINE_LOG_FILE: &str = "cross_network_remote_exit_dns_direct_remote_exit.log";
/// Artifact basename of the managed-DNS child's report.
const MANAGED_DNS_REPORT_FILE: &str = "cross_network_remote_exit_dns_managed_dns_report.json";
/// Artifact basename of the managed-DNS child's log.
const MANAGED_DNS_LOG_FILE: &str = "cross_network_remote_exit_dns_managed_dns.log";
/// Artifact basename of the ssh trust summary.
const TRUST_SUMMARY_FILE: &str = "cross_network_remote_exit_dns_ssh_trust_summary.txt";

/// The managed-DNS child's inputs that the shell exposed as flags.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteExitDnsOptions {
    pub zone_name: String,
    pub dns_interface: String,
    pub dns_bind_addr: String,
}

impl Default for RemoteExitDnsOptions {
    fn default() -> Self {
        Self {
            zone_name: DEFAULT_ZONE_NAME.to_owned(),
            dns_interface: DEFAULT_DNS_INTERFACE.to_owned(),
            dns_bind_addr: DEFAULT_DNS_BIND_ADDR.to_owned(),
        }
    }
}

impl RemoteExitDnsOptions {
    /// Validate each value before it can reach the child's argv.
    pub fn validate(&self) -> Result<(), String> {
        provisioning::validate_argv_value("zone name", &self.zone_name)?;
        provisioning::validate_argv_value("dns interface", &self.dns_interface)?;
        provisioning::validate_argv_value("dns bind address", &self.dns_bind_addr)
    }
}

/// Run the remote-exit DNS scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: &RemoteExitDnsOptions,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);

    let paths = Paths::in_dir(&lab.artifact_dir);
    let source_artifacts = vec![
        baseline::path_arg(&paths.baseline_report),
        baseline::path_arg(&paths.managed_dns_report),
        baseline::path_arg(&paths.trust_summary),
    ];
    let log_artifacts = vec![
        baseline::path_arg(&paths.baseline_log),
        baseline::path_arg(&paths.managed_dns_log),
    ];

    let mut outcome = match execute(host, inputs, lab, options, &paths, &mut checks) {
        Ok(()) => ScenarioOutcome::passed(checks),
        Err(summary) => ScenarioOutcome::failed(checks, summary),
    };
    outcome.source_artifacts = source_artifacts;
    outcome.log_artifacts = log_artifacts;
    outcome
}

/// The five artifact paths this scenario derives from the stage's artifact
/// directory, exactly as the shell derived them from `dirname "$REPORT_PATH"`.
pub struct Paths {
    pub baseline_report: PathBuf,
    pub baseline_log: PathBuf,
    pub managed_dns_report: PathBuf,
    pub managed_dns_log: PathBuf,
    pub trust_summary: PathBuf,
}

impl Paths {
    pub fn in_dir(artifact_dir: &Path) -> Self {
        Self {
            baseline_report: artifact_dir.join(BASELINE_REPORT_FILE),
            baseline_log: artifact_dir.join(BASELINE_LOG_FILE),
            managed_dns_report: artifact_dir.join(MANAGED_DNS_REPORT_FILE),
            managed_dns_log: artifact_dir.join(MANAGED_DNS_LOG_FILE),
            trust_summary: artifact_dir.join(TRUST_SUMMARY_FILE),
        }
    }
}

fn execute(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: &RemoteExitDnsOptions,
    paths: &Paths,
    checks: &mut Checks,
) -> Result<(), String> {
    options.validate()?;

    let phase = "verifying pinned host-key and passwordless-sudo prerequisites";
    during(
        phase,
        write_trust_summary(
            host,
            &paths.trust_summary,
            SUITE,
            &[
                ("client-host", lab.client_ssh_target.as_str()),
                ("exit-host", lab.exit_ssh_target.as_str()),
            ],
        ),
    )?;

    // ── child 1: the cross-network exit path ──
    let phase = "bootstrapping direct remote-exit path for DNS validation";
    let baseline = baseline::compose(
        host,
        inputs,
        lab,
        BaselineScenario::Direct,
        &BaselinePaths {
            report_path: paths.baseline_report.as_path(),
            log_path: paths.baseline_log.as_path(),
        },
        phase,
    )?;

    // Note the fold differs from the node-switch scenario's, which reads the
    // same three fields: there, leak resistance is folded INTO readiness; here
    // it is its own reported check, because this scenario's own conclusion is
    // about DNS and the leak result has to survive into the report separately.
    checks.record_bool(
        "direct_remote_exit_ready",
        baseline.succeeded() && baseline.passed(BaselineScenario::Direct.success_check()),
    );
    checks.record_bool(
        "remote_exit_no_underlay_leak",
        baseline.passed("remote_exit_no_underlay_leak"),
    );
    checks.record_bool(
        "cross_network_topology_heuristic",
        baseline.passed("cross_network_topology_heuristic"),
    );
    if !checks.passed("direct_remote_exit_ready") {
        return Err(
            "direct remote-exit child validator did not prove a secure cross-network remote-exit \
             path"
                .to_owned(),
        );
    }

    // ── child 2: managed DNS, on that path ──
    let evidence = run_managed_dns_child(host, inputs, lab, options, paths)?;
    // Zero-indexed, because the status is no longer prepended — see the module
    // docs. `all_pass` on an empty slice is false, so a report that yielded
    // nothing cannot pass either half.
    let (resolution, fail_closed) = split_managed_dns_checks(&evidence.checks);
    checks.record_bool("managed_dns_child_ready", evidence.status == CHECK_PASS);
    checks.record_bool("managed_dns_resolution_success", all_pass(resolution));
    checks.record_bool("remote_exit_dns_fail_closed", all_pass(fail_closed));

    // ── verdict, in the shell's order ──
    //
    // The shell also required the child's process exit status here. That is the
    // same fact as its report status — the child writes `status` from the
    // outcome of the run whose exit code it then returns — so the two clauses
    // collapse into the one check above rather than being checked twice.
    if !checks.passed("managed_dns_child_ready") {
        return Err(
            "managed DNS child validator did not produce a passing managed DNS runtime".to_owned(),
        );
    }
    if !checks.passed("managed_dns_resolution_success") {
        return Err("managed DNS did not resolve securely on the remote-exit client".to_owned());
    }
    if !checks.passed("remote_exit_dns_fail_closed") {
        return Err(
            "managed DNS did not fail closed under stale or unauthorized queries on the \
             remote-exit client"
                .to_owned(),
        );
    }
    if !checks.passed("remote_exit_no_underlay_leak") {
        return Err("remote-exit DNS path could not prove underlay leak resistance".to_owned());
    }
    if !checks.passed("cross_network_topology_heuristic") {
        return Err(
            "client and exit underlay topology did not credibly prove a cross-network claim"
                .to_owned(),
        );
    }
    Ok(())
}

/// What the managed-DNS child reported.
#[derive(Debug)]
struct ManagedDnsEvidence {
    status: String,
    checks: Vec<String>,
}

/// Run the managed-DNS child and read its evidence.
fn run_managed_dns_child(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: &RemoteExitDnsOptions,
    paths: &Paths,
) -> Result<ManagedDnsEvidence, String> {
    let phase = "running managed DNS validation on the remote-exit client";
    let identity = provisioning::path_arg(&lab.ssh_identity_file);
    let report_arg = provisioning::path_arg(&paths.managed_dns_report);
    let log_arg = provisioning::path_arg(&paths.managed_dns_log);
    // The EXIT is the signer: it holds the assignment signing secret in this
    // topology, so it is the node that can issue the signed DNS zone the client
    // then has to verify.
    let args = [
        "--ssh-identity-file",
        identity.as_str(),
        "--signer-host",
        lab.exit_ssh_target.as_str(),
        "--client-host",
        lab.client_ssh_target.as_str(),
        "--signer-node-id",
        inputs.exit.node_id.as_str(),
        "--client-node-id",
        inputs.client.node_id.as_str(),
        "--ssh-allow-cidrs",
        lab.ssh_allow_cidrs.as_str(),
        "--zone-name",
        options.zone_name.as_str(),
        "--dns-interface",
        options.dns_interface.as_str(),
        "--dns-bind-addr",
        options.dns_bind_addr.as_str(),
        "--report-path",
        report_arg.as_str(),
        "--log-path",
        log_arg.as_str(),
    ];
    let ran = during(
        phase,
        host.run_validator_bin(provisioning::BIN_MANAGED_DNS, &args),
    )?;
    if !ran && !host.report_exists(&paths.managed_dns_report) {
        return Err("managed DNS child validator failed before emitting evidence".to_owned());
    }
    Ok(ManagedDnsEvidence {
        status: during(phase, host.read_report_status(&paths.managed_dns_report))?,
        checks: during(
            phase,
            host.read_report_checks(&paths.managed_dns_report, MANAGED_DNS_CHECKS),
        )?,
    })
}

/// Split the child's results into the resolution half and the fail-closed half.
///
/// `min` keeps a short read from panicking; `read_report_checks` already pads
/// to the requested length, so this only matters if that contract ever changes,
/// and a short slice reads as fail either way.
fn split_managed_dns_checks(managed: &[String]) -> (&[String], &[String]) {
    managed.split_at(RESOLUTION_CHECK_COUNT.min(managed.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::scenario::host::recording::{
        HostCall, RecordingHost,
    };
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::NatProfileId;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;
    use std::collections::BTreeMap;

    fn nat_profile() -> NatProfileId {
        NatProfileId::parse("baseline_lan").expect("baseline_lan is a known NAT profile")
    }

    #[test]
    fn the_managed_dns_check_split_covers_every_check_it_reads() {
        // The two halves must partition the list: a check in neither would be
        // read from the child's report and then silently discarded.
        assert_eq!(MANAGED_DNS_CHECKS.len(), 9);
        assert!(RESOLUTION_CHECK_COUNT < MANAGED_DNS_CHECKS.len());
        let (resolution, fail_closed) = MANAGED_DNS_CHECKS.split_at(RESOLUTION_CHECK_COUNT);
        assert_eq!(resolution.len(), 6);
        assert_eq!(
            fail_closed,
            [
                "non_managed_query_refused",
                "stale_bundle_fail_closed",
                "valid_bundle_restored"
            ]
        );
    }

    fn values(count: usize, verdict: &str) -> Vec<String> {
        vec![verdict.to_owned(); count]
    }

    fn host_with(managed: Vec<String>) -> RecordingHost {
        let paths = Paths::in_dir(Path::new("/tmp/rustynet-cn3-tests"));
        let mut report_checks = BTreeMap::new();
        report_checks.insert(paths.managed_dns_report.clone(), managed);
        RecordingHost {
            existing_reports: vec![paths.managed_dns_report, paths.baseline_report],
            report_checks,
            ..RecordingHost::default()
        }
    }

    /// Fold the managed-DNS results exactly as `execute` does, without needing
    /// a lab: the split and the two `all_pass` calls are the whole conclusion.
    fn fold(managed: &[String]) -> (bool, bool) {
        let (resolution, fail_closed) = split_managed_dns_checks(managed);
        (all_pass(resolution), all_pass(fail_closed))
    }

    #[test]
    fn a_fully_passing_child_report_passes_both_halves() {
        let (resolution, fail_closed) = fold(&values(9, CHECK_PASS));
        assert!(resolution);
        assert!(fail_closed);
    }

    #[test]
    fn a_resolver_that_answers_everything_passes_resolution_and_fails_fail_closed() {
        // The failure this scenario exists to catch: DNS is up and answering,
        // but it does not refuse what it should.
        let mut managed = values(9, CHECK_PASS);
        managed[6] = "fail".to_owned(); // non_managed_query_refused
        let (resolution, fail_closed) = fold(&managed);
        assert!(resolution, "the resolution half is unaffected");
        assert!(!fail_closed);
    }

    #[test]
    fn a_broken_resolver_fails_only_the_resolution_half() {
        let mut managed = values(9, CHECK_PASS);
        managed[3] = "fail".to_owned(); // loopback_resolver_answers_managed_name
        let (resolution, fail_closed) = fold(&managed);
        assert!(!resolution);
        assert!(
            fail_closed,
            "refusing what it should is a separate property"
        );
    }

    #[test]
    fn a_truncated_child_report_cannot_pass_either_half() {
        // `read_report_checks` pads short answers with "fail", so this is
        // belt-and-braces — but a slice that lost its fail-closed half entirely
        // must not pass it vacuously, which is what `all_pass` on an empty
        // slice would otherwise do.
        for len in [0, 3, 6] {
            let (resolution, fail_closed) = fold(&values(len, CHECK_PASS));
            assert!(
                !(resolution && fail_closed),
                "{len} values must not prove both halves"
            );
        }
        let (_, fail_closed) = fold(&values(6, CHECK_PASS));
        assert!(
            !fail_closed,
            "an absent fail-closed half is not a passing one"
        );
    }

    #[test]
    fn the_managed_dns_child_is_invoked_argv_only_with_the_shells_flag_set() {
        let host = host_with(values(9, CHECK_PASS));
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let options = RemoteExitDnsOptions::default();
        let paths = Paths::in_dir(&lab.artifact_dir);

        let client_runner = MockLeafRunner::default();
        let exit_runner = MockLeafRunner::default();
        let inputs = ScenarioInputs {
            client: super::super::ScenarioNode::new(&client_runner, "client-1", "192.168.18.40"),
            exit: super::super::ScenarioNode::new(&exit_runner, "exit-1", "192.168.19.40"),
            relay: None,
            probe: None,
            nat_profile: nat_profile(),
            impairment_profile: "none".to_owned(),
        };
        let evidence = run_managed_dns_child(&host, &inputs, &lab, &options, &paths)
            .expect("the child ran and left evidence");
        assert_eq!(evidence.status, CHECK_PASS);
        assert_eq!(evidence.checks.len(), MANAGED_DNS_CHECKS.len());

        let managed = host
            .recorded()
            .into_iter()
            .find_map(|call| match call {
                HostCall::ValidatorBin { bin, args } if bin == provisioning::BIN_MANAGED_DNS => {
                    Some(args)
                }
                _ => None,
            })
            .expect("the managed DNS child must be invoked");
        assert_eq!(
            managed,
            vec![
                "--ssh-identity-file",
                "/home/op/.ssh/id",
                // The exit signs: it holds the signing secret in this topology.
                "--signer-host",
                "debian@exit-host",
                "--client-host",
                "debian@client-host",
                "--signer-node-id",
                "exit-1",
                "--client-node-id",
                "client-1",
                "--ssh-allow-cidrs",
                "192.168.18.0/24",
                "--zone-name",
                "rustynet",
                "--dns-interface",
                "rustynet0",
                "--dns-bind-addr",
                "127.0.0.1:53535",
                "--report-path",
                "/tmp/rustynet-cn3-tests/cross_network_remote_exit_dns_managed_dns_report.json",
                "--log-path",
                "/tmp/rustynet-cn3-tests/cross_network_remote_exit_dns_managed_dns.log",
            ]
        );
        // No remote command was issued by this scenario itself — both children
        // drive their own transport.
        assert!(client_runner.recorded().is_empty());
        assert!(exit_runner.recorded().is_empty());
    }

    #[test]
    fn a_child_that_failed_without_leaving_evidence_fails_closed() {
        let paths = Paths::in_dir(Path::new("/tmp/rustynet-cn3-tests"));
        let mut validator_results = BTreeMap::new();
        validator_results.insert(provisioning::BIN_MANAGED_DNS.to_owned(), false);
        let host = RecordingHost {
            // The managed-DNS report is deliberately absent.
            existing_reports: Vec::new(),
            validator_results,
            ..RecordingHost::default()
        };
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_runner = MockLeafRunner::default();
        let exit_runner = MockLeafRunner::default();
        let inputs = ScenarioInputs {
            client: super::super::ScenarioNode::new(&client_runner, "client-1", "192.168.18.40"),
            exit: super::super::ScenarioNode::new(&exit_runner, "exit-1", "192.168.19.40"),
            relay: None,
            probe: None,
            nat_profile: nat_profile(),
            impairment_profile: "none".to_owned(),
        };
        let err = run_managed_dns_child(
            &host,
            &inputs,
            &lab,
            &RemoteExitDnsOptions::default(),
            &paths,
        )
        .expect_err("no report means nothing to assert on");
        assert_eq!(
            err,
            "managed DNS child validator failed before emitting evidence"
        );
    }

    #[test]
    fn a_child_that_failed_but_left_evidence_is_still_read() {
        // The shell deliberately continued here: the report is the evidence,
        // not the exit status, and reading it is how the scenario reports WHICH
        // DNS property broke.
        let mut host = host_with(values(9, CHECK_PASS));
        let mut validator_results = BTreeMap::new();
        validator_results.insert(provisioning::BIN_MANAGED_DNS.to_owned(), false);
        host.validator_results = validator_results;
        let paths = Paths::in_dir(Path::new("/tmp/rustynet-cn3-tests"));
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_runner = MockLeafRunner::default();
        let exit_runner = MockLeafRunner::default();
        let inputs = ScenarioInputs {
            client: super::super::ScenarioNode::new(&client_runner, "client-1", "192.168.18.40"),
            exit: super::super::ScenarioNode::new(&exit_runner, "exit-1", "192.168.19.40"),
            relay: None,
            probe: None,
            nat_profile: nat_profile(),
            impairment_profile: "none".to_owned(),
        };
        let evidence = run_managed_dns_child(
            &host,
            &inputs,
            &lab,
            &RemoteExitDnsOptions::default(),
            &paths,
        )
        .expect("a failing child that left a report is assertable");
        assert_eq!(evidence.checks.len(), MANAGED_DNS_CHECKS.len());
    }

    #[test]
    fn the_status_is_read_separately_from_the_checks() {
        // The shell's `--include-status` prepended the status and shifted every
        // check index by one. Two calls means a check can never be read as the
        // status, or the status as a check.
        let host = host_with(values(9, CHECK_PASS));
        let paths = Paths::in_dir(Path::new("/tmp/rustynet-cn3-tests"));
        let status = host
            .read_report_status(&paths.managed_dns_report)
            .expect("status");
        assert_eq!(status, CHECK_PASS);
        let read = host
            .read_report_checks(&paths.managed_dns_report, MANAGED_DNS_CHECKS)
            .expect("checks");
        assert_eq!(read.len(), MANAGED_DNS_CHECKS.len());
        assert_eq!(
            read[0], CHECK_PASS,
            "index 0 is the FIRST check, not the status"
        );
    }

    #[test]
    fn the_dns_bind_address_stays_on_loopback() {
        // A managed resolver reachable off-box would answer for names the
        // scenario is asserting are only resolvable through the tunnel.
        let options = RemoteExitDnsOptions::default();
        assert!(options.dns_bind_addr.starts_with("127.0.0.1:"));
        assert_eq!(options.dns_interface, super::super::TUNNEL_INTERFACE);
        options.validate().expect("the defaults must be valid argv");
    }

    #[test]
    fn an_option_that_could_be_read_as_a_flag_is_rejected_before_argv() {
        let hostile = RemoteExitDnsOptions {
            zone_name: "-oProxyCommand=x".to_owned(),
            ..RemoteExitDnsOptions::default()
        };
        assert!(hostile.validate().is_err());
        let empty = RemoteExitDnsOptions {
            dns_interface: String::new(),
            ..RemoteExitDnsOptions::default()
        };
        assert!(empty.validate().is_err());
    }
}
