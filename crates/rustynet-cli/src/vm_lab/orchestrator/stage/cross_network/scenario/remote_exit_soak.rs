//! `cross_network_remote_exit_soak`, ported from
//! `scripts/e2e/live_linux_cross_network_remote_exit_soak_test.sh` (629 ln).
//!
//! # What this proves
//!
//! That a cross-network direct remote-exit path stays *the same path* for a
//! sustained period — not merely that it works at the start and end.
//!
//! The distinction is the whole scenario. A path that flapped to the relay and
//! back would satisfy a before/after check perfectly, so the aggregate here
//! demands that **every** sample was `direct_active`, that there were **zero**
//! path transitions, and that the relay, fail-closed and other-path sample
//! counts are all zero. It also requires a leak-resistance and bypass-narrowness
//! result from *both* before and after the soak, because a path that was narrow
//! at the start and broad at the end has not been stable.
//!
//! # Wall clock and test time
//!
//! The soak is long-running by design: it samples every
//! [`DEFAULT_SAMPLE_INTERVAL_SECS`] seconds until
//! [`DEFAULT_SOAK_DURATION_SECS`] have elapsed, and `elapsed >= duration` is
//! itself one of the stability clauses. That makes a naive
//! [`TimeScale::Collapsed`](super::provisioning::TimeScale::Collapsed) run
//! wrong in two ways at once: zero-length sleeps would spin the loop against a
//! real deadline, and the real elapsed time would then fail the duration clause
//! that the compressed run is supposed to preserve.
//!
//! [`SoakClock`] resolves both. Under `Real` it is the wall clock and the sleeps
//! are real. Under `Collapsed` it is a *virtual* clock that advances by exactly
//! one sample interval per sample and never sleeps — so the sample count, the
//! deadline comparison, the elapsed-time clause and every counter come out
//! identical to a real run of the same length, in no time at all. Live
//! semantics are unchanged; only the waiting is.
//!
//! # Checks the shell performed that are now structural
//!
//! The ones common to every scenario (see the module docs), plus `live_lab_init`
//! / `live_lab_push_sudo_password` on both hosts and
//! `live_lab_resolved_target_address`.
//!
//! New drops, specific to this scenario: the four soak tunables
//! (`--soak-duration-secs`, `--soak-sample-interval-secs`,
//! `--soak-max-consecutive-failures`, `--soak-max-failing-samples`) are typed
//! fields on [`SoakOptions`], whose constructor rejects a zero duration and a
//! zero interval. The two failure allowances may legitimately be zero — that is
//! the strictest setting, not an invalid one — so they are not rejected.

use std::path::{Path, PathBuf};

use crate::ops_cross_network_reports::WriteCrossNetworkSoakMonitorSummaryConfig;

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::unix_now;
use super::host::ScenarioHost;
use super::node_network_switch::squeeze;
use super::provisioning::{self, LabContext, TimeScale, during};
use super::remote_exit_common::{
    BYPASS_CHECKS, BypassRun, run_bypass_validator, write_trust_summary,
};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, Verdict, capture_root_allow_failure,
    client_exit_selected, no_plaintext_passphrase_check, route_via_rustynet, status,
    wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_remote_exit_soak";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "long_soak_stable",
    "remote_exit_no_underlay_leak",
    "remote_exit_server_ip_bypass_is_narrow",
    "cross_network_topology_heuristic",
    "direct_remote_exit_ready",
    "post_soak_bypass_ready",
    "no_plaintext_passphrase_files",
];

/// The shell's `--soak-duration-secs` default.
pub const DEFAULT_SOAK_DURATION_SECS: u64 = 120;
/// The shell's `--soak-sample-interval-secs` default.
pub const DEFAULT_SAMPLE_INTERVAL_SECS: u64 = 5;
/// The shell's `--soak-max-consecutive-failures` default.
pub const DEFAULT_MAX_CONSECUTIVE_FAILURES: u64 = 2;
/// The shell's `--soak-max-failing-samples` default.
pub const DEFAULT_MAX_FAILING_SAMPLES: u64 = 2;

/// The `path_mode` a healthy soak sample reports.
const PATH_MODE_DIRECT: &str = "direct_active";
/// The `path_mode` that means the client fell back to the relay.
const PATH_MODE_RELAY: &str = "relay_active";
/// The only acceptable `transport_socket_identity_state`.
const AUTHORITATIVE_TRANSPORT: &str = "authoritative_backend_shared_transport";
/// The value every "no problem" reason field carries.
const REASON_NONE: &str = "none";

/// Artifact basename of the composed direct baseline's report.
const BASELINE_REPORT_FILE: &str = "cross_network_remote_exit_soak_direct_remote_exit_report.json";
/// Artifact basename of the composed direct baseline's log.
const BASELINE_LOG_FILE: &str = "cross_network_remote_exit_soak_direct_remote_exit.log";
/// Artifact basename of the post-soak bypass validator's report.
const BYPASS_REPORT_FILE: &str = "cross_network_remote_exit_soak_server_ip_bypass_report.json";
/// Artifact basename of the post-soak bypass validator's log.
const BYPASS_LOG_FILE: &str = "cross_network_remote_exit_soak_server_ip_bypass.log";
/// Artifact basename of the per-sample soak transcript.
const MONITOR_LOG_FILE: &str = "cross_network_remote_exit_soak_monitor.log";
/// Artifact basename of the machine-readable monitor summary.
const MONITOR_SUMMARY_FILE: &str = "cross_network_remote_exit_soak_monitor_summary.json";
/// Artifact basename of the ssh trust summary.
const TRUST_SUMMARY_FILE: &str = "cross_network_remote_exit_soak_ssh_trust_summary.txt";

/// The scenario's four tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SoakOptions {
    duration_secs: u64,
    sample_interval_secs: u64,
    max_consecutive_failures: u64,
    max_failing_samples: u64,
}

impl Default for SoakOptions {
    fn default() -> Self {
        Self {
            duration_secs: DEFAULT_SOAK_DURATION_SECS,
            sample_interval_secs: DEFAULT_SAMPLE_INTERVAL_SECS,
            max_consecutive_failures: DEFAULT_MAX_CONSECUTIVE_FAILURES,
            max_failing_samples: DEFAULT_MAX_FAILING_SAMPLES,
        }
    }
}

impl SoakOptions {
    /// A zero duration or interval is rejected; the two failure allowances may
    /// be zero, because zero is the strictest setting rather than an invalid
    /// one.
    pub fn new(
        duration_secs: u64,
        sample_interval_secs: u64,
        max_consecutive_failures: u64,
        max_failing_samples: u64,
    ) -> Result<Self, String> {
        if duration_secs == 0 {
            return Err("soak duration seconds must be a positive integer".to_owned());
        }
        if sample_interval_secs == 0 {
            return Err("soak sample interval seconds must be a positive integer".to_owned());
        }
        Ok(Self {
            duration_secs,
            sample_interval_secs,
            max_consecutive_failures,
            max_failing_samples,
        })
    }

    pub fn duration_secs(self) -> u64 {
        self.duration_secs
    }

    pub fn sample_interval_secs(self) -> u64 {
        self.sample_interval_secs
    }
}

/// The soak loop's notion of time.
///
/// See the module docs for why this exists rather than the loop simply calling
/// [`LabContext::sleep`](super::provisioning::LabContext::sleep): the soak's
/// stability verdict *reads* elapsed time, so collapsing the waits without also
/// collapsing the clock would change the answer rather than only the runtime.
pub struct SoakClock {
    scale: TimeScale,
    started_unix: u64,
    /// Only used under [`TimeScale::Collapsed`]: seconds of virtual time that
    /// have "passed".
    virtual_elapsed_secs: u64,
}

impl SoakClock {
    pub fn start(scale: TimeScale) -> Self {
        Self {
            scale,
            started_unix: unix_now(),
            virtual_elapsed_secs: 0,
        }
    }

    pub fn started_unix(&self) -> u64 {
        self.started_unix
    }

    /// The current time, real or virtual.
    pub fn now(&self) -> u64 {
        match self.scale {
            TimeScale::Real => unix_now(),
            TimeScale::Collapsed => self.started_unix.saturating_add(self.virtual_elapsed_secs),
        }
    }

    /// Seconds since the soak began. Saturating rather than wrapping: a clock
    /// that moved backwards reads as zero elapsed, which fails the duration
    /// clause instead of overflowing into a passing one.
    pub fn elapsed_secs(&self) -> u64 {
        self.now().saturating_sub(self.started_unix)
    }

    /// Wait one sample interval — really under `Real`, virtually under
    /// `Collapsed`.
    pub fn tick(&mut self, interval_secs: u64) {
        match self.scale {
            TimeScale::Real => {
                std::thread::sleep(std::time::Duration::from_secs(interval_secs));
            }
            TimeScale::Collapsed => {
                self.virtual_elapsed_secs = self.virtual_elapsed_secs.saturating_add(interval_secs);
            }
        }
    }
}

/// Run the remote-exit soak scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: SoakOptions,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);
    let mut path_status_line = None;

    let paths = Paths::in_dir(&lab.artifact_dir);
    let source_artifacts = vec![
        baseline::path_arg(&paths.baseline_report),
        baseline::path_arg(&paths.bypass_report),
        baseline::path_arg(&paths.monitor_summary),
        baseline::path_arg(&paths.trust_summary),
    ];
    let log_artifacts = vec![
        baseline::path_arg(&paths.baseline_log),
        baseline::path_arg(&paths.bypass_log),
        baseline::path_arg(&paths.monitor_log),
    ];

    let mut outcome = match execute(
        host,
        inputs,
        lab,
        options,
        &paths,
        &mut checks,
        &mut path_status_line,
    ) {
        Ok(()) => ScenarioOutcome::passed(checks),
        Err(summary) => ScenarioOutcome::failed(checks, summary),
    };
    if let Some(line) = path_status_line {
        outcome = outcome.with_path_status_line(line);
    }
    outcome.source_artifacts = source_artifacts;
    outcome.log_artifacts = log_artifacts;
    outcome
}

/// The artifact paths this scenario derives from the stage's artifact directory.
pub struct Paths {
    pub baseline_report: PathBuf,
    pub baseline_log: PathBuf,
    pub bypass_report: PathBuf,
    pub bypass_log: PathBuf,
    pub monitor_log: PathBuf,
    pub monitor_summary: PathBuf,
    pub trust_summary: PathBuf,
}

impl Paths {
    pub fn in_dir(artifact_dir: &Path) -> Self {
        Self {
            baseline_report: artifact_dir.join(BASELINE_REPORT_FILE),
            baseline_log: artifact_dir.join(BASELINE_LOG_FILE),
            bypass_report: artifact_dir.join(BYPASS_REPORT_FILE),
            bypass_log: artifact_dir.join(BYPASS_LOG_FILE),
            monitor_log: artifact_dir.join(MONITOR_LOG_FILE),
            monitor_summary: artifact_dir.join(MONITOR_SUMMARY_FILE),
            trust_summary: artifact_dir.join(TRUST_SUMMARY_FILE),
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the shell's `main` is one linear sequence of phases and splitting it \
              would hide the order the evidence is gathered in, which is itself \
              load-bearing: the pre-soak bypass verdicts must be read before the \
              soak and the post-soak ones after it"
)]
fn execute(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: SoakOptions,
    paths: &Paths,
    checks: &mut Checks,
    path_status_line: &mut Option<String>,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    // ── baseline, and the PRE-soak half of the leak/bypass evidence ──
    let phase = "bootstrapping direct remote-exit path before soak";
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
    checks.record_bool(
        "direct_remote_exit_ready",
        baseline.succeeded() && baseline.passed(BaselineScenario::Direct.success_check()),
    );
    checks.record_bool(
        "cross_network_topology_heuristic",
        baseline.passed("cross_network_topology_heuristic"),
    );
    let pre_leak_ok = baseline.passed("remote_exit_no_underlay_leak");
    let pre_bypass_ok = baseline.passed("remote_exit_server_ip_bypass_is_narrow");

    if !checks.passed("direct_remote_exit_ready") {
        return Err("direct remote-exit baseline failed; refusing soak claim".to_owned());
    }
    if !checks.passed("cross_network_topology_heuristic") {
        return Err(
            "direct remote-exit baseline did not prove a credible cross-network topology"
                .to_owned(),
        );
    }

    let phase = "initializing live runtime monitor for cross-network soak";
    write_trust_summary(
        host,
        &paths.trust_summary,
        SUITE,
        &[
            ("client-host", lab.client_ssh_target.as_str()),
            ("exit-host", lab.exit_ssh_target.as_str()),
        ],
    )?;
    during(phase, wait_for_daemon_socket(exit.runner))?;
    during(phase, wait_for_daemon_socket(client.runner))?;

    let client_plaintext_start = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_start = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    // ── the soak ──
    let phase = "soaking the cross-network remote-exit path";
    let soak = during(phase, soak_loop(client, exit, lab, options))?;

    let client_plaintext_end = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_end = during(phase, no_plaintext_passphrase_check(exit.runner))?;
    checks.record_bool(
        "no_plaintext_passphrase_files",
        client_plaintext_start
            && exit_plaintext_start
            && client_plaintext_end
            && exit_plaintext_end,
    );

    // ── the POST-soak half ──
    let phase = "running post-soak leak and bypass verification";
    let verdicts = run_bypass_validator(
        host,
        lab,
        &BypassRun {
            report_path: paths.bypass_report.as_path(),
            log_path: paths.bypass_log.as_path(),
            probe_ssh_target: lab.exit_ssh_target.as_str(),
            probe_bind_ip: None,
            missing_evidence_summary: "post-soak server-IP bypass validator failed before emitting evidence",
            phase,
        },
    )?;
    let bypass_status = during(phase, host.read_report_status(&paths.bypass_report))?;
    checks.record_bool(
        "post_soak_bypass_ready",
        bypass_status == super::host::CHECK_PASS,
    );

    // Both halves, before AND after. A path that resisted a bypass at the start
    // and not at the end has not been stable, which is the only thing this
    // scenario claims.
    checks.record_bool(
        "remote_exit_no_underlay_leak",
        pre_leak_ok && verdicts.no_underlay_leak,
    );
    checks.record_bool(
        "remote_exit_server_ip_bypass_is_narrow",
        pre_bypass_ok && verdicts.bypass_is_narrow,
    );

    let phase = "capturing final live-path evidence after soak";
    *path_status_line = Some(during(phase, status(client.runner))?);

    // The shell also required the bypass child's process exit status here. That
    // is the same fact as its report status, already recorded above as
    // `post_soak_bypass_ready`, so it is not checked twice.
    checks.record_bool(
        "long_soak_stable",
        soak.is_stable(options) && checks.passed("no_plaintext_passphrase_files"),
    );

    during(
        phase,
        host.write_artifact(&paths.monitor_log, &soak.transcript),
    )?;
    during(
        phase,
        host.write_soak_monitor_summary(soak.summary_config(
            &paths.monitor_summary,
            options,
            checks,
        )),
    )?;

    // ── verdict, in the shell's order ──
    if !checks.passed("cross_network_topology_heuristic") {
        return Err("soak path topology did not credibly prove a cross-network claim".to_owned());
    }
    if !checks.passed("direct_remote_exit_ready") {
        return Err("soak path did not preserve direct remote-exit bootstrap proof".to_owned());
    }
    if !checks.passed("post_soak_bypass_ready") {
        return Err(
            "soak path did not produce a passing post-soak server-IP bypass report".to_owned(),
        );
    }
    if !checks.passed("no_plaintext_passphrase_files") {
        return Err(
            "soak path detected plaintext passphrase material before or after soak".to_owned(),
        );
    }
    if !checks.passed("long_soak_stable") {
        return Err(soak.instability_summary());
    }
    if !checks.passed("remote_exit_no_underlay_leak") {
        return Err(
            "cross-network remote-exit soak could not prove underlay leak resistance before and \
             after soak"
                .to_owned(),
        );
    }
    if !checks.passed("remote_exit_server_ip_bypass_is_narrow") {
        return Err(
            "cross-network remote-exit soak server-IP bypass scope was broader than allowed"
                .to_owned(),
        );
    }
    Ok(())
}

/// Every counter the soak keeps, and the transcript it wrote.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SoakObservation {
    pub samples: u64,
    pub failing_samples: u64,
    pub max_consecutive_failures_observed: u64,
    pub elapsed_secs: u64,
    pub direct_samples: u64,
    pub relay_samples: u64,
    pub fail_closed_samples: u64,
    pub other_path_samples: u64,
    pub path_transition_count: u64,
    pub status_mismatch_samples: u64,
    pub route_mismatch_samples: u64,
    pub endpoint_mismatch_samples: u64,
    pub dns_alarm_bad_samples: u64,
    pub transport_identity_failures: u64,
    pub endpoint_change_events_start: u64,
    pub endpoint_change_events_end: u64,
    pub first_non_direct_reason: String,
    pub last_path_mode: String,
    pub last_path_reason: String,
    pub first_failure_reason: String,
    pub transcript: String,
}

impl SoakObservation {
    /// The counter delta across the soak, floored at zero.
    ///
    /// The shell floored it too: the counter is monotonic in the daemon, so a
    /// smaller end value means the daemon restarted, and a negative delta would
    /// be meaningless rather than informative.
    pub fn endpoint_change_events_delta(&self) -> u64 {
        self.endpoint_change_events_end
            .saturating_sub(self.endpoint_change_events_start)
    }

    /// The shell's fifteen-clause stability conjunction, minus the plaintext
    /// check which the caller ANDs in separately (it is also its own reported
    /// check).
    ///
    /// The zero-valued clauses are the ones that make this a *stability* proof
    /// rather than a liveness one: any relay sample, any fail-closed sample,
    /// any path transition at all means the path changed, and a path that
    /// changed has not been stable however well it ended up.
    pub fn is_stable(&self, options: SoakOptions) -> bool {
        self.samples > 0
            && self.elapsed_secs >= options.duration_secs
            && self.failing_samples <= options.max_failing_samples
            && self.max_consecutive_failures_observed <= options.max_consecutive_failures
            && self.direct_samples == self.samples
            && self.relay_samples == 0
            && self.fail_closed_samples == 0
            && self.other_path_samples == 0
            && self.path_transition_count == 0
            && self.status_mismatch_samples == 0
            && self.route_mismatch_samples == 0
            && self.endpoint_mismatch_samples == 0
            && self.dns_alarm_bad_samples == 0
            && self.transport_identity_failures == 0
    }

    /// The shell's instability summary, which names every counter rather than
    /// only the first failing one — an unstable soak usually trips several at
    /// once and the combination is the diagnosis.
    pub fn instability_summary(&self) -> String {
        format!(
            "cross-network remote-exit soak stability checks failed (samples={}, failing={}, \
             consecutive={}, direct={}, relay={}, fail_closed={}, other={}, transitions={}, \
             status_mismatch={}, route_mismatch={}, endpoint_mismatch={}, dns_alarm_bad={}, \
             transport_identity_failures={}, elapsed={}s, first_failure={}, first_non_direct={})",
            self.samples,
            self.failing_samples,
            self.max_consecutive_failures_observed,
            self.direct_samples,
            self.relay_samples,
            self.fail_closed_samples,
            self.other_path_samples,
            self.path_transition_count,
            self.status_mismatch_samples,
            self.route_mismatch_samples,
            self.endpoint_mismatch_samples,
            self.dns_alarm_bad_samples,
            self.transport_identity_failures,
            self.elapsed_secs,
            none_if_empty(&self.first_failure_reason),
            none_if_empty(&self.first_non_direct_reason),
        )
    }

    fn summary_config(
        &self,
        path: &Path,
        options: SoakOptions,
        checks: &Checks,
    ) -> WriteCrossNetworkSoakMonitorSummaryConfig {
        WriteCrossNetworkSoakMonitorSummaryConfig {
            path: path.to_path_buf(),
            samples: self.samples,
            failing_samples: self.failing_samples,
            max_consecutive_failures_observed: self.max_consecutive_failures_observed,
            elapsed_secs: self.elapsed_secs,
            required_soak_duration_secs: options.duration_secs,
            allowed_failing_samples: options.max_failing_samples,
            allowed_max_consecutive_failures: options.max_consecutive_failures,
            direct_remote_exit_ready: verdict_str(checks, "direct_remote_exit_ready"),
            post_soak_bypass_ready: verdict_str(checks, "post_soak_bypass_ready"),
            no_plaintext_passphrase_files: verdict_str(checks, "no_plaintext_passphrase_files"),
            direct_samples: self.direct_samples,
            relay_samples: self.relay_samples,
            fail_closed_samples: self.fail_closed_samples,
            other_path_samples: self.other_path_samples,
            path_transition_count: self.path_transition_count,
            status_mismatch_samples: self.status_mismatch_samples,
            route_mismatch_samples: self.route_mismatch_samples,
            endpoint_mismatch_samples: self.endpoint_mismatch_samples,
            dns_alarm_bad_samples: self.dns_alarm_bad_samples,
            transport_identity_failures: self.transport_identity_failures,
            endpoint_change_events_start: self.endpoint_change_events_start,
            endpoint_change_events_end: self.endpoint_change_events_end,
            endpoint_change_events_delta: self.endpoint_change_events_delta(),
            first_non_direct_reason: none_if_empty(&self.first_non_direct_reason).to_owned(),
            last_path_mode: none_if_empty(&self.last_path_mode).to_owned(),
            last_path_reason: none_if_empty(&self.last_path_reason).to_owned(),
            first_failure_reason: none_if_empty(&self.first_failure_reason).to_owned(),
            long_soak_stable: verdict_str(checks, "long_soak_stable"),
        }
    }
}

/// `"none"` for an empty string — the shell's `${var:-none}`, which every one of
/// these fields went through before reaching the summary writer.
fn none_if_empty(value: &str) -> &str {
    if value.is_empty() { REASON_NONE } else { value }
}

fn verdict_str(checks: &Checks, name: &str) -> String {
    checks.verdict(name).as_str().to_owned()
}

/// Sample the path until the soak duration has elapsed, or until too many
/// samples have failed in a row.
fn soak_loop(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    options: SoakOptions,
) -> Result<SoakObservation, String> {
    let mut clock = SoakClock::start(lab.time_scale);
    let mut observed = SoakObservation::default();
    let mut consecutive_failures: u64 = 0;
    let mut previous_path_mode: Option<String> = None;
    let exit_endpoint = exit.wireguard_endpoint();

    while clock.elapsed_secs() < options.duration_secs {
        let sampled_at = clock.now();
        observed.samples += 1;

        // A command that could not be run at all yields a marker string rather
        // than aborting the soak. That is the shell's shape and it is right: a
        // transport hiccup mid-soak is itself a stability observation, and the
        // sample it produces fails, which is the honest verdict.
        let client_status = status(client.runner).unwrap_or_else(|_| STATUS_FAILED.to_owned());
        let client_route = provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        )
        .unwrap_or_else(|_| ROUTE_FAILED.to_owned());
        let client_endpoints =
            capture_root_allow_failure(client.runner, &["wg", "show", "rustynet0", "endpoints"])
                .unwrap_or_else(|_| ENDPOINT_FAILED.to_owned());

        let field = |key: &str| provisioning::extract_netcheck_value(&client_status, key);
        let path_mode = field("path_mode").unwrap_or_default();
        let path_reason = field("path_reason").unwrap_or_default();
        let transport_identity_state = field("transport_socket_identity_state").unwrap_or_default();
        let transport_identity_error = field("transport_socket_identity_error").unwrap_or_default();
        let dns_alarm_state = field("dns_alarm_state").unwrap_or_default();
        let dns_alarm_reason = field("dns_alarm_reason").unwrap_or_default();
        let endpoint_change_events =
            provisioning::netcheck_counter(&client_status, "traversal_endpoint_change_events");

        if observed.samples == 1 {
            observed.endpoint_change_events_start = endpoint_change_events;
        }
        observed.endpoint_change_events_end = endpoint_change_events;

        let last_path_mode = if path_mode.is_empty() {
            UNKNOWN.to_owned()
        } else {
            path_mode.clone()
        };
        let last_path_reason = if path_reason.is_empty() {
            UNKNOWN.to_owned()
        } else {
            path_reason.clone()
        };
        // A transition is a CHANGE, so the first sample can never be one.
        if previous_path_mode
            .as_deref()
            .is_some_and(|previous| previous != last_path_mode)
        {
            observed.path_transition_count += 1;
        }
        previous_path_mode = Some(last_path_mode.clone());

        let mut reasons: Vec<&str> = Vec::new();
        match last_path_mode.as_str() {
            PATH_MODE_DIRECT => observed.direct_samples += 1,
            PATH_MODE_RELAY => {
                observed.relay_samples += 1;
                if observed.first_non_direct_reason.is_empty() {
                    observed.first_non_direct_reason = last_path_reason.clone();
                }
            }
            other => {
                // Fail-closed is counted apart from "some other mode" because
                // they mean opposite things: the first is the daemon correctly
                // refusing to leak, the second is a mode nobody predicted.
                if client_status.contains("state=FailClosed")
                    || other.contains("fail_closed")
                    || other.contains("blocked")
                {
                    observed.fail_closed_samples += 1;
                } else {
                    observed.other_path_samples += 1;
                }
                if observed.first_non_direct_reason.is_empty() {
                    observed.first_non_direct_reason = last_path_reason.clone();
                }
            }
        }
        if last_path_mode != PATH_MODE_DIRECT {
            reasons.push("path_not_direct");
        }

        if !client_exit_selected(&client_status, &exit.node_id) {
            reasons.push("status_not_exit_active");
            observed.status_mismatch_samples += 1;
        }
        if !route_via_rustynet(&client_route) {
            reasons.push("route_not_tunnelled");
            observed.route_mismatch_samples += 1;
        }
        if !client_endpoints.contains(&exit_endpoint) {
            reasons.push("exit_endpoint_not_visible");
            observed.endpoint_mismatch_samples += 1;
        }
        // Both the state AND the reason: a daemon reporting an `ok` alarm state
        // with a non-`none` reason is telling you something is wrong in the
        // half of the pair the state does not cover.
        if matches!(dns_alarm_state.as_str(), "critical" | "error" | "missing")
            || none_if_empty(&dns_alarm_reason) != REASON_NONE
        {
            reasons.push("dns_alarm_bad");
            observed.dns_alarm_bad_samples += 1;
        }
        // A POSITIVE requirement, so an absent field fails rather than passing
        // by omission — the same trap `signed_state_healthy` guards against.
        if transport_identity_state != AUTHORITATIVE_TRANSPORT
            || none_if_empty(&transport_identity_error) != REASON_NONE
        {
            reasons.push("transport_identity_not_authoritative");
            observed.transport_identity_failures += 1;
        }

        let sample_failed = !reasons.is_empty();
        let sample_reason = if sample_failed {
            let mut joined = reasons.join(";");
            joined.push(';');
            joined
        } else {
            REASON_NONE.to_owned()
        };

        observed.transcript.push_str(&render_sample(
            sampled_at,
            observed.samples,
            sample_failed,
            &sample_reason,
            &SampleFields {
                path_mode: &last_path_mode,
                path_reason: &last_path_reason,
                transport_identity_state: &transport_identity_state,
                transport_identity_error: &transport_identity_error,
                dns_alarm_state: &dns_alarm_state,
                dns_alarm_reason: &dns_alarm_reason,
                endpoint_change_events,
                status: &client_status,
                route: &client_route,
                endpoints: &client_endpoints,
            },
        ));

        observed.last_path_mode = last_path_mode;
        observed.last_path_reason = last_path_reason;

        if sample_failed {
            observed.failing_samples += 1;
            consecutive_failures += 1;
            if observed.first_failure_reason.is_empty() {
                observed.first_failure_reason = sample_reason;
            }
            observed.max_consecutive_failures_observed = observed
                .max_consecutive_failures_observed
                .max(consecutive_failures);
            // Breaking early leaves `elapsed_secs` short of the duration, which
            // fails the stability clause on its own — so an aborted soak cannot
            // be mistaken for a completed one.
            if consecutive_failures > options.max_consecutive_failures {
                break;
            }
        } else {
            consecutive_failures = 0;
        }

        clock.tick(options.sample_interval_secs);
    }

    observed.elapsed_secs = clock.elapsed_secs();
    Ok(observed)
}

/// The marker a sample records when the status command could not be run.
const STATUS_FAILED: &str = "status-command-failed";
/// As above, for the route query.
const ROUTE_FAILED: &str = "route-command-failed";
/// As above, for the endpoint table.
const ENDPOINT_FAILED: &str = "endpoint-command-failed";
/// The shell's `${var:-unknown}` for an absent path field.
const UNKNOWN: &str = "unknown";

/// The captured fields one monitor line reports.
struct SampleFields<'a> {
    path_mode: &'a str,
    path_reason: &'a str,
    transport_identity_state: &'a str,
    transport_identity_error: &'a str,
    dns_alarm_state: &'a str,
    dns_alarm_reason: &'a str,
    endpoint_change_events: u64,
    status: &'a str,
    route: &'a str,
    endpoints: &'a str,
}

/// One monitor-log line, in the shell's `printf` layout.
///
/// Absent fields render as `missing` rather than empty, so a line always has the
/// same shape and a reader can tell "the daemon did not report this" from "the
/// daemon reported an empty value".
fn render_sample(
    sampled_at: u64,
    sample: u64,
    failed: bool,
    reason: &str,
    fields: &SampleFields<'_>,
) -> String {
    let missing = |value: &str| {
        if value.is_empty() {
            "missing".to_owned()
        } else {
            value.to_owned()
        }
    };
    let result = if failed {
        Verdict::Fail.as_str()
    } else {
        Verdict::Pass.as_str()
    };
    format!(
        "{sampled_at}|sample={sample}|result={result}|reason={reason}|path_mode={}|path_reason={}|\
         transport_identity_state={}|transport_identity_error={}|dns_alarm_state={}|\
         dns_alarm_reason={}|endpoint_change_events={}|status={}|route={}|endpoints={}\n",
        missing(fields.path_mode),
        missing(fields.path_reason),
        missing(fields.transport_identity_state),
        missing(fields.transport_identity_error),
        missing(fields.dns_alarm_state),
        missing(fields.dns_alarm_reason),
        fields.endpoint_change_events,
        squeeze(fields.status),
        squeeze(fields.route),
        squeeze(fields.endpoints),
    )
}

/// Re-exported so the stage and tests can name the child checks this scenario
/// folds. See [`BYPASS_CHECKS`].
pub const POST_SOAK_BYPASS_CHECKS: &[&str] = BYPASS_CHECKS;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const EXIT_NODE_ID: &str = "exit-1";
    const EXIT_ADDR: &str = "192.168.19.40";

    fn options(duration: u64, interval: u64) -> SoakOptions {
        SoakOptions::new(duration, interval, 2, 2).expect("positive")
    }

    /// A client whose every sampled field is healthy.
    fn stable_client() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!(
                        "exit_node={EXIT_NODE_ID} state=ExitActive path_mode=direct_active \
                         path_reason=none transport_socket_identity_state={AUTHORITATIVE_TRANSPORT} \
                         transport_socket_identity_error=none dns_alarm_state=ok \
                         dns_alarm_reason=none traversal_endpoint_change_events=7"
                    ),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0 src 10.42.0.2".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{EXIT_ADDR}:51820"),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn soak(client: &MockLeafRunner, options: SoakOptions) -> SoakObservation {
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(client, "client-1", "192.168.18.40");
        let exit_runner = MockLeafRunner::default();
        let exit_node = ScenarioNode::new(&exit_runner, EXIT_NODE_ID, EXIT_ADDR);
        soak_loop(&client_node, &exit_node, &lab, options).expect("soak")
    }

    #[test]
    fn the_virtual_clock_runs_the_real_sample_count_in_no_time() {
        // The contract the whole module is built on: a collapsed run takes the
        // same samples over the same virtual duration as a real one, and its
        // elapsed time still satisfies the duration clause.
        let started = std::time::Instant::now();
        let observed = soak(&stable_client(), options(120, 5));
        assert_eq!(observed.samples, 24, "120s at 5s intervals");
        assert_eq!(observed.elapsed_secs, 120);
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "a collapsed soak must not actually wait"
        );
        assert!(observed.is_stable(options(120, 5)));
    }

    #[test]
    fn a_collapsed_clock_reports_the_same_elapsed_time_a_real_one_would() {
        let mut clock = SoakClock::start(TimeScale::Collapsed);
        assert_eq!(clock.elapsed_secs(), 0);
        clock.tick(5);
        clock.tick(5);
        assert_eq!(clock.elapsed_secs(), 10);
        assert_eq!(clock.now(), clock.started_unix() + 10);
    }

    #[test]
    fn a_stable_soak_records_every_sample_as_direct_with_no_transitions() {
        let observed = soak(&stable_client(), options(20, 5));
        assert_eq!(observed.samples, 4);
        assert_eq!(observed.direct_samples, observed.samples);
        assert_eq!(observed.failing_samples, 0);
        assert_eq!(observed.path_transition_count, 0);
        assert_eq!(observed.relay_samples, 0);
        assert_eq!(observed.endpoint_change_events_start, 7);
        assert_eq!(observed.endpoint_change_events_end, 7);
        assert_eq!(observed.endpoint_change_events_delta(), 0);
        assert_eq!(observed.first_failure_reason, "");
        assert_eq!(observed.last_path_mode, PATH_MODE_DIRECT);
    }

    #[test]
    fn a_path_that_flapped_to_the_relay_and_back_is_not_stable() {
        // The failure a before/after check cannot see, and the reason this
        // scenario samples at all.
        let mut observed = SoakObservation {
            samples: 10,
            elapsed_secs: 120,
            direct_samples: 9,
            relay_samples: 1,
            path_transition_count: 2,
            ..SoakObservation::default()
        };
        assert!(!observed.is_stable(options(120, 5)));

        // Even with the relay sample forgiven, the transitions alone disqualify
        // it: the path changed.
        observed.direct_samples = 10;
        observed.relay_samples = 0;
        assert!(!observed.is_stable(options(120, 5)));

        observed.path_transition_count = 0;
        assert!(observed.is_stable(options(120, 5)));
    }

    #[test]
    fn a_soak_cut_short_by_consecutive_failures_fails_the_duration_clause() {
        // Nothing scripted: every sample fails every clause.
        let observed = soak(&MockLeafRunner::default(), options(120, 5));
        // Three failures in a row exceeds the allowance of 2, so it breaks.
        assert_eq!(observed.samples, 3);
        assert_eq!(observed.max_consecutive_failures_observed, 3);
        assert!(observed.elapsed_secs < 120);
        assert!(
            !observed.is_stable(options(120, 5)),
            "an aborted soak must not read as a completed one"
        );
        assert!(observed.first_failure_reason.contains("path_not_direct"));
    }

    #[test]
    fn a_missing_transport_identity_field_fails_the_sample_rather_than_passing_by_omission() {
        let client = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    // Everything healthy EXCEPT the transport identity, which
                    // is simply absent.
                    format!(
                        "exit_node={EXIT_NODE_ID} state=ExitActive path_mode=direct_active \
                         dns_alarm_state=ok dns_alarm_reason=none"
                    ),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{EXIT_ADDR}:51820"),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let observed = soak(&client, options(5, 5));
        assert_eq!(observed.transport_identity_failures, 1);
        assert_eq!(observed.failing_samples, 1);
        assert_eq!(
            observed.direct_samples, 1,
            "the path mode itself was still direct"
        );
    }

    #[test]
    fn a_healthy_dns_alarm_state_with_a_non_none_reason_still_fails() {
        // The pair is checked as a pair: an `ok` state with a reason attached is
        // the daemon telling you about the half the state does not cover.
        let client = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!(
                        "exit_node={EXIT_NODE_ID} state=ExitActive path_mode=direct_active \
                         transport_socket_identity_state={AUTHORITATIVE_TRANSPORT} \
                         transport_socket_identity_error=none dns_alarm_state=ok \
                         dns_alarm_reason=zone_stale"
                    ),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{EXIT_ADDR}:51820"),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let observed = soak(&client, options(5, 5));
        assert_eq!(observed.dns_alarm_bad_samples, 1);
    }

    #[test]
    fn a_fail_closed_sample_is_counted_apart_from_an_unrecognised_mode() {
        // Opposite meanings: one is the daemon correctly refusing to leak, the
        // other is a mode nobody predicted.
        let fail_closed = MockLeafRunner {
            stdout_by_match: vec![(
                "rustynet status".to_owned(),
                "state=FailClosed path_mode=blocked".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let observed = soak(&fail_closed, options(5, 5));
        assert_eq!(observed.fail_closed_samples, 1);
        assert_eq!(observed.other_path_samples, 0);

        let strange = MockLeafRunner {
            stdout_by_match: vec![(
                "rustynet status".to_owned(),
                "state=Connecting path_mode=negotiating".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let observed = soak(&strange, options(5, 5));
        assert_eq!(observed.fail_closed_samples, 0);
        assert_eq!(observed.other_path_samples, 1);
    }

    #[test]
    fn a_transport_failure_mid_soak_becomes_a_failing_sample_not_an_aborted_run() {
        let client = MockLeafRunner {
            transport_error_on: vec![0],
            ..stable_client()
        };
        let observed = soak(&client, options(10, 5));
        assert_eq!(observed.samples, 2, "the soak continued");
        assert_eq!(observed.failing_samples, 1);
        assert!(observed.transcript.contains(STATUS_FAILED));
    }

    #[test]
    fn the_endpoint_change_delta_floors_at_zero_when_the_daemon_restarted() {
        let observed = SoakObservation {
            endpoint_change_events_start: 9,
            endpoint_change_events_end: 2,
            ..SoakObservation::default()
        };
        assert_eq!(observed.endpoint_change_events_delta(), 0);
    }

    #[test]
    fn absent_fields_render_as_missing_so_a_line_keeps_its_shape() {
        let line = render_sample(
            1700,
            3,
            true,
            "path_not_direct;",
            &SampleFields {
                path_mode: "",
                path_reason: "",
                transport_identity_state: "",
                transport_identity_error: "",
                dns_alarm_state: "",
                dns_alarm_reason: "",
                endpoint_change_events: 4,
                status: "a  b\nc",
                route: "",
                endpoints: "",
            },
        );
        assert!(line.starts_with("1700|sample=3|result=fail|reason=path_not_direct;|"));
        assert!(line.contains("path_mode=missing"));
        assert!(line.contains("dns_alarm_reason=missing"));
        assert!(line.contains("status=a b;c"));
        assert!(line.ends_with('\n'));
    }

    #[test]
    fn the_tunables_reject_a_zero_duration_or_interval_but_allow_zero_allowances() {
        assert!(SoakOptions::new(0, 5, 2, 2).is_err());
        assert!(SoakOptions::new(120, 0, 2, 2).is_err());
        // Zero allowances are the STRICTEST setting, not an invalid one.
        assert!(SoakOptions::new(120, 5, 0, 0).is_ok());
        let defaults = SoakOptions::default();
        assert_eq!(defaults.duration_secs(), 120);
        assert_eq!(defaults.sample_interval_secs(), 5);
    }

    #[test]
    fn the_instability_summary_names_every_counter() {
        let observed = SoakObservation {
            samples: 5,
            failing_samples: 3,
            relay_samples: 2,
            elapsed_secs: 25,
            ..SoakObservation::default()
        };
        let summary = observed.instability_summary();
        assert!(summary.contains("samples=5"));
        assert!(summary.contains("failing=3"));
        assert!(summary.contains("relay=2"));
        assert!(summary.contains("elapsed=25s"));
        // Empty reasons read as "none", the shell's `${var:-none}`.
        assert!(summary.contains("first_failure=none"));
        assert!(summary.contains("first_non_direct=none"));
    }
}
