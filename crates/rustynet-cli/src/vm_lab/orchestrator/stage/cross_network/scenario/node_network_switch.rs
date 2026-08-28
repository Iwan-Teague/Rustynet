//! `cross_network_node_network_switch`, ported from
//! `scripts/e2e/live_linux_cross_network_node_network_switch_test.sh` (631 ln).
//!
//! # What this proves
//!
//! That a client whose underlay address changes under a live tunnel notices,
//! re-issues its signed traversal state, is seen at its new endpoint by the
//! peer, and re-converges within a reconnect SLO — **without** leaking around
//! the tunnel or degrading its signed state at any point in between.
//!
//! The last clause is what makes this different from a reconnect test, and it
//! is why the evidence is a *sampled series* rather than a before/after pair.
//! `no_underlay_leak_during_transition` and
//! `signed_state_valid_during_transition` pass only when **every** sample
//! during the transition was clean; a scenario that looked only at the endpoint
//! state would accept a client that briefly routed in the clear while its
//! tunnel was down, which is precisely the window this scenario exists to
//! inspect.
//!
//! # Composition
//!
//! The baseline is [`direct_remote_exit`](super::direct_remote_exit), run
//! through [`baseline::compose`]. In bash this was `bash
//! live_linux_cross_network_direct_remote_exit_test.sh …` followed by reading
//! four fields back out of the report it wrote; the readiness verdict is now
//! taken from the returned [`ScenarioOutcome`] directly.
//!
//! # Checks the shell performed that are now structural
//!
//! Beyond the ones common to every scenario (see the module docs), this port
//! drops:
//!
//! * **`validate_positive_integer` on `--reconnect-slo-secs`.** The SLO is a
//!   [`u32`] the caller supplies, and [`NodeNetworkSwitchOptions::new`] rejects
//!   zero — there is no argv string left to fail to parse.
//! * **`live_lab_init` / `live_lab_push_sudo_password` on both hosts**, for the
//!   reason the direct scenario drops them: `SudoRunner` emits `sudo -n` and
//!   fails closed on exactly the condition the pre-check existed to detect.
//! * **`live_lab_resolved_target_address`.** The caller resolved both underlay
//!   addresses before building [`ScenarioNode`](super::ScenarioNode).
//!
//! One new deviation, recorded rather than silent: the shell's monitor summary
//! was written by an inline `python` heredoc. It is [`serde_json`] here, which
//! removes a python3 dependency from a validator that had no other reason to
//! need one. The field names and types are unchanged.

use std::path::Path;

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::{self, DefaultRoute, RoamAlias, SAMPLE_INTERVAL, unix_now};
use super::host::ScenarioHost;
use super::provisioning::{self, LabContext, during, netcheck_counter};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, capture_root_allow_failure,
    no_plaintext_passphrase_check, route_via_rustynet, rustynet_capture_allow_failure, status,
    wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_node_network_switch";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "node_network_switch_success",
    "direct_remote_exit_ready",
    "endpoint_change_detected",
    "traversal_reissue_triggered",
    "session_reconnect_within_slo",
    "peer_received_updated_endpoint_hint",
    "no_underlay_leak_during_transition",
    "signed_state_valid_during_transition",
    "cross_network_topology_heuristic",
    "no_plaintext_passphrase_files",
];

/// The nine checks `node_network_switch_success` aggregates — every other check
/// in [`CHECKS`]. Named once so the aggregate cannot drift from the list the
/// shell spelled inline as a nine-clause `&&`.
const AGGREGATE_CHECKS: &[&str] = &[
    "direct_remote_exit_ready",
    "endpoint_change_detected",
    "traversal_reissue_triggered",
    "session_reconnect_within_slo",
    "peer_received_updated_endpoint_hint",
    "no_underlay_leak_during_transition",
    "signed_state_valid_during_transition",
    "cross_network_topology_heuristic",
    "no_plaintext_passphrase_files",
];

/// The shell's `--reconnect-slo-secs` default. It is both the SLO the
/// reconnect is measured against **and** the sample count of the monitoring
/// loop, because the loop runs one sample per second for exactly that many
/// seconds — so raising it lengthens the observation window as well as the
/// budget.
pub const DEFAULT_RECONNECT_SLO_SECS: u32 = 30;

/// The `traversal_endpoint_fingerprint` field an endpoint change alters.
const FINGERPRINT_FIELD: &str = "traversal_endpoint_fingerprint";
/// The monotonic counter a traversal re-issue increments.
const REISSUE_FIELD: &str = "traversal_preexpiry_refresh_events";

/// Artifact basename of the composed baseline's report.
const BASELINE_REPORT_FILE: &str = "cross_network_node_network_switch_direct_stage_report.json";
/// Artifact basename of the composed baseline's log.
const BASELINE_LOG_FILE: &str = "cross_network_node_network_switch_direct_stage.log";
/// Artifact basename of the per-sample monitoring transcript.
const MONITOR_LOG_FILE: &str = "cross_network_node_network_switch_monitor.log";
/// Artifact basename of the machine-readable monitoring summary.
const MONITOR_SUMMARY_FILE: &str = "cross_network_node_network_switch_summary.json";

/// The scenario's one tunable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeNetworkSwitchOptions {
    reconnect_slo_secs: u32,
}

impl Default for NodeNetworkSwitchOptions {
    fn default() -> Self {
        Self {
            reconnect_slo_secs: DEFAULT_RECONNECT_SLO_SECS,
        }
    }
}

impl NodeNetworkSwitchOptions {
    /// A zero SLO is rejected rather than clamped: it would run zero samples,
    /// so every sampled check would pass vacuously and the scenario would
    /// report a clean transition it never observed.
    pub fn new(reconnect_slo_secs: u32) -> Result<Self, String> {
        if reconnect_slo_secs == 0 {
            return Err("reconnect slo seconds must be a positive integer".to_owned());
        }
        Ok(Self { reconnect_slo_secs })
    }

    pub fn reconnect_slo_secs(self) -> u32 {
        self.reconnect_slo_secs
    }
}

/// Run the node network-switch scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);

    // Declared before they exist, as the shell did, so a report written from a
    // failure path still names its evidence.
    let source_artifacts = vec![
        baseline::path_arg(&lab.artifact(BASELINE_REPORT_FILE)),
        baseline::path_arg(&lab.artifact(MONITOR_SUMMARY_FILE)),
    ];
    let log_artifacts = vec![
        baseline::path_arg(&lab.artifact(BASELINE_LOG_FILE)),
        baseline::path_arg(&lab.artifact(MONITOR_LOG_FILE)),
    ];

    let mut outcome = match execute(host, inputs, lab, options, &mut checks) {
        Ok(()) => ScenarioOutcome::passed(checks),
        Err(summary) => ScenarioOutcome::failed(checks, summary),
    };
    outcome.source_artifacts = source_artifacts;
    outcome.log_artifacts = log_artifacts;
    outcome
}

fn execute(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
    checks: &mut Checks,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    // ── baseline ──
    let phase = "bootstrapping direct remote-exit path before node network-switch simulation";
    let baseline_report = lab.artifact(BASELINE_REPORT_FILE);
    let baseline_log = lab.artifact(BASELINE_LOG_FILE);
    let baseline = baseline::compose(
        host,
        inputs,
        lab,
        BaselineScenario::Direct,
        &BaselinePaths {
            report_path: baseline_report.as_path(),
            log_path: baseline_log.as_path(),
        },
        phase,
    )?;

    // The shell read four fields back out of the baseline's report: its status
    // plus three checks. Readiness required the first three of those to be
    // `pass`; the topology heuristic was recorded independently, because it
    // describes the LAB rather than this scenario's own behaviour and a
    // same-subnet topology must be reported as such even when everything else
    // failed.
    checks.record_bool(
        "direct_remote_exit_ready",
        baseline.succeeded()
            && baseline.passed(BaselineScenario::Direct.success_check())
            && baseline.passed("remote_exit_no_underlay_leak"),
    );
    checks.record_bool(
        "cross_network_topology_heuristic",
        baseline.passed("cross_network_topology_heuristic"),
    );
    if !checks.passed("direct_remote_exit_ready") {
        return Err(
            "direct baseline did not produce secure readiness for node switch validation"
                .to_owned(),
        );
    }

    // ── prepare the switch ──
    let phase = "initializing runtime for node underlay switch validation";
    during(phase, wait_for_daemon_socket(exit.runner))?;
    during(phase, wait_for_daemon_socket(client.runner))?;

    let alias = during(
        phase,
        endpoint_switch::choose_alias(
            &client.address,
            &[client.address.as_str(), exit.address.as_str()],
        ),
    )?;
    let route = during(phase, endpoint_switch::read_default_route(client.runner))?;

    let client_plaintext_start = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_start = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    // Two separate `netcheck` calls in the shell, one per field. Collapsed to
    // one: reading the fingerprint and the re-issue counter from the same
    // sample removes a window in which the endpoint could change between them
    // and make the "before" state internally inconsistent.
    let before = during(
        phase,
        rustynet_capture_allow_failure(client.runner, &["netcheck"]),
    )?;
    let fingerprint_before = provisioning::extract_netcheck_value(&before, FINGERPRINT_FIELD);
    let reissue_events_before = netcheck_counter(&before, REISSUE_FIELD);

    // ── switch, observe, and always put the route table back ──
    let phase = "applying client underlay alias and route switch";
    let switch_started_unix = unix_now();
    let observed = observe_transition(
        client,
        exit,
        lab,
        options,
        &route,
        &alias,
        &Baseline {
            fingerprint: fingerprint_before.as_deref(),
            reissue_events: reissue_events_before,
        },
    );
    // The shell cleared the alias from an `EXIT` trap, so it ran on every path
    // including the failure ones. Clearing here before the `?` keeps that: a
    // scenario that leaves a guest with a rewritten default route has left
    // residue for the next stage to trip over.
    endpoint_switch::clear_alias(client.runner, &route, &alias);
    let observed = during(phase, observed)?;

    let phase = "recording node network-switch evidence";
    checks.record_bool(
        "endpoint_change_detected",
        observed.endpoint_change_detected,
    );
    checks.record_bool(
        "traversal_reissue_triggered",
        observed.traversal_reissue_triggered,
    );
    checks.record_bool(
        "peer_received_updated_endpoint_hint",
        observed.peer_received_updated_endpoint_hint,
    );
    checks.record_bool(
        "no_underlay_leak_during_transition",
        observed.route_leak_samples == 0,
    );
    checks.record_bool(
        "signed_state_valid_during_transition",
        observed.signed_state_invalid_samples == 0,
    );

    let reconnect_secs = observed.reconnect_secs(switch_started_unix);
    checks.record_bool(
        "session_reconnect_within_slo",
        matches!(reconnect_secs, Some(secs) if secs <= i64::from(options.reconnect_slo_secs)),
    );

    let client_plaintext_end = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_end = during(phase, no_plaintext_passphrase_check(exit.runner))?;
    // All four observations, not just the closing pair: a node that held
    // plaintext material before the switch and cleaned it up during is not a
    // node that never held any.
    checks.record_bool(
        "no_plaintext_passphrase_files",
        client_plaintext_start
            && exit_plaintext_start
            && client_plaintext_end
            && exit_plaintext_end,
    );

    during(
        phase,
        host.write_artifact(&lab.artifact(MONITOR_LOG_FILE), &observed.transcript),
    )?;
    during(
        phase,
        host.write_artifact(
            &lab.artifact(MONITOR_SUMMARY_FILE),
            &render_summary(
                switch_started_unix,
                &alias,
                &observed,
                reconnect_secs,
                options,
                checks,
            )?,
        ),
    )?;

    checks.record_bool(
        "node_network_switch_success",
        checks.all_passed(AGGREGATE_CHECKS),
    );
    if checks.passed("node_network_switch_success") {
        return Ok(());
    }
    Err(failure_summary(checks, options, reconnect_secs))
}

/// The shell's `if/elif` chain, in its order. The order is the diagnosis: it
/// names the *first* thing that did not happen, which for a transition is the
/// one that explains the rest.
fn failure_summary(
    checks: &Checks,
    options: NodeNetworkSwitchOptions,
    reconnect_secs: Option<i64>,
) -> String {
    if !checks.passed("endpoint_change_detected") {
        return "endpoint-change detection did not trigger during node underlay switch".to_owned();
    }
    if !checks.passed("traversal_reissue_triggered") {
        return "traversal re-issue did not trigger during node underlay switch".to_owned();
    }
    if !checks.passed("peer_received_updated_endpoint_hint") {
        return "peer did not observe updated endpoint hint after node underlay switch".to_owned();
    }
    if !checks.passed("session_reconnect_within_slo") {
        return format!(
            "session reconvergence exceeded reconnect SLO ({}s), measured={}s",
            options.reconnect_slo_secs,
            reconnect_secs.unwrap_or(NO_RECONNECT_SECS)
        );
    }
    if !checks.passed("no_underlay_leak_during_transition") {
        return "underlay leak detected during node underlay switch transition".to_owned();
    }
    if !checks.passed("signed_state_valid_during_transition") {
        return "signed state became invalid during node underlay switch transition".to_owned();
    }
    if !checks.passed("no_plaintext_passphrase_files") {
        return "plaintext passphrase files detected during node network-switch validation"
            .to_owned();
    }
    "node network-switch validation checks did not all pass".to_owned()
}

/// The shell's `reconnect_secs=-1` sentinel for "never reconnected", kept
/// because it is written into the summary artifact's typed `reconnect_secs`
/// field and a consumer reading that file expects the number, not `null`.
const NO_RECONNECT_SECS: i64 = -1;

/// The pre-switch values a change is measured against.
struct Baseline<'a> {
    /// `None` when the daemon reported no fingerprint at all. The shell
    /// required BOTH the before and after values to be non-empty before
    /// calling a change detected, so an absent baseline can never produce a
    /// detection — absence is not evidence of change.
    fingerprint: Option<&'a str>,
    reissue_events: u64,
}

/// What the monitoring loop saw.
struct Observation {
    endpoint_change_detected: bool,
    traversal_reissue_triggered: bool,
    peer_received_updated_endpoint_hint: bool,
    route_leak_samples: u32,
    signed_state_invalid_samples: u32,
    /// Unix seconds at which the client was seen fully re-converged, or `None`
    /// if it never was within the window.
    reconnect_unix: Option<u64>,
    transcript: String,
}

impl Observation {
    /// Seconds from the switch to re-convergence, or `None` if it never
    /// happened. A negative result is possible only under a clock that moved
    /// backwards; it is returned as-is so the SLO comparison rejects it rather
    /// than being silently clamped into passing.
    fn reconnect_secs(&self, switch_started_unix: u64) -> Option<i64> {
        self.reconnect_unix.map(|at| {
            i64::try_from(at).unwrap_or(i64::MAX)
                - i64::try_from(switch_started_unix).unwrap_or(i64::MAX)
        })
    }
}

/// Apply the alias switch, then sample the transition once a second until the
/// client has fully re-converged or the window closes.
fn observe_transition(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
    route: &DefaultRoute,
    alias: &RoamAlias,
    before: &Baseline<'_>,
) -> Result<Observation, String> {
    endpoint_switch::apply_alias(client.runner, route, alias)
        .map_err(|err| format!("failed to apply client alias route switch: {err}"))?;

    let mut observed = Observation {
        endpoint_change_detected: false,
        traversal_reissue_triggered: false,
        peer_received_updated_endpoint_hint: false,
        route_leak_samples: 0,
        signed_state_invalid_samples: 0,
        reconnect_unix: None,
        transcript: String::new(),
    };
    let alias_endpoint = alias.wireguard_endpoint();

    for sample in 1..=options.reconnect_slo_secs {
        let sampled_at = unix_now();
        let client_status = status(client.runner)?;
        let client_route = provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        )?;
        let client_netcheck = rustynet_capture_allow_failure(client.runner, &["netcheck"])?;
        let exit_netcheck = rustynet_capture_allow_failure(exit.runner, &["netcheck"])?;
        let client_endpoints =
            capture_root_allow_failure(client.runner, &["wg", "show", "rustynet0", "endpoints"])?;
        let exit_endpoints =
            capture_root_allow_failure(exit.runner, &["wg", "show", "rustynet0", "endpoints"])?;

        let route_ok = route_via_rustynet(&client_route);
        if !route_ok {
            observed.route_leak_samples += 1;
        }
        // Both ends, because a transition that keeps the client's signed state
        // healthy while the exit's degrades is still a transition that broke
        // signed state.
        let signed_ok = super::signed_state_healthy(&client_netcheck)
            && super::signed_state_healthy(&exit_netcheck);
        if !signed_ok {
            observed.signed_state_invalid_samples += 1;
        }

        // Latching: each of these three is set once and never cleared, matching
        // the shell. They are event detections, not states — the fingerprint
        // will settle back to a stable value after the change, and clearing the
        // flag then would erase the very thing being proved.
        if let (Some(was), Some(now)) = (
            before.fingerprint,
            provisioning::extract_netcheck_value(&client_netcheck, FINGERPRINT_FIELD),
        ) && was != now
        {
            observed.endpoint_change_detected = true;
        }
        if netcheck_counter(&client_netcheck, REISSUE_FIELD) > before.reissue_events {
            observed.traversal_reissue_triggered = true;
        }
        // Either end seeing the new endpoint counts: the shell accepted the
        // client's own table as well as the exit's, because the hint travels in
        // both directions and observing it at one end proves it propagated.
        if exit_endpoints.contains(&alias_endpoint) || client_endpoints.contains(&alias_endpoint) {
            observed.peer_received_updated_endpoint_hint = true;
        }

        observed.transcript.push_str(&render_sample(
            sampled_at,
            sample,
            &[
                ("route", &client_route),
                ("status", &client_status),
                ("client_netcheck", &client_netcheck),
                ("exit_netcheck", &exit_netcheck),
                ("client_endpoints", &client_endpoints),
                ("exit_endpoints", &exit_endpoints),
            ],
        ));

        // Full re-convergence: the client names the exit again, is ExitActive,
        // routes through the tunnel, and both ends' signed state is healthy.
        // Anything less is a partial recovery, and stopping on one would let
        // the SLO be met by a client that had not actually finished.
        if super::client_exit_selected(&client_status, &exit.node_id) && route_ok && signed_ok {
            observed.reconnect_unix = Some(sampled_at);
            break;
        }

        lab.sleep(SAMPLE_INTERVAL);
    }
    Ok(observed)
}

/// One monitor-log line, in the shell's `printf` layout: a pipe-delimited
/// record whose multi-line fields are squeezed onto one line so the log stays
/// greppable per sample.
fn render_sample(sampled_at: u64, sample: u32, fields: &[(&str, &String)]) -> String {
    let mut line = format!("{sampled_at}|iter={sample}");
    for (name, value) in fields {
        line.push('|');
        line.push_str(name);
        line.push('=');
        line.push_str(&squeeze(value));
    }
    line.push('\n');
    line
}

/// The shell's `tr -s ' ' | tr '\n' ';'`: collapse runs of spaces, then turn
/// newlines into `;` so one sample is one line.
///
/// Shared with [`failback_roaming`](super::failback_roaming), whose monitor log
/// uses the same layout — one greppable line per sample.
pub(super) fn squeeze(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut last_was_space = false;
    for ch in value.chars() {
        match ch {
            '\n' => {
                out.push(';');
                last_was_space = false;
            }
            ' ' => {
                if !last_was_space {
                    out.push(' ');
                }
                last_was_space = true;
            }
            other => {
                out.push(other);
                last_was_space = false;
            }
        }
    }
    out
}

/// The monitor summary artifact.
///
/// Field names, types and nesting are the shell's exactly, including
/// `reconnect_unix` being `null` rather than `0` when no reconnect was
/// observed and `reconnect_secs` being `-1` in the same case — the two spell
/// "did not happen" differently and a consumer may read either.
fn render_summary(
    switch_started_unix: u64,
    alias: &RoamAlias,
    observed: &Observation,
    reconnect_secs: Option<i64>,
    options: NodeNetworkSwitchOptions,
    checks: &Checks,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "switch_started_unix": switch_started_unix,
        "alias_ip": alias.ip,
        "reconnect_unix": observed.reconnect_unix,
        "reconnect_secs": reconnect_secs.unwrap_or(NO_RECONNECT_SECS),
        "reconnect_slo_secs": options.reconnect_slo_secs,
        "route_leak_samples": observed.route_leak_samples,
        "signed_state_invalid_samples": observed.signed_state_invalid_samples,
        "checks": {
            "endpoint_change_detected": checks.verdict("endpoint_change_detected").as_str(),
            "traversal_reissue_triggered": checks.verdict("traversal_reissue_triggered").as_str(),
            "peer_received_updated_endpoint_hint":
                checks.verdict("peer_received_updated_endpoint_hint").as_str(),
        },
    });
    serde_json::to_string_pretty(&payload)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|err| format!("failed to render node network-switch summary: {err}"))
}

/// The artifact paths this scenario declares, for the stage and for tests.
pub fn artifact_paths(artifact_dir: &Path) -> [std::path::PathBuf; 4] {
    [
        artifact_dir.join(BASELINE_REPORT_FILE),
        artifact_dir.join(BASELINE_LOG_FILE),
        artifact_dir.join(MONITOR_LOG_FILE),
        artifact_dir.join(MONITOR_SUMMARY_FILE),
    ]
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::super::provisioning::{LabContext, TimeScale};
    use std::path::PathBuf;

    /// A [`LabContext`] with collapsed waits, for scenario unit tests. Attempt
    /// counts and loop bounds are unchanged; only the sleeps are zero-length.
    pub fn lab(artifact_dir: &str) -> LabContext {
        LabContext {
            ssh_identity_file: PathBuf::from("/home/op/.ssh/id"),
            ssh_allow_cidrs: "192.168.18.0/24".to_owned(),
            artifact_dir: PathBuf::from(artifact_dir),
            client_ssh_target: "debian@client-host".to_owned(),
            exit_ssh_target: "debian@exit-host".to_owned(),
            relay_ssh_target: Some("debian@relay-host".to_owned()),
            probe_ssh_target: Some("debian@probe-host".to_owned()),
            client_src_dir: "/home/debian/Rustynet".to_owned(),
            exit_src_dir: "/home/debian/Rustynet".to_owned(),
            relay_src_dir: Some("/home/debian/Rustynet".to_owned()),
            client_network_id: "net-client".to_owned(),
            exit_network_id: "net-exit".to_owned(),
            relay_network_id: Some("net-relay".to_owned()),
            time_scale: TimeScale::Collapsed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const ALIAS_IP: &str = "192.168.18.77";
    const EXIT_NODE_ID: &str = "exit-1";

    fn alias() -> RoamAlias {
        RoamAlias {
            ip: ALIAS_IP.to_owned(),
            prefix: 24,
        }
    }

    fn route() -> DefaultRoute {
        DefaultRoute {
            iface: "enp0s1".to_owned(),
            snapshot: "default via 192.168.18.1 dev enp0s1".to_owned(),
        }
    }

    /// A converged client: it names the exit, is `ExitActive`, routes through
    /// the tunnel, its endpoint fingerprint has moved, its re-issue counter has
    /// advanced, and its own endpoint table already shows the alias.
    fn converged_client() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!("exit_node={EXIT_NODE_ID} state=ExitActive"),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0 src 10.42.0.2".to_owned(),
                ),
                (
                    "rustynet netcheck".to_owned(),
                    "traversal_error=none traversal_endpoint_fingerprint=after \
                     traversal_preexpiry_refresh_events=4"
                        .to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{ALIAS_IP}:51820"),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn healthy_exit() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet netcheck".to_owned(),
                    "traversal_error=none".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{ALIAS_IP}:51820"),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn before() -> Baseline<'static> {
        Baseline {
            fingerprint: Some("before"),
            reissue_events: 3,
        }
    }

    fn observe(
        client: &MockLeafRunner,
        exit: &MockLeafRunner,
        options: NodeNetworkSwitchOptions,
        baseline: &Baseline<'_>,
    ) -> Result<Observation, String> {
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(client, "client-1", "192.168.18.40");
        let exit_node = ScenarioNode::new(exit, EXIT_NODE_ID, "192.168.19.40");
        observe_transition(
            &client_node,
            &exit_node,
            &lab,
            options,
            &route(),
            &alias(),
            baseline,
        )
    }

    #[test]
    fn a_converged_client_stops_sampling_on_the_first_clean_sample() {
        let client = converged_client();
        let exit = healthy_exit();
        let observed = observe(
            &client,
            &exit,
            NodeNetworkSwitchOptions::default(),
            &before(),
        )
        .expect("observe");

        assert!(observed.endpoint_change_detected);
        assert!(observed.traversal_reissue_triggered);
        assert!(observed.peer_received_updated_endpoint_hint);
        assert_eq!(observed.route_leak_samples, 0);
        assert_eq!(observed.signed_state_invalid_samples, 0);
        assert!(observed.reconnect_unix.is_some());
        assert_eq!(
            observed.transcript.lines().count(),
            1,
            "one sample was enough; sampling on must not continue past convergence"
        );
    }

    #[test]
    fn a_client_that_never_reconverges_runs_the_whole_window_and_reports_no_reconnect() {
        // Nothing scripted: no exit selected, no route through the tunnel, no
        // healthy signed state.
        let client = MockLeafRunner::default();
        let exit = MockLeafRunner::default();
        let options = NodeNetworkSwitchOptions::new(3).expect("positive slo");
        let observed = observe(&client, &exit, options, &before()).expect("observe");

        assert!(observed.reconnect_unix.is_none());
        assert_eq!(observed.reconnect_secs(1000), None);
        assert_eq!(
            observed.transcript.lines().count(),
            3,
            "one line per sample"
        );
        // Every sample leaked and every sample had unhealthy signed state, so
        // both sampled checks must be able to fail.
        assert_eq!(observed.route_leak_samples, 3);
        assert_eq!(observed.signed_state_invalid_samples, 3);
    }

    #[test]
    fn a_single_leaking_sample_is_enough_to_fail_the_transition() {
        // The client converges on the second sample, but the first one routed
        // in the clear. That window is exactly what this scenario exists to
        // inspect, so the leak must survive the later recovery.
        let client = MockLeafRunner {
            stdout_for: vec![(
                // The first sample's `route get`. `apply_alias` runs three
                // calls first — `ip addr show`, `ip addr add`, `ip route
                // replace` — then the sample opens with `rustynet status`.
                4,
                "1.1.1.1 via 192.168.18.1 dev enp0s1".to_owned(),
            )],
            ..converged_client()
        };
        let exit = healthy_exit();
        let observed = observe(
            &client,
            &exit,
            NodeNetworkSwitchOptions::default(),
            &before(),
        )
        .expect("observe");

        assert_eq!(observed.route_leak_samples, 1);
        assert!(
            observed.reconnect_unix.is_some(),
            "it did eventually reconverge"
        );
    }

    #[test]
    fn an_absent_baseline_fingerprint_can_never_detect_a_change() {
        // The shell required BOTH the before and after values to be non-empty.
        // Absence is not evidence of change, and treating it as such would let
        // a daemon that reports no fingerprint at all pass this check.
        let client = converged_client();
        let exit = healthy_exit();
        let observed = observe(
            &client,
            &exit,
            NodeNetworkSwitchOptions::default(),
            &Baseline {
                fingerprint: None,
                reissue_events: 3,
            },
        )
        .expect("observe");
        assert!(!observed.endpoint_change_detected);
    }

    #[test]
    fn an_unchanged_reissue_counter_does_not_trigger_the_reissue_check() {
        let client = converged_client();
        let exit = healthy_exit();
        let observed = observe(
            &client,
            &exit,
            NodeNetworkSwitchOptions::default(),
            &Baseline {
                fingerprint: Some("before"),
                // The client reports 4; a baseline already at 4 is no advance.
                reissue_events: 4,
            },
        )
        .expect("observe");
        assert!(!observed.traversal_reissue_triggered);
    }

    #[test]
    fn a_zero_slo_is_rejected_rather_than_running_zero_samples() {
        // Zero samples would pass every sampled check vacuously, reporting a
        // clean transition the scenario never observed.
        assert!(NodeNetworkSwitchOptions::new(0).is_err());
        assert_eq!(
            NodeNetworkSwitchOptions::default().reconnect_slo_secs(),
            DEFAULT_RECONNECT_SLO_SECS
        );
    }

    #[test]
    fn the_aggregate_covers_every_other_check_in_the_report() {
        // The shell's nine-clause `&&`. A check that is emitted but not
        // aggregated is a check that cannot fail the scenario.
        let mut expected: Vec<&str> = CHECKS
            .iter()
            .copied()
            .filter(|name| *name != "node_network_switch_success")
            .collect();
        let mut actual = AGGREGATE_CHECKS.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn the_failure_summary_names_the_first_thing_that_did_not_happen() {
        let options = NodeNetworkSwitchOptions::default();
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        assert_eq!(
            failure_summary(&checks, options, None),
            "endpoint-change detection did not trigger during node underlay switch"
        );

        checks.record_bool("endpoint_change_detected", true);
        assert_eq!(
            failure_summary(&checks, options, None),
            "traversal re-issue did not trigger during node underlay switch"
        );

        checks.record_bool("traversal_reissue_triggered", true);
        checks.record_bool("peer_received_updated_endpoint_hint", true);
        assert_eq!(
            failure_summary(&checks, options, None),
            "session reconvergence exceeded reconnect SLO (30s), measured=-1s",
            "a reconnect that never happened is reported as the shell's -1 sentinel"
        );

        checks.record_bool("session_reconnect_within_slo", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "underlay leak detected during node underlay switch transition"
        );

        checks.record_bool("no_underlay_leak_during_transition", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "signed state became invalid during node underlay switch transition"
        );

        checks.record_bool("signed_state_valid_during_transition", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "plaintext passphrase files detected during node network-switch validation"
        );

        checks.record_bool("no_plaintext_passphrase_files", true);
        // Everything this chain names has passed, so only the two checks it
        // never mentions — readiness and topology — can still be failing.
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "node network-switch validation checks did not all pass"
        );
    }

    #[test]
    fn a_multi_line_capture_becomes_one_greppable_monitor_line() {
        assert_eq!(squeeze("a   b\nc  d"), "a b;c d");
        let rendered = render_sample(1700, 2, &[("route", &"a\nb".to_owned())]);
        assert_eq!(rendered, "1700|iter=2|route=a;b\n");
    }

    #[test]
    fn the_summary_spells_a_missing_reconnect_as_null_and_minus_one() {
        // The two fields say "did not happen" differently and a consumer may
        // read either, so both spellings are part of the artifact's contract.
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        let observed = Observation {
            endpoint_change_detected: false,
            traversal_reissue_triggered: false,
            peer_received_updated_endpoint_hint: false,
            route_leak_samples: 2,
            signed_state_invalid_samples: 1,
            reconnect_unix: None,
            transcript: String::new(),
        };
        let rendered = render_summary(
            1700,
            &alias(),
            &observed,
            None,
            NodeNetworkSwitchOptions::default(),
            &checks,
        )
        .expect("render summary");
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("summary is valid JSON");
        assert!(parsed["reconnect_unix"].is_null());
        assert_eq!(parsed["reconnect_secs"], -1);
        assert_eq!(parsed["reconnect_slo_secs"], 30);
        assert_eq!(parsed["alias_ip"], ALIAS_IP);
        assert_eq!(parsed["route_leak_samples"], 2);
        assert_eq!(parsed["checks"]["endpoint_change_detected"], "fail");
    }
}
