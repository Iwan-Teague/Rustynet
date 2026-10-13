//! `cross_network_node_network_switch`, ported from
//! `scripts/e2e/live_linux_cross_network_node_network_switch_test.sh` (631 ln)
//! and redesigned (node-switch fix, owner decision 2026-10-09) around a real
//! source change and the counters the daemon actually increments.
//!
//! # What this proves
//!
//! That a client whose underlay address changes under a live tunnel
//!
//! 1. really has a new source address in use for the WireGuard flow (the lab
//!    stimulus took effect; see [`endpoint_switch`](super::endpoint_switch));
//! 2. is noticed by its daemon - the endpoint fingerprint moves and
//!    `traversal_endpoint_change_events` advances, bounded (no refresh storm);
//! 3. advertises the new address: the gossip bundle the client last minted
//!    lists it, and the exit has applied a bundle that lists it
//!    (`gossip_hints` in `netcheck`);
//! 4. re-converges within a reconnect SLO - **without** leaking around the
//!    tunnel or degrading its signed state at any point in between;
//! 5. and that the stimulus is fully undone: the guest is clean when read back
//!    and the daemon's fingerprint returns to its pre-switch value.
//!
//! Point 4's last clause is what makes this different from a reconnect test,
//! and it is why the evidence is a *sampled series* rather than a before/after
//! pair. `no_underlay_leak_during_transition` and
//! `signed_state_valid_during_transition` pass only when **every** sample
//! during the transition was clean; a scenario that looked only at the endpoint
//! state would accept a client that briefly routed in the clear while its
//! tunnel was down, which is precisely the window this scenario exists to
//! inspect. A transition with ZERO samples is not clean, it is unobserved, so
//! those two checks also require at least one sample.
//!
//! # What changed from the first port, and why
//!
//! * **The stimulus** was `ip route replace default dev <if> src <alias>`,
//!   which neither moved the gateway the daemon fingerprints nor changed the
//!   source of the WireGuard flow (the daemon's `ip rule 10000 lookup 51820`
//!   pin has no `src`). It is now a source pin - see the `endpoint_switch`
//!   module docs. Evidence: katana-xnet-148/150.
//! * **`traversal_reissue_triggered`** read `traversal_preexpiry_refresh_events`,
//!   the timer-driven pre-expiry counter, which an endpoint change never
//!   increments. It now reads `traversal_endpoint_change_events`, bounded above
//!   so a refresh storm fails instead of passing.
//! * **`peer_received_updated_endpoint_hint`** looked for `alias:51820` in the
//!   peers' WireGuard endpoint tables. That cannot be satisfied on the
//!   userspace-shared backend (`supports_roaming: false`; the engine never
//!   learns an endpoint from a received packet) and never was on any backend
//!   (the old stimulus never changed the source). It now asks the question its
//!   name asks: did the exit APPLY a signed hint that lists the new address.
//!   The WireGuard-level observation is still recorded in every sample and in
//!   the summary (`exit_wg_endpoint_saw_alias`), just not gating.
//! * **Missing evidence is a failure, not a zero.** A daemon that does not
//!   report the counter, the fingerprint or `gossip_hints` fails the stage by
//!   field name, so running against a binary that predates the fix cannot pass.
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
//! need one. The original field names and types are unchanged; the new
//! evidence is additive.

use std::path::Path;

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::{
    self, AppliedPin, RollbackReport, SAMPLE_INTERVAL, SOURCE_PIN_RULE_PRIORITY, SOURCE_PIN_TABLE,
    SourcePin, unix_now,
};
use super::host::ScenarioHost;
use super::provisioning::{self, LabContext, during};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, capture_peer_endpoints,
    no_plaintext_passphrase_check, route_via_rustynet, rustynet_capture_allow_failure, status,
    wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_node_network_switch";

/// The report's check names. The first nine keep the shell's relative order;
/// the four added by the node-switch fix sit next to the evidence they gate.
pub const CHECKS: &[&str] = &[
    "node_network_switch_success",
    "direct_remote_exit_ready",
    "stimulus_took_effect",
    "endpoint_change_detected",
    "traversal_reissue_triggered",
    "advertised_hint_carries_new_address",
    "session_reconnect_within_slo",
    "peer_received_updated_endpoint_hint",
    "no_underlay_leak_during_transition",
    "signed_state_valid_during_transition",
    "stimulus_rolled_back",
    "cross_network_topology_heuristic",
    "no_plaintext_passphrase_files",
];

/// The checks `node_network_switch_success` aggregates — every other check in
/// [`CHECKS`]. Named once so the aggregate cannot drift from the list.
const AGGREGATE_CHECKS: &[&str] = &[
    "direct_remote_exit_ready",
    "stimulus_took_effect",
    "endpoint_change_detected",
    "traversal_reissue_triggered",
    "advertised_hint_carries_new_address",
    "session_reconnect_within_slo",
    "peer_received_updated_endpoint_hint",
    "no_underlay_leak_during_transition",
    "signed_state_valid_during_transition",
    "stimulus_rolled_back",
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
/// The monotonic counter the daemon's endpoint-change refresh increments.
/// (Not `traversal_preexpiry_refresh_events`: that is the pre-expiry timer's.)
const ENDPOINT_EVENTS_FIELD: &str = "traversal_endpoint_change_events";
/// The `netcheck` field listing the candidates this node last minted into its
/// gossip bundle (`self/…`) and the candidates last applied from each peer.
const HINTS_FIELD: &str = "gossip_hints";
/// The label of the node's own entry in [`HINTS_FIELD`].
const SELF_HINTS_LABEL: &str = "self";

/// Most endpoint-change events one clean address switch may produce. The daemon
/// limits itself to one refresh per 10 s and a single address add is one change,
/// so the expected delta is exactly 1; one extra is tolerated for a coincident
/// guest-side address event. More means the limiter or the address-set
/// normalisation failed - a storm, which must fail rather than pass.
const MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH: u64 = 2;

/// Samples to keep watching after the first endpoint-change event, once every
/// other latch is satisfied, so a storm that starts a moment later is seen. One
/// daemon limiter window (10 s) plus margin at one sample per second.
const STORM_WATCH_SAMPLES: u32 = 12;

/// Baseline reads (1 s apart) allowed for the client's endpoint state to go
/// quiet before the switch. A baseline that is still moving cannot be a
/// baseline.
const BASELINE_QUIESCENCE_ATTEMPTS: u32 = 15;

/// Polls (1 s apart) for the fingerprint to return to its pre-switch value
/// after rollback. The daemon's limiter may defer the removal event by up to
/// 10 s after the add event, so the wait is longer than that.
const RESTORE_WAIT_ATTEMPTS: u32 = 25;

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

    switch_after_baseline(host, inputs, lab, options, checks)
}

/// Everything after the composed direct baseline: plan the switch, take the
/// pre-switch baseline, apply / observe / roll back, record the checks and write
/// the artifacts. Split from [`execute`] so the whole flow, not just its parts,
/// is exercised by unit tests against scripted guests, without having to
/// script the entire direct-remote-exit baseline.
fn switch_after_baseline(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
    checks: &mut Checks,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;

    // ── prepare the switch (read-only until `run_switch`) ──
    let phase = "initializing runtime for node underlay switch validation";
    during(phase, wait_for_daemon_socket(exit.runner))?;
    during(phase, wait_for_daemon_socket(client.runner))?;

    // Every address already in play must be avoided, the optional relay's
    // included: an alias that landed on a third node would make the hint
    // checks attribute that node's bundle to the client.
    let mut used: Vec<&str> = vec![client.address.as_str(), exit.address.as_str()];
    if let Some(relay) = inputs.relay.as_ref() {
        used.push(relay.address.as_str());
    }
    let alias = during(phase, endpoint_switch::choose_alias(&client.address, &used))?;
    let pin = during(
        phase,
        endpoint_switch::plan_source_pin(client.runner, &exit.address, alias),
    )?;
    // The pin moves the source of traffic to the exit's UNDERLAY address. That
    // only moves the tunnel if the tunnel actually dials that address; in a
    // topology where it does not (a NAT-shaped overlay endpoint, say) the
    // stimulus would be "effective" at the kernel and vacuous for WireGuard.
    let client_endpoints = during(phase, capture_peer_endpoints(client.runner))?;
    if !client_endpoints.contains(&exit.wireguard_endpoint()) {
        return Err(format!(
            "{phase}: the client's WireGuard peer endpoints ({}) do not include the exit's \
             underlay endpoint {}; a source pin on that address would not move the tunnel's \
             source",
            client_endpoints.replace('\n', ","),
            exit.wireguard_endpoint()
        ));
    }

    let client_plaintext_start = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let exit_plaintext_start = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    // The pre-switch values every later observation is measured against. Taken
    // twice and required to agree: a counter or fingerprint that is still
    // moving would let an unrelated event be credited to the switch.
    let before = during(phase, read_baseline(client, exit, lab, &pin.alias.ip))?;

    // ── switch, observe, and ALWAYS roll back ──
    let phase = "applying client underlay source pin and observing the switch";
    let switch_started_unix = unix_now();
    let switched = run_switch(client, exit, lab, options, &pin, &before);
    // The rollback has already run, on every path including the failure ones.
    // An observation error is reported together with an incomplete rollback so
    // the operator sees the residue, not just the first error.
    let observed = match switched.observed {
        Ok(observed) => observed,
        Err(err) => {
            // Even when the observation itself failed, say whether the guest
            // was left clean: it is the first thing the operator needs to know
            // and the next stage's problem if it was not.
            checks.record_bool(
                "stimulus_rolled_back",
                switched.rollback.complete() && switched.restore.restored,
            );
            let mut message = format!("{phase}: {err}");
            if !switched.rollback.complete() {
                message.push_str(&format!(
                    "; ROLLBACK INCOMPLETE ({})",
                    switched.rollback.describe()
                ));
            }
            return Err(message);
        }
    };

    let phase = "recording node network-switch evidence";
    let reconnect_secs = observed.reconnect_secs(switch_started_unix);
    record_switch_checks(
        checks,
        &observed,
        &switched.rollback,
        &switched.restore,
        reconnect_secs,
        options,
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
            &render_summary(&SummaryInputs {
                switch_started_unix,
                pin: &pin,
                observed: &observed,
                before: &before,
                restore: &switched.restore,
                rollback: &switched.rollback,
                reconnect_secs,
                options,
                checks,
            })?,
        ),
    )?;

    checks.record_bool(
        "node_network_switch_success",
        checks.all_passed(AGGREGATE_CHECKS),
    );
    if checks.passed("node_network_switch_success") {
        return Ok(());
    }
    Err(failure_summary(
        checks,
        options,
        reconnect_secs,
        observed.max_event_delta,
    ))
}

/// Record every check that depends on the switch's observation.
///
/// A pure function of what was observed (no I/O), so each condition is
/// unit-tested on its own: every check here has a test that flips exactly the
/// one observation it depends on.
fn record_switch_checks(
    checks: &mut Checks,
    observed: &Observation,
    rollback: &RollbackReport,
    restore: &Restore,
    reconnect_secs: Option<i64>,
    options: NodeNetworkSwitchOptions,
) {
    // Zero samples is "unobserved", not "clean" (see the module docs).
    let samples_taken = observed.samples_taken > 0;
    checks.record_bool(
        "stimulus_took_effect",
        observed.stimulus_effective && observed.pin_alias_samples >= 1,
    );
    checks.record_bool(
        "endpoint_change_detected",
        observed.endpoint_change_detected,
    );
    // At least one event (the daemon's refresh ran) and no more than the bound
    // (the limiter and the address-set normalisation held).
    checks.record_bool(
        "traversal_reissue_triggered",
        observed.first_event_seen
            && observed.max_event_delta <= MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH,
    );
    checks.record_bool(
        "advertised_hint_carries_new_address",
        observed.alias_in_self_hints,
    );
    checks.record_bool(
        "peer_received_updated_endpoint_hint",
        observed.alias_in_peer_hints,
    );
    checks.record_bool(
        "no_underlay_leak_during_transition",
        samples_taken && observed.route_leak_samples == 0,
    );
    checks.record_bool(
        "signed_state_valid_during_transition",
        samples_taken && observed.signed_state_invalid_samples == 0,
    );
    checks.record_bool(
        "stimulus_rolled_back",
        rollback.complete() && restore.restored,
    );
    // A negative measurement (a wall clock that stepped backwards) is not a
    // reconnect time; `Observation::reconnect_secs` hands it back unclamped
    // precisely so that it is rejected here rather than read as "instant".
    checks.record_bool(
        "session_reconnect_within_slo",
        matches!(reconnect_secs, Some(secs) if (0..=i64::from(options.reconnect_slo_secs)).contains(&secs)),
    );
}

/// The "first thing that did not happen" chain. The order is the diagnosis:
/// residue first (it poisons the next stage), then whether the stimulus did
/// anything at all (nothing else is attributable to it if not), then detection,
/// the refresh, the advertised hint, the peer's copy, and finally the
/// continuity checks.
fn failure_summary(
    checks: &Checks,
    options: NodeNetworkSwitchOptions,
    reconnect_secs: Option<i64>,
    max_event_delta: u64,
) -> String {
    if !checks.passed("stimulus_rolled_back") {
        return "node underlay switch stimulus was not cleanly rolled back (lab residue on the \
                client, or the daemon's endpoint fingerprint did not return to its pre-switch \
                value)"
            .to_owned();
    }
    if !checks.passed("stimulus_took_effect") {
        return "node underlay switch stimulus did not move the WireGuard source address \
                (lab stimulus ineffective)"
            .to_owned();
    }
    if !checks.passed("endpoint_change_detected") {
        return "endpoint-change detection did not trigger during node underlay switch".to_owned();
    }
    if !checks.passed("traversal_reissue_triggered") {
        if max_event_delta > MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH {
            return format!(
                "endpoint-change refresh storm during node underlay switch \
                 ({ENDPOINT_EVENTS_FIELD} advanced by {max_event_delta}, limit \
                 {MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH})"
            );
        }
        return format!(
            "endpoint-change refresh did not run during node underlay switch \
             ({ENDPOINT_EVENTS_FIELD} did not advance)"
        );
    }
    if !checks.passed("advertised_hint_carries_new_address") {
        return "refreshed gossip hint did not carry the new underlay address after node \
                underlay switch"
            .to_owned();
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

// ───────────────────────────── netcheck parsing ─────────────────────────────

/// A counter that MUST be present: a missing or non-numeric field is an error
/// naming the field, never a silent 0 (which would let a daemon that does not
/// report the counter look like one that reported "no events").
fn required_counter(netcheck: &str, key: &str) -> Result<u64, String> {
    provisioning::extract_netcheck_value(netcheck, key)
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| {
            format!(
                "daemon netcheck does not report a numeric {key} (daemon older than the \
                 node-switch fix?)"
            )
        })
}

/// The `gossip_hints=` value as `(label, candidate tokens)` entries.
///
/// An error when the field is absent (a daemon without it) or `none` (gossip
/// not configured on that node): in both cases the hint checks could never
/// pass, and saying so up front beats a late "hint did not arrive".
fn gossip_hint_entries(netcheck: &str) -> Result<Vec<(String, Vec<String>)>, String> {
    let value = provisioning::extract_netcheck_value(netcheck, HINTS_FIELD).ok_or_else(|| {
        format!(
            "daemon netcheck does not report {HINTS_FIELD} (daemon older than the node-switch \
             fix?)"
        )
    })?;
    if value == "none" {
        return Err(format!(
            "{HINTS_FIELD}=none: gossip is not configured on this node, so hint propagation \
             cannot be proven"
        ));
    }
    Ok(value
        .split('+')
        .filter_map(|entry| {
            let (label, list) = entry.split_once('/')?;
            let tokens = if list == "none" {
                Vec::new()
            } else {
                list.split(',').map(str::to_owned).collect()
            };
            Some((label.to_owned(), tokens))
        })
        .collect())
}

/// True when `token` (a bare IP, or `ip:port` for a reflexive candidate) is the
/// address `ip`. Exact on the IP part: `192.168.1.25` is not `192.168.1.254`.
fn token_is_address(token: &str, ip: &str) -> bool {
    token == ip
        || token
            .strip_prefix(ip)
            .is_some_and(|rest| rest.starts_with(':'))
}

/// The node's OWN last-minted bundle lists `ip`.
fn self_hints_mention(entries: &[(String, Vec<String>)], ip: &str) -> bool {
    entries
        .iter()
        .filter(|(label, _)| label == SELF_HINTS_LABEL)
        .flat_map(|(_, tokens)| tokens.iter())
        .any(|token| token_is_address(token, ip))
}

/// A PEER's applied bundle (any entry other than `self`) lists `ip`.
fn peer_hints_mention(entries: &[(String, Vec<String>)], ip: &str) -> bool {
    entries
        .iter()
        .filter(|(label, _)| label != SELF_HINTS_LABEL)
        .flat_map(|(_, tokens)| tokens.iter())
        .any(|token| token_is_address(token, ip))
}

// ───────────────────────────── baseline ─────────────────────────────

/// The pre-switch values a change is measured against.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Baseline {
    /// The client's endpoint fingerprint. Always a real value: a daemon that
    /// reports `none` (not yet seeded) is waited on, and one that never
    /// reports a fingerprint fails the stage - absence is not evidence.
    fingerprint: String,
    /// `traversal_endpoint_change_events` on the client.
    endpoint_events: u64,
}

/// Read the client's endpoint state until two reads (one sample apart) agree,
/// then verify the alias is advertised by nobody yet.
///
/// The "advertised by nobody yet" requirement makes the two hint checks
/// meaningful: an alias already present in a bundle (residue, or a collision
/// with another node's address) would let them pass without the switch.
fn read_baseline(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    alias_ip: &str,
) -> Result<Baseline, String> {
    let mut previous: Option<(String, u64)> = None;
    let mut last_problem = String::from("no baseline read completed");
    for attempt in 1..=BASELINE_QUIESCENCE_ATTEMPTS {
        let client_netcheck = rustynet_capture_allow_failure(client.runner, &["netcheck"])?;
        let fingerprint = provisioning::extract_netcheck_value(&client_netcheck, FINGERPRINT_FIELD)
            .ok_or_else(|| {
                format!(
                    "daemon netcheck does not report {FINGERPRINT_FIELD} (daemon older than \
                     the node-switch fix?)"
                )
            })?;
        let events = required_counter(&client_netcheck, ENDPOINT_EVENTS_FIELD)?;
        if fingerprint == "none" {
            // Not seeded yet (the daemon seeds on its first trigger). Wait.
            last_problem = format!("the daemon has not reported an {FINGERPRINT_FIELD} yet");
        } else {
            let current = (fingerprint, events);
            if previous.as_ref() == Some(&current) {
                let client_entries = gossip_hint_entries(&client_netcheck)?;
                if self_hints_mention(&client_entries, alias_ip) {
                    return Err(format!(
                        "roam alias {alias_ip} is already in the client's minted gossip bundle \
                         before the switch; the hint checks would be vacuous"
                    ));
                }
                let exit_netcheck = rustynet_capture_allow_failure(exit.runner, &["netcheck"])?;
                let exit_entries = gossip_hint_entries(&exit_netcheck)?;
                if peer_hints_mention(&exit_entries, alias_ip) {
                    return Err(format!(
                        "roam alias {alias_ip} is already in a bundle applied by the exit before \
                         the switch; the hint checks would be vacuous"
                    ));
                }
                return Ok(Baseline {
                    fingerprint: current.0,
                    endpoint_events: current.1,
                });
            }
            last_problem = format!(
                "{FINGERPRINT_FIELD}/{ENDPOINT_EVENTS_FIELD} changed between consecutive reads"
            );
            previous = Some(current);
        }
        if attempt < BASELINE_QUIESCENCE_ATTEMPTS {
            lab.sleep(SAMPLE_INTERVAL);
        }
    }
    Err(format!(
        "baseline endpoint state not quiescent after {BASELINE_QUIESCENCE_ATTEMPTS} reads: \
         {last_problem}"
    ))
}

// ───────────────────────────── the switch ─────────────────────────────

/// What the monitoring loop saw.
struct Observation {
    /// The kernel selected the alias as the source of the WireGuard flow right
    /// after the pin was applied. False means the lab stimulus did nothing.
    stimulus_effective: bool,
    /// Samples in which the kernel still selected the alias.
    pin_alias_samples: u32,
    /// Samples actually taken. Zero means the transition went unobserved.
    samples_taken: u32,
    /// The client's fingerprint differed from the baseline in some sample.
    endpoint_change_detected: bool,
    /// `traversal_endpoint_change_events` advanced at least once.
    first_event_seen: bool,
    /// Largest `traversal_endpoint_change_events` advance over the baseline.
    max_event_delta: u64,
    /// The client's last-minted gossip bundle listed the alias.
    alias_in_self_hints: bool,
    /// The exit had applied a peer bundle listing the alias.
    alias_in_peer_hints: bool,
    /// Informational, NOT gating: the exit's WireGuard endpoint table showed
    /// `alias:51820` (see the module docs on why it cannot gate).
    exit_wg_endpoint_saw_alias: bool,
    route_leak_samples: u32,
    signed_state_invalid_samples: u32,
    /// Unix seconds at which the client was seen fully re-converged, or `None`
    /// if it never was within the window.
    reconnect_unix: Option<u64>,
    transcript: String,
}

impl Observation {
    fn new() -> Self {
        Self {
            stimulus_effective: false,
            pin_alias_samples: 0,
            samples_taken: 0,
            endpoint_change_detected: false,
            first_event_seen: false,
            max_event_delta: 0,
            alias_in_self_hints: false,
            alias_in_peer_hints: false,
            exit_wg_endpoint_saw_alias: false,
            route_leak_samples: 0,
            signed_state_invalid_samples: 0,
            reconnect_unix: None,
            transcript: String::new(),
        }
    }

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

/// Whether the client's fingerprint came back to its pre-switch value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Restore {
    restored: bool,
    last_fingerprint: Option<String>,
}

/// Everything the switch produced. The rollback and the restore wait have
/// ALREADY happened by the time this exists, whatever `observed` holds.
struct SwitchRun {
    observed: Result<Observation, String>,
    rollback: RollbackReport,
    restore: Restore,
}

/// Apply the pin, observe the transition, roll back, verify the rollback and
/// wait for the fingerprint to return. The rollback runs after the observation
/// whether it succeeded, errored, or stopped early because the stimulus was
/// ineffective; it removes exactly what was applied (see
/// [`endpoint_switch::rollback_source_pin`]).
fn run_switch(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
    pin: &SourcePin,
    before: &Baseline,
) -> SwitchRun {
    let mut applied = AppliedPin::default();
    let observed = observe_transition(client, exit, lab, options, pin, before, &mut applied);
    let rollback = endpoint_switch::rollback_source_pin(client.runner, pin, applied);
    // Waiting for the fingerprint only makes sense once the guest is clean.
    let restore = if rollback.complete() {
        wait_for_restored_fingerprint(client, lab, &before.fingerprint)
    } else {
        Restore {
            restored: false,
            last_fingerprint: None,
        }
    };
    SwitchRun {
        observed,
        rollback,
        restore,
    }
}

/// Poll the client's `netcheck` until its fingerprint equals `expected`.
fn wait_for_restored_fingerprint(
    client: &ScenarioNode<'_>,
    lab: &LabContext,
    expected: &str,
) -> Restore {
    let mut last_fingerprint = None;
    for attempt in 1..=RESTORE_WAIT_ATTEMPTS {
        if let Ok(netcheck) = rustynet_capture_allow_failure(client.runner, &["netcheck"]) {
            last_fingerprint = provisioning::extract_netcheck_value(&netcheck, FINGERPRINT_FIELD);
            if last_fingerprint.as_deref() == Some(expected) {
                return Restore {
                    restored: true,
                    last_fingerprint,
                };
            }
        }
        if attempt < RESTORE_WAIT_ATTEMPTS {
            lab.sleep(SAMPLE_INTERVAL);
        }
    }
    Restore {
        restored: false,
        last_fingerprint,
    }
}

/// Apply the source pin, then sample the transition once a second.
///
/// Sampling ends when the client has fully re-converged AND every detection
/// latch (fingerprint moved, endpoint-change refresh ran, the alias is in the
/// client's minted bundle and in the exit's applied bundle) has been seen AND
/// the storm watch has run its course, or when the window (the reconnect SLO,
/// in samples) closes. The time of the first full re-convergence is latched
/// separately and is what the SLO measures.
fn observe_transition(
    client: &ScenarioNode<'_>,
    exit: &ScenarioNode<'_>,
    lab: &LabContext,
    options: NodeNetworkSwitchOptions,
    pin: &SourcePin,
    before: &Baseline,
    applied: &mut AppliedPin,
) -> Result<Observation, String> {
    let (applied_now, apply_result) = endpoint_switch::apply_source_pin(client.runner, pin);
    // Recorded BEFORE the result is inspected: a half-applied pin must still be
    // rolled back.
    *applied = applied_now;
    apply_result.map_err(|err| format!("failed to apply the node underlay switch: {err}"))?;

    let mut observed = Observation::new();

    // The stimulus must be effective before anything else is attributed to it:
    // ask the kernel which source the WireGuard flow to the exit now uses.
    let selected = endpoint_switch::selected_source(client.runner, pin)?;
    observed.stimulus_effective = selected == Some(pin.alias_ip);
    if !observed.stimulus_effective {
        observed.transcript.push_str(&format!(
            "{}|stimulus_ineffective|selected_src={}|expected_src={}\n",
            unix_now(),
            selected.map_or_else(|| "none".to_owned(), |ip| ip.to_string()),
            pin.alias_ip
        ));
        return Ok(observed);
    }

    let alias_endpoint = pin.alias.wireguard_endpoint();
    // The sample on which the first endpoint-change event was seen; the storm
    // watch runs for `STORM_WATCH_SAMPLES` samples after it.
    let mut first_event_sample: Option<u32> = None;

    for sample in 1..=options.reconnect_slo_secs {
        let sampled_at = unix_now();
        let client_status = status(client.runner)?;
        let client_route = provisioning::capture_allow_failure(
            client.runner,
            &["ip", "-4", "route", "get", "1.1.1.1"],
        )?;
        let pin_route = endpoint_switch::read_flow_route_text(client.runner, pin.peer)?;
        let client_netcheck = rustynet_capture_allow_failure(client.runner, &["netcheck"])?;
        let exit_netcheck = rustynet_capture_allow_failure(exit.runner, &["netcheck"])?;
        // Informational only (see the module docs): a missing endpoint table
        // must not abort the observation the way it used to.
        let client_endpoints = capture_peer_endpoints(client.runner)
            .unwrap_or_else(|err| format!("unavailable: {err}"));
        let exit_endpoints =
            capture_peer_endpoints(exit.runner).unwrap_or_else(|err| format!("unavailable: {err}"));
        observed.samples_taken += 1;

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
        if endpoint_switch::parse_route_get(&pin_route, pin.peer)
            .and_then(|path| path.src)
            .is_some_and(|src| src == pin.alias_ip)
        {
            observed.pin_alias_samples += 1;
        }

        // Latching: each of these is set once and never cleared. They are event
        // detections, not states - the fingerprint settles back to a stable
        // value after the change, and clearing the flag then would erase the
        // very thing being proved.
        if let Some(now) = provisioning::extract_netcheck_value(&client_netcheck, FINGERPRINT_FIELD)
            && now != "none"
            && now != before.fingerprint
        {
            observed.endpoint_change_detected = true;
        }
        if let Ok(events) = required_counter(&client_netcheck, ENDPOINT_EVENTS_FIELD) {
            let delta = events.saturating_sub(before.endpoint_events);
            observed.max_event_delta = observed.max_event_delta.max(delta);
            if delta >= 1 {
                observed.first_event_seen = true;
            }
        }
        if let Ok(entries) = gossip_hint_entries(&client_netcheck)
            && self_hints_mention(&entries, &pin.alias.ip)
        {
            observed.alias_in_self_hints = true;
        }
        if let Ok(entries) = gossip_hint_entries(&exit_netcheck)
            && peer_hints_mention(&entries, &pin.alias.ip)
        {
            observed.alias_in_peer_hints = true;
        }
        if exit_endpoints.contains(&alias_endpoint) {
            observed.exit_wg_endpoint_saw_alias = true;
        }

        observed.transcript.push_str(&render_sample(
            sampled_at,
            sample,
            &[
                ("route", &client_route),
                ("pin_route", &pin_route),
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
        //
        // The time of FIRST full re-convergence is what the SLO measures, so it
        // is latched once. It must NOT end the observation by itself, though: a
        // client that never lost its session is "re-converged" at the very first
        // sample, one second after the stimulus was applied, before the daemon
        // has had any chance to notice the new local address. Stopping there
        // froze the detection latches at their first-sample values and failed
        // `endpoint_change_detected` without ever watching for it
        // (katana-xnet-73). The window is the SLO the caller already granted, so
        // the loop also waits, inside that window, for the detection events;
        // every detection check still needs a positive observation, none is
        // relaxed.
        if observed.reconnect_unix.is_none()
            && super::client_exit_selected(&client_status, &exit.node_id)
            && route_ok
            && signed_ok
        {
            observed.reconnect_unix = Some(sampled_at);
        }
        if observed.first_event_seen && first_event_sample.is_none() {
            first_event_sample = Some(sample);
        }
        // One daemon limiter window after the first event, so a storm that
        // starts a moment later is still seen before the observation ends.
        let storm_watch_done = first_event_sample
            .is_some_and(|first| sample.saturating_sub(first) >= STORM_WATCH_SAMPLES);
        let every_latch = observed.reconnect_unix.is_some()
            && observed.endpoint_change_detected
            && observed.first_event_seen
            && observed.alias_in_self_hints
            && observed.alias_in_peer_hints;
        if every_latch && storm_watch_done {
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

/// Everything [`render_summary`] writes.
struct SummaryInputs<'a> {
    switch_started_unix: u64,
    pin: &'a SourcePin,
    observed: &'a Observation,
    before: &'a Baseline,
    restore: &'a Restore,
    rollback: &'a RollbackReport,
    reconnect_secs: Option<i64>,
    options: NodeNetworkSwitchOptions,
    checks: &'a Checks,
}

/// The monitor summary artifact.
///
/// Field names, types and nesting of the original keys are the shell's exactly,
/// including `reconnect_unix` being `null` rather than `0` when no reconnect
/// was observed and `reconnect_secs` being `-1` in the same case — the two spell
/// "did not happen" differently and a consumer may read either. The evidence the
/// node-switch fix added is additive (`stimulus`, `endpoint_change`, `hints`,
/// `rollback`, `exit_wg_endpoint_saw_alias`), so a consumer of the old keys is
/// unaffected.
fn render_summary(inputs: &SummaryInputs<'_>) -> Result<String, String> {
    let SummaryInputs {
        switch_started_unix,
        pin,
        observed,
        before,
        restore,
        rollback,
        reconnect_secs,
        options,
        checks,
    } = inputs;
    let payload = serde_json::json!({
        "switch_started_unix": switch_started_unix,
        "alias_ip": pin.alias.ip,
        "reconnect_unix": observed.reconnect_unix,
        "reconnect_secs": reconnect_secs.unwrap_or(NO_RECONNECT_SECS),
        "reconnect_slo_secs": options.reconnect_slo_secs,
        "route_leak_samples": observed.route_leak_samples,
        "signed_state_invalid_samples": observed.signed_state_invalid_samples,
        "samples_taken": observed.samples_taken,
        "checks": {
            "endpoint_change_detected": checks.verdict("endpoint_change_detected").as_str(),
            "traversal_reissue_triggered": checks.verdict("traversal_reissue_triggered").as_str(),
            "peer_received_updated_endpoint_hint":
                checks.verdict("peer_received_updated_endpoint_hint").as_str(),
            "stimulus_took_effect": checks.verdict("stimulus_took_effect").as_str(),
            "advertised_hint_carries_new_address":
                checks.verdict("advertised_hint_carries_new_address").as_str(),
            "stimulus_rolled_back": checks.verdict("stimulus_rolled_back").as_str(),
        },
        "stimulus": {
            "kind": "alias_source_pin",
            "interface": pin.iface,
            "peer_ip": pin.peer.to_string(),
            "gateway": pin.via.map(|via| via.to_string()),
            "original_src": pin.original_src.map(|src| src.to_string()),
            "pinned_src": pin.alias.ip,
            "route_table": SOURCE_PIN_TABLE,
            "rule_priority": SOURCE_PIN_RULE_PRIORITY,
            "effective": observed.stimulus_effective,
            "pinned_src_samples": observed.pin_alias_samples,
        },
        "endpoint_change": {
            "events_before": before.endpoint_events,
            "max_event_delta": observed.max_event_delta,
            "max_event_delta_allowed": MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH,
            "fingerprint_before": before.fingerprint,
            "fingerprint_restored": restore.restored,
            "fingerprint_after_restore": restore.last_fingerprint,
        },
        "hints": {
            "alias_in_client_minted_bundle": observed.alias_in_self_hints,
            "alias_in_exit_applied_bundle": observed.alias_in_peer_hints,
        },
        "exit_wg_endpoint_saw_alias": observed.exit_wg_endpoint_saw_alias,
        "rollback": {
            "complete": rollback.complete(),
            "residue": rollback.residue,
            "errors": rollback.errors,
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
    const CLIENT_IP: &str = "192.168.18.40";
    const EXIT_IP: &str = "192.168.19.40";
    const EXIT_NODE_ID: &str = "exit-1";
    const DEFAULT_ROUTE: &str =
        "default via 192.168.18.1 dev enp0s1 proto dhcp src 192.168.18.40 metric 100";

    // ── fixtures ──

    /// The kernel's answer for the WG flow BEFORE the pin: the daemon's
    /// table-51820 bypass pin, `via` but no `src`, so the primary address wins.
    fn route_get_unpinned() -> String {
        format!("{EXIT_IP} via 192.168.18.1 dev enp0s1 table 51820 src {CLIENT_IP} uid 0")
    }

    /// The answer with the pin in force.
    fn route_get_pinned() -> String {
        format!("{EXIT_IP} via 192.168.18.1 dev enp0s1 table 51873 src {ALIAS_IP} uid 0")
    }

    /// A `netcheck` line as the fixed daemon prints it.
    fn netcheck(fingerprint: &str, events: u64, hints: &str) -> String {
        format!(
            "traversal_error=none traversal_endpoint_fingerprint={fingerprint} \
             traversal_endpoint_change_events={events} traversal_preexpiry_refresh_events=9 \
             gossip_hints={hints}"
        )
    }

    fn clean_hints() -> String {
        "self/192.168.18.40,172.20.10.2+aaaaaaaa/192.168.19.40".to_owned()
    }

    fn client_hints_with_alias() -> String {
        format!("self/192.168.18.40,172.20.10.2,{ALIAS_IP}+aaaaaaaa/192.168.19.40")
    }

    fn exit_hints_with_alias() -> String {
        format!("self/192.168.19.40+bbbbbbbb/192.168.18.40,{ALIAS_IP}")
    }

    fn baseline() -> Baseline {
        Baseline {
            fingerprint: "before".to_owned(),
            endpoint_events: 3,
        }
    }

    fn alias() -> endpoint_switch::RoamAlias {
        endpoint_switch::RoamAlias {
            ip: ALIAS_IP.to_owned(),
            prefix: 24,
        }
    }

    /// A pin planned against a clean guest.
    fn pin() -> SourcePin {
        let planning = MockLeafRunner {
            stdout_by_match: vec![
                ("route show default".to_owned(), DEFAULT_ROUTE.to_owned()),
                (format!("route get {EXIT_IP}"), route_get_unpinned()),
            ],
            ..MockLeafRunner::default()
        };
        endpoint_switch::plan_source_pin(&planning, EXIT_IP, alias()).expect("plan")
    }

    /// A client whose pin took effect, that stays `ExitActive` through the
    /// tunnel, and whose `netcheck` answers from `netchecks` in order (the last
    /// entry repeats).
    fn client(netchecks: Vec<String>) -> MockLeafRunner {
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
                (format!("route get {EXIT_IP}"), route_get_pinned()),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{EXIT_IP}:51820"),
                ),
            ],
            stdout_seq_by_match: vec![("rustynet netcheck".to_owned(), netchecks)],
            ..MockLeafRunner::default()
        }
    }

    fn exit(netchecks: Vec<String>) -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![(
                "wg show rustynet0 endpoints".to_owned(),
                format!("peerkey\t{CLIENT_IP}:51820"),
            )],
            stdout_seq_by_match: vec![("rustynet netcheck".to_owned(), netchecks)],
            ..MockLeafRunner::default()
        }
    }

    fn observe(
        client_runner: &MockLeafRunner,
        exit_runner: &MockLeafRunner,
        options: NodeNetworkSwitchOptions,
    ) -> (Result<Observation, String>, AppliedPin) {
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(client_runner, "client-1", CLIENT_IP);
        let exit_node = ScenarioNode::new(exit_runner, EXIT_NODE_ID, EXIT_IP);
        let mut applied = AppliedPin::default();
        let observed = observe_transition(
            &client_node,
            &exit_node,
            &lab,
            options,
            &pin(),
            &baseline(),
            &mut applied,
        );
        (observed, applied)
    }

    fn quick(slo: u32) -> NodeNetworkSwitchOptions {
        NodeNetworkSwitchOptions::new(slo).expect("positive slo")
    }

    fn full_applied() -> AppliedPin {
        AppliedPin {
            alias_added: true,
            route_installed: true,
            rule_installed: true,
        }
    }

    // ── the observation loop ──

    #[test]
    fn a_healthy_switch_is_seen_and_the_storm_watch_runs_after_the_first_event() {
        // Sample 1 already shows every effect: new fingerprint, one event, the
        // alias in the client's minted bundle and in the exit's applied one.
        let c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        let e = exit(vec![netcheck("exit-fp", 0, &exit_hints_with_alias())]);
        let (observed, applied) = observe(&c, &e, NodeNetworkSwitchOptions::default());
        let observed = observed.expect("observe");

        assert_eq!(applied, full_applied());
        assert!(observed.stimulus_effective);
        assert!(observed.pin_alias_samples >= 1);
        assert!(observed.endpoint_change_detected);
        assert!(observed.first_event_seen);
        assert_eq!(observed.max_event_delta, 1);
        assert!(observed.alias_in_self_hints);
        assert!(observed.alias_in_peer_hints);
        assert!(observed.reconnect_unix.is_some());
        assert_eq!(observed.route_leak_samples, 0);
        assert_eq!(observed.signed_state_invalid_samples, 0);
        assert_eq!(
            observed.transcript.lines().count(),
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small"),
            "every latch was set on sample 1, then the storm watch keeps sampling for one limiter window"
        );
    }

    #[test]
    fn the_wireguard_endpoint_table_is_recorded_but_does_not_gate() {
        // The exit's endpoint table never shows the alias (userspace-shared
        // does not learn roamed endpoints) yet every gating latch is satisfied.
        let c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        let e = exit(vec![netcheck("exit-fp", 0, &exit_hints_with_alias())]);
        let observed = observe(&c, &e, quick(3)).0.expect("observe");
        assert!(!observed.exit_wg_endpoint_saw_alias);
        assert!(observed.alias_in_peer_hints);

        let mut roamed = exit(vec![netcheck("exit-fp", 0, &exit_hints_with_alias())]);
        roamed.stdout_by_match = vec![(
            "wg show rustynet0 endpoints".to_owned(),
            format!("peerkey\t{ALIAS_IP}:51820"),
        )];
        let observed = observe(&c, &roamed, quick(3)).0.expect("observe");
        assert!(observed.exit_wg_endpoint_saw_alias);
    }

    /// katana-xnet-73: the client is "re-converged" at the first sample (it never
    /// lost its session) but the daemon only reports the change on a later one.
    /// Sampling must go on inside the window until it does, while the reconnect
    /// time stays the FIRST re-converged sample.
    #[test]
    fn a_reconverged_client_keeps_sampling_until_the_events_are_seen() {
        let c = client(vec![
            netcheck("before", 3, &clean_hints()),
            netcheck("after", 4, &client_hints_with_alias()),
        ]);
        let e = exit(vec![
            netcheck("exit-fp", 0, &clean_hints()),
            netcheck("exit-fp", 0, &exit_hints_with_alias()),
        ]);
        let observed = observe(&c, &e, quick(5)).0.expect("observe");

        assert!(observed.endpoint_change_detected);
        assert!(observed.first_event_seen);
        assert!(observed.alias_in_self_hints);
        assert!(observed.alias_in_peer_hints);
        let first_sample_unix: u64 = observed
            .transcript
            .lines()
            .next()
            .and_then(|line| line.split('|').next())
            .and_then(|stamp| stamp.parse().ok())
            .expect("first sample timestamp");
        assert_eq!(
            observed.reconnect_unix,
            Some(first_sample_unix),
            "the reconnect time is the first re-converged sample"
        );
        assert_eq!(
            observed.transcript.lines().count(),
            5,
            "the window (5) bounds the sampling; the storm watch had not completed"
        );
    }

    /// The observation is bounded by the SLO window and never turns a missing
    /// detection into a pass.
    #[test]
    fn a_reconverged_client_with_no_detection_runs_the_window_and_detects_nothing() {
        let c = client(vec![netcheck("before", 3, &clean_hints())]);
        let e = exit(vec![netcheck("exit-fp", 0, &clean_hints())]);
        let observed = observe(&c, &e, quick(3)).0.expect("observe");

        assert!(!observed.endpoint_change_detected);
        assert!(!observed.first_event_seen);
        assert!(!observed.alias_in_self_hints);
        assert!(!observed.alias_in_peer_hints);
        assert_eq!(observed.transcript.lines().count(), 3, "bounded by the SLO");
        assert!(observed.reconnect_unix.is_some(), "it did re-converge");
    }

    #[test]
    fn the_pre_expiry_counter_is_never_credited_as_an_endpoint_change() {
        // The fixed netcheck carries traversal_preexpiry_refresh_events=9 in
        // every line; a client whose ONLY movement is that timer counter has
        // not seen an endpoint change.
        let moving_timer = vec![
            "traversal_error=none traversal_endpoint_fingerprint=before \
             traversal_endpoint_change_events=3 traversal_preexpiry_refresh_events=4 \
             gossip_hints=self/192.168.18.40"
                .to_owned(),
            "traversal_error=none traversal_endpoint_fingerprint=before \
             traversal_endpoint_change_events=3 traversal_preexpiry_refresh_events=5 \
             gossip_hints=self/192.168.18.40"
                .to_owned(),
        ];
        let observed = observe(
            &client(moving_timer),
            &exit(vec![netcheck("e", 0, &clean_hints())]),
            quick(4),
        )
        .0
        .expect("observe");
        assert!(!observed.first_event_seen);
        assert_eq!(observed.max_event_delta, 0);
    }

    #[test]
    fn a_refresh_storm_is_observed_as_an_oversized_delta() {
        let c = client(vec![
            netcheck("a", 4, &client_hints_with_alias()),
            netcheck("b", 5, &client_hints_with_alias()),
            netcheck("c", 6, &client_hints_with_alias()),
        ]);
        let e = exit(vec![netcheck("e", 0, &exit_hints_with_alias())]);
        let observed = observe(&c, &e, quick(4)).0.expect("observe");
        assert!(observed.first_event_seen);
        assert_eq!(observed.max_event_delta, 3);
        assert!(observed.max_event_delta > MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH);
    }

    #[test]
    fn a_counter_that_goes_backwards_is_not_an_event() {
        // A daemon restart resets the counter and re-seeds the fingerprint.
        let c = client(vec![
            netcheck("none", 0, &client_hints_with_alias()),
            netcheck("restarted", 0, &client_hints_with_alias()),
        ]);
        let observed = observe(&c, &exit(vec![netcheck("e", 0, &clean_hints())]), quick(3))
            .0
            .expect("observe");
        assert!(
            !observed.first_event_seen,
            "0 < baseline 3 is not an advance"
        );
        assert!(
            observed.endpoint_change_detected,
            "a different non-`none` fingerprint is still a different fingerprint"
        );
    }

    #[test]
    fn the_alias_must_be_in_the_right_bundle_to_count() {
        // Alias only in a PEER entry of the client's own netcheck, and only in
        // the SELF entry of the exit's: neither satisfies its latch.
        let c = client(vec![netcheck(
            "after",
            4,
            &format!("self/192.168.18.40+aaaaaaaa/{ALIAS_IP}"),
        )]);
        let e = exit(vec![netcheck(
            "e",
            0,
            &format!("self/{ALIAS_IP}+aaaaaaaa/192.168.18.40"),
        )]);
        let observed = observe(&c, &e, quick(3)).0.expect("observe");
        assert!(!observed.alias_in_self_hints);
        assert!(!observed.alias_in_peer_hints);
    }

    #[test]
    fn hint_matching_is_exact_on_the_ip_not_a_prefix() {
        let entries = gossip_hint_entries(&netcheck(
            "x",
            0,
            "self/192.168.18.77,10.0.0.11:51820+aaaaaaaa/192.168.18.9,none",
        ))
        .expect("entries");
        // A token that merely STARTS with the queried address is another
        // address: .7 is not .77, 10.0.0.1 is not 10.0.0.11.
        assert!(!self_hints_mention(&entries, "192.168.18.7"));
        assert!(!self_hints_mention(&entries, "10.0.0.1"));
        // The queried address followed by more digits of a longer address,
        // or a shorter token, must not match either.
        assert!(!self_hints_mention(&entries, "192.168.18.770"));
        assert!(!self_hints_mention(&entries, "10.0.0.111"));
        // Exact matches, including a reflexive `ip:port` token naming its ip.
        assert!(self_hints_mention(&entries, "192.168.18.77"));
        assert!(
            self_hints_mention(&entries, "10.0.0.11"),
            "a reflexive ip:port token names its ip"
        );
        assert!(peer_hints_mention(&entries, "192.168.18.9"));
        assert!(!peer_hints_mention(&entries, "192.168.18.7"));
        assert!(!peer_hints_mention(&entries, "192.168.18.77"));
    }

    #[test]
    fn an_ineffective_stimulus_stops_the_observation_and_attributes_nothing() {
        // The kernel keeps selecting the OLD source: the pin did nothing.
        let mut c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        c.stdout_by_match
            .retain(|(needle, _)| needle != &format!("route get {EXIT_IP}"));
        c.stdout_by_match
            .push((format!("route get {EXIT_IP}"), route_get_unpinned()));
        let e = exit(vec![netcheck("e", 0, &exit_hints_with_alias())]);
        let (observed, applied) = observe(&c, &e, NodeNetworkSwitchOptions::default());
        let observed = observed.expect("an ineffective stimulus is an outcome, not an error");

        assert!(!observed.stimulus_effective);
        assert_eq!(observed.samples_taken, 0);
        assert!(!observed.endpoint_change_detected && !observed.first_event_seen);
        assert!(!observed.alias_in_self_hints && !observed.alias_in_peer_hints);
        assert_eq!(
            applied,
            full_applied(),
            "it was applied, so it must be rolled back"
        );
        assert!(observed.transcript.contains("stimulus_ineffective"));
    }

    #[test]
    fn a_failed_apply_still_reports_what_was_applied_for_the_rollback() {
        let mut c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        // Call 0 = addr add succeeds, call 1 = route replace fails.
        c.fail_on = vec![1];
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let (observed, applied) = observe(&c, &e, quick(3));
        let err = observed.err().expect("a failed apply is an error");
        assert!(
            err.contains("failed to apply the node underlay switch"),
            "{err}"
        );
        assert_eq!(
            applied,
            AppliedPin {
                alias_added: true,
                ..AppliedPin::default()
            }
        );
    }

    #[test]
    fn a_client_that_never_reconverges_runs_the_whole_window_and_reports_no_reconnect() {
        // Only the pin route is scripted: no exit selected, no route through the
        // tunnel, no healthy signed state, no fingerprint.
        let c = MockLeafRunner {
            stdout_by_match: vec![(format!("route get {EXIT_IP}"), route_get_pinned())],
            ..MockLeafRunner::default()
        };
        let e = MockLeafRunner::default();
        let observed = observe(&c, &e, quick(3)).0.expect("observe");

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
        let mut c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        c.stdout_by_match
            .retain(|(needle, _)| needle != "route get 1.1.1.1");
        c.stdout_seq_by_match.push((
            "route get 1.1.1.1".to_owned(),
            vec![
                "1.1.1.1 via 192.168.18.1 dev enp0s1".to_owned(),
                "1.1.1.1 dev rustynet0 src 10.42.0.2".to_owned(),
            ],
        ));
        let e = exit(vec![netcheck("e", 0, &exit_hints_with_alias())]);
        let observed = observe(&c, &e, quick(4)).0.expect("observe");

        assert_eq!(observed.route_leak_samples, 1);
        assert!(
            observed.reconnect_unix.is_some(),
            "it did eventually reconverge"
        );
    }

    // ── baseline ──

    fn read_baseline_with(c: &MockLeafRunner, e: &MockLeafRunner) -> Result<Baseline, String> {
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(c, "client-1", CLIENT_IP);
        let exit_node = ScenarioNode::new(e, EXIT_NODE_ID, EXIT_IP);
        read_baseline(&client_node, &exit_node, &lab, ALIAS_IP)
    }

    #[test]
    fn a_quiet_baseline_is_two_agreeing_reads() {
        let c = client(vec![netcheck("before", 3, &clean_hints())]);
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let got = read_baseline_with(&c, &e).expect("baseline");
        assert_eq!(got, baseline());
        let netchecks = c
            .recorded()
            .iter()
            .filter(|call| call.join(" ").contains("rustynet netcheck"))
            .count();
        assert_eq!(netchecks, 2, "two client reads before it counts as quiet");
    }

    #[test]
    fn a_moving_baseline_waits_for_quiet_and_never_accepts_a_changing_value() {
        let c = client(vec![
            netcheck("a", 3, &clean_hints()),
            netcheck("b", 4, &clean_hints()),
            netcheck("b", 4, &clean_hints()),
        ]);
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let got = read_baseline_with(&c, &e).expect("settles on the third read");
        assert_eq!(got.fingerprint, "b");
        assert_eq!(got.endpoint_events, 4);

        let never_quiet: Vec<String> = (0..BASELINE_QUIESCENCE_ATTEMPTS + 2)
            .map(|n| netcheck(&format!("fp{n}"), u64::from(n), &clean_hints()))
            .collect();
        let err = read_baseline_with(&client(never_quiet), &e).expect_err("never quiet");
        assert!(err.contains("not quiescent"), "{err}");
    }

    #[test]
    fn a_baseline_without_the_new_daemon_fields_fails_naming_the_field() {
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let no_counter = client(vec![
            "traversal_error=none traversal_endpoint_fingerprint=before gossip_hints=self/1.2.3.4"
                .to_owned(),
        ]);
        let err = read_baseline_with(&no_counter, &e).expect_err("no counter");
        assert!(err.contains(ENDPOINT_EVENTS_FIELD), "{err}");

        let no_fingerprint = client(vec![
            "traversal_error=none traversal_endpoint_change_events=3 gossip_hints=self/1.2.3.4"
                .to_owned(),
        ]);
        let err = read_baseline_with(&no_fingerprint, &e).expect_err("no fingerprint");
        assert!(err.contains(FINGERPRINT_FIELD), "{err}");

        let no_hints = client(vec![
            "traversal_error=none traversal_endpoint_fingerprint=before \
             traversal_endpoint_change_events=3"
                .to_owned(),
        ]);
        let err = read_baseline_with(&no_hints, &e).expect_err("no hints");
        assert!(err.contains(HINTS_FIELD), "{err}");

        let gossip_off = client(vec![netcheck("before", 3, "none")]);
        let err = read_baseline_with(&gossip_off, &e).expect_err("gossip unconfigured");
        assert!(err.contains("not configured"), "{err}");
    }

    #[test]
    fn an_unseeded_fingerprint_is_waited_on_and_never_becomes_the_baseline() {
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let only_none = client(vec![netcheck("none", 0, &clean_hints())]);
        let err = read_baseline_with(&only_none, &e).expect_err("never seeded");
        assert!(err.contains("not quiescent"), "{err}");

        let seeds = client(vec![
            netcheck("none", 0, &clean_hints()),
            netcheck("seeded", 0, &clean_hints()),
        ]);
        let got = read_baseline_with(&seeds, &e).expect("baseline");
        assert_eq!(got.fingerprint, "seeded");
    }

    #[test]
    fn an_alias_that_is_already_advertised_makes_the_baseline_fail() {
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let client_has_it = client(vec![netcheck("before", 3, &client_hints_with_alias())]);
        let err = read_baseline_with(&client_has_it, &e).expect_err("client already minted it");
        assert!(err.contains("client's minted gossip bundle"), "{err}");

        let exit_has_it = exit(vec![netcheck("e", 0, &exit_hints_with_alias())]);
        let c = client(vec![netcheck("before", 3, &clean_hints())]);
        let err = read_baseline_with(&c, &exit_has_it).expect_err("exit already applied it");
        assert!(err.contains("applied by the exit"), "{err}");
    }

    // ── rollback is part of every path ──

    #[test]
    fn the_rollback_runs_even_when_the_observation_fails_midway() {
        // Transport failure on the first sampling command after the apply (3
        // apply commands + the source read = calls 0..=3; call 4 is `status`).
        let mut c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        c.transport_error_on = vec![4];
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(&c, "client-1", CLIENT_IP);
        let exit_node = ScenarioNode::new(&e, EXIT_NODE_ID, EXIT_IP);
        let run = run_switch(
            &client_node,
            &exit_node,
            &lab,
            NodeNetworkSwitchOptions::default(),
            &pin(),
            &baseline(),
        );
        assert!(run.observed.is_err(), "the transport failure is the error");
        let joined: Vec<String> = c.recorded().iter().map(|call| call.join(" ")).collect();
        for expected in ["ip rule del", "ip route flush table 51873", "ip addr del"] {
            assert!(
                joined.iter().any(|call| call.contains(expected)),
                "rollback step {expected:?} must run after a failed observation: {joined:#?}"
            );
        }
        assert!(run.rollback.complete());
    }

    #[test]
    fn an_ineffective_stimulus_is_still_rolled_back_and_restored() {
        let mut c = client(vec![netcheck("before", 3, &clean_hints())]);
        c.stdout_by_match
            .retain(|(needle, _)| needle != &format!("route get {EXIT_IP}"));
        c.stdout_by_match
            .push((format!("route get {EXIT_IP}"), route_get_unpinned()));
        let e = exit(vec![netcheck("e", 0, &clean_hints())]);
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(&c, "client-1", CLIENT_IP);
        let exit_node = ScenarioNode::new(&e, EXIT_NODE_ID, EXIT_IP);
        let run = run_switch(
            &client_node,
            &exit_node,
            &lab,
            NodeNetworkSwitchOptions::default(),
            &pin(),
            &baseline(),
        );
        assert!(!run.observed.expect("outcome").stimulus_effective);
        assert!(run.rollback.complete());
        assert!(
            run.restore.restored,
            "the daemon's fingerprint never left `before`, so it reads as restored"
        );
    }

    #[test]
    fn restore_requires_the_exact_pre_switch_fingerprint() {
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let stuck = client(vec![netcheck("after", 5, &clean_hints())]);
        let node = ScenarioNode::new(&stuck, "client-1", CLIENT_IP);
        let restore = wait_for_restored_fingerprint(&node, &lab, "before");
        assert!(!restore.restored);
        assert_eq!(restore.last_fingerprint.as_deref(), Some("after"));
        let polls = stuck
            .recorded()
            .iter()
            .filter(|call| call.join(" ").contains("rustynet netcheck"))
            .count();
        assert_eq!(
            polls,
            usize::try_from(RESTORE_WAIT_ATTEMPTS).expect("small")
        );

        let returns = client(vec![
            netcheck("after", 5, &clean_hints()),
            netcheck("after", 5, &clean_hints()),
            netcheck("before", 6, &clean_hints()),
        ]);
        let node = ScenarioNode::new(&returns, "client-1", CLIENT_IP);
        let restore = wait_for_restored_fingerprint(&node, &lab, "before");
        assert!(restore.restored);
    }

    #[test]
    fn an_incomplete_rollback_skips_the_restore_wait_and_is_reported() {
        let mut c = client(vec![netcheck("after", 4, &client_hints_with_alias())]);
        // The rollback's read-back still shows the rule: residue.
        c.stdout_by_match.push((
            "ip rule show".to_owned(),
            format!("{SOURCE_PIN_RULE_PRIORITY}:\tfrom all to {EXIT_IP} lookup {SOURCE_PIN_TABLE}"),
        ));
        let e = exit(vec![netcheck("e", 0, &exit_hints_with_alias())]);
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(&c, "client-1", CLIENT_IP);
        let exit_node = ScenarioNode::new(&e, EXIT_NODE_ID, EXIT_IP);
        let run = run_switch(
            &client_node,
            &exit_node,
            &lab,
            quick(2),
            &pin(),
            &baseline(),
        );
        assert!(!run.rollback.complete());
        assert!(!run.restore.restored);
        assert_eq!(run.restore.last_fingerprint, None, "the wait must not run");
        assert!(run.rollback.describe().contains("priority 9873"));
    }

    // ── reporting ──

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

    // ── the pure check recorder ──

    /// An observation in which everything the stage looks for happened.
    fn good_observation() -> Observation {
        let mut observed = Observation::new();
        observed.stimulus_effective = true;
        observed.pin_alias_samples = 4;
        observed.samples_taken = 4;
        observed.endpoint_change_detected = true;
        observed.first_event_seen = true;
        observed.max_event_delta = 1;
        observed.alias_in_self_hints = true;
        observed.alias_in_peer_hints = true;
        observed.reconnect_unix = Some(1001);
        observed
    }

    fn restored() -> Restore {
        Restore {
            restored: true,
            last_fingerprint: Some("before".to_owned()),
        }
    }

    fn recorded(
        observed: &Observation,
        rollback: &RollbackReport,
        restore: &Restore,
        reconnect_secs: Option<i64>,
    ) -> Checks {
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        record_switch_checks(
            &mut checks,
            observed,
            rollback,
            restore,
            reconnect_secs,
            NodeNetworkSwitchOptions::default(),
        );
        checks
    }

    const OBSERVED_CHECKS: &[&str] = &[
        "stimulus_took_effect",
        "endpoint_change_detected",
        "traversal_reissue_triggered",
        "advertised_hint_carries_new_address",
        "peer_received_updated_endpoint_hint",
        "no_underlay_leak_during_transition",
        "signed_state_valid_during_transition",
        "stimulus_rolled_back",
        "session_reconnect_within_slo",
    ];

    #[test]
    fn a_fully_good_observation_passes_every_observed_check() {
        let checks = recorded(
            &good_observation(),
            &RollbackReport::default(),
            &restored(),
            Some(1),
        );
        for name in OBSERVED_CHECKS {
            assert!(checks.passed(name), "{name} should pass");
        }
    }

    #[test]
    fn each_observed_check_fails_when_its_own_evidence_is_missing() {
        type Spoil = fn(&mut Observation);
        let cases: &[(&str, Spoil)] = &[
            ("stimulus_took_effect", |o| o.stimulus_effective = false),
            ("stimulus_took_effect", |o| o.pin_alias_samples = 0),
            ("endpoint_change_detected", |o| {
                o.endpoint_change_detected = false;
            }),
            ("traversal_reissue_triggered", |o| {
                o.first_event_seen = false
            }),
            ("traversal_reissue_triggered", |o| {
                o.max_event_delta = MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH + 1;
            }),
            ("advertised_hint_carries_new_address", |o| {
                o.alias_in_self_hints = false;
            }),
            ("peer_received_updated_endpoint_hint", |o| {
                o.alias_in_peer_hints = false;
            }),
            ("no_underlay_leak_during_transition", |o| {
                o.route_leak_samples = 1;
            }),
            ("signed_state_valid_during_transition", |o| {
                o.signed_state_invalid_samples = 1;
            }),
        ];
        for (name, spoil) in cases {
            let mut observed = good_observation();
            spoil(&mut observed);
            let checks = recorded(&observed, &RollbackReport::default(), &restored(), Some(1));
            assert!(
                !checks.passed(name),
                "{name} must fail when its evidence is gone"
            );
            let failing: Vec<&str> = OBSERVED_CHECKS
                .iter()
                .copied()
                .filter(|other| !checks.passed(other))
                .collect();
            assert_eq!(
                failing,
                vec![*name],
                "spoiling the evidence for {name} must fail that check and no other"
            );
        }
    }

    #[test]
    fn the_event_bound_is_inclusive_at_the_limit_and_fails_one_above() {
        for (delta, expect) in [
            (1, true),
            (MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH, true),
            (MAX_ENDPOINT_CHANGE_EVENTS_PER_SWITCH + 1, false),
        ] {
            let mut observed = good_observation();
            observed.max_event_delta = delta;
            let checks = recorded(&observed, &RollbackReport::default(), &restored(), Some(1));
            assert_eq!(
                checks.passed("traversal_reissue_triggered"),
                expect,
                "delta {delta}"
            );
        }
    }

    #[test]
    fn an_unobserved_transition_is_not_a_clean_one() {
        // The ineffective-stimulus path takes ZERO samples; the two sampled
        // checks must not read "no leak seen" / "no invalid state seen" from
        // having looked at nothing.
        let mut observed = good_observation();
        observed.samples_taken = 0;
        let checks = recorded(&observed, &RollbackReport::default(), &restored(), Some(1));
        assert!(!checks.passed("no_underlay_leak_during_transition"));
        assert!(!checks.passed("signed_state_valid_during_transition"));
    }

    #[test]
    fn rollback_and_restore_are_both_required_for_stimulus_rolled_back() {
        let residue = RollbackReport {
            residue: vec!["alias still present".to_owned()],
            errors: Vec::new(),
        };
        let not_restored = Restore {
            restored: false,
            last_fingerprint: Some("after".to_owned()),
        };
        let good = good_observation();
        assert!(!recorded(&good, &residue, &restored(), Some(1)).passed("stimulus_rolled_back"));
        assert!(
            !recorded(&good, &RollbackReport::default(), &not_restored, Some(1))
                .passed("stimulus_rolled_back")
        );
        assert!(
            recorded(&good, &RollbackReport::default(), &restored(), Some(1))
                .passed("stimulus_rolled_back")
        );
    }

    #[test]
    fn the_reconnect_slo_is_a_closed_interval_and_a_negative_time_is_not_instant() {
        let slo = i64::from(DEFAULT_RECONNECT_SLO_SECS);
        for (secs, expect) in [
            (Some(0), true),
            (Some(slo), true),
            (Some(slo + 1), false),
            (Some(-1), false),
            (None, false),
        ] {
            let checks = recorded(
                &good_observation(),
                &RollbackReport::default(),
                &restored(),
                secs,
            );
            assert_eq!(
                checks.passed("session_reconnect_within_slo"),
                expect,
                "{secs:?}"
            );
        }
    }

    #[test]
    fn the_aggregate_covers_every_other_check_in_the_report() {
        // A check that is emitted but not aggregated is a check that cannot
        // fail the scenario.
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
    fn the_check_list_names_the_new_evidence_and_keeps_the_old_names() {
        for name in [
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
            "stimulus_took_effect",
            "advertised_hint_carries_new_address",
            "stimulus_rolled_back",
        ] {
            assert!(CHECKS.contains(&name), "{name} missing from CHECKS");
        }
        assert_eq!(CHECKS.len(), 13);
    }

    #[test]
    fn the_failure_summary_names_the_first_thing_that_did_not_happen() {
        let options = NodeNetworkSwitchOptions::default();
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        // Declared checks default to fail, so the chain starts at rollback.
        assert!(
            failure_summary(&checks, options, None, 0).contains("not cleanly rolled back"),
            "residue is reported first because it poisons the next stage"
        );

        checks.record_bool("stimulus_rolled_back", true);
        assert!(failure_summary(&checks, options, None, 0).contains("lab stimulus ineffective"));

        checks.record_bool("stimulus_took_effect", true);
        assert_eq!(
            failure_summary(&checks, options, None, 0),
            "endpoint-change detection did not trigger during node underlay switch"
        );

        checks.record_bool("endpoint_change_detected", true);
        assert_eq!(
            failure_summary(&checks, options, None, 0),
            "endpoint-change refresh did not run during node underlay switch \
             (traversal_endpoint_change_events did not advance)"
        );
        assert_eq!(
            failure_summary(&checks, options, None, 5),
            "endpoint-change refresh storm during node underlay switch \
             (traversal_endpoint_change_events advanced by 5, limit 2)"
        );

        checks.record_bool("traversal_reissue_triggered", true);
        assert_eq!(
            failure_summary(&checks, options, None, 1),
            "refreshed gossip hint did not carry the new underlay address after node underlay \
             switch"
        );

        checks.record_bool("advertised_hint_carries_new_address", true);
        assert_eq!(
            failure_summary(&checks, options, None, 1),
            "peer did not observe updated endpoint hint after node underlay switch"
        );

        checks.record_bool("peer_received_updated_endpoint_hint", true);
        assert_eq!(
            failure_summary(&checks, options, None, 1),
            "session reconvergence exceeded reconnect SLO (30s), measured=-1s",
            "a reconnect that never happened is reported as the shell's -1 sentinel"
        );

        checks.record_bool("session_reconnect_within_slo", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4), 1),
            "underlay leak detected during node underlay switch transition"
        );

        checks.record_bool("no_underlay_leak_during_transition", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4), 1),
            "signed state became invalid during node underlay switch transition"
        );

        checks.record_bool("signed_state_valid_during_transition", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4), 1),
            "plaintext passphrase files detected during node network-switch validation"
        );

        checks.record_bool("no_plaintext_passphrase_files", true);
        // Everything this chain names has passed, so only the two checks it
        // never mentions — readiness and topology — can still be failing.
        assert_eq!(
            failure_summary(&checks, options, Some(4), 1),
            "node network-switch validation checks did not all pass"
        );
    }

    #[test]
    fn a_multi_line_capture_becomes_one_greppable_monitor_line() {
        assert_eq!(squeeze("a   b\nc  d"), "a b;c d");
        let rendered = render_sample(1700, 2, &[("route", &"a\nb".to_owned())]);
        assert_eq!(rendered, "1700|iter=2|route=a;b\n");
    }

    fn summary_for(observed: &Observation, rollback: &RollbackReport) -> serde_json::Value {
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        let rendered = render_summary(&SummaryInputs {
            switch_started_unix: 1700,
            pin: &pin(),
            observed,
            before: &baseline(),
            restore: &Restore {
                restored: false,
                last_fingerprint: Some("after".to_owned()),
            },
            rollback,
            reconnect_secs: None,
            options: NodeNetworkSwitchOptions::default(),
            checks: &checks,
        })
        .expect("render summary");
        serde_json::from_str(&rendered).expect("summary is valid JSON")
    }

    #[test]
    fn the_summary_spells_a_missing_reconnect_as_null_and_minus_one() {
        // The two fields say "did not happen" differently and a consumer may
        // read either, so both spellings are part of the artifact's contract.
        let mut observed = Observation::new();
        observed.route_leak_samples = 2;
        observed.signed_state_invalid_samples = 1;
        let parsed = summary_for(&observed, &RollbackReport::default());
        assert!(parsed["reconnect_unix"].is_null());
        assert_eq!(parsed["reconnect_secs"], -1);
        assert_eq!(parsed["reconnect_slo_secs"], 30);
        assert_eq!(parsed["alias_ip"], ALIAS_IP);
        assert_eq!(parsed["route_leak_samples"], 2);
        assert_eq!(parsed["checks"]["endpoint_change_detected"], "fail");
    }

    #[test]
    fn the_summary_adds_the_new_evidence_without_renaming_the_old_keys() {
        let mut observed = Observation::new();
        observed.stimulus_effective = true;
        observed.pin_alias_samples = 7;
        observed.max_event_delta = 1;
        observed.alias_in_self_hints = true;
        let rollback = RollbackReport {
            residue: vec!["ip rule at priority 9873 still present".to_owned()],
            errors: Vec::new(),
        };
        let parsed = summary_for(&observed, &rollback);

        assert_eq!(parsed["stimulus"]["kind"], "alias_source_pin");
        assert_eq!(parsed["stimulus"]["interface"], "enp0s1");
        assert_eq!(parsed["stimulus"]["peer_ip"], EXIT_IP);
        assert_eq!(parsed["stimulus"]["gateway"], "192.168.18.1");
        assert_eq!(parsed["stimulus"]["original_src"], CLIENT_IP);
        assert_eq!(parsed["stimulus"]["pinned_src"], ALIAS_IP);
        assert_eq!(parsed["stimulus"]["route_table"], 51873);
        assert_eq!(parsed["stimulus"]["rule_priority"], 9873);
        assert_eq!(parsed["stimulus"]["pinned_src_samples"], 7);
        assert_eq!(parsed["endpoint_change"]["events_before"], 3);
        assert_eq!(parsed["endpoint_change"]["max_event_delta"], 1);
        assert_eq!(parsed["endpoint_change"]["fingerprint_before"], "before");
        assert_eq!(parsed["endpoint_change"]["fingerprint_restored"], false);
        assert_eq!(parsed["hints"]["alias_in_client_minted_bundle"], true);
        assert_eq!(parsed["hints"]["alias_in_exit_applied_bundle"], false);
        assert_eq!(parsed["rollback"]["complete"], false);
        assert_eq!(
            parsed["rollback"]["residue"][0],
            "ip rule at priority 9873 still present"
        );
        // Old keys and nesting are untouched.
        for key in [
            "switch_started_unix",
            "alias_ip",
            "reconnect_unix",
            "reconnect_secs",
            "reconnect_slo_secs",
            "route_leak_samples",
            "signed_state_invalid_samples",
        ] {
            assert!(parsed.get(key).is_some(), "{key} must survive");
        }
        for key in [
            "endpoint_change_detected",
            "traversal_reissue_triggered",
            "peer_received_updated_endpoint_hint",
        ] {
            assert!(parsed["checks"].get(key).is_some(), "{key} must survive");
        }
    }

    // ── the whole post-baseline flow, against scripted guests ──

    use crate::vm_lab::orchestrator::stage::cross_network::scenario::host::recording::{
        HostCall, RecordingHost,
    };
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::NatProfileId;

    /// The alias the flow will actually choose for these addresses.
    fn flow_alias_ip() -> String {
        endpoint_switch::choose_alias(CLIENT_IP, &[CLIENT_IP, EXIT_IP])
            .expect("alias")
            .ip
    }

    fn flow_client_hints(alias_ip: &str) -> String {
        format!("self/{CLIENT_IP},172.20.10.2,{alias_ip}+aaaaaaaa/{EXIT_IP}")
    }

    fn flow_exit_hints(alias_ip: &str) -> String {
        format!("self/{EXIT_IP}+bbbbbbbb/{CLIENT_IP},{alias_ip}")
    }

    /// The client's netcheck answers over a whole flow: the two baseline reads,
    /// then `samples`, then the restore poll(s) (the last entry repeats).
    fn flow_client_netchecks(samples: Vec<String>) -> Vec<String> {
        let mut all = vec![
            netcheck("before", 3, &clean_hints()),
            netcheck("before", 3, &clean_hints()),
        ];
        all.extend(samples);
        all.push(netcheck("before", 4, &clean_hints()));
        all
    }

    fn flow_client(netchecks: Vec<String>, alias_ip: &str, pin_effective: bool) -> MockLeafRunner {
        let after_apply = if pin_effective {
            format!("{EXIT_IP} via 192.168.18.1 dev enp0s1 table 51873 src {alias_ip} uid 0")
        } else {
            route_get_unpinned()
        };
        MockLeafRunner {
            stdout_by_match: vec![
                ("route show default".to_owned(), DEFAULT_ROUTE.to_owned()),
                (
                    "rustynet status".to_owned(),
                    format!("exit_node={EXIT_NODE_ID} state=ExitActive"),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0 src 10.42.0.2".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peer\t{EXIT_IP}:51820"),
                ),
                (
                    "addr show dev".to_owned(),
                    format!("    inet {CLIENT_IP}/24 scope global dynamic enp0s1"),
                ),
                (
                    "ip rule show".to_owned(),
                    "0:\tfrom all lookup local\n10000:\tfrom all lookup 51820".to_owned(),
                ),
            ],
            stdout_seq_by_match: vec![
                (
                    format!("route get {EXIT_IP}"),
                    vec![route_get_unpinned(), after_apply],
                ),
                ("rustynet netcheck".to_owned(), netchecks),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn flow_exit(netchecks: Vec<String>) -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    "exit_node=none state=ExitActive serving_exit_node=true".to_owned(),
                ),
                (
                    "wg show rustynet0 endpoints".to_owned(),
                    format!("peerkey\t{CLIENT_IP}:51820"),
                ),
            ],
            stdout_seq_by_match: vec![("rustynet netcheck".to_owned(), netchecks)],
            ..MockLeafRunner::default()
        }
    }

    fn run_flow(
        c: &MockLeafRunner,
        e: &MockLeafRunner,
    ) -> (Result<(), String>, Checks, RecordingHost) {
        let host = RecordingHost::default();
        let lab = test_support::lab("/tmp/rustynet-cn3-tests");
        let inputs = ScenarioInputs {
            client: ScenarioNode::new(c, "client-1", CLIENT_IP),
            exit: ScenarioNode::new(e, EXIT_NODE_ID, EXIT_IP),
            relay: None,
            probe: None,
            nat_profile: NatProfileId::parse("baseline_lan").expect("known NAT profile"),
            impairment_profile: "none".to_owned(),
        };
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        // `execute` records these two from the composed baseline before it
        // hands over to the flow under test.
        checks.record_bool("direct_remote_exit_ready", true);
        checks.record_bool("cross_network_topology_heuristic", true);
        let result = switch_after_baseline(
            &host,
            &inputs,
            &lab,
            NodeNetworkSwitchOptions::default(),
            &mut checks,
        );
        (result, checks, host)
    }

    fn calls_of(runner: &MockLeafRunner) -> Vec<String> {
        runner
            .recorded()
            .iter()
            .map(|call| call.join(" "))
            .collect()
    }

    fn mutating_calls(calls: &[String]) -> Vec<&String> {
        calls
            .iter()
            .filter(|call| {
                [
                    " addr add ",
                    " route replace ",
                    " rule add ",
                    " rule del ",
                    " route flush ",
                    " addr del ",
                ]
                .iter()
                .any(|verb| call.contains(verb))
            })
            .collect()
    }

    fn artifact_named(host: &RecordingHost, suffix: &str) -> String {
        host.recorded()
            .into_iter()
            .find_map(|call| match call {
                HostCall::WriteArtifact { path, contents }
                    if path.to_string_lossy().ends_with(suffix) =>
                {
                    Some(contents)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("no artifact ending in {suffix} was written"))
    }

    #[test]
    fn the_whole_flow_passes_on_a_healthy_switch_and_leaves_the_guest_clean() {
        let alias_ip = flow_alias_ip();
        let samples = vec![
            netcheck("after", 4, &flow_client_hints(&alias_ip));
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small")
        ];
        let c = flow_client(flow_client_netchecks(samples), &alias_ip, true);
        let mut exit_netchecks = vec![netcheck("e", 0, &clean_hints())];
        exit_netchecks.extend(vec![
            netcheck("e", 0, &flow_exit_hints(&alias_ip));
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small")
        ]);
        let e = flow_exit(exit_netchecks);

        let (result, checks, host) = run_flow(&c, &e);
        result.expect("a healthy switch passes");
        for name in AGGREGATE_CHECKS {
            assert!(checks.passed(name), "{name}");
        }
        assert!(checks.passed("node_network_switch_success"));

        // The three changes go in, in order, and come out in reverse order.
        let calls = calls_of(&c);
        let mutations = mutating_calls(&calls);
        let verbs: Vec<&str> = mutations
            .iter()
            .map(|call| {
                [
                    "addr add",
                    "route replace",
                    "rule add",
                    "rule del",
                    "route flush",
                    "addr del",
                ]
                .into_iter()
                .find(|verb| call.contains(verb))
                .expect("a mutating verb")
            })
            .collect();
        assert_eq!(
            verbs,
            vec![
                "addr add",
                "route replace",
                "rule add",
                "rule del",
                "route flush",
                "addr del"
            ]
        );
        assert!(
            mutations[0].contains(&format!("{alias_ip}/24")),
            "the chosen alias is the one added: {}",
            mutations[0]
        );
        assert!(
            calls_of(&e)
                .iter()
                .all(|call| mutating_calls(std::slice::from_ref(call)).is_empty()),
            "the exit is never modified"
        );

        // Artifacts: one monitor line per sample, and the summary says what happened.
        let monitor = artifact_named(&host, "cross_network_node_network_switch_monitor.log");
        assert_eq!(
            monitor.lines().count(),
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small")
        );
        let summary: serde_json::Value = serde_json::from_str(&artifact_named(
            &host,
            "cross_network_node_network_switch_summary.json",
        ))
        .expect("summary json");
        assert_eq!(summary["alias_ip"], alias_ip.as_str());
        assert_eq!(summary["stimulus"]["effective"], true);
        assert_eq!(summary["endpoint_change"]["max_event_delta"], 1);
        assert_eq!(summary["endpoint_change"]["fingerprint_restored"], true);
        assert_eq!(summary["hints"]["alias_in_exit_applied_bundle"], true);
        assert_eq!(summary["rollback"]["complete"], true);
        assert_eq!(summary["checks"]["stimulus_rolled_back"], "pass");
    }

    #[test]
    fn a_daemon_without_the_new_fields_fails_before_the_guest_is_touched() {
        let old_daemon = "traversal_error=none traversal_endpoint_fingerprint=before \
                          traversal_preexpiry_refresh_events=3"
            .to_owned();
        let alias_ip = flow_alias_ip();
        let c = flow_client(vec![old_daemon], &alias_ip, true);
        let e = flow_exit(vec![netcheck("e", 0, &clean_hints())]);
        let (result, checks, _host) = run_flow(&c, &e);
        let err = result.expect_err("a daemon predating the fix cannot pass");
        assert!(err.contains(ENDPOINT_EVENTS_FIELD), "{err}");
        assert!(
            mutating_calls(&calls_of(&c)).is_empty(),
            "nothing may be applied before the baseline is proven: {:?}",
            calls_of(&c)
        );
        assert!(!checks.passed("node_network_switch_success"));
    }

    #[test]
    fn a_baseline_that_never_goes_quiet_fails_before_the_guest_is_touched() {
        let alias_ip = flow_alias_ip();
        let moving: Vec<String> = (0..40)
            .map(|n| netcheck(&format!("fp{n}"), n, &clean_hints()))
            .collect();
        let c = flow_client(moving, &alias_ip, true);
        let e = flow_exit(vec![netcheck("e", 0, &clean_hints())]);
        let (result, _checks, _host) = run_flow(&c, &e);
        let err = result.expect_err("moving baseline");
        assert!(err.contains("not quiescent"), "{err}");
        assert!(mutating_calls(&calls_of(&c)).is_empty());
    }

    #[test]
    fn an_ineffective_stimulus_fails_with_the_lab_message_and_is_still_rolled_back() {
        let alias_ip = flow_alias_ip();
        let c = flow_client(flow_client_netchecks(Vec::new()), &alias_ip, false);
        let e = flow_exit(vec![netcheck("e", 0, &clean_hints())]);
        let (result, checks, host) = run_flow(&c, &e);
        let err = result.expect_err("an ineffective stimulus fails the stage");
        assert!(err.contains("lab stimulus ineffective"), "{err}");
        assert!(!checks.passed("stimulus_took_effect"));
        assert!(checks.passed("stimulus_rolled_back"));
        assert!(
            !checks.passed("no_underlay_leak_during_transition"),
            "nothing was observed, so nothing can be called clean"
        );
        let verbs = mutating_calls(&calls_of(&c)).len();
        assert_eq!(verbs, 6, "3 applied, 3 removed: {:?}", calls_of(&c));
        let summary: serde_json::Value = serde_json::from_str(&artifact_named(
            &host,
            "cross_network_node_network_switch_summary.json",
        ))
        .expect("summary json");
        assert_eq!(summary["stimulus"]["effective"], false);
        assert_eq!(summary["samples_taken"], 0);
    }

    #[test]
    fn a_hint_that_never_reaches_the_exit_fails_with_the_peer_message() {
        let alias_ip = flow_alias_ip();
        let window = usize::try_from(DEFAULT_RECONNECT_SLO_SECS).expect("small");
        let c = flow_client(
            flow_client_netchecks(vec![
                netcheck("after", 4, &flow_client_hints(&alias_ip));
                window
            ]),
            &alias_ip,
            true,
        );
        // The exit never applies a bundle listing the alias.
        let e = flow_exit(vec![netcheck("e", 0, &clean_hints())]);
        let (result, checks, _host) = run_flow(&c, &e);
        let err = result.expect_err("no peer hint");
        assert_eq!(
            err,
            "peer did not observe updated endpoint hint after node underlay switch"
        );
        assert!(checks.passed("advertised_hint_carries_new_address"));
        assert!(!checks.passed("peer_received_updated_endpoint_hint"));
        assert!(checks.passed("stimulus_rolled_back"));
    }

    #[test]
    fn rollback_residue_is_reported_first_and_recorded() {
        let alias_ip = flow_alias_ip();
        let samples = vec![
            netcheck("after", 4, &flow_client_hints(&alias_ip));
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small")
        ];
        let mut c = flow_client(flow_client_netchecks(samples), &alias_ip, true);
        // `ip rule show` is read twice: while planning (clean) and when the
        // rollback reads the guest back (the rule is still there).
        c.stdout_seq_by_match.push((
            "ip rule show".to_owned(),
            vec![
                "0:\tfrom all lookup local\n10000:\tfrom all lookup 51820".to_owned(),
                format!(
                    "{SOURCE_PIN_RULE_PRIORITY}:\tfrom all to {EXIT_IP} lookup {SOURCE_PIN_TABLE}"
                ),
            ],
        ));
        let mut exit_netchecks = vec![netcheck("e", 0, &clean_hints())];
        exit_netchecks.extend(vec![
            netcheck("e", 0, &flow_exit_hints(&alias_ip));
            1 + usize::try_from(STORM_WATCH_SAMPLES).expect("small")
        ]);
        let e = flow_exit(exit_netchecks);
        let (result, checks, host) = run_flow(&c, &e);
        let err = result.expect_err("residue fails the stage");
        assert!(err.contains("not cleanly rolled back"), "{err}");
        assert!(!checks.passed("stimulus_rolled_back"));
        let summary: serde_json::Value = serde_json::from_str(&artifact_named(
            &host,
            "cross_network_node_network_switch_summary.json",
        ))
        .expect("summary json");
        assert_eq!(summary["rollback"]["complete"], false);
        assert!(
            summary["rollback"]["residue"][0]
                .as_str()
                .is_some_and(|text| text.contains("sudo ip rule del priority 9873")),
            "{summary}"
        );
    }

    #[test]
    fn a_transport_failure_mid_observation_is_reported_after_a_clean_rollback() {
        let alias_ip = flow_alias_ip();
        let samples = vec![netcheck("after", 4, &flow_client_hints(&alias_ip)); 3];
        let build_client = || flow_client(flow_client_netchecks(samples.clone()), &alias_ip, true);
        let mut exit_netchecks = vec![netcheck("e", 0, &clean_hints())];
        exit_netchecks.extend(vec![netcheck("e", 0, &flow_exit_hints(&alias_ip)); 3]);

        // A dry run teaches the index of the first sampling command (the mock
        // is deterministic, so the second run issues the same calls up to it).
        let dry = build_client();
        let _ = run_flow(&dry, &flow_exit(exit_netchecks.clone()));
        let calls = calls_of(&dry);
        let rule_add = calls
            .iter()
            .position(|call| call.contains(" rule add "))
            .expect("the pin rule is added");
        let first_sample_command = calls
            .iter()
            .enumerate()
            .skip(rule_add)
            .find(|(_, call)| call.contains("rustynet status"))
            .map(|(index, _)| index)
            .expect("the first sample runs `rustynet status`");

        let mut c = build_client();
        c.transport_error_on = vec![first_sample_command];
        let e = flow_exit(exit_netchecks);
        let (result, checks, _host) = run_flow(&c, &e);
        let err = result.expect_err("a transport failure mid-observation fails the stage");
        assert!(
            err.starts_with("applying client underlay source pin and observing the switch:"),
            "{err}"
        );
        assert!(!err.contains("ROLLBACK INCOMPLETE"), "{err}");
        assert!(
            checks.passed("stimulus_rolled_back"),
            "the rollback ran and was verified, and the report must say so even though the \
             observation errored"
        );
        let verbs = mutating_calls(&calls_of(&c)).len();
        assert_eq!(verbs, 6, "3 applied, 3 removed: {:?}", calls_of(&c));
    }

    #[test]
    fn a_transport_failure_with_residue_names_the_residue_in_the_error() {
        let alias_ip = flow_alias_ip();
        let samples = vec![netcheck("after", 4, &flow_client_hints(&alias_ip)); 3];
        let mut exit_netchecks = vec![netcheck("e", 0, &clean_hints())];
        exit_netchecks.extend(vec![netcheck("e", 0, &flow_exit_hints(&alias_ip)); 3]);
        let build_client = || {
            let mut c = flow_client(flow_client_netchecks(samples.clone()), &alias_ip, true);
            // `ip rule show`: clean while planning, residue when read back.
            c.stdout_seq_by_match.push((
                "ip rule show".to_owned(),
                vec![
                    "0:\tfrom all lookup local\n10000:\tfrom all lookup 51820".to_owned(),
                    format!(
                        "{SOURCE_PIN_RULE_PRIORITY}:\tfrom all to {EXIT_IP} lookup {SOURCE_PIN_TABLE}"
                    ),
                ],
            ));
            c
        };
        let dry = build_client();
        let _ = run_flow(&dry, &flow_exit(exit_netchecks.clone()));
        let calls = calls_of(&dry);
        let rule_add = calls
            .iter()
            .position(|call| call.contains(" rule add "))
            .expect("the pin rule is added");
        let first_sample_command = calls
            .iter()
            .enumerate()
            .skip(rule_add)
            .find(|(_, call)| call.contains("rustynet status"))
            .map(|(index, _)| index)
            .expect("the first sample runs `rustynet status`");

        let mut c = build_client();
        c.transport_error_on = vec![first_sample_command];
        let (result, checks, _host) = run_flow(&c, &flow_exit(exit_netchecks));
        let err = result.expect_err("a transport failure mid-observation fails the stage");
        assert!(
            err.contains("ROLLBACK INCOMPLETE") && err.contains("sudo ip rule del priority 9873"),
            "the residue must be named next to the observation error: {err}"
        );
        assert!(!checks.passed("stimulus_rolled_back"));
    }

    #[test]
    fn a_tunnel_that_does_not_dial_the_exit_underlay_address_is_refused_before_any_change() {
        let alias_ip = flow_alias_ip();
        let mut c = flow_client(flow_client_netchecks(Vec::new()), &alias_ip, true);
        // The client's tunnel dials some other address (a NAT-shaped endpoint).
        c.stdout_by_match
            .retain(|(needle, _)| needle != "wg show rustynet0 endpoints");
        c.stdout_by_match.push((
            "wg show rustynet0 endpoints".to_owned(),
            "peer\t203.0.113.9:51820".to_owned(),
        ));
        let e = flow_exit(vec![netcheck("e", 0, &clean_hints())]);
        let (result, _checks, _host) = run_flow(&c, &e);
        let err = result.expect_err("a pin that cannot move the tunnel must be refused");
        assert!(err.contains("203.0.113.9:51820"), "{err}");
        assert!(err.contains(&format!("{EXIT_IP}:51820")), "{err}");
        assert!(
            mutating_calls(&calls_of(&c)).is_empty(),
            "nothing may be applied: {:?}",
            calls_of(&c)
        );
    }
}
