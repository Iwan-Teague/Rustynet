//! `cross_network_controller_switch`, ported from
//! `scripts/e2e/live_linux_cross_network_controller_switch_test.sh` (619 ln).
//!
//! # What this proves
//!
//! That losing the **controller** does not lose the dataplane, and that
//! recovering it happens by *pulling* fresh signed state rather than by a push
//! the client cannot verify.
//!
//! The outage is manufactured, not simulated: an nftables table on the client
//! and the relay drops every packet to and from the controller's underlay
//! address, so the daemons genuinely cannot reach it. What must survive that is
//! the relayed exit path — the client keeps routing through the tunnel and both
//! ends keep healthy signed state for the whole outage — and what must happen
//! afterwards is a reconnect within an SLO whose evidence is a
//! `signed state refresh completed` record.
//!
//! # Why the leak and signed-state counters span both phases
//!
//! Samples are taken during the outage **and** during the recovery, into one
//! pair of counters. That is the shell's shape and it is the point: a client
//! that held the tunnel while the controller was unreachable but leaked for two
//! seconds while re-establishing has still leaked. Counting the phases
//! separately would let the recovery window launder a failure the outage window
//! caught.
//!
//! # Preserved asymmetries
//!
//! * **The reconnect target is the RELAY, not the exit.** This scenario runs on
//!   the relay topology, where the client's own `exit_node` is the relay; the
//!   final exit is the *relay's* exit. Asserting on the exit here would assert
//!   the wrong hop.
//! * **The controller is the exit's underlay address.** The lab has no separate
//!   controller node, so the exit doubles as one, and the block is installed on
//!   the two nodes that talk to it rather than on the controller itself.
//! * **Pull-refresh evidence is `OR` across the two nodes, but the fallback is
//!   `AND`.** Passive journal evidence from *either* node proves a pull happened;
//!   the active fallback, which asks each daemon to refresh on demand, requires
//!   *both* to answer. Those are different questions — "did a refresh occur" and
//!   "can each node still refresh" — and the shell asked them differently.
//!
//! # Checks the shell performed that are now structural
//!
//! The ones common to every scenario (see the module docs), plus `live_lab_init`
//! / `live_lab_push_sudo_password` on all three hosts,
//! `live_lab_resolved_target_address`, and the three-way host- and
//! network-id-distinctness guards.
//!
//! New drops, specific to this scenario: **`validate_positive_integer` on
//! `--controller-outage-secs` and `--reconnect-slo-secs`** — both are typed
//! fields on [`ControllerSwitchOptions`], whose constructor rejects zero for
//! each.

use super::baseline::{self, BaselinePaths, BaselineScenario};
use super::endpoint_switch::{SAMPLE_INTERVAL, unix_now};
use super::host::ScenarioHost;
use super::node_network_switch::squeeze;
use super::provisioning::{self, LabContext, during};
use super::{
    Checks, ScenarioInputs, ScenarioNode, ScenarioOutcome, client_exit_selected,
    no_plaintext_passphrase_check, route_via_rustynet, run_root, run_root_allow_failure,
    rustynet_capture_allow_failure, signed_state_healthy, status, wait_for_daemon_socket,
};

/// The scenario name used in fail-closed errors and the report suite field.
pub const SUITE: &str = "cross_network_controller_switch";

/// The report's check names, in the shell's emission order.
pub const CHECKS: &[&str] = &[
    "controller_switch_success",
    "relay_remote_exit_ready",
    "controller_reconnect_within_slo",
    "reconnect_via_pull_refresh",
    "no_underlay_leak_during_reconnect",
    "signed_state_valid_during_reconnect",
    "cross_network_topology_heuristic",
    "no_plaintext_passphrase_files",
];

/// The seven checks `controller_switch_success` aggregates — every other check
/// in [`CHECKS`].
const AGGREGATE_CHECKS: &[&str] = &[
    "relay_remote_exit_ready",
    "controller_reconnect_within_slo",
    "reconnect_via_pull_refresh",
    "no_underlay_leak_during_reconnect",
    "signed_state_valid_during_reconnect",
    "cross_network_topology_heuristic",
    "no_plaintext_passphrase_files",
];

/// The shell's `--controller-outage-secs` default: how many one-second samples
/// are taken while the controller is unreachable.
pub const DEFAULT_CONTROLLER_OUTAGE_SECS: u32 = 8;
/// The shell's `--reconnect-slo-secs` default, which is both the recovery
/// budget and the recovery phase's sample count.
pub const DEFAULT_RECONNECT_SLO_SECS: u32 = 30;

/// The nftables table the block lives in. Named once because it is created,
/// added to, and torn down from three separate places, and a typo in any of
/// them would leave a lab guest permanently unable to reach its controller.
const BLOCK_TABLE: &str = "rustynet_controller_switch_gate";

/// The log line a daemon emits when it has pulled fresh signed state.
const REFRESH_MARKER: &str = "signed state refresh completed";

/// The systemd unit whose journal carries that line.
const DAEMON_UNIT: &str = "rustynetd";

/// Artifact basename of the composed relay baseline's report.
const BASELINE_REPORT_FILE: &str = "cross_network_controller_switch_relay_stage_report.json";
/// Artifact basename of the composed relay baseline's log.
const BASELINE_LOG_FILE: &str = "cross_network_controller_switch_relay_stage.log";
/// Artifact basename of the per-sample monitoring transcript.
const MONITOR_LOG_FILE: &str = "cross_network_controller_switch_monitor.log";
/// Artifact basename of the machine-readable monitoring summary.
const MONITOR_SUMMARY_FILE: &str = "cross_network_controller_switch_summary.json";

/// The scenario's two tunables.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerSwitchOptions {
    controller_outage_secs: u32,
    reconnect_slo_secs: u32,
}

impl Default for ControllerSwitchOptions {
    fn default() -> Self {
        Self {
            controller_outage_secs: DEFAULT_CONTROLLER_OUTAGE_SECS,
            reconnect_slo_secs: DEFAULT_RECONNECT_SLO_SECS,
        }
    }
}

impl ControllerSwitchOptions {
    /// Both must be positive, matching the shell's `validate_positive_integer`
    /// on each flag. A zero outage would never actually take the controller
    /// away; a zero SLO would run no recovery samples and so could never
    /// observe a reconnect.
    pub fn new(controller_outage_secs: u32, reconnect_slo_secs: u32) -> Result<Self, String> {
        if controller_outage_secs == 0 {
            return Err("controller outage seconds must be a positive integer".to_owned());
        }
        if reconnect_slo_secs == 0 {
            return Err("reconnect slo seconds must be a positive integer".to_owned());
        }
        Ok(Self {
            controller_outage_secs,
            reconnect_slo_secs,
        })
    }

    pub fn controller_outage_secs(self) -> u32 {
        self.controller_outage_secs
    }

    pub fn reconnect_slo_secs(self) -> u32 {
        self.reconnect_slo_secs
    }
}

/// Run the controller-switch scenario.
pub fn run(
    host: &dyn ScenarioHost,
    inputs: &ScenarioInputs<'_>,
    lab: &LabContext,
    options: ControllerSwitchOptions,
) -> ScenarioOutcome {
    let mut checks = Checks::new();
    checks.declare(CHECKS);

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
    options: ControllerSwitchOptions,
    checks: &mut Checks,
) -> Result<(), String> {
    let client = &inputs.client;
    let exit = &inputs.exit;
    let relay = inputs.require_relay(SUITE)?;

    // ── relay baseline ──
    let phase = "bootstrapping relay remote-exit path before controller-switch simulation";
    let baseline_report = lab.artifact(BASELINE_REPORT_FILE);
    let baseline_log = lab.artifact(BASELINE_LOG_FILE);
    let baseline = baseline::compose(
        host,
        inputs,
        lab,
        BaselineScenario::Relay,
        &BaselinePaths {
            report_path: baseline_report.as_path(),
            log_path: baseline_log.as_path(),
        },
        phase,
    )?;
    checks.record_bool(
        "relay_remote_exit_ready",
        baseline.succeeded()
            && baseline.passed(BaselineScenario::Relay.success_check())
            && baseline.passed("remote_exit_no_underlay_leak"),
    );
    checks.record_bool(
        "cross_network_topology_heuristic",
        baseline.passed("cross_network_topology_heuristic"),
    );
    if !checks.passed("relay_remote_exit_ready") {
        return Err(
            "relay bootstrap did not produce a secure baseline for controller-switch validation"
                .to_owned(),
        );
    }

    let phase = "initializing live-lab runtime for controller-switch validation";
    for node in [exit, relay, client] {
        during(phase, wait_for_daemon_socket(node.runner))?;
    }

    let client_plaintext_start = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let relay_plaintext_start = during(phase, no_plaintext_passphrase_check(relay.runner))?;
    let exit_plaintext_start = during(phase, no_plaintext_passphrase_check(exit.runner))?;

    // The lab has no separate controller node, so the exit doubles as one and
    // the block goes on the two nodes that talk to it.
    let controller_ip = exit.address.clone();

    // ── outage, recovery, and an unconditional unblock ──
    let phase = "blocking controller underlay path with nftables";
    let switch_started_unix = unix_now();
    let observed =
        observe_controller_switch(client, relay, lab, options, &controller_ip, &relay.node_id);
    // The shell cleared both blocks from an `EXIT` trap, so they came down on
    // every path. Doing it before the `?` keeps that: a guest left with an
    // nftables table that drops its controller is a guest the next stage cannot
    // provision.
    clear_controller_block(client.runner);
    clear_controller_block(relay.runner);
    let observed = during(phase, observed)?;

    let phase = "recording controller-switch evidence";
    let reconnect_secs = observed.reconnect_secs();
    checks.record_bool(
        "controller_reconnect_within_slo",
        matches!(
            reconnect_secs,
            Some(secs) if (0..=i64::from(options.reconnect_slo_secs)).contains(&secs)
        ),
    );
    checks.record_bool(
        "no_underlay_leak_during_reconnect",
        observed.route_leak_samples == 0,
    );
    checks.record_bool(
        "signed_state_valid_during_reconnect",
        observed.signed_state_invalid_samples == 0,
    );

    checks.record_bool(
        "reconnect_via_pull_refresh",
        pull_refresh_observed(client, relay, switch_started_unix)?,
    );

    let client_plaintext_end = during(phase, no_plaintext_passphrase_check(client.runner))?;
    let relay_plaintext_end = during(phase, no_plaintext_passphrase_check(relay.runner))?;
    let exit_plaintext_end = during(phase, no_plaintext_passphrase_check(exit.runner))?;
    // All six observations, three nodes before and after. A node that held
    // plaintext material before the outage and cleaned up during it is not a
    // node that never held any.
    checks.record_bool(
        "no_plaintext_passphrase_files",
        client_plaintext_start
            && relay_plaintext_start
            && exit_plaintext_start
            && client_plaintext_end
            && relay_plaintext_end
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
                &controller_ip,
                &observed,
                reconnect_secs,
                options,
                checks,
            )?,
        ),
    )?;

    checks.record_bool(
        "controller_switch_success",
        checks.all_passed(AGGREGATE_CHECKS),
    );
    if checks.passed("controller_switch_success") {
        return Ok(());
    }
    Err(failure_summary(checks, options, reconnect_secs))
}

/// The shell's `if/elif` chain, in its order.
fn failure_summary(
    checks: &Checks,
    options: ControllerSwitchOptions,
    reconnect_secs: Option<i64>,
) -> String {
    if !checks.passed("controller_reconnect_within_slo") {
        return format!(
            "controller switch reconvergence exceeded reconnect SLO ({}s), measured={}s",
            options.reconnect_slo_secs,
            reconnect_secs.unwrap_or(NO_RECONNECT_SECS)
        );
    }
    if !checks.passed("reconnect_via_pull_refresh") {
        return "controller switch did not show signed pull-refresh recovery evidence".to_owned();
    }
    if !checks.passed("no_underlay_leak_during_reconnect") {
        return "underlay leak detected while controller path was switching".to_owned();
    }
    if !checks.passed("signed_state_valid_during_reconnect") {
        return "signed state became invalid while controller path was switching".to_owned();
    }
    if !checks.passed("no_plaintext_passphrase_files") {
        return "plaintext passphrase files were detected during controller-switch validation"
            .to_owned();
    }
    "controller switch validation checks did not all pass".to_owned()
}

/// The shell's `reconnect_secs=-1` sentinel, written into the summary artifact.
const NO_RECONNECT_SECS: i64 = -1;

/// What the two monitoring phases saw.
struct ControllerObservation {
    /// Unix seconds at which the block was lifted. The reconnect SLO is
    /// measured from here, not from the start of the outage: the daemons could
    /// not have recovered while the controller was still unreachable, so
    /// charging them for the outage would measure the test's own parameter.
    restore_started_unix: u64,
    /// Unix seconds at which the client was seen fully recovered.
    reconnect_unix: Option<u64>,
    /// Leaking samples across BOTH phases — see the module docs.
    route_leak_samples: u32,
    /// Samples with unhealthy signed state, across both phases.
    signed_state_invalid_samples: u32,
    transcript: String,
}

impl ControllerObservation {
    fn reconnect_secs(&self) -> Option<i64> {
        self.reconnect_unix.map(|at| {
            i64::try_from(at).unwrap_or(i64::MAX)
                - i64::try_from(self.restore_started_unix).unwrap_or(i64::MAX)
        })
    }
}

/// One sample of the client's and relay's state.
struct Sample {
    route_ok: bool,
    signed_ok: bool,
    client_status: String,
    line: String,
}

/// Take one sample and render its monitor-log line.
fn take_sample(
    client: &ScenarioNode<'_>,
    relay: &ScenarioNode<'_>,
    phase_label: &str,
    iteration: u32,
    sampled_at: u64,
) -> Result<Sample, String> {
    let client_route = provisioning::capture_allow_failure(
        client.runner,
        &["ip", "-4", "route", "get", "1.1.1.1"],
    )?;
    let client_status = status(client.runner)?;
    let client_netcheck = rustynet_capture_allow_failure(client.runner, &["netcheck"])?;
    let relay_netcheck = rustynet_capture_allow_failure(relay.runner, &["netcheck"])?;

    // Both ends: a controller outage the client rides out while the relay's
    // signed state degrades is still an outage that broke signed state.
    let signed_ok = signed_state_healthy(&client_netcheck) && signed_state_healthy(&relay_netcheck);
    let line = format!(
        "{sampled_at}|phase={phase_label}|iter={iteration}|route={}|status={}|client_netcheck={}|relay_netcheck={}\n",
        squeeze(&client_route),
        squeeze(&client_status),
        squeeze(&client_netcheck),
        squeeze(&relay_netcheck),
    );
    Ok(Sample {
        route_ok: route_via_rustynet(&client_route),
        signed_ok,
        client_status,
        line,
    })
}

/// Block the controller, sample the outage, unblock, then sample the recovery.
fn observe_controller_switch(
    client: &ScenarioNode<'_>,
    relay: &ScenarioNode<'_>,
    lab: &LabContext,
    options: ControllerSwitchOptions,
    controller_ip: &str,
    relay_node_id: &str,
) -> Result<ControllerObservation, String> {
    apply_controller_block(client.runner, controller_ip)?;
    apply_controller_block(relay.runner, controller_ip)?;

    let mut route_leak_samples = 0;
    let mut signed_state_invalid_samples = 0;
    let mut transcript = String::new();

    // ── phase 1: the controller is unreachable ──
    for iteration in 1..=options.controller_outage_secs {
        let sample = take_sample(client, relay, "blocked", iteration, unix_now())?;
        if !sample.route_ok {
            route_leak_samples += 1;
        }
        if !sample.signed_ok {
            signed_state_invalid_samples += 1;
        }
        transcript.push_str(&sample.line);
        lab.sleep(SAMPLE_INTERVAL);
    }

    // ── phase 2: the controller is reachable again ──
    //
    // Unblocking here rather than only in the caller's teardown is deliberate:
    // the recovery phase measures what happens once the path is back, so the
    // block must come down before the first recovery sample. The teardown call
    // is idempotent and covers the failure paths.
    clear_controller_block(client.runner);
    clear_controller_block(relay.runner);
    let restore_started_unix = unix_now();

    let mut reconnect_unix = None;
    for iteration in 1..=options.reconnect_slo_secs {
        let sampled_at = unix_now();
        let sample = take_sample(client, relay, "recovery", iteration, sampled_at)?;
        if !sample.route_ok {
            route_leak_samples += 1;
        }
        if !sample.signed_ok {
            signed_state_invalid_samples += 1;
        }
        transcript.push_str(&sample.line);

        // The client's exit is the RELAY on this topology — see the module
        // docs. Full recovery is all four clauses; anything less is a partial
        // one that would let the SLO be met by a client that had not finished.
        if client_exit_selected(&sample.client_status, relay_node_id)
            && sample.route_ok
            && sample.signed_ok
        {
            reconnect_unix = Some(sampled_at);
            break;
        }
        lab.sleep(SAMPLE_INTERVAL);
    }

    Ok(ControllerObservation {
        restore_started_unix,
        reconnect_unix,
        route_leak_samples,
        signed_state_invalid_samples,
        transcript,
    })
}

/// Install the nftables table that drops traffic to and from `controller_ip`.
///
/// The shell ran six `nft` invocations as one remote shell script with the
/// address interpolated into each. Here each is its own argv and the address is
/// an element rather than text spliced into a rule, so a hostile value cannot
/// extend the ruleset — it can only be a malformed address `nft` rejects.
fn apply_controller_block(
    runner: &dyn super::super::substrate::NetLeafRunner,
    controller_ip: &str,
) -> Result<(), String> {
    provisioning::validate_argv_value("controller ip", controller_ip)?;
    // Delete first, tolerating absence: the shell's `|| true`, which lets a
    // re-run install a clean table rather than failing on the previous one.
    let _ = run_root_allow_failure(runner, &["nft", "delete", "table", "inet", BLOCK_TABLE]);
    run_root(runner, &["nft", "add", "table", "inet", BLOCK_TABLE])?;
    // Priority -150 puts these chains ahead of the daemon's own filter tables,
    // so the drop is not something a later rule can accept around.
    for hook in ["input", "output"] {
        run_root(
            runner,
            &[
                "nft",
                "add",
                "chain",
                "inet",
                BLOCK_TABLE,
                hook,
                &format!("{{ type filter hook {hook} priority -150; policy accept; }}"),
            ],
        )?;
    }
    run_root(
        runner,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            BLOCK_TABLE,
            "input",
            "ip",
            "saddr",
            controller_ip,
            "counter",
            "drop",
        ],
    )?;
    run_root(
        runner,
        &[
            "nft",
            "add",
            "rule",
            "inet",
            BLOCK_TABLE,
            "output",
            "ip",
            "daddr",
            controller_ip,
            "counter",
            "drop",
        ],
    )
}

/// Remove the block table, tolerating its absence.
///
/// Best-effort and idempotent, because it runs both mid-scenario (to open the
/// recovery window) and on every exit path (to leave no residue). A guest that
/// cannot drop the table is broken in a way this scenario's verdict should not
/// be reporting.
fn clear_controller_block(runner: &dyn super::super::substrate::NetLeafRunner) {
    let _ = run_root_allow_failure(runner, &["nft", "delete", "table", "inet", BLOCK_TABLE]);
}

/// Did either node pull fresh signed state, and if not, can both still do so on
/// demand?
///
/// Two questions, asked in the shell's order and with its different quantifiers.
/// The passive check reads each daemon's journal since the outage began and
/// passes if **either** node logged a refresh — one node's pull is proof that
/// pulling works. The active fallback asks each daemon to refresh now and
/// requires **both** to succeed, because it is asking a different thing: not
/// "did a refresh happen" but "is every node still able to".
fn pull_refresh_observed(
    client: &ScenarioNode<'_>,
    relay: &ScenarioNode<'_>,
    since_unix: u64,
) -> Result<bool, String> {
    let phase = "reading signed pull-refresh recovery evidence";
    let client_logged = during(phase, refresh_logged(client, since_unix))?;
    let relay_logged = during(phase, refresh_logged(relay, since_unix))?;
    if client_logged || relay_logged {
        return Ok(true);
    }

    let client_refreshed = during(
        phase,
        rustynet_capture_allow_failure(client.runner, &["state", "refresh"]),
    )?;
    let relay_refreshed = during(
        phase,
        rustynet_capture_allow_failure(relay.runner, &["state", "refresh"]),
    )?;
    Ok(client_refreshed.contains(REFRESH_MARKER) && relay_refreshed.contains(REFRESH_MARKER))
}

/// True when the node's daemon journal records a refresh since `since_unix`.
///
/// The shell piped `journalctl` into `grep -F … || true`, so an empty journal
/// and an unreadable one both read as "no evidence". That is preserved: this
/// check only ever *adds* evidence, and its absence falls through to the active
/// fallback rather than failing the scenario outright.
fn refresh_logged(node: &ScenarioNode<'_>, since_unix: u64) -> Result<bool, String> {
    let since = format!("@{since_unix}");
    let journal = super::capture_root_allow_failure(
        node.runner,
        &[
            "journalctl",
            "-u",
            DAEMON_UNIT,
            "--since",
            &since,
            "--no-pager",
        ],
    )?;
    Ok(journal.contains(REFRESH_MARKER))
}

/// The monitor summary artifact, in the shell's field names and types.
fn render_summary(
    switch_started_unix: u64,
    controller_ip: &str,
    observed: &ControllerObservation,
    reconnect_secs: Option<i64>,
    options: ControllerSwitchOptions,
    checks: &Checks,
) -> Result<String, String> {
    let payload = serde_json::json!({
        "controller_switch_started_unix": switch_started_unix,
        "controller_ip": controller_ip,
        "reconnect_unix": observed.reconnect_unix,
        "reconnect_secs": reconnect_secs.unwrap_or(NO_RECONNECT_SECS),
        "reconnect_slo_secs": options.reconnect_slo_secs,
        "route_leak_samples": observed.route_leak_samples,
        "signed_state_invalid_samples": observed.signed_state_invalid_samples,
        "checks": {
            "controller_reconnect_within_slo":
                checks.verdict("controller_reconnect_within_slo").as_str(),
            "reconnect_via_pull_refresh": checks.verdict("reconnect_via_pull_refresh").as_str(),
        },
    });
    serde_json::to_string_pretty(&payload)
        .map(|rendered| format!("{rendered}\n"))
        .map_err(|err| format!("failed to render controller-switch summary: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm_lab::orchestrator::stage::cross_network::substrate::mock::MockLeafRunner;

    const RELAY_NODE_ID: &str = "relay-1";
    const CONTROLLER_IP: &str = "192.168.19.40";

    fn options(outage: u32, slo: u32) -> ControllerSwitchOptions {
        ControllerSwitchOptions::new(outage, slo).expect("positive")
    }

    /// A client holding a healthy relayed path.
    fn healthy_client() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    format!("exit_node={RELAY_NODE_ID} state=ExitActive"),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0 src 10.42.0.2".to_owned(),
                ),
                (
                    "rustynet netcheck".to_owned(),
                    "traversal_error=none traversal_alarm_state=ok dns_alarm_state=ok".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        }
    }

    fn healthy_relay() -> MockLeafRunner {
        MockLeafRunner {
            stdout_by_match: vec![(
                "rustynet netcheck".to_owned(),
                "traversal_error=none".to_owned(),
            )],
            ..MockLeafRunner::default()
        }
    }

    fn observe(
        client: &MockLeafRunner,
        relay: &MockLeafRunner,
        options: ControllerSwitchOptions,
    ) -> Result<ControllerObservation, String> {
        let lab = super::super::node_network_switch::test_support::lab("/tmp/rustynet-cn3-tests");
        let client_node = ScenarioNode::new(client, "client-1", "192.168.18.40");
        let relay_node = ScenarioNode::new(relay, RELAY_NODE_ID, "192.168.20.40");
        observe_controller_switch(
            &client_node,
            &relay_node,
            &lab,
            options,
            CONTROLLER_IP,
            RELAY_NODE_ID,
        )
    }

    #[test]
    fn the_outage_phase_runs_to_completion_before_the_recovery_phase_begins() {
        // A healthy client recovers on the first recovery sample, so the
        // transcript is the whole outage plus exactly one recovery line.
        let client = healthy_client();
        let relay = healthy_relay();
        let observed = observe(&client, &relay, options(4, 30)).expect("observe");

        let lines: Vec<&str> = observed.transcript.lines().collect();
        assert_eq!(lines.len(), 5);
        assert_eq!(
            lines.iter().filter(|l| l.contains("phase=blocked")).count(),
            4
        );
        assert_eq!(
            lines
                .iter()
                .filter(|l| l.contains("phase=recovery"))
                .count(),
            1
        );
        assert!(observed.reconnect_unix.is_some());
        assert_eq!(observed.reconnect_secs(), Some(0));
    }

    #[test]
    fn leak_samples_from_the_outage_phase_survive_a_clean_recovery() {
        // The whole point of one shared counter: a client that leaked while the
        // controller was away must not have that laundered by recovering
        // cleanly afterwards.
        let client = MockLeafRunner {
            // Only the FIRST route query leaks. Call 0-6 are the block install
            // (delete, add table, two chains, two rules) so the first sample's
            // `route get` is call 6.
            stdout_for: vec![(6, "1.1.1.1 via 192.168.18.1 dev enp0s1".to_owned())],
            ..healthy_client()
        };
        let relay = healthy_relay();
        let observed = observe(&client, &relay, options(3, 30)).expect("observe");

        assert_eq!(observed.route_leak_samples, 1);
        assert!(
            observed.reconnect_unix.is_some(),
            "it recovered anyway, and the leak still counts"
        );
    }

    #[test]
    fn a_relay_with_degraded_signed_state_fails_the_sample_even_when_the_client_is_healthy() {
        let client = healthy_client();
        let relay = MockLeafRunner {
            stdout_by_match: vec![(
                "rustynet netcheck".to_owned(),
                "traversal_error=none dns_alarm_state=critical".to_owned(),
            )],
            ..MockLeafRunner::default()
        };
        let observed = observe(&client, &relay, options(2, 3)).expect("observe");

        // Two outage samples plus three recovery samples: the client never
        // counts as recovered because the relay's state is never healthy.
        assert_eq!(observed.signed_state_invalid_samples, 5);
        assert!(observed.reconnect_unix.is_none());
        assert_eq!(observed.reconnect_secs(), None);
    }

    #[test]
    fn recovery_requires_the_relay_as_the_clients_exit_not_the_final_exit() {
        // This scenario runs on the relay topology, where the client's own
        // `exit_node` is the relay. Asserting on the final exit would assert
        // the wrong hop.
        let client = MockLeafRunner {
            stdout_by_match: vec![
                (
                    "rustynet status".to_owned(),
                    "exit_node=exit-1 state=ExitActive".to_owned(),
                ),
                (
                    "route get 1.1.1.1".to_owned(),
                    "1.1.1.1 dev rustynet0".to_owned(),
                ),
                (
                    "rustynet netcheck".to_owned(),
                    "traversal_error=none".to_owned(),
                ),
            ],
            ..MockLeafRunner::default()
        };
        let relay = healthy_relay();
        let observed = observe(&client, &relay, options(1, 2)).expect("observe");
        assert!(observed.reconnect_unix.is_none());
    }

    #[test]
    fn the_block_is_installed_and_removed_with_the_controller_address_as_argv() {
        let runner = MockLeafRunner::default();
        apply_controller_block(&runner, CONTROLLER_IP).expect("install");
        clear_controller_block(&runner);
        let calls = runner.recorded();

        assert_eq!(calls.len(), 7, "delete, table, 2 chains, 2 rules, delete");
        assert_eq!(
            calls[0],
            vec![
                "sudo",
                "-n",
                "nft",
                "delete",
                "table",
                "inet",
                "rustynet_controller_switch_gate"
            ],
            "a stale table from a previous run is dropped first"
        );
        // The address is its own argv element, never spliced into a rule string.
        assert!(calls[5].contains(&CONTROLLER_IP.to_owned()));
        assert_eq!(calls[5].last().expect("a verb"), "drop");
        assert_eq!(calls[6], calls[0], "teardown repeats the same delete");
    }

    #[test]
    fn a_controller_address_that_could_be_read_as_an_option_is_rejected() {
        let runner = MockLeafRunner::default();
        assert!(apply_controller_block(&runner, "-o").is_err());
        assert!(apply_controller_block(&runner, "").is_err());
        assert!(
            runner.recorded().is_empty(),
            "validation must happen before anything reaches the guest"
        );
    }

    #[test]
    fn journal_evidence_from_either_node_proves_a_pull_happened() {
        let logged = MockLeafRunner {
            stdout_by_match: vec![(
                "journalctl".to_owned(),
                format!("Aug 28 10:00:00 host rustynetd[1]: {REFRESH_MARKER}"),
            )],
            ..MockLeafRunner::default()
        };
        let silent = MockLeafRunner::default();

        let client = ScenarioNode::new(&silent, "client-1", "192.168.18.40");
        let relay = ScenarioNode::new(&logged, RELAY_NODE_ID, "192.168.20.40");
        assert!(pull_refresh_observed(&client, &relay, 1700).expect("evidence"));
        // Only the two journal reads: the active fallback must not run once
        // passive evidence exists.
        assert_eq!(silent.recorded().len(), 1);
    }

    #[test]
    fn the_active_fallback_requires_both_nodes_to_refresh() {
        // Different question from the passive check, and the shell asked it
        // with a different quantifier.
        let refreshes = || MockLeafRunner {
            stdout_by_match: vec![("state refresh".to_owned(), REFRESH_MARKER.to_owned())],
            ..MockLeafRunner::default()
        };
        let client_ok = refreshes();
        let relay_ok = refreshes();
        assert!(
            pull_refresh_observed(
                &ScenarioNode::new(&client_ok, "client-1", "192.168.18.40"),
                &ScenarioNode::new(&relay_ok, RELAY_NODE_ID, "192.168.20.40"),
                1700
            )
            .expect("evidence")
        );

        let client_only = refreshes();
        let relay_silent = MockLeafRunner::default();
        assert!(
            !pull_refresh_observed(
                &ScenarioNode::new(&client_only, "client-1", "192.168.18.40"),
                &ScenarioNode::new(&relay_silent, RELAY_NODE_ID, "192.168.20.40"),
                1700
            )
            .expect("evidence")
        );
    }

    #[test]
    fn both_tunables_reject_zero_and_default_to_the_shells_values() {
        assert!(ControllerSwitchOptions::new(0, 30).is_err());
        assert!(ControllerSwitchOptions::new(8, 0).is_err());
        let defaults = ControllerSwitchOptions::default();
        assert_eq!(defaults.controller_outage_secs(), 8);
        assert_eq!(defaults.reconnect_slo_secs(), 30);
    }

    #[test]
    fn the_aggregate_covers_every_other_check_in_the_report() {
        let mut expected: Vec<&str> = CHECKS
            .iter()
            .copied()
            .filter(|name| *name != "controller_switch_success")
            .collect();
        let mut actual = AGGREGATE_CHECKS.to_vec();
        expected.sort_unstable();
        actual.sort_unstable();
        assert_eq!(actual, expected);
    }

    #[test]
    fn the_failure_summary_names_the_first_thing_that_did_not_happen() {
        let options = ControllerSwitchOptions::default();
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        assert_eq!(
            failure_summary(&checks, options, None),
            "controller switch reconvergence exceeded reconnect SLO (30s), measured=-1s"
        );

        checks.record_bool("controller_reconnect_within_slo", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "controller switch did not show signed pull-refresh recovery evidence"
        );

        checks.record_bool("reconnect_via_pull_refresh", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "underlay leak detected while controller path was switching"
        );

        checks.record_bool("no_underlay_leak_during_reconnect", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "signed state became invalid while controller path was switching"
        );

        checks.record_bool("signed_state_valid_during_reconnect", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "plaintext passphrase files were detected during controller-switch validation"
        );

        checks.record_bool("no_plaintext_passphrase_files", true);
        assert_eq!(
            failure_summary(&checks, options, Some(4)),
            "controller switch validation checks did not all pass"
        );
    }

    #[test]
    fn the_summary_spells_a_missing_reconnect_as_null_and_minus_one() {
        let mut checks = Checks::new();
        checks.declare(CHECKS);
        let observed = ControllerObservation {
            restore_started_unix: 1700,
            reconnect_unix: None,
            route_leak_samples: 2,
            signed_state_invalid_samples: 0,
            transcript: String::new(),
        };
        let rendered = render_summary(
            1690,
            CONTROLLER_IP,
            &observed,
            None,
            ControllerSwitchOptions::default(),
            &checks,
        )
        .expect("render");
        let parsed: serde_json::Value = serde_json::from_str(&rendered).expect("valid JSON");
        assert!(parsed["reconnect_unix"].is_null());
        assert_eq!(parsed["reconnect_secs"], -1);
        assert_eq!(parsed["controller_ip"], CONTROLLER_IP);
        assert_eq!(parsed["controller_switch_started_unix"], 1690);
        assert_eq!(parsed["route_leak_samples"], 2);
        assert_eq!(parsed["checks"]["reconnect_via_pull_refresh"], "fail");
    }
}
